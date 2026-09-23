// Copyright (c) 2026, Janoš Guljaš <janos@resenje.org>
// All rights reserved.

package sajberpank

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/base64"
	"fmt"
	"strings"
)

// DefaultPayloadInfo returns the standard info parameter used for RFC 9180 HPKE recipient setup (nil in Sajberpank).
func DefaultPayloadInfo() []byte {
	return nil
}

// Decrypt decrypts the EncryptedPayload using AES-256-GCM and the provided 32-byte symmetric key,
// with optional authenticated additional data (AAD). If aad is provided, it attempts decryption with
// aad first, falling back to nil AAD for backward compatibility with unauthenticated envelopes.
func (p *EncryptedPayload) Decrypt(key []byte, aad ...[]byte) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("nil encrypted payload")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length %d, expected 32", len(key))
	}

	nonceBytes, err := base64.StdEncoding.DecodeString(p.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}

	ciphertextBytes, err := base64.StdEncoding.DecodeString(p.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes gcm: %w", err)
	}

	if len(nonceBytes) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size: %d, expected %d", len(nonceBytes), gcm.NonceSize())
	}

	var candidateAADs [][]byte
	if len(aad) > 0 && len(aad[0]) > 0 {
		candidateAADs = [][]byte{aad[0], nil}
	} else {
		candidateAADs = [][]byte{nil}
	}

	var lastErr error
	for _, authData := range candidateAADs {
		plaintext, err := gcm.Open(nil, nonceBytes, ciphertextBytes, authData)
		if err == nil {
			return plaintext, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("aes gcm open: %w", lastErr)
}

type decryptConfig struct {
	kdf  hpke.KDF
	aead hpke.AEAD
	info []byte
}

func applyDecryptOptions(opts []DecryptOption) decryptConfig {
	cfg := decryptConfig{
		kdf:  hpke.HKDFSHA256(),
		aead: hpke.ChaCha20Poly1305(),
		info: DefaultPayloadInfo(),
	}
	for _, opt := range opts {
		if opt != nil {
			opt.apply(&cfg)
		}
	}
	return cfg
}

// DecryptOption configures optional parameters for HPKE decryption.
type DecryptOption interface {
	apply(*decryptConfig)
}

type decryptOptionFunc func(*decryptConfig)

func (f decryptOptionFunc) apply(c *decryptConfig) {
	f(c)
}

// WithSuite configures custom KDF and AEAD algorithms for HPKE decryption.
func WithSuite(kdf hpke.KDF, aead hpke.AEAD) DecryptOption {
	return decryptOptionFunc(func(c *decryptConfig) {
		if kdf != nil {
			c.kdf = kdf
		}
		if aead != nil {
			c.aead = aead
		}
	})
}

// WithInfo sets application-specific context information (info parameter) for HPKE decryption.
func WithInfo(info []byte) DecryptOption {
	return decryptOptionFunc(func(c *decryptConfig) {
		c.info = info
	})
}

// DecryptKey decrypts the KeyEnvelope using RFC 9180 HPKE and the recipient private key to recover the 32-byte symmetric key.
func (k *KeyEnvelope) DecryptKey(priv hpke.PrivateKey, opts ...DecryptOption) ([]byte, error) {
	if k == nil {
		return nil, fmt.Errorf("nil key envelope")
	}

	encBytes, err := base64.StdEncoding.DecodeString(k.EncapsulatedKey)
	if err != nil {
		return nil, fmt.Errorf("decode encapsulated key: %w", err)
	}

	ciphertextBytes, err := base64.StdEncoding.DecodeString(k.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	cfg := applyDecryptOptions(opts)
	recipient, err := hpke.NewRecipient(encBytes, priv, cfg.kdf, cfg.aead, cfg.info)
	if err != nil {
		return nil, fmt.Errorf("setup recipient: %w", err)
	}

	var aad []byte
	if k.KeyID != "" {
		aad = []byte(k.KeyID)
	}

	symmetricKey, err := recipient.Open(aad, ciphertextBytes)
	if err != nil && aad != nil {
		// Fallback to nil AAD for unauthenticated envelopes
		if symKeyFallback, fErr := recipient.Open(nil, ciphertextBytes); fErr == nil {
			return symKeyFallback, nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("open key envelope: %w", err)
	}

	return symmetricKey, nil
}

// Decrypt decrypts the keyword payload using the recipient private key and optional HPKE cipher suite parameters.
func (kw *EncryptedKeyword) Decrypt(priv hpke.PrivateKey, opts ...DecryptOption) (string, error) {
	if kw == nil {
		return "", fmt.Errorf("nil encrypted keyword")
	}
	symKey, err := kw.KeyEnvelope.DecryptKey(priv, opts...)
	if err != nil {
		return "", fmt.Errorf("decrypt keyword symmetric key: %w", err)
	}
	var kwAAD []byte
	if kw.KeyEnvelope.KeyID != "" {
		kwAAD = []byte(kw.KeyEnvelope.KeyID)
	}
	plain, err := kw.Payload.Decrypt(symKey, kwAAD)
	if err != nil {
		return "", fmt.Errorf("decrypt keyword payload: %w", err)
	}
	return string(plain), nil
}

// newKeyEnvelope encrypts a symmetric key using the recipient's public key (RFC 9180 HPKE) to produce a KeyEnvelope.
func newKeyEnvelope(pubBytes []byte, keyID string, symmetricKey []byte) (*KeyEnvelope, error) {
	return newKeyEnvelopeWithSuite(pubBytes, keyID, symmetricKey, hpke.DHKEM(ecdh.X25519()), hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), DefaultPayloadInfo())
}

// newKeyEnvelopeWithSuite encrypts a symmetric key with a specific HPKE cipher suite.
func newKeyEnvelopeWithSuite(pubBytes []byte, keyID string, symmetricKey []byte, kem hpke.KEM, kdf hpke.KDF, aead hpke.AEAD, info []byte) (*KeyEnvelope, error) {
	pub, err := kem.NewPublicKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("new public key: %w", err)
	}
	encap, sender, err := hpke.NewSender(pub, kdf, aead, info)
	if err != nil {
		return nil, fmt.Errorf("new sender: %w", err)
	}
	var aad []byte
	if keyID != "" {
		aad = []byte(keyID)
	}
	ct, err := sender.Seal(aad, symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("seal key: %w", err)
	}
	return &KeyEnvelope{
		KeyID:           keyID,
		EncapsulatedKey: base64.StdEncoding.EncodeToString(encap),
		Ciphertext:      base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// Keyring maps key IDs to their corresponding HPKE private keys for multi-key decryption.
type Keyring map[string]hpke.PrivateKey

// Decrypt decrypts a KeyEnvelope using the matching key ID from the keyring with optional cipher suite parameters.
func (k Keyring) Decrypt(ek *KeyEnvelope, opts ...DecryptOption) ([]byte, error) {
	if ek == nil {
		return nil, fmt.Errorf("nil key envelope")
	}
	priv, ok := k[ek.KeyID]
	if !ok {
		return nil, fmt.Errorf("key %q not found in keyring", ek.KeyID)
	}
	return ek.DecryptKey(priv, opts...)
}

// GenerateX25519Key generates a DHKEM(X25519) private key and its raw public key bytes.
func GenerateX25519Key() (hpke.PrivateKey, []byte, error) {
	kem := hpke.DHKEM(ecdh.X25519())
	priv, err := kem.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return priv, priv.PublicKey().Bytes(), nil
}

// GenerateP256Key generates a DHKEM(P-256) private key and its raw public key bytes.
func GenerateP256Key() (hpke.PrivateKey, []byte, error) {
	kem := hpke.DHKEM(ecdh.P256())
	priv, err := kem.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return priv, priv.PublicKey().Bytes(), nil
}

// GenerateMLKEMKey generates a post-quantum hybrid ML-KEM-768/X25519 key and its public key bytes.
func GenerateMLKEMKey() (hpke.PrivateKey, []byte, error) {
	kem := hpke.MLKEM768X25519()
	priv, err := kem.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return priv, priv.PublicKey().Bytes(), nil
}

func resolveKEM(s string) (hpke.KEM, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "", "HPKE_KEM_UNSPECIFIED", "HPKE_KEM_DHKEM_X25519_HKDF_SHA256", "DHKEM_X25519_HKDF_SHA256", "DHKEM_X25519", "X25519":
		return hpke.DHKEM(ecdh.X25519()), nil
	case "HPKE_KEM_DHKEM_P256_HKDF_SHA256", "DHKEM_P256_HKDF_SHA256", "DHKEM_P256", "P256", "P-256":
		return hpke.DHKEM(ecdh.P256()), nil
	case "HPKE_KEM_MLKEM768_X25519", "MLKEM768_X25519", "MLKEM768X25519":
		return hpke.MLKEM768X25519(), nil
	case "HPKE_KEM_MLKEM768", "MLKEM768":
		return hpke.MLKEM768(), nil
	default:
		return nil, fmt.Errorf("unsupported KEM %q", s)
	}
}

func resolveKDF(s string) (hpke.KDF, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "", "HPKE_KDF_UNSPECIFIED", "HPKE_KDF_HKDF_SHA256", "HKDF_SHA256", "SHA256":
		return hpke.HKDFSHA256(), nil
	case "HPKE_KDF_HKDF_SHA384", "HKDF_SHA384", "SHA384":
		return hpke.HKDFSHA384(), nil
	case "HPKE_KDF_HKDF_SHA512", "HKDF_SHA512", "SHA512":
		return hpke.HKDFSHA512(), nil
	default:
		return nil, fmt.Errorf("unsupported KDF %q", s)
	}
}

func resolveAEAD(s string) (hpke.AEAD, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "", "HPKE_AEAD_UNSPECIFIED", "HPKE_AEAD_CHACHA20_POLY1305", "CHACHA20_POLY1305", "CHACHA20POLY1305":
		return hpke.ChaCha20Poly1305(), nil
	case "HPKE_AEAD_AES_256_GCM", "AES_256_GCM", "AES256GCM":
		return hpke.AES256GCM(), nil
	case "HPKE_AEAD_AES_128_GCM", "AES_128_GCM", "AES128GCM":
		return hpke.AES128GCM(), nil
	default:
		return nil, fmt.Errorf("unsupported AEAD %q", s)
	}
}

func resolveSuite(kemStr, kdfStr, aeadStr string) (hpke.KEM, hpke.KDF, hpke.AEAD, error) {
	kem, err := resolveKEM(kemStr)
	if err != nil {
		return nil, nil, nil, err
	}
	kdf, err := resolveKDF(kdfStr)
	if err != nil {
		return nil, nil, nil, err
	}
	aead, err := resolveAEAD(aeadStr)
	if err != nil {
		return nil, nil, nil, err
	}
	return kem, kdf, aead, nil
}
