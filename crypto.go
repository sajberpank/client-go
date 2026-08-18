// Copyright (c) 2026, Janoš Guljaš <janos@resenje.org>
// All rights reserved.

package sajberpank

import (
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/base64"
	"fmt"
)

// DefaultHPKEInfo is the optional domain separation context tag for HPKE.
// In Sajberpank and Metron, nil is the standard default info tag.

// DefaultPayloadInfo returns the standard info parameter used for RFC 9180 HPKE recipient setup.
func DefaultPayloadInfo() []byte {
	return nil
}

// Open decrypts the encrypted payload using the provided recipient private key.
func (p *EncryptedPayload) Open(priv hpke.PrivateKey, kdf hpke.KDF, aead hpke.AEAD, info []byte) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("nil encrypted payload")
	}

	encBytes, err := base64.StdEncoding.DecodeString(p.Enc)
	if err != nil {
		return nil, fmt.Errorf("decode enc header: %w", err)
	}

	ciphertextBytes, err := base64.StdEncoding.DecodeString(p.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	recipient, err := hpke.NewRecipient(encBytes, priv, kdf, aead, info)
	if err != nil {
		return nil, fmt.Errorf("setup recipient: %w", err)
	}

	plaintext, err := recipient.Open(nil, ciphertextBytes)
	if err != nil {
		return nil, fmt.Errorf("open ciphertext: %w", err)
	}

	return plaintext, nil
}

// OpenDefault decrypts the encrypted payload using the default cipher suite:
// HKDF-SHA256, ChaCha20Poly1305, and standard sajberpank payload info tag.
func (p *EncryptedPayload) OpenDefault(priv hpke.PrivateKey) ([]byte, error) {
	return p.Open(priv, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), nil)
}

// Keyring maps key IDs to their corresponding HPKE private keys for multi-key decryption.
type Keyring map[string]hpke.PrivateKey

// Open decrypts an EncryptedPayload using the matching key ID from the keyring with default cipher suite.
func (k Keyring) Open(p *EncryptedPayload) ([]byte, error) {
	return k.OpenWithSuite(p, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), nil)
}

// OpenWithSuite decrypts an EncryptedPayload using the matching key ID from the keyring with specified cipher suite.
func (k Keyring) OpenWithSuite(p *EncryptedPayload, kdf hpke.KDF, aead hpke.AEAD, info []byte) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("nil encrypted payload")
	}
	priv, ok := k[p.KeyID]
	if !ok {
		return nil, fmt.Errorf("key %q not found in keyring", p.KeyID)
	}
	return p.Open(priv, kdf, aead, info)
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
