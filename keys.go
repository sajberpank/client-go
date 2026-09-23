// Copyright (c) 2026, Janoš Guljaš <janos@resenje.org>
// All rights reserved.

package sajberpank

import (
	"context"
	"crypto/hpke"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// KeysService handles registration and retrieval of HPKE public encryption keys.
type KeysService service

// AddKeyOptions contains parameters for uploading a public key.
type AddKeyOptions struct {
	Name      string
	PublicKey []byte
	KEM       string
	KDF       string
	AEAD      string
}

// Key represents a stored public key configuration.
type Key struct {
	Name      string
	PublicKey string
	KEM       string
	KDF       string
	AEAD      string
	CreatedAt time.Time
}

// PublicKeyBytes decodes the base64-encoded public key to raw bytes.
func (k *Key) PublicKeyBytes() ([]byte, error) {
	return base64.StdEncoding.DecodeString(k.PublicKey)
}

type keyResponseBody struct {
	Name      string    `json:"name"`
	PublicKey string    `json:"public_key"`
	KEM       string    `json:"kem"`
	KDF       string    `json:"kdf"`
	AEAD      string    `json:"aead"`
	CreatedAt time.Time `json:"created_at"`
}

type addKeyRequestBody struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	KEM       string `json:"kem,omitempty"`
	KDF       string `json:"kdf,omitempty"`
	AEAD      string `json:"aead,omitempty"`
}

type listKeysResponseBody struct {
	Keys []keyResponseBody `json:"keys"`
}

// Add uploads a new public key.
func (s *KeysService) Add(ctx context.Context, o AddKeyOptions) (*Key, error) {
	if strings.TrimSpace(o.Name) == "" {
		return nil, ErrInvalidKeyName
	}

	body := addKeyRequestBody{
		Name:      o.Name,
		PublicKey: base64.StdEncoding.EncodeToString(o.PublicKey),
		KEM:       o.KEM,
		KDF:       o.KDF,
		AEAD:      o.AEAD,
	}

	var respBody keyResponseBody
	if err := s.client.request(ctx, http.MethodPost, "/v1/search/keys", body, &respBody); err != nil {
		return nil, err
	}
	key := Key(respBody)
	return &key, nil
}

// Get retrieves metadata of a public key by name.
func (s *KeysService) Get(ctx context.Context, name string) (*Key, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrInvalidKeyName
	}
	path := fmt.Sprintf("/v1/search/keys/%s", url.PathEscape(name))
	var respBody keyResponseBody
	if err := s.client.request(ctx, http.MethodGet, path, nil, &respBody); err != nil {
		return nil, err
	}
	key := Key(respBody)
	return &key, nil
}

// List returns all stored public keys for the current authenticated account.
func (s *KeysService) List(ctx context.Context) ([]Key, error) {
	var respBody listKeysResponseBody
	if err := s.client.request(ctx, http.MethodGet, "/v1/search/keys", nil, &respBody); err != nil {
		return nil, err
	}
	keys := make([]Key, len(respBody.Keys))
	for i, k := range respBody.Keys {
		keys[i] = Key(k)
	}
	return keys, nil
}

// Delete removes a stored public key by name.
func (s *KeysService) Delete(ctx context.Context, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return ErrInvalidKeyName
	}
	path := fmt.Sprintf("/v1/search/keys/%s", url.PathEscape(name))
	return s.client.request(ctx, http.MethodDelete, path, nil, nil)
}

// RotateOptions contains parameters for rotating from an old key to a new key.
type RotateOptions struct {
	// OldKeyName is the registered name of the key to migrate away from.
	OldKeyName string
	// NewKeyName is the registered name of the key to migrate to.
	// This key must already be registered with Search.Keys.Add before calling Rotate.
	NewKeyName string
	// OldPrivateKey is the recipient private key for OldKeyName, used strictly locally
	// to decrypt the wrapped symmetric key for each point. It is never transmitted to the server.
	OldPrivateKey hpke.PrivateKey
	// OldDecryptOptions specifies optional cipher suite parameters (e.g. WithSuite, WithInfo)
	// needed to decrypt envelopes wrapped with OldKeyName if it used non-default algorithms.
	OldDecryptOptions []DecryptOption
	// ProgressCallback is an optional hook invoked after each batch with the running total of migrated items.
	ProgressCallback func(migratedCount int)
}

// RotateResult contains the outcome of a key rotation operation.
type RotateResult struct {
	// UpdatedCount is the total number of document and keyword key envelopes re-encrypted.
	UpdatedCount int
}

type rotateKeysEntryBody struct {
	ID          string          `json:"id"`
	KeyEnvelope keyEnvelopeBody `json:"key_envelope"`
}

type rotateKeysRequestBody struct {
	OldKeyName string                `json:"old_key_name,omitempty"`
	NewKeyName string                `json:"new_key_name,omitempty"`
	SessionID  string                `json:"session_id,omitempty"`
	Entries    []rotateKeysEntryBody `json:"entries,omitempty"`
}

type rotateKeysResponseBody struct {
	SessionID    string                `json:"session_id,omitempty"`
	Entries      []rotateKeysEntryBody `json:"entries,omitempty"`
	Done         bool                  `json:"done"`
	UpdatedCount int                   `json:"updated_count"`
}

// Rotate migrates all documents and keywords encrypted with OldKeyName to NewKeyName.
//
// Key Rotation Workflow:
//  1. Generate a new HPKE key pair locally (e.g. via GenerateX25519Key).
//  2. Register the new public key using Search.Keys.Add with NewKeyName.
//  3. Add the new private key to your application's Keyring alongside OldPrivateKey
//     so that live searches during migration can decrypt both old and new items.
//  4. Call Rotate with OldKeyName, NewKeyName, and OldPrivateKey.
//  5. Once Rotate completes, safely delete the old key using Search.Keys.Delete.
//
// Security & Operation Guarantees:
//   - Zero-Knowledge Security: OldPrivateKey is executed strictly in memory on the client
//     machine to decrypt data encryption keys. It is never sent to the server.
//   - NewPrivateKey Not Needed: Re-encryption only requires the public key of NewKeyName,
//     which Rotate retrieves automatically from the API.
//   - Zero Downtime: Document text, vectors, and metadata fields are untouched.
//     Only 32-byte key envelopes are re-encrypted in streaming atomic batches.
//   - Resumable & Idempotent: If interrupted by a network issue, re-running Rotate with the
//     same parameters safely resumes from the remaining unmigrated envelopes.
func (s *KeysService) Rotate(ctx context.Context, o RotateOptions) (*RotateResult, error) {
	if strings.TrimSpace(o.OldKeyName) == "" {
		return nil, ErrInvalidKeyName
	}
	if strings.TrimSpace(o.NewKeyName) == "" {
		return nil, ErrInvalidKeyName
	}
	if o.OldPrivateKey == nil {
		return nil, fmt.Errorf("old private key is required")
	}

	newKey, err := s.Get(ctx, o.NewKeyName)
	if err != nil {
		return nil, fmt.Errorf("get new key %q: %w", o.NewKeyName, err)
	}
	newPublicKey, err := newKey.PublicKeyBytes()
	if err != nil {
		return nil, fmt.Errorf("decode new public key %q: %w", o.NewKeyName, err)
	}

	kem, kdf, aead, err := resolveSuite(newKey.KEM, newKey.KDF, newKey.AEAD)
	if err != nil {
		return nil, fmt.Errorf("resolve cipher suite for new key %q: %w", o.NewKeyName, err)
	}

	// 1. Initial request to start rotation session
	reqBody := rotateKeysRequestBody{
		OldKeyName: o.OldKeyName,
		NewKeyName: o.NewKeyName,
	}
	var respBody rotateKeysResponseBody
	if err := s.client.request(ctx, http.MethodPost, "/v1/search/keys/rotate", reqBody, &respBody); err != nil {
		return nil, err
	}

	totalUpdated := respBody.UpdatedCount

	for !respBody.Done {
		items := respBody.Entries
		if len(items) == 0 {
			break
		}

		for i, item := range items {
			ek := KeyEnvelope(item.KeyEnvelope)
			symKey, err := ek.DecryptKey(o.OldPrivateKey, o.OldDecryptOptions...)
			if err != nil {
				return nil, fmt.Errorf("decrypt symmetric key for item %s: %w", item.ID, err)
			}
			newEk, err := newKeyEnvelopeWithSuite(newPublicKey, o.NewKeyName, symKey, kem, kdf, aead, nil)
			if err != nil {
				return nil, fmt.Errorf("re-encrypt symmetric key for item %s: %w", item.ID, err)
			}
			items[i].KeyEnvelope = keyEnvelopeBody(*newEk)
		}

		reqBody = rotateKeysRequestBody{
			SessionID: respBody.SessionID,
			Entries:   items,
		}
		respBody = rotateKeysResponseBody{}
		if err := s.client.request(ctx, http.MethodPost, "/v1/search/keys/rotate", reqBody, &respBody); err != nil {
			return nil, err
		}

		totalUpdated = respBody.UpdatedCount
		if o.ProgressCallback != nil {
			o.ProgressCallback(totalUpdated)
		}
	}

	return &RotateResult{
		UpdatedCount: totalUpdated,
	}, nil
}
