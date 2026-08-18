// Copyright (c) 2026, Janoš Guljaš <janos@resenje.org>
// All rights reserved.

package sajberpank

import (
	"context"
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
