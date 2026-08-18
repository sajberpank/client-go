// Copyright (c) 2026, Janoš Guljaš <janos@resenje.org>
// All rights reserved.

package sajberpank

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// API Key permission scopes
const (
	ScopeAll             = "*"
	ScopeSearch          = "search"
	ScopeDocumentsAll    = "documents:*"
	ScopeDocumentsRead   = "documents:read"
	ScopeDocumentsWrite  = "documents:write"
	ScopeDocumentsDelete = "documents:delete"
	ScopeKeysAll         = "keys:*"
	ScopeKeysRead        = "keys:read"
	ScopeKeysWrite       = "keys:write"
	ScopeKeysDelete      = "keys:delete"
	ScopeAccountKeys     = "account:keys"
)

// AccountService handles operations for account management.
type AccountService struct {
	client *Client
	Keys   *AccountKeysService
}

// AccountKeysService handles management of API keys for the authenticated account.
type AccountKeysService service

// AccountKey represents an API key metadata item.
type AccountKey struct {
	ID         string
	Name       string
	Prefix     string
	Scopes     []string
	ExpiresAt  *time.Time
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// AccountKeyDetails represents newly created API key including the raw secret.
type AccountKeyDetails struct {
	AccountKey
	APIKey string
}

// CreateKeyOptions specifies optional configuration when creating a new API key.
type CreateKeyOptions struct {
	Name      string
	Scopes    []string
	ExpiresAt *time.Time
}

type accountKeyResponseBody struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Scopes     []string   `json:"scopes,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

type accountKeyDetailsResponseBody struct {
	accountKeyResponseBody
	APIKey string `json:"api_key"`
}

type createAccountKeyRequestBody struct {
	Name      string   `json:"name,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
	ExpiresAt *string  `json:"expires_at,omitempty"`
}

type listAccountKeysResponseBody struct {
	Keys []accountKeyResponseBody `json:"keys"`
}

// Create generates a new API key for the authenticated account with default scopes (*).
func (s *AccountKeysService) Create(ctx context.Context, name string) (*AccountKeyDetails, error) {
	return s.CreateWithOptions(ctx, CreateKeyOptions{Name: name})
}

// CreateWithOptions generates a new API key with specific scopes and optional expiration.
func (s *AccountKeysService) CreateWithOptions(ctx context.Context, o CreateKeyOptions) (*AccountKeyDetails, error) {
	var expStr *string
	if o.ExpiresAt != nil {
		formatted := o.ExpiresAt.UTC().Format(time.RFC3339)
		expStr = &formatted
	}

	body := createAccountKeyRequestBody{
		Name:      strings.TrimSpace(o.Name),
		Scopes:    o.Scopes,
		ExpiresAt: expStr,
	}

	var respBody accountKeyDetailsResponseBody
	if err := s.client.request(ctx, http.MethodPost, "/v1/account/keys", body, &respBody); err != nil {
		return nil, err
	}

	resp := AccountKeyDetails{
		AccountKey: AccountKey(respBody.accountKeyResponseBody),
		APIKey:     respBody.APIKey,
	}
	return &resp, nil
}

// List returns all active API keys for the authenticated account.
func (s *AccountKeysService) List(ctx context.Context) ([]AccountKey, error) {
	var respBody listAccountKeysResponseBody
	if err := s.client.request(ctx, http.MethodGet, "/v1/account/keys", nil, &respBody); err != nil {
		return nil, err
	}
	keys := make([]AccountKey, len(respBody.Keys))
	for i, k := range respBody.Keys {
		keys[i] = AccountKey(k)
	}
	return keys, nil
}

// Revoke invalidates an API key by its key ID.
func (s *AccountKeysService) Revoke(ctx context.Context, keyID string) error {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return ErrInvalidKey
	}
	return s.client.request(ctx, http.MethodDelete, "/v1/account/keys/"+url.PathEscape(keyID), nil, nil)
}
