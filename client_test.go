// Copyright (c) 2026, Janoš Guljaš <janos@resenje.org>
// All rights reserved.

package sajberpank_test

import (
	"context"
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	client "sajberpank.rs/sajberpank"
)

const testAPIKey = "sp_live_d47f98d5_7a8607bf3bc7ec21c43232bb256b1076ee212a44f51be02f"

func newTestServer(t *testing.T, handler http.HandlerFunc) (*client.Client, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	parsedURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}

	c := client.New(testAPIKey, &client.ClientOptions{
		BaseURL: parsedURL,
	})
	return c, ts
}

func TestAccountKeysService(t *testing.T) {
	ctx := context.Background()

	t.Run("Create with defaults", func(t *testing.T) {
		var receivedBody map[string]any
		var receivedAuth string

		c, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			receivedAuth = r.Header.Get("Authorization")
			_ = json.NewDecoder(r.Body).Decode(&receivedBody)

			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":         "key_12345",
				"name":       receivedBody["name"],
				"prefix":     "sp_live_12345678",
				"api_key":    "sp_live_12345678_rawsecretkeyvalue",
				"scopes":     []string{"*"},
				"created_at": time.Now().UTC(),
			})
		})

		k, err := c.Account.Keys.Create(ctx, "Ingestion Worker")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if k.ID != "key_12345" || k.Name != "Ingestion Worker" || k.APIKey == "" {
			t.Errorf("unexpected created key: %+v", k)
		}
		if receivedAuth != "Bearer "+testAPIKey {
			t.Errorf("unexpected auth header: %q", receivedAuth)
		}
	})

	t.Run("CreateWithOptions with scopes and expiration", func(t *testing.T) {
		var receivedBody map[string]any
		exp := time.Now().UTC().Add(24 * time.Hour)

		c, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&receivedBody)

			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":         "key_scoped",
				"name":       receivedBody["name"],
				"prefix":     "sp_live_scoped12",
				"api_key":    "sp_live_scoped12_rawsecretkeyvalue",
				"scopes":     receivedBody["scopes"],
				"expires_at": receivedBody["expires_at"],
				"created_at": time.Now().UTC(),
			})
		})

		k, err := c.Account.Keys.CreateWithOptions(ctx, client.CreateKeyOptions{
			Name:      "Search Only Key",
			Scopes:    []string{client.ScopeSearch},
			ExpiresAt: &exp,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if k.ID != "key_scoped" || len(k.Scopes) != 1 || k.Scopes[0] != client.ScopeSearch {
			t.Errorf("unexpected key response: %+v", k)
		}
	})

	t.Run("List", func(t *testing.T) {
		c, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]any{
					{
						"id":     "key_1",
						"name":   "Worker 1",
						"prefix": "sp_live_11111111",
						"scopes": []string{"*"},
					},
					{
						"id":     "key_2",
						"name":   "Worker 2",
						"prefix": "sp_live_22222222",
						"scopes": []string{"search"},
					},
				},
			})
		})

		keys, err := c.Account.Keys.List(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(keys) != 2 {
			t.Fatalf("expected 2 keys, got %d", len(keys))
		}
	})

	t.Run("Revoke", func(t *testing.T) {
		c, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodDelete && r.URL.Path == "/v1/account/keys/key_123" {
				w.WriteHeader(http.StatusOK)
				return
			}
			http.Error(w, "not found", http.StatusNotFound)
		})

		if err := c.Account.Keys.Revoke(ctx, "key_123"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestKeysService(t *testing.T) {
	ctx := context.Background()
	_, pubBytes, err := client.GenerateX25519Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	t.Run("Add", func(t *testing.T) {
		var receivedBody map[string]any
		var receivedAuth string
		var receivedUserAgent string

		c, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			receivedAuth = r.Header.Get("Authorization")
			receivedUserAgent = r.Header.Get("User-Agent")
			_ = json.NewDecoder(r.Body).Decode(&receivedBody)

			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name":       receivedBody["name"],
				"public_key": receivedBody["public_key"],
				"kem":        "HPKE_KEM_DHKEM_X25519_HKDF_SHA256",
				"kdf":        "HPKE_KDF_HKDF_SHA256",
				"aead":       "HPKE_AEAD_CHACHA20_POLY1305",
				"created_at": time.Now().UTC(),
			})
		})

		k, err := c.Search.Keys.Add(ctx, client.AddKeyOptions{
			Name:      "test-key",
			PublicKey: pubBytes,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if k.Name != "test-key" {
			t.Errorf("got name %q, want test-key", k.Name)
		}
		if receivedAuth != "Bearer "+testAPIKey {
			t.Errorf("unexpected auth header: %q", receivedAuth)
		}
		if receivedUserAgent == "" {
			t.Error("expected user-agent to be set")
		}
	})

	t.Run("Get", func(t *testing.T) {
		c, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/search/keys/test-key" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"name":       "test-key",
					"public_key": base64.StdEncoding.EncodeToString(pubBytes),
					"kem":        "HPKE_KEM_DHKEM_X25519_HKDF_SHA256",
					"kdf":        "HPKE_KDF_HKDF_SHA256",
					"aead":       "HPKE_AEAD_CHACHA20_POLY1305",
				})
				return
			}
			http.Error(w, "not found", http.StatusNotFound)
		})

		k, err := c.Search.Keys.Get(ctx, "test-key")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if k.Name != "test-key" {
			t.Errorf("got name %q, want test-key", k.Name)
		}
	})

	t.Run("List", func(t *testing.T) {
		c, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]any{
					{
						"name":       "test-key-1",
						"public_key": base64.StdEncoding.EncodeToString(pubBytes),
					},
					{
						"name":       "test-key-2",
						"public_key": base64.StdEncoding.EncodeToString(pubBytes),
					},
				},
			})
		})

		keys, err := c.Search.Keys.List(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(keys) != 2 {
			t.Errorf("expected 2 keys, got %d", len(keys))
		}
	})

	t.Run("Delete", func(t *testing.T) {
		c, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodDelete && r.URL.Path == "/v1/search/keys/test-key" {
				w.WriteHeader(http.StatusOK)
				return
			}
			http.Error(w, "not found", http.StatusNotFound)
		})

		if err := c.Search.Keys.Delete(ctx, "test-key"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestDocumentsService(t *testing.T) {
	ctx := context.Background()

	t.Run("Add with Text", func(t *testing.T) {
		var receivedBody map[string]any

		c, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/v1/search/documents" {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			_ = json.NewDecoder(r.Body).Decode(&receivedBody)

			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":        receivedBody["id"],
				"namespace": receivedBody["namespace"].(string) + ":" + receivedBody["category"].(string),
				"added":     true,
			})
		})

		ts := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
		resp, err := c.Search.Documents.Add(ctx, client.DocumentOptions{
			Namespace:    "insureme",
			Category:     "policy",
			ID:           "POL-12345",
			KeyName:      "primary-key",
			Content:      client.Text("Policy coverage text goes here."),
			DocumentTime: &ts,
			Fields: map[string]string{
				"category": "health",
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.ID != "POL-12345" || !resp.Added {
			t.Errorf("unexpected response: %+v", resp)
		}
		if receivedBody["text"] != "Policy coverage text goes here." {
			t.Errorf("got text %v", receivedBody["text"])
		}
	})

	t.Run("Add with Pages", func(t *testing.T) {
		var receivedBody map[string]any
		c, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&receivedBody)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":        receivedBody["id"],
				"namespace": receivedBody["namespace"].(string) + ":" + receivedBody["category"].(string),
				"added":     true,
			})
		})

		resp, err := c.Search.Documents.Add(ctx, client.DocumentOptions{
			Namespace: "insureme",
			Category:  "report",
			ID:        "REP-100",
			KeyName:   "primary-key",
			Content: client.Pages{
				{PageNumber: 1, Text: "Page 1 text"},
				{PageNumber: 2, Text: "Page 2 text"},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.ID != "REP-100" {
			t.Errorf("unexpected response: %+v", resp)
		}
		pagesList, ok := receivedBody["pages"].([]any)
		if !ok || len(pagesList) != 2 {
			t.Fatalf("expected 2 pages sent, got %+v", receivedBody["pages"])
		}
	})

	t.Run("Add with Sentences", func(t *testing.T) {
		var receivedBody map[string]any
		c, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&receivedBody)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":        receivedBody["id"],
				"namespace": receivedBody["namespace"].(string) + ":" + receivedBody["category"].(string),
				"added":     true,
			})
		})

		resp, err := c.Search.Documents.Add(ctx, client.DocumentOptions{
			Namespace: "insureme",
			Category:  "contract",
			ID:        "CTR-100",
			KeyName:   "primary-key",
			Content: client.Sentences{
				{Text: "Sentence 1", PageNumber: 1, Reference: "sec-1"},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.ID != "CTR-100" {
			t.Errorf("unexpected response: %+v", resp)
		}
	})

	t.Run("Add with nil Content fails client validation", func(t *testing.T) {
		c := client.New(testAPIKey, nil)
		_, err := c.Search.Documents.Add(ctx, client.DocumentOptions{
			Namespace: "insureme",
			Category:  "policy",
			ID:        "POL-1",
			KeyName:   "key",
			Content:   nil,
		})
		if !errors.Is(err, client.ErrMissingDocumentContent) {
			t.Errorf("expected ErrMissingDocumentContent, got %v", err)
		}
	})

	t.Run("GetStatus", func(t *testing.T) {
		c, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/search/documents/insureme/policy/POL-12345" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"exists":        true,
					"is_complete":   true,
					"chunk_count":   2,
					"total_tokens":  300,
					"pages":         []int{1, 2},
					"references":    []string{"sec-1", "para-2"},
					"add_time":      "2026-08-18T12:00:00Z",
					"document_time": "2026-08-16T12:00:00Z",
				})
				return
			}
			http.Error(w, "not found", http.StatusNotFound)
		})

		status, err := c.Search.Documents.GetStatus(ctx, "insureme", "policy", "POL-12345")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !status.Exists || !status.IsComplete {
			t.Errorf("unexpected status: %+v", status)
		}
		if status.ChunkCount != 2 {
			t.Errorf("unexpected chunk count: %d", status.ChunkCount)
		}
		if len(status.Pages) != 2 || len(status.References) != 2 {
			t.Errorf("unexpected pages/references: %v / %v", status.Pages, status.References)
		}
		if status.DocumentTime == nil || !status.DocumentTime.Equal(time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)) {
			t.Errorf("unexpected document_time: %v", status.DocumentTime)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		c, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodDelete && r.URL.Path == "/v1/search/documents/insureme/policy/POL-12345" {
				w.WriteHeader(http.StatusOK)
				return
			}
			http.Error(w, "not found", http.StatusNotFound)
		})

		if err := c.Search.Documents.Delete(ctx, "insureme", "policy", "POL-12345"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestSearchService(t *testing.T) {
	ctx := context.Background()

	priv, pubBytes, err := client.GenerateX25519Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	kem := hpke.DHKEM(ecdh.X25519())
	kdf := hpke.HKDFSHA256()
	aead := hpke.ChaCha20Poly1305()

	pubKey, err := kem.NewPublicKey(pubBytes)
	if err != nil {
		t.Fatalf("new public key: %v", err)
	}

	encap, sealer, err := hpke.NewSender(pubKey, kdf, aead, nil)
	if err != nil {
		t.Fatalf("new sender: %v", err)
	}
	ciphertext, err := sealer.Seal(nil, []byte("Decrypted policy content matching query."))
	if err != nil {
		t.Fatalf("sealer seal: %v", err)
	}

	encapB64 := base64.StdEncoding.EncodeToString(encap)
	cipherB64 := base64.StdEncoding.EncodeToString(ciphertext)

	t.Run("Search and Decrypt", func(t *testing.T) {
		c, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/v1/search/query" {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}

			expectedTime := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"results": []map[string]any{
					{
						"id":            "POL-999",
						"namespace":     "insureme",
						"category":      "policy",
						"score":         0.88,
						"pages":         []int32{1, 2},
						"references":    []string{"sec-1.1", "sec-1.2"},
						"add_time":      expectedTime.Format(time.RFC3339),
						"document_time": expectedTime.Format(time.RFC3339),
						"encrypted_text": map[string]any{
							"key_id":     "test-key",
							"enc":        encapB64,
							"ciphertext": cipherB64,
						},
					},
				},
			})
		})

		resp, err := c.Search.Query(ctx, client.SearchOptions{
			Namespace:  "insureme",
			Categories: []string{"policy"},
			Query:      "policy coverage",
		})
		if err != nil {
			t.Fatalf("search query failed: %v", err)
		}
		if len(resp.Results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(resp.Results))
		}

		res := resp.Results[0]
		if len(res.Pages) != 2 || res.Pages[0] != 1 || res.Pages[1] != 2 {
			t.Errorf("unexpected Pages: %v", res.Pages)
		}
		if len(res.References) != 2 || res.References[0] != "sec-1.1" || res.References[1] != "sec-1.2" {
			t.Errorf("unexpected References: %v", res.References)
		}
		if !res.AddTime.Equal(time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)) {
			t.Errorf("unexpected AddTime: %v", res.AddTime)
		}
		if res.DocumentTime == nil || !res.DocumentTime.Equal(time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)) {
			t.Errorf("unexpected DocumentTime: %v", res.DocumentTime)
		}

		decrypted, err := resp.Results[0].EncryptedText.Open(priv, kdf, aead, nil)
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}
		if string(decrypted) != "Decrypted policy content matching query." {
			t.Errorf("got decrypted text %q", string(decrypted))
		}

		// Test OpenDefault
		decryptedDefault, err := resp.Results[0].EncryptedText.OpenDefault(priv)
		if err != nil {
			t.Fatalf("decrypt default failed: %v", err)
		}
		if string(decryptedDefault) != "Decrypted policy content matching query." {
			t.Errorf("got decrypted text %q", string(decryptedDefault))
		}

		// Test DecryptText helper
		text, err := resp.Results[0].DecryptText(priv)
		if err != nil {
			t.Fatalf("DecryptText failed: %v", err)
		}
		if text != "Decrypted policy content matching query." {
			t.Errorf("got decrypted text %q", text)
		}

		// Test Keyring
		ring := client.Keyring{
			"test-key": priv,
		}
		ringDecrypted, err := ring.Open(resp.Results[0].EncryptedText)
		if err != nil {
			t.Fatalf("keyring open failed: %v", err)
		}
		if string(ringDecrypted) != "Decrypted policy content matching query." {
			t.Errorf("got keyring decrypted text %q", string(ringDecrypted))
		}

		// Test Keyring missing key
		emptyRing := client.Keyring{}
		if _, err := emptyRing.Open(resp.Results[0].EncryptedText); err == nil {
			t.Errorf("expected error for missing key in keyring, got nil")
		}
	})

	t.Run("Similarity Search with Positive and Strategy", func(t *testing.T) {
		var receivedBody map[string]any
		c, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&receivedBody)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"results": []map[string]any{
					{
						"id":        "POL-888",
						"namespace": "insureme",
						"category":  "policy",
						"score":     0.95,
					},
				},
			})
		})

		resp, err := c.Search.Query(ctx, client.SearchOptions{
			Namespace:  "insureme",
			Categories: []string{"policy"},
			Similarity: &client.SimilarityOptions{
				Positive: []client.SimilarityDocument{
					{ID: "POL-999", Category: "policy"},
				},
				Negative: []client.SimilarityDocument{
					{ID: "POL-111", Category: "policy"},
				},
			},
		})
		if err != nil {
			t.Fatalf("similarity query failed: %v", err)
		}
		if len(resp.Results) != 1 || resp.Results[0].ID != "POL-888" {
			t.Errorf("unexpected results: %+v", resp.Results)
		}

		simMap, ok := receivedBody["similarity"].(map[string]any)
		if !ok {
			t.Errorf("unexpected similarity payload sent: %+v", receivedBody["similarity"])
		}
		negList, ok := simMap["negative"].([]any)
		if !ok || len(negList) != 1 {
			t.Errorf("expected 1 negative document sent, got %+v", simMap["negative"])
		}
	})
}

func TestErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("BadRequest with structured validation errors", func(t *testing.T) {
		c, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":    400,
				"message": "Bad Request",
				"errors": []map[string]any{
					{
						"field":   "categories",
						"reason":  client.ReasonMissing,
						"message": "at least one category is required",
					},
					{
						"field":   "query",
						"reason":  client.ReasonMissing,
						"message": "query cannot be empty",
					},
				},
			})
		})

		_, err := c.Search.Query(ctx, client.SearchOptions{Namespace: "test"})
		var badReq *client.BadRequestError
		if !errors.As(err, &badReq) {
			t.Fatalf("expected *BadRequestError, got %T (%v)", err, err)
		}
		if len(badReq.FieldErrors()) != 2 {
			t.Errorf("expected 2 field errors, got %d", len(badReq.FieldErrors()))
		}
		if !badReq.HasReason(client.ReasonMissing) {
			t.Errorf("expected HasReason(ReasonMissing) to be true")
		}
		if !badReq.HasField("categories") || !badReq.HasField("query") {
			t.Errorf("expected HasField for categories and query to be true")
		}
		if !badReq.HasFieldReason("categories", client.ReasonMissing) {
			t.Errorf("expected HasFieldReason(categories, ReasonMissing) to be true")
		}
	})

	t.Run("Unauthorized with and without message", func(t *testing.T) {
		c1, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":    401,
				"message": "Invalid API Key format",
			})
		})

		_, err := c1.Search.Keys.List(ctx)
		if !errors.Is(err, client.ErrUnauthorized) {
			t.Errorf("expected ErrUnauthorized, got %v", err)
		}
		if !strings.Contains(err.Error(), "Invalid API Key format") {
			t.Errorf("expected wrapped message in error, got %q", err.Error())
		}

		// Without message
		c2, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		})
		_, err = c2.Search.Keys.List(ctx)
		if !errors.Is(err, client.ErrUnauthorized) {
			t.Errorf("expected ErrUnauthorized, got %v", err)
		}
		if err.Error() != "unauthorized" {
			t.Errorf("got %q, want 'unauthorized'", err.Error())
		}
	})

	t.Run("Forbidden with and without message", func(t *testing.T) {
		c1, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":    403,
				"message": "Scope keys:read is required",
			})
		})

		_, err := c1.Account.Keys.List(ctx)
		if !errors.Is(err, client.ErrForbidden) {
			t.Errorf("expected ErrForbidden, got %v", err)
		}
		if !strings.Contains(err.Error(), "Scope keys:read is required") {
			t.Errorf("expected wrapped message in error, got %q", err.Error())
		}

		// Without message
		c2, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		})
		_, err = c2.Account.Keys.List(ctx)
		if !errors.Is(err, client.ErrForbidden) {
			t.Errorf("expected ErrForbidden, got %v", err)
		}
		if err.Error() != "forbidden" {
			t.Errorf("got %q, want 'forbidden'", err.Error())
		}
	})

	t.Run("NotFound with and without message", func(t *testing.T) {
		c1, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":    404,
				"message": "Key not found",
			})
		})

		_, err := c1.Search.Keys.Get(ctx, "non-existent")
		if !errors.Is(err, client.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
		if !strings.Contains(err.Error(), "Key not found") {
			t.Errorf("expected error string to contain 'Key not found', got %q", err.Error())
		}

		// Without message
		c2, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})
		_, err = c2.Search.Keys.Get(ctx, "non-existent")
		if !errors.Is(err, client.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
		if err.Error() != "not found" {
			t.Errorf("got %q, want 'not found'", err.Error())
		}
	})

	t.Run("Conflict with and without message", func(t *testing.T) {
		c1, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":    409,
				"message": "Key with name already exists",
			})
		})

		_, err := c1.Search.Keys.Add(ctx, client.AddKeyOptions{Name: "existing-key"})
		if !errors.Is(err, client.ErrConflict) {
			t.Errorf("expected ErrConflict, got %v", err)
		}
		if !strings.Contains(err.Error(), "Key with name already exists") {
			t.Errorf("expected error string to contain 'Key with name already exists', got %q", err.Error())
		}

		// Without message
		c2, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusConflict)
		})
		_, err = c2.Search.Keys.Add(ctx, client.AddKeyOptions{Name: "existing-key"})
		if !errors.Is(err, client.ErrConflict) {
			t.Errorf("expected ErrConflict, got %v", err)
		}
		if err.Error() != "conflict" {
			t.Errorf("got %q, want 'conflict'", err.Error())
		}
	})

	t.Run("TooManyRequests with and without message", func(t *testing.T) {
		c1, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":    429,
				"message": "Rate limit exceeded. Retry in 10s",
			})
		})

		_, err := c1.Search.Keys.List(ctx)
		if !errors.Is(err, client.ErrTooManyRequests) {
			t.Errorf("expected ErrTooManyRequests, got %v", err)
		}
		if !strings.Contains(err.Error(), "Rate limit exceeded") {
			t.Errorf("expected error string to contain 'Rate limit exceeded', got %q", err.Error())
		}

		// Without message
		c2, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		})
		_, err = c2.Search.Keys.List(ctx)
		if !errors.Is(err, client.ErrTooManyRequests) {
			t.Errorf("expected ErrTooManyRequests, got %v", err)
		}
		if err.Error() != "too many requests" {
			t.Errorf("got %q, want 'too many requests'", err.Error())
		}
	})

	t.Run("InternalServerError with and without message", func(t *testing.T) {
		c1, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":    500,
				"message": "Database connection error",
			})
		})

		_, err := c1.Search.Keys.List(ctx)
		if !errors.Is(err, client.ErrInternalServerError) {
			t.Errorf("expected ErrInternalServerError, got %v", err)
		}
		if !strings.Contains(err.Error(), "Database connection error") {
			t.Errorf("expected error string to contain 'Database connection error', got %q", err.Error())
		}

		// Without message
		c2, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		_, err = c2.Search.Keys.List(ctx)
		if !errors.Is(err, client.ErrInternalServerError) {
			t.Errorf("expected ErrInternalServerError, got %v", err)
		}
		if err.Error() != "internal server error" {
			t.Errorf("got %q, want 'internal server error'", err.Error())
		}
	})

	t.Run("APIError for unhandled status codes", func(t *testing.T) {
		// With message
		c1, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":    502,
				"message": "Upstream service timeout",
			})
		})
		_, err := c1.Search.Keys.List(ctx)
		var apiErr *client.APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("expected *client.APIError, got %T (%v)", err, err)
		}
		if apiErr.StatusCode != 502 || apiErr.Message != "Upstream service timeout" {
			t.Errorf("unexpected APIError: %+v", apiErr)
		}
		if apiErr.Error() != "api error (502): Upstream service timeout" {
			t.Errorf("got %q, want 'api error (502): Upstream service timeout'", apiErr.Error())
		}

		// Without message
		c2, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		})
		_, err = c2.Search.Keys.List(ctx)
		if !errors.As(err, &apiErr) {
			t.Fatalf("expected *client.APIError, got %T (%v)", err, err)
		}
		if apiErr.StatusCode != 503 || apiErr.Message != "Service Unavailable" {
			t.Errorf("unexpected APIError: %+v", apiErr)
		}
	})

	t.Run("Client-side validation error sentinels", func(t *testing.T) {
		c := client.New(testAPIKey, nil)

		if err := c.Account.Keys.Revoke(ctx, ""); !errors.Is(err, client.ErrInvalidKey) {
			t.Errorf("expected ErrInvalidKey, got %v", err)
		}

		if _, err := c.Search.Keys.Get(ctx, ""); !errors.Is(err, client.ErrInvalidKeyName) {
			t.Errorf("expected ErrInvalidKeyName, got %v", err)
		}

		if _, err := c.Search.Documents.GetStatus(ctx, "", "policy", "DOC-1"); !errors.Is(err, client.ErrInvalidNamespace) {
			t.Errorf("expected ErrInvalidNamespace, got %v", err)
		}

		if _, err := c.Search.Documents.GetStatus(ctx, "ns", "", "DOC-1"); !errors.Is(err, client.ErrInvalidCategory) {
			t.Errorf("expected ErrInvalidCategory, got %v", err)
		}

		if _, err := c.Search.Documents.GetStatus(ctx, "ns", "policy", ""); !errors.Is(err, client.ErrInvalidDocumentID) {
			t.Errorf("expected ErrInvalidDocumentID, got %v", err)
		}

		// Documents.Add validation
		if _, err := c.Search.Documents.Add(ctx, client.DocumentOptions{Namespace: "", Category: "policy", ID: "1", KeyName: "k", Content: client.Text("hi")}); !errors.Is(err, client.ErrInvalidNamespace) {
			t.Errorf("expected ErrInvalidNamespace, got %v", err)
		}
		if _, err := c.Search.Documents.Add(ctx, client.DocumentOptions{Namespace: "ns", Category: "", ID: "1", KeyName: "k", Content: client.Text("hi")}); !errors.Is(err, client.ErrInvalidCategory) {
			t.Errorf("expected ErrInvalidCategory, got %v", err)
		}
		if _, err := c.Search.Documents.Add(ctx, client.DocumentOptions{Namespace: "ns", Category: "cat", ID: "", KeyName: "k", Content: client.Text("hi")}); !errors.Is(err, client.ErrInvalidDocumentID) {
			t.Errorf("expected ErrInvalidDocumentID, got %v", err)
		}
		if _, err := c.Search.Documents.Add(ctx, client.DocumentOptions{Namespace: "ns", Category: "cat", ID: "1", KeyName: "", Content: client.Text("hi")}); !errors.Is(err, client.ErrInvalidKeyName) {
			t.Errorf("expected ErrInvalidKeyName, got %v", err)
		}

		// Search.Query validation
		if _, err := c.Search.Query(ctx, client.SearchOptions{Namespace: ""}); !errors.Is(err, client.ErrInvalidNamespace) {
			t.Errorf("expected ErrInvalidNamespace, got %v", err)
		}
	})
}

func TestUserAgent(t *testing.T) {
	ctx := context.Background()

	t.Run("Default User-Agent", func(t *testing.T) {
		var receivedUserAgent string
		c, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			receivedUserAgent = r.Header.Get("User-Agent")
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{}})
		})

		_, err := c.Search.Keys.List(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.HasPrefix(receivedUserAgent, "sajberpank-client-go") {
			t.Errorf("expected default prefix, got %q", receivedUserAgent)
		}
	})

	t.Run("Appended User-Agent", func(t *testing.T) {
		var receivedUserAgent string
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedUserAgent = r.Header.Get("User-Agent")
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{}})
		}))
		defer ts.Close()

		u, _ := url.Parse(ts.URL)
		c := client.New(testAPIKey, &client.ClientOptions{
			BaseURL:   u,
			UserAgent: "custom-app/2.5",
		})

		_, err := c.Search.Keys.List(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.HasPrefix(receivedUserAgent, "sajberpank-client-go") || !strings.HasSuffix(receivedUserAgent, "custom-app/2.5") {
			t.Errorf("expected user agent to start with sajberpank-client-go and end with custom-app/2.5, got %q", receivedUserAgent)
		}
	})
}

func TestConvenienceCryptoFunctions(t *testing.T) {
	priv, pubBytes, err := client.GenerateX25519Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	kem := hpke.DHKEM(ecdh.X25519())
	kdf := hpke.HKDFSHA256()
	aead := hpke.ChaCha20Poly1305()

	pubKey, err := kem.NewPublicKey(pubBytes)
	if err != nil {
		t.Fatalf("new public key: %v", err)
	}

	encap, sealer, err := hpke.NewSender(pubKey, kdf, aead, client.DefaultPayloadInfo())
	if err != nil {
		t.Fatalf("new sender: %v", err)
	}
	ciphertext, err := sealer.Seal(nil, []byte("Secret text content"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	payload := &client.EncryptedPayload{
		Enc:        base64.StdEncoding.EncodeToString(encap),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		KeyID:      "key-1",
	}

	t.Run("EncryptedPayload.OpenDefault success", func(t *testing.T) {
		pt, err := payload.OpenDefault(priv)
		if err != nil {
			t.Fatalf("OpenDefault failed: %v", err)
		}
		if string(pt) != "Secret text content" {
			t.Errorf("got %q, want %q", string(pt), "Secret text content")
		}
	})

	t.Run("EncryptedPayload.OpenDefault nil payload", func(t *testing.T) {
		var nilPayload *client.EncryptedPayload
		if _, err := nilPayload.OpenDefault(priv); err == nil {
			t.Error("expected error for nil payload, got nil")
		}
	})

	t.Run("EncryptedPayload.Open error on invalid base64 enc", func(t *testing.T) {
		badPayload := &client.EncryptedPayload{
			Enc:        "invalid base64 !!",
			Ciphertext: payload.Ciphertext,
		}
		if _, err := badPayload.OpenDefault(priv); err == nil {
			t.Error("expected base64 decode error, got nil")
		}
	})

	t.Run("EncryptedPayload.Open error on invalid base64 ciphertext", func(t *testing.T) {
		badPayload := &client.EncryptedPayload{
			Enc:        payload.Enc,
			Ciphertext: "invalid base64 !!",
		}
		if _, err := badPayload.OpenDefault(priv); err == nil {
			t.Error("expected base64 decode error, got nil")
		}
	})

	t.Run("SearchResult.DecryptText success", func(t *testing.T) {
		res := client.SearchResult{
			ID:            "DOC-1",
			EncryptedText: payload,
		}
		text, err := res.DecryptText(priv)
		if err != nil {
			t.Fatalf("DecryptText failed: %v", err)
		}
		if text != "Secret text content" {
			t.Errorf("got %q, want %q", text, "Secret text content")
		}
	})

	t.Run("SearchResult.DecryptText nil EncryptedText", func(t *testing.T) {
		res := client.SearchResult{
			ID:            "DOC-2",
			EncryptedText: nil,
		}
		text, err := res.DecryptText(priv)
		if err != nil {
			t.Fatalf("unexpected error for nil EncryptedText: %v", err)
		}
		if text != "" {
			t.Errorf("expected empty string for nil EncryptedText, got %q", text)
		}
	})

	t.Run("SearchResult.DecryptText error propagation", func(t *testing.T) {
		res := client.SearchResult{
			ID: "DOC-3",
			EncryptedText: &client.EncryptedPayload{
				Enc:        "bad",
				Ciphertext: "bad",
			},
		}
		if _, err := res.DecryptText(priv); err == nil {
			t.Error("expected error on corrupt payload, got nil")
		}
	})

	t.Run("SearchResponse.DecryptKeywords success and nil", func(t *testing.T) {
		resNil := &client.SearchResponse{}
		kws, err := resNil.DecryptKeywords(priv)
		if err != nil {
			t.Fatalf("unexpected error on nil EncryptedKeywords: %v", err)
		}
		if len(kws) != 0 {
			t.Errorf("expected 0 keywords, got %d", len(kws))
		}

		resWithKeywords := &client.SearchResponse{
			EncryptedKeywords: []client.EncryptedPayload{*payload},
		}
		kws, err = resWithKeywords.DecryptKeywords(priv)
		if err != nil {
			t.Fatalf("DecryptKeywords failed: %v", err)
		}
		if len(kws) != 1 || kws[0] != "Secret text content" {
			t.Errorf("unexpected keywords: %v", kws)
		}

		resCorrupt := &client.SearchResponse{
			EncryptedKeywords: []client.EncryptedPayload{
				{Enc: "invalid base64", Ciphertext: "invalid base64"},
			},
		}
		if _, err := resCorrupt.DecryptKeywords(priv); err == nil {
			t.Error("expected error on corrupt keyword, got nil")
		}
	})

	t.Run("SearchResult.DecryptFields success and nil", func(t *testing.T) {
		resNil := client.SearchResult{ID: "DOC-F1"}
		fields, err := resNil.DecryptFields(priv)
		if err != nil {
			t.Fatalf("unexpected error on nil EncryptedFields: %v", err)
		}
		if len(fields) != 0 {
			t.Errorf("expected 0 fields, got %d", len(fields))
		}

		resWithFields := client.SearchResult{
			ID: "DOC-F2",
			EncryptedFields: map[string]client.EncryptedPayload{
				"region": *payload,
			},
		}
		fields, err = resWithFields.DecryptFields(priv)
		if err != nil {
			t.Fatalf("DecryptFields failed: %v", err)
		}
		if len(fields) != 1 || fields["region"] != "Secret text content" {
			t.Errorf("unexpected fields map: %v", fields)
		}

		resCorrupt := client.SearchResult{
			ID: "DOC-F3",
			EncryptedFields: map[string]client.EncryptedPayload{
				"bad": {Enc: "invalid base64", Ciphertext: "invalid base64"},
			},
		}
		if _, err := resCorrupt.DecryptFields(priv); err == nil {
			t.Error("expected error on corrupt field payload, got nil")
		}
	})

	t.Run("Keyring.Open success and missing key", func(t *testing.T) {
		ring := client.Keyring{
			"key-1": priv,
		}

		pt, err := ring.Open(payload)
		if err != nil {
			t.Fatalf("keyring Open failed: %v", err)
		}
		if string(pt) != "Secret text content" {
			t.Errorf("got %q, want %q", string(pt), "Secret text content")
		}

		// Missing key in keyring
		missingPayload := &client.EncryptedPayload{
			Enc:        payload.Enc,
			Ciphertext: payload.Ciphertext,
			KeyID:      "unknown-key",
		}
		if _, err := ring.Open(missingPayload); err == nil {
			t.Error("expected error for missing key in keyring, got nil")
		}

		// Nil payload in keyring
		if _, err := ring.Open(nil); err == nil {
			t.Error("expected error for nil payload, got nil")
		}
	})

	t.Run("Keyring.OpenWithSuite custom suite", func(t *testing.T) {
		customInfo := []byte("custom-tag")
		encapCustom, sealerCustom, err := hpke.NewSender(pubKey, kdf, aead, customInfo)
		if err != nil {
			t.Fatalf("new sender: %v", err)
		}
		cipherCustom, err := sealerCustom.Seal(nil, []byte("Custom suite text"))
		if err != nil {
			t.Fatalf("seal: %v", err)
		}

		customPayload := &client.EncryptedPayload{
			Enc:        base64.StdEncoding.EncodeToString(encapCustom),
			Ciphertext: base64.StdEncoding.EncodeToString(cipherCustom),
			KeyID:      "key-1",
		}

		ring := client.Keyring{
			"key-1": priv,
		}
		pt, err := ring.OpenWithSuite(customPayload, kdf, aead, customInfo)
		if err != nil {
			t.Fatalf("OpenWithSuite failed: %v", err)
		}
		if string(pt) != "Custom suite text" {
			t.Errorf("got %q, want %q", string(pt), "Custom suite text")
		}
	})
}

func TestFieldErrorFormatting(t *testing.T) {
	t.Run("With field, value, message, and reason", func(t *testing.T) {
		fe := client.FieldError{
			Field:   "namespace",
			Value:   "bad_ns!",
			Message: "invalid characters",
			Reason:  client.ReasonInvalidCharacter,
		}
		expected := `namespace ("bad_ns!"): invalid characters [invalid_character]`
		if fe.String() != expected {
			t.Errorf("got %q, want %q", fe.String(), expected)
		}
	})

	t.Run("With field, message, and reason without value", func(t *testing.T) {
		fe := client.FieldError{
			Field:   "query",
			Message: "missing query string",
			Reason:  client.ReasonMissing,
		}
		expected := `query: missing query string [missing]`
		if fe.String() != expected {
			t.Errorf("got %q, want %q", fe.String(), expected)
		}
	})

	t.Run("Sensitive field value redaction", func(t *testing.T) {
		fe := client.FieldError{
			Field:   "api_key",
			Value:   "sp_live_secret_12345",
			Message: "invalid key format",
			Reason:  client.ReasonInvalidFormat,
		}
		expected := `api_key ("[REDACTED]"): invalid key format [invalid_format]`
		if fe.String() != expected {
			t.Errorf("got %q, want %q", fe.String(), expected)
		}
	})

	t.Run("Without field", func(t *testing.T) {
		fe := client.FieldError{
			Message: "unsupported request",
			Reason:  client.ReasonUnsupported,
		}
		expected := `unsupported request [unsupported]`
		if fe.String() != expected {
			t.Errorf("got %q, want %q", fe.String(), expected)
		}
	})
}

func TestBadRequestErrorHelpers(t *testing.T) {
	t.Run("Formatting with message and fields", func(t *testing.T) {
		err := &client.BadRequestError{}
		if err.Error() != "bad request" {
			t.Errorf("got %q, want 'bad request'", err.Error())
		}
		if err.Message() != "" {
			t.Errorf("got message %q, want empty", err.Message())
		}

		// Test via simulated HTTP response with message only
		c, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":    400,
				"message": "Malformed JSON body",
			})
		})
		_, reqErr := c.Search.Keys.List(context.Background())
		var badReq *client.BadRequestError
		if !errors.As(reqErr, &badReq) {
			t.Fatalf("expected *BadRequestError, got %T (%v)", reqErr, reqErr)
		}
		if badReq.Message() != "Malformed JSON body" {
			t.Errorf("got %q, want 'Malformed JSON body'", badReq.Message())
		}
		if badReq.Error() != "bad request: Malformed JSON body" {
			t.Errorf("got %q, want 'bad request: Malformed JSON body'", badReq.Error())
		}

		errWithMsg := client.NewBadRequestError(
			client.FieldError{Field: "category", Reason: client.ReasonMissing, Message: "required"},
		)
		if !errWithMsg.HasField("category") {
			t.Error("expected HasField(category) to be true")
		}
		if !errWithMsg.HasReason(client.ReasonMissing) {
			t.Error("expected HasReason(missing) to be true")
		}
		if !errWithMsg.HasFieldReason("category", client.ReasonMissing) {
			t.Error("expected HasFieldReason(category, missing) to be true")
		}
		if len(errWithMsg.FieldErrors()) != 1 {
			t.Errorf("expected 1 field error, got %d", len(errWithMsg.FieldErrors()))
		}
		if len(errWithMsg.FindByField("category")) != 1 {
			t.Errorf("expected 1 match for category, got %d", len(errWithMsg.FindByField("category")))
		}
		if len(errWithMsg.FindByField("unknown")) != 0 {
			t.Errorf("expected 0 matches for unknown, got %d", len(errWithMsg.FindByField("unknown")))
		}
	})

	t.Run("APIError direct construction", func(t *testing.T) {
		apiErr := &client.APIError{
			StatusCode: 504,
			Message:    "Gateway Timeout",
		}
		if apiErr.Error() != "api error (504): Gateway Timeout" {
			t.Errorf("got %q, want 'api error (504): Gateway Timeout'", apiErr.Error())
		}
	})
}
