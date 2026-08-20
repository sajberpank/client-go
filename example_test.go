// Copyright (c) 2026, Janoš Guljaš <janos@resenje.org>
// All rights reserved.

package sajberpank_test

import (
	"context"
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"sajberpank.rs/sajberpank"
)

func ExampleNew() {
	// Initialize standard client with your Sajberpank API key
	apiClient := sajberpank.New("sp_live_b4b8bd21_5bed2652220a8316580462963f3f84b9cfd06da2683da11x", nil)
	_ = apiClient
}

func ExampleNew_customOptions() {
	stagingURL, _ := url.Parse("https://api-staging.sajberpank.rs")
	customClient := sajberpank.New("sp_live_b4b8bd21_5bed2652220a8316580462963f3f84b9cfd06da2683da11x", &sajberpank.ClientOptions{
		BaseURL: stagingURL,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		UserAgent: "my-service/1.0",
	})
	_ = customClient
}

func ExampleKeysService_Add() {
	ctx := context.Background()

	// Mock server for public key registration
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{
			"name": "primary-x25519-key",
			"kem": "HPKE_KEM_DHKEM_X25519_HKDF_SHA256",
			"aead": "HPKE_AEAD_CHACHA20_POLY1305"
		}`))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	apiClient := sajberpank.New("test-key", &sajberpank.ClientOptions{BaseURL: u})

	// 1. Generate an X25519 key pair locally
	_, pubKeyBytes, err := sajberpank.GenerateX25519Key()
	if err != nil {
		log.Fatalf("generate key pair: %v", err)
	}

	// 2. Upload ONLY the public key to Sajberpank
	key, err := apiClient.Search.Keys.Add(ctx, sajberpank.AddKeyOptions{
		Name:      "primary-x25519-key",
		PublicKey: pubKeyBytes,
	})
	if err != nil {
		log.Fatalf("register public key: %v", err)
	}

	fmt.Printf("Registered public key %q (KEM: %s, AEAD: %s)\n", key.Name, key.KEM, key.AEAD)
	// Output:
	// Registered public key "primary-x25519-key" (KEM: HPKE_KEM_DHKEM_X25519_HKDF_SHA256, AEAD: HPKE_AEAD_CHACHA20_POLY1305)
}

func ExampleDocumentsService_Add() {
	ctx := context.Background()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"CTR-2026-001","namespace":"legal-corp:contracts","added":true}`))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	apiClient := sajberpank.New("test-key", &sajberpank.ClientOptions{BaseURL: u})

	docTimestamp := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)

	// A. Plain Text Ingestion
	result, err := apiClient.Search.Documents.Add(ctx, sajberpank.DocumentOptions[sajberpank.Text]{
		Namespace:    "legal-corp",
		Category:     "contracts",
		ID:           "CTR-2026-001",
		KeyName:      "primary-x25519-key",
		Content:      sajberpank.Text("Commercial General Liability coverage covering bodily injury and property damage worldwide."),
		DocumentTime: &docTimestamp,
		Fields: map[string]string{
			"region":        "EMEA",
			"policy_number": "POL-98741",
		},
	})
	if err != nil {
		log.Fatalf("ingest text: %v", err)
	}
	fmt.Printf("Document added: %s (namespace: %s)\n", result.ID, result.Namespace)

	// B. Paginated Document Ingestion
	_, _ = apiClient.Search.Documents.Add(ctx, sajberpank.DocumentOptions[sajberpank.Pages]{
		Namespace: "legal-corp",
		Category:  "filings",
		ID:        "FIL-2026-902",
		KeyName:   "primary-x25519-key",
		Content: sajberpank.Pages{
			{PageNumber: 1, Text: "Executive Summary: Audit results."},
			{PageNumber: 2, Text: "Risk Factors: Market volatility."},
		},
	})

	// C. Structured Sentences with Citation Tracking
	_, _ = apiClient.Search.Documents.Add(ctx, sajberpank.DocumentOptions[sajberpank.Sentences]{
		Namespace: "legal-corp",
		Category:  "opinions",
		ID:        "OPN-2026-441",
		KeyName:   "primary-x25519-key",
		Content: sajberpank.Sentences{
			{Text: "Indemnification clause applies.", PageNumber: 14, Reference: "Paragraph 3.2.1"},
		},
	})

	// D. Overwriting an Existing Document
	_, _ = apiClient.Search.Documents.Add(ctx, sajberpank.DocumentOptions[sajberpank.Text]{
		Namespace: "legal-corp",
		Category:  "contracts",
		ID:        "CTR-2026-001",
		KeyName:   "primary-x25519-key",
		Content:   sajberpank.Text("Updated Commercial General Liability coverage terms."),
		Overwrite: new(true),
	})
	// Output:
	// Document added: CTR-2026-001 (namespace: legal-corp:contracts)
}

func ExampleDocumentsService_GetStatus() {
	ctx := context.Background()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"exists":true,"is_complete":true}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	apiClient := sajberpank.New("test-key", &sajberpank.ClientOptions{BaseURL: u})

	// 1. Inspect status
	status, err := apiClient.Search.Documents.GetStatus(ctx, "legal-corp", "contracts", "CTR-2026-001")
	if err != nil {
		log.Fatalf("get status: %v", err)
	}
	fmt.Printf("Document exists: %t, indexing complete: %t\n", status.Exists, status.IsComplete)

	// 2. Delete document
	if err := apiClient.Search.Documents.Delete(ctx, "legal-corp", "contracts", "CTR-2026-001"); err != nil {
		log.Fatalf("delete document: %v", err)
	}
	fmt.Println("Document deleted successfully")
	// Output:
	// Document exists: true, indexing complete: true
	// Document deleted successfully
}

func ExampleSearchService_Query() {
	ctx := context.Background()

	// Generate a recipient key pair for demonstration
	privKey, pubBytes, err := sajberpank.GenerateX25519Key()
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}

	kem := hpke.DHKEM(ecdh.X25519())
	kdf := hpke.HKDFSHA256()
	aead := hpke.ChaCha20Poly1305()
	pubKey, _ := kem.NewPublicKey(pubBytes)
	encap, sealer, _ := hpke.NewSender(pubKey, kdf, aead, sajberpank.DefaultPayloadInfo())
	cipher, _ := sealer.Seal(nil, []byte("Decrypted legal clause text."))

	encB64 := base64.StdEncoding.EncodeToString(encap)
	cipherB64 := base64.StdEncoding.EncodeToString(cipher)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{
			"results": [{
				"id": "CTR-2026-001",
				"namespace": "legal-corp",
				"category": "contracts",
				"score": 0.9421,
				"encrypted_text": {
					"key_id": "primary-x25519-key",
					"enc": %q,
					"ciphertext": %q
				}
			}]
		}`, encB64, cipherB64)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	apiClient := sajberpank.New("test-key", &sajberpank.ClientOptions{BaseURL: u})

	resp, err := apiClient.Search.Query(ctx, sajberpank.SearchOptions{
		Namespace:  "legal-corp",
		Categories: []string{"contracts"},
		Query:      "indemnification liability limitations",
		Limit:      10,
	})
	if err != nil {
		log.Fatalf("search query failed: %v", err)
	}

	for i, res := range resp.Results {
		decryptedText, err := res.DecryptText(privKey)
		if err != nil {
			log.Fatalf("decrypt failed: %v", err)
		}
		fmt.Printf("[%d] ID: %s (Score: %.4f)\n", i+1, res.ID, res.Score)
		fmt.Printf("    Content: %s\n", decryptedText)
	}
	// Output:
	// [1] ID: CTR-2026-001 (Score: 0.9421)
	//     Content: Decrypted legal clause text.
}

func ExampleSearchService_Query_similarity() {
	ctx := context.Background()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{
			"results": [{
				"id": "CTR-2026-002",
				"namespace": "legal-corp",
				"category": "contracts",
				"score": 0.8842
			}]
		}`)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	apiClient := sajberpank.New("test-key", &sajberpank.ClientOptions{BaseURL: u})

	resp, err := apiClient.Search.Query(ctx, sajberpank.SearchOptions{
		Namespace:  "legal-corp",
		Categories: []string{"contracts"},
		Similarity: &sajberpank.SimilarityOptions{
			Positive: []sajberpank.SimilarityDocument{
				{ID: "CTR-2026-001", Category: "contracts"},
			},
			Negative: []sajberpank.SimilarityDocument{
				{ID: "CTR-2026-999", Category: "contracts"},
			},
		},
		Limit: 5,
	})
	if err != nil {
		log.Fatalf("similarity query failed: %v", err)
	}

	for _, res := range resp.Results {
		fmt.Printf("Recommended: %s (score: %.4f)\n", res.ID, res.Score)
	}
	// Output:
	// Recommended: CTR-2026-002 (score: 0.8842)
}

func ExampleSearchService_Query_decryptFields() {
	ctx := context.Background()

	privKey, pubBytes, err := sajberpank.GenerateX25519Key()
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}

	kem := hpke.DHKEM(ecdh.X25519())
	kdf := hpke.HKDFSHA256()
	aead := hpke.ChaCha20Poly1305()
	pubKey, _ := kem.NewPublicKey(pubBytes)

	encField, sealerField, _ := hpke.NewSender(pubKey, kdf, aead, sajberpank.DefaultPayloadInfo())
	cipherField, _ := sealerField.Seal(nil, []byte("EMEA"))

	encKw, sealerKw, _ := hpke.NewSender(pubKey, kdf, aead, sajberpank.DefaultPayloadInfo())
	cipherKw, _ := sealerKw.Seal(nil, []byte("liability"))

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{
			"results": [{
				"id": "CTR-2026-001",
				"namespace": "legal-corp",
				"category": "contracts",
				"score": 0.95,
				"encrypted_fields": {
					"region": {
						"key_id": "primary-x25519-key",
						"enc": %q,
						"ciphertext": %q
					}
				}
			}],
			"encrypted_keywords": [{
				"key_id": "primary-x25519-key",
				"enc": %q,
				"ciphertext": %q
			}]
		}`,
			base64.StdEncoding.EncodeToString(encField),
			base64.StdEncoding.EncodeToString(cipherField),
			base64.StdEncoding.EncodeToString(encKw),
			base64.StdEncoding.EncodeToString(cipherKw),
		)
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	apiClient := sajberpank.New("test-key", &sajberpank.ClientOptions{BaseURL: u})

	resp, err := apiClient.Search.Query(ctx, sajberpank.SearchOptions{
		Namespace:  "legal-corp",
		Categories: []string{"contracts"},
		Query:      "indemnification liability limitations",
		Temporal: &sajberpank.TemporalOptions{
			DecayType:    sajberpank.DecayTypeExponential,
			ScaleSeconds: 30 * 86400,
		},
	})
	if err != nil {
		log.Fatalf("query failed: %v", err)
	}

	kwList, err := resp.DecryptKeywords(privKey)
	if err != nil {
		log.Fatalf("decrypt keywords: %v", err)
	}
	fmt.Printf("Keywords: %v\n", kwList)

	fields, err := resp.Results[0].DecryptFields(privKey)
	if err != nil {
		log.Fatalf("decrypt fields: %v", err)
	}
	fmt.Printf("Region: %s\n", fields["region"])
	// Output:
	// Keywords: [liability]
	// Region: EMEA
}

func ExampleKeyring() {
	// Generate key pair
	privKey, pubBytes, _ := sajberpank.GenerateX25519Key()
	kem := hpke.DHKEM(ecdh.X25519())
	kdf := hpke.HKDFSHA256()
	aead := hpke.ChaCha20Poly1305()
	pubKey, _ := kem.NewPublicKey(pubBytes)
	encap, sealer, _ := hpke.NewSender(pubKey, kdf, aead, sajberpank.DefaultPayloadInfo())
	cipher, _ := sealer.Seal(nil, []byte("Decrypted multi-key content"))

	payload := &sajberpank.EncryptedPayload{
		Enc:        base64.StdEncoding.EncodeToString(encap),
		Ciphertext: base64.StdEncoding.EncodeToString(cipher),
		KeyID:      "primary-x25519-key",
	}

	// Configure private keys indexed by their registered KeyID
	ring := sajberpank.Keyring{
		"primary-x25519-key": privKey,
	}

	plaintext, err := ring.Open(payload)
	if err != nil {
		log.Fatalf("keyring decryption failed: %v", err)
	}
	fmt.Printf("Decrypted from keyring: %s\n", string(plaintext))
	// Output:
	// Decrypted from keyring: Decrypted multi-key content
}

func ExampleAccountKeysService_CreateWithOptions() {
	ctx := context.Background()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{
			"id": "key_worker99",
			"name": "Nightly Ingestion Worker",
			"prefix": "sp_live_worker99",
			"api_key": "sp_live_worker99_rawsecrettoken"
		}`))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	apiClient := sajberpank.New("test-key", &sajberpank.ClientOptions{BaseURL: u})

	key, err := apiClient.Account.Keys.CreateWithOptions(ctx, sajberpank.CreateKeyOptions{
		Name:   "Nightly Ingestion Worker",
		Scopes: []string{sajberpank.ScopeDocumentsWrite, sajberpank.ScopeSearch},
	})
	if err != nil {
		log.Fatalf("create api key: %v", err)
	}

	fmt.Printf("Created Key: %s (Prefix: %s)\n", key.ID, key.Prefix)
	// Output:
	// Created Key: key_worker99 (Prefix: sp_live_worker99)
}

func Example_errorHandling() {
	ctx := context.Background()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{
			"code": 400,
			"message": "Invalid document payload",
			"errors": [{
				"field": "category",
				"reason": "missing",
				"message": "category cannot be empty"
			}]
		}`))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	apiClient := sajberpank.New("test-key", &sajberpank.ClientOptions{BaseURL: u})

	_, err := apiClient.Search.Documents.Add(ctx, sajberpank.DocumentOptions[sajberpank.Text]{
		Namespace: "legal-corp",
		Category:  "contracts",
		ID:        "CTR-001",
		KeyName:   "primary-x25519-key",
		Content:   sajberpank.Text("Example contract text"),
	})
	if err != nil {
		if badReq, ok := errors.AsType[*sajberpank.BadRequestError](err); ok {
			fmt.Printf("Validation error: %s\n", badReq.Message())
			for _, fe := range badReq.FieldErrors() {
				fmt.Printf("  - Field %q (%s): %s\n", fe.Field, fe.Reason, fe.Message)
			}
			if badReq.HasFieldReason("category", sajberpank.ReasonMissing) {
				fmt.Println("Handled missing category error")
			}
		}
	}
	// Output:
	// Validation error: Invalid document payload
	//   - Field "category" (missing): category cannot be empty
	// Handled missing category error
}
