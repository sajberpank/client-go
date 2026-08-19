# Sajberpank Client for Go

[![Go Reference](https://pkg.go.dev/badge/sajberpank.rs/sajberpank.svg)](https://pkg.go.dev/sajberpank.rs/sajberpank)
[![Go Report Card](https://goreportcard.com/badge/sajberpank.rs/sajberpank)](https://goreportcard.com/report/sajberpank.rs/sajberpank)
[![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](LICENSE)

`sajberpank.rs/sajberpank` is the official Go client for the **Sajberpank API**.

Sajberpank delivers hybrid semantic and keyword search with **Zero-Knowledge Blind Storage** using [RFC 9180 HPKE](https://www.rfc-editor.org/rfc/rfc9180.html) (Hybrid Public Key Encryption). The server transiently indexes dense embeddings and sparse lexical tokens, then persists the document data sealed with the client's public key. **The server never sees or stores private keys**—decryption is performed exclusively at the client edge.

---

## Table of Contents

- [Features](#features)
- [Installation & Requirements](#installation--requirements)
- [Quick Start](#quick-start)
  - [Custom Client Options](#custom-client-options)
- [Core Workflows & Examples](#core-workflows--examples)
  - [1. Register a Public Key for Blind Storage](#1-register-a-public-key-for-blind-storage)
  - [2. Ingesting Documents (Type-Safe Content)](#2-ingesting-documents-type-safe-content)
    - [A. Plain Text (`sajberpank.Text`)](#a-plain-text-sajberpanktext)
    - [B. Paginated Document (`sajberpank.Pages`)](#b-paginated-document-sajberpankpages)
    - [C. Structured Sentences (`sajberpank.Sentences`)](#c-structured-sentences-sajberpanksentences)
  - [3. Document Status & Lifecycle](#3-document-status--lifecycle)
  - [4. Executing Search & Client-Edge Decryption](#4-executing-search--client-edge-decryption)
    - [Keyword Highlighting with resenje.org/keywords](#keyword-highlighting-with-resenjeorgkeywords)
  - [5. Temporal Decay Scoring](#5-temporal-decay-scoring)
  - [6. Vector Similarity Recommendations](#6-vector-similarity-recommendations)
  - [7. Multi-Key Decryption via Keyring](#7-multi-key-decryption-via-keyring)
  - [8. Account API Key Management](#8-account-api-key-management)
- [Error Handling & Diagnostics](#error-handling--diagnostics)
- [Security & Architecture Constraints](#security--architecture-constraints)
- [License](#license)

---

## Features

- **Zero-Knowledge Security**: End-to-end asymmetric encryption using Go 1.26 standard library `crypto/hpke` (`DHKEM_X25519`, `DHKEM_P256`, and post-quantum `MLKEM768_X25519`).
- **Type-Safe Ingestion Variants**: Go 1.27 constrained type union and generic options for document content (`sajberpank.Text`, `sajberpank.Pages`, and `sajberpank.Sentences`).
- **Hybrid Retrieval**: Combines dense semantic vector similarity with sparse BM25 keyword search and temporal score decay.
- **Similarity & Negative Recommendations**: Recommend similar documents with positive/negative examples and configurable fusion strategies (`average_vector`, `best_score`, `sum_scores`).
- **Zero External Dependencies**: Implemented strictly using the Go standard library for maximum security, performance, and minimal footprint.
- **Developer-Friendly Ergonomics**: Direct decryption helpers (`res.DecryptText()`, `EncryptedPayload.OpenDefault()`, `sajberpank.Keyring`) and rich error diagnostics (`sajberpank.BadRequestError`).

---

## Installation & Requirements

```bash
go get sajberpank.rs/sajberpank
```

> **Requirements**: **Go 1.27 or later** (requires Go 1.27 method type parameters and standard library `crypto/hpke`).

---

## Quick Start

```go
package main

import (
	"context"
	"fmt"
	"log"

	"sajberpank.rs/sajberpank"
)

func main() {
	ctx := context.Background()

	// 1. Initialize client with your Sajberpank API key
	apiClient := sajberpank.New("sp_live_b4b8bd21_5bed2652220a8316580462963f3f84b9cfd06da2683da11x", nil)

	// 2. Perform a search query
	resp, err := apiClient.Search.Query(ctx, sajberpank.SearchOptions{
		Namespace:  "legal-corp",
		Categories: []string{"contracts"},
		Query:      "liability limitations",
		Limit:      5,
	})
	if err != nil {
		log.Fatalf("search query failed: %v", err)
	}

	for _, res := range resp.Results {
		fmt.Printf("Found document: %s (score: %.4f)\n", res.ID, res.Score)
	}
}
```

### Custom Client Options

Configure a custom base URL, custom HTTP client/timeout, or append an application identifier to the `User-Agent`:

```go
package main

import (
	"net/http"
	"net/url"
	"time"

	"sajberpank.rs/sajberpank"
)

func main() {
	stagingURL, _ := url.Parse("https://api-staging.sajberpank.rs")

	customClient := sajberpank.New("sp_live_b4b8bd21_5bed2652220a8316580462963f3f84b9cfd06da2683da11x", &sajberpank.ClientOptions{
		BaseURL: stagingURL,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		UserAgent: "my-service/1.0", // Appends to default "sajberpank-client-go (<os>; <arch>)"
	})
	_ = customClient
}
```

---

## Core Workflows & Examples

### 1. Register a Public Key for Blind Storage

Before ingesting encrypted documents, generate an HPKE key pair locally and register only the **public key** with Sajberpank:

```go
// 1. Generate an X25519 key pair locally
privKey, pubKeyBytes, err := sajberpank.GenerateX25519Key()
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
```

---

### 2. Ingesting Documents (Type-Safe Content)

The client enforces compile-time type constraints via generic `sajberpank.DocumentOptions[C sajberpank.Content]` and the `sajberpank.Content` type union (`Text | Pages | Sentences`):

#### A. Plain Text (`sajberpank.Text`)

```go
docTimestamp := time.Now().UTC()

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
```

#### B. Paginated Document (`sajberpank.Pages`)

```go
result, err := apiClient.Search.Documents.Add(ctx, sajberpank.DocumentOptions[sajberpank.Pages]{
	Namespace: "legal-corp",
	Category:  "filings",
	ID:        "FIL-2026-902",
	KeyName:   "primary-x25519-key",
	Content: sajberpank.Pages{
		{
			PageNumber: 1,
			Text:       "Executive Summary: Financial and operational audit results for Q1 2026.",
		},
		{
			PageNumber: 2,
			Text:       "Risk Factors: Market volatility and currency fluctuations impacted foreign revenues.",
		},
	},
})
```

#### C. Structured Sentences (`sajberpank.Sentences`)

```go
result, err := apiClient.Search.Documents.Add(ctx, sajberpank.DocumentOptions[sajberpank.Sentences]{
	Namespace: "legal-corp",
	Category:  "opinions",
	ID:        "OPN-2026-441",
	KeyName:   "primary-x25519-key",
	Content: sajberpank.Sentences{
		{
			Text:       "The court held that indemnification clauses must be explicitly stated in the agreement.",
			PageNumber: 14,
			Reference:  "Paragraph 3.2.1",
		},
		{
			Text:       "Summary judgment on negligence claims was accordingly granted.",
			PageNumber: 15,
			Reference:  "Paragraph 3.2.4",
		},
	},
})
```

---

### 3. Document Status & Lifecycle

Inspect indexing status, structural chunk metadata, and domain timestamps:

```go
// 1. Inspect status & metadata
status, err := apiClient.Search.Documents.GetStatus(ctx, "legal-corp", "contracts", "CTR-2026-001")
if err != nil {
	log.Fatalf("get status: %v", err)
}
fmt.Printf("Document exists: %t, indexing complete: %t (chunks: %d, pages: %v)\n",
	status.Exists, status.IsComplete, status.ChunkCount, status.Pages)

// 2. Delete document
if err := apiClient.Search.Documents.Delete(ctx, "legal-corp", "contracts", "CTR-2026-001"); err != nil {
	log.Fatalf("delete document: %v", err)
}
```

---

### 4. Executing Search & Client-Edge Decryption

Search matches are returned sealed with your registered public key. Decrypt them locally:

```go
resp, err := apiClient.Search.Query(ctx, sajberpank.SearchOptions{
	Namespace:  "legal-corp",
	Categories: []string{"contracts", "opinions"},
	Query:      "indemnification liability limitations",
	Limit:      10,
	Temporal: &sajberpank.TemporalOptions{
		DecayType:    sajberpank.DecayTypeExponential,
		ScaleSeconds: 30 * 86400, // 30 days
		Midpoint:     0.5,
	},
})
if err != nil {
	log.Fatalf("search query failed: %v", err)
}

// Decrypt query-level matched keywords
keywords, err := resp.DecryptKeywords(privKey)
if err != nil {
	log.Printf("failed to decrypt query keywords: %v", err)
}
fmt.Printf("Matched query keywords: %v\n", keywords)

// Option A: Direct string decryption with standard default cipher suite
for i, res := range resp.Results {
	decryptedText, err := res.DecryptText(privKey)
	if err != nil {
		log.Printf("failed to decrypt result %d: %v", i, err)
		continue
	}

	fmt.Printf("[%d] ID: %s (Score: %.4f, Pages: %v, References: %v)\n", i+1, res.ID, res.Score, res.Pages, res.References)
	fmt.Printf("    Content: %s\n", decryptedText)

	// Decrypt custom encrypted fields
	fields, err := res.DecryptFields(privKey)
	if err != nil {
		log.Printf("failed to decrypt fields: %v", err)
	}
	for fieldName, fieldVal := range fields {
		fmt.Printf("    Field %s = %s\n", fieldName, fieldVal)
	}
}

// Option B: Decryption with custom HPKE cipher suite parameters
kdf := hpke.HKDFSHA256()
aead := hpke.ChaCha20Poly1305() // or hpke.AES128GCM(), hpke.AES256GCM()

for _, res := range resp.Results {
	if res.EncryptedText != nil {
		decryptedBytes, err := res.EncryptedText.Open(privKey, kdf, aead, nil)
		if err != nil {
			log.Fatalf("custom decryption failed: %v", err)
		}
		fmt.Printf("Decrypted with custom parameters: %s\n", string(decryptedBytes))
	}
}
```

#### Keyword Highlighting with `resenje.org/keywords`

In Zero-Knowledge Blind Storage, the server never stores or views document plaintext or raw keywords, so search highlighting cannot happen on the server. Instead, search matches return query-level sealed encrypted keywords in `resp.EncryptedKeywords`.

Once you decrypt the query keywords and document text at the client edge, you can use [`resenje.org/keywords`](https://pkg.go.dev/resenje.org/keywords)—a high-performance, Unicode-aware Aho-Corasick text matcher—to highlight search terms across all matching documents:

```bash
go get resenje.org/keywords
```

```go
package main

import (
	"context"
	"fmt"
	"log"

	"resenje.org/keywords"
	"sajberpank.rs/sajberpank"
)

func main() {
	ctx := context.Background()
	apiClient := sajberpank.New("sp_live_b4b8bd21_5bed2652220a8316580462963f3f84b9cfd06da2683da11x", nil)

	// 1. Execute search query
	resp, err := apiClient.Search.Query(ctx, sajberpank.SearchOptions{
		Namespace:  "legal-corp",
		Categories: []string{"contracts"},
		Query:      "indemnification liability limitations",
	})
	if err != nil {
		log.Fatalf("search query failed: %v", err)
	}

	// 2. Decrypt query-level matched keywords once using your private key
	decryptedKeywords, err := resp.DecryptKeywords(privKey)
	if err != nil {
		log.Printf("failed to decrypt keywords: %v", err)
	}

	// 3. Build an Aho-Corasick matcher once from the decrypted keywords
	matcher := keywords.NewMatcher(decryptedKeywords)

	// 4. Decrypt and highlight keywords for each matching document
	for _, res := range resp.Results {
		decryptedText, err := res.DecryptText(privKey)
		if err != nil {
			log.Printf("failed to decrypt %s: %v", res.ID, err)
			continue
		}

		highlighted := keywords.Highlight(decryptedText, matcher, "mark", map[string]string{
			"class": "bg-yellow-200 font-semibold",
		})

		fmt.Printf("[%s] %s\n", res.ID, highlighted)
	}
}
```

---

### 5. Temporal Decay Scoring

Apply mathematical time-decay adjustments to search relevance scores based on the document's domain event/publication time:

> **Important**: Temporal score modification is adjusted compared strictly to the document's domain `DocumentTime` (if specified during document ingestion), and is **never** compared to the system `AddTime` (ingestion timestamp). If a document does not have a `DocumentTime`, its score remains unadjusted.

```go
resp, err := apiClient.Search.Query(ctx, sajberpank.SearchOptions{
	Namespace:  "legal-corp",
	Categories: []string{"contracts"},
	Query:      "commercial property liability",
	Temporal: &sajberpank.TemporalOptions{
		DecayType:    sajberpank.DecayTypeExponential, // Exponential, Linear, or Gaussian
		ScaleSeconds: 30 * 86400,                      // 30 days scale
		Midpoint:     0.5,
	},
})
```

---

### 6. Vector Similarity Recommendations

Find documents similar to existing documents while steering away from negative examples:

```go
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
```

---

### 7. Multi-Key Decryption via Keyring

For rotating keys or multi-tenant collections where search results contain documents encrypted with different key IDs:

```go
// Configure private keys indexed by their registered KeyID
ring := sajberpank.Keyring{
	"primary-x25519-key": privKey1,
	"backup-x25519-key":  privKey2,
}

for _, res := range resp.Results {
	if res.EncryptedText != nil {
		plaintext, err := ring.Open(res.EncryptedText)
		if err != nil {
			log.Printf("failed to decrypt %s: %v", res.ID, err)
			continue
		}
		fmt.Printf("[%s] %s\n", res.ID, string(plaintext))
	}
}
```

---

### 8. Account API Key Management

Programmatically generate and manage API keys for worker services:

```go
// 1. Create a scoped API key
key, err := apiClient.Account.Keys.CreateWithOptions(ctx, sajberpank.CreateKeyOptions{
	Name:   "Nightly Ingestion Worker",
	Scopes: []string{sajberpank.ScopeDocumentsWrite, sajberpank.ScopeSearch},
})
if err != nil {
	log.Fatalf("create api key: %v", err)
}
fmt.Printf("Created Key: %s (Bearer Secret: %s)\n", key.ID, key.APIKey)

// 2. List active API keys
keys, err := apiClient.Account.Keys.List(ctx)
for _, k := range keys {
	fmt.Printf("- %s: %s (Prefix: %s)\n", k.ID, k.Name, k.Prefix)
}

// 3. Revoke a key
if err := apiClient.Account.Keys.Revoke(ctx, key.ID); err != nil {
	log.Fatalf("revoke key: %v", err)
}
```

---

## Error Handling & Diagnostics

Errors returned by the client provide structured validation diagnostics and standard sentinel error matching:

```go
_, err := apiClient.Search.Documents.Add(ctx, sajberpank.DocumentOptions[sajberpank.Text]{
	Namespace: "legal-corp",
	Category:  "contracts",
	ID:        "CTR-001",
	KeyName:   "primary-x25519-key",
	Content:   sajberpank.Text("Example contract text"),
})
if err != nil {
	// 1. Check for structured validation errors (HTTP 400 Bad Request)
	var badReq *sajberpank.BadRequestError
	if errors.As(err, &badReq) {
		fmt.Printf("Validation failed: %s\n", badReq.Message())
		for _, fe := range badReq.FieldErrors() {
			fmt.Printf("  - Field %q (%s): %s\n", fe.Field, fe.Reason, fe.Message)
		}

		// Field-level inspection helpers
		if badReq.HasFieldReason("category", sajberpank.ReasonMissing) {
			fmt.Println("Please supply a valid category")
		}
		return
	}

	// 2. Check for standard sentinel error conditions
	switch {
	case errors.Is(err, sajberpank.ErrNotFound):
		fmt.Println("Document or Key not found:", err)
	case errors.Is(err, sajberpank.ErrConflict):
		fmt.Println("Resource already exists:", err)
	case errors.Is(err, sajberpank.ErrUnauthorized):
		fmt.Println("Invalid or revoked API key:", err)
	case errors.Is(err, sajberpank.ErrForbidden):
		fmt.Println("Insufficient key permissions for this operation:", err)
	case errors.Is(err, sajberpank.ErrTooManyRequests):
		fmt.Println("Rate limit exceeded; back off and retry:", err)
	default:
		fmt.Printf("API request failed: %v\n", err)
	}
}
```

---

## Security & Architecture Constraints

### 1. Zero-Knowledge Blind Storage
- **Client-Side Decryption Only**: The server stores only RFC 9180 sealed ciphertexts (`enc`, `ciphertext`, `key_id`). The server cannot decrypt or inspect documents at rest.
- **Client-Side Reranking**: Server-side cross-encoder reranking is automatically bypassed for encrypted points. Local reranking can be performed at the client edge after decryption.
- **Plaintext Payload Attributes Omitted**: Raw document text and custom field strings are never written in plaintext to the vector index.

### 2. Search & Similarity Constraints
- **Query Anchors**: A search request must provide either a non-empty `Query` string OR at least one `Positive` document in `SimilarityOptions`. Supplying only negative documents without an anchor is not permitted.
- **Document Reference Validity**: Document IDs referenced in `SimilarityOptions` must exist within the target `Namespace`.

### 3. Rate Limiting
- Standard rate limit: **100 requests/second** sustained per account.
- Instantaneous burst capacity: **Up to 200 requests**.
- When exceeded, the API returns HTTP `429 Too Many Requests` with a `Retry-After` header.

---

## License

This library is distributed under the BSD 3-Clause License. See the [LICENSE](LICENSE) file for details.
