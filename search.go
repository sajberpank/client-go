// Copyright (c) 2026, Janoš Guljaš <janos@resenje.org>
// All rights reserved.

package sajberpank

import (
	"context"
	"crypto/hpke"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// SearchService provides semantic and hybrid search capabilities alongside keys and documents management.
type SearchService struct {
	client *Client

	Keys      *KeysService
	Documents *DocumentsService
}

// DecayType represents temporal score decay algorithm.
type DecayType string

const (
	DecayTypeExponential DecayType = "exponential"
	DecayTypeLinear      DecayType = "linear"
	DecayTypeGaussian    DecayType = "gaussian"
)

// TemporalOptions controls temporal scoring for documents with a DocumentTime.
// Temporal score decay is adjusted compared strictly to the document's domain DocumentTime
// (if there is one), and never compared to the system AddTime (ingestion timestamp).
type TemporalOptions struct {
	DecayType    DecayType
	ScaleSeconds float32
	Midpoint     float32
}

// SimilarityDocument specifies a document reference for similarity recommendation.
type SimilarityDocument struct {
	ID       string
	Category string
}

// SimilarityOptions holds positive and negative document examples for similarity search.
type SimilarityOptions struct {
	Positive []SimilarityDocument
	Negative []SimilarityDocument
}

// SearchOptions holds parameters for executing a search query.
type SearchOptions struct {
	Namespace  string
	Categories []string
	Query      string
	Similarity *SimilarityOptions
	Limit      int
	Temporal   *TemporalOptions
}

// EncryptedPayload represents base64-encoded encrypted payload and key metadata.
type EncryptedPayload struct {
	Enc        string
	Ciphertext string
	KeyID      string
}

// SearchResult represents an encrypted matching document returned by search.
type SearchResult struct {
	ID              string
	Namespace       string
	Category        string
	Score           float32
	Pages           []int32
	References      []string
	AddTime         time.Time
	DocumentTime    *time.Time
	EncryptedText   *EncryptedPayload
	EncryptedFields map[string]EncryptedPayload
}

// SearchResponse contains matched document results and query-level encrypted keywords.
type SearchResponse struct {
	Results           []SearchResult
	EncryptedKeywords []EncryptedPayload
}

type temporalOptionsBody struct {
	DecayType    DecayType `json:"decay_type"`
	ScaleSeconds float32   `json:"scale_seconds"`
	Midpoint     float32   `json:"midpoint,omitempty"`
}

type similarityDocumentBody struct {
	ID       string `json:"id"`
	Category string `json:"category,omitempty"`
}

type similarityOptionsBody struct {
	Positive []similarityDocumentBody `json:"positive,omitempty"`
	Negative []similarityDocumentBody `json:"negative,omitempty"`
}

type searchQueryRequestBody struct {
	Namespace  string                 `json:"namespace"`
	Categories []string               `json:"categories,omitempty"`
	Query      string                 `json:"query,omitempty"`
	Similarity *similarityOptionsBody `json:"similarity,omitempty"`
	Limit      int                    `json:"limit,omitempty"`
	Temporal   *temporalOptionsBody   `json:"temporal,omitempty"`
}

type encryptedPayloadBody struct {
	Enc        string `json:"enc"`
	Ciphertext string `json:"ciphertext"`
	KeyID      string `json:"key_id,omitempty"`
}

type searchResultBody struct {
	ID              string                          `json:"id"`
	Namespace       string                          `json:"namespace"`
	Category        string                          `json:"category"`
	Score           float32                         `json:"score"`
	Pages           []int32                         `json:"pages,omitempty"`
	References      []string                        `json:"references,omitempty"`
	AddTime         time.Time                       `json:"add_time"`
	DocumentTime    *time.Time                      `json:"document_time,omitempty"`
	EncryptedText   *encryptedPayloadBody           `json:"encrypted_text,omitempty"`
	EncryptedFields map[string]encryptedPayloadBody `json:"encrypted_fields,omitempty"`
}

type searchResponseBody struct {
	Results           []searchResultBody     `json:"results"`
	EncryptedKeywords []encryptedPayloadBody `json:"encrypted_keywords,omitempty"`
}

func toTemporalOptionsBody(t *TemporalOptions) *temporalOptionsBody {
	if t == nil {
		return nil
	}
	return &temporalOptionsBody{
		DecayType:    t.DecayType,
		ScaleSeconds: t.ScaleSeconds,
		Midpoint:     t.Midpoint,
	}
}

func toSimilarityDocumentBodies(docs []SimilarityDocument) []similarityDocumentBody {
	if docs == nil {
		return nil
	}
	bodies := make([]similarityDocumentBody, len(docs))
	for i, d := range docs {
		bodies[i] = similarityDocumentBody(d)
	}
	return bodies
}

func toSimilarityOptionsBody(s *SimilarityOptions) *similarityOptionsBody {
	if s == nil {
		return nil
	}
	return &similarityOptionsBody{
		Positive: toSimilarityDocumentBodies(s.Positive),
		Negative: toSimilarityDocumentBodies(s.Negative),
	}
}

func toEncryptedPayload(body *encryptedPayloadBody) *EncryptedPayload {
	if body == nil {
		return nil
	}
	p := EncryptedPayload(*body)
	return &p
}

func toEncryptedPayloadMap(bodies map[string]encryptedPayloadBody) map[string]EncryptedPayload {
	if bodies == nil {
		return nil
	}
	m := make(map[string]EncryptedPayload, len(bodies))
	for k, v := range bodies {
		m[k] = EncryptedPayload(v)
	}
	return m
}

func toSearchResult(body searchResultBody) SearchResult {
	return SearchResult{
		ID:              body.ID,
		Namespace:       body.Namespace,
		Category:        body.Category,
		Score:           body.Score,
		Pages:           body.Pages,
		References:      body.References,
		AddTime:         body.AddTime,
		DocumentTime:    body.DocumentTime,
		EncryptedText:   toEncryptedPayload(body.EncryptedText),
		EncryptedFields: toEncryptedPayloadMap(body.EncryptedFields),
	}
}

func toSearchResponse(body searchResponseBody) *SearchResponse {
	results := make([]SearchResult, len(body.Results))
	for i, r := range body.Results {
		results[i] = toSearchResult(r)
	}

	var keywords []EncryptedPayload
	if body.EncryptedKeywords != nil {
		keywords = make([]EncryptedPayload, len(body.EncryptedKeywords))
		for i, kw := range body.EncryptedKeywords {
			keywords[i] = EncryptedPayload(kw)
		}
	}

	return &SearchResponse{
		Results:           results,
		EncryptedKeywords: keywords,
	}
}

// DecryptText decrypts the EncryptedText payload using the provided recipient private key and default cipher suite.
func (r *SearchResult) DecryptText(priv hpke.PrivateKey) (string, error) {
	if r.EncryptedText == nil {
		return "", nil
	}
	b, err := r.EncryptedText.OpenDefault(priv)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// DecryptKeywords decrypts all EncryptedKeywords payloads using the provided recipient private key and default cipher suite.
func (r *SearchResponse) DecryptKeywords(priv hpke.PrivateKey) ([]string, error) {
	if len(r.EncryptedKeywords) == 0 {
		return nil, nil
	}
	kws := make([]string, 0, len(r.EncryptedKeywords))
	for i, encKw := range r.EncryptedKeywords {
		b, err := encKw.OpenDefault(priv)
		if err != nil {
			return nil, fmt.Errorf("decrypt keyword %d: %w", i, err)
		}
		kws = append(kws, string(b))
	}
	return kws, nil
}

// DecryptFields decrypts all EncryptedFields payloads using the provided recipient private key and default cipher suite.
func (r *SearchResult) DecryptFields(priv hpke.PrivateKey) (map[string]string, error) {
	if len(r.EncryptedFields) == 0 {
		return nil, nil
	}
	fields := make(map[string]string, len(r.EncryptedFields))
	for name, encField := range r.EncryptedFields {
		b, err := encField.OpenDefault(priv)
		if err != nil {
			return nil, fmt.Errorf("decrypt field %q: %w", name, err)
		}
		fields[name] = string(b)
	}
	return fields, nil
}

// Query performs hybrid search on the namespace's documents.
func (s *SearchService) Query(ctx context.Context, o SearchOptions) (*SearchResponse, error) {
	if strings.TrimSpace(o.Namespace) == "" {
		return nil, ErrInvalidNamespace
	}

	req := searchQueryRequestBody{
		Namespace:  o.Namespace,
		Categories: o.Categories,
		Query:      o.Query,
		Similarity: toSimilarityOptionsBody(o.Similarity),
		Limit:      o.Limit,
		Temporal:   toTemporalOptionsBody(o.Temporal),
	}

	var respBody searchResponseBody
	if err := s.client.request(ctx, http.MethodPost, "/v1/search/query", req, &respBody); err != nil {
		return nil, err
	}
	return toSearchResponse(respBody), nil
}

// Search executes a search query (alias for Query).
func (s *SearchService) Search(ctx context.Context, o SearchOptions) (*SearchResponse, error) {
	return s.Query(ctx, o)
}
