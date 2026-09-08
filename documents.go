// Copyright (c) 2026, Janoš Guljaš <janos@resenje.org>
// All rights reserved.

package sajberpank

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DocumentsService manages indexing, status inspection, and deletion of documents.
type DocumentsService service

// Page represents a single page of text within a multi-page document.
type Page struct {
	PageNumber int32
	Text       string
}

// Sentence represents a structured sentence with optional page tracking and citation reference.
type Sentence struct {
	Text       string
	PageNumber int32
	Reference  string
}

// Concrete content types:
type Text string
type Pages []Page
type Sentences []Sentence

// Content is a type constraint allowing only Text, Pages, or Sentences.
type Content interface {
	Text | Pages | Sentences
}

// DocumentOptions contains parameters for ingesting a document parameterized by content type.
type DocumentOptions[C Content] struct {
	Namespace       string
	Category        string
	ID              string
	KeyName         string
	Content         C
	DocumentTime    *time.Time
	Fields          map[string]string
	WithoutKeywords *bool
	Overwrite       *bool
}

// AddDocumentResult contains metadata of the ingested document.
type AddDocumentResult struct {
	ID        string
	Namespace string
	Added     bool
}

// DocumentStatus represents current indexing status and structural metadata of a document.
type DocumentStatus struct {
	Exists       bool
	IsComplete   bool
	ChunkCount   int
	Pages        []int32
	References   []string
	AddTime      time.Time
	DocumentTime *time.Time
}

type pageBody struct {
	PageNumber int32  `json:"page_number"`
	Text       string `json:"text"`
}

type sentenceBody struct {
	Text       string `json:"text"`
	PageNumber int32  `json:"page_number,omitempty"`
	Reference  string `json:"reference,omitempty"`
}

type addDocumentRequestBody struct {
	Namespace       string            `json:"namespace"`
	Category        string            `json:"category"`
	ID              string            `json:"id"`
	KeyName         string            `json:"key_name"`
	Text            string            `json:"text,omitempty"`
	Pages           []pageBody        `json:"pages,omitempty"`
	Sentences       []sentenceBody    `json:"sentences,omitempty"`
	DocumentTime    *time.Time        `json:"document_time,omitzero"`
	Fields          map[string]string `json:"fields,omitempty"`
	WithoutKeywords *bool             `json:"without_keywords,omitempty"`
	Overwrite       *bool             `json:"overwrite,omitempty"`
}

type addDocumentResponseBody struct {
	ID        string `json:"id"`
	Namespace string `json:"namespace"`
	Added     bool   `json:"added"`
}

type documentStatusBody struct {
	Exists       bool       `json:"exists"`
	IsComplete   bool       `json:"is_complete"`
	ChunkCount   int        `json:"chunk_count"`
	Pages        []int32    `json:"pages,omitempty"`
	References   []string   `json:"references,omitempty"`
	AddTime      time.Time  `json:"add_time,omitzero"`
	DocumentTime *time.Time `json:"document_time,omitempty"`
}

func toPageBodies(pages []Page) []pageBody {
	if pages == nil {
		return nil
	}
	bodies := make([]pageBody, len(pages))
	for i, p := range pages {
		bodies[i] = pageBody(p)
	}
	return bodies
}

func toSentenceBodies(sentences []Sentence) []sentenceBody {
	if sentences == nil {
		return nil
	}
	bodies := make([]sentenceBody, len(sentences))
	for i, s := range sentences {
		bodies[i] = sentenceBody(s)
	}
	return bodies
}

// Add ingests and seals a document under the specified namespace and category.
func (s *DocumentsService) Add[C Content](ctx context.Context, o DocumentOptions[C]) (*AddDocumentResult, error) {
	if strings.TrimSpace(o.Namespace) == "" {
		return nil, ErrInvalidNamespace
	}
	if strings.TrimSpace(o.Category) == "" {
		return nil, ErrInvalidCategory
	}
	if strings.TrimSpace(o.ID) == "" {
		return nil, ErrInvalidDocumentID
	}
	if strings.TrimSpace(o.KeyName) == "" {
		return nil, ErrInvalidKeyName
	}

	body := addDocumentRequestBody{
		Namespace:       o.Namespace,
		Category:        o.Category,
		ID:              o.ID,
		KeyName:         o.KeyName,
		DocumentTime:    o.DocumentTime,
		Fields:          o.Fields,
		WithoutKeywords: o.WithoutKeywords,
		Overwrite:       o.Overwrite,
	}

	switch c := any(o.Content).(type) {
	case Text:
		if strings.TrimSpace(string(c)) == "" {
			return nil, ErrMissingDocumentContent
		}
		body.Text = string(c)
	case Pages:
		if len(c) == 0 {
			return nil, ErrMissingDocumentContent
		}
		body.Pages = toPageBodies(c)
	case Sentences:
		if len(c) == 0 {
			return nil, ErrMissingDocumentContent
		}
		body.Sentences = toSentenceBodies(c)
	default:
		return nil, ErrInvalidDocumentContent
	}

	var resBody addDocumentResponseBody
	if err := s.client.request(ctx, http.MethodPost, "/v1/search/documents", body, &resBody); err != nil {
		return nil, err
	}
	res := AddDocumentResult(resBody)
	return &res, nil
}

// GetStatus checks whether a document exists and is indexed.
func (s *DocumentsService) GetStatus(ctx context.Context, namespace, category, id string) (*DocumentStatus, error) {
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		return nil, ErrInvalidNamespace
	}
	category = strings.TrimSpace(category)
	if category == "" {
		return nil, ErrInvalidCategory
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, ErrInvalidDocumentID
	}

	path := fmt.Sprintf("/v1/search/documents/%s/%s/%s", url.PathEscape(namespace), url.PathEscape(category), url.PathEscape(id))
	var statusBody documentStatusBody
	if err := s.client.request(ctx, http.MethodGet, path, nil, &statusBody); err != nil {
		return nil, err
	}
	return &DocumentStatus{
		Exists:       statusBody.Exists,
		IsComplete:   statusBody.IsComplete,
		ChunkCount:   statusBody.ChunkCount,
		Pages:        statusBody.Pages,
		References:   statusBody.References,
		AddTime:      statusBody.AddTime,
		DocumentTime: statusBody.DocumentTime,
	}, nil
}

// Delete removes a document from the collection.
func (s *DocumentsService) Delete(ctx context.Context, namespace, category, id string) error {
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		return ErrInvalidNamespace
	}
	category = strings.TrimSpace(category)
	if category == "" {
		return ErrInvalidCategory
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return ErrInvalidDocumentID
	}

	path := fmt.Sprintf("/v1/search/documents/%s/%s/%s", url.PathEscape(namespace), url.PathEscape(category), url.PathEscape(id))
	return s.client.request(ctx, http.MethodDelete, path, nil, nil)
}

// DeleteAll removes all documents for the account.
func (s *DocumentsService) DeleteAll(ctx context.Context) error {
	return s.client.request(ctx, http.MethodDelete, "/v1/search/documents", nil, nil)
}
