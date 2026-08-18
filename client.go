// Copyright (c) 2026, Janoš Guljaš <janos@resenje.org>
// All rights reserved.

package sajberpank

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"
)

const (
	defaultBaseURL     = "https://api.sajberpank.rs"
	defaultUserAgent   = "sajberpank-client-go"
	maxDrainBodyBytes  = 1 << 20  // 1 MB max drain limit
	maxTargetBodyBytes = 32 << 20 // 32 MB max target decode limit
)

// Client manages communication with the Sajberpank API.
type Client struct {
	client    *http.Client
	baseURL   *url.URL
	apiKey    string
	userAgent string

	common service

	// Account provides access to the /v1/account API (keys management).
	Account *AccountService

	// Search provides access to the /v1/search API (queries, keys, and documents).
	Search *SearchService
}

type service struct {
	client *Client
}

// ClientOptions configures the Client instance.
type ClientOptions struct {
	BaseURL    *url.URL
	HTTPClient *http.Client
	// UserAgent specifies an optional string to append to the default User-Agent header.
	UserAgent string
}

// New creates a new Sajberpank API client with Bearer API Key authentication.
func New(apiKey string, o *ClientOptions) *Client {
	if o == nil {
		o = &ClientOptions{}
	}

	httpClient := o.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
		}
	}

	baseURL := o.BaseURL
	if baseURL == nil {
		var err error
		baseURL, err = url.Parse(defaultBaseURL)
		if err != nil {
			panic(fmt.Sprintf("parse defaultBaseURL: %v", err))
		}
	}

	ua := fmt.Sprintf("%s (%s; %s)", defaultUserAgent, runtime.GOOS, runtime.GOARCH)
	if extra := strings.TrimSpace(o.UserAgent); extra != "" {
		ua += " " + extra
	}

	c := &Client{
		client:    httpClient,
		baseURL:   baseURL,
		apiKey:    apiKey,
		userAgent: ua,
	}
	c.common.client = c

	c.Account = &AccountService{
		client: c,
		Keys:   (*AccountKeysService)(&c.common),
	}

	c.Search = &SearchService{
		client:    c,
		Keys:      (*KeysService)(&c.common),
		Documents: (*DocumentsService)(&c.common),
	}

	return c
}

func (c *Client) request(ctx context.Context, method, path string, body, target any) error {
	rel, err := url.Parse(strings.TrimPrefix(path, "/"))
	if err != nil {
		return fmt.Errorf("parse path %q: %w", path, err)
	}
	u := c.baseURL.ResolveReference(rel)

	var reqBody io.Reader
	if body != nil {
		buf := &bytes.Buffer{}
		if err := json.NewEncoder(buf).Encode(body); err != nil {
			return fmt.Errorf("encode request body: %w", err)
		}
		reqBody = buf
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), reqBody)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", c.userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	req.Header.Set("Accept", "application/json")

	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("execute request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDrainBodyBytes))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 400 {
		return handleErrorResponse(resp)
	}

	if target != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxTargetBodyBytes)).Decode(target); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}

	return nil
}
