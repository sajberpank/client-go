// Copyright (c) 2026, Janoš Guljaš <janos@resenje.org>
// All rights reserved.

package sajberpank_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	client "sajberpank.rs/sajberpank"
)

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestCircuitBreakerTransport_Transitions_FailuresToOpen(t *testing.T) {
	var statusCode atomic.Int32
	statusCode.Store(http.StatusInternalServerError)

	baseTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: int(statusCode.Load()),
			Body:       http.NoBody,
		}, nil
	})

	cbt := client.NewCircuitBreakerTransportWithOptions(baseTransport, client.CircuitBreakerOptions{
		Threshold:    3,
		ResetTimeout: 50 * time.Millisecond,
	})

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://localhost/test", nil)

	// 2 failures
	for i := 1; i <= 2; i++ {
		_, err := cbt.RoundTrip(req)
		if err != nil {
			t.Fatalf("iteration %d: unexpected error: %v", i, err)
		}
		if failures := client.CircuitBreakerTransportFailures(cbt); failures != i {
			t.Fatalf("iteration %d: expected %d failures, got %d", i, i, failures)
		}
		if state := client.CircuitBreakerTransportState(cbt); state != client.CircuitBreakerClosed {
			t.Fatalf("iteration %d: expected closed state, got %q", i, state)
		}
	}

	// 3rd failure trips the circuit
	_, err := cbt.RoundTrip(req)
	if err != nil {
		t.Fatalf("iteration 3: unexpected error: %v", err)
	}

	if state := client.CircuitBreakerTransportState(cbt); state != client.CircuitBreakerOpen {
		t.Fatalf("expected open state, got %q", state)
	}

	// Immediate next request should fail fast with ErrServiceUnavailable
	_, err = cbt.RoundTrip(req)
	if !errors.Is(err, client.ErrServiceUnavailable) {
		t.Fatalf("expected ErrServiceUnavailable, got %v", err)
	}
}

func TestCircuitBreakerTransport_OpenToHalfOpenAndRecover(t *testing.T) {
	var shouldFail atomic.Bool
	shouldFail.Store(true)

	baseTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if shouldFail.Load() {
			return nil, errors.New("network error")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       http.NoBody,
		}, nil
	})

	cbt := client.NewCircuitBreakerTransportWithOptions(baseTransport, client.CircuitBreakerOptions{
		Threshold:    1,
		ResetTimeout: 30 * time.Millisecond,
	})

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://localhost/test", nil)

	_, err := cbt.RoundTrip(req)
	if err == nil {
		t.Fatal("expected error from failing transport")
	}

	if state := client.CircuitBreakerTransportState(cbt); state != client.CircuitBreakerOpen {
		t.Fatalf("expected open state, got %q", state)
	}

	time.Sleep(40 * time.Millisecond)

	if state := client.CircuitBreakerTransportState(cbt); state != client.CircuitBreakerHalfOpen {
		t.Fatalf("expected half-open state after timeout, got %q", state)
	}

	// Recover service
	shouldFail.Store(false)

	// Probe request should succeed
	resp, err := cbt.RoundTrip(req)
	if err != nil {
		t.Fatalf("expected probe request to succeed, got: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// State should now be closed
	if state := client.CircuitBreakerTransportState(cbt); state != client.CircuitBreakerClosed {
		t.Fatalf("expected closed state, got %q", state)
	}
}

func TestCircuitBreakerTransport_HalfOpenFailureTripsBack(t *testing.T) {
	var shouldFail atomic.Bool
	shouldFail.Store(true)

	baseTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Body:       http.NoBody,
		}, nil
	})

	cbt := client.NewCircuitBreakerTransportWithOptions(baseTransport, client.CircuitBreakerOptions{
		Threshold:    1,
		ResetTimeout: 30 * time.Millisecond,
	})

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://localhost/test", nil)

	_, _ = cbt.RoundTrip(req)

	time.Sleep(40 * time.Millisecond)

	// Probe fails
	_, _ = cbt.RoundTrip(req)

	if state := client.CircuitBreakerTransportState(cbt); state != client.CircuitBreakerOpen {
		t.Fatalf("expected state to trip back to open, got %q", state)
	}

	_, err := cbt.RoundTrip(req)
	if !errors.Is(err, client.ErrServiceUnavailable) {
		t.Fatalf("expected ErrServiceUnavailable, got %v", err)
	}
}

func TestCircuitBreakerTransport_ContextCanceledNotFailure(t *testing.T) {
	baseTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, context.Canceled
	})

	cbt := client.NewCircuitBreakerTransportWithOptions(baseTransport, client.CircuitBreakerOptions{
		Threshold: 1,
	})

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://localhost/test", nil)

	_, err := cbt.RoundTrip(req)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	if failures := client.CircuitBreakerTransportFailures(cbt); failures != 0 {
		t.Fatalf("expected 0 failures for context.Canceled, got %d", failures)
	}
	if state := client.CircuitBreakerTransportState(cbt); state != client.CircuitBreakerClosed {
		t.Fatalf("expected closed state, got %q", state)
	}
}

func TestCircuitBreakerTransport_ClientErrorsNotFailure(t *testing.T) {
	for _, status := range []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusConflict,
		http.StatusTooManyRequests,
	} {
		baseTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Body: http.NoBody}, nil
		})

		cbt := client.NewCircuitBreakerTransportWithOptions(baseTransport, client.CircuitBreakerOptions{
			Threshold: 1,
		})

		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://localhost/test", nil)
		_, _ = cbt.RoundTrip(req)

		if failures := client.CircuitBreakerTransportFailures(cbt); failures != 0 {
			t.Fatalf("status %d should not be a failure, got %d", status, failures)
		}
	}
}

func TestCircuitBreakerTransport_TripAndReset(t *testing.T) {
	cbt := client.NewCircuitBreakerTransportWithOptions(http.DefaultTransport, client.CircuitBreakerOptions{
		Threshold: 5,
	})

	client.CircuitBreakerTransportTrip(cbt)
	if state := client.CircuitBreakerTransportState(cbt); state != client.CircuitBreakerOpen {
		t.Fatalf("expected open state after Trip, got %q", state)
	}

	client.CircuitBreakerTransportReset(cbt)
	if state := client.CircuitBreakerTransportState(cbt); state != client.CircuitBreakerClosed {
		t.Fatalf("expected closed state after Reset, got %q", state)
	}
}

func TestCircuitBreakerTransport_ConcurrentAccess(t *testing.T) {
	baseTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})

	cbt := client.NewCircuitBreakerTransportWithOptions(baseTransport, client.CircuitBreakerOptions{
		Threshold:           10,
		ResetTimeout:        10 * time.Millisecond,
		HalfOpenMaxRequests: 2,
	})

	const numGoroutines = 50
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := range numGoroutines {
		go func(id int) {
			defer wg.Done()
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://localhost/test", nil)
			for range iterations {
				_, _ = cbt.RoundTrip(req)
			}
		}(i)
	}

	wg.Wait()
}

func TestClient_CircuitBreakerInTransport(t *testing.T) {
	ctx := context.Background()
	var serverCalls atomic.Int32
	var shouldFail atomic.Bool
	shouldFail.Store(true)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverCalls.Add(1)
		if shouldFail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer ts.Close()

	parsedURL, _ := url.Parse(ts.URL)

	// Create client with custom transport threshold for testing
	httpClient := &http.Client{
		Transport: client.NewCircuitBreakerTransportWithOptions(http.DefaultTransport, client.CircuitBreakerOptions{
			Threshold:    3,
			ResetTimeout: 50 * time.Millisecond,
		}),
	}

	c := client.New("test_key", &client.ClientOptions{
		BaseURL:    parsedURL,
		HTTPClient: httpClient,
	})

	// Trigger 3 failures
	for i := 1; i <= 3; i++ {
		_, err := c.Search.Keys.List(ctx)
		if !errors.Is(err, client.ErrInternalServerError) {
			t.Fatalf("call %d: expected ErrInternalServerError, got %v", i, err)
		}
	}

	if calls := serverCalls.Load(); calls != 3 {
		t.Fatalf("expected 3 server calls, got %d", calls)
	}

	// 4th call should fail fast via transport: server should NOT be called!
	_, err := c.Search.Keys.List(ctx)
	if !errors.Is(err, client.ErrServiceUnavailable) {
		t.Fatalf("expected ErrServiceUnavailable, got %v", err)
	}
	if calls := serverCalls.Load(); calls != 3 {
		t.Fatalf("expected server calls to remain 3, got %d", calls)
	}

	// Recover the server
	shouldFail.Store(false)
	time.Sleep(60 * time.Millisecond)

	// Probe request should succeed and close the circuit
	_, err = c.Search.Keys.List(ctx)
	if err != nil {
		t.Fatalf("expected probe request to succeed, got %v", err)
	}
	if calls := serverCalls.Load(); calls != 4 {
		t.Fatalf("expected 4 server calls after recovery probe, got %d", calls)
	}

	// Subsequent request succeeds
	_, err = c.Search.Keys.List(ctx)
	if err != nil {
		t.Fatalf("expected normal request to succeed, got %v", err)
	}
	if calls := serverCalls.Load(); calls != 5 {
		t.Fatalf("expected 5 server calls, got %d", calls)
	}
}

func TestClient_DefaultTransportWrapsWithCircuitBreaker(t *testing.T) {
	ctx := context.Background()
	var serverCalls atomic.Int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	parsedURL, _ := url.Parse(ts.URL)

	// Default client (no options passed) has circuit breaker in its transport (threshold = 5)
	c := client.New("test_key", &client.ClientOptions{
		BaseURL: parsedURL,
	})

	// 5 failures
	for i := 1; i <= 5; i++ {
		_, err := c.Search.Keys.List(ctx)
		if !errors.Is(err, client.ErrInternalServerError) {
			t.Fatalf("call %d: expected ErrInternalServerError, got %v", i, err)
		}
	}
	if calls := serverCalls.Load(); calls != 5 {
		t.Fatalf("expected 5 server calls, got %d", calls)
	}

	// 6th call should fail fast with ErrServiceUnavailable without contacting server
	_, err := c.Search.Keys.List(ctx)
	if !errors.Is(err, client.ErrServiceUnavailable) {
		t.Fatalf("expected ErrServiceUnavailable, got %v", err)
	}
	if calls := serverCalls.Load(); calls != 5 {
		t.Fatalf("expected server calls to stay 5, got %d", calls)
	}
}

func TestClient_HTTPClientTransportWrapping(t *testing.T) {
	t.Run("user HTTPClient is copied and original is not mutated", func(t *testing.T) {
		customTransport := &http.Transport{}
		userClient := &http.Client{
			Transport: customTransport,
			Timeout:   15 * time.Second,
		}

		c := client.New("test_key", &client.ClientOptions{
			HTTPClient: userClient,
		})

		// Caller's client must NOT have its transport mutated
		if userClient.Transport != customTransport {
			t.Errorf("expected userClient.Transport to not be mutated, got %v", userClient.Transport)
		}

		// Client's internal HTTP client must be a copy
		internalClient := client.ClientHTTPClient(c)
		if internalClient == userClient {
			t.Error("expected internal httpClient to be a copy, got same pointer")
		}

		// Internal client's transport must be wrapped in circuitBreakerTransport
		if !client.IsCircuitBreakerTransport(internalClient.Transport) {
			t.Errorf("expected internalClient.Transport to be a circuitBreakerTransport, got %T", internalClient.Transport)
		}
	})

	t.Run("user HTTPClient with nil transport defaults to http.DefaultTransport wrapped", func(t *testing.T) {
		userClient := &http.Client{
			Timeout: 10 * time.Second,
		}

		c := client.New("test_key", &client.ClientOptions{
			HTTPClient: userClient,
		})

		// User client transport must remain nil
		if userClient.Transport != nil {
			t.Errorf("expected userClient.Transport to remain nil, got %v", userClient.Transport)
		}

		// Internal client must have a circuitBreakerTransport wrapping http.DefaultTransport
		internalClient := client.ClientHTTPClient(c)
		if !client.IsCircuitBreakerTransport(internalClient.Transport) {
			t.Errorf("expected internalClient.Transport to be a circuitBreakerTransport, got %T", internalClient.Transport)
		}
	})

	t.Run("user HTTPClient with already wrapped transport avoids double wrapping", func(t *testing.T) {
		alreadyWrapped := client.NewCircuitBreakerTransport(http.DefaultTransport)
		userClient := &http.Client{
			Transport: alreadyWrapped,
		}

		c := client.New("test_key", &client.ClientOptions{
			HTTPClient: userClient,
		})

		internalClient := client.ClientHTTPClient(c)
		if internalClient.Transport != alreadyWrapped {
			t.Errorf("expected already wrapped transport not to be wrapped again, got %v", internalClient.Transport)
		}
	})
}
