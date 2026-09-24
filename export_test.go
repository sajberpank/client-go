// Copyright (c) 2026, Janoš Guljaš <janos@resenje.org>
// All rights reserved.

package sajberpank

import (
	"net/http"
	"time"
)

type CircuitBreakerState = circuitBreakerState

const (
	CircuitBreakerClosed   = circuitBreakerClosed
	CircuitBreakerHalfOpen = circuitBreakerHalfOpen
	CircuitBreakerOpen     = circuitBreakerOpen
)

type CircuitBreakerOptions struct {
	Threshold           int
	ResetTimeout        time.Duration
	HalfOpenMaxRequests int
	IsFailure           func(resp *http.Response, err error) bool
	OnStateChange       func(from, to CircuitBreakerState)
}

// Export internal functions for black-box testing (e.g. package sajberpank_test).
var (
	NewKeyEnvelope             = newKeyEnvelope
	NewKeyEnvelopeWithSuite    = newKeyEnvelopeWithSuite
	NewCircuitBreakerTransport = newCircuitBreakerTransport
)

func NewCircuitBreakerTransportWithOptions(transport http.RoundTripper, opts CircuitBreakerOptions) *circuitBreakerTransport {
	return newCircuitBreakerTransportWithOptions(transport, circuitBreakerOptions{
		threshold:           opts.Threshold,
		resetTimeout:        opts.ResetTimeout,
		halfOpenMaxRequests: opts.HalfOpenMaxRequests,
		isFailure:           opts.IsFailure,
		onStateChange:       opts.OnStateChange,
	})
}

func CircuitBreakerTransportState(rt http.RoundTripper) CircuitBreakerState {
	if cbt, ok := rt.(*circuitBreakerTransport); ok {
		return cbt.cb.currentState()
	}
	return ""
}

func CircuitBreakerTransportFailures(rt http.RoundTripper) int {
	if cbt, ok := rt.(*circuitBreakerTransport); ok {
		return cbt.cb.failuresCount()
	}
	return 0
}

func CircuitBreakerTransportTrip(rt http.RoundTripper) {
	if cbt, ok := rt.(*circuitBreakerTransport); ok {
		cbt.cb.trip()
	}
}

func CircuitBreakerTransportReset(rt http.RoundTripper) {
	if cbt, ok := rt.(*circuitBreakerTransport); ok {
		cbt.cb.reset()
	}
}

func ClientHTTPClient(c *Client) *http.Client {
	return c.client
}

func IsCircuitBreakerTransport(rt http.RoundTripper) bool {
	_, ok := rt.(*circuitBreakerTransport)
	return ok
}
