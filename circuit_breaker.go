// Copyright (c) 2026, Janoš Guljaš <janos@resenje.org>
// All rights reserved.

package sajberpank

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"
)

// Default circuit breaker configuration values.
const (
	defaultCircuitBreakerThreshold           = 5
	defaultCircuitBreakerResetTimeout        = 30 * time.Second
	defaultCircuitBreakerHalfOpenMaxRequests = 1
)

type circuitBreakerState string

const (
	circuitBreakerClosed   circuitBreakerState = "closed"
	circuitBreakerHalfOpen circuitBreakerState = "half-open"
	circuitBreakerOpen     circuitBreakerState = "open"
)

type circuitBreakerOptions struct {
	threshold           int
	resetTimeout        time.Duration
	halfOpenMaxRequests int
	isFailure           func(resp *http.Response, err error) bool
	onStateChange       func(from, to circuitBreakerState)
}

type circuitBreaker struct {
	mu                  sync.Mutex
	state               circuitBreakerState
	threshold           int
	resetTimeout        time.Duration
	halfOpenMaxRequests int
	isFailure           func(resp *http.Response, err error) bool
	onStateChange       func(from, to circuitBreakerState)

	failures          int
	halfOpenRequests  int
	halfOpenSuccesses int
	openedAt          time.Time
	lastStateChange   time.Time
}

func newCircuitBreaker(opts circuitBreakerOptions) *circuitBreaker {
	threshold := opts.threshold
	if threshold <= 0 {
		threshold = defaultCircuitBreakerThreshold
	}

	resetTimeout := opts.resetTimeout
	if resetTimeout <= 0 {
		resetTimeout = defaultCircuitBreakerResetTimeout
	}

	halfOpenMaxRequests := opts.halfOpenMaxRequests
	if halfOpenMaxRequests <= 0 {
		halfOpenMaxRequests = defaultCircuitBreakerHalfOpenMaxRequests
	}

	isFailure := opts.isFailure
	if isFailure == nil {
		isFailure = defaultIsFailure
	}

	now := time.Now()
	return &circuitBreaker{
		state:               circuitBreakerClosed,
		threshold:           threshold,
		resetTimeout:        resetTimeout,
		halfOpenMaxRequests: halfOpenMaxRequests,
		isFailure:           isFailure,
		onStateChange:       opts.onStateChange,
		lastStateChange:     now,
	}
}

func defaultIsFailure(resp *http.Response, err error) bool {
	if err != nil {
		return !errors.Is(err, context.Canceled)
	}
	return resp != nil && resp.StatusCode >= 500
}

func (cb *circuitBreaker) allow() (func(resp *http.Response, err error), error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()

	if cb.state == circuitBreakerOpen {
		if now.Sub(cb.openedAt) >= cb.resetTimeout {
			notify := cb.transitionTo(circuitBreakerHalfOpen, now)
			if notify != nil {
				defer notify()
			}
		} else {
			return nil, ErrServiceUnavailable
		}
	}

	if cb.state == circuitBreakerHalfOpen {
		if cb.halfOpenRequests >= cb.halfOpenMaxRequests {
			return nil, ErrServiceUnavailable
		}
		cb.halfOpenRequests++
		return cb.makeDoneFunc(), nil
	}

	return cb.makeDoneFunc(), nil
}

func (cb *circuitBreaker) makeDoneFunc() func(resp *http.Response, err error) {
	var once sync.Once
	return func(resp *http.Response, err error) {
		once.Do(func() {
			cb.finishRequest(resp, err)
		})
	}
}

func (cb *circuitBreaker) finishRequest(resp *http.Response, err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	failed := cb.isFailure(resp, err)
	now := time.Now()
	var notify func()

	switch cb.state {
	case circuitBreakerClosed:
		if failed {
			cb.failures++
			if cb.failures >= cb.threshold {
				notify = cb.transitionTo(circuitBreakerOpen, now)
			}
		} else {
			cb.failures = 0
		}

	case circuitBreakerHalfOpen:
		if failed {
			notify = cb.transitionTo(circuitBreakerOpen, now)
		} else {
			cb.halfOpenSuccesses++
			if cb.halfOpenSuccesses >= cb.halfOpenMaxRequests {
				notify = cb.transitionTo(circuitBreakerClosed, now)
			}
		}

	case circuitBreakerOpen:
	}

	if notify != nil {
		defer notify()
	}
}

func (cb *circuitBreaker) transitionTo(newState circuitBreakerState, now time.Time) func() {
	if cb.state == newState {
		return nil
	}
	oldState := cb.state
	cb.state = newState
	cb.lastStateChange = now

	switch newState {
	case circuitBreakerClosed:
		cb.failures = 0
		cb.halfOpenRequests = 0
		cb.halfOpenSuccesses = 0
	case circuitBreakerOpen:
		cb.openedAt = now
		cb.failures = 0
		cb.halfOpenRequests = 0
		cb.halfOpenSuccesses = 0
	case circuitBreakerHalfOpen:
		cb.halfOpenRequests = 0
		cb.halfOpenSuccesses = 0
	}

	if cb.onStateChange != nil {
		fn := cb.onStateChange
		return func() {
			fn(oldState, newState)
		}
	}
	return nil
}

func (cb *circuitBreaker) currentState() circuitBreakerState {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == circuitBreakerOpen && time.Since(cb.openedAt) >= cb.resetTimeout {
		return circuitBreakerHalfOpen
	}
	return cb.state
}

func (cb *circuitBreaker) failuresCount() int {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.failures
}

func (cb *circuitBreaker) reset() {
	cb.mu.Lock()
	notify := cb.transitionTo(circuitBreakerClosed, time.Now())
	cb.mu.Unlock()
	if notify != nil {
		notify()
	}
}

func (cb *circuitBreaker) trip() {
	cb.mu.Lock()
	notify := cb.transitionTo(circuitBreakerOpen, time.Now())
	cb.mu.Unlock()
	if notify != nil {
		notify()
	}
}

type circuitBreakerTransport struct {
	transport http.RoundTripper
	cb        *circuitBreaker
}

func newCircuitBreakerTransport(transport http.RoundTripper) *circuitBreakerTransport {
	return newCircuitBreakerTransportWithOptions(transport, circuitBreakerOptions{
		threshold:           defaultCircuitBreakerThreshold,
		resetTimeout:        defaultCircuitBreakerResetTimeout,
		halfOpenMaxRequests: defaultCircuitBreakerHalfOpenMaxRequests,
	})
}

func newCircuitBreakerTransportWithOptions(transport http.RoundTripper, opts circuitBreakerOptions) *circuitBreakerTransport {
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &circuitBreakerTransport{
		transport: transport,
		cb:        newCircuitBreaker(opts),
	}
}

func (t *circuitBreakerTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	done, cbErr := t.cb.allow()
	if cbErr != nil {
		return nil, cbErr
	}
	defer func() {
		done(resp, err)
	}()
	return t.transport.RoundTrip(req)
}
