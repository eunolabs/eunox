// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package circuitbreaker

import "net/http"

// Transport wraps an http.RoundTripper with circuit breaker protection.
// When the breaker is open, requests are rejected immediately with ErrOpen.
type Transport struct {
	inner   http.RoundTripper
	breaker *Breaker
}

// NewTransport creates an HTTP transport wrapped with a circuit breaker.
// If inner is nil, http.DefaultTransport is used.
func NewTransport(inner http.RoundTripper, breaker *Breaker) *Transport {
	if breaker == nil {
		panic("circuitbreaker: breaker must not be nil")
	}
	if inner == nil {
		inner = http.DefaultTransport
	}
	return &Transport{inner: inner, breaker: breaker}
}

// RoundTrip implements http.RoundTripper with circuit breaker protection.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := req.Context().Err(); err != nil {
		return nil, err
	}

	if !t.breaker.Allow() {
		return nil, ErrOpen
	}

	resp, err := t.inner.RoundTrip(req)
	if err != nil {
		t.breaker.RecordFailure()
		return nil, err
	}

	// Treat 5xx as failures for circuit breaker purposes.
	if resp.StatusCode >= 500 {
		t.breaker.RecordFailure()
	} else {
		t.breaker.RecordSuccess()
	}

	return resp, nil
}
