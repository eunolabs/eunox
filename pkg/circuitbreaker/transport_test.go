// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package circuitbreaker_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/edgeobs/eunox/pkg/circuitbreaker"
)

func TestTransport_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	b := circuitbreaker.New(circuitbreaker.DefaultConfig())
	client := &http.Client{Transport: circuitbreaker.NewTransport(nil, b)}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	stats := b.Stats()
	if stats.TotalSuccesses != 1 {
		t.Errorf("expected 1 success, got %d", stats.TotalSuccesses)
	}
}

func TestTransport_5xxCountsAsFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := circuitbreaker.Config{
		FailureThreshold:  2,
		CooldownDuration:  time.Minute,
		HalfOpenMaxProbes: 1,
	}
	b := circuitbreaker.New(cfg)
	client := &http.Client{Transport: circuitbreaker.NewTransport(nil, b)}

	for i := 0; i < 2; i++ {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resp.Body.Close()
	}

	// Breaker should be open now.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
	_, err := client.Do(req)
	if !errors.Is(err, circuitbreaker.ErrOpen) {
		t.Fatalf("expected ErrOpen, got %v", err)
	}
}

func TestTransport_NetworkErrorCountsAsFailure(t *testing.T) {
	cfg := circuitbreaker.Config{
		FailureThreshold:  1,
		CooldownDuration:  time.Minute,
		HalfOpenMaxProbes: 1,
	}
	b := circuitbreaker.New(cfg)
	client := &http.Client{Transport: circuitbreaker.NewTransport(nil, b)}

	// Request to a closed server.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:1", http.NoBody)
	_, err := client.Do(req)
	if err == nil {
		t.Fatal("expected network error")
	}

	// Breaker should be open now.
	req, _ = http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:1", http.NoBody)
	_, err = client.Do(req)
	if !errors.Is(err, circuitbreaker.ErrOpen) {
		t.Fatalf("expected ErrOpen, got %v", err)
	}
}

func TestTransport_CancelledContext(t *testing.T) {
	b := circuitbreaker.New(circuitbreaker.DefaultConfig())
	client := &http.Client{Transport: circuitbreaker.NewTransport(nil, b)}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.com", http.NoBody)
	_, err := client.Do(req)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestTransport_4xxCountsAsSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	b := circuitbreaker.New(circuitbreaker.DefaultConfig())
	client := &http.Client{Transport: circuitbreaker.NewTransport(nil, b)}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()

	stats := b.Stats()
	if stats.TotalSuccesses != 1 {
		t.Errorf("expected 1 success (4xx is not a circuit failure), got %d", stats.TotalSuccesses)
	}
}
