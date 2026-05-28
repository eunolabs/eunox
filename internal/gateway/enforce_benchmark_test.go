// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package gateway_test provides benchmarks for the enforcement hot path (P2-1).
//
// Run with:
//
//	go test -bench=BenchmarkHandleEnforce -benchtime=5s -count=3 ./internal/gateway/
//
// P50/P99 latency numbers for each scenario can be extracted with:
//
//	go test -bench=BenchmarkHandleEnforce -benchtime=5s -benchmem ./internal/gateway/ | tee bench.txt
//	benchstat bench.txt  # requires golang.org/x/perf/cmd/benchstat
package gateway_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/edgeobs/eunox/internal/gateway"
	"github.com/edgeobs/eunox/pkg/callcounter"
	"github.com/edgeobs/eunox/pkg/capability"
	"github.com/edgeobs/eunox/pkg/enforcement"
	"github.com/edgeobs/eunox/pkg/killswitch"
	"github.com/edgeobs/eunox/pkg/revocation"
)

// benchmarkEnforceApp builds a gateway App configured for benchmarking.
// tokenCacheTTL > 0 enables the in-process token cache.
func benchmarkEnforceApp(b *testing.B, tokenCacheTTL time.Duration) *gateway.App {
	b.Helper()

	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ks := killswitch.NewInMemory()
	revStore := revocation.NewInMemory()
	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	verifier := &mockJWTVerifier{
		claims: &capability.TokenPayload{
			Subject:   "bench-subject",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			Capabilities: []capability.Constraint{
				{
					Resource: "echo",
					Actions:  []string{"*"},
				},
			},
		},
	}

	deps := gateway.Dependencies{
		Engine:      engine,
		KillSwitch:  ks,
		Revocation:  revStore,
		JWTVerifier: verifier,
		DPoPStore:   dpopStore,
		Logger:      logger,
	}

	cfg := gateway.Config{
		GatewayAudience:         "bench-gateway",
		TokenCacheTTL:           tokenCacheTTL,
		RateLimitRequests:       1_000_000,
		RateLimitWindow:         time.Minute,
	}

	app, err := gateway.New(&cfg, &deps)
	if err != nil {
		b.Fatalf("gateway.New: %v", err)
	}
	ctx := b.Context()
	app.Start(ctx)
	b.Cleanup(app.Close)
	return app
}

// benchmarkEnforcePayload returns a serialised enforce request for the given
// token string.
func benchmarkEnforcePayload(b *testing.B, token string) []byte {
	b.Helper()
	payload := struct {
		Token   string                    `json:"token"`
		Request capability.EnforceRequest `json:"request"`
	}{
		Token: token,
		Request: capability.EnforceRequest{
			ToolName: "echo",
			Context: capability.EnforceRequestContext{
				Operation: "call",
			},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		b.Fatalf("marshal payload: %v", err)
	}
	return body
}

// BenchmarkHandleEnforce_NoCache measures the enforcement hot path without an
// in-process token cache: every request performs a full JWKS verify +
// revocation check.
func BenchmarkHandleEnforce_NoCache(b *testing.B) {
	app := benchmarkEnforceApp(b, 0)
	body := benchmarkEnforcePayload(b, "bench-token-no-cache")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			app.Handler().ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				b.Errorf("unexpected status %d", w.Code)
			}
		}
	})
}

// BenchmarkHandleEnforce_CacheHit measures the enforcement hot path with a
// warm in-process token cache.  After the first request, all subsequent
// requests are served from the cache without JWKS + revocation round-trips.
func BenchmarkHandleEnforce_CacheHit(b *testing.B) {
	app := benchmarkEnforceApp(b, 30*time.Second)
	body := benchmarkEnforcePayload(b, "bench-token-cache-hit")

	// Warm the cache with a single enforce request before timing starts.
	warmReq := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", bytes.NewReader(body))
	warmReq.Header.Set("Content-Type", "application/json")
	warmW := httptest.NewRecorder()
	app.Handler().ServeHTTP(warmW, warmReq)
	if warmW.Code != http.StatusOK {
		b.Fatalf("warm-up enforce failed with status %d", warmW.Code)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			app.Handler().ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				b.Errorf("unexpected status %d", w.Code)
			}
		}
	})
}

// BenchmarkHandleEnforce_CacheMiss_Concurrent simulates the cache-miss path
// under concurrent load.  Each goroutine uses a unique token, so every request
// is a cache miss, but the parallel verification is exercised.
func BenchmarkHandleEnforce_CacheMiss_Concurrent(b *testing.B) {
	app := benchmarkEnforceApp(b, 30*time.Second)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			i++
			// Unique tokens per iteration to force cache misses.
			token := "bench-miss-token-" + string(rune('a'+i%26))
			body := benchmarkEnforcePayload(b, token)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			app.Handler().ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				b.Errorf("unexpected status %d", w.Code)
			}
		}
	})
}
