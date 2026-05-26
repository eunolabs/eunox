// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/edgeobs/eunox/internal/gateway"
	"github.com/edgeobs/eunox/pkg/capability"
	"github.com/edgeobs/eunox/pkg/enforcement"
	"github.com/edgeobs/eunox/pkg/killswitch"
	"github.com/edgeobs/eunox/pkg/revocation"
)

// BenchmarkEnforce_SimpleAllow benchmarks the enforce endpoint for simple allow decisions.
func BenchmarkEnforce_SimpleAllow(b *testing.B) {
	claims := &capability.TokenPayload{
		Subject:   "bench-user",
		JWTID:     "bench-jti",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	}

	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)
	app := gateway.New(gateway.Config{
		GatewayAudience: "bench-gateway",
		AdminAPIKey:     "bench-admin-key",
	}, gateway.Dependencies{
		Engine:      enforcement.New(),
		KillSwitch:  killswitch.NewInMemory(),
		Revocation:  revocation.NewInMemory(),
		JWTVerifier: &staticClaimsVerifier{claims: claims},
		DPoPStore:   dpopStore,
	})
	handler := app.Handler()

	payload, _ := json.Marshal(map[string]any{
		"token": "bench-token",
		"request": map[string]any{
			"sessionId": "bench-sess",
			"toolName":  "file-read",
			"context":   map[string]any{"sourceIp": "10.0.0.1"},
		},
	})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			b.Fatalf("unexpected status %d", w.Code)
		}
	}
}

// BenchmarkEnforce_WithConditions benchmarks enforcement with multiple conditions.
func BenchmarkEnforce_WithConditions(b *testing.B) {
	claims := &capability.TokenPayload{
		Subject:   "bench-user",
		JWTID:     "bench-jti",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{
				Resource: "db://*",
				Actions:  []string{"query"},
				Conditions: []capability.Condition{
					&capability.IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}},
					&capability.AllowedOperationsCondition{Operations: []string{"query"}},
				},
			},
		},
	}

	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)
	app := gateway.New(gateway.Config{
		GatewayAudience: "bench-gateway",
		AdminAPIKey:     "bench-admin-key",
	}, gateway.Dependencies{
		Engine:      enforcement.New(),
		KillSwitch:  killswitch.NewInMemory(),
		Revocation:  revocation.NewInMemory(),
		JWTVerifier: &staticClaimsVerifier{claims: claims},
		DPoPStore:   dpopStore,
	})
	handler := app.Handler()

	payload, _ := json.Marshal(map[string]any{
		"token": "bench-token",
		"request": map[string]any{
			"sessionId": "bench-sess",
			"toolName":  "db://prod/users",
			"context":   map[string]any{"sourceIp": "10.0.0.1", "operation": "query"},
		},
	})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			b.Fatalf("unexpected status %d", w.Code)
		}
	}
}

// BenchmarkEnforce_Deny benchmarks the enforce endpoint for deny decisions.
func BenchmarkEnforce_Deny(b *testing.B) {
	claims := &capability.TokenPayload{
		Subject:   "bench-user",
		JWTID:     "bench-jti",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{Resource: "file-read-only", Actions: []string{"read"}},
		},
	}

	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)
	app := gateway.New(gateway.Config{
		GatewayAudience: "bench-gateway",
		AdminAPIKey:     "bench-admin-key",
	}, gateway.Dependencies{
		Engine:      enforcement.New(),
		KillSwitch:  killswitch.NewInMemory(),
		Revocation:  revocation.NewInMemory(),
		JWTVerifier: &staticClaimsVerifier{claims: claims},
		DPoPStore:   dpopStore,
	})
	handler := app.Handler()

	payload, _ := json.Marshal(map[string]any{
		"token": "bench-token",
		"request": map[string]any{
			"sessionId": "bench-sess",
			"toolName":  "admin-panel",
			"context":   map[string]any{"sourceIp": "10.0.0.1"},
		},
	})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			b.Fatalf("unexpected status %d", w.Code)
		}
	}
}

// BenchmarkEnforce_WithKillSwitchCheck benchmarks enforcement with active kill-switch lookups.
func BenchmarkEnforce_WithKillSwitchCheck(b *testing.B) {
	ks := killswitch.NewInMemory()
	// Populate some killed agents/sessions to ensure lookup overhead
	for i := 0; i < 100; i++ {
		_ = ks.KillAgent(context.Background(), "killed-agent-"+string(rune(i+'a')))
	}

	claims := &capability.TokenPayload{
		Subject:   "active-agent",
		JWTID:     "bench-jti",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	}

	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)
	app := gateway.New(gateway.Config{
		GatewayAudience: "bench-gateway",
		AdminAPIKey:     "bench-admin-key",
	}, gateway.Dependencies{
		Engine:      enforcement.New(),
		KillSwitch:  ks,
		Revocation:  revocation.NewInMemory(),
		JWTVerifier: &staticClaimsVerifier{claims: claims},
		DPoPStore:   dpopStore,
	})
	handler := app.Handler()

	payload, _ := json.Marshal(map[string]any{
		"token": "bench-token",
		"request": map[string]any{
			"sessionId": "bench-sess",
			"toolName":  "tool",
			"context":   map[string]any{"sourceIp": "10.0.0.1"},
		},
	})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			b.Fatalf("unexpected status %d", w.Code)
		}
	}
}

// BenchmarkEnforce_WithRevocationCheck benchmarks enforcement with populated revocation store.
func BenchmarkEnforce_WithRevocationCheck(b *testing.B) {
	revStore := revocation.NewInMemory()
	// Populate revocation store
	for i := 0; i < 1000; i++ {
		_ = revStore.Revoke(context.Background(), "revoked-jti-"+string(rune(i)), 1*time.Hour)
	}

	claims := &capability.TokenPayload{
		Subject:   "bench-user",
		JWTID:     "valid-jti",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	}

	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)
	app := gateway.New(gateway.Config{
		GatewayAudience: "bench-gateway",
		AdminAPIKey:     "bench-admin-key",
	}, gateway.Dependencies{
		Engine:      enforcement.New(),
		KillSwitch:  killswitch.NewInMemory(),
		Revocation:  revStore,
		JWTVerifier: &staticClaimsVerifier{claims: claims},
		DPoPStore:   dpopStore,
	})
	handler := app.Handler()

	payload, _ := json.Marshal(map[string]any{
		"token": "bench-token",
		"request": map[string]any{
			"sessionId": "bench-sess",
			"toolName":  "tool",
			"context":   map[string]any{"sourceIp": "10.0.0.1"},
		},
	})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			b.Fatalf("unexpected status %d", w.Code)
		}
	}
}

// TestBenchmark_EnforceP99Threshold is a regression test that verifies the enforce endpoint
// completes within an acceptable latency budget (p99 < 5ms for in-memory backends).
func TestBenchmark_EnforceP99Threshold(b *testing.T) {
	claims := &capability.TokenPayload{
		Subject:   "perf-user",
		JWTID:     "perf-jti",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	}

	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)
	app := gateway.New(gateway.Config{
		GatewayAudience: "perf-gateway",
		AdminAPIKey:     "perf-admin-key",
	}, gateway.Dependencies{
		Engine:      enforcement.New(),
		KillSwitch:  killswitch.NewInMemory(),
		Revocation:  revocation.NewInMemory(),
		JWTVerifier: &staticClaimsVerifier{claims: claims},
		DPoPStore:   dpopStore,
	})
	handler := app.Handler()

	payload, _ := json.Marshal(map[string]any{
		"token": "perf-token",
		"request": map[string]any{
			"sessionId": "perf-sess",
			"toolName":  "tool",
			"context":   map[string]any{"sourceIp": "10.0.0.1"},
		},
	})

	const iterations = 1000
	durations := make([]time.Duration, iterations)

	// Warmup
	for i := 0; i < 50; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}

	// Measure
	for i := 0; i < iterations; i++ {
		start := time.Now()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		durations[i] = time.Since(start)
		require.Equal(b, http.StatusOK, w.Code)
	}

	// Sort and compute p99
	sortDurations(durations)
	p99 := durations[int(float64(iterations)*0.99)]
	p50 := durations[iterations/2]

	b.Logf("p50=%v p99=%v", p50, p99)

	// p99 should be < 5ms for in-memory backends on CI
	if p99 > 5*time.Millisecond {
		b.Errorf("p99 latency %v exceeds 5ms threshold", p99)
	}
}

// sortDurations sorts a slice of durations in-place.
func sortDurations(d []time.Duration) {
	n := len(d)
	for i := 1; i < n; i++ {
		key := d[i]
		j := i - 1
		for j >= 0 && d[j] > key {
			d[j+1] = d[j]
			j--
		}
		d[j+1] = key
	}
}
