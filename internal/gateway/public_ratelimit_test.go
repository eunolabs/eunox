// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package gateway_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/gateway"
	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/killswitch"
	"github.com/eunolabs/eunox/pkg/revocation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newPublicRateLimitTestApp(t *testing.T, ratePerMin int) *gateway.App {
	t.Helper()

	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ks := killswitch.NewInMemory()
	revStore := revocation.NewInMemory()
	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	deps := gateway.Dependencies{
		Engine:      engine,
		KillSwitch:  ks,
		Revocation:  revStore,
		JWTVerifier: &mockJWTVerifier{},
		DPoPStore:   dpopStore,
		Logger:      logger,
	}

	cfg := gateway.Config{
		GatewayAudience:   "test-gateway",
		RateLimitRequests: ratePerMin,
		RateLimitWindow:   time.Minute,
	}

	app, err := gateway.New(&cfg, &deps)
	require.NoError(t, err)
	return app
}

// enforceRequest builds a minimal POST /api/v1/enforce request with RemoteAddr set.
func enforceRequest(remoteAddr string) *http.Request {
	body := `{"token":"tok","request":{"tool":"t","action":"a"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remoteAddr
	return req
}

func TestPublicRateLimitMiddleware_AllowsWithinLimit(t *testing.T) {
	t.Parallel()
	app := newPublicRateLimitTestApp(t, 5)

	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		app.Handler().ServeHTTP(w, enforceRequest("10.0.0.1:1234"))
		// 401 is expected (no valid JWT) but not 429.
		assert.NotEqual(t, http.StatusTooManyRequests, w.Code, "request %d should not be rate-limited", i+1)
		assert.NotEmpty(t, w.Header().Get("X-RateLimit-Limit"))
		assert.NotEmpty(t, w.Header().Get("X-RateLimit-Remaining"))
		assert.NotEmpty(t, w.Header().Get("X-RateLimit-Reset"))
	}
}

func TestPublicRateLimitMiddleware_BlocksOverLimit(t *testing.T) {
	t.Parallel()
	app := newPublicRateLimitTestApp(t, 3)

	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		app.Handler().ServeHTTP(w, enforceRequest("10.0.0.2:1234"))
		require.NotEqual(t, http.StatusTooManyRequests, w.Code, "request %d should not be rate-limited yet", i+1)
	}

	// Fourth request should be rate-limited.
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, enforceRequest("10.0.0.2:1234"))
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Contains(t, w.Body.String(), "rate limit exceeded")
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
}

func TestPublicRateLimitMiddleware_PerIPIsolation(t *testing.T) {
	t.Parallel()
	app := newPublicRateLimitTestApp(t, 2)

	// Exhaust limit for IP A.
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		app.Handler().ServeHTTP(w, enforceRequest("192.168.1.1:5555"))
		require.NotEqual(t, http.StatusTooManyRequests, w.Code)
	}

	// IP A should now be blocked.
	wA := httptest.NewRecorder()
	app.Handler().ServeHTTP(wA, enforceRequest("192.168.1.1:5555"))
	assert.Equal(t, http.StatusTooManyRequests, wA.Code)

	// IP B should still be allowed.
	wB := httptest.NewRecorder()
	app.Handler().ServeHTTP(wB, enforceRequest("192.168.1.2:5555"))
	assert.NotEqual(t, http.StatusTooManyRequests, wB.Code)
}

func TestPublicRateLimitMiddleware_RateLimitHeaders(t *testing.T) {
	t.Parallel()
	app := newPublicRateLimitTestApp(t, 5)

	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, enforceRequest("172.16.0.1:9999"))

	assert.Equal(t, "5", w.Header().Get("X-RateLimit-Limit"))
	remaining, err := strconv.Atoi(w.Header().Get("X-RateLimit-Remaining"))
	require.NoError(t, err)
	assert.Equal(t, 4, remaining)
	resetStr := w.Header().Get("X-RateLimit-Reset")
	resetUnix, err := strconv.ParseInt(resetStr, 10, 64)
	require.NoError(t, err)
	assert.Greater(t, resetUnix, time.Now().Unix()-2)
}

func TestPublicRateLimitMiddleware_DefaultRate(t *testing.T) {
	t.Parallel()
	// RateLimitRequests = 0 should use the default (600 req/min).
	// We just verify the app starts and requests are served (not 429) at low traffic.
	app := newPublicRateLimitTestApp(t, 0)

	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		app.Handler().ServeHTTP(w, enforceRequest("1.2.3.4:4321"))
		assert.NotEqual(t, http.StatusTooManyRequests, w.Code, "request %d should not be rate-limited", i+1)
		assert.Equal(t, "600", w.Header().Get("X-RateLimit-Limit"))
	}
}

func TestPublicRateLimitMiddleware_HealthNotRateLimited(t *testing.T) {
	t.Parallel()
	app := newPublicRateLimitTestApp(t, 1)

	// Exhaust the public limit.
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, enforceRequest("8.8.8.8:80"))
	require.NotEqual(t, http.StatusTooManyRequests, w.Code)

	// Verify limit is exhausted.
	w = httptest.NewRecorder()
	app.Handler().ServeHTTP(w, enforceRequest("8.8.8.8:80"))
	require.Equal(t, http.StatusTooManyRequests, w.Code)

	// Health endpoints are outside the /api/v1 group and must not be rate-limited.
	req := httptest.NewRequest(http.MethodGet, "/health/live", http.NoBody)
	req.RemoteAddr = "8.8.8.8:80"
	w = httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
