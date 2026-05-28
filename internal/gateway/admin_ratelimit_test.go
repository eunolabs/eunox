// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
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

func newRateLimitTestApp(t *testing.T, ratePerMin int) *gateway.App {
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
		GatewayAudience:         "test-gateway",
		AdminAPIKey:             testAdminKey,
		TenantID:                "tenant-1",
		AdminRateLimitPerMinute: ratePerMin,
	}

	app, err := gateway.New(&cfg, &deps)
	require.NoError(t, err)
	return app
}

func TestAdminRateLimitMiddleware_AllowsWithinLimit(t *testing.T) {
	app := newRateLimitTestApp(t, 5)

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/admin/usage", http.NoBody)
		req.Header.Set("X-Admin-Api-Key", testAdminKey)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()
		app.AdminHandler().ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "request %d should succeed", i+1)
		assert.NotEmpty(t, w.Header().Get("X-RateLimit-Limit"))
		assert.NotEmpty(t, w.Header().Get("X-RateLimit-Remaining"))
		assert.NotEmpty(t, w.Header().Get("X-RateLimit-Reset"))
	}
}

func TestAdminRateLimitMiddleware_BlocksOverLimit(t *testing.T) {
	app := newRateLimitTestApp(t, 3)

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/admin/usage", http.NoBody)
		req.Header.Set("X-Admin-Api-Key", testAdminKey)
		req.RemoteAddr = "10.0.0.1:9999"
		w := httptest.NewRecorder()
		app.AdminHandler().ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, "request %d should succeed", i+1)
	}

	// Fourth request should be rate-limited.
	req := httptest.NewRequest(http.MethodGet, "/admin/usage", http.NoBody)
	req.Header.Set("X-Admin-Api-Key", testAdminKey)
	req.RemoteAddr = "10.0.0.1:9999"
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Contains(t, w.Body.String(), "rate limit exceeded")
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
}

func TestAdminRateLimitMiddleware_PerIPIsolation(t *testing.T) {
	app := newRateLimitTestApp(t, 2)

	// Exhaust limit for IP A.
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/admin/usage", http.NoBody)
		req.Header.Set("X-Admin-Api-Key", testAdminKey)
		req.RemoteAddr = "1.1.1.1:1234"
		w := httptest.NewRecorder()
		app.AdminHandler().ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
	}

	// IP B should still be allowed.
	req := httptest.NewRequest(http.MethodGet, "/admin/usage", http.NoBody)
	req.Header.Set("X-Admin-Api-Key", testAdminKey)
	req.RemoteAddr = "2.2.2.2:1234"
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminRateLimitMiddleware_IgnoresXForwardedFor(t *testing.T) {
	app := newRateLimitTestApp(t, 2)

	// Exhaust limit for remote address A.
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/admin/usage", http.NoBody)
		req.Header.Set("X-Admin-Api-Key", testAdminKey)
		req.Header.Set("X-Forwarded-For", "9.9.9.9, 8.8.8.8")
		req.RemoteAddr = "127.0.0.1:5555"
		w := httptest.NewRecorder()
		app.AdminHandler().ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
	}

	// Different remote address with same XFF should still be allowed.
	req := httptest.NewRequest(http.MethodGet, "/admin/usage", http.NoBody)
	req.Header.Set("X-Admin-Api-Key", testAdminKey)
	req.Header.Set("X-Forwarded-For", "9.9.9.9, 8.8.8.8")
	req.RemoteAddr = "127.0.0.2:5555"
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Same remote address should be blocked regardless of XFF value.
	req = httptest.NewRequest(http.MethodGet, "/admin/usage", http.NoBody)
	req.Header.Set("X-Admin-Api-Key", testAdminKey)
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 2.2.2.2")
	req.RemoteAddr = "127.0.0.1:5555"
	w = httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

func TestAdminRateLimitMiddleware_DefaultRate(t *testing.T) {
	// AdminRateLimitPerMinute = 0 should use default of 10.
	app := newRateLimitTestApp(t, 0)

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/admin/usage", http.NoBody)
		req.Header.Set("X-Admin-Api-Key", testAdminKey)
		req.RemoteAddr = "5.5.5.5:1111"
		w := httptest.NewRecorder()
		app.AdminHandler().ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, "request %d should succeed", i+1)
	}

	// 11th should be blocked.
	req := httptest.NewRequest(http.MethodGet, "/admin/usage", http.NoBody)
	req.Header.Set("X-Admin-Api-Key", testAdminKey)
	req.RemoteAddr = "5.5.5.5:1111"
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

func TestAdminRateLimitMiddleware_RateLimitHeaders(t *testing.T) {
	app := newRateLimitTestApp(t, 5)

	req := httptest.NewRequest(http.MethodGet, "/admin/usage", http.NoBody)
	req.Header.Set("X-Admin-Api-Key", testAdminKey)
	req.RemoteAddr = "6.6.6.6:2222"
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "5", w.Header().Get("X-RateLimit-Limit"))

	remaining, err := strconv.Atoi(w.Header().Get("X-RateLimit-Remaining"))
	require.NoError(t, err)
	assert.Equal(t, 4, remaining)

	resetStr := w.Header().Get("X-RateLimit-Reset")
	resetUnix, err := strconv.ParseInt(resetStr, 10, 64)
	require.NoError(t, err)
	assert.Greater(t, resetUnix, time.Now().Unix()-2)
}

func TestAdminRateLimitMiddleware_HealthEndpointsNotRateLimited(t *testing.T) {
	app := newRateLimitTestApp(t, 1)

	// Exhaust rate limit with an admin request.
	req := httptest.NewRequest(http.MethodGet, "/admin/usage", http.NoBody)
	req.Header.Set("X-Admin-Api-Key", testAdminKey)
	req.RemoteAddr = "7.7.7.7:3333"
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Health endpoints should still work (they're outside the rate-limited group).
	req = httptest.NewRequest(http.MethodGet, "/health/live", http.NoBody)
	req.RemoteAddr = "7.7.7.7:3333"
	w = httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
