// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package gateway — security-audit Finding 1 tests (internal access required).
//
// Finding 1: X-Forwarded-For IP spoofing is mitigated via TrustedProxyCIDRs.
// These tests live in package gateway (not gateway_test) because extractClientIP
// and isTrustedProxy are unexported methods.
package gateway

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"

	"github.com/edgeobs/eunox/pkg/capability"
	"github.com/stretchr/testify/assert"
)

// makeAppWithCIDRs builds a minimal App with the given trusted-proxy CIDRs.
func makeAppWithCIDRs(t *testing.T, cidrs []string) *App {
	t.Helper()
	app := &App{
		deps: Dependencies{},
	}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("invalid CIDR %q: %v", cidr, err)
		}
		app.trustedProxyNets = append(app.trustedProxyNets, network)
	}
	return app
}

// ─── Finding 1: X-Forwarded-For / TrustedProxyCIDRs ─────────────────────────

func TestExtractClientIP_NoTrustedProxies_IgnoresXFF(t *testing.T) {
	// When TrustedProxyCIDRs is empty, XFF must never be trusted.
	app := makeAppWithCIDRs(t, nil)

	req, _ := http.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "203.0.113.1:54321"
	req.Header.Set("X-Forwarded-For", "10.10.10.10")

	assert.Equal(t, "203.0.113.1", app.extractClientIP(req))
}

func TestExtractClientIP_TrustedProxy_UsesXFF(t *testing.T) {
	// When RemoteAddr matches a trusted CIDR, the rightmost untrusted XFF IP is used.
	app := makeAppWithCIDRs(t, []string{"10.0.0.0/8"})

	req, _ := http.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "10.0.0.2:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.42, 10.0.0.1")

	assert.Equal(t, "203.0.113.42", app.extractClientIP(req))
}

func TestExtractClientIP_UntrustedProxy_IgnoresXFF(t *testing.T) {
	// When RemoteAddr does NOT match any trusted CIDR, XFF is ignored.
	app := makeAppWithCIDRs(t, []string{"10.0.0.0/8"})

	req, _ := http.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "172.16.0.5:9999"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	assert.Equal(t, "172.16.0.5", app.extractClientIP(req))
}

func TestExtractClientIP_MultipleXFFEntries_UsesLeftmost(t *testing.T) {
	// XFF chain "clientIP, proxy1, proxy2" → rightmost untrusted is the original client.
	app := makeAppWithCIDRs(t, []string{"192.168.0.0/16"})

	req, _ := http.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "192.168.1.1:8080"
	req.Header.Set("X-Forwarded-For", "5.6.7.8, 192.168.1.2, 192.168.1.3")

	assert.Equal(t, "5.6.7.8", app.extractClientIP(req))
}

func TestExtractClientIP_XFFMissing_FallsBackToRemoteAddr(t *testing.T) {
	// Trusted proxy, but no XFF header → use RemoteAddr directly.
	app := makeAppWithCIDRs(t, []string{"10.0.0.0/8"})

	req, _ := http.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "10.0.0.3:7777"

	assert.Equal(t, "10.0.0.3", app.extractClientIP(req))
}

func TestExtractClientIP_IPv4MappedIPv6RemoteAddr(t *testing.T) {
	// IPv4-mapped IPv6 remote addresses should resolve correctly.
	app := makeAppWithCIDRs(t, []string{"::ffff:10.0.0.0/104"})

	req, _ := http.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "[::ffff:10.0.0.1]:4444"
	req.Header.Set("X-Forwarded-For", "8.8.8.8")

	assert.Equal(t, "8.8.8.8", app.extractClientIP(req))
}

func TestExtractClientIP_RemoteAddrWithoutPort(t *testing.T) {
	// Some test environments pass RemoteAddr without a port.
	app := makeAppWithCIDRs(t, nil)

	req, _ := http.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "203.0.113.5"
	req.Header.Set("X-Forwarded-For", "10.0.0.1")

	// No trusted proxies: XFF ignored; RemoteAddr returned as-is.
	assert.Equal(t, "203.0.113.5", app.extractClientIP(req))
}

func TestExtractClientIP_XFFSpoofingPrevented(t *testing.T) {
	// A client sends a forged leftmost IP; the trusted proxy appends the real
	// client IP and its own address.  The rightmost-untrusted algorithm must
	// return the real client IP and ignore the forged entry.
	app := makeAppWithCIDRs(t, []string{"10.0.0.0/8"})

	req, _ := http.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "10.0.0.2:12345"
	// forged by client, real client added by proxy, proxy itself added by proxy
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 203.0.113.99, 10.0.0.1")

	assert.Equal(t, "203.0.113.99", app.extractClientIP(req))
}

func TestIsTrustedProxy_MatchesConfiguredCIDR(t *testing.T) {
	app := makeAppWithCIDRs(t, []string{"10.0.0.0/8"})

	assert.True(t, app.isTrustedProxy(net.ParseIP("10.0.0.1")))
	assert.True(t, app.isTrustedProxy(net.ParseIP("10.255.255.255")))
	assert.False(t, app.isTrustedProxy(net.ParseIP("11.0.0.0")))
	assert.False(t, app.isTrustedProxy(net.ParseIP("192.168.1.1")))
}

func TestIsTrustedProxy_EmptyCIDRs(t *testing.T) {
	app := makeAppWithCIDRs(t, nil)
	assert.False(t, app.isTrustedProxy(net.ParseIP("10.0.0.1")))
	assert.False(t, app.isTrustedProxy(net.ParseIP("127.0.0.1")))
}

// ─── DPoP enforcement in handleProxy (F-2 fix) ──────────────────────────────

func TestHandleProxy_DPoPRequired_MissingHeader(t *testing.T) {
	// When a token has a cnf.jkt binding but no DPoP header is present,
	// handleProxy must reject the request with 401.
	app := makeAppWithCIDRs(t, nil)

	// Set up a dummy backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	backendURL, _ := url.Parse(backend.URL)
	app.proxy = httputil.NewSingleHostReverseProxy(backendURL)

	app.deps.JWTVerifier = &mockProxyJWTVerifier{
		claims: &capability.TokenPayload{
			Subject:   "agent-123",
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			Confirmation: &capability.Confirmation{
				JKT: "test-thumbprint",
			},
		},
	}

	req, _ := http.NewRequest(http.MethodPost, "/proxy", http.NoBody)
	req.Header.Set("Authorization", "Bearer fake-token")
	req.Header.Set("X-Tool-Name", "test-tool")
	req.RemoteAddr = "203.0.113.1:54321"
	w := httptest.NewRecorder()

	app.handleProxy(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "DPoP proof required")
}

func TestHandleProxy_NoDPoPBinding_SkipsDPoPCheck(t *testing.T) {
	// When a token has no cnf.jkt binding, DPoP checks are skipped
	// and the request proceeds to enforcement.
	app := makeAppWithCIDRs(t, nil)
	app.deps.JWTVerifier = &mockProxyJWTVerifier{
		claims: &capability.TokenPayload{
			Subject:   "agent-123",
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			// No Confirmation field - not DPoP-bound
			Capabilities: []capability.Constraint{
				{Resource: "test-tool", Actions: []string{"*"}},
			},
		},
	}

	req, _ := http.NewRequest(http.MethodPost, "/proxy", http.NoBody)
	req.Header.Set("Authorization", "Bearer fake-token")
	req.Header.Set("X-Tool-Name", "test-tool")
	req.RemoteAddr = "203.0.113.1:54321"
	w := httptest.NewRecorder()

	app.handleProxy(w, req)

	// Should NOT fail with DPoP error - will fail at enforcement since engine is nil,
	// but that's expected. The key is it didn't fail at DPoP check.
	assert.NotContains(t, w.Body.String(), "DPoP proof required")
}

// mockProxyJWTVerifier is a test JWT verifier for handleProxy tests.
type mockProxyJWTVerifier struct {
	claims *capability.TokenPayload
	err    error
}

func (m *mockProxyJWTVerifier) VerifyToken(_ context.Context, _ string) (*capability.TokenPayload, error) {
	return m.claims, m.err
}
