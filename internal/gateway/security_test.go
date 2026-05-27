// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package gateway — security-audit Finding 1 tests (internal access required).
//
// Finding 1: X-Forwarded-For IP spoofing is mitigated via TrustedProxyCIDRs.
// These tests live in package gateway (not gateway_test) because extractClientIP
// and isTrustedProxy are unexported methods.
package gateway

import (
"net"
"net/http"
"testing"

"github.com/stretchr/testify/assert"
)

// makeAppWithCIDRs builds a minimal App with the given trusted-proxy CIDRs.
func makeAppWithCIDRs(t *testing.T, cidrs []string) *App {
t.Helper()
app := &App{}
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
// When RemoteAddr matches a trusted CIDR, the leftmost XFF IP is used.
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
// XFF chain "clientIP, proxy1, proxy2" → leftmost is the original client.
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
