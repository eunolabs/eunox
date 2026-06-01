// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/eunolabs/eunox/pkg/capability"
)

// -------------------------------------------------------------------------
// Test helpers
// -------------------------------------------------------------------------

// testKey holds an ECDSA key pair for signing test JWTs.
type testKey struct {
	priv *ecdsa.PrivateKey
	kid  string
}

func newTestKey(t *testing.T, kid string) testKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return testKey{priv: priv, kid: kid}
}

// makeJWKSServer returns a test JWKS HTTP server serving the public key.
func makeJWKSServer(t *testing.T, keys ...testKey) *httptest.Server {
	t.Helper()
	jwks := jose.JSONWebKeySet{}
	for _, k := range keys {
		jwks.Keys = append(jwks.Keys, jose.JSONWebKey{
			Key:   k.priv.Public(),
			KeyID: k.kid,
			Use:   "sig",
		})
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
}

// makeIDPToken signs an IdP JWT with the given capability claims and standard claims.
func makeIDPToken(t *testing.T, key testKey, caps []string, iss, aud, sub string, exp time.Time) string {
	t.Helper()

	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key.priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", key.kid),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	now := time.Now()
	stdClaims := jwt.Claims{
		Issuer:   iss,
		Subject:  sub,
		Audience: jwt.Audience{aud},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(exp),
	}
	payload := idpJWTPayload{
		MCP: mcpClaimSet{Version: mcpClaimVersion, Capabilities: caps},
	}
	token, err := jwt.Signed(sig).Claims(stdClaims).Claims(payload).Serialize()
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return token
}

// makeJWTPDP creates a JWTPDP pointing at the given httptest.Server JWKS endpoint.
func makeJWTPDP(t *testing.T, srv *httptest.Server, iss, aud string, inner PolicyDecisionPoint) *JWTPDP {
	t.Helper()
	return NewJWTPDP(JWTPDPOptions{
		JWKSURI:  srv.URL + "/",
		Issuer:   iss,
		Audience: aud,
		Inner:    inner,
		CacheTTL: 5 * time.Second,
	})
}

// -------------------------------------------------------------------------
// Claim parsing tests
// -------------------------------------------------------------------------

func TestParseCapabilityClaim(t *testing.T) {
	cases := []struct {
		input    string
		wantTool string
		wantCond string
	}{
		{"read_file", "read_file", ""},
		{"read_file:/reports/*", "read_file", "/reports/*"},
		{"query_db:SELECT", "query_db", "SELECT"},
		{"write_file:/tmp/*", "write_file", "/tmp/*"},
		{"tool:a:b", "tool", "a:b"}, // only first colon splits
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			tool, cond := parseCapabilityClaim(tc.input)
			if tool != tc.wantTool || cond != tc.wantCond {
				t.Errorf("parseCapabilityClaim(%q) = (%q, %q), want (%q, %q)",
					tc.input, tool, cond, tc.wantTool, tc.wantCond)
			}
		})
	}
}

func TestBuildConstraint_NoCondition(t *testing.T) {
	c := buildConstraint("read_file", "")
	if c.Resource != "read_file" {
		t.Errorf("resource = %q, want %q", c.Resource, "read_file")
	}
	if len(c.Conditions) != 0 {
		t.Errorf("expected no conditions, got %d", len(c.Conditions))
	}
}

func TestBuildConstraint_SQLVerb(t *testing.T) {
	c := buildConstraint("query_db", "SELECT")
	if len(c.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(c.Conditions))
	}
	aoc, ok := c.Conditions[0].(capability.AllowedOperationsCondition)
	if !ok {
		t.Fatalf("expected AllowedOperationsCondition, got %T", c.Conditions[0])
	}
	if len(aoc.Operations) != 1 || aoc.Operations[0] != "SELECT" {
		t.Errorf("operations = %v, want [SELECT]", aoc.Operations)
	}
}

func TestBuildConstraint_PathGlob(t *testing.T) {
	c := buildConstraint("read_file", "/reports/*")
	if len(c.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(c.Conditions))
	}
	avc, ok := c.Conditions[0].(capability.AllowedValuesCondition)
	if !ok {
		t.Fatalf("expected AllowedValuesCondition, got %T", c.Conditions[0])
	}
	if avc.Argument != "path" {
		t.Errorf("argument = %q, want %q", avc.Argument, "path")
	}
	if len(avc.Values) != 1 || avc.Values[0] != "/reports/*" {
		t.Errorf("values = %v, want [/reports/*]", avc.Values)
	}
}

func TestIsSQLVerb(t *testing.T) {
	verbs := []string{"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "TRUNCATE", "MERGE", "UPSERT", "REPLACE"}
	for _, v := range verbs {
		if !isSQLVerb(v) {
			t.Errorf("isSQLVerb(%q) = false, want true", v)
		}
	}
	nonVerbs := []string{"select", "Select", "/reports/*", "read_file", ""}
	for _, v := range nonVerbs {
		if isSQLVerb(v) {
			t.Errorf("isSQLVerb(%q) = true, want false", v)
		}
	}
}

// -------------------------------------------------------------------------
// JWT validation tests
// -------------------------------------------------------------------------

func TestJWTPDP_ValidateToken_Valid(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	pdp := makeJWTPDP(t, srv, "https://idp.example.com", "eunox", nil)
	token := makeIDPToken(t, key, []string{"read_file"}, "https://idp.example.com", "eunox", "agent-1", time.Now().Add(time.Hour))

	ctx, err := pdp.ValidateToken(context.Background(), "Bearer "+token)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}
	claims, ok := jwtClaimsFromContext(ctx)
	if !ok {
		t.Fatal("no claims in context")
	}
	if claims.Subject != "agent-1" {
		t.Errorf("subject = %q, want %q", claims.Subject, "agent-1")
	}
	if len(claims.Capabilities) != 1 || claims.Capabilities[0] != "read_file" {
		t.Errorf("capabilities = %v, want [read_file]", claims.Capabilities)
	}
}

func TestJWTPDP_ValidateToken_UnknownClaimVersion(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	pdp := makeJWTPDP(t, srv, "", "", nil)

	// Build a token with an unrecognised mcp.v value using the same signer as makeIDPToken.
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key.priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", key.kid),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	stdClaims := jwt.Claims{
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	payload := idpJWTPayload{MCP: mcpClaimSet{Version: "99.0", Capabilities: []string{"read_file"}}}
	token, err := jwt.Signed(sig).Claims(stdClaims).Claims(payload).Serialize()
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	_, err = pdp.ValidateToken(context.Background(), "Bearer "+token)
	if err == nil {
		t.Fatal("expected error for unknown mcp claim version")
	}
	if !strings.Contains(err.Error(), "unsupported mcp claim version") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestJWTPDP_ValidateToken_MissingBearer(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	pdp := makeJWTPDP(t, srv, "", "", nil)
	_, err := pdp.ValidateToken(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for missing Authorization header")
	}
}

func TestJWTPDP_ValidateToken_ExpiredToken(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	pdp := makeJWTPDP(t, srv, "", "", nil)
	token := makeIDPToken(t, key, []string{"read_file"}, "", "", "agent-1", time.Now().Add(-2*time.Hour))

	_, err := pdp.ValidateToken(context.Background(), "Bearer "+token)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestJWTPDP_ValidateToken_WrongIssuer(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	pdp := makeJWTPDP(t, srv, "https://expected.issuer.com", "", nil)
	token := makeIDPToken(t, key, []string{"read_file"}, "https://other.issuer.com", "", "agent-1", time.Now().Add(time.Hour))

	_, err := pdp.ValidateToken(context.Background(), "Bearer "+token)
	if err == nil {
		t.Fatal("expected error for wrong issuer")
	}
}

func TestJWTPDP_ValidateToken_WrongAudience(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	pdp := makeJWTPDP(t, srv, "", "expected-audience", nil)
	token := makeIDPToken(t, key, []string{"read_file"}, "", "other-audience", "agent-1", time.Now().Add(time.Hour))

	_, err := pdp.ValidateToken(context.Background(), "Bearer "+token)
	if err == nil {
		t.Fatal("expected error for wrong audience")
	}
}

func TestJWTPDP_ValidateToken_InvalidSignature(t *testing.T) {
	key1 := newTestKey(t, "k1")
	key2 := newTestKey(t, "k1") // different key, same kid
	srv := makeJWKSServer(t, key1)
	defer srv.Close()

	pdp := makeJWTPDP(t, srv, "", "", nil)
	// Sign with key2 but JWKS has key1 — signature mismatch.
	token := makeIDPToken(t, key2, []string{"read_file"}, "", "", "agent-1", time.Now().Add(time.Hour))

	_, err := pdp.ValidateToken(context.Background(), "Bearer "+token)
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}
}

func TestJWTPDP_ValidateToken_UnknownKID_Refresh(t *testing.T) {
	key1 := newTestKey(t, "k1")
	key2 := newTestKey(t, "k2")

	// Start with only key1 in JWKS, then add key2 on second fetch.
	var fetchCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := fetchCount.Add(1)
		jwks := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{Key: key1.priv.Public(), KeyID: key1.kid, Use: "sig"},
			},
		}
		if n > 1 {
			jwks.Keys = append(jwks.Keys, jose.JSONWebKey{
				Key: key2.priv.Public(), KeyID: key2.kid, Use: "sig",
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	pdp := makeJWTPDP(t, srv, "", "", nil)
	// First call primes cache with key1 only.
	tok1 := makeIDPToken(t, key1, []string{"read_file"}, "", "", "s1", time.Now().Add(time.Hour))
	if _, err := pdp.ValidateToken(context.Background(), "Bearer "+tok1); err != nil {
		t.Fatalf("initial validation failed: %v", err)
	}

	// Token signed by key2 — not in cache yet, should trigger refresh.
	tok2 := makeIDPToken(t, key2, []string{"write_file"}, "", "", "s2", time.Now().Add(time.Hour))
	ctx, err := pdp.ValidateToken(context.Background(), "Bearer "+tok2)
	if err != nil {
		t.Fatalf("validation with refreshed JWKS failed: %v", err)
	}
	claims, _ := jwtClaimsFromContext(ctx)
	if len(claims.Capabilities) == 0 || claims.Capabilities[0] != "write_file" {
		t.Errorf("capabilities = %v, want [write_file]", claims.Capabilities)
	}
	if fetchCount.Load() < 2 {
		t.Errorf("expected at least 2 JWKS fetches, got %d", fetchCount.Load())
	}
}

// -------------------------------------------------------------------------
// JWTPDP.Decide tests
// -------------------------------------------------------------------------

func TestJWTPDP_Decide_AllowSimple(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	pdp := makeJWTPDP(t, srv, "", "", nil)
	token := makeIDPToken(t, key, []string{"read_file"}, "", "", "a1", time.Now().Add(time.Hour))
	ctx, err := pdp.ValidateToken(context.Background(), "Bearer "+token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}

	resp := pdp.Decide(ctx, "sess-1", "read_file", map[string]interface{}{}, "127.0.0.1")
	if resp.Decision != capability.DecisionAllow {
		t.Errorf("decision = %q, want allow; denial = %+v", resp.Decision, resp.Denial)
	}
}

func TestJWTPDP_Decide_DenyToolNotInClaims(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	pdp := makeJWTPDP(t, srv, "", "", nil)
	token := makeIDPToken(t, key, []string{"read_file"}, "", "", "a1", time.Now().Add(time.Hour))
	ctx, err := pdp.ValidateToken(context.Background(), "Bearer "+token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}

	resp := pdp.Decide(ctx, "sess-1", "write_file", map[string]interface{}{}, "127.0.0.1")
	if resp.Decision != capability.DecisionDeny {
		t.Errorf("decision = %q, want deny", resp.Decision)
	}
	if resp.Denial == nil || resp.Denial.Code != "CAPABILITY_NOT_GRANTED" {
		t.Errorf("denial code = %v, want CAPABILITY_NOT_GRANTED", resp.Denial)
	}
}

func TestJWTPDP_Decide_AllowPathGlobMatch(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	pdp := makeJWTPDP(t, srv, "", "", nil)
	token := makeIDPToken(t, key, []string{"read_file:/reports/*"}, "", "", "a1", time.Now().Add(time.Hour))
	ctx, err := pdp.ValidateToken(context.Background(), "Bearer "+token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}

	resp := pdp.Decide(ctx, "sess-1", "read_file", map[string]interface{}{"path": "/reports/q3.pdf"}, "127.0.0.1")
	if resp.Decision != capability.DecisionAllow {
		t.Errorf("decision = %q, want allow; denial = %+v", resp.Decision, resp.Denial)
	}
}

func TestJWTPDP_Decide_DenyPathGlobNoMatch(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	pdp := makeJWTPDP(t, srv, "", "", nil)
	token := makeIDPToken(t, key, []string{"read_file:/reports/*"}, "", "", "a1", time.Now().Add(time.Hour))
	ctx, err := pdp.ValidateToken(context.Background(), "Bearer "+token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}

	resp := pdp.Decide(ctx, "sess-1", "read_file", map[string]interface{}{"path": "/etc/passwd"}, "127.0.0.1")
	if resp.Decision != capability.DecisionDeny {
		t.Errorf("decision = %q, want deny", resp.Decision)
	}
}

func TestJWTPDP_Decide_AllowSQLVerb(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	pdp := makeJWTPDP(t, srv, "", "", nil)
	token := makeIDPToken(t, key, []string{"query_db:SELECT"}, "", "", "a1", time.Now().Add(time.Hour))
	ctx, err := pdp.ValidateToken(context.Background(), "Bearer "+token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}

	resp := pdp.Decide(ctx, "sess-1", "query_db", map[string]interface{}{"sql": "SELECT * FROM users"}, "127.0.0.1")
	if resp.Decision != capability.DecisionAllow {
		t.Errorf("decision = %q, want allow; denial = %+v", resp.Decision, resp.Denial)
	}
}

func TestJWTPDP_Decide_DenySQLVerbMismatch(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	pdp := makeJWTPDP(t, srv, "", "", nil)
	token := makeIDPToken(t, key, []string{"query_db:SELECT"}, "", "", "a1", time.Now().Add(time.Hour))
	ctx, err := pdp.ValidateToken(context.Background(), "Bearer "+token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}

	resp := pdp.Decide(ctx, "sess-1", "query_db", map[string]interface{}{"sql": "DROP TABLE users"}, "127.0.0.1")
	if resp.Decision != capability.DecisionDeny {
		t.Errorf("decision = %q, want deny", resp.Decision)
	}
}

func TestJWTPDP_Decide_NoClaimsInContext(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	pdp := makeJWTPDP(t, srv, "", "", nil)
	resp := pdp.Decide(context.Background(), "sess-1", "read_file", map[string]interface{}{}, "127.0.0.1")
	if resp.Decision != capability.DecisionDeny {
		t.Errorf("decision = %q, want deny (no claims)", resp.Decision)
	}
	if resp.Denial == nil || resp.Denial.Code != "NO_JWT_CLAIMS" {
		t.Errorf("denial code = %v, want NO_JWT_CLAIMS", resp.Denial)
	}
}

// -------------------------------------------------------------------------
// Intersection (JWT + manifest) tests
// -------------------------------------------------------------------------

func TestJWTPDP_Intersection_BothAllow(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	// Inner manifest PDP that allows read_file.
	inner := alwaysAllowPDP{}
	pdp := makeJWTPDP(t, srv, "", "", inner)
	token := makeIDPToken(t, key, []string{"read_file"}, "", "", "a1", time.Now().Add(time.Hour))
	ctx, _ := pdp.ValidateToken(context.Background(), "Bearer "+token)

	resp := pdp.Decide(ctx, "sess-1", "read_file", map[string]interface{}{}, "127.0.0.1")
	if resp.Decision != capability.DecisionAllow {
		t.Errorf("decision = %q, want allow", resp.Decision)
	}
}

func TestJWTPDP_Intersection_JWTDenies_ManifestAllow(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	// Inner manifest allows everything; JWT only has read_file.
	inner := alwaysAllowPDP{}
	pdp := makeJWTPDP(t, srv, "", "", inner)
	token := makeIDPToken(t, key, []string{"read_file"}, "", "", "a1", time.Now().Add(time.Hour))
	ctx, _ := pdp.ValidateToken(context.Background(), "Bearer "+token)

	// write_file: JWT denies (not in claims), manifest would allow — JWT wins.
	resp := pdp.Decide(ctx, "sess-1", "write_file", map[string]interface{}{}, "127.0.0.1")
	if resp.Decision != capability.DecisionDeny {
		t.Errorf("decision = %q, want deny (JWT narrows manifest)", resp.Decision)
	}
}

func TestJWTPDP_Intersection_ManifestDenies_JWTAllow(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	// Inner manifest denies everything.
	inner := denyAllPDP{}
	pdp := makeJWTPDP(t, srv, "", "", inner)
	token := makeIDPToken(t, key, []string{"read_file"}, "", "", "a1", time.Now().Add(time.Hour))
	ctx, _ := pdp.ValidateToken(context.Background(), "Bearer "+token)

	// JWT allows read_file but manifest denies — manifest wins.
	resp := pdp.Decide(ctx, "sess-1", "read_file", map[string]interface{}{}, "127.0.0.1")
	if resp.Decision != capability.DecisionDeny {
		t.Errorf("decision = %q, want deny (manifest narrows JWT)", resp.Decision)
	}
}

// -------------------------------------------------------------------------
// JWKS cache singleflight test
// -------------------------------------------------------------------------

func TestJWKSCache_ConcurrentRefresh_SingleFlight(t *testing.T) {
	var fetchCount atomic.Int32
	key := newTestKey(t, "k1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetchCount.Add(1)
		jwks := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{Key: key.priv.Public(), KeyID: key.kid, Use: "sig"}},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	cache := newJWKSCache(srv.URL+"/", time.Second, nil)

	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			_, errs[i] = cache.getKeys(context.Background())
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}
	// All concurrent calls should have resulted in at most a small number of
	// fetches (ideally 1, but singleflight allows at most ~2 if timing is unlucky).
	if got := fetchCount.Load(); got > 3 {
		t.Errorf("expected ≤3 JWKS fetches for %d concurrent callers, got %d", n, got)
	}
}

// -------------------------------------------------------------------------
// HTTP integration test: 401 on missing/invalid JWT
// -------------------------------------------------------------------------

func TestHTTPProxy_JWTMode_401OnMissingToken(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	jwtPDP := makeJWTPDP(t, srv, "", "", nil)

	// Use a fake upstream that accepts anything.
	upstream := newFakeUpstreamForJWT(t)
	defer upstream.srv.Close()

	proxy := NewHTTPProxy(HTTPProxyOptions{
		JWTPDP:      jwtPDP,
		PDP:         jwtPDP,
		UpstreamURL: upstream.srv.URL,
		Port:        0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	// POST to /mcp with no Authorization header.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, proxySrv.URL+"/mcp", http.NoBody)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestHTTPProxy_JWTMode_401OnExpiredToken(t *testing.T) {
	key := newTestKey(t, "k1")
	srv := makeJWKSServer(t, key)
	defer srv.Close()

	jwtPDP := makeJWTPDP(t, srv, "", "", nil)
	upstream := newFakeUpstreamForJWT(t)
	defer upstream.srv.Close()

	proxy := NewHTTPProxy(HTTPProxyOptions{
		JWTPDP:      jwtPDP,
		PDP:         jwtPDP,
		UpstreamURL: upstream.srv.URL,
		Port:        0,
	})
	proxySrv := httptest.NewServer(http.HandlerFunc(proxy.handleMCP))
	defer proxySrv.Close()

	token := makeIDPToken(t, key, []string{"read_file"}, "", "", "a1", time.Now().Add(-2*time.Hour))
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, proxySrv.URL+"/mcp", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

// -------------------------------------------------------------------------
// Context propagation
// -------------------------------------------------------------------------

func TestJWTClaimsContext_RoundTrip(t *testing.T) {
	original := &JWTClaims{
		Capabilities: []string{"read_file:/reports/*", "query_db:SELECT"},
		TaskID:       "task-1",
		AgentID:      "agent-1",
		Subject:      "user@example.com",
		Issuer:       "https://idp.example.com",
	}
	ctx := withJWTClaims(context.Background(), original)
	got, ok := jwtClaimsFromContext(ctx)
	if !ok {
		t.Fatal("claims not found in context")
	}
	if got.Subject != original.Subject || got.TaskID != original.TaskID {
		t.Errorf("claims mismatch: got %+v, want %+v", got, original)
	}
	if len(got.Capabilities) != len(original.Capabilities) {
		t.Errorf("capabilities mismatch: got %v, want %v", got.Capabilities, original.Capabilities)
	}
}

func TestJWTClaimsContext_EmptyContext(t *testing.T) {
	_, ok := jwtClaimsFromContext(context.Background())
	if ok {
		t.Error("expected no claims in empty context")
	}
}

// -------------------------------------------------------------------------
// Helpers used by HTTP integration tests
// -------------------------------------------------------------------------

// fakeUpstreamForJWT is a minimal MCP HTTP stub for JWT integration tests.
type fakeUpstreamForJWT struct {
	srv *httptest.Server
}

func newFakeUpstreamForJWT(t *testing.T) *fakeUpstreamForJWT {
	t.Helper()
	var sessionID string
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var msg rpcMsg
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if msg.Method == "initialize" {
			sessionID = fmt.Sprintf("us-%s", msg.Method)
			w.Header().Set("Mcp-Session-Id", sessionID)
			initResult, _ := json.Marshal(map[string]interface{}{
				"protocolVersion": "2025-11-05",
				"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				"serverInfo":      map[string]interface{}{"name": "test", "version": "0"},
			})
			resp := rpcMsg{JSONRPC: "2.0", ID: msg.ID, Result: json.RawMessage(initResult)}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		if msg.isNotification() {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		toolResult := json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`)
		resp := rpcMsg{JSONRPC: "2.0", ID: msg.ID, Result: toolResult}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	srv := httptest.NewServer(mux)
	return &fakeUpstreamForJWT{srv: srv}
}

// denyAllPDP is a test PDP that always denies.
// (Also defined in http_upstream_test.go but that file is in the same package
// so we can't redeclare it; use the one from there.)
