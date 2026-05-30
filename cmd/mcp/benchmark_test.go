// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Performance benchmarks for the eunox-mcp policy enforcement hot path (T-09).
//
// Four measured scenarios, matching the targets in docs/benchmarks.md:
//
//  1. ManifestPDP.Decide() — 1-rule and 50-rule manifests (pure CPU, no I/O)
//  2. HTTPProxy + ManifestPDP — full Streamable HTTP round-trip, stateless mode
//  3. HTTPProxy + JWTPDP — full round-trip including JWT signature verification
//  4. HTTPProxy + ManifestPDP + Redis kill switch — miniredis, measures KS overhead
//
// Run all benchmarks:
//
//	go test -bench=. -benchtime=3s -benchmem -count=3 ./cmd/mcp/
//
// Or via the convenience script:
//
//	./scripts/bench.sh
//
// Extract p99 with benchstat (requires golang.org/x/perf/cmd/benchstat):
//
//	go test -bench=. -benchtime=3s -count=10 ./cmd/mcp/ | tee bench.txt
//	benchstat bench.txt

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	goredis "github.com/redis/go-redis/v9"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/killswitch"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// build50RuleManifest returns a slice of 50 Constraints whose resources are
// named tool_00 … tool_49.  Used for worst-case linear-scan benchmarks.
func build50RuleManifest() []capability.Constraint {
	caps := make([]capability.Constraint, 50)
	for i := range caps {
		caps[i] = capability.Constraint{
			Resource: fmt.Sprintf("tool_%02d", i),
			Actions:  []string{"call"},
		}
	}
	return caps
}

// benchPDPOnly builds a ManifestPDP with an in-memory kill switch and no
// enforcement engine counters — pure condition evaluation, no I/O.
func benchPDPOnly(b *testing.B, caps ...capability.Constraint) *ManifestPDP {
	b.Helper()
	manifest := &LocalManifest{Name: "bench", Version: "1.0", Capabilities: caps}
	engine := enforcement.New()
	ks := killswitch.NewInMemory()
	return NewManifestPDP(manifest, engine, ks)
}

// newBenchUpstream starts a minimal MCP HTTP server optimised for benchmarks.
// Unlike fakeUpstream, it does not record received requests (no allocation
// growth over time) and always drains request bodies so the HTTP keep-alive
// connection pool is fully utilised.
func newBenchUpstream(b *testing.B) *httptest.Server {
	b.Helper()

	// Pre-build a fixed tools/call result so each request has zero marshal work.
	toolResultBytes, _ := json.Marshal(mcpToolCallResult{
		Content: []mcpContent{{Type: "text", Text: `{"ok":true}`}},
	})
	toolRespBytes, _ := json.Marshal(rpcMsg{
		JSONRPC: "2.0",
		ID:      rawJSON("2"),
		Result:  toolResultBytes,
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always drain the request body — required for HTTP/1.1 keep-alive.
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}

		var msg rpcMsg
		if err := json.Unmarshal(body, &msg); err != nil {
			http.Error(w, "bad JSON", http.StatusBadRequest)
			return
		}

		switch msg.Method {
		case "initialize":
			initResult, _ := json.Marshal(mcpInitResult{
				ProtocolVersion: mcpProtocolVersion,
				Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
				ServerInfo:      map[string]interface{}{"name": "bench-upstream", "version": "0.1"},
			})
			resp, _ := json.Marshal(rpcMsg{JSONRPC: "2.0", ID: msg.ID, Result: initResult})
			w.Header().Set(sessionHeader, "bench-upstream-sess")
			w.Header().Set("Content-Type", ctJSON)
			_, _ = w.Write(resp)

		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)

		case "tools/call":
			w.Header().Set("Content-Type", ctJSON)
			_, _ = w.Write(toolRespBytes)

		default:
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	b.Cleanup(srv.Close)
	return srv
}

// benchAuditSink creates a temporary audit sink that writes to a throwaway file
// in b.TempDir() so I/O noise is contained and the dir is cleaned up after.
func benchAuditSink(b *testing.B) *auditSink {
	b.Helper()
	f, err := os.CreateTemp(b.TempDir(), "bench-audit-*.jsonl")
	if err != nil {
		b.Fatalf("create temp audit log: %v", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		b.Fatalf("generate bench audit key: %v", err)
	}
	s := &auditSink{
		f:        f,
		key:      key,
		maxBytes: 100 << 20,
		logPath:  f.Name(),
	}
	b.Cleanup(func() { _ = s.Close() })
	return s
}

// benchJWTPDPContext builds a JWTPDP backed by an in-process JWKS server,
// pre-validates a token to warm the JWKS cache, and returns both the PDP and
// a context carrying valid JWT claims.  The JWKS server is stopped via
// b.Cleanup so callers need not manage its lifecycle.
func benchJWTPDPContext(b *testing.B, inner PolicyDecisionPoint) (*JWTPDP, context.Context, string) {
	b.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("generate ECDSA key: %v", err)
	}
	const kid = "bench-k1"

	jwksSet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: priv.Public(), KeyID: kid, Use: "sig"},
	}}
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwksSet)
	}))
	b.Cleanup(jwksSrv.Close)

	pdp := NewJWTPDP(JWTPDPOptions{
		JWKSURI:  jwksSrv.URL + "/",
		Issuer:   "https://idp.bench",
		Audience: "eunox",
		Inner:    inner,
		CacheTTL: 5 * time.Minute,
	})

	// Mint a token valid for the benchmark run.
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	if err != nil {
		b.Fatalf("new signer: %v", err)
	}
	stdClaims := josejwt.Claims{
		Issuer:   "https://idp.bench",
		Subject:  "bench-agent",
		Audience: josejwt.Audience{"eunox"},
		IssuedAt: josejwt.NewNumericDate(time.Now()),
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	payload := idpJWTPayload{
		Eunox: eunoxClaimSet{
			Capabilities: []string{"read_file:/reports/*", "query_db:SELECT"},
			AgentID:      "bench-agent",
			TaskID:       "bench-task",
		},
	}
	token, err := josejwt.Signed(sig).Claims(stdClaims).Claims(payload).Serialize()
	if err != nil {
		b.Fatalf("sign bench token: %v", err)
	}

	// Warm the JWKS cache and get a pre-populated context.
	ctx, err := pdp.ValidateToken(context.Background(), "Bearer "+token)
	if err != nil {
		b.Fatalf("ValidateToken warmup: %v", err)
	}

	return pdp, ctx, "Bearer " + token
}

// benchProxySession creates an HTTPProxy wired to a fake remote upstream, calls
// initialize to establish one session, and returns the proxy, the session ID,
// and a cleanup function.  The caller must call b.ResetTimer() after this.
func benchProxySession(b *testing.B, opts HTTPProxyOptions) (*HTTPProxy, string) { //nolint:gocritic // unnamedResult: multiple returns; names add no clarity here
	b.Helper()

	upSrv := newBenchUpstream(b)

	opts.UpstreamURL = upSrv.URL
	if opts.PDP == nil {
		opts.PDP = alwaysAllowPDP{}
	}
	proxy := NewHTTPProxy(opts)

	initBody := mustMarshal(b, rpcMsg{
		JSONRPC: "2.0",
		ID:      rawJSON("1"),
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"bench","version":"1.0"}}`),
	})
	initReq := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(initBody))
	initReq.Header.Set("Content-Type", ctJSON)
	initW := httptest.NewRecorder()
	proxy.handleMCP(initW, initReq)

	sid := initW.Header().Get(sessionHeader)
	if sid == "" {
		b.Fatalf("no session ID after initialize (status %d)", initW.Code)
	}
	return proxy, sid
}

// benchProxySessionWithJWT creates a proxy backed by a JWTPDP (+ optional inner
// manifest PDP), initialises a session with a pre-issued JWT, and returns
// everything needed for the hot loop.
func benchProxySessionWithJWT(b *testing.B, inner PolicyDecisionPoint) (*HTTPProxy, string, string) { //nolint:gocritic // unnamedResult: multiple returns; names add no clarity here
	b.Helper()

	jwtPDP, _, bearerToken := benchJWTPDPContext(b, inner)

	upSrv := newBenchUpstream(b)

	proxy := NewHTTPProxy(HTTPProxyOptions{
		UpstreamURL: upSrv.URL,
		PDP:         jwtPDP,
		JWTPDP:      jwtPDP,
	})

	initBody := mustMarshal(b, rpcMsg{
		JSONRPC: "2.0",
		ID:      rawJSON("1"),
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"bench-jwt","version":"1.0"}}`),
	})
	initReq := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(initBody))
	initReq.Header.Set("Content-Type", ctJSON)
	initReq.Header.Set("Authorization", bearerToken)
	initW := httptest.NewRecorder()
	proxy.handleMCP(initW, initReq)

	sid := initW.Header().Get(sessionHeader)
	if sid == "" {
		b.Fatalf("no session ID after JWT initialize (status %d; body: %s)",
			initW.Code, initW.Body.String())
	}
	return proxy, sid, bearerToken
}

// mustMarshal marshals v to JSON or fatals the benchmark.
func mustMarshal(b *testing.B, v interface{}) []byte {
	b.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		b.Fatalf("json.Marshal: %v", err)
	}
	return out
}

// prebuiltToolCall returns pre-serialised JSON for a tools/call request.
func prebuiltToolCall(tool string, args map[string]interface{}) []byte {
	params, _ := json.Marshal(mcpToolCallParams{Name: tool, Arguments: args})
	msg := rpcMsg{
		JSONRPC: "2.0",
		ID:      rawJSON("2"),
		Method:  "tools/call",
		Params:  params,
	}
	out, _ := json.Marshal(msg)
	return out
}

// ── 1. ManifestPDP — pure CPU, no I/O ────────────────────────────────────────

// BenchmarkManifestPDP measures the PDP decision latency in isolation.
// There is no network, no file I/O, and no syscalls in the hot path.
// These numbers represent the raw CPU cost of the policy evaluation loop.
//
// Target: p99 < 1 ms for any rule count.
func BenchmarkManifestPDP(b *testing.B) {
	allowArgs := map[string]interface{}{"path": "/reports/q3.pdf"}
	ctx := context.Background()

	b.Run("Decide_Allow_SimpleRule", func(b *testing.B) {
		pdp := benchPDPOnly(b,
			capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
		)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = pdp.Decide(ctx, "sess-bench", "read_file", allowArgs, "127.0.0.1")
		}
	})

	b.Run("Decide_Deny_AbsentTool", func(b *testing.B) {
		pdp := benchPDPOnly(b,
			capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
		)
		denyArgs := map[string]interface{}{"path": "/etc/passwd", "content": "x"}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = pdp.Decide(ctx, "sess-bench", "write_file", denyArgs, "127.0.0.1")
		}
	})

	b.Run("Decide_Allow_WithGlobCondition", func(b *testing.B) {
		pdp := benchPDPOnly(b,
			capability.Constraint{
				Resource: "read_file",
				Actions:  []string{"call"},
				Conditions: []capability.Condition{
					&capability.AllowedValuesCondition{
						Argument: "path",
						Values:   []interface{}{"/reports/*"},
					},
				},
			},
		)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = pdp.Decide(ctx, "sess-bench", "read_file", allowArgs, "127.0.0.1")
		}
	})

	b.Run("Decide_Allow_50Rules", func(b *testing.B) {
		// Match the last rule (worst-case linear scan).
		rules := build50RuleManifest()
		pdp := benchPDPOnly(b, rules...)
		lastTool := fmt.Sprintf("tool_%02d", len(rules)-1)
		args := map[string]interface{}{}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = pdp.Decide(ctx, "sess-bench", lastTool, args, "127.0.0.1")
		}
	})

	b.Run("Decide_Deny_50Rules", func(b *testing.B) {
		// Absent tool: must scan all 50 rules before returning deny.
		rules := build50RuleManifest()
		pdp := benchPDPOnly(b, rules...)
		args := map[string]interface{}{}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = pdp.Decide(ctx, "sess-bench", "tool_unknown", args, "127.0.0.1")
		}
	})

	b.Run("Decide_Allow_WithAllowedOperations", func(b *testing.B) {
		pdp := benchPDPOnly(b,
			capability.Constraint{
				Resource: "query_db",
				Actions:  []string{"call"},
				Conditions: []capability.Condition{
					capability.AllowedOperationsCondition{
						Operations: []string{"SELECT"},
					},
				},
			},
		)
		dbArgs := map[string]interface{}{"query": "SELECT * FROM reports"}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = pdp.Decide(ctx, "sess-bench", "query_db", dbArgs, "127.0.0.1")
		}
	})
}

// ── 2. JWTPDP — JWKS cached after warmup ─────────────────────────────────────

// BenchmarkJWTPDP measures JWTPDP overhead in two sub-scenarios:
//
//   - Decide_CachedClaims: claims already in context; measures constraint
//     building + condition evaluation only (no crypto).
//   - ValidateToken_CachedJWKS: full JWT validation including ECDSA P-256
//     signature verification; JWKS is cached so no network I/O.
//
// Target: p99 < 3 ms added overhead (JWT PDP mode, JWKS cached).
func BenchmarkJWTPDP(b *testing.B) {
	b.Run("Decide_CachedClaims_Allow", func(b *testing.B) {
		// Context already carries valid JWT claims (populated by ValidateToken
		// during setup).  Measures only constraint building + condition
		// evaluation — no crypto, no JWKS fetch.
		jwtPDP, ctx, _ := benchJWTPDPContext(b, nil)
		allowArgs := map[string]interface{}{"path": "/reports/q3.pdf"}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = jwtPDP.Decide(ctx, "sess-bench", "read_file", allowArgs, "127.0.0.1")
		}
	})

	b.Run("Decide_CachedClaims_Deny", func(b *testing.B) {
		jwtPDP, ctx, _ := benchJWTPDPContext(b, nil)
		absentArgs := map[string]interface{}{}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = jwtPDP.Decide(ctx, "sess-bench", "write_file", absentArgs, "127.0.0.1")
		}
	})

	b.Run("ValidateToken_CachedJWKS", func(b *testing.B) {
		// Full ValidateToken path: JWT parse + ECDSA verify + claim extract.
		// JWKS is fetched once during setup; all iterations hit the cache.
		jwtPDP, _, token := benchJWTPDPContext(b, nil)
		baseCtx := context.Background()
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = jwtPDP.ValidateToken(baseCtx, token)
		}
	})
}

// ── 3. HTTP proxy round-trip — stateless mode ─────────────────────────────────

// BenchmarkHTTPProxy measures the added latency of the eunox-mcp proxy over a
// direct upstream call.  The fake upstream is an in-process httptest.Server
// that returns a static response; its baseline latency is subtracted via the
// companion BenchmarkUpstream_Baseline sub-benchmark.
//
// Architecture under test:
//
//	b.Loop ──► proxy.handleMCP ──► ManifestPDP.Decide ──► upstream httptest
//
// Targets:
//   - Stateless mode (no audit): p99 < 2 ms overhead
//   - With audit log: overhead varies by storage (tmpfs: +~50 µs; SSD: +~200 µs)
func BenchmarkHTTPProxy(b *testing.B) {
	allowBody := prebuiltToolCall("read_file", map[string]interface{}{"path": "/reports/q3.pdf"})
	denyBody := prebuiltToolCall("write_file", map[string]interface{}{"path": "/etc/passwd", "content": "x"})

	b.Run("Baseline_DirectUpstream", func(b *testing.B) {
		// Measures the bench upstream alone (no proxy) so callers can compute
		// overhead = ManifestPDP_Allow - Baseline_DirectUpstream.
		upSrv := newBenchUpstream(b)

		client := &http.Client{}

		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			req, _ := http.NewRequestWithContext(context.Background(),
				http.MethodPost, upSrv.URL+"/mcp", bytes.NewReader(allowBody))
			req.Header.Set("Content-Type", ctJSON)
			resp, err := client.Do(req)
			if err != nil {
				b.Fatalf("upstream request: %v", err)
			}
			// Drain body before Close so the HTTP transport can reuse the
			// keep-alive connection.  Without this, every iteration opens a new
			// TCP connection and exhausts macOS ephemeral ports in ~3 s.
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	})

	b.Run("ManifestPDP_Allow", func(b *testing.B) {
		pdp := benchPDPOnly(b,
			capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
			capability.Constraint{Resource: "query_db", Actions: []string{"call"}},
		)
		proxy, sid := benchProxySession(b, HTTPProxyOptions{PDP: pdp})
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(allowBody))
			req.Header.Set("Content-Type", ctJSON)
			req.Header.Set(sessionHeader, sid)
			w := httptest.NewRecorder()
			proxy.handleMCP(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("unexpected status %d: %s", w.Code, w.Body.String())
			}
		}
	})

	b.Run("ManifestPDP_Deny", func(b *testing.B) {
		pdp := benchPDPOnly(b,
			capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
		)
		proxy, sid := benchProxySession(b, HTTPProxyOptions{PDP: pdp})
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(denyBody))
			req.Header.Set("Content-Type", ctJSON)
			req.Header.Set(sessionHeader, sid)
			w := httptest.NewRecorder()
			proxy.handleMCP(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("unexpected status %d", w.Code)
			}
		}
	})

	b.Run("ManifestPDP_Allow_WithAudit", func(b *testing.B) {
		// Adds HMAC-SHA256 audit record per call written to a temp file.
		// Shows the marginal cost of the audit pipeline.
		pdp := benchPDPOnly(b,
			capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
		)
		sink := benchAuditSink(b)
		proxy, sid := benchProxySession(b, HTTPProxyOptions{PDP: pdp, Sink: sink})
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(allowBody))
			req.Header.Set("Content-Type", ctJSON)
			req.Header.Set(sessionHeader, sid)
			w := httptest.NewRecorder()
			proxy.handleMCP(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("unexpected status %d", w.Code)
			}
		}
	})

	b.Run("ManifestPDP_50Rules_Allow", func(b *testing.B) {
		// Worst-case policy evaluation: 50 rules, match on rule 49.
		rules := build50RuleManifest()
		lastBody := prebuiltToolCall(
			fmt.Sprintf("tool_%02d", len(rules)-1),
			map[string]interface{}{},
		)
		pdp := benchPDPOnly(b, rules...)
		proxy, sid := benchProxySession(b, HTTPProxyOptions{PDP: pdp})
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(lastBody))
			req.Header.Set("Content-Type", ctJSON)
			req.Header.Set(sessionHeader, sid)
			w := httptest.NewRecorder()
			proxy.handleMCP(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("unexpected status %d", w.Code)
			}
		}
	})
}

// ── 4. HTTP proxy — JWT PDP mode ──────────────────────────────────────────────

// BenchmarkHTTPProxy_JWTPDP measures the overhead when --jwks-uri is set.
// Every handleMCP call validates the Bearer JWT (ECDSA P-256 signature
// verification) before routing to the PDP.  The JWKS is fetched once and
// cached for the duration of the benchmark run.
//
// Target: p99 < 3 ms added overhead (JWT PDP, JWKS cached).
func BenchmarkHTTPProxy_JWTPDP(b *testing.B) {
	allowBody := prebuiltToolCall("read_file", map[string]interface{}{"path": "/reports/q3.pdf"})
	denyBody := prebuiltToolCall("write_file", map[string]interface{}{"path": "/etc/passwd", "content": "x"})

	b.Run("Allow_JWTOnly", func(b *testing.B) {
		// JWT only — no manifest inner PDP.
		proxy, sid, token := benchProxySessionWithJWT(b, nil)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(allowBody))
			req.Header.Set("Content-Type", ctJSON)
			req.Header.Set(sessionHeader, sid)
			req.Header.Set("Authorization", token)
			w := httptest.NewRecorder()
			proxy.handleMCP(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("unexpected status %d: %s", w.Code, w.Body.String())
			}
		}
	})

	b.Run("Allow_JWTAndManifest", func(b *testing.B) {
		// JWT narrowed by manifest (intersection mode — the typical production setup).
		inner := benchPDPOnly(b,
			capability.Constraint{Resource: "read_file", Actions: []string{"call"}},
			capability.Constraint{Resource: "query_db", Actions: []string{"call"}},
		)
		proxy, sid, token := benchProxySessionWithJWT(b, inner)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(allowBody))
			req.Header.Set("Content-Type", ctJSON)
			req.Header.Set(sessionHeader, sid)
			req.Header.Set("Authorization", token)
			w := httptest.NewRecorder()
			proxy.handleMCP(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("unexpected status %d: %s", w.Code, w.Body.String())
			}
		}
	})

	b.Run("Deny_AbsentFromJWT", func(b *testing.B) {
		proxy, sid, token := benchProxySessionWithJWT(b, nil)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(denyBody))
			req.Header.Set("Content-Type", ctJSON)
			req.Header.Set(sessionHeader, sid)
			req.Header.Set("Authorization", token)
			w := httptest.NewRecorder()
			proxy.handleMCP(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("unexpected status %d", w.Code)
			}
		}
	})
}

// ── 5. Redis kill-switch overhead ─────────────────────────────────────────────

// BenchmarkHTTPProxy_RedisKS measures the overhead introduced by wiring the
// proxy to a Redis-backed kill switch (via miniredis, in-process).
//
// Note: the Redis kill switch caches state in-memory and refreshes via pub/sub.
// ShouldBlock() is therefore a mutex + map lookup on the hot path, not a
// Redis round-trip.  The p99 overhead over the in-memory baseline is expected
// to be < 1 µs.  A real Redis deployment adds network RTT only on state
// changes (kill/revive), not on every request.
//
// Target: p99 < 5 ms overhead (Redis session state, includes Redis RTT on
// state changes; hot-path reads are in-memory).
func BenchmarkHTTPProxy_RedisKS(b *testing.B) {
	allowBody := prebuiltToolCall("read_file", map[string]interface{}{"path": "/reports/q3.pdf"})

	b.Run("ManifestPDP_Allow_RedisKS", func(b *testing.B) {
		mr := miniredis.RunT(b)
		redisClient := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
		b.Cleanup(func() { _ = redisClient.Close() })

		ctx, cancel := context.WithCancel(context.Background())
		ks := killswitch.NewRedis(redisClient)
		ks.Start(ctx)
		b.Cleanup(func() { cancel(); ks.Stop() })

		manifest := &LocalManifest{
			Name:    "bench",
			Version: "1.0",
			Capabilities: []capability.Constraint{
				{Resource: "read_file", Actions: []string{"call"}},
			},
		}
		pdp := NewManifestPDP(manifest, enforcement.New(), ks)

		upSrv := newBenchUpstream(b)

		proxy := NewHTTPProxy(HTTPProxyOptions{
			UpstreamURL: upSrv.URL,
			PDP:         pdp,
			KS:          ks,
		})

		// Initialise one session before the timer.
		initBody := mustMarshal(b, rpcMsg{
			JSONRPC: "2.0",
			ID:      rawJSON("1"),
			Method:  "initialize",
			Params:  json.RawMessage(`{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"bench-redis","version":"1.0"}}`),
		})
		initReq := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(initBody))
		initReq.Header.Set("Content-Type", ctJSON)
		initW := httptest.NewRecorder()
		proxy.handleMCP(initW, initReq)
		sid := initW.Header().Get(sessionHeader)
		if sid == "" {
			b.Fatalf("no session ID after initialize (status %d)", initW.Code)
		}

		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(allowBody))
			req.Header.Set("Content-Type", ctJSON)
			req.Header.Set(sessionHeader, sid)
			w := httptest.NewRecorder()
			proxy.handleMCP(w, req)
			if w.Code != http.StatusOK {
				b.Fatalf("unexpected status %d", w.Code)
			}
		}
	})
}
