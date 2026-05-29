# Security Audit Report — Eunox Go Codebase

**Date:** 2026-05-27  
**Scope:** Full Go codebase (`cmd/`, `internal/`, `pkg/`, `gateway/`)  
**Methodology:** Static analysis of source code for exploitable vulnerabilities

---

## Executive Summary

The Eunox codebase demonstrates **strong security posture overall**. The most common vulnerability classes (SQL injection, command injection, path traversal) are absent. Authentication uses modern JWT + DPoP with constant-time key comparison. All HTTP clients and servers have explicit timeouts, and request body sizes are bounded.

Four findings were identified (one Medium, three Low severity).

---

## Findings

> **All four findings resolved as of 2026-05-29.**

### Finding 1: X-Forwarded-For IP Spoofing in Enforcement Context

- **Location:** `internal/gateway/handlers.go:366-374` (`extractClientIP`)
- **Severity:** Medium
- **Status:** ✅ Fixed
- **What:** The `extractClientIP` function unconditionally trusts the `X-Forwarded-For` header for the `SourceIP` field passed to the enforcement engine. Any client can set this header to an arbitrary IP.
- **Why it matters:** The enforcement engine (`pkg/enforcement/engine.go`) evaluates policy conditions including IP-based rules. An attacker can set `X-Forwarded-For: 10.0.0.1` to satisfy an IP allowlist condition on enforcement policies, bypassing geo-restrictions or IP-based access controls. This is distinct from the admin rate limiter (which correctly uses `RemoteAddr`).
- **Fix:** Add a `TrustedProxies` configuration (similar to what the Helm values.schema.json already documents for the Node.js trust-proxy setting). Only honor `X-Forwarded-For` when the request's `RemoteAddr` matches a trusted proxy CIDR.
- **Implementation:**
  - `internal/gateway/app.go` — `Config.TrustedProxyCIDRs []string` field added; `New()` parses each CIDR at startup (malformed CIDRs are fatal so misconfiguration fails closed); parsed nets stored in `App.trustedProxyNets []*net.IPNet`.
  - `internal/gateway/handlers.go` — `isTrustedProxy(ip net.IP) bool` helper added; `extractClientIP` walks the XFF chain right-to-left, returning the first IP not in the trusted set. When no trusted proxies are configured, or the immediate peer is untrusted, `RemoteAddr` is used directly. `reconstructRequestURL` applies the same guard for DPoP `htu` verification.
  - `pkg/config/gateway.go` — `GATEWAY_TRUSTED_PROXY_CIDRS` env var wired through to `GatewayConfig.TrustedProxyCIDRs`.
  - `internal/gateway/security_test.go` — full regression suite: no-proxy fallback, single/chained trusted proxy, spoofed leftmost entry, all-trusted chain, malformed CIDR startup failure.

---

### Finding 2: `http.DefaultClient` Fallback Without Timeout

- **Location:** `pkg/identity/oidc.go:203` (`newOIDCProvider`)
- **Severity:** Low
- **Status:** ✅ Fixed
- **What:** When `httpClient` is `nil`, the function falls back to `http.DefaultClient`, which has no timeout. This code path is reachable when creating an OIDC provider with a nil client parameter.
- **Why it matters:** If the upstream OIDC discovery endpoint hangs indefinitely, the goroutine performing discovery will block forever. In production startup paths, this could delay or prevent service readiness. The context-based timeout (line 211) mitigates this partially, but `http.DefaultClient` connections can outlive context cancellation if the TCP handshake itself hangs.
- **Implementation:**
  - `pkg/identity/oidc.go` — `newOIDCProvider` now assigns `&http.Client{Timeout: defaultHTTPTimeout}` (10 s) when `httpClient == nil`, consistent with `NewHTTPJWKSClient` (line 88) and `NewOIDCProviderWithJWKSClient` (line 168).
  - `pkg/identity/identity_test.go` — `TestNewHTTPJWKSClient_NilClientUsesTimeout` and `TestNewHTTPJWKSClient_ExplicitClientPreserved` verify the nil-client and explicit-client paths respectively.

---

### Finding 3: `math/rand/v2` for Token Refresh Jitter

- **Location:** `internal/agentruntime/token_provider.go:134` (`defaultJitter`)
- **Severity:** Low
- **Status:** ✅ Documented — no code change required
- **What:** Token refresh jitter uses `math/rand/v2.Int64N()`, which in Go 1.22+ is automatically seeded from the runtime's cryptographic entropy source. This is **not a vulnerability** in current Go versions.
- **Why it matters:** In Go 1.22+, `math/rand/v2` is auto-seeded from `crypto/rand` at startup, making the output non-deterministic. However, the PRNG state is shared across goroutines and theoretically reconstructible if an attacker observes enough outputs. For jitter timing this is acceptable — jitter is not a security mechanism, it's a thundering-herd avoidance technique.
- **Implementation:**
  - `internal/agentruntime/token_provider.go` — `defaultJitter` doc comment explicitly states: *"math/rand/v2 (not crypto/rand) is intentional here: jitter is a load-spreading mechanism, not a security primitive. In Go 1.22+, math/rand/v2 is automatically seeded from the runtime's cryptographic entropy source, producing non-deterministic output suitable for this purpose."*

---

### Finding 4: CORS Wildcard Allowed in Production Configuration

- **Location:** `internal/gateway/app.go:170-177`
- **Severity:** Low (configuration-dependent)
- **Status:** ✅ Fixed — fail-closed in production
- **What:** The gateway allows `*` in `AllowedOrigins` for production, only emitting a warning log.
- **Why it matters:** If an operator configures `AllowedOrigins: ["*"]` in production and the API sets `Access-Control-Allow-Credentials: true`, browsers will reject the response (CORS spec disallows wildcard + credentials). However, if credentials are not included, the wildcard allows any origin to make cross-origin requests, which could enable CSRF-like attacks on state-changing endpoints if the API relies solely on cookies (it doesn't — it uses Bearer-token auth). Given Bearer-token auth, the real risk is minimal.
- **Implementation:**
  - `internal/gateway/app.go` — `New()` returns an error when `Environment == "production"` and any element of `AllowedOrigins` is `"*"`. The error message includes the remediation action (`configure explicit AllowedOrigins`), making operator misconfiguration a hard startup failure rather than a silent warning.
  - `internal/gateway/gateway_test.go` — tests verify that a wildcard origin in production fails `New()`, and that a non-wildcard explicit origin in production succeeds.

---

## Areas Reviewed — No Findings

| Category                 | Status         | Notes                                                                                     |
| ------------------------ | -------------- | ----------------------------------------------------------------------------------------- |
| SQL Injection            | ✅ Safe        | All queries use positional parameters (`$1`, `$2`, etc.) via `ExecContext`/`QueryContext` |
| Command Injection        | ✅ Safe        | No `exec.Command` usage in codebase                                                       |
| Path Traversal           | ✅ Safe        | `os.ReadFile` only used with operator-configured paths (policy files, CA certs)           |
| SSRF                     | ✅ Safe        | No user-controlled URLs passed to HTTP clients; all URLs from config                      |
| Template Injection       | ✅ Safe        | No HTML/text template rendering; JSON-only API                                            |
| Hardcoded Secrets        | ✅ Safe        | All secrets loaded from environment; test constants in `_test.go` only                    |
| JWT Implementation       | ✅ Strong      | go-jose/v4, multi-algorithm support, JWKS rotation, DPoP binding                          |
| Auth Middleware          | ✅ Complete    | All non-health endpoints require authentication                                           |
| Constant-time Comparison | ✅ Used        | `subtle.ConstantTimeCompare` for static admin key validation                              |
| Cryptographic Algorithms | ✅ Modern      | Ed25519, ECDSA P-256, RSA-2048+; no MD5/SHA1 for security                                 |
| Random Number Generation | ✅ Safe        | `crypto/rand.Reader` for all key material and secrets                                     |
| TLS Configuration        | ✅ Strong      | TLS 1.2 minimum, no `InsecureSkipVerify`, cert rotation support                           |
| Race Conditions          | ✅ Protected   | All shared state guarded by `sync.Mutex` or `sync.RWMutex`                                |
| Goroutine Lifecycle      | ✅ Managed     | All goroutines have cancellation via context or stop channels                             |
| Defer in Loops           | ✅ None        | No resource-leaking defer patterns                                                        |
| Request Size Limits      | ✅ Enforced    | 1MB default on all endpoints via `LimitReader`/`MaxBytesReader`                           |
| HTTP Timeouts            | ✅ Configured  | All servers: Read/Write/Idle; All clients: explicit Timeout                               |
| Error Disclosure         | ✅ Sanitized   | Generic error messages to clients; details logged server-side                             |
| Sensitive Data Logging   | ✅ Clean       | No tokens, keys, or PII in log output                                                     |
| pprof/expvar             | ✅ Not exposed | No debug endpoints in production code                                                     |
| Panic Safety             | ✅ Recovered   | `chi.Recoverer` middleware + panics only from internal invariant violations               |
| Dependencies             | ✅ Modern      | go-jose/v4, golang.org/x/crypto; no abandoned packages                                    |

---

## Execution Plan (Priority Order)

| Priority | Finding                                    | Effort  | Dependency                                             |
| -------- | ------------------------------------------ | ------- | ------------------------------------------------------ |
| 1        | Fix X-Forwarded-For IP spoofing (#1)       | Medium  | Requires config schema change + tests                  |
| 2        | Fix `http.DefaultClient` fallback (#2)     | Trivial | None — one-line change                                 |
| 3        | Reject CORS wildcard in production (#4)    | Low     | May require operator communication for breaking change |
| 4        | Document `math/rand/v2` jitter intent (#3) | Trivial | None                                                   |

**Dependency graph:**

- Finding #1 should be addressed before any IP-based enforcement policies are deployed to production.
- Finding #2 is independent and can be fixed immediately.
- Finding #4 is a policy decision that may need operator buy-in.
- Finding #3 requires no code change.

---

## Methodology Notes

- Static analysis performed on full Go source tree
- No dynamic testing or fuzzing performed
- Test files (`*_test.go`) excluded from findings (test credentials are acceptable)
- Integration test directory reviewed for patterns but not flagged
- `gosec` nolint directives reviewed and found justified (documented in code)
