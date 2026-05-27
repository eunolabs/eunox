# Eunox Go Codebase — Technical Audit Report

**Date:** 2026-05-27  
**Scope:** All Go source in `cmd/`, `internal/`, `pkg/`  
**Module:** `github.com/edgeobs/eunox` (Go 1.25)

---

## Executive Summary

The codebase is well-structured, with clean separation of concerns, comprehensive interfaces, explicit error handling, and production-safety guards. No TODO/FIXME comments, no panic stubs, no dead code of significance. Test coverage exists across all 30 packages (99 test files, 31k LOC test code).

However, the audit identified **5 confirmed bugs**, **3 feature gaps**, and **2 structural vulnerabilities** that should be addressed. The most critical finding is a Slowloris DoS vulnerability in the gateway (missing `ReadHeaderTimeout`).

---

## 1. Bugs

### BUG-1: Missing `ReadHeaderTimeout` — Slowloris DoS Vulnerability

| Field | Value |
|-------|-------|
| **Location** | `cmd/gateway/main.go:176-182`, `cmd/posture-emitter/main.go:108-113` |
| **Category** | Bug — Resource management / Security |
| **Severity** | **Critical** |

**What:** The gateway and posture-emitter HTTP servers set `ReadTimeout` and `WriteTimeout` but omit `ReadHeaderTimeout`. All other services (`minter`, `issuer`, `db-token-svc`, `storage-grant-svc`) correctly set it to 10s.

**Evidence:**
```go
// cmd/gateway/main.go:176-182
srv := &http.Server{
    Addr:         fmt.Sprintf(":%d", cfg.Port),
    Handler:      app.Handler(),
    ReadTimeout:  readTimeout,   // 10s
    WriteTimeout: writeTimeout,  // 60s
    IdleTimeout:  idleTimeout,   // 120s
    // ReadHeaderTimeout: MISSING
}
```

Compare with `cmd/minter/main.go:98`:
```go
ReadHeaderTimeout: 10 * time.Second, // ✓ Present
```

**Impact:** An attacker can open thousands of connections and send headers byte-by-byte, exhausting the server's goroutine/fd pool. The `ReadTimeout` only starts counting after the connection is accepted but Go's net/http does not enforce header-read deadlines without `ReadHeaderTimeout`.

**Fix:**
```go
ReadHeaderTimeout: readTimeout, // Add to both gateway servers and posture-emitter
```

---

### BUG-2: Token Expiry Off-by-One — Token Valid at Exact Expiry Second

| Field | Value |
|-------|-------|
| **Location** | `internal/gateway/handlers.go:93`, `internal/gateway/handlers.go:275` |
| **Category** | Bug — Data correctness |
| **Severity** | **Medium** |

**What:** Token expiry uses strict greater-than (`>`) instead of greater-than-or-equal (`>=`). A token with `exp=1000` is accepted when `time.Now().Unix() == 1000`.

**Evidence:**
```go
// Line 93 and 275 (both enforce and proxy handlers)
if claims.ExpiresAt > 0 && time.Now().Unix() > claims.ExpiresAt {
    // deny
}
```

**Impact:** Tokens are valid for 1 extra second beyond their stated expiry. Per RFC 7519 §4.1.4, `exp` is "the time on or after which the JWT MUST NOT be accepted" — the current implementation is non-compliant.

**Fix:**
```go
if claims.ExpiresAt > 0 && time.Now().Unix() >= claims.ExpiresAt {
```

---

### BUG-3: Policy Engine `StartHotReload()` Spawns Multiple Goroutines Without Guard

| Field | Value |
|-------|-------|
| **Location** | `internal/issuer/policy/policy.go:103-109` |
| **Category** | Bug — Concurrency |
| **Severity** | **Medium** |

**What:** Calling `StartHotReload()` multiple times spawns multiple `pollLoop()` goroutines with no idempotency guard.

**Evidence:**
```go
func (e *Engine) StartHotReload() {
    if e.filePath == "" {
        return
    }
    go e.pollLoop() // No check if already running
}
```

The `Stop()` method uses `sync.Once` to close `stopCh`, so all spawned goroutines will eventually exit. But while running, multiple goroutines race on `e.reload()` which does file I/O + mutex-protected map replacement. This is functionally benign but wasteful.

**Impact:** If accidentally called twice (e.g., config hot-reload + startup), duplicate file-polling goroutines run and potentially issue concurrent reloads. Low severity because the mutex in `reload()` serializes the actual policy swap.

**Fix:**
```go
func (e *Engine) StartHotReload() {
    if e.filePath == "" {
        return
    }
    e.startOnce.Do(func() {
        go e.pollLoop()
    })
}
```

---

### BUG-4: Integer Overflow in RSA Public Exponent Parsing

| Field | Value |
|-------|-------|
| **Location** | `internal/gateway/dpop_crypto.go:105` |
| **Category** | Bug — Data correctness / Security |
| **Severity** | **Low** (exploitability limited) |

**What:** RSA public exponent bytes are converted via `big.Int → Int64() → int` without bounds checking. A maliciously crafted JWK could supply an exponent that overflows.

**Evidence:**
```go
pubKey := &rsa.PublicKey{
    N: new(big.Int).SetBytes(nBytes),
    E: int(new(big.Int).SetBytes(eBytes).Int64()), // Unchecked truncation
}
```

**Impact:** On 64-bit systems, `Int64()` returns 0 for values > MaxInt64. A 0 exponent would cause RSA verification to always fail (safe failure). On 32-bit systems (unlikely in production), could silently truncate. The attack surface is limited because the DPoP JWK comes from the authenticated client's proof.

**Fix:**
```go
eBig := new(big.Int).SetBytes(eBytes)
if !eBig.IsInt64() || eBig.Int64() > math.MaxInt32 || eBig.Int64() < 1 {
    return fmt.Errorf("RSA JWK: exponent out of safe range")
}
pubKey := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(eBig.Int64())}
```

---

### BUG-5: Exponential Backoff Integer Overflow for Large Attempt Counts

| Field | Value |
|-------|-------|
| **Location** | `internal/posture/delivery.go:246` |
| **Category** | Bug — Data correctness |
| **Severity** | **Low** (mitigated by MaxAttempts default=10) |

**What:** `1 << uint(currentAttempts)` overflows for attempts ≥ 63 (64-bit) producing a negative `time.Duration`.

**Evidence:**
```go
func (w *DeliveryWorker) computeNextAttempt(currentAttempts int) int64 {
    backoff := w.config.BackoffBase * (1 << uint(currentAttempts))
    if backoff > w.config.BackoffMax {
        backoff = w.config.BackoffMax
    }
    return time.Now().Add(backoff).UnixMilli()
}
```

**Impact:** With default `MaxAttempts=10`, `currentAttempts` never exceeds 9 (dead-lettered at 10). Safe in default config. However, if operators increase `MaxAttempts` beyond 62, the backoff becomes negative, causing immediate retries (thundering herd).

**Fix:**
```go
backoff := w.config.BackoffBase * (1 << min(uint(currentAttempts), 62))
```

---

## 2. Unimplemented & Stub Code

### STUB-1: Cloud Adapter Stubs (DB Token + Storage Grant)

| Field | Value |
|-------|-------|
| **Location** | `internal/dbtokensvc/adapter_*.go`, `internal/storagegrantsvc/adapter_*.go` |
| **Category** | Unimplemented |
| **Severity** | Informational |

**What:** All 6 cloud adapters (AWS RDS, Azure SQL, GCP Cloud SQL, AWS S3, Azure Blob, GCP GCS) are stubs that return placeholder credentials/URLs. They are correctly blocked in production mode.

**Evidence:** (e.g., `internal/dbtokensvc/adapter_aws.go`)
```go
func (a *AWSRDSAdapter) MintCredential(ctx context.Context, req *MintDBCredentialRequest) (*DBCredential, error) {
    // Stub: returns synthetic credentials for development/testing.
    return &DBCredential{
        Username: req.Username,
        Password: fmt.Sprintf("stub-rds-token-%s-%d", req.Username, time.Now().Unix()),
        ...
    }, nil
}
```

**Impact:** None in production (blocked). Development-only.

---

### STUB-2: CSPM Posture Plugins (Defender, SecurityHub, SCC)

| Field | Value |
|-------|-------|
| **Location** | `internal/posture/` (plugin implementations) |
| **Category** | Unimplemented |
| **Severity** | Informational |

**What:** Three of four posture delivery plugins are stubs. Only `StdoutPlugin` is functional. These are documented as "not implemented" and return errors at runtime.

---

## 3. Feature Gaps

### GAP-1: Missing Pagination on Admin List Endpoints

| Field | Value |
|-------|-------|
| **Location** | `internal/gateway/admin_partner_dids.go:54-69`, `internal/issuer/scim.go:436-448` |
| **Category** | Feature Gap |
| **Severity** | Medium |

**What:** Partner DID list and SCIM Users/Groups list endpoints return ALL records without pagination. The audit records endpoint correctly implements pagination with `page_size` and `page` query params.

**Evidence:**
```go
// admin_partner_dids.go — returns ALL partners
partners, err := app.adminDeps.PartnerDIDs.List(r.Context())
writeJSON(w, http.StatusOK, map[string]any{
    "partners": partners,
    "count":    len(partners),
})
```

**Impact:** With many partners/users, responses grow unbounded. Memory pressure on both server and client. OOM risk at scale.

---

### GAP-2: Audit Transport `Enqueue` Race Window (Event Loss After Close)

| Field | Value |
|-------|-------|
| **Location** | `pkg/audit/transport.go:172-188` |
| **Category** | Feature Gap |
| **Severity** | Low |

**What:** Between releasing the mutex (line 178) and the channel send (line 181), `Close()` could set `closed=true` and drain the buffer. An event could then successfully enqueue into the buffer after `Close()` has finished draining — the event would never be delivered.

**Evidence:**
```go
func (t *HTTPTransport) Enqueue(evidence *SignedAuditEvidence) error {
    t.mu.Lock()
    if t.closed {
        t.mu.Unlock()
        return ErrTransportClosed
    }
    t.mu.Unlock()
    // ← WINDOW: Close() runs here, drains buffer, returns
    select {
    case t.buffer <- evidence: // This event is never flushed
        return nil
    default:
        return ErrBatchFull
    }
}
```

**Impact:** Under concurrent close + enqueue, a small number of audit events may be silently lost. The documented overflow policy already accepts event loss, so this is consistent with the design philosophy but worth noting.

---

### GAP-3: Kill Switch `refreshState` Error Silently Dropped

| Field | Value |
|-------|-------|
| **Location** | `pkg/killswitch/redis.go:54` |
| **Category** | Feature Gap |
| **Severity** | Low |

**What:** Initial state refresh error is discarded:
```go
_ = r.refreshState(subCtx)
```

**Impact:** If Redis is temporarily unreachable at startup, the kill switch starts with empty state (all-allowed). A previously activated global kill switch would not be enforced until the next pub/sub message arrives. This is a "fail-open" behavior.

---

## 4. Stale & Dead Code

**No significant dead code found.** The codebase is clean:
- No unreachable functions
- No orphaned packages
- No TODO/FIXME/HACK comments
- No commented-out code blocks
- All exported types have callers
- All constants are referenced

---

## 5. Structural & Design Issues

### STRUCT-1: Gateway Lacks Drain Delay Before Shutdown

| Field | Value |
|-------|-------|
| **Location** | `cmd/gateway/main.go:224-250` (compared with `pkg/lifecycle/lifecycle.go:194-200`) |
| **Category** | Structural |
| **Severity** | Medium |

**What:** The gateway's `main.go` implements its own shutdown logic instead of using the `pkg/lifecycle.Manager` which includes a configurable drain delay for K8s load balancer de-registration. The gateway shuts down immediately on signal without waiting for LB endpoint removal.

Other services (minter, issuer, etc.) use `lifecycle.Manager` which provides:
```go
// Drain delay: allow load balancer to remove this endpoint.
if m.drainDelay > 0 {
    m.logger.Info("drain delay", slog.Duration("delay", m.drainDelay))
    time.Sleep(m.drainDelay)
}
```

**Impact:** During rolling deployments, the gateway may reject in-flight requests from LBs that haven't yet removed the endpoint. Other services handle this correctly.

---

### STRUCT-2: Telemetry Collector `Stop()` Race Under Concurrent Calls

| Field | Value |
|-------|-------|
| **Location** | `internal/gateway/telemetry.go:80-91` |
| **Category** | Structural |
| **Severity** | Low |

**What:** The `stopped` flag and `close(tc.stopCh)` are protected by mutex, making the double-close safe. However, `Flush()` after `close(tc.stopCh)` runs outside the lock. If a concurrent `Record()` call is in progress, the flush may miss the event.

This is benign — telemetry loss during shutdown is acceptable.

---

## 6. Test Coverage Gaps (Bug Signals)

### TEST-1: Admin JWT Verification — 3 Tests for 267 LOC

| Field | Value |
|-------|-------|
| **Location** | `internal/gateway/admin_jwt.go` |
| **Risk** | High — auth bypass if malformed tokens aren't rejected |

The JWT verification path for admin routes has minimal test coverage. Token failure scenarios (expired, wrong audience, malformed header, revoked key) should be exercised.

---

### TEST-2: Identity/OIDC Provider — 8 Tests for 542 LOC

| Field | Value |
|-------|-------|
| **Location** | `pkg/identity/` |
| **Risk** | High — identity verification is the trust root |

OIDC token validation, audience checking, and error paths need comprehensive testing. This is the primary trust boundary for token issuance.

---

### TEST-3: Federation Package — 1 Test for 288 LOC

| Field | Value |
|-------|-------|
| **Location** | `pkg/federation/` |
| **Risk** | Medium — cross-org trust boundary |

Partner federation with attenuation and circuit breaker wrapping has near-zero test coverage.

---

### TEST-4: No Explicit `-race` CI Configuration

The `Makefile` runs `go test -race -count=1 ./...` which is correct. However, the rotating keystore is the only package with explicit concurrent-access tests. Given the concurrency patterns in:
- Token provider (background refresh timer)
- Kill switch (pub/sub goroutine)  
- Audit transport (flush loop)
- Delivery worker (poll loop)

Dedicated race-condition tests would catch latent issues.

---

## Execution Plan (Priority Order)

### Phase 1 — Critical Security Fix (Immediate)

| # | Finding | Effort | Dependencies |
|---|---------|--------|--------------|
| 1 | BUG-1: Add `ReadHeaderTimeout` to gateway + posture-emitter | 5 min | None |

### Phase 2 — Correctness Fixes (This Sprint)

| # | Finding | Effort | Dependencies |
|---|---------|--------|--------------|
| 2 | BUG-2: Fix token expiry `>` → `>=` | 5 min | None |
| 3 | BUG-3: Add `sync.Once` to `StartHotReload` | 10 min | None |
| 4 | BUG-4: Validate RSA exponent bounds | 15 min | None |
| 5 | BUG-5: Cap backoff shift operand | 5 min | None |

### Phase 3 — Feature Gaps (Next Sprint)

**Status: ✅ Complete** — Implemented 2026-05-27.

| # | Finding | Effort | Status |
|---|---------|--------|--------|
| 6 | GAP-1: Add pagination to partner DID + SCIM list endpoints | 2 hrs | ✅ Done |
| 7 | STRUCT-1: Migrate gateway to `lifecycle.Manager` (or add drain delay) | 1 hr | ✅ Done |
| 8 | GAP-3: Log kill switch initial refresh failure | 10 min | ✅ Done |

**Implementation notes:**

- **GAP-1**: `handlePartnerDIDList` now supports `page_size` (default 50, max 1000) and `page` (1-indexed) query parameters. Results are sorted stably by `RegisteredAt` ASC then `DID` ASC. Response includes `total_count`, `has_more`, `page`, `page_size`. Both `handleSCIMListUsers` and `handleSCIMListGroups` implement RFC 7644 §3.4.2.4 SCIM pagination via `startIndex` (1-based, default 1) and `count` (default 100, max 1000, `count=0` returns `totalResults` only). Results sorted by `Meta.Created` ASC then `ID` ASC.
- **STRUCT-1**: `pkg/lifecycle.Manager` gained `AddServerWithListener(name, srv, ln)` for pre-bound listeners (e.g. admin server restricted to loopback). `cmd/gateway/main.go` replaced its manual signal/shutdown block with `lifecycle.New(WithDrainDelay(5s), ...)`. `Config.IsReady func() bool` field added; `handleReady` returns 503 while `IsReady` returns false (drain window).
- **GAP-3**: `Redis` struct gained an optional `*slog.Logger` set via `WithLogger(logger)`. The initial `refreshState` failure in `Start()` is now logged as `Warn` with `"kill switch: initial state refresh failed; starting fail-open"` instead of silently discarded.

### Phase 4 — Test Coverage ✅ Complete

| # | Finding | Effort | Status |
|---|---------|--------|--------|
| 9 | TEST-1: Admin JWT verification tests | 2 hrs | ✅ Done |
| 10 | TEST-2: OIDC identity provider tests | 3 hrs | ✅ Done |
| 11 | TEST-3: Federation package tests | 2 hrs | ✅ Done |
| 12 | TEST-4: Concurrent access tests for audit transport, telemetry, kill switch | 3 hrs | ✅ Done |

**Implementation notes:**

- **TEST-1** (`internal/gateway/admin_jwt_extended_test.go`): 16 test functions covering malformed tokens, audience mismatch, missing subject, JWKS unavailability/invalid JSON, key rotation with cache TTL expiry, RSA+ECDSA multi-algorithm support, wrong signature, concurrent verification (100 goroutines with `-race`), cache expiry, context cancellation, not-yet-valid tokens, X-Admin-Key static header auth, bearer token precedence, and no-credentials rejection.
- **TEST-2** (`pkg/identity/identity_extended_test.go`): 16 test functions covering wrong issuer/audience rejection, JWKS fetch failure after cache expiry, cache TTL refresh, concurrent token verification, context cancellation, empty/malformed tokens, no-kid header handling, multiple JWKS keys selection, no matching kid, OIDC discovery failure, untrusted DID rejection, nil JWKS client, and non-OK HTTP status codes.
- **TEST-3** (`pkg/federation/federation_extended_test.go`): 11 test functions covering concurrent register/approve/revoke (50 goroutines), concurrent list+register, duplicate register (overwrite semantics), approve/revoke not-found, concurrent `ResolvePublicKeys`, concurrent `getOrCreateBreaker` (race-free double-checked locking), empty DID document, resolver errors, resource prefix matching, multiple capabilities, and action subset validation.
- **TEST-4**: Concurrent access stress tests across three packages:
  - `pkg/audit/transport_concurrent_test.go`: 6 tests — concurrent Enqueue (100 goroutines), concurrent Enqueue+Close race, buffer pressure with drops, concurrent Send, flush loop stress (200 records with interleaved flushes), double Close idempotency.
  - `internal/gateway/telemetry_concurrent_test.go`: 6 tests — concurrent Record (100 goroutines), concurrent Record+Flush, concurrent Record+Stop, concurrent RecordEnforcement, concurrent UsageTracker read/write, concurrent IdempotencyStore set/get.
  - `pkg/killswitch/killswitch_concurrent_test.go`: 6 tests — concurrent ShouldBlock, concurrent Kill/Revive agents, concurrent global toggle, concurrent session operations, concurrent Reset+query, concurrent Status.

---

## Non-Findings (Verified Correct)

- **Graceful shutdown**: All services properly handle SIGTERM/SIGINT with context-based shutdown
- **Admin auth**: All admin routes consistently protected via middleware
- **Idempotency**: Admin mutations use idempotency store with TTL
- **Error wrapping**: Consistent use of `fmt.Errorf("context: %w", err)` 
- **No dead code**: Clean codebase, no orphaned exports
- **No panic stubs**: All interfaces fully implemented (stubs are documented dev-mode placeholders)
- **Resource cleanup**: `defer resp.Body.Close()` consistently used in HTTP clients
- **Default-deny enforcement**: Engine correctly denies when no capability matches
