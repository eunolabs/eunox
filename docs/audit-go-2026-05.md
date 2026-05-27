# Eunox Go Codebase — Technical Audit Report

**Date:** 2026-05-27  
**Scope:** ~190 Go files across `cmd/`, `internal/`, and `pkg/`  
**Services:** gateway, issuer, minter, db-token-svc, storage-grant-svc, posture-emitter  

---

## 1. Bugs

### B-1 · `handleValidate` skips revocation **and** kill-switch checks — HIGH

**Location:** `internal/gateway/handlers.go:203–262`

`handleValidate` verifies the JWT signature and matches resource/action — nothing more. It does not call `app.deps.Revocation.IsRevoked()` or `app.deps.KillSwitch.ShouldBlock()`. A token that has been explicitly revoked (e.g. after credential compromise) still receives `{"allowed": true}` from `/api/v1/validate`. An agent that calls `/validate` instead of `/enforce` is never protected by revocation.

```
handleEnforce  → revocation check ✓  kill-switch check ✓
handleValidate → revocation check ✗  kill-switch check ✗   ← BUG
handleProxy    → kill-switch first   revocation second
```

**Impact:** Revoked credentials bypass policy enforcement on the `/validate` path.

**Fix:** Apply the same revocation + kill-switch checks used in `handleEnforce` before returning `Allowed: true`.

---

### B-2 · `handleValidate` ignores conditions — HIGH

**Location:** `internal/gateway/handlers.go:233–262`

`handleValidate` only checks `Resource` and `Actions` matching. It does not evaluate `Conditions` (e.g. `TimeWindowCondition`, `IPRangeCondition`, `AllowedOperationsCondition`). A caller receives `Allowed: true` even if a `notAfter` time has passed or the caller is outside the permitted IP range.

**Impact:** Callers treating `/validate` as authoritative receive incorrect allow decisions for expired or IP-restricted capabilities.

**Fix:** Either run the full enforcement engine (`engine.ValidateAction`) or document clearly that `/validate` is signature-only and must not substitute for `/enforce`.

---

### B-3 · `handleProxy` checks kill-switch **before** revocation — MEDIUM

**Location:** `internal/gateway/handlers.go:298–325`

Check order inconsistency:
- `handleEnforce`: revocation → DPoP → kill-switch
- `handleProxy`: kill-switch → revocation

Both checks are present, so there is no security bypass. However, if kill-switch activation and revocation coincide, the proxy path's audit event records "kill-switch block" rather than "revocation block," producing misleading forensic trails.

**Fix:** Align `handleProxy` to match `handleEnforce` order (revocation first).

---

### B-4 · DPoP replay protection uses composite hash instead of JTI — HIGH

**Location:** `internal/gateway/dpop_verify.go`, `dpop_store.go`

`verifyDPoP` derives a store key as `SHA256(proof || method || url)` rather than extracting the `jti` claim from the DPoP proof JWT. The same DPoP JWT replayed to a **different** URL is treated as a new proof — replay protection is silently bypassed by changing even one query parameter.

The DPoP RFC (RFC 9449 §11.1) requires the `jti` in the proof to be unique and stored for replay detection, independent of the URL.

**Impact:** A stolen DPoP proof can be replayed against any URL within the nonce window.

**Fix:** Parse the DPoP proof JWT, extract the `jti` claim, and store `jti` as the replay key. The `htm`/`htu` binding check should be a separate validation step.

---

### B-5 · `killswitch/redis.go` `Reset()` silently drops global key deletion error — MEDIUM

**Location:** `pkg/killswitch/redis.go:178–192`

```go
func (r *Redis) Reset(ctx context.Context) error {
    _ = r.client.Del(ctx, redisGlobalKey).Err()   // error discarded
    // ...
}
```

If the Redis `DEL` for the global kill-switch key fails (e.g. network partition), `Reset()` returns `nil`. The caller assumes success, but the global kill-switch remains active. For an emergency "revive all" operation, this is a critical silent failure.

**Fix:** Return the error from the `Del` call; log and propagate it.

---

### B-6 · `pkg/audit/transport.go` — context cancel not deferred inside batch loop — MEDIUM

**Location:** `pkg/audit/transport.go`, `flushBuffer` method

Inside the batch-size-limit branch of the flush loop, `ctx, cancel := context.WithTimeout(...)` is created, used, then `cancel()` is called manually. If `deliverWithRetry` panics (e.g. marshaling failure on a malformed event), `cancel` is never called, leaking a goroutine pinned to the context timer.

**Fix:** Use `defer cancel()` immediately after `context.WithTimeout`.

---

### B-7 · `isUniqueViolation` uses string-matching on error message — LOW

**Location:** `internal/minter/postgres_store.go:431–445`

```go
return strings.Contains(msg, code) // code = "23505"
```

The digit string `"23505"` can appear in other error messages (e.g. a row value that happens to contain it). The correct vendor-neutral approach is `errors.As(err, &pgErr)` with `pgconn.PgError` (pgx v5) or a `pq.Error` type assertion, both available without depending on the full driver. As written, this can produce false positives on multi-row errors that embed numeric data.

---

## 2. Unimplemented / Stub Code

### U-1 · Cloud adapters (`dbtokensvc`, `storagegrantsvc`) are stubs — no real SDK integration — MEDIUM

**Location:** `internal/dbtokensvc/adapter_aws.go`, `adapter_azure.go`, `adapter_gcp.go`; same for `storagegrantsvc/`

The AWS adapter implements SigV4 signing manually from scratch (no `aws-sdk-go-v2`). The Azure and GCP adapters use thin `TokenProvider` interfaces with no bundled implementations. The only deployable path in production today is through the `StubAdapter`, which is explicitly blocked with `ErrNotImplemented`. The services cannot be run in production without writing the cloud provider wiring.

The manual `generateAuthToken` SigV4 builder for AWS RDS is also untested against the reference implementation (`rdsutils.BuildAuthToken` from `aws-sdk-go-v2`).

---

### U-2 · `handleRenew` does not check revocation before issuing a new token — HIGH

**Location:** `internal/issuer/app.go:413–500`

`handleRenew` accepts an existing capability token, re-authenticates the user identity, and issues a fresh token with the same capabilities. It calls `verifyCapabilityToken` (signature + expiry check) but never checks whether the original token's `jti` is revoked.

An attacker with a revoked-but-not-yet-expired token can call `/issuer/renew` with a valid ID token to obtain a new, non-revoked token with the same capabilities, permanently bypassing revocation.

The issuer's `Dependencies` struct does not include a `Revocation` field — the revocation check is architecturally absent, not just an oversight in the handler.

**Fix:** Add `Revocation revocation.Checker` to `issuer.Dependencies` and check it in `handleRenew` before issuing the renewed token.

---

### U-3 · `noopVerifier` in `cmd/gateway/main.go` rejects every token — dev mode is broken

**Location:** `cmd/gateway/main.go`

When `IssuerJWKSURL` is empty, a `noopVerifier` is wired as the JWT verifier. The `noopVerifier` returns `ErrNoVerifier` for every `VerifyToken` call, so every request to `/api/v1/enforce` and `/api/v1/validate` returns 401. Local development without a live JWKS endpoint is not practically possible.

---

### U-4 · `audit_routes.go` — `order_by` and `order_dir` query params are no-ops

**Location:** `internal/gateway/audit_routes.go:284–288`

```go
_ = orderBy // Reserved for future use in query store.
_ = dir     // Reserved for future use.
```

`GET /api/v1/audit/records` accepts `order_by` and `order_dir` params that are silently ignored. Callers relying on ordering of audit results will get unspecified ordering from the underlying store.

---

## 3. Feature Gaps

### F-1 · `IntersectCapabilities` falls back to full policy grant when no capabilities are requested

**Location:** `internal/issuer/policy/policy.go:176–183`

```go
if len(requested) == 0 {
    return policy.Capabilities, nil  // returns ALL policy caps
}
```

If a caller submits an issue request with an empty `capabilities` array, they receive every capability the policy allows. Any caller who omits capabilities — e.g. due to a client bug — silently gets maximum permissions.

**Fix:** Require at least one explicitly requested capability; return an error for empty requests.

---

### F-2 · `handleProxy` has no DPoP enforcement for proxied requests

**Location:** `internal/gateway/handlers.go:264–360`

`handleEnforce` and `handleValidate` both have DPoP proof verification hooks, but `handleProxy` does not. Proxied requests require a valid capability token but not a DPoP proof, allowing a stolen token to be replayed to any proxied backend without the sender-constraint DPoP provides.

---

### F-3 · `InMemoryPartnerDIDStore` is not safe for multi-replica gateway

**Location:** `internal/gateway/admin_routes.go`, `NewInMemoryPartnerDIDStore()`

Partner DID registrations are stored in process memory. In a multi-replica gateway deployment, a DID registered against replica A is invisible to replica B. The wiring in `cmd/gateway/main.go` should be verified to ensure the Redis-backed store is used when `RedisURL` is configured.

---

### F-4 · `SQLiteQueue` in posture emitter has no backpressure under sustained overload

**Location:** `internal/posture/queue.go:44–62`

The comment accurately documents the ~100–500 events/s ceiling, but there is no backpressure mechanism. If the delivery worker falls behind, `Push` callers block on the mutex indefinitely. Under sustained overload, HTTP handler goroutines pile up and the server becomes unresponsive.

**Fix:** Add a bounded channel or dropped-event counter to shed load gracefully.

---

## 4. Dead Code

### D-1 · `RedactFieldsCondition` value-form type assertion is dead code

**Location:** `pkg/enforcement/engine.go:116–130`

```go
if rc, ok := cond.(*capability.RedactFieldsCondition); ok { ... continue }
// Unreachable — unmarshalCondition always returns a pointer:
if rc, ok := cond.(capability.RedactFieldsCondition); ok { ... continue }
```

`unmarshalCondition` always returns `&RedactFieldsCondition{}`. The value-form type assertion is unreachable.

**Fix:** Remove the second branch; add a `default` panic for unrecognized condition types to catch future changes.

---

### D-2 · `auditPrincipal` discarded in two handlers

**Location:** `internal/gateway/audit_routes.go:185, 201`

```go
_ = auditPrincipalFromCtx(r.Context())
```

`handleAuditSigningKeys` and `handleAuditChainProof` call `auditPrincipalFromCtx` only for its panic-guard side-effect. The returned value is immediately discarded. Consider extracting a `requireAuditAuth(ctx)` guard to make the intent explicit.

---

### D-3 · Policy engine `pollLoop` does not update `lastModified` on initial load

**Location:** `internal/issuer/policy/policy.go:240–260`

`LoadFromFile` calls `reload()` but does not set `e.lastModified`. On the first poll tick, `info.ModTime().After(time.Time{})` is always `true`, so `reload()` is always called on the first tick regardless of whether the file changed.

**Fix:** Set `e.lastModified` in `LoadFromFile` after a successful reload.

---

## 5. Structural Issues

### S-1 · `ResilientRedis.Start` calls `refreshState` twice

**Location:** `pkg/killswitch/resilient_redis.go:36–49`

`r.inner.Start(ctx)` internally calls `r.inner.refreshState(subCtx)` (child context). `ResilientRedis.Start` then calls `r.inner.refreshState(ctx)` a second time on the original context. The two calls race against the pub/sub goroutine launched by `Start`. The second call also uses the parent `ctx` rather than `subCtx`, so if `ctx` is cancelled before the lifecycle ends, the inner Redis state diverges from the resilient wrapper's health report.

**Fix:** Expose a `HealthStatus() error` method on `Redis` instead of re-running `refreshState`.

---

### S-2 · `InMemoryDPoPStore.MarkUsed` iterates entire map under write lock when map > 1000

**Location:** `internal/gateway/dpop_store.go`

The eviction logic in `MarkUsed` iterates every entry in the map to delete expired ones whenever `len(s.entries) > 1000`. Under high-concurrency DPoP usage, this causes long write-lock hold times on every 1001st proof, producing request latency spikes.

---

### S-3 · `lifecycle.Manager` drops one error when two servers fail simultaneously

**Location:** `pkg/lifecycle/lifecycle.go:176–204`

If two servers fail simultaneously and both send to `errCh` before `shutdown()` sets the `stopOnce`, only the first error is returned; the second error is silently dropped.

**Fix:** Use `errors.Join` (Go 1.20+) to accumulate both errors.

---

### S-4 · `issuer/policy/Engine.pollLoop` — `lastModified` not set on initial `LoadFromFile`

**Location:** `internal/issuer/policy/policy.go:237–260`

Same root cause as D-3. `e.lastModified` is never set by `LoadFromFile`, so the first poll tick always re-reads the file regardless of change. Combined with D-3's fix, both issues resolve together.

---

## 6. Test Coverage Gaps (as bug signal)

### T-1 · No test that a revoked token returns `Allowed: false` from `/validate`

**Location:** `internal/gateway/` test files  
This gap exists because B-1 is the actual bug — once B-1 is fixed, a covering test must be added.

---

### T-2 · No cross-URL DPoP replay test

**Location:** `internal/gateway/dpop_store_test.go`  
Tests verify same `proof+method+url` is rejected on the second call, but not that the same DPoP proof JWT replayed to a different URL is also rejected (the B-4 attack vector).

---

### T-3 · No test that a revoked token cannot be renewed

**Location:** `internal/issuer/app_test.go` (missing)  
After U-2 is fixed, a test submitting a revoked token to `/issuer/renew` and asserting 401 must be added.

---

### T-4 · `killswitch Reset()` silently-dropped error not tested

**Location:** `pkg/killswitch/redis_test.go`  
No test injects a `DEL` failure for `Reset()`. After B-5 is fixed, add a failure injection test.

---

### T-5 · `generateAuthToken` has no golden-output test vs AWS SDK

**Location:** `internal/dbtokensvc/adapter_aws.go`  
The manual SigV4 implementation is not compared against `rdsutils.BuildAuthToken`. A divergence would cause silent auth failures. A table-driven test with known inputs or a comparison test using the SDK reference is needed.

---

### T-6 · `posture/queue.go` `Push` under backpressure is untested

**Location:** `internal/posture/queue.go`  
No tests for behavior of `Push` when the delivery worker is stalled, exposing the indefinite-block risk documented in F-4.

---

## Prioritized Execution Plan

| Priority | ID | Area | Action |
|----------|----|----- |--------|
| P0 | B-1 | Gateway `/validate` | Add revocation + kill-switch checks to `handleValidate` |
| P0 | B-2 | Gateway `/validate` | Evaluate conditions in `handleValidate`, or gate and document clearly |
| P0 | U-2 | Issuer `/renew` | Add `Revocation` dependency to issuer; check in `handleRenew` |
| P0 | B-4 | DPoP replay | Store JTI claim as replay key, not composite hash |
| P1 | B-5 | Kill-switch `Reset` | Return error from `Del` in `Reset()` |
| P1 | B-3 | Gateway `/proxy` | Align kill-switch / revocation order with `handleEnforce` |
| P1 | F-2 | Gateway proxy DPoP | Add DPoP enforcement to `handleProxy` |
| P2 | B-6 | Audit transport | `defer cancel()` in `flushBuffer` batch loop |
| P2 | S-1 | Kill-switch resilient | Remove duplicate `refreshState` call; expose `HealthStatus()` |
| P2 | F-1 | Policy engine | Reject empty `capabilities` request; do not grant full policy defaults |
| P2 | B-7 | Minter Postgres | Replace string-match with `pgconn.PgError` type assertion |
| P3 | U-1 | dbtokensvc/storagegrantsvc | Provide bundled real cloud provider adapter implementations |
| P3 | S-3 | Lifecycle manager | Use `errors.Join` to preserve both error values on concurrent server failure |
| P3 | D-1 | Enforcement engine | Remove dead value-form `RedactFieldsCondition` type assertion |
| P3 | D-3 / S-4 | Policy engine | Set `lastModified` in `LoadFromFile` |
| P4 | T-1–T-6 | Tests | Add test cases for every bug and gap fixed above |
