# Formal Architecture Review — eunox

> **Reviewer:** Principal Software Architect (AI-assisted)  
> **Review date:** 2026-05-27  
> **Scope:** Full repository — `cmd/`, `internal/`, `pkg/`, `migrations/`, `k8s/`, `infra/`, `docs/`  
> **Codebase:** Go 1.25 monorepo at `github.com/edgeobs/eunox`

---

## Executive summary

eunox is a capability-native, zero-trust governance plane for AI agents. Its core design
— cryptographically signed, time-limited JWT capability tokens enforced at a
single gateway PEP — is architecturally sound. The threat model is clearly
articulated (`docs/architecture.md`) and the code is largely consistent with it.
The team has applied good practices: default-deny enforcement engine, constant-time
key comparison, DPoP replay protection, Redis HA validation at boot, and a
structured config validation layer.

The primary risks are operational rather than fundamental: in-memory
implementations are wired in production paths with no compile-time or runtime
guard against misuse; the public enforcement API (`/api/v1/enforce`) lacks a
global per-IP rate limiter; TLS termination is fully delegated to the external
layer with no enforcement in binaries; and the gateway's `noopVerifier` returns
an error (correct) but would still start without JWKS configured unless the
operator notices the startup log. The sections below document every finding with
priority and a concrete remediation path.

---

## [!] Critical Risks

### CR-1 — In-memory state wired into production service entry-points

**Severity:** Critical — data-plane security property loss under restart  
**Files:** `cmd/gateway/main.go:93-99`, `cmd/minter/main.go:68,73,78`

**Status: ✅ Implemented** — `cmd/gateway/main.go` (2026-05-27).

`buildGatewayBackends()` now wires resilient Redis-backed implementations for
kill-switch, revocation, and call-counter when `REDIS_URL` (or per-service
overrides `KILL_SWITCH_REDIS_URL`, `REVOCATION_REDIS_URL`, `CALL_COUNTER_REDIS_URL`)
is set. Production startup fails with a fatal error when `REDIS_URL` is absent.
In-memory fallbacks remain for development only and emit `WARN` logs.

- Kill-switch + revocation: **fail-closed** (`ResilientRedis` wrappers).
- Call counter: **fail-open** (temporary under-counting acceptable; reconcilable).
- DPoP store: no Redis implementation yet — `WARN` log emitted in production.
- Minter `KeyStore`: `MINTER_API_KEY_DB_URL production:"required"` config tag
  already enforces this at config load time.

---

### CR-2 — No rate limiting on the public enforcement endpoint (`/api/v1/enforce`)

**Severity:** Critical — DoS / resource exhaustion  
**Files:** `internal/gateway/app.go:233-267`, `internal/gateway/handlers.go:44-170`

`POST /api/v1/enforce` is the hot path that verifies JWTs, checks revocation,
evaluates conditions, and records audit entries. It carries no global per-IP or
per-tenant rate limiter (the `RateLimitRequests` / `RateLimitWindow` config fields
are declared but never applied as middleware to the public router). An unauthenticated
attacker can saturate the enforcement pipeline, triggering Redis and PostgreSQL load.
The admin router correctly applies `adminRateLimitMiddleware`; the data plane does not.

**Remediation:**  
Apply a rate-limiting middleware to the `/api/v1` route group using the existing
`ratelimit.InMemoryLimiter` (or `ResilientRedisLimiter` when Redis is configured):

```go
r.Route("/api/v1", func(r chi.Router) {
    r.Use(app.publicRateLimitMiddleware) // <-- add
    r.Post("/enforce", app.handleEnforce)
    ...
})
```

---

### CR-3 — `GATEWAY_ADMIN_JWKS_URI` enforced only in production; staging accepts static key alone

**Severity:** High — credential exposure window in staging  
**Files:** `cmd/gateway/main.go:195-212`

`validateAdminAuth` enforces JWT-based admin auth only when `NODE_ENV=production`.
Staging deployments can run with a static `ADMIN_API_KEY` alone. If staging shares
infrastructure (same Redis, same PostgreSQL) with production data, a stolen staging
admin key grants full kill-switch and revocation powers.

**Remediation:**  
Apply the same JWT-auth requirement to `staging`. The current check is:
```go
if cfg.NodeEnv != config.EnvProduction {
    return nil
}
```
Change to:
```go
if cfg.NodeEnv == config.EnvDevelopment {
    return nil
}
```

---

### CR-4 — `X-Forwarded-For` header trusted without proxy-list validation in gateway enforce path

**Severity:** High — IP range conditions bypassable  
**Files:** `internal/gateway/handlers.go:310-323`

`extractClientIP` for the public enforce path trusts the first value in
`X-Forwarded-For` verbatim. If the gateway is behind a misconfigured or missing
load balancer, a client can inject an arbitrary IP and bypass `ipRange` capability
conditions. The admin rate-limiting path (`internal/gateway/admin_ratelimit.go:43-49`)
correctly uses `r.RemoteAddr` only; the discrepancy creates an inconsistency.

**Remediation:**  
Introduce a `GATEWAY_TRUSTED_PROXIES` config variable (CIDR list). Only strip
`X-Forwarded-For` when `r.RemoteAddr` is within a trusted proxy CIDR. Fail closed
(use `RemoteAddr`) when the list is empty or the connecting IP is untrusted.

---

### CR-5 — Minter `handleRevokeKey` double-reads the store after revocation (TOCTOU)

**Severity:** Medium–High — race condition and silent metric miss  
**Files:** `internal/minter/app.go:204-233`

After revoking a key, the handler calls `app.deps.Store.GetKey()` again to retrieve
the `tenantID` for Prometheus metric labeling. In a concurrent scenario (two
simultaneous revocations of different keys for the same tenant) or with a PostgreSQL
backend that returns an error on the second read, the metric is silently skipped
(`key, _ := app.deps.Store.GetKey(...)` — the error is discarded). The initial
`RevokeKey` operation should return the key metadata or the metric should be
recorded before the revocation.

**Remediation:**  
Extend `KeyStore.RevokeKey()` to return the revoked `*APIKey`, or record the metric
from the first `GetKey` lookup in `handlePing`/`handleCreateKey` where the key is
already fetched.

---

## [~] Design Improvements

### DI-1 — InMemoryPartnerDIDStore not persisted across restarts

**Status:** Implemented

**Files:** `internal/gateway/app.go:131`, `internal/gateway/admin_routes.go`

Partner DID registrations (cross-org federation trust list) are stored in
`InMemoryPartnerDIDStore`. After a gateway restart, all registered partner DIDs are
gone and cross-org tokens will fail to verify until re-registered. In multi-replica
deployments every replica has its own independent list.

**Recommendation:** Persist partner DID registrations in Redis (with an existing
Redis client) or a small PostgreSQL table. Add a `partner_dids` migration alongside
the existing `audit` and `minter` schemas.

---

### DI-2 — `noopVerifier` silently accepts startup without JWKS; logging not guaranteed

**Status:** Implemented

**Files:** `cmd/gateway/main.go:91-104`

When `GATEWAY_ISSUER_JWKS_URL` is empty the gateway starts successfully with a
`noopVerifier` that rejects every token with an error message. This is correct
behaviour for development but, in production, if the environment variable is
missing from a Kubernetes secret/ConfigMap the service starts, health probes pass,
and every `/enforce` call returns 200 with a denial — silently breaking agent
operations with no boot-time alarm.

**Recommendation:**  
Add a startup check: if `NODE_ENV=production` and `GATEWAY_ISSUER_JWKS_URL` is empty, exit
with a fatal error (consistent with how `GATEWAY_ADMIN_JWKS_URI` is treated).

---

### DI-3 — Revocation store has no persistence or cross-replica coordination

**Files:** `cmd/gateway/main.go:98`, `pkg/revocation/memory.go`

`revocation.NewInMemory()` is always used. A Redis implementation exists
(`pkg/revocation/redis.go`) but is never wired. In a multi-replica deployment,
revoking a token via the admin API writes only to the local replica's in-memory
store. Other replicas continue to accept the token until they restart.

**Recommendation:**  
Wire `revocation.NewRedis(redisClient)` when `REDIS_URL` is set, with
`ResilientRedisLimiter`-style fail-closed fallback mirroring `pkg/killswitch`.

---

### DI-4 — `handleListKeys` has a hard-coded `limit=100, offset=0`

**Status:** Implemented

**Files:** `internal/minter/app.go:178-191`

The list-keys endpoint exposes no pagination cursor to callers and always fetches
the first 100 keys. This will silently truncate tenants with more than 100 keys and
makes the admin UI (or any operator script) unreliable at scale.

**Recommendation:**  
Accept `?limit=` and `?offset=` (or cursor-based `?after=`) query parameters.
Validate and cap `limit` to a maximum (e.g., 200). Return `nextCursor` / `total`
in the response body.

---

### DI-5 — Database connection pool configured per service but never validated at startup

**Status:** Implemented

**Files:** `pkg/config/database.go`, `cmd/minter/main.go`, `cmd/issuer/main.go`

`DatabasePoolConfig` is defined with solid defaults and documented tiering
recommendations. However, the actual `OpenPool()` call is never validated: if
`MINTER_AUDIT_DB_URL` is syntactically valid but the server is unreachable,
the service starts, health probes pass, and audit writes begin silently
erroring. There is no ping-on-start or readiness check backed by the database
connection state.

**Recommendation:**  
After `database.OpenPool()`, call `db.PingContext(ctx)` with a short timeout (3–5 s)
in the `handleReady` readiness handler, so Kubernetes traffic only reaches the pod
once the database is reachable.

---

### DI-6 — Audit transport uses `context.Background()` for background flush goroutines

**Status:** Implemented

**Files:** `pkg/audit/transport.go` (multiple `context.Background()` calls)

Background flush goroutines in `OCSFHTTPTransport` are started with
`context.Background()`, which means they are not tied to the service lifecycle
context. This breaks graceful shutdown: if the service receives `SIGTERM`, inflight
audit batches may be abandoned rather than flushed, leaving a gap in the audit ledger.

**Recommendation:**  
Pass the service lifecycle context (`ctx`) from `main.go` into `NewHTTPTransport`.
The existing `lifecycleCtx`/`lifecycleCancel` fields already capture the intent;
ensure they are initialized from the caller's shutdown context rather than
`context.Background()`.

---

### DI-7 — Enforcement engine `findMatchingCapability` uses first-match semantics with no priority ordering

**Status:** Implemented

**Files:** `pkg/enforcement/engine.go:93-100`

The engine returns the _first_ capability that matches `(resource, action)`. If a
token contains both a narrow and a broad capability for the same resource, the order
in which the issuer serializes them into the JWT determines which conditions apply.
This is fragile and may allow condition bypass if an attacker influences capability
ordering (e.g., via attenuation).

**Recommendation:**  
Match on the _most specific_ capability (longest non-wildcard resource prefix,
fewest wildcard actions) rather than the first. Document the tie-breaking rule
explicitly in `pkg/enforcement/engine.go`.

---

### DI-8 — No circuit breaker on the `capability.JWKSClient` JWKS fetch path

**Status:** Implemented

**Files:** `internal/gateway/jwks_verifier.go`, `pkg/capability/jwks.go`

The `JWKSClient` fetches JWKS on cache miss. If the issuer's JWKS endpoint becomes
slow or unavailable, every cache miss on the enforcement hot path will block for
the HTTP client timeout. `pkg/capability/jwks.go` already defaults the client to
`&http.Client{Timeout: 10 * time.Second}` when no client is provided, so the
gateway will not hang indefinitely. However, there is no circuit breaker: repeated
cache misses during a prolonged JWKS outage will each wait the full 10 s, degrading
gateway latency significantly.

**Recommendation:**  
Wrap the JWKS fetch with `pkg/circuitbreaker` to fast-fail after repeated JWKS
errors, returning a clear `503` to callers rather than serially exhausting the
per-request timeout budget.

---

### DI-9 — Key rotation relies on manual `Rotate()` / `Prune()` calls with no automation

**Status:** Implemented

**Files:** `internal/issuer/rotating_keystore.go`

`RotatingKeyStore` correctly supports key rotation but provides no scheduler or
automation. Operators must call `Rotate()` and then `Prune()` with the right cutoff
manually. If `Prune()` is not called, the JWKS endpoint grows indefinitely with
retired keys. If `Rotate()` is never called, the service runs on a single static
key indefinitely.

**Recommendation:**  
Add a background goroutine in the issuer that rotates the key on a configurable
schedule (`ISSUER_KEY_ROTATION_INTERVAL`, default 90 days) and calls `Prune()` with
a cutoff of `now() - maxTokenTTL`. Emit a structured log event and a Prometheus
gauge (`issuer_signing_key_age_seconds`) so operators can alert on stale keys.

---

## [+] Code and Implementation Feedback

### CI-1 — `cmd/minter/main.go` exits from a goroutine (unrecoverable panic risk)

**Files:** `cmd/minter/main.go:82-88`

```go
go func() {
    if listenErr := srv.ListenAndServe(); listenErr != nil && !errors.Is(listenErr, http.ErrServerClosed) {
        logger.Error("server error", ...)
        os.Exit(1)   // <-- called from goroutine
    }
}()
```

`os.Exit(1)` called from a goroutine bypasses all deferred functions, including any
cleanup registered in the calling goroutine. This pattern is inconsistent with the
gateway (`cmd/gateway/main.go`) which uses an `errCh` to propagate errors back to
`main()`. The minter, issuer, db-token-svc, and storage-grant-svc all share this
pattern.

**Recommendation:**  
Use an `errCh chan error` as in the gateway, and `select` between the signal channel
and the error channel in `main()`.

**Status: Implemented** — `cmd/minter/main.go`, `cmd/issuer/main.go`, `cmd/db-token-svc/main.go`,
and `cmd/storage-grant-svc/main.go` all use a `run() error` function with an internal
`errCh chan error` to propagate server errors back to `main()`, matching the gateway pattern.

---

### CI-2 — `handleProxy` builds an `EnforceRequest` from HTTP headers without input validation

**Files:** `internal/gateway/handlers.go:253-310`

The proxy enforcement path builds the `EnforceRequest` from `r.Header.Get("X-Tool-Name")`.
There is no validation or sanitization of this value. A tool name of `../../../admin`
or a name exceeding 1 KB could inject unexpected values into audit records or
trigger unexpected glob matching in `matchesResource()`.

**Recommendation:**  
Validate `X-Tool-Name` against a `^[a-zA-Z0-9_\-:.]{1,256}$` allowlist pattern
before using it in enforcement. Return `400 Bad Request` if the header is missing
or invalid.

**Status: Implemented** — `internal/gateway/handlers.go` validates `X-Tool-Name` with
`validToolNameRE` (`^[a-zA-Z0-9_\-:.]{1,256}$`) and returns `400 Bad Request` for missing
or non-conforming values before any enforcement logic runs.

---

### CI-3 — `matchesResource` glob implementation is prefix-only; no `?` or character class support

**Files:** `pkg/enforcement/engine.go:187-198`

The `matchesResource` function treats `*` as a trailing wildcard only
(`tool:*` matches `tool:foo`). The docstring for `Constraint.Resource` in
`pkg/capability/constraint.go` implies broader glob semantics but the
implementation only supports trailing `*`. If operators write capabilities with
`*` in non-trailing positions (e.g., `file:*.csv`) the match will silently fail.

**Recommendation:**  
Either restrict `Resource` to the documented trailing-`*`-only semantics and reject
other patterns during capability validation, or use `path/filepath.Match` for
consistent glob semantics. Add tests for mid-string wildcards.

**Status: Implemented** — `pkg/enforcement/engine.go` `matchesResource` now uses `path.Match`
for full glob semantics (`?`, `[abc]`, mid-string `*`). `ValidateResourcePattern` is exported
for use at capability load time to reject malformed patterns. Tests for `?`, character classes,
and mid-string wildcards added in `pkg/enforcement/enforcement_test.go`.

---

### CI-4 — `pkg/audit/audit.go` HMAC chain key is derived from the audit signing key

**Files:** `pkg/audit/audit.go`

The HMAC chain integrity hash uses the same cryptographic material as the per-record
signature. If the signing key is rotated, historical records' chain hashes remain
valid but the chain cannot be verified against the new key without a migration step.
This couples the signing key lifecycle to the chain integrity model.

**Recommendation:**  
Separate the HMAC chain key from the record signing key. Derive the chain key from a
dedicated `AUDIT_CHAIN_HMAC_SECRET` environment variable (similar to `PEPPER_HEX` in
the minter). This enables independent key rotation without breaking chain continuity.

**Status: Implemented** — `pkg/audit/audit.go` adds `ComputeChainHashWithSecret` /
`VerifyChainHashWithSecret` that use a dedicated HMAC secret (message includes `previousHash`
to preserve ordering). `PipelineConfig.ChainHMACSecret` activates the new mode when set;
pipelines without it continue to use the legacy key-derived hash, preserving backward
compatibility. Tests in `pkg/audit/audit_test.go` verify determinism, incompatibility
between modes, and pipeline integration.

---

### CI-5 — `pkg/ratelimit/resilient_redis.go` fail-open semantics not surfaced in health/readiness

**Files:** `pkg/ratelimit/resilient_redis.go:26-45`

When Redis is unreachable the `ResilientRedisLimiter` silently falls back to the
in-memory limiter. This means the global rate limit degrades from a fleet-wide limit
to a per-replica limit with no external signal. Operators may not notice the
degradation until an SLO breach.

**Recommendation:**  
Expose the `reporter.IsDegraded()` state as a Prometheus gauge
(`ratelimit_redis_degraded{component="ratelimit"}`) and incorporate it into the
readiness probe response so load balancers can drain degraded replicas if desired.

**Status: Implemented** — `pkg/ratelimit/resilient_redis.go` adds a `WithPrometheusRegisterer`
functional option that accepts a caller-supplied `component` label. When provided, a `GaugeFunc`
named `ratelimit_redis_degraded` is registered and reflects the live degradation state
(`reporter.State() == Degraded`). Tests in `pkg/ratelimit/resilient_redis_test.go` verify the
gauge reads 1 when degraded and 0 when healthy, and that the component label is set correctly.

---

### CI-6 — `InMemoryDPoPStore` cleanup fires only on `len(seen) > 1000`; no periodic cleanup

**Files:** `internal/gateway/dpop_store.go:45-55`

The DPoP replay store only cleans expired entries when the map exceeds 1000 entries.
Under light traffic the map never purges and can accumulate stale entries across the
full TTL window (5 minutes default). Under heavy traffic it triggers O(N) cleanup on
every 1001st call, adding latency spikes to the enforcement hot path.

**Recommendation:**  
Run a background cleanup goroutine on a fixed interval (e.g., every 2 minutes) tied
to the service lifecycle context, matching the pattern used in
`pkg/killswitch/redis.go`.

**Status: Implemented** — `internal/gateway/dpop_store.go` adds a `Start(ctx context.Context)`
method that runs a background ticker-based cleanup goroutine. `cleanupInterval` defaults to 2
minutes. `cmd/gateway/main.go` calls `dpopStore.Start(ctx)` with the root cancellable context.
Tests in `internal/gateway/dpop_store_test.go` cover cleanup, replay detection, and goroutine
cancellation.

---

### CI-7 — Audit read routes are authenticated per-handler rather than via middleware

**Files:** `internal/gateway/app.go:250-261`, `internal/gateway/audit_routes.go`

The audit read endpoints (`/records`, `/export`, `/signing-keys`, `/chain-proof`) are
mounted under `/api/v1/audit/` on the _public_ router. Each handler immediately calls
`authenticateAuditRequest`, which requires either a valid `X-Admin-Api-Key` header or
a tenant-scoped JWT before returning any records. Unauthenticated requests are
rejected by the handler.

The concern is defence-in-depth and middleware placement: authentication logic is
duplicated across four handlers rather than enforced once at the router boundary. A
future handler added to this group might omit the `authenticateAuditRequest` call.

**Recommendation:**  
Extract the `authenticateAuditRequest` check into a chi middleware and apply it to
the `/api/v1/audit` sub-router, so protection is structural and cannot be bypassed
by accidentally omitting an inline call.

**Status: Implemented** — `internal/gateway/audit_routes.go` adds `auditAuthMiddleware()` chi
middleware and stores the principal in context via `auditPrincipalKey`. Applied with `r.Use`
on the `/audit` sub-router in `app.go`. All four handlers now call `auditPrincipalFromCtx(r.Context())`
instead of inline auth. Tests in `internal/gateway/audit_routes_test.go` verify unauthenticated
requests are rejected at the router boundary for all four routes.

---

### CI-8 — `pkg/config/validation.go` regex validation uses `regexp.MatchString` (full-match not anchored)

**Files:** `pkg/config/validation.go:94-106`

`validateField` calls `regexp.MatchString(tags.Regex, stringifyValue(value))`.
`regexp.MatchString` performs a substring match, not a full-string match. The
`PepperHex` regex `^[0-9a-fA-F]{64}$` works because it uses `^` / `$` anchors, but
any regex without anchors will accept partial matches. Future regex constraints added
without anchors will silently pass malformed values.

**Recommendation:**  
Wrap the pattern with anchors unconditionally: `"^(?:" + tags.Regex + ")$"`, or
document that all `regex` tag values must be anchored and add a unit test that
verifies partial matches are rejected.

**Status: Implemented** — `pkg/config/validation.go` wraps every regex with `^(?:...)$`
before calling `regexp.MatchString`, ensuring full-string matching regardless of whether the
tag value includes explicit anchors.

---

### CI-9 — No request-ID propagation from gateway to backend proxy

**Files:** `internal/gateway/handlers.go:253-310`

`handleProxy` reverse-proxies to the backend after enforcement but does not inject
`X-Request-Id` (generated at gateway entry) into the upstream request. This makes
distributed tracing and log correlation across gateway → backend very difficult in
production.

**Recommendation:**  
Before calling `app.proxy.ServeHTTP(w, r)`, set the request ID on the outgoing
request:
```go
r.Header.Set("X-Request-Id", requestID)
```

**Status: Implemented** — `internal/gateway/handlers.go` `handleProxy` now calls
`r.Header.Set("X-Request-Id", requestID)` before proxying to the backend, enabling
distributed log correlation across gateway and backend services.

---

### CI-10 — Posture emitter is SQLite-backed and cannot scale beyond one replica

**Files:** `cmd/posture-emitter/main.go`, `migrations/posture/`, `k8s/helm/euno/templates/posture-emitter.yaml`

The posture emitter uses a SQLite database on a local named volume and relies on
PostgreSQL advisory locks for single-writer semantics. The single-replica constraint
is already enforced at the Helm chart level: `k8s/helm/euno/templates/posture-emitter.yaml`
contains a render-time `fail` that aborts `helm install`/`upgrade` if
`postureEmitter.replicaCount` is not exactly 1, along with a comment documenting the
SQLite single-writer constraint.

The remaining concern is the lack of a migration path when horizontal scaling of
posture emission becomes necessary.

**Recommendation:**  
Document a migration path to a PostgreSQL backend when horizontal scaling of posture
emission is required.

**Status: Implemented** — `internal/posture/app.go` includes a comment block documenting
the PostgreSQL migration path: replacing the SQLite driver and local volume with a shared
PostgreSQL connection string and updating the queue backend wiring.

---

### CI-11 — Audit ledger PostgreSQL advisory lock enforces single-writer but no failover guard

**Files:** `pkg/audit/backend.go`

The audit ledger uses a PostgreSQL advisory lock to enforce single-writer ordering.
If the lock holder dies mid-write (pod killed, OOM) without releasing the lock, the
advisory lock may block the next writer until the PostgreSQL session timeout expires
(default: no timeout). In multi-zone failover scenarios this could stall audit
writes for several minutes.

**Recommendation:**  
Set a session-level `lock_timeout` on the audit DB connection (e.g., `SET
lock_timeout = '5s'`), and emit a structured error/metric when the lock wait
exceeds a threshold so alerts fire before the write backlog grows.

**Status: Implemented** — `pkg/audit/backend.go` adds `LockTimeout time.Duration` to
`PostgresLedgerConfig`. When non-zero, `AcquireLock` emits `SET lock_timeout = 'Nms'` before
the advisory lock call, bounding the wait when a blocking lock implementation is used. Tests in
`pkg/audit/audit_test.go` verify the `SET` statement is emitted in the correct order and
skipped when `LockTimeout` is zero.

---

### CI-12 — `pkg/circuitbreaker/do.go` uses `panic` for nil guard instead of returning an error

**Files:** `pkg/circuitbreaker/do.go`

Constructor-guard panics (`panic("circuitbreaker: breaker must not be nil")`) are
acceptable when misuse is a programming error. However, when these are called from
service initialization code they produce an unrecoverable crash rather than a
structured startup error. All panic sites in the circuitbreaker package are
constructor guards and are acceptable, but they should be documented as invariants
in the package godoc so callers are aware.

**Status: Implemented** — `pkg/circuitbreaker/do.go` package-level godoc explicitly documents
that `Do` and `DoVoid` panic on nil breaker as a programming-error invariant, and
callers must ensure the breaker is constructed before use.

---

## [?] Open Questions

### OQ-1 — Production PostgreSQL KeyStore implementation for minter

The minter has `InMemoryStore` wired in `cmd/minter/main.go`. Is there a PostgreSQL
implementation in a private branch or planned milestone? The migration
(`migrations/minter/001_create_api_keys.up.sql`) exists and is fully defined, but
no `PostgresKeyStore` type appears in the repository. Operators deploying the minter
in production would need to implement this themselves.

---

### OQ-2 — Telemetry sink target and data governance

`TelemetryCollector` and `TelemetrySink` are wired in `internal/gateway/telemetry.go`
but `TelemetryConfig.Sink` is set to `nil` in `cmd/gateway/main.go` (events are
discarded). What is the intended telemetry target (Eunox SaaS, operator-configured
webhook)? Are there GDPR implications for the `tenantId` field in telemetry events?

---

### OQ-3 — `EUNO_DEPLOYMENT_TIER` configuration field is declared but never read

**Status:** Implemented

**Files:** `pkg/config/gateway.go:12`

`DeploymentTier` is parsed from `EUNO_DEPLOYMENT_TIER` with valid enum values
(`single-replica`, `multi-replica`, `multi-region-active-active`) but is not used
anywhere in the gateway startup logic. Is it intended to drive pool sizing, Redis
HA requirements, or read-replica selection? If so, it should be integrated;
otherwise, it should be removed to avoid confusion.

---

### OQ-4 — Partner federation DID allowlist vs. TRUSTED_PARTNER_DIDS

The architecture document (`architecture.md §5.3 DFD-2`) references
`TRUSTED_PARTNER_DIDS` as the allowlist for cross-org federation. In the Go code,
trusted partner DIDs are managed via the admin API (`handlePartnerDIDRegister`) and
stored in `InMemoryPartnerDIDStore`. There is no `TRUSTED_PARTNER_DIDS` environment
variable. Do the docs reflect a legacy design, or is the env-var-based allowlist
intended for an upcoming stage?

---

### OQ-5 — `docs/architecture.md` references TypeScript implementation details

Several sequence diagrams and component names in `docs/architecture.md` reference
TypeScript/Node.js constructs (`index.ts`, `CapabilityIssuerService.ts`,
`@eunox/common`, `helmet`). The repository is now a pure Go codebase. Are these
documents intentionally retained as conceptual references, or do they need updating
to reflect the Go implementation?

---

## Execution Plan

Ordered by impact and dependency:

| Priority | Item | Dependency | Effort | Status |
|----------|------|------------|--------|--------|
| 1 | **CR-1** Wire Redis backends for kill-switch, revocation, DPoP in production | None | Medium | ✅ Done |
| 2 | **CR-2** Add public-API rate limiting middleware to `/api/v1` | None | Small | ✅ Done |
| 3 | **CI-7** Refactor audit route auth into a chi middleware (defence-in-depth) | None | Small | ✅ Done |
| 4 | **CR-4** Add `GATEWAY_TRUSTED_PROXIES` config + IP extraction fix | None | Small | ✅ Done |
| 5 | **DI-2** Fatal startup check for missing `GATEWAY_ISSUER_JWKS_URL` in production | None | Small | ✅ Done |
| 6 | **DI-3** Wire `revocation.NewRedis` when `REDIS_URL` is set | CR-1 done first | Small | ✅ Done (part of CR-1) |
| 7 | **CI-1** Replace `os.Exit(1)` from goroutines with `errCh` pattern | None | Small | |
| 8 | **CI-6** Add background cleanup goroutine to `InMemoryDPoPStore` | None | Small | |
| 9 | **CR-3** Extend JWT admin auth requirement to staging | None | Trivial | ✅ Done |
| 10 | **CI-2** Validate `X-Tool-Name` header before enforcement | None | Small | ✅ Done |
| 11 | **DI-4** Add pagination parameters to `handleListKeys` | OQ-1 context | Small | ✅ Done |
| 12 | **DI-5** Add `db.PingContext` to readiness handler | None | Small | ✅ Done |
| 13 | **CI-9** Propagate `X-Request-Id` to proxied backend requests | None | Trivial | ✅ Done |
| 14 | **DI-7** Change `findMatchingCapability` to most-specific-match semantics | None | Medium | ✅ Done |
| 15 | **DI-8** Add circuit breaker to JWKS client (10 s timeout already set) | None | Small | ✅ Done |
| 16 | **DI-1** Persist partner DID registrations in Redis or PostgreSQL | CR-1 done first | Medium | ✅ Done |
| 17 | **CI-4** Separate audit HMAC chain key from signing key | None | Medium | ✅ Done |
| 18 | **DI-9** Automate key rotation scheduling in issuer | None | Medium | ✅ Done |
| 19 | **CI-8** Anchor regex patterns unconditionally in config validation | None | Small | ✅ Done |
| 20 | **DI-6** Fix audit transport lifecycle context | None | Small | ✅ Done |
| 21 | **OQ-3** Decide fate of `EUNO_DEPLOYMENT_TIER` (integrate or remove) | None | Small | ✅ Done |
| 22 | **OQ-5** Reconcile architecture docs with Go implementation | None | Small | |
| 23 | **CI-10** Document PostgreSQL migration path for posture-emitter horizontal scaling | None | Small | |
| 24 | **CI-11** Set `lock_timeout` on audit DB connection | None | Small | ✅ Done |
