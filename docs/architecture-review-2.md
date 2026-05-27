# Architecture Review — Cycle 2

**Reviewer:** Principal Software Architect  
**Review date:** 2026-05-27  
**Repository:** github.com/edgeobs/eunox  
**Scope:** Full codebase (Go services, shared packages, migrations, deployment assets)

---

## Executive Summary

This review covers the current state of the eunox Go monorepo following the complete resolution of all 28 findings raised in the previous cycle (`docs/architecture-review.md`). The system has matured significantly: the enforcement engine is default-deny with most-specific-match semantics, Redis HA is enforced in production, admin JWT auth is required through staging, XFF spoofing is mitigated, and HMAC chain integrity is in place for the audit ledger. The design is architecturally sound for a v1 production deployment.

This cycle identifies **2 unresolved security/reliability risks**, **4 design improvements**, **6 code-level findings**, and **3 open questions** that are relevant to production hardening and horizontal scaling.

---

## [!] Critical Risks

### CR-1 — DPoP JTI Store Is Per-Replica In-Memory with No Enforcement Path to Redis

**Severity:** High  
**Location:** `internal/gateway/app.go` (DPoP store initialization), `cmd/gateway/main.go` (bootstrap)

The Demonstrating Proof of Possession (DPoP) replay prevention store is constructed as an in-memory map. No Redis-backed implementation exists. A production log warning is emitted, but startup is not blocked.

In a multi-replica gateway deployment a DPoP proof captured from a first request can be replayed to any *other* replica within the jti TTL window, completely defeating the binding guarantee. DPoP is listed in the architecture as a first-class security primitive; without a shared replay store it provides no security in the only production topology (≥2 replicas).

**Required action:**  
Implement `ResilientRedisDPoPStore` (analogous to `ResilientRedisKillSwitch`) and block gateway startup when `EUNOX_DEPLOYMENT_TIER` indicates a multi-replica tier and the DPoP store is in-memory — identical to the treatment of `validateRedisConfig` for revocation and kill-switch.

---

### CR-2 — Public Enforcement Rate Limiter Is Per-Replica In-Memory

**Severity:** High  
**Location:** `internal/gateway/app.go` (publicRateLimiter wiring)

The per-IP rate limiter protecting `POST /api/v1/enforce` is constructed with `ratelimit.NewInMemory(...)`. Rate-limit counters are not shared across replicas. Under a horizontal autoscaling deployment with *N* replicas, the effective throughput allowed per IP is *N × configured_limit*.

An adversary can exploit this by distributing requests across all replicas through round-robin or by exploiting predictable load-balancer affinity, completely defeating the denial-of-service protection on the hottest enforcement path.

**Required action:**  
Wire `ResilientRedisLimiter` (already implemented in `pkg/ratelimit/redis.go`) for the public enforcement limiter, mirroring how the call-counter rate limiter uses Redis. Fail closed to `InMemoryLimiter` only for the `development` deployment tier.

---

## [~] Design Improvements

### DI-1 — `handleValidate` Uses a Different Match Algorithm Than the Enforcement Engine

**Location:** `internal/gateway/handlers.go:233–261`, `pkg/enforcement/engine.go`

`POST /api/v1/validate` implements a linear first-match scan with exact equality on `Resource` (only `"*"` is treated as a wildcard). The enforcement engine's `findMatchingCapability` uses `path.Match` glob semantics and a resource × action specificity score to select the *most specific* matching capability.

A token whose capabilities express a wildcard pattern such as `tools/*` is matched correctly by the enforcement engine but is rejected by `handleValidate` unless the exact resource is `"*"`. Callers using `/validate` as a pre-flight check before `/enforce` receive inconsistently optimistic denials. This is a semantic contract violation between two sibling endpoints.

**Recommended change:**  
Route `handleValidate` through `enforcement.Engine.ValidateAction` so both endpoints share identical matching semantics. The validation endpoint can omit the Redis side-effects (kill-switch, revocation, call-counter) while retaining full capability-matching logic.

---

### DI-2 — DID Cache Has No Stale-on-Error Behaviour

**Location:** `pkg/did/resolver.go:127–158`

`CachingResolver.Resolve` always delegates to the upstream resolver on a cache miss or expiry. If the upstream DID endpoint is temporarily unavailable (network partition, provider outage), the resolver returns an error immediately — there is no grace period in which a recently expired entry is served as a stale result.

With the default 5-minute TTL, a DID endpoint outage of any duration causes all gateway requests carrying partner tokens to fail with HTTP 500 for up to 5 minutes after the last successful resolution. Given that partner DID documents change infrequently, serving the most recent valid document for a short grace window is a significant reliability improvement.

**Recommended change:**  
Add a separate `staleWindow` to `cacheEntry` (e.g. an extra 5 minutes beyond `ttl`) during which the cached document is served on upstream error, and a `fetchedAt` vs `expiresAt` distinction. This pattern is already used by the FallbackCache in `pkg/redisfailover/failover.go`.

---

### DI-3 — `IdempotencyStore` Has No Background Cleanup

**Location:** `internal/gateway/admin.go` (IdempotencyStore)

Expired entries are evicted only as a side-effect of the `Set()` call: a full O(N) map scan runs on every idempotent admin mutation. There is no background goroutine or ticker performing periodic cleanup.

The DPoP JTI store, the kill-switch monitor, and the rate limiter all use background tickers for eviction. Relying on `Set()` to trigger cleanup means that if admin mutation rates are low, entries accumulate; if rates are high, the O(N) scan adds latency to every request on the admin hot path.

**Recommended change:**  
Add a `cleanupInterval` field and a `startCleanup(ctx)` goroutine (using `time.NewTicker`) started at `App.New()`, consistent with the pattern in `pkg/ratelimit/memory.go`.

---

### DI-4 — PostgreSQL Driver Is `lib/pq` Instead of `pgx`

**Location:** `go.mod`, `internal/minter/store.go`, `migrations/`

The system uses the `lib/pq` PostgreSQL driver. It does not support prepared statement caching, provides no connection pool metrics (no `pgxpool.Stat` equivalent), and does not expose `pgconn`-level error codes for conditional retry logic. The `pgx/v5` driver is the community successor, and its stdlib compatibility layer (`pgx/v5/stdlib`) requires no changes to existing `database/sql` code.

Missing pool metrics means the system has no visibility into connection exhaustion under load — a common failure mode for services with many replicas connecting to a managed PostgreSQL instance with a fixed `max_connections`.

**Recommended change:**  
Replace `lib/pq` with `github.com/jackc/pgx/v5/stdlib` and expose `pgxpool.Stat()` fields (`TotalConns`, `IdleConns`, `AcquireCount`) as Prometheus gauges in the `observability.MetricsRegistry`.

---

## [+] Code / Implementation Feedback

### CI-1 — `handleValidate` Does Not Check Revocation or Kill-Switch

**Location:** `internal/gateway/handlers.go:203–262`

The `/api/v1/validate` endpoint verifies the JWT signature and checks capability coverage, but does not consult the revocation store or kill-switch. A token that has been revoked at the Redis level, or an API key whose kill-switch has been activated, is still returned as `allowed: true` by this endpoint.

Callers that use `/validate` to gate decisions without subsequently calling `/enforce` will bypass all runtime revocation. The endpoint's doc comment should be explicit about this limitation, and if the endpoint is intended for security-critical pre-flight checks, revocation and kill-switch checks must be added.

---

### CI-2 — `handleListKeys` Pagination Total Is Non-Atomic

**Location:** `internal/minter/app.go:342–403`

`handleListKeys` issues two sequential queries: `CountKeys` to obtain the total, then `ListKeys` for the page. These are not wrapped in a transaction. Between the two calls, concurrent key creation or revocation can change the actual count, causing the `total` field in the response to be stale.

This creates a confusing UX: the caller may paginate to the expected final offset and find either more or fewer keys than `total` indicated. For a system managing access credentials this inconsistency may trigger incorrect automation logic in operator tooling.

**Recommended change:**  
Execute `CountKeys` and `ListKeys` inside a single read-committed transaction, or implement a cursor-based pagination scheme that avoids the need for a total count.

---

### CI-3 — Minter `handlePing` Rate Limiter Ignores Trusted Proxy Headers

**Location:** `internal/minter/app.go` (`extractClientIP`)

The minter's `extractClientIP` function reads only `r.RemoteAddr`. When the minter is deployed behind a load balancer (the standard production topology), every client request arrives from the same load-balancer IP address. The per-IP rate limiter on `GET /api/v1/ping` will therefore count all clients against a single shared bucket, causing legitimate clients to be rate-limited whenever any single client abuses the endpoint.

**Recommended change:**  
Accept a `trustedProxyCIDRs []net.IPNet` field in the minter `Config` (mirroring the gateway's `TrustedProxyCIDRs`) and apply trusted-proxy XFF extraction in `extractClientIP`, consistent with `internal/gateway/handlers.go:extractClientIP`.

---

### CI-4 — No `Retry-After` Header on 429 Responses

**Location:** `pkg/ratelimit/`, `internal/gateway/app.go` (rate limit middleware)

Responses with HTTP 429 (Too Many Requests) do not include a `Retry-After` header. RFC 6585 §4 requires this header to allow clients and intermediaries to back off correctly. Without it, clients typically resort to fixed-interval polling that can cause thundering-herd behaviour when all rate-limited clients retry simultaneously.

**Recommended change:**  
Have the rate-limit middleware set `Retry-After: <seconds>` equal to the `window` duration from the limiter's `Config`. The `Limiter` interface can be extended with a `WindowSeconds() int` method, or the middleware can read the config it was constructed with.

---

### CI-5 — `testcontainers-go` Is in the Production Module

**Location:** `go.mod`

`github.com/testcontainers/testcontainers-go` is listed as a direct dependency in the root `go.mod`. This library embeds a Docker client, Moby networking code, and container lifecycle management — none of which belongs in a production binary. It inflates the binary size, increases the attack surface, and can cause unexpected behaviour if a Docker socket is inadvertently accessible at runtime.

**Recommended change:**  
Move integration-test dependencies into a separate `go.mod` under `tests/` or `integration/`, or use a `//go:build integration` build tag to isolate them from the production dependency graph.

---

### CI-6 — `CachingResolver.Resolve` Has a Redundant-Fetch Race

**Location:** `pkg/did/resolver.go:127–158`

The resolver checks the cache under `RLock`, releases the lock, fetches from upstream, then re-acquires `Lock` to store the result. Between the `RUnlock` and the `Lock`, another goroutine can begin and complete an identical upstream fetch. Under burst traffic where many goroutines concurrently request the same DID for the first time, every goroutine issues a separate HTTP call to the DID endpoint.

**Recommended change:**  
Use a `sync.Map` of `singleflight.Group` keys (or `golang.org/x/sync/singleflight`) to deduplicate concurrent fetches for the same DID, ensuring at most one in-flight resolution per DID at any time.

---

## [?] Open Questions

### OQ-1 — Multi-Issuer Co-Signature (`TokenPayload.Proofs`) Verification

**Location:** `pkg/capability/token.go` (`Proofs` / `IssuanceProofs`), `internal/gateway/partner_verifier.go`

`TokenPayload` carries a `Proofs.Signatures` field described in the architecture as multi-issuer co-signatures for cross-org delegation. No code in the enforcement path or in `PartnerTokenVerifier.VerifyPartnerToken` visibly verifies these signatures. If this field is intended as a security primitive (e.g., a quorum of issuers must co-sign before a token is valid), the verification must be present in the enforcement hot path. If it is metadata only, the field-level doc comment should say so explicitly to prevent future implementers from assuming it is enforced.

---

### OQ-2 — Operator-Configurable OTLP / Distributed Tracing Endpoint

The observability layer emits Prometheus metrics and structured logs. There is no visible configuration path for an operator to supply an OTLP endpoint (`OTEL_EXPORTER_OTLP_ENDPOINT` or equivalent) and enable distributed traces across the gateway → issuer → minter → audit chain. Without distributed tracing, diagnosing latency anomalies across service boundaries requires correlating structured log streams by `X-Request-Id`, which is operationally expensive. The deployment guide (`docs/DEPLOYMENT.md`) should document whether OTLP is planned and what environment variables control it.

---

### OQ-3 — `posture-emitter` SQLite Single-Replica Constraint

**Location:** `go.mod` (`modernc.org/sqlite`), `internal/posture/`

The posture-emitter uses SQLite as its persistence layer, which is suitable for single-node development but incompatible with any multi-replica deployment. If the posture-emitter is intended to scale horizontally (e.g., one instance per cluster node emitting host-level posture signals), each replica would operate an isolated SQLite database with no cross-replica aggregation. The architecture should clarify whether the posture-emitter is a singleton sidecar or a replicated service, and if the latter, what the migration path to a shared store (PostgreSQL or Redis) is.

---

## Execution Plan

The findings are ordered by risk impact and dependency. Items marked ⚡ should be addressed before the next production release; items marked 🔧 are improvements for the next sprint.

| Priority | ID | Description | Effort |
|---|---|---|---|
| ⚡ 1 | CR-1 | Implement `RedisDPoPStore`; block startup on multi-replica tier | M |
| ⚡ 2 | CR-2 | Wire `ResilientRedisLimiter` for the public enforcement rate limiter | S |
| ⚡ 3 | CI-1 | Document or add revocation/kill-switch checks to `/api/v1/validate` | S |
| 🔧 4 | DI-1 | Route `handleValidate` through `enforcement.Engine.ValidateAction` | M |
| 🔧 5 | CI-2 | Wrap `CountKeys` + `ListKeys` in a transaction (or adopt cursor pagination) | S |
| 🔧 6 | CI-3 | Add trusted-proxy XFF extraction to minter `extractClientIP` | S |
| 🔧 7 | CI-4 | Emit `Retry-After` header on all 429 responses | S |
| 🔧 8 | DI-2 | Add stale-on-error window to `CachingResolver` | M |
| 🔧 9 | DI-3 | Replace `Set()` piggybacked cleanup with a background ticker in `IdempotencyStore` | S |
| 🔧 10 | CI-6 | Use `singleflight` in `CachingResolver.Resolve` to deduplicate concurrent DID fetches | S |
| 🔧 11 | DI-4 | Migrate from `lib/pq` to `pgx/v5/stdlib`; expose pool metrics | M |
| 🔧 12 | CI-5 | Move `testcontainers-go` to a separate test module | S |
| 📋 13 | OQ-1 | Clarify `Proofs.Signatures` enforcement contract; add verification if required | L |
| 📋 14 | OQ-2 | Define OTLP configuration interface; document in `DEPLOYMENT.md` | M |
| 📋 15 | OQ-3 | Document posture-emitter scaling model; define path to shared store | S |

**Effort key:** S = 1–2 days, M = 3–5 days, L = 1+ week

---

## Prior Review Status

All 28 findings from the first review cycle are confirmed resolved (see `docs/architecture-review.md`):

- **CR-1–CR-5:** In-memory → Redis for kill-switch, revocation, and call-counter; rate limiting on public API; JWT admin auth to staging; XFF trusted-proxy enforcement; atomic `RevokeKey` ✅
- **DI-1–DI-9:** Fail-closed Redis fail policies; deployment-tier configuration; per-route rate limiting; most-specific-match enforcement; admin idempotency store; CORS hardening; ChainHMACSecret separation; DPoP integration; partner federation circuit breaker ✅
- **CI-1–CI-12:** All code-level fixes implemented ✅
- **OQ-1–OQ-4:** All open questions resolved ✅
- **OQ-5:** Documentation reconciliation (PR #298) 🔄 in progress
