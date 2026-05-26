# Formal Technical Architecture Review

**Repository:** `edgeobs/eunox`  
**Reviewer Role:** Principal Software Architect  
**Date:** 2026-05-26  
**Commit:** `81563305` (HEAD of `copilot/technical-review-system-architecture`)  
**Scope:** Full system architecture, design documents, and implementation code

---

## Executive Summary

eunox is a Go monorepo implementing a capability-based zero-trust governance system for AI agents. The system enforces fine-grained access control via JWT capability tokens with conditions, maintains cryptographic audit trails, and supports pluggable identity/signing backends across AWS, Azure, and GCP.

The architecture demonstrates strong engineering discipline: interface-driven dependency injection, comprehensive documentation (34+ docs, ~500 KB), production-grade observability (slog/Prometheus/OpenTelemetry), and a healthy test-to-source ratio (89 test files / 150 source files = 59%). Prior review items (Phases 1–4) have been addressed and verified.

**Overall Rating: 8.5/10** — Production-ready with identified hardening opportunities below.

---

## [!] Critical Risks

### CR-1: Remaining `context.Background()` in Agent Runtime Hot Path

**Severity:** High  
**Location:** `internal/agentruntime/httpclient.go:38`  
**Impact:** Reliability & Observability

```go
reqCtx := req.Context
if reqCtx == nil {
    reqCtx = context.Background()  // Fallback silently drops tracing/cancellation
}
```

While this is a defensive nil-guard, it means any caller that forgets to set `req.Context` will silently lose request-scoped cancellation, timeout inheritance, and distributed tracing linkage. In high-concurrency agent runtime scenarios, stale HTTP requests will accumulate during upstream failures.

**Recommendation:**
- Require `Context` as a non-nil parameter at the API boundary (reject calls with nil context)
- Add a `contextcheck` linter to `.golangci.yml` to prevent regressions
- Log a warning when the fallback triggers (to surface misconfigured callers)

---

### CR-2: Posture Emitter SQLite Single-Connection Under Delivery Pressure

**Severity:** High  
**Location:** `internal/posture/queue.go:66-69`, `internal/posture/delivery.go:94`  
**Impact:** Reliability & Data Integrity

```go
db.SetMaxOpenConns(1)
db.SetMaxIdleConns(1)
```

The posture queue uses SQLite with a single connection and an exclusive lock (`_locking_mode=EXCLUSIVE`). The delivery worker already implements per-plugin timeouts via `context.WithTimeout` (`DefaultPluginTimeout = 5s`), exponential backoff, dead-letter semantics (`posture_dead_letter` table), and Prometheus metrics (`posture_queue_depth`, `posture_delivery_errors_total`). The remaining throughput bottleneck is the single-connection, single-writer design itself:

- All queue operations (Push, Peek, Nack, Ack, DeadLetter) serialize through a `sync.Mutex`-guarded connection
- Under sustained burst, enqueuing callers contend for the same lock as the delivery worker's write operations, causing latency spikes rather than immediate back-pressure
- The exclusive-lock mode prevents any concurrent readers, even for diagnostic queries

**Recommendation:**
- Document SQLite limitations and recommend PostgreSQL for high-volume posture deployments (>100 events/s)
- Evaluate whether the exclusive-lock constraint can be relaxed by splitting the read (Peek) path to a separate read-only connection under WAL mode

---

### CR-3: Token Provider Background Refresh Has No Circuit Breaker

**Severity:** Medium-High  
**Location:** `internal/agentruntime/token_provider.go:67`  
**Impact:** Reliability

The `AuthTokenProvider` creates a lifecycle context for background token refresh but lacks:
- Circuit breaker protection against failing token endpoints
- Jitter on refresh intervals (thundering herd on restart)
- Graceful degradation (serve stale token if refresh fails within window)

**Recommendation:**
- Wrap token refresh in `pkg/circuitbreaker.Do()` (already available in the codebase)
- Add jitter: `refreshInterval + rand(0, 10%)` to prevent synchronized refreshes
- Implement stale-token grace period: continue serving last-known-good token for `N` seconds after refresh failure
- Emit metric: `agentruntime_token_refresh_failures_total`

---

## [~] Design Improvements

### DI-1: PostgreSQL Connection Pool Not Explicitly Configured

**Location:** Database connection paths (audit ledger, minter store)  
**Impact:** Scalability & Reliability

No explicit `SetMaxOpenConns()`, `SetMaxIdleConns()`, or `SetConnMaxLifetime()` configuration found for PostgreSQL connections. The default Go `database/sql` pool (`maxIdleConns=2`, `maxOpenConns=0` i.e. unlimited) is unsuitable for production:
- Unlimited connections can exhaust PostgreSQL's `max_connections` (default: 100)
- Idle connections are not recycled, leading to stale connections after network partitions
- No connection lifetime limit means connections survive past PgBouncer timeouts

**Recommendation:**
- Add pool configuration to `pkg/config` structs: `DB_MAX_OPEN_CONNS` (default: 25), `DB_MAX_IDLE_CONNS` (default: 5), `DB_CONN_MAX_LIFETIME` (default: 5m)
- Document recommended settings for single-replica vs. multi-replica deployments
- Add a metric: `db_pool_open_connections` gauge

---

### DI-2: No Graceful Degradation for Redis Unavailability

**Location:** Kill switch, revocation store, call counter, rate limiter  
**Impact:** Reliability

Multiple critical-path components depend on Redis (kill switch, revocation, rate limiting). If Redis becomes unavailable:
- Kill switch: Cannot check if agents/sessions are killed — **fail-open or fail-closed?**
- Revocation: Cannot verify token revocation — security risk if fail-open
- Rate limiter: Cannot enforce limits — potential abuse if fail-open

The codebase includes `pkg/circuitbreaker` but Redis failure modes are not consistently documented.

**Recommendation:**
- Define and document fail-open vs. fail-closed policy for each Redis-dependent component:
  - Kill switch: **fail-closed** (deny if unknown)
  - Revocation: **fail-closed** (deny if unknown)
  - Rate limiter: **fail-open** with local fallback (in-memory limiter)
  - Call counter: **fail-open** (degrade gracefully)
- Implement local fallback caches with TTL for kill switch and revocation (cache last-known state for N seconds)
- Add health check degradation: `/health/ready` returns 503 when Redis is unreachable

---

### DI-3: Audit Transport Overflow Policy Is Implicit

**Location:** `pkg/audit/transport.go` (buffered channel)  
**Impact:** Scalability & Data Integrity

The audit HTTP transport uses a buffered channel for event queuing. The `Enqueue` path is **non-blocking**: when the buffer is full it returns `ErrBatchFull` immediately and records a `dropped` outcome via metrics (`audit_enqueue_total{status="dropped"}`), preventing head-of-line blocking on the enforcement hot path. However, the drop-on-full overflow policy is implicit — callers that ignore `ErrBatchFull` silently lose audit events without operator visibility.

**Recommendation:**
- Document the overflow policy explicitly (in `docs/AUDIT_CHAIN_ARCHITECTURE.md` and in a code comment on `Enqueue`) so operators understand that audit events are dropped, not blocked, when the buffer is full
- Decide whether drop-on-full is acceptable for all deployment tiers, or whether a configurable policy (e.g., synchronous write-aside to disk for high-assurance deployments) should be offered
- Ensure callers log dropped events with enough context for manual reconciliation

---

### DI-4: No Request ID Correlation Across All Paths

**Location:** `pkg/observability/middleware.go`  
**Impact:** Observability & Debugging

While OpenTelemetry trace propagation is supported, not all log entries include a request ID that survives across service boundaries without full tracing infrastructure. Operators without Jaeger/Tempo cannot correlate logs.

The services already wire `chimiddleware.RequestID` (chi v5), which generates an `X-Request-ID` header when absent and stores the value in the request context. The current gap is that `RequestLogging` in `pkg/observability/middleware.go` does not extract this value from context and include it as a `request_id` field in the log entry. Similarly, outbound calls (audit writes, posture delivery) do not forward the `X-Request-ID` header.

**Recommendation:**
- In `RequestLogging`, read the request ID via `chimiddleware.GetReqID(r.Context())` and add it as a `request_id` slog attribute on every log entry
- Propagate the request ID on all outbound inter-service calls (audit writes, posture delivery) by setting the `X-Request-ID` HTTP header on the outbound request
- Document the correlation approach for operators without a distributed tracing backend

---

### DI-5: CORS Wildcard (`*`) Allowed Without Production Warning

**Location:** `internal/gateway/app.go` (CORS middleware)  
**Impact:** Security

The CORS configuration accepts `*` as a valid origin, which disables cross-origin protection entirely. In production, this enables any origin to make credentialed requests.

**Recommendation:**
- Log a warning at startup if `*` is in `AllowedOrigins` and environment is production
- Consider rejecting wildcard in production mode (require explicit origins)
- Document in deployment guides that wildcard CORS should only be used in development

---

## [+] Code/Implementation Feedback

### IF-1: Excellent Interface-Driven Architecture (Positive)

**Location:** `pkg/audit/audit.go`, `pkg/enforcement/engine.go`, `pkg/ratelimit/ratelimit.go`, `pkg/crypto/signer.go`

The codebase maintains exceptional discipline in interface-based design:
- All critical dependencies injected via narrow interfaces
- `Pipeline`, `LedgerBackend`, `Limiter`, `CallCounter`, `Provider`, `Signer`, `Breaker`
- Mock implementations are minimal and focused
- No concrete type dependencies in business logic

**Assessment:** Continue this pattern. No action needed.

---

### IF-2: TLS Configuration Is Production-Grade (Positive)

**Location:** `pkg/tlsconf/tlsconf.go`

- TLS 1.2+ enforced by default
- Only ECDHE + AEAD cipher suites permitted
- mTLS with client certificate verification
- Hot-reload via `CertReloader` (zero-downtime certificate rotation)
- 1MB response body limit on JWKS fetches (prevents DoS)

**Assessment:** Exemplary. No action needed.

---

### IF-3: DPoP Implementation Has Robust Replay Protection (Positive)

**Location:** `internal/gateway/jwt.go:28-73`

- JWK thumbprint verification against `cnf.jkt` claim
- HTTP method and URL binding
- JTI-based replay detection with marking
- Length-prefixed hash input prevents concatenation collision attacks

**Assessment:** Strong implementation. No action needed.

---

### IF-4: API Key Pepper Rotation Is Well-Designed (Positive)

**Location:** `internal/minter/store.go:100-187`

- HMAC-SHA256 with base64url encoding
- Supports old pepper verification during rotation window
- Key format `sk-{keyId}.{secret}` with 16-byte ID + 32-byte secret
- Uses `crypto/rand.Reader` for generation

**Assessment:** Follows industry best practices. No action needed.

---

### IF-5: Circuit Breaker Package Is Generic and Reusable (Positive)

**Location:** `pkg/circuitbreaker/breaker.go`

- Generic `Do[T]` and `DoVoid` wrappers
- Three-state machine: Closed → Open → Half-Open
- Configurable thresholds, cooldown, and half-open probes
- Applied to KMS, HTTP transport, and Redis operations
- 87.7% test coverage

**Assessment:** Excellent extraction from federation package. No action needed.

---

### IF-6: Posture Queue Could Benefit from WAL Mode Documentation

**Location:** `internal/posture/queue.go:69-71`

`internal/posture/queue.go` already configures WAL mode in both the DSN (`_journal_mode=WAL&_locking_mode=EXCLUSIVE`) and via an explicit `PRAGMA journal_mode=WAL` call at initialization. The `NewSQLiteQueue` doc comment explains the WAL/single-writer behavior. This is fully implemented.

**Assessment:** No action needed. WAL mode is active and documented. See CR-2 for the remaining throughput constraint imposed by the exclusive-lock, single-connection design.

---

### IF-7: Admin Rate Limiter Uses In-Memory Store Only

**Location:** `internal/gateway/admin_ratelimit.go`

The admin rate limiter is in-memory only (not Redis-backed). In a multi-replica deployment behind a load balancer, each replica maintains independent rate limit state. An attacker can distribute requests across replicas to bypass the limit.

**Recommendation:**
- For admin endpoints bound to `127.0.0.1` (single-node), this is acceptable
- If admin endpoints are ever exposed to multiple replicas, switch to Redis-backed rate limiting
- Document this assumption in `docs/DEPLOYMENT.md`

---

## [?] Open Questions

### OQ-1: Agent Runtime Sandbox Isolation Boundaries

The `internal/agentruntime/` package manages tool invocation and execution. Questions:
- What sandbox mechanisms prevent a malicious tool from escalating privileges?
- Is there process-level isolation (seccomp, namespaces) for tool execution?
- How are tool execution timeouts enforced end-to-end?

**Action:** ✅ Documented in [`docs/AGENT_RUNTIME_SECURITY.md`](AGENT_RUNTIME_SECURITY.md) — covers sandbox isolation layers (Kata/gVisor/Firecracker), security controls, tool execution mediation, timeout enforcement, blast radius containment, and threat model.

---

### OQ-2: Storage Grant Service Trust Boundary

The `cmd/storage-grant-svc` and `internal/storagegrantsvc` suggest a service that grants storage access. Questions:
- How are storage grants scoped (time-limited, resource-limited)?
- What prevents grant replay or grant escalation?
- Is there integration with the audit trail for grant issuance?

**Action:** ✅ Documented in [`docs/STORAGE_GRANT_ARCHITECTURE.md`](STORAGE_GRANT_ARCHITECTURE.md) — covers storage grant lifecycle, trust model, grant scoping (TTL, resource, permission), replay/escalation prevention, and audit integration.

---

### OQ-3: DB Token Service Authentication Model

The `cmd/db-token-svc` provides database token management. Questions:
- How are database tokens differentiated from capability tokens?
- What is the rotation/revocation model for database tokens?
- Is there mutual authentication between the DB token service and consumers?

**Action:** ✅ Documented in [`docs/DB_TOKEN_ARCHITECTURE.md`](DB_TOKEN_ARCHITECTURE.md) — covers DB token architecture, differentiation from capability tokens and Minter API keys, trust chain, policy-based username mapping, mutual authentication, and rotation/revocation model.

---

### OQ-4: Chaos Testing Coverage and Production Readiness

The `internal/chaos/` package contains scenario and injector implementations. Questions:
- What failure modes are tested (network partition, disk full, OOM, clock skew)?
- Are chaos tests run in CI or only on-demand?
- What is the acceptance criteria for chaos test results before a release?

**Action:** ✅ Documented in [`docs/CHAOS_TESTING_STRATEGY.md`](CHAOS_TESTING_STRATEGY.md) — covers chaos testing framework, failure mode coverage matrix, fault injection points, CI integration, release gates, and acceptance criteria.

---

### OQ-5: Multi-Region Consistency Guarantees

The deployment documentation references EKS and GKE. For multi-region deployments:
- What is the consistency model for the audit ledger across regions?
- How is split-brain prevented for the kill switch (Redis cluster partitions)?
- What is the expected behavior during a network partition between regions?

**Action:** ✅ Documented in [`docs/MULTI_REGION_CONSISTENCY.md`](MULTI_REGION_CONSISTENCY.md) — covers consistency model, partition tolerance behavior, kill switch propagation, audit ledger consistency, deployment topologies, and cloud-specific recommendations.

---

## Execution Plan

Ordered by priority and dependency:

### Phase 1: Reliability Hardening (Priority: Critical, Effort: 1 week)

> **Status: ✅ COMPLETED** (2026-05-26)

| # | Item | Depends On | Effort | Status |
|---|------|-----------|--------|--------|
| 1 | CR-1: Enforce non-nil context in agent runtime | — | 1 day | ✅ Done |
| 2 | CR-2: Document SQLite throughput limits; evaluate read/write connection split | — | 1 day | ✅ Done |
| 3 | CR-3: Add circuit breaker to token provider refresh | DI-2 pattern | 1 day | ✅ Done |
| 4 | DI-1: Configure PostgreSQL connection pool | — | 1 day | ✅ Done |
| 5 | DI-2: Define Redis failure mode policies | — | 2 days | ✅ Done |

**Implementation Summary:**

- **CR-1:** Removed `context.Background()` fallback in `internal/agentruntime/httpclient.go`; added `ErrNilContext` sentinel error. Added `contextcheck` linter to `.golangci.yml`. All HTTP calls now require explicit non-nil context.
- **CR-2:** Added doc comment to `SQLiteQueue` explaining throughput limits. Created `docs/POSTURE_SCALING.md` with PostgreSQL migration path, recommended schema, and monitoring guidance.
- **CR-3:** Token provider now uses `circuitbreaker.Do[T]()` for refresh calls with stale-token grace period (serves cached token for up to 60s during failures). Added jitter (0–10% of delay) to prevent thundering herd. Exposed `RefreshFailures()` and `CircuitBreakerState()` for metrics.
- **DI-1:** Created `pkg/config.DatabasePoolConfig` (env-tag driven, defaults: 25 open, 5 idle, 5m lifetime, 60s idle time). Created `pkg/database.OpenPool()` and `pkg/database.ConfigurePool()` helpers. Added `PoolMetrics()` for Prometheus `db_pool_*` gauges.
- **DI-2:** Created `pkg/redisfailover` package with `Monitor`, `Reporter`, `FallbackCache[K,V]`, `HealthChecker`, and `Pinger` interface. Added resilient wrappers: `killswitch.ResilientRedis` (fail-closed), `revocation.ResilientRedis` (fail-closed with TTL cache), `ratelimit.ResilientRedisLimiter` (fail-open with in-memory fallback), `callcounter.ResilientRedis` (fail-open). Created `docs/REDIS_FAILURE_MODES.md`.

### Phase 2: Observability & Resilience (Priority: High, Effort: 1 week)

| # | Item | Depends On | Effort | Owner |
|---|------|-----------|--------|-------|
| 6 | DI-3: Document audit drop-on-full overflow policy | — | 0.5 days | Platform |
| 7 | DI-4: Log request ID in RequestLogging; propagate on outbound calls | — | 1 day | Observability |
| 8 | DI-5: CORS wildcard production warning | — | 0.5 days | Security |
| 9 | IF-7: Document admin rate limiter scope | — | 0.5 days | Docs |

### Phase 3: Documentation & Open Questions (Priority: Medium, Effort: 1–2 weeks)

> **Status: ✅ COMPLETED** (2026-05-26)

| # | Item | Depends On | Effort | Status |
|---|------|-----------|--------|--------|
| 11 | OQ-1: Agent runtime sandbox documentation | — | 2 days | ✅ Done |
| 12 | OQ-2: Storage grant trust model | — | 1 day | ✅ Done |
| 13 | OQ-3: DB token service architecture | — | 1 day | ✅ Done |
| 14 | OQ-4: Chaos testing strategy | — | 2 days | ✅ Done |
| 15 | OQ-5: Multi-region consistency model | — | 3 days | ✅ Done |

**Implementation Summary:**

- **OQ-1:** Created `docs/AGENT_RUNTIME_SECURITY.md` documenting the agent runtime security model, sandbox isolation boundaries (Kata/gVisor/Firecracker), blast radius containment, DPoP proof-of-possession, tool execution mediation, timeout enforcement, and threat model.
- **OQ-2:** Created `docs/STORAGE_GRANT_ARCHITECTURE.md` documenting the storage grant lifecycle, trust model (capability token → cloud-native credential), grant scoping (time-limited, resource-limited), replay prevention, audit integration, and cloud provider details (AWS S3, Azure Blob, GCP GCS).
- **OQ-3:** Created `docs/DB_TOKEN_ARCHITECTURE.md` documenting the DB token service architecture, differentiation from capability tokens and Minter API keys, trust chain, policy-based username mapping, mutual authentication, rotation/revocation model, and cloud provider integration (AWS RDS, Azure SQL, GCP Cloud SQL).
- **OQ-4:** Created `docs/CHAOS_TESTING_STRATEGY.md` documenting the chaos testing framework, failure mode coverage matrix (12+ scenarios), fault injection points, CI integration, release gates and acceptance criteria, and recommended future enhancements.
- **OQ-5:** Created `docs/MULTI_REGION_CONSISTENCY.md` documenting the multi-region consistency model, partition tolerance behavior (fail-closed safety / fail-open best-effort), kill switch propagation (worst-case 30s staleness), audit ledger consistency, deployment topologies (active-passive and active-active), and cloud-specific recommendations.

---

## Architecture Scorecard

| Dimension | Score | Key Finding |
|-----------|-------|-------------|
| Security | 8.5/10 | Strong crypto, KMS wired, DPoP/pepper rotation; CORS wildcard risk remains |
| Reliability | 7.5/10 | Circuit breakers deployed; posture queue SPOF, Redis failure modes undefined |
| Scalability | 8/10 | Stateless services, HPA ready; audit chain + SQLite are scaling limits |
| Maintainability | 9.5/10 | Interface-driven, consistent patterns, 59% test file ratio |
| Observability | 8.5/10 | Full slog/Prometheus/OTLP; needs request ID correlation |
| Documentation | 10/10 | 34+ files, comprehensive architecture/deployment/operations guides |
| Code Quality | 9/10 | Race detector, linter enforced, strong error handling patterns |
| Deployment Readiness | 9/10 | Helm, K8s, air-gap, multi-cloud; production-ready with ops prerequisites |

**Production Readiness Verdict:** 🟢 Production-ready for standard deployments. Phase 1 items recommended before high-scale (>5K RPS) or high-availability (99.99%) targets.

---

## Appendix: Metrics Summary

| Metric | Value |
|--------|-------|
| Go source files (non-test) | 150 |
| Test files | 89 |
| Test file ratio (files) | 59% |
| Services (cmd/) | 6 (gateway, issuer, minter, db-token-svc, posture-emitter, storage-grant-svc) |
| Packages (pkg/) | 15+ |
| Documentation files | 39+ |
| Migration sets | 2 (audit, minter) |
| External dependencies | 22 direct |
| Go version | 1.25.0 |
| CI | GitHub Actions with race detector, linting, coverage |

---

*Review conducted against commit `81563305` of `edgeobs/eunox` branch `copilot/technical-review-system-architecture`.*
