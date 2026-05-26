# Formal Technical Architecture Review

**Repository:** `edgeobs/eunox`
**Reviewer Role:** Principal Software Architect
**Date:** 2026-05-26
**Scope:** Full system architecture, design, and implementation

> **Authority note:** [`docs/formaltechnicalarchitecturereview.md`](./formaltechnicalarchitecturereview.md) remains the canonical architecture review for the staged Go reimplementation. This document is a supplemental repository-level review snapshot focused on current risks and design follow-ups that are not already captured there.

---

## Executive Summary

eunox is a Go monorepo implementing a capability-based governance system for AI agents. The system provides zero-trust enforcement via JWT capability tokens with fine-grained conditions, cryptographic audit trails, and pluggable identity/signing backends. The architecture is well-designed with strong separation of concerns, interface-driven dependency injection, and comprehensive documentation. However, several critical and design-level issues must be addressed before production deployment.

**Overall Rating: 8/10** — Excellent foundation; production blockers identified below.

---

## [!] Critical Risks

### CR-1: Issuer KMS Wiring Falls Back to Software Keys

**Location:** `cmd/issuer/main.go` (lines 160–172), `pkg/crypto/kms_aws.go`, `pkg/crypto/kms_azure.go`, `pkg/crypto/kms_gcp.go`
**Severity:** Critical — Blocks production deployment
**Impact:** Security & Reliability

The repository already contains production-style signer implementations for AWS KMS, Azure Key Vault, and GCP Cloud KMS in `pkg/crypto`. The current production gap is wiring: `cmd/issuer/main.go`'s `buildSigner()` still generates an in-process software key even when `aws-kms`, `azure-keyvault`, or `gcp-cloudkms` is selected. As a result, deployments can appear to use external KMS while actually keeping signing keys in-process.

**Recommendation:** Wire `buildSigner()` to the existing `NewRealAWSKMSSigner`, `NewRealAzureKeyVaultSigner`, and `NewRealGCPCloudKMSSigner` constructors. Add startup validation that rejects `software` signing in production unless it is explicitly intended.

---

### CR-2: Request/IO Paths Drop Caller Context

**Location:** Request and IO paths such as `internal/gateway/partner_did_redis.go`
**Severity:** Critical — Impacts reliability and observability
**Impact:** Reliability & Observability

Some `context.Background()` usages are appropriate in tests or bounded startup/shutdown flows. The actionable issue is production request/IO code that uses `context.Background()` instead of propagating the caller context. In those paths:
- No request-scoped cancellation (stale work continues after client disconnect)
- No timeout inheritance (unbounded operations possible)
- Broken distributed tracing (spans are not linked to parent request)
- No graceful degradation under load (cannot cancel in-flight work)

**Recommendation:** Audit request-driven and network/storage-backed code paths first, starting with Redis access in `internal/gateway/partner_did_redis.go`, and replace `context.Background()` with propagated request or lifecycle contexts. A lint rule such as `contextcheck` can help prevent regressions in those paths.

---

### CR-3: Gateway Admin Auth Still Permits Legacy Static Secret Fallback

**Location:** `internal/gateway/app.go`, `internal/gateway/admin_jwt.go`
**Severity:** High — Security risk
**Impact:** Security

The gateway already supports JWT-based admin authentication via `AdminJWKSURI` and `AdminJWTAudience`, with a static `ADMIN_API_KEY` fallback for legacy deployments. The remaining risk is that production environments can still rely on a single shared secret. If that fallback key is compromised:
- No rotation mechanism without restart
- No per-operator attribution in audit logs
- No revocation of individual operator access
- Shared secret across all operators

**Recommendation:** Treat JWT-based admin authentication as the production default and require it in hardened deployments. Keep the static key only as a deprecated compatibility path, with documentation and startup checks that discourage or block it in production.

---

### CR-4: No Rate Limiting on Admin Endpoints

**Location:** `internal/gateway/app.go` (admin router setup)
**Severity:** High — Security risk
**Impact:** Security

Admin endpoints (policy management, kill switch, revocation) lack rate limiting. Even bound to `127.0.0.1:3003`, lateral movement within a cluster (compromised pod, SSRF) could allow brute-force attacks against the admin API key.

**Recommendation:** Add a separate, stricter rate limiter for admin endpoints (e.g., 10 req/min per source IP). Consider mutual TLS for admin plane.

---

## [~] Design Improvements

### DI-1: Audit Chain Single-Writer Bottleneck

**Location:** `pkg/audit/backend.go:51-57` (advisory lock), `pkg/audit/audit.go:178-181`
**Impact:** Scalability

The `PostgresLedgerBackend` uses PostgreSQL advisory locks to enforce single-writer semantics for the HMAC chain. This means:
- Only one gateway replica can write to the centralized audit store at a time
- Under high load, `ErrLockContention` will be returned to other replicas

The `PerReplicaPostgresLedgerBackend` mitigates this by partitioning chains per replica, but cross-chain verification adds complexity and potential inconsistency windows.

**Recommendation:** Document the trade-offs explicitly. For high-throughput deployments, recommend the per-replica backend with periodic cross-chain reconciliation. Consider a Kafka/NATS-based audit transport for eventual-consistency at scale.

---

### DI-2: Audit Schema Migration Coverage Is Minimal

**Location:** `migrations/audit/001_create_audit_records.up.sql`, `migrations/minter/001_create_api_keys.up.sql`
**Impact:** Maintainability & Scalability

The repository currently has two migration sets (`audit` and `minter`), each with a single up/down pair. If the concern is the audit schema specifically, its migration history is still minimal. As the system matures, schema evolution will become riskier without clearer tooling and versioning guidance.

**Recommendation:**
- Document the migration framework (golang-migrate/v4 per the reimplementation plan)
- Add schema documentation with ER diagrams
- Implement migration dry-run in CI (validate up/down idempotency)
- Add migration sequence validation in startup

---

### DI-3: Hard-Coded Body Size Limits

**Location:** `internal/dbtokensvc/app.go:25` (`1 << 20` = 1MB)
**Impact:** Maintainability

Request body limits are hard-coded magic numbers. Different services may need different limits (e.g., policy uploads vs. token requests).

**Recommendation:** Extract to configuration with per-route overrides. Define sensible defaults in the config struct with env var support.

---

### DI-4: Health Check Standardization Should Be Documented, Not Re-implemented

**Location:** `internal/gateway/app.go`, `internal/issuer/app.go`, other service routers
**Impact:** Reliability

The issuer service already exposes `/health/live` and `/health/ready`, matching the gateway and the other service routers. The remaining gap is documentation and enforcement of the convention, so future services keep the same health probe shape and semantics.

**Recommendation:** Document the existing `/health/live` and `/health/ready` convention as a cross-service requirement and keep new services aligned with it, whether they use `pkg/lifecycle` directly or equivalent handlers.

---

### DI-5: No Circuit Breaker for External Dependencies

**Location:** Identity provider calls, KMS calls, Redis calls
**Impact:** Reliability

External service calls (IdP token verification, KMS signing, Redis) lack circuit breaker patterns. A failing upstream (e.g., IdP outage) will cause cascading latency across all requests.

**Recommendation:** Implement circuit breakers (e.g., `sony/gobreaker`) for:
- Identity provider verification
- KMS signing operations
- Redis operations (especially kill switch, which has a fallback path)

---

### DI-6: Configuration Validation Exits Process

**Location:** `pkg/config/loader.go:14-44` (`LoadOrExit`)
**Impact:** Testability

`LoadOrExit()` calls `os.Exit(1)` on validation failure. This pattern:
- Cannot be tested without mocking `os.Exit`
- Prevents graceful error reporting in orchestrated environments
- Makes integration testing of config validation difficult

**Recommendation:** Prefer `Load()` (which returns errors) in new code. Reserve `LoadOrExit()` only for `main()` entry points. Add config validation tests using `Load()`.

---

## [+] Code/Implementation Feedback

### IF-1: Excellent Interface-Based Design

**Location:** `pkg/audit/audit.go:82-100`, `pkg/enforcement/engine.go:36-38`, `pkg/ratelimit/ratelimit.go:19-44`
**Assessment:** Positive

The codebase demonstrates disciplined interface-based design:
- `Pipeline`, `LedgerBackend`, `Limiter`, `CallCounter`, `Provider`, `Signer`
- All critical dependencies are injected via interface, enabling isolated testing
- Mock implementations in test files are clean and minimal

**No action needed** — continue this pattern.

---

### IF-2: Structured Error Handling Is Consistent

**Location:** `pkg/audit/audit.go:25-35`, `pkg/dbtokensvc/app.go:28-34`, `pkg/capability/errors.go`
**Assessment:** Positive

Package-level sentinel errors with `errors.New()` and consistent `fmt.Errorf(...%w)` wrapping enables proper error chain inspection. Error codes in capability package enable structured API responses.

**Minor improvement:** Consider adding `errors.Is()`/`errors.As()` documentation in CONTRIBUTING.md to ensure all contributors follow this pattern.

---

### IF-3: Audit Pipeline HMAC Chain — Optimize Flush Batching

**Location:** `pkg/audit/transport.go:137` (flush loop), `pkg/audit/transport.go:88` (buffer channel)
**Assessment:** Opportunity

The HTTP transport uses a buffered channel and periodic flush. Under burst load, the channel may fill and block the hot path.

**Recommendation:**
- Add a metric for channel backpressure (buffer fill ratio)
- Consider adaptive batch sizing (flush at N items OR time interval, whichever comes first)
- Add a configurable overflow policy (drop-oldest, block, or write-aside)

---

### IF-4: Rate Limiter Cleanup Loop Could Leak

**Location:** `pkg/ratelimit/memory.go:37-39` (cleanup goroutine)
**Assessment:** Minor risk

The in-memory limiter starts a background goroutine for expired entry cleanup. If the limiter is created but never closed (e.g., in tests), the goroutine leaks.

**Recommendation:** Ensure all test code calls `Close()` on limiters. Consider a finalizer or `runtime.SetFinalizer` warning in debug builds.

---

### IF-5: Lifecycle Manager — Parallel Server Startup

**Location:** `pkg/lifecycle/lifecycle.go:157-162`
**Assessment:** Positive with caveat

Servers start in parallel goroutines, but there's no dependency ordering. If the admin server must be ready before the data plane (e.g., for initial config push), the current design doesn't enforce that.

**Recommendation:** Add optional dependency ordering or startup phases if needed. For now, document the assumption that all servers are independent.

---

### IF-6: Observability Stack Is Production-Grade

**Location:** `pkg/observability/logging.go`, `metrics.go`, `tracing.go`, `middleware.go`
**Assessment:** Positive

The observability package provides:
- `slog`-based structured logging with JSON/text modes
- Prometheus metrics with standard HTTP histogram buckets
- OpenTelemetry tracing with OTLP gRPC export
- Middleware chain for request logging, metrics, and trace propagation

**Minor improvement:** Add a `pkg/observability/README.md` documenting the standard label/tag conventions for consistent metric naming across services.

---

### IF-7: Test Infrastructure Is Comprehensive

**Location:** `pkg/testutil/clock.go:22-84`, `pkg/testutil/containers_integration.go`, `pkg/audit/audit_test.go:39-91`
**Assessment:** Positive

- `FakeClock` for deterministic time-based testing
- Testcontainers for PostgreSQL/Redis integration tests
- In-memory mock implementations of all critical interfaces
- Race detector enabled in CI (`go test -race`)
- ~37% test file ratio (84 test files / 226 total)

**No action needed** — maintain this standard.

---

## [?] Open Questions

### OQ-1: Multi-Tenancy Isolation Model

The system references `tenant_id` in audit records and configuration. However, the isolation guarantees are unclear:
- Are tenants isolated at the database level (schema per tenant, row-level security)?
- Can a compromised token from Tenant A affect Tenant B's enforcement?
- Is there tenant-scoped rate limiting?

**Action:** Document the tenant isolation boundaries and threat model.

---

### OQ-2: Partner Federation Trust Model

Partner DID resolution (`pkg/federation/`, `pkg/did/`) enables cross-organization trust. Questions:
- What happens when a partner DID document is compromised?
- Is there a trust revocation mechanism beyond the kill switch?
- How are partner policies versioned and synchronized?

**Action:** Document the federation trust lifecycle (onboarding, rotation, revocation).

---

### OQ-3: Audit Record Retention and Compliance

The cryptographic audit trail is append-only with HMAC chain integrity. However:
- What is the retention policy? (GDPR requires bounded retention)
- How are records archived or pruned without breaking the chain?
- Is there a compliance certification target (SOC 2, HIPAA)?

**Action:** Document retention strategy and chain pruning approach.

---

### OQ-4: Hot-Reload of Policies

The issuer loads role policies from `ROLE_POLICY_FILE`. Questions:
- Is hot-reload supported (file watch)?
- What happens if the policy file is malformed during reload?
- Is there a validation endpoint to test policy changes before applying?

**Action:** Document the policy lifecycle and safe reload mechanism.

---

### OQ-5: Disaster Recovery and Backup

The documentation mentions deployment across clouds (EKS, GKE) but:
- Is there a documented RTO/RPO target?
- How are audit records backed up (given append-only guarantees)?
- What is the restore procedure for a corrupted HMAC chain?

**Action:** Create a disaster recovery runbook with specific procedures.

---

## Execution Plan

Ordered by priority and dependency:

### Phase 1: Security Hardening (Week 1–2) ✅ COMPLETE

| # | Item | Depends On | Effort | Status |
|---|------|-----------|--------|--------|
| 1 | CR-1: Implement real KMS signers | — | 2 weeks | ✅ Done |
| 2 | CR-3: Migrate admin auth to JWT | CR-1 (key material) | 3 days | ✅ Done |
| 3 | CR-4: Add admin endpoint rate limiting | — | 2 days | ✅ Done |

**Implementation Notes (Phase 1):**

- **CR-1**: `buildSigner()` in `cmd/issuer/main.go` now wires real KMS signers (AWS KMS, Azure Key Vault, GCP Cloud KMS) via a factory-based client registration pattern (`pkg/crypto/kms_clients.go`). Software signing is rejected in production. `SingleKeyStore` accepts `crypto.Signer` interface.
- **CR-3**: `validateAdminAuth()` in `cmd/gateway/main.go` enforces JWT admin auth (`GATEWAY_ADMIN_JWKS_URI`) in production. Static `ADMIN_API_KEY` is deprecated with a warning when used alongside JWT.
- **CR-4**: Admin endpoints are rate-limited at 10 req/min per source IP (configurable via `GATEWAY_ADMIN_RATE_LIMIT_PER_MINUTE`). Health endpoints (`/health/*`) are exempt. Standard rate-limit headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, `Retry-After`) are returned.

### Phase 2: Reliability (Week 2–3)

| # | Item | Depends On | Effort | Owner |
|---|------|-----------|--------|-------|
| 4 | CR-2: Fix context propagation (36 instances) | — | 1 week | ✅ Done |
| 5 | DI-4: Standardize health checks | — | 2 days | ✅ Done |
| 6 | DI-5: Add circuit breakers | — | 3 days | ✅ Done |

**Implementation Notes (Phase 2):**

- **CR-2**: Added `context.Context` parameter to `PartnerDIDStore` interface, `RedisPartnerDIDStore`, posture emitter methods (`EmitObserved`, `EmitRevoked`, `QueueDepth`, `UpdateMetrics`), and kill switch pub/sub handler. All request-path code now propagates the caller's context to Redis and I/O operations. Defensive nil-guards in shutdown paths (audit flush, identity init) left as-is.
- **DI-4**: Created `docs/HEALTH_CHECKS.md` documenting the `/health/live` and `/health/ready` convention, Kubernetes probe config, circuit breaker integration, and per-service behavior. Added `Content-Type: application/json` headers to `pkg/lifecycle` handlers.
- **DI-5**: Extracted generic `pkg/circuitbreaker` package from `pkg/federation`: `Breaker` (3-state: closed/open/half-open), `Do`/`DoVoid` generic wrappers, `ProtectedSigner` (KMS), `Transport` (HTTP/IdP/JWKS), `ProtectedRedis` (Redis commands). Federation package refactored to delegate via type aliases (backward-compatible). 87.7% test coverage.

### Phase 3: Scalability & Maintainability (Week 3–4)

| # | Item | Depends On | Effort | Owner |
|---|------|-----------|--------|-------|
| 7 | DI-1: Document audit chain trade-offs | — | 1 day | Architect |
| 8 | DI-2: Schema documentation & CI validation | — | 3 days | Database team |
| 9 | DI-3: Extract hard-coded limits to config | — | 1 day | Platform team |
| 10 | IF-3: Audit flush backpressure metrics | — | 2 days | Observability team |

### Phase 4: Documentation & Open Questions (Week 4–5)

| # | Item | Depends On | Effort | Owner |
|---|------|-----------|--------|-------|
| 11 | OQ-1: Document multi-tenancy model | — | 2 days | Architect |
| 12 | OQ-2: Document federation trust lifecycle | — | 2 days | Security team |
| 13 | OQ-3: Define retention/compliance strategy | — | 3 days | Compliance team |
| 14 | OQ-4: Document policy hot-reload | — | 1 day | Platform team |
| 15 | OQ-5: Create DR runbook | — | 3 days | SRE team |

---

## Architecture Scorecard

| Dimension | Score | Key Finding |
|-----------|-------|-------------|
| Security | 7/10 | Strong crypto design; KMS stubs and static admin key are blockers |
| Reliability | 7/10 | Graceful lifecycle; missing circuit breakers and context propagation |
| Scalability | 8/10 | Stateless services, HA Redis, HPA ready; audit chain is bottleneck |
| Maintainability | 9/10 | Interface-driven, consistent patterns, excellent test coverage |
| Observability | 8/10 | Full slog/Prometheus/OTLP stack; needs backpressure metrics |
| Documentation | 10/10 | 34 files, ~500 KB; architecture, deployment, operations covered |
| Code Quality | 9/10 | 80%+ coverage target, race detector, linter enforced |
| Deployment Readiness | 8/10 | Helm, K8s, air-gap; needs KMS integration for production |

**Production Readiness Verdict:** 🟡 Deploy to staging today; production after Phase 1–2 completion (~3 weeks).

---

*Review conducted against commit HEAD of `edgeobs/eunox` main branch.*
