# Architecture Review — Open Questions Resolved

> Reference: [`formaltechnicalarchitecturereview.md`](./formaltechnicalarchitecturereview.md) §[?] Open Questions

This document provides authoritative answers to the open questions raised during the formal technical architecture review.

---

## 1. Multi-Tenancy Model

**Question:** The admin API supports tenantID isolation, but there's no documentation on how tenants are provisioned. Is there a tenant management API, or is each deployment single-tenant?

**Answer:** Eunox uses a **single-tenant-per-deployment** model by design.

### Design Rationale

Each deployment of the eunox control plane serves exactly one tenant (organization). Tenant isolation is achieved at the infrastructure level rather than through a multi-tenant provisioning API:

- **`GATEWAY_TENANT_ID`** is a required environment variable in production. It binds the entire deployment to a single organizational identity.
- **Audit records**, **API keys**, and **rate-limit state** are all scoped by `tenant_id` at the database schema level, providing defense-in-depth even in single-tenant mode.
- **`GATEWAY_HOSTED_MODE=true`** enables a managed-service variant where the gateway enforces per-audience isolation. In this mode, each API key is associated with a specific audience (derived from the provisioning flow), but the underlying deployment still serves one organizational tenant.

### Why No Provisioning API

A multi-tenant provisioning API introduces shared-fate risks that conflict with the zero-trust governance model:

1. **Blast radius isolation** — a compromised gateway in one tenant cannot affect another tenant's agents.
2. **Compliance boundaries** — data residency (GDPR, SOC 2) is trivially satisfied when each tenant has its own infrastructure.
3. **Key management** — each deployment has its own signing key, preventing cross-tenant token forgery.

### Deployment Model

| Scenario | How tenants are provisioned |
|----------|---------------------------|
| Self-hosted (enterprise) | Operator deploys one eunox stack per organization via Helm chart |
| Hosted/SaaS | Orchestrator (external to eunox) provisions isolated deployments per customer |
| Development | Single deployment with `GATEWAY_TENANT_ID=dev` |

---

## 2. KMS Key Rotation

**Question:** The crypto package has KMS stubs but no key rotation mechanism. How are signing keys rotated without service interruption?

**Answer:** Key rotation is supported via the `RotatingKeyStore` (implemented in `internal/issuer/rotating_keystore.go`).

### Rotation Mechanism

The `RotatingKeyStore` maintains:
- **One active signing key** — used for all new token issuance.
- **Zero or more retired keys** — no longer used for signing but still published in JWKS so that previously-issued tokens remain verifiable.

### Rotation Procedure (Zero-Downtime)

1. **Generate new key material:**
   ```bash
   # Example: generate a new EC P-256 key
   openssl ecparam -genkey -name prime256v1 -noout | openssl pkcs8 -topk8 -nocrypt -out new-key.pem
   ```

2. **Load new key into the issuer** — call `RotatingKeyStore.Rotate(newSigner)`:
   - The current active key is moved to the retired list.
   - The new key becomes the active signer.
   - The JWKS endpoint immediately begins serving both keys.

3. **Wait for max token TTL** — all tokens signed with the old key will have expired.

4. **Prune the retired key** — call `RotatingKeyStore.Prune(cutoff)`:
   - Removes retired keys whose retirement timestamp is before the cutoff.
   - After pruning, the old key is no longer in JWKS.

### Operational Notes

- **JWKS caching:** Relying parties (gateways) cache JWKS with a configurable TTL (`GATEWAY_EUNO_JWKS_CACHE_TTL_SECONDS`, default 300s). After rotating, allow at least one cache TTL cycle before the new key is universally available.
- **KMS stubs:** The cloud KMS integrations (AWS KMS, Azure Key Vault, GCP Cloud KMS) remain stubs by design in Stage 1. Today, `RotatingKeyStore` stores `*crypto.SoftwareSigner`, so KMS-backed rotation would require widening the store to an interface that exposes signing plus public-key metadata for JWKS publication.
- **Key ID (`kid`):** Each key has a unique `kid` used in JWT headers for key selection. The `GATEWAY_EUNO_REQUIRE_KID=true` setting ensures gateways always select the correct verification key from JWKS.

---

## 3. Database Connection Pooling

**Question:** pgx/v5 is listed as the driver but the audit `PostgresLedgerBackend` accepts `*sql.DB`. Is there a reason for not using pgxpool directly?

**Answer:** The design uses a minimal `DB` interface intentionally. pgx is **not** currently a dependency.

### Design Rationale

The `pkg/audit.DB` interface:
```go
type DB interface {
    ExecContext(ctx context.Context, query string, args ...any) (Result, error)
    QueryRowContext(ctx context.Context, query string, args ...any) Row
    QueryContext(ctx context.Context, query string, args ...any) (Rows, error)
}
```

This interface is satisfied by:
- `*sql.DB` (standard library) — used in production with any SQL driver.
- `*pgxpool.Pool` via the `pgx/v5/stdlib` adapter — for operators who want pgx-native performance.
- In-memory test implementations — for unit testing without Docker.

### Why Not pgxpool Directly

1. **Driver independence** — the audit backend works with PostgreSQL, CockroachDB, or any SQL-compatible database without code changes.
2. **Test simplicity** — unit tests use a lightweight in-memory implementation rather than requiring Docker containers.
3. **Connection pooling** — `database/sql` provides its own connection pool (`SetMaxOpenConns`, `SetMaxIdleConns`, `SetConnMaxLifetime`). For most deployments, this is sufficient.

### Production Recommendation

For deployments requiring pgx-native features (prepared statement caching, COPY protocol, extended query protocol):

```go
import "github.com/jackc/pgx/v5/stdlib"

db := stdlib.OpenDB(pgxConfig)
// db satisfies *sql.DB and thus pkg/audit.DB
```

This gives pgx performance characteristics while maintaining interface compatibility.

---

## 4. Rate Limiting State Persistence

**Question:** The Redis rate limiter exists, but is rate-limit state preserved across gateway restarts? If using in-memory for development, what's the production expectation?

**Answer:** Gateway max-call state is persistent when the Redis-backed call counter is configured; otherwise development and test setups use in-memory state.

### Implementation Details

| Backend | State persistence | Use case |
|---------|------------------|----------|
| `callcounter.Redis` (`pkg/callcounter/redis.go`) | ✅ Persistent in Redis with per-window expiration | Production gateway max-call enforcement |
| `callcounter.InMemory` (`pkg/callcounter/memory.go`) | ❌ Lost on restart | Development, testing |

### Production Expectations

- **Redis backend is required for durable production max-call enforcement.** Configure it via `GATEWAY_CALL_COUNTER_REDIS_URL`.
- **State survives gateway restarts** because the counter state is stored in Redis and reused by any replacement replica.
- **Multi-replica consistency:** All gateway replicas share the same Redis-backed call-counter state, so max-call conditions are enforced cluster-wide.
- **Failure mode:** If the call counter errors, enforcement returns a condition failure and the request is denied rather than allowed.

### Configuration

```env
# Production (Redis-backed max-call enforcement)
GATEWAY_CALL_COUNTER_REDIS_URL=redis://redis-cluster:6379
GATEWAY_RATE_LIMIT_WINDOW_MS=60000
GATEWAY_RATE_LIMIT_MAX_REQUESTS=1000

# Development (in-memory, no persistence)
# Omit GATEWAY_CALL_COUNTER_REDIS_URL to use in-memory fallback
```

---

## 5. SCIM Provisioning Completeness

**Question:** The issuer has POST /scim/v2/Users and POST /scim/v2/Groups but no GET/PATCH/DELETE. Is this intentional, or is full SCIM 2.0 compliance planned?

**Answer:** Full SCIM 2.0 compliance is now implemented (P3 #17, completed).

### Implemented Endpoints

| Resource | POST | GET (single) | GET (list) | PATCH | PUT | DELETE |
|----------|------|-------------|-----------|-------|-----|--------|
| Users | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Groups | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

### Features

- SCIM PATCH operations: add/replace/remove with path support
- Filtering: `eq` operator on `userName`, `displayName`, `externalId` (Users); `displayName`, `externalId` (Groups)
- Automatic `User.groups` synchronization when group membership changes
- Proper SCIM error responses (`urn:ietf:params:scim:api:messages:2.0:Error`)
- Dedicated `requireSCIMAuth` middleware

See `internal/issuer/scim.go` for implementation and `internal/issuer/scim_test.go` for 40+ test cases.

---

## 6. Testcontainers & Integration Testing

**Question:** `pkg/testutil/containers.go` has testcontainers gated by build tag and commented out. How are integration tests running against real PostgreSQL/Redis?

**Answer:** The checked-in integration suite currently uses in-memory backends. Real PostgreSQL/Redis container helpers are only planned scaffolding at the moment.

### Current Architecture

```
internal/integration/        → Integration tests using in-memory backends (no Docker, no build tag)
pkg/testutil/containers.go   → Integration-tagged placeholder for future testcontainers helpers
```

### Design Decision

The integration test suite currently has a single implemented tier:

| Tier | Build tag | Backend | Docker required | CI gate |
|------|-----------|---------|----------------|---------|
| **Unit + Integration (in-memory)** | (none) | In-memory implementations | No | `make test` |

### Rationale

1. **Fast CI feedback** — `make test` runs without Docker and is the primary CI gate.
2. **Local development** — developers can run the checked-in test suite without Docker installed.
3. **Future extension point** — `pkg/testutil/containers.go` documents how real-infra helpers can be added later behind the `integration` build tag.

### Current State of Real Integration Tests

At present there are no wired `integration`-tagged tests that start PostgreSQL or Redis containers. The helper implementations in `pkg/testutil/containers.go` are commented TODO scaffolding rather than active utilities.

---

## Summary

| # | Question | Resolution |
|---|----------|-----------|
| 1 | Multi-tenancy model | Single-tenant-per-deployment by design |
| 2 | KMS key rotation | `RotatingKeyStore` with active + retired keys in JWKS |
| 3 | Database connection pooling | Intentional `DB` interface for driver independence |
| 4 | Rate limiting persistence | Redis backend is persistent; in-memory is dev-only |
| 5 | SCIM completeness | Full SCIM 2.0 implemented (P3 #17) |
| 6 | Testcontainers | Current suite is in-memory; Docker helpers are planned scaffolding |
