# Architecture Review — euno-platform (v2)

> **Reviewer role:** Principal Software Architect
> **Date:** May 2026 (second-round review)
> **Scope:** Full-stack post-hardening review — `tool-gateway`, `api-key-minter`,
> `capability-issuer`, `common-infra`, `@euno/mcp` remote enforcer, K8s manifests,
> all architecture / design documents.
>
> **Prior review:** [`architecture-review-2026-05.md`](./architecture-review-2026-05.md)
> (all items marked ✅ there are treated as closed).
>
> **Artefacts reviewed:**
> - `docs/ARCHITECTURE.md`, `docs/stage-3-design.md`, `docs/pricing-stage-3.md`
> - `euno-platform/packages/tool-gateway/src/`
> - `euno-platform/packages/api-key-minter/src/`
> - `euno-platform/packages/capability-issuer/src/`
> - `euno-platform/packages/common-infra/src/`
> - `public/packages/mcp/src/enforcer/remote.ts`
> - `public/packages/common/src/config/schema.ts`
> - `k8s/`

---

## Overall Assessment

The architectural foundations are genuinely strong: capability-native zero-trust,
KMS-backed cryptographic signing, fail-closed defaults throughout, pluggable adapter
pattern for cloud portability, defence-in-depth (AGT + gateway + kill-switch + audit
chain), and the per-replica ledger backend are all well-considered and consistently
executed. The prior review resolved every P0/P1 code-level finding. What remains are
**four new critical risks** introduced or exposed during that hardening work, **five
structural improvements** that should precede production GA, and a set of
implementation refinements worth addressing before billing activates.

---

## [!] Critical Risks

### CR-NEW-1 — Primary `/mint` rate limiter is still `InMemoryMintRateLimiter`

**Severity:** High
**File:** `euno-platform/packages/api-key-minter/src/bootstrap.ts:182`

CI-5 from the prior review migrated only the **ping** rate limiter to
`RedisBackedMintRateLimiter`. The primary mint-route rate limiter remains
`InMemoryMintRateLimiter`. The CI-5 "Residual risk" section documents this
explicitly: *"The mint rate limiter (`MintRouterOptions.rateLimiter`) still uses
`InMemoryMintRateLimiter`. Operators who need fleet-wide mint limiting should
inject a `RedisBackedMintRateLimiter` directly."*

In the hosted multi-replica minter, an attacker can distribute API-key-to-JWT
exchange requests across N pods and see only 1/N of the configured rate on each
replica, achieving N × `MINTER_RATE_LIMIT_MAX` mints per window fleet-wide. At
`N=3` pods this triples the effective token-minting budget, which cascades into
over-billing, anomaly-detection noise, and an inflated blast radius for a compromised
API key.

**Recommendation:** Apply the same `createPingRateLimiterFromEnv` pattern to the
main mint route — add a `createMintRateLimiterFromEnv` factory that selects
`RedisBackedMintRateLimiter` when `MINTER_REDIS_URL` or `REDIS_URL` is set, and
wires it in place of the hardcoded `InMemoryMintRateLimiter` in `bootstrap.ts`.
Log a structured `warn` when falling back to in-memory so production deployments
without Redis are immediately visible. The `RedisBackedMintRateLimiter` class
already exists and is fully tested.

---

### CR-NEW-2 — Minter Postgres connection pools are not closed on graceful shutdown

**Severity:** High
**File:** `euno-platform/packages/api-key-minter/src/bootstrap.ts:242–251`

The minter's SIGTERM/SIGINT handler:

```ts
const shutdown = (): void => {
  if (anomalyDetector instanceof RedisAnomalyDetector) {
    void anomalyDetector.close();
  }
  server.close(() => process.exit(0));
};
```

It closes the Redis anomaly detector but never calls `.end()` on either the
`MintAuditPgPool` or the `ApiKeyPgPool`. Under a rolling deploy or Kubernetes pod
eviction:

1. The Postgres server sees an abrupt TCP teardown instead of a `FIN`. Under default
   `pg` client behaviour (`idleTimeoutMillis` off), idle connections linger on the
   Postgres server for the server-side `tcp_keepalives_idle` seconds (often 120–600 s
   on cloud-hosted Postgres), exhausting the connection limit.
2. New minter pods compete for the same limited connection slots with dangling
   connections from the previous generation. Under rapid rolling deploys (e.g. a
   Kubernetes HPA scale event) this can trigger connection exhaustion on the Postgres
   side, converting audit writes to 503s and ultimately blocking all mints.

**Recommendation:** Add `await auditPool?.end()` and `await keyPool?.end()` inside
the shutdown function, wrapped in try/catch so a pool-level error does not prevent
`server.close()` from completing. Both pool references should be hoisted to the same
scope as the `shutdown` closure.

---

### CR-NEW-3 — Cross-tenant token replay via default shared gateway audience (OQ-6, unresolved)

**Severity:** High
**File:** `euno-platform/packages/tool-gateway/src/enforcement.ts:302`

`EnforcementEngine` defaults `gatewayAudience` to the literal `"tool-gateway"`. In
a hosted multi-tenant gateway where multiple tenants share a single gateway instance,
a capability token minted for tenant A with `aud: "tool-gateway"` passes audience
validation at the gateway serving tenant B, because the `tenantId` claim inside
`authorizedBy` is the only tenant-scoping field.

The enforcement engine uses `authorizedBy.tenantId` for usage metering attribution
(line 417) but does **not** validate it against a per-request tenant header or a
policy-configured expected value. A malicious tenant A who can obtain or forge the
`authorizedBy.tenantId` of tenant B (or who observes a leaked token) can replay it
at the shared gateway. The `jti` revocation list prevents the exact same token from
being replayed, but a valid unexpired token can be presented to the gateway for any
of tenant B's resources.

**Recommendation:**
- Mandate a unique `gatewayAudience` per tenant in the hosted deployment — e.g.
  `"tool-gateway:acme-corp-prod"`. The existing `gatewayAudience` option already
  exists; the gap is that the deployment docs and minter config do not require it.
  Add a production-mode validation rule to `GatewayConfigSchema` that rejects the
  default `"tool-gateway"` audience when `HOSTED_MODE=true`.
- Alternatively, enforce that the `tenantId` in `authorizedBy` must match a
  request-scoped tenant header (`X-Tenant-Id`) that is set by the minter façade and
  stripped by the ingress, similar to how `X-Target-Host` is canonicalised by the
  proxy middleware.

---

### CR-NEW-4 — `parseEnforceRequestBody` passes unknown context fields unchecked (CI-1, still open)

**Severity:** Medium-High
**File:** `euno-platform/packages/tool-gateway/src/routes/enforce.ts:177–241`

The parser performs type-checks on `sourceIp`, `recipients`, and `now` individually,
then returns `b as unknown as EnforceRequest`. Unknown properties in `context` are
silently forwarded into `ConditionContext` and ultimately into `enforceConditions`.
When v2 protocol fields are added (e.g. a new `clientCertificate` field), a v1
gateway accepting v2-only fields could misinterpret or leak the unknown data into
audit records, and a v2 client connected to a v1 gateway receives no feedback that
its context fields are being ignored.

**Recommendation:** At the end of `parseEnforceRequestBody`, enumerate
`Object.keys(ctx)` against the known set `{'sourceIp', 'recipients', 'now'}`. Log
unknown keys at `debug` level and, when the declared protocol version equals the
current supported version, strip them before returning so they never reach condition
evaluation.

---

## [~] Design Improvements

### DI-NEW-1 — SQLite posture-emitter queue is unsafe in a multi-replica issuer

**File:** `euno-platform/packages/capability-issuer/src/index.ts`,
`k8s/capability-issuer-deployment.yaml`

The `DurablePostureEmitter` uses SQLite as a write-ahead queue. The K8s deployment
spec runs the issuer with `HPA 2..N` replicas. If `POSTURE_DURABLE_QUEUE_PATH` is
set to a path on a shared persistent volume (e.g. `ReadWriteMany` NFS or Azure File),
multiple issuer pods write to the **same** SQLite file concurrently. SQLite WAL mode
is not designed for multi-process writers across nodes — the WAL file, WAL-index, and
SHM file require file-level locking that does not work reliably across networked
storage, leading to data corruption, lock contention, or silent data loss.

**Recommendation:** Either (a) require `POSTURE_DURABLE_QUEUE_PATH` to be on a
`ReadWriteOnce` PVC (pod-local) by adding documentation and a startup assertion; or
(b) replace the SQLite queue with a Postgres-backed or Redis-backed durable queue
when `NODE_ENV=production` with more than one replica. Document which topology is
supported and fail loudly when the constraint is violated.

---

### DI-NEW-2 — Admin HTTP surface default binding is not enforced at startup

**File:** `euno-platform/packages/tool-gateway/src/bootstrap.ts`,
`GatewayDependencies.adminHost`

The `adminHost` field is documented as requiring a non-wildcard value in production,
but the enforcement lives inside the Zod config schema rather than at the code level.
If an operator accidentally omits `ADMIN_HOST` in production (or sets it to
`"0.0.0.0"`), the admin surface — kill-switch, revocation, epoch-reset, partner-DID
management — is reachable on the public-facing interface. An ingress misconfiguration
or a missing network policy rule would expose the admin API to the internet.

**Recommendation:** Add an explicit check in `initializeServices` (alongside the
existing `checkProductionRedisHa` call) that throws when `NODE_ENV=production` and
`adminHost` is absent, empty, or a wildcard address.

---

### DI-NEW-3 — Production guard stops after first Redis violation (inconsistent fail-fast model)

**File:** `euno-platform/packages/api-key-minter/src/production-guard.ts:150–152`

The `validateProductionMinterConfig` function collects **all** violations for
non-Redis checks so operators can fix every problem in one restart cycle. The Redis
HA check, however, uses `break` after the first single-node URL and only reports that
one. An operator who fixes `REDIS_URL` and restarts will then see a second failure
for `ANOMALY_REDIS_URL`, requiring a third restart cycle. This is inconsistent with
the stated goal of "fix all issues in one restart cycle."

**Recommendation:** Remove the `break` and collect all Redis HA violations into
`violations[]` exactly as the other checks do.

---

### DI-NEW-4 — Kill-switch 30-second staleness window is not committed as an SLA (OQ-3)

**File:** `docs/DISTRIBUTED_STATE.md`, `docs/DEPLOYMENT.md`

`KILL_SWITCH_REFRESH_INTERVAL_MS` defaults to 30 000 ms. For Cloud Team and
Enterprise customers who rely on the kill switch for incident containment, a
30-second window in which a compromised agent continues to execute tool calls is
material. The current architecture document notes this as the "worst-case" bound but
does not commit it as the SLA, nor does it document whether the pub/sub primary path
(sub-second) is the contractual bound.

**Recommendation:** In `docs/DEPLOYMENT.md` and the product docs, explicitly state:
(a) sub-second under normal Redis pub/sub operation, (b) ≤30 s worst-case if a
pub/sub message is dropped and the periodic refresh fires, (c) Redis downtime
degrades to locally-cached state (indefinite staleness). Expose the refresh interval
as a configurable default in the config schema so Enterprise operators can reduce it
(e.g. to 5 s) at the cost of more Redis traffic.

---

### DI-NEW-5 — No Postgres pool size or health-check configuration on minter pools

**File:** `euno-platform/packages/api-key-minter/src/bootstrap.ts:123, 163`

Both `new pgModule.Pool({ connectionString: auditDbUrl })` and
`new pgKeyModule.Pool({ connectionString: apiKeyDbUrl })` use default `pg` pool
settings: 10 max connections, no `idleTimeoutMillis`, no `connectionTimeoutMillis`,
no health-check query. Under sustained load the pool may be insufficient and a
saturated pool blocks mint handlers indefinitely rather than returning a 503.

**Recommendation:** Expose `MINTER_AUDIT_POOL_SIZE`, `MINTER_API_KEY_POOL_SIZE`, and
`MINTER_PG_CONNECTION_TIMEOUT_MS` as typed config entries. Wire them into the pool
constructors. Add a startup pool health check (`SELECT 1`) to fail fast when the DB
is unreachable at startup rather than discovering it on the first mint attempt.

---

## [+] Code / Implementation Feedback

### CI-NEW-1 — `require('pg')` dynamic import anti-pattern in bootstrap

**File:** `euno-platform/packages/api-key-minter/src/bootstrap.ts:113–116, 153–156`

Both Postgres pools use `require('pg')` with an eslint-disable comment. This
prevents TypeScript compile-time type-checking, disables IDE auto-complete, and
makes the try/catch error message the only signal of a missing dependency. The
justification is valid for optional dependency semantics but the same goal is
achievable with a static optional import.

**Recommendation:** Declare `pg` as an optional peer dependency
(`peerDependenciesMeta: { pg: { optional: true } }`). Replace the dynamic `require`
with a static `import type { Pool } from 'pg'` and a runtime `import('pg')` dynamic
ES import in the conditional block. This preserves optional-dep behaviour while
restoring type safety.

---

### CI-NEW-2 — `context.now` validation vs. enforcement clock (OQ-4, still open)

**File:** `euno-platform/packages/tool-gateway/src/routes/enforce.ts:253–271`

`validateClockSkew` rejects a `context.now` that deviates more than 60 seconds from
the gateway clock, but `enforceConditions` is called with the full
`EnforceRequest.context`. If `timeWindow` conditions read `context.now` rather than
`Date.now()`, a client within the 60-second skew tolerance can shift their effective
enforcement time by up to 60 seconds.

**Recommendation:** Add a regression test that explicitly passes `context.now` at the
limit of the 60-second skew and verifies `timeWindow` evaluation uses the **gateway
clock**. Add a code comment to `enforceConditions` confirming that `context.now` is
for audit attribution only, not for condition evaluation.

---

### CI-NEW-3 — `RedisBackedMintRateLimiter` INCR→EXPIRE is non-atomic

**File:** `euno-platform/packages/api-key-minter/src/mint-rate-limiter.ts:173–178`

```ts
const count = await this.client.incr(fullKey);
if (count === 1) {
  await this.client.expire(fullKey, this.windowSeconds);
}
```

If the pod crashes between `INCR` and `EXPIRE`, the key has no TTL and the counter
is permanently stuck, blocking the tenant. The `ttl === -1` recovery path only
triggers on the deny branch, so a low-traffic tenant may be permanently blocked
before hitting the deny threshold.

**Recommendation:** Replace with an atomic approach: use a Lua script or
`SET key 1 EX window NX` combined with `INCR` in a pipeline so the first write
always carries a TTL atomically.

---

### CI-NEW-4 — Anomaly detection misses authentication-failure spray attacks

**File:** `euno-platform/packages/api-key-minter/src/routes/mint.ts:196–220`

The anomaly detector is called with `recordMint(tenantId, false)` on the failure
path, but `tenantId` is only populated after API-key verification succeeds. For
authentication failures the call is skipped (`if (tenantId !== undefined)`). This
means authentication spray attacks — the most critical signal for the
`failure_clustering` rule — are invisible to the detector.

**Recommendation:** On authentication failure, attempt to extract the key prefix from
the raw bearer token (the prefix is the public portion of the
`sk-<prefix8>.<secret>` format) and call `recordMint(prefix, false)` using the
prefix as a pseudo-tenant identifier so the `failure_clustering` rule can fire on
targeted brute-force.

---

### CI-NEW-5 — Minter bootstrap lacks a consolidated startup summary log

**File:** `euno-platform/packages/api-key-minter/src/bootstrap.ts`

The minter bootstrap logs individual component choices but no consolidated startup
summary. An operator cannot quickly verify the full configuration profile (KMS vs PEM
vs ephemeral, Postgres audit vs in-memory, Redis anomaly vs in-memory, JWT admin auth
vs key-only) without reading through the entire log stream.

**Recommendation:** Add a single structured `logger.info('Minter bootstrap complete',
{ ... })` at the end of `main()` that captures the active configuration profile,
mirroring the gateway's pattern.

---

## [?] Open Questions

### OQ-3 — Kill-switch staleness SLA (carried forward)

The 30-second worst-case window is not committed in any product SLA or support
document. For Enterprise customers requiring sub-5-second containment, this needs to
be either contractually scoped or the interval must be configurable.

### OQ-4 — `context.now` in condition evaluation (carried forward)

Whether `enforceConditions` uses the client-supplied `context.now` or the gateway's
`Date.now()` for `timeWindow` evaluation is not definitively addressed in code
comments or tests.

### OQ-NEW-1 — Pepper rotation strategy for the minter

`peppers` is an array of `PepperEntry` correctly designed for rotation. However, no
runbook exists for rotating the pepper while keeping in-flight API keys verifiable
(unlike the HMAC rotation runbook produced in CI-7 of the prior review).

**Recommendation:** Write a `docs/runbooks/minter-pepper-rotation.md` specifying how
to add a second pepper entry, how long both peppers remain active, when to remove the
old one, and how `ApiKeyVerifier` resolves which pepper to use.

### OQ-NEW-2 — Posture emitter queue durability in HA issuer

With CI-6's fix (production requires `POSTURE_DURABLE_QUEUE_PATH`), operators of
multi-replica issuers must choose between a per-pod path (data isolated per replica)
or a shared PVC path (unsafe for SQLite, see DI-NEW-1). No deployment guidance
currently addresses this trade-off.

---

## Execution Plan Summary

See [`architecture-follow-up-tasks-2026-05-v2.md`](./architecture-follow-up-tasks-2026-05-v2.md)
for the detailed Copilot-ready task list with full implementation context.

| Priority | Item | Effort |
|----------|------|--------|
| P0 | CR-NEW-1 Wire Redis-backed mint rate limiter for `/mint` route | Small |
| P0 | CR-NEW-2 Close Postgres pools in minter shutdown handler | Trivial |
| P0 | CR-NEW-3 Mandate unique `gatewayAudience` per tenant in hosted mode | Small |
| P1 | CR-NEW-4 Strip unknown context fields in `parseEnforceRequestBody` | Small |
| P1 | DI-NEW-3 Remove `break` from production guard Redis loop | Trivial |
| P1 | DI-NEW-2 Enforce non-wildcard `adminHost` at startup | Trivial |
| P1 | DI-NEW-5 Expose Postgres pool size / timeout config on minter | Small |
| P2 | DI-NEW-1 Document / enforce SQLite queue single-writer constraint | Small |
| P2 | DI-NEW-4 Commit and document kill-switch staleness SLA | Small |
| P2 | CI-NEW-2 Confirm gateway-clock wins for `timeWindow` (test + comment) | Trivial |
| P2 | CI-NEW-3 Make `RedisBackedMintRateLimiter` INCR atomic | Small |
| P2 | CI-NEW-1 Replace `require('pg')` with optional peer dep + dynamic ESM import | Small |
| P3 | CI-NEW-4 Feed auth-failure events to anomaly detector using key prefix | Small |
| P3 | CI-NEW-5 Add consolidated startup summary log to minter bootstrap | Trivial |
| P3 | OQ-NEW-1 Write minter pepper rotation runbook | Small |
| P3 | OQ-NEW-2 Document posture-emitter queue topology for HA issuer | Small |
