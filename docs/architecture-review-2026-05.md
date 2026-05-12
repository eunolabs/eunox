# Architecture Review — euno-platform

> **Reviewer role:** Principal Software Architect  
> **Date:** May 2026  
> **Scope:** Stage 3 implementation — tool-gateway, api-key-minter, @euno/mcp remote-enforcer, billing plumbing (Task 17), distributed state (Redis/Postgres)  
> **Artefacts reviewed:** `docs/ARCHITECTURE.md`, `docs/stage-3-design.md`, `docs/pricing-stage-3.md`, gateway source (`euno-platform/packages/tool-gateway/src/`), minter source (`euno-platform/packages/api-key-minter/src/`), common-infra (`euno-platform/packages/common-infra/src/`), MCP remote enforcer (`public/packages/mcp/src/enforcer/remote.ts`), config schema (`public/packages/common/src/config/schema.ts`)

---

## [!] Critical Risks

### CR-1 — In-memory `UsageMeter` data loss creates billing integrity failures ✅ FIXED

**Severity:** High  
**Packages:** `tool-gateway`, `@euno/common`  
**File:** `euno-platform/packages/tool-gateway/src/bootstrap.ts` (Step 13a)  
**Fix:** `RedisUsageMeter` + `createUsageMeterFromEnv` factory in `@euno/common-infra`;
`euno_usage_meter_errors_total` Prometheus counter + `onMeterError` callback in
`EnforcementEngine` (see commit with "feat(gateway/infra): cr-1/ci-2/ci-4 — durable
Redis UsageMeter, usage-meter error counter, anomaly structured logging").

`InMemoryUsageMeter` (wired in `bootstrap.ts` Step 13a) holds all per-tenant
enforcement-event counters in process memory with no durable backend. A pod
restart, OOM kill, or rolling deploy silently zeroes every tenant's counter.
Billing at the Cloud Team tier ($49/seat/month or metered overage) depends on
this data. There is currently no write-ahead log, Redis flush, or Postgres
persistence for usage counts. The `POST /admin/usage/reset` call also has no
durability. If billing goes live before a durable `UsageMeter` is wired,
customers will be under-billed or the meter will be untrustworthy for SLA
disputes.

**Recommendation:** Before billing activates, replace `InMemoryUsageMeter` with a
Redis-backed (`INCRBY` per period key + TTL aligned to billing window) or
Postgres-backed implementation behind the existing `UsageMeter` interface.
`recordEnforcement` errors are currently swallowed silently in the `finally` block
of `validateAction` — add an error counter (`euno_usage_meter_errors_total`) so
silent failures are observable.

---

### CR-2 — `sourceIp` is fully client-controlled in self-hosted deployments ✅ FIXED

**Severity:** High  
**Package:** `tool-gateway`  
**File:** `euno-platform/packages/tool-gateway/src/routes/enforce.ts`  
**Fix:** `ENFORCE_SOURCE_IP_MODE` env var + `sourceIpMode` option on
`EnforceRouterOptions` (see commit with "fix(gateway): CR-2 sourceIp trust
boundary").

The `EnforceRequest.context.sourceIp` field was used verbatim as the effective
source IP for `ipRange` condition evaluation. An `@euno/mcp` client running in
remote-enforcer mode could pass any string as `context.sourceIp` to bypass IP
range allow/deny policies.

**Root cause:** The gateway had no mechanism to distinguish the
client-asserted IP from the IP derived from the TCP connection or trusted
`X-Forwarded-For` headers.

**Resolution:** Added `sourceIpMode: 'gateway' | 'client'` to
`EnforceRouterOptions`. In `'gateway'` mode (the new default, wired in
`initializeServices` and `createApp` via `ENFORCE_SOURCE_IP_MODE`), the route
overrides `validationContext.sourceIp` with `req.ip` (which already respects the
existing `TRUST_PROXY` / `trust proxy` configuration). A structured `warn` log is
emitted whenever the client-supplied value differs from the connection-derived
value, giving operators visibility into spoofing attempts. The legacy `'client'`
mode remains available for backward compatibility via `ENFORCE_SOURCE_IP_MODE=client`.

**Residual risk:** The fix is only effective when `TRUST_PROXY` is correctly
configured for the deployment topology. See **DEPLOYMENT.md** §"Source IP trust"
for the configuration matrix. Misconfiguring `TRUST_PROXY` (e.g. `true` when the
gateway is also reachable directly) can still lead to IP spoofing via forged
`X-Forwarded-For` headers — this is an Express-level concern documented at
https://expressjs.com/en/guide/behind-proxies.html.

---

### CR-3 — Redis as a simultaneous single point of failure for kill-switch, revocation, call counters, and DPoP replay

**Severity:** High  
**Package:** `common-infra`, deployment  
**Files:** `euno-platform/packages/common-infra/src/redis-circuit-breaker.ts`, `k8s/redis.yaml`

All four runtime-security state stores share a single `REDIS_URL` with no Redis
Sentinel or Cluster HA at the application level. The in-cluster `k8s/redis.yaml`
ships a single-node Redis. The consequence under the documented fail-closed
defaults: a Redis outage causes 100 % of enforcement decisions to be denied
(revocation returns "revoked", call counters overflow, DPoP replay store fails).
Under `fail-open`, all revocations and call limits are bypassed. The
`RedisCircuitBreaker` limits hot-path latency but does not change this binary
outcome.

**Recommendation:**
- For production, mandate Redis Sentinel or Cluster in `DEPLOYMENT.md`; gate the
  single-node `k8s/redis.yaml` behind a `DEV_ONLY` annotation.
- Add a startup `warn` when `NODE_ENV=production` and `REDIS_URL` points at a
  non-sentinel, non-cluster URL.
- Introduce a short-duration `REDIS_GRACE_PERIOD_MS` on the revocation and
  call-counter stores to tolerate brief network blips without denying all traffic.
- Add a Prometheus alert on `euno_gateway_revocation_unavailable_total > 0` over
  a sustained window (e.g. `> 0 for 2m`).

---

### CR-4 — Minter anomaly detection is per-replica; distributed brute-force is invisible

**Severity:** Medium-High  
**Package:** `api-key-minter`  
**File:** `euno-platform/packages/api-key-minter/src/anomaly-detector.ts`

`AnomalyDetector` is an in-process ring-buffer structure. Each minter replica
maintains completely independent per-tenant `BucketStore` state. An attacker
distributing mint requests across N replicas (e.g. via a load balancer) would
see only 1/N of the mint rate on each replica, staying comfortably below the
`rate_spike` threshold. The `off_hours_low_activity` and `failure_clustering`
rules share the same blind spot.

**Recommendation:**
- Document this limitation explicitly in `anomaly-detector.ts` and in the minter
  threat model.
- For the hosted service, back anomaly state with Redis hashes (one bucket entry
  per `tenantId:bucketTs` key, TTL aligned to the ring-buffer window) so all
  replicas share a coherent view.
- Add a Prometheus alert on `euno_minter_anomaly_alerts_total` with a per-replica
  label so per-instance vs. fleet-wide discrepancies are visible.

---

### CR-5 — Minter threat model sign-off is pending; merge gate is unenforceable

**Severity:** High (process)  
**File:** `docs/security/minter-threat-model.md`

The threat model carries the status: *"Pending sign-off (requires ≥ 2 engineers
+ 1 security reviewer outside the implementer before minter code merges to
main)"*. The reviewers and dates fields are blank. Merging Stage 3 minter code to
`main` before this gate is met violates the stated process.

**Recommendation:** Record sign-off names and dates before any minter code is
merged. Gate CI on the presence of a `SIGNED_OFF: true` tag in the threat model
front-matter, or use a CODEOWNERS approval requirement on
`docs/security/minter-threat-model.md`.

---

## [~] Design Improvements

### DI-1 — GCP per-tenant key isolation is explicitly blocked ✅ FIXED

**Package:** `common-infra`  
**File:** `euno-platform/packages/common-infra/src/kms-token-signer.ts`

The design document (`docs/stage-3-design.md §1.1`) states: *"GCP deployments
currently lack per-tenant key isolation through a shared signer config."* This
means any GCP-deployed tenant shares a signing key with other tenants — a
compromise of one tenant's token-issuing surface can mint tokens for other
tenants.

**Recommendation:** Treat Task 11 as a hard prerequisite for any GCP multi-tenant
production deployment. Add a startup assertion in the GCP driver that fails loudly
when `tenantKeyMap` is absent, rather than silently falling back to the default
key.

**Fix:** The `KmsTokenSigner` constructor now throws a hard `Error` when
`provider === 'gcp-cloudkms'` and `tenantKeyMap` is absent or empty, with a
message referencing `docs/security/minter-threat-model.md §1` and the required
`MINTER_TENANT_KEY_MAP` variable. Two new regression tests cover the absent and
empty-object cases; the existing GCP factory test is updated to supply a
`tenantKeyMap`. See `docs/DEPLOYMENT.md §"GCP Cloud KMS per-tenant key isolation"`
for the operator guide.

---

### DI-2 — PostgreSQL advisory lock is a global serialization bottleneck for the audit ledger ✅ FIXED

**Package:** `common-infra`  
**File:** `euno-platform/packages/common-infra/src/ledger-signer.ts`

`PostgresLedgerBackend` acquires `pg_advisory_xact_lock(BigInt('0x455534004C454447'))`,
a **single global lock** shared by all replicas and all tenants. Under high
multi-replica, multi-tenant write load this becomes a throughput ceiling: every
audit write competes for this single transaction-level lock.

The `PerReplicaPostgresLedgerBackend` addresses this, but the simple
`PostgresLedgerBackend` remains the default.

**Recommendation:**
- Make `PerReplicaPostgresLedgerBackend` the recommended production default in
  deployment docs.
- Add an explicit throughput SLA or benchmark for `PostgresLedgerBackend` so
  operators know when to upgrade.
- Consider sharding the advisory lock by tenant for the shared-table case (e.g.
  `hashtext(tenantId) mod N` as the lock ID), accepting that chain integrity
  becomes per-tenant rather than global.

**Fix:**
- `PostgresLedgerOptions` gains an `advisoryLockMode?: 'global' | 'per-tenant'`
  option. When `'per-tenant'`, each tenant acquires a separate advisory lock
  derived from a stable FNV-1a 32-bit hash of `evidence.tenantId`, allowing
  concurrent writes from independent tenants. The global seq namespace is
  preserved; hash collisions result in a transparent retry (up to 3 attempts) on
  Postgres unique-constraint violation (23505).
- A throughput SLA table is added to both `PostgresLedgerOptions.advisoryLockMode`
  JSDoc and `docs/DEPLOYMENT.md §"Audit Ledger backend selection"`.
- `docs/DEPLOYMENT.md` now explicitly recommends `PerReplicaPostgresLedgerBackend`
  (`AUDIT_LEDGER_BACKEND=per-replica-postgres`) for any Stage 3+ multi-replica or
  multi-tenant production deployment, with per-replica throughput estimates.

---

### DI-3 — `AdminIdempotencyStore` is in-memory; provides false guarantees in multi-replica deployments ✅ FIXED

**Package:** `tool-gateway`  
**File:** `euno-platform/packages/tool-gateway/src/admin-api.ts`

The in-memory `AdminIdempotencyStore` is local-process only, correctly documented
as such. However: (a) a replica restart clears the store, allowing re-processing
of unexpired idempotency keys; (b) any future change routing admin traffic across
replicas for HA breaks idempotency silently without a code change.

**Recommendation:**
- Replace with a Redis-backed implementation for Stage 4 or before any admin HA
  deployment.
- Add a startup `warn` when `REDIS_URL` is set but no Redis-backed idempotency
  store is configured.

**Fix:** Added `RedisAdminIdempotencyStore` (atomic `SET EX NX` + `GET`) and
`RedisIdempotencyClient` interface to `admin-api.ts`. Added a startup `warn` in
`initializeServices` when `REDIS_URL` or `ADMIN_IDEMPOTENCY_REDIS_URL` is
configured but the in-memory store is in use, directing operators to wire the
Redis store for Stage 4 HA admin deployments.

---

### DI-4 — Telemetry endpoint is an outbound call to an external service from the enforcement plane ✅ FIXED

**Package:** `tool-gateway`  
**File:** `euno-platform/packages/tool-gateway/src/gateway-telemetry.ts`

`GatewayTelemetryCollector` calls `https://telemetry.euno.dev/v1/events` by
default. This outbound connection from the enforcement plane to an external HTTPS
endpoint is a data-flow risk: self-hosters may not expect it; a BGP hijack or
compromise of `telemetry.euno.dev` receives per-tenant enforcement rate data; the
gateway's egress network policy does not appear to allow this path by default.
`EUNO_TELEMETRY=0` disables it, but the default is **enabled**.

**Recommendation:**
- Change the default to opt-in (`EUNO_TELEMETRY=1` required explicitly, not the
  current "unset = enabled").
- Document the telemetry endpoint in `DEPLOYMENT.md` and `self-host.md`.
- Add to the self-host network policy egress rules only when telemetry is
  explicitly enabled.

**Fix:** `createGatewayTelemetryFromEnv` now returns `null` unless
`EUNO_TELEMETRY === '1'` (opt-in). Telemetry is disabled by default. Updated
module-level comments, `GatewayDependencies` JSDoc, and the Step 15 comment in
`initializeServices`. The old `EUNO_TELEMETRY=0` opt-out is superseded: the
equivalent is now simply not setting `EUNO_TELEMETRY`.

---

### DI-5 — No distributed tracing across the minter → gateway → backend call chain ✅ FIXED

**Files:** Cross-cutting; `docs/ARCHITECTURE.md §8`

The architecture explicitly acknowledges: *"OpenTelemetry not yet wired."* The
only correlation mechanism across services is `X-Request-Id` reflected in enforce
responses. There is no trace context propagation (`traceparent`/`tracestate`), no
span hierarchy, and no way to join latency across service boundaries. Production
incident response is log-grep-only.

**Recommendation:** Wire the OpenTelemetry SDK with W3C trace context propagation
before Stage 4. The `GatewayDependencies` bag in `bootstrap.ts` is the correct
injection point for a tracer; no deep refactor is needed.

**Fix:** W3C trace-context fully wired via `@opentelemetry/api` and `tracing.ts`
in `@euno/common-core`. `tracingMiddleware` runs on every gateway and minter
request. `RemoteEnforcerPDP` propagates `traceparent`/`tracestate` outbound via
`injectTraceContext`. Audit log entries carry `trace_id`/`span_id` when a span is
active. Attaching an OTel SDK exporter (Jaeger, OTLP, etc.) is a config-only
deployment change — no code modification required. `docs/ARCHITECTURE.md §8`
updated.

---

## [+] Code / Implementation Feedback

### CI-1 — `parseEnforceRequestBody` passes unknown context fields through unchecked

**File:** `euno-platform/packages/tool-gateway/src/routes/enforce.ts`

The enforce-request parser performs individual `typeof` checks. Unknown fields in
`context` (beyond `sourceIp`, `recipients`, `now`) pass through silently. When
Protocol Version 2 adds new context fields, there is no structural guarantee the
parser rejects v2-only fields on a v1 gateway.

**Recommendation:** Add a strict-unknown-keys pass at the end of
`parseEnforceRequestBody` that logs unexpected fields at `debug` and rejects them
if the protocol version is ≤ the current supported version; or use a lightweight
Zod schema keyed to the protocol version.

---

### CI-2 — `usageMeter.recordEnforcement` errors are silently swallowed with no counter ✅ FIXED

**File:** `euno-platform/packages/tool-gateway/src/enforcement.ts`  
**Fix:** Added `onMeterError?: () => void` to `EnforcementEngineOptions`; the
`catch {}` block in `validateAction`'s `finally` now calls
`this.onMeterError?.()`. Bootstrap wires this to a new `euno_usage_meter_errors_total`
Prometheus counter; the `RedisUsageMeter.onError` callback also increments it on
Redis write failures.

The `finally` block in `validateAction` catches all errors from `recordEnforcement`
with an empty `catch {}` body. A billing error here is a silent business failure.

**Recommendation:** Add `this.meterErrorCounter?.inc()` inside the catch block
so failures surface in dashboards (`euno_usage_meter_errors_total`).

---

### CI-3 — Admin kill-switch "illusion of kill" when `KILL_SWITCH_FAIL_OPEN_ON_WRITE=true` ✅ FIXED

**File:** `euno-platform/packages/tool-gateway/src/admin-api.ts`

When `KILL_SWITCH_FAIL_OPEN_ON_WRITE=true` and Redis is unreachable, the admin
API returns 200 (kill appeared to succeed) but only the originating replica
applied it. An operator believing the kill is fleet-wide will not get the
containment they expect.

**Recommendation:** Return `207 Multi-Status` or a `503` with a clear message
such as `"Kill applied locally; fleet propagation pending Redis recovery"` when
`failOpenOnWrite` is active.

**Fix:** Added `killSwitchFailOpenOnWrite` field to `AdminApiOptions` and
`GatewayDependencies`. When `KILL_SWITCH_FAIL_OPEN_ON_WRITE=true`, all seven
mutating kill-switch endpoints now return `207 Multi-Status` with
`fleetPropagationPending: true` and a `warning` field explaining that the kill
was applied to this replica only and fleet-wide propagation is pending Redis
recovery. Idempotency cache stores the `207` status so retries replay the same
warning. The flag is plumbed from the env var through `initializeServices` →
`GatewayDependencies` → `createAdminApp` → `createAdminRouter`.

---

### CI-4 — Anomaly detection fires only to Prometheus; silent if Prometheus is unavailable ✅ FIXED

**File:** `euno-platform/packages/api-key-minter/src/routes/mint.ts`  
**Fix:** `AnomalyDetector.recordMint()` return value is already checked in the
mint route and a structured `logger.warn('Mint anomaly detected', { tenantId, rules })`
is emitted when `firedRules.length > 0` — both after a successful mint and after
a failure where the tenant is known. The anomaly signal is therefore preserved even
when the Prometheus scrape endpoint is unavailable.

`AnomalyDetector.recordMint` returns fired rule names which the mint route uses
to increment `anomalyAlertsTotal`. If Prometheus is unavailable, anomaly firings
vanish completely — there is no structured log entry.

**Recommendation:** Also emit a structured `logger.warn('Anomaly detected', { tenantId, rules })`
from the mint route when `firedRules.length > 0`, so the signal survives a
Prometheus outage.

---

### CI-5 — `InMemoryMintRateLimiter` for `/api/v1/ping` is per-process, not per-fleet ✅ FIXED

**File:** `euno-platform/packages/api-key-minter/src/mint-rate-limiter.ts`  
**Fix:** `RedisBackedMintRateLimiter` + `createPingRateLimiterFromEnv` factory
(see commit with "fix(minter): CI-5 Redis-backed ping rate limiter").

The `InMemoryMintRateLimiter` used as the default ping rate limiter was per-process.
Under a multi-replica minter deployment, an attacker could distribute API key prefix
enumeration requests across N replicas, achieving N × 20 req/60s before any single
replica triggered the limit.

**Resolution:** Added `RedisBackedMintRateLimiter` that uses the same
`INCR + EXPIRE` pattern as `RedisCallCounterStore` in `@euno/common-infra`, backed
by a `RedisCallCounterClient`. Added `createPingRateLimiterFromEnv(env, logger)`
factory function that selects the Redis-backed implementation when `MINTER_REDIS_URL`
or `REDIS_URL` is set, and logs a structured `warn` when falling back to the
in-memory limiter (so operators can detect the gap in production). The bootstrap
wires this factory for the ping rate limiter.

**Residual risk:** The mint rate limiter (`MintRouterOptions.rateLimiter`) still
uses `InMemoryMintRateLimiter`. Operators who need fleet-wide mint limiting should
inject a `RedisBackedMintRateLimiter` directly; a follow-up task should wire this
identically to the ping limiter.

---

### CI-6 — `POSTURE_DURABLE_QUEUE_PATH` defaults to `:memory:` ✅ FIXED

**File:** `capability-issuer/src/index.ts` (bootstrap)

Defaulting the posture emitter to `:memory:` means a crashed issuer pod loses all
pending posture inventory records, defeating the durability guarantee the WAL
design exists to provide.

**Recommendation:** Change the default to a required env var with a hard startup
error in `NODE_ENV=production`, and document `POSTURE_DURABLE_QUEUE_PATH=/var/lib/euno/posture-queue.db`
in the deployment docs and k8s ConfigMap template.

**Fix:** `DurablePostureEmitter.fromEnv` now throws a hard `Error` when
`POSTURE_DURABLE_QUEUE_PATH` is unset and `NODE_ENV=production`. Non-production
environments (dev, test, CI) still fall back to `:memory:` with a warn that
includes the new production behaviour note.

---

### CI-7 — Audit ledger HMAC secret rotation procedure is undocumented ✅ FIXED

**File:** `euno-platform/packages/common-infra/src/ledger-signer.ts`

The per-row `row_hmac` is a tamper-detection mechanism whose secret has no documented
rotation procedure. Rotating the secret invalidates every existing row's HMAC,
breaking tamper detection for historical records unless old secrets are retained.

**Recommendation:** Write a `docs/runbooks/ledger-hmac-rotation.md` specifying a
`verifyHmac(oldSecret)` fallback path during the rotation window, and document the
provisioning source for `hmacSecret` in the deployment docs.

**Fix:** Created `docs/runbooks/ledger-hmac-rotation.md` covering secret provisioning,
three rotation strategies (new table, dual-secret backfill, per-row versioning),
environment variables, Kubernetes/Helm deployment snippets, and cross-references.

---

### CI-8 — JWKS cache `kid`-miss can cause a fan-out stampede to the issuer on key rotation ✅ FIXED

**File:** `euno-platform/packages/tool-gateway/src/verifier.ts` (JwksClient usage)

On key rotation, all in-flight tokens with the new `kid` arrive simultaneously at
a cache that still holds the old key set, triggering concurrent JWKS refreshes.
There is no singleflight coalesce. Under a hot deployment (many replicas, high
token rate), this creates an N × M fan-out to the issuer's JWKS endpoint.

**Recommendation:** Implement a singleflight pattern on `kid`-miss: only one
outstanding JWKS refresh per `kid` at a time per replica. The others wait on the
same promise and resolve from the refreshed cache.

**Fix:** Added a `kidPendingRefreshes: Map<string, Promise<JwkKey>>` to `JwksClient`.
`getKeyByKid` now stores the pending refresh promise in the map before awaiting,
so any concurrent caller for the same unknown `kid` joins the same promise rather
than issuing a second HTTP request. The map entry is cleared after resolution
(success or failure) using a `finally` block.

---

## [?] Open Questions

### OQ-1 — How is the audit ledger HMAC secret provisioned and rotated in production? ✅ FIXED

The schema stores `row_hmac = HMAC-SHA256(hmacSecret, ...)`. The design doc refers
to it as "a separate credential, distinct from the signing key" but there is no
corresponding env-var entry in `schema.ts` or provisioning runbook.

**Fix:** `AUDIT_LEDGER_HMAC_SECRET` is present in `schema.ts` (see
`public/packages/common/src/config/schema.ts`) and documented in
`docs/runbooks/ledger-hmac-rotation.md` (CI-7), which covers secret generation
(`openssl rand -hex 32`), accepted formats, three rotation strategies (new table,
dual-secret backfill, per-row versioning), Kubernetes/Helm examples, and guidance
on storing the secret in a secrets manager. See also
`docs/DEPLOYMENT.md §"Audit Ledger backend selection"` for the provisioning
quick-reference.

---

### OQ-2 — What is the per-tenant multi-tenancy isolation model at the minter DB level? ✅ FIXED

The `api_keys` table has a `tenant_id` column but the minter appears to use a
single Postgres database with no row-level security. Application-layer filtering is
the only isolation mechanism. Is Postgres RLS a planned hardening step?

**Fix:** Documented in `docs/DEPLOYMENT.md §"Minter database multi-tenancy
isolation"`. The current model (application-layer `WHERE tenant_id = $1` on every
query) is correct and defended in depth by the API key credential structure, but
relies on the application never issuing a cross-tenant query. The deployment guide
now provides a complete RLS migration script (`ENABLE ROW LEVEL SECURITY` +
`CREATE POLICY ... USING (tenant_id = current_setting('euno.tenant_id', true))`)
for operators who want the database to enforce the `tenant_id` boundary as a
second layer of isolation. The guide clearly notes that full wiring of the
`SET LOCAL euno.tenant_id = ...` session parameter in application code is a
follow-on hardening task.

---

### OQ-3 — What is the cross-replica kill-switch staleness SLA during a pub/sub outage?

The design documents a 30-second worst-case staleness bound
(`KILL_SWITCH_REFRESH_INTERVAL_MS`). For security incidents requiring immediate
kill, this window is significant. Is 30 seconds the documented SLA for Cloud
Team/Enterprise tiers?

---

### OQ-4 — Is `context.now` used for `timeWindow` enforcement on the gateway's own clock?

`validateClockSkew` rejects divergence > 60 s but does not substitute the gateway
clock into the enforcement context. Does `enforceConditions` use the
client-supplied `context.now` or `Date.now()` when evaluating `timeWindow`
conditions? This should be explicit and tested.

---

### OQ-5 — Is the DPoP `cnf.jkt` ↔ proof JWK binding explicitly checked and tested? ✅ FIXED

DPoP verification must confirm that the `cnf.jkt` in the capability token matches
the `jwk` thumbprint in the DPoP proof header. If the proof's JWK is not bound to
the token's `cnf.jkt`, a token can be presented with an attacker-controlled JWK.
Is this binding check present and covered by tests?

**Fix:** Added an `OQ-5: cnf.jkt ↔ proof JWK binding` describe block to
`enforcement.test.ts` with three security regression tests: (a) a different-key
proof is rejected with a "does not match" error; (b) a matching-key proof is
accepted; (c) a proof attached to a non-sender-constrained bearer token (no
`cnf.jkt`) is ignored rather than rejected.

---

### OQ-6 — Is there a cross-tenant token replay guard beyond `aud` claim checking?

In a multi-tenant hosted gateway where all tenants share the same gateway instance,
only the `tenantId` in `authorizedBy` separates them. Is the enforcement engine
validated to never allow a token carrying tenant A's `tenantId` to enforce policies
for tenant B's resources?

---

## Execution Plan (Priority × Dependency Order)

| Priority | Item | Dependency | Effort |
|----------|------|------------|--------|
| P0 | **CR-5** Obtain minter threat model sign-off before merging | None | Process |
| P0 | ~~**CR-2** Fix `sourceIp` trust boundary~~ ✅ Done | — | — |
| P0 | ~~**CR-1** Wire durable `UsageMeter` backend (Redis or Postgres)~~ ✅ Done | — | — |
| P0 | ~~**DI-1** Close GCP per-tenant key isolation (Task 11)~~ ✅ Done | — | — |
| P1 | **CR-3** Mandate Redis Sentinel/Cluster in prod k8s | k8s/redis.yaml | Medium |
| P1 | **CR-4** Redis-backed `AnomalyDetector` (or document per-replica limitation) | Redis infra | Medium |
| P1 | ~~**CI-3** Admin kill-switch "illusion of kill" — return 207/503 when fail-open~~ ✅ Done | admin-api.ts | Small |
| P1 | ~~**CI-6** Change `POSTURE_DURABLE_QUEUE_PATH` default to required in prod~~ ✅ Done | index.ts | Small |
| P2 | ~~**DI-5** Wire OpenTelemetry distributed tracing~~ ✅ Done | — | — |
| P2 | ~~**DI-4** Change telemetry default to opt-in; update network policy~~ ✅ Done | gateway-telemetry.ts | Small |
| P2 | ~~**DI-2** Benchmark advisory lock; promote `PerReplicaPostgresLedgerBackend`~~ ✅ Done | — | — |
| P2 | ~~**CI-8** Add singleflight coalesce on JWKS `kid`-miss~~ ✅ Done | jwks-client.ts | Small |
| P2 | ~~**CI-7** Write `hmacSecret` rotation runbook for the audit ledger~~ ✅ Done | Docs | Small |
| P2 | ~~**DI-3** Wire `AdminIdempotencyStore` Redis backend; add startup warning~~ ✅ Done | admin-api.ts | Small |
| P3 | ~~**CI-2** Add `euno_usage_meter_errors_total` counter~~ ✅ Done | — | — |
| P3 | ~~**CI-4** Log structured `warn` when anomaly fires (not only Prometheus)~~ ✅ Done | — | — |
| P3 | ~~**CI-5** Redis-backed ping rate limiter~~ ✅ Done | — | — |
| P3 | ~~**OQ-1/2** Document HMAC secret provisioning; add Postgres RLS hardening option~~ ✅ Done | — | — |
| P3 | ~~**OQ-5** Add explicit test for DPoP `cnf.jkt` ↔ proof JWK binding~~ ✅ Done | tests/ | Small |

---

## Overall Assessment

The architectural foundations are strong: the capability-native trust model,
fail-closed defaults, defence-in-depth layering (AGT + gateway + kill-switch +
audit), and the pluggable adapter pattern for cloud portability are all
well-considered and consistently implemented. The most acute risks are in the
**operationalization layer**: distributed state consistency under partial failures
(CR-3), billing meter durability (CR-1), and the `sourceIp` trust boundary
(CR-2, now fixed). Addressing the remaining P0/P1 items before Stage 3 ships to
paying customers is the critical path.
