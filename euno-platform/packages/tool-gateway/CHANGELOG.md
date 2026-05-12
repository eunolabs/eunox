# Changelog — @euno/tool-gateway

All notable changes to this package are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased — Stage 3, Task 18] — Reference Materials & Migration Guide

### Added

- **`docs/migrating-from-local.md`** — new comprehensive migration guide for
  operators and developers upgrading from `@euno/mcp` local-enforcement mode to
  the hosted gateway.  Covers:
  - Before/after configuration examples (the one-config-change upgrade).
  - The cryptographic story: why the `sk-...` API key is not a JWT capability
    token and how the minter façade preserves the cryptographic-token invariant
    (API key → minter → HSM-signed JWT → gateway PDP).
  - **Explicit data-boundary analysis** (the SOC2/GDPR gating question): exactly
    which fields in `EnforceRequest` leave the customer's network on every
    `tools/call` (`sessionId`, `toolName`, `arguments`, `context.sourceIp`,
    `context.recipients`), which data stays local (upstream MCP server responses,
    raw `sk-...` key material, HSM signing key material, local HMAC audit log),
    and a network topology diagram showing that the gateway never reaches the
    upstream MCP server.
  - Step-by-step migration procedure with an optional parallel smoke-test phase.
  - Manual migration recipe using the admin API directly.
  - Rollback procedure (instantaneous — re-add `--policy`, no gateway changes needed).
  - Self-host alternative for teams with strict data-residency requirements.
  - FAQ: policy file format reuse, fail-closed on gateway unavailability,
    self-issued JWTs for self-host, local audit log fate, custom conditions.

- **`docs/README.md`** — added `migrating-from-local.md` and `self-host.md` to the
  "Deployment and operations" section of the documentation index.

### Changed

- **`README.md`** — added "Hosted gateway (Stage 3)" sub-section under "What you get"
  showing the one-config-change diff and linking to the migration guide.  Project
  Status table updated to reflect Stage 3 as in progress.  Documentation section
  updated to link `migrating-from-local.md` and `self-host.md`.

- **`public/packages/mcp/README.md`** — added a callout block in the Stage-3
  remote-enforcer section directing users to `docs/migrating-from-local.md` for
  the step-by-step guide and SOC2/GDPR data-boundary analysis.

---

## [Unreleased — Stage 3, Task 13] — Self-Hostable Docker Image

### Summary

Task 13 ships a production-ready self-hosted deployment story for the tool
gateway. The key deliverables are:

1. **Fixed Dockerfiles** (`tool-gateway` and `capability-issuer`) — corrected
   the multi-stage build to include all required workspace packages
   (`@euno/common-core`, `@euno/common-infra`, `@euno/capability-issuer`).
   The previous Dockerfiles omitted these packages, causing build failures.

2. **Canonical local stack** (`infra/docker-compose.yml`) — brings up the
   gateway with Redis + Postgres (full stack) or in-memory dev mode with a
   single `--profile` flag. Also includes a smoke-test profile that exercises
   core endpoints after the stack is healthy.

3. **Smoke-test target** (`infra/smoke-test.sh`) — exercises health, metrics,
   JWKS, and authentication-enforcement endpoints; used by the `smoke` profile
   in docker-compose.yml.

4. **Self-host configuration tests** (`tests/self-host-config.test.ts`) — 39
   new unit tests covering `loadConfigFromEnv`, `resolveAllowedOrigins`,
   `deriveIssuerMetadataUrl`, `checkActionResolverHashParity`, and backend
   environment-variable profiles (dev/in-memory, full Redis+Postgres, smoke).

### Added

**`infra/docker-compose.yml`** — canonical local stack with three runtime profiles:

- Default (no `--profile` flag): gateway only (capability-issuer + gateway).
  All control-surface stores use in-memory fallbacks; no Redis or Postgres
  required.  Suitable for local development and quick-start exploration.

- `--profile full`: adds `redis` and `postgres` services and wires the gateway
  to use them (`REDIS_URL=redis://redis:6379`, `AUDIT_LEDGER_BACKEND=postgres`).
  Auto-runs schema migrations (`AUDIT_LEDGER_RUN_MIGRATIONS=true`).  Suitable
  for integration testing and pre-production validation.

- `--profile smoke`: starts the full stack and runs `infra/smoke-test.sh` as an
  `alpine/curl`-based service after all health-checks pass.  Use with
  `--abort-on-container-exit` for CI smoke-gate usage.

**`infra/smoke-test.sh`** — portable POSIX shell script that exercises:
- Gateway liveness (`/health`), liveness (`/health/live`), readiness
  (`/health/ready`)
- Issuer JWKS endpoint (`/.well-known/jwks.json`)
- Authentication enforcement (unauthenticated POST to `/api/v1/tools/invoke`
  and `/api/v1/enforce` must return 401)
- Prometheus metrics (`/metrics` includes `euno_gateway_decisions_total`)
- Exits 0 on success, 1 on any failure.  Can be run standalone against any
  running gateway:
  ```sh
  GATEWAY_URL=http://localhost:3002 sh infra/smoke-test.sh
  ```

**`tests/self-host-config.test.ts`** — 39 new tests covering:
- `loadConfigFromEnv`: dev profile (minimum required vars), production profile
  (ADMIN_HOST, ADMIN_API_KEY, evidence-signing constraints), `EUNO_DEPLOYMENT_TIER`
  validation (single-replica vs multi-replica vs production enforcement).
- `resolveAllowedOrigins`: CORS defaults per environment, custom origin
  override.
- `deriveIssuerMetadataUrl`: URL derivation from JWKS URL, explicit override,
  empty/whitespace guard, localhost port preservation.
- `checkActionResolverHashParity`: non-fatal behaviour on network error,
  non-OK HTTP status, missing `actionResolverHash` field; warn vs error
  enforcement modes.
- Docker-compose backend profile parity: confirms the env vars used in
  `docker-compose.yml` (`dev`, `full`, `smoke` profiles) are accepted by the
  config schema.

### Fixed

**Dockerfiles** (`packages/tool-gateway/Dockerfile`,
`packages/capability-issuer/Dockerfile`):
- Added `public/packages/common` (`@euno/common-core`) to the build so
  `export * from '@euno/common-core'` in `@euno/common/src/index.ts` resolves.
- Added `euno-platform/packages/common-infra` (`@euno/common-infra`) to the
  build for the same reason.
- Fixed build order: `@euno/common-core` → `@euno/common-infra` → `@euno/common`
  → `@euno/capability-issuer` → `@euno/tool-gateway`.
- Added `@euno/capability-issuer` workspace package to the tool-gateway
  Dockerfile (it is a runtime dependency and must be present in production).
- Added `EXPOSE 3003` for the admin port (previously undocumented in the image
  metadata).
- Added OCI image labels (`org.opencontainers.image.*`).
- Health-check now reads `PORT` env var instead of hardcoding `3002`.

**`euno-platform/packages/integration-tests/jest.config.js`**:
- Added `@euno/common-infra` and `@euno/common-core` to `moduleNameMapper` and
  the `ts-jest` `tsconfig.paths` object so that integration tests can resolve
  `@euno/common` (which re-exports both) without a pre-built `dist/`.
- Previously all 5 integration test suites failed with
  `Cannot find module '@euno/common-infra'`; all 31 tests now pass.

---

## [Unreleased — Stage 3, Task 9] — Hosted Enforcement HTTP Contract

### Summary

Task 9 defines and implements the wire protocol for `@euno/mcp` remote-enforcer
mode. The gateway now exposes `POST /api/v1/enforce` — the endpoint called on
every intercepted `tools/call` when `@euno/mcp` is configured with
`enforcer: "https://..."`. Decisions (allow or deny) and any obligations
(`redactFields`) are returned in a structured `EnforceResponse` so the
proxy can apply them locally without throwing.

### Added

**Wire-protocol types (`@euno/common-core`)**

- `EnforceRequest` — typed request envelope: `sessionId`, `toolName`,
  `arguments`, `context` (`EnforceRequestContext`).
- `EnforceRequestContext` — per-request context: `sourceIp`, `recipients`,
  `now` (ISO-8601, clock-skew guard).
- `EnforceResponse` — typed response envelope: `requestId`, `decision`,
  optional `obligations[]`, optional `denial`, `decidedAt`.
- `Obligation` — discriminated union: `{ type: 'redactFields'; paths }` and
  `{ type: 'annotate'; key; value }`.
- `DenialInfo` — structured denial: `code`, `conditionType`, `message`,
  optional `details`.
- `ENFORCE_PROTOCOL_VERSION` (`1`) — current monotonic protocol version
  constant.
- `SUPPORTED_ENFORCE_PROTOCOL_VERSIONS` — `ReadonlySet<number>` of all
  gateway-accepted protocol versions; checked on every request.

**New error codes (`ErrorCode` in `@euno/common-core`)**

- `UNSUPPORTED_PROTOCOL_VERSION` — `X-Euno-Protocol-Version` header carries
  a version the gateway does not recognise; HTTP 400.
- `GATEWAY_UNAVAILABLE` — transient infrastructure failure; HTTP 503.
- `REQUEST_TOO_LARGE` — request body exceeds 512 KiB; HTTP 413.
- `PERMISSION_DENIED` — valid key without the required scope; HTTP 403.
- `MISSING_CONTEXT` — a condition required a context field (e.g. `sourceIp`
  for `ipRange`) that was absent; returned inside an `EnforceResponse` (HTTP
  200, `decision: 'deny'`).
- `ARGUMENT_SCHEMA_VIOLATION` — tool call arguments failed the capability's
  `argumentSchema`; returned inside an `EnforceResponse`.

**Gateway route (`tool-gateway/src/routes/enforce.ts`)**

- `POST /api/v1/enforce` — the remote-enforcer endpoint.
  - `X-Euno-Protocol-Version` negotiation: echoed in every response; missing
    header defaults to version 1 (back-compat); unsupported versions → 400
    with `supportedVersions[]` in the error body.
  - `Authorization: Bearer <jwt>` required; 401 when absent or invalid.
  - 512 KiB body size guard (checked via `Content-Length` header); 413 on
    exceedance.
  - Full structural validation of `EnforceRequest` body fields.
  - 60-second `context.now` clock-skew guard; `INVALID_REQUEST` on violation.
  - Server-side action + resource derivation from `toolName` (never trusts
    client-supplied action/resource strings).
  - In-band deny for all 4xx CapabilityErrors except 401 (which stays out-of-
    band); 503 CapabilityErrors also remain out-of-band.
  - `obligations[]` built from matched capability's `redactFields` conditions.
  - `requestId` echoed from `X-Request-Id` or auto-generated (UUID).
  - `decidedAt` always stamped from the gateway's authoritative clock.

**Documentation (`docs/stage-3-gateway-protocol.md`)**

- Complete protocol specification: configuration, endpoint, request/response
  schemas, HTTP status codes, protocol versioning rules, authentication and
  session lifecycle, policy caching, error-class taxonomy, and the
  backward-compatibility promise.
- Server-side translator contract for future version bumps.
- Backward-compat promise: the `EnforceRequest`/`EnforceResponse` shapes are
  additive-only within version 1; clients MUST tolerate unknown `Obligation`
  types and unknown `DenialInfo.code` values.

**Tests (`tests/enforce.test.ts`)**

- 32 unit tests covering: protocol version negotiation (missing, valid,
  unsupported, non-integer, zero), authentication (absent header, invalid
  JWT), body validation (all required-field cases, array arguments, invalid
  context types, clock-skew guard), allow decisions (matching capability, with
  and without obligations, `requestId` echoing and auto-generation,
  `decidedAt`), deny decisions (no matching capability, wrong audience,
  JWT verification failure, `decidedAt`), kill-switch in-band deny
  (`AGENT_TERMINATED`, `conditionType: 'killSwitch'`), `timeWindow` condition
  (expired → deny, active → allow), and `sourceIp` forwarding (CIDR allow and
  deny).

### Changed

- `app-factory.ts` — mounts `createEnforceRouter` after the existing
  `createToolsRouter`.

---

## [Unreleased — Stage 3, Task 6] — Kill-Switch Durable Persistence
---

## [Unreleased — Stage 3, Task 8] — Admin API Hardening

### Summary

Task 8 audits and hardens the admin API (kill-switch, revocation, revocation
epoch) across three orthogonal dimensions:

1. **Tenant scoping** — A gateway configured with `ADMIN_TENANT_ID` now
   enforces that every mutating request carries a `tenantId` body field that
   matches the configured tenant.  A mismatch returns HTTP 403 `TENANT_MISMATCH`
   so a credential issued for tenant A cannot kill or revoke resources belonging
   to tenant B.  Global operations (activate/deactivate global kill switch, reset
   all) additionally require `acknowledgesCrossTenantImpact: true` because they
   affect all tenants on the gateway instance; the explicit field forces
   operators to be deliberate about the blast radius.

2. **Idempotency keys** — All mutating endpoints now honour the
   `Idempotency-Key` request header.  The first call stores its response in an
   in-memory `AdminIdempotencyStore` (24-hour TTL, configurable via
   `idempotencyStore` option).  Subsequent requests with the same key against
   the same endpoint return the cached response without re-executing the
   operation.  Reusing a key against a *different* endpoint is rejected with
   HTTP 422 `IDEMPOTENCY_KEY_REUSE`.

3. **OCSF audit trail** — All mutating admin actions now emit an OCSF
   Authorization event (class_uid 3003) to the `ocsfTransport` configured on
   the admin router.  Activity, severity, targets, actor, and status are
   populated so SIEMs can ingest admin actions without a Euno-specific parser.
   Failed cross-tenant operations are emitted as Failure events (activity_id=2,
   severity_id=4) so attempted cross-tenant abuses are visible in SIEM dashboards.

### Added

**`admin-api.ts`**

- `AdminIdempotencyStore` — exported class with configurable TTL and max-size;
  prunes expired entries lazily on insert.
- `AdminApiOptions.tenantId?: string` — when set, all mutating endpoints
  enforce tenant isolation.
- `AdminApiOptions.ocsfTransport?: OcsfAuditTransport` — when set, every
  mutating operation emits an OCSF Authorization event.
- `AdminApiOptions.idempotencyStore?: AdminIdempotencyStore` — optional
  injected store; defaults to a fresh in-process store per router instance.
- `Idempotency-Key` header support on all mutating endpoints.
- `X-Admin-Operator` header is now recorded in OCSF `actor.user.uid` as well
  as in the existing Winston audit-chain entry.
- `auditEventId` field added to all Winston audit-chain entries so events can
  be correlated with OCSF events by their shared UUID.

**`bootstrap.ts`**

- `GatewayDependencies.adminTenantId?: string` — populated from
  `ADMIN_TENANT_ID` and forwarded to `createAdminApp`.

**`app-factory.ts`**

- `createAdminApp` wires `tenantId: deps.adminTenantId` and
  `ocsfTransport: deps.ocsfTransport` into `createAdminRouter`.

**Config schema (`@euno/common-core`)**

- `ADMIN_TENANT_ID` — new optional gateway env var with full description
  of its scoping semantics.

**Documentation**

- `docs/ADMIN_API_CURL_RECIPES.md` — comprehensive curl recipe reference
  covering all admin endpoints with idempotency-key, tenant-scope, and
  operator-attribution examples.

**Tests (`tests/admin-api.test.ts`)**

- 31 new tests covering tenant scoping (rejection on missing/mismatched
  tenantId, acknowledgement required for cross-tenant operations, pass-through
  when tenant scoping is disabled), idempotency (replay without re-execution,
  key-reuse rejection, no-header baseline), OCSF event shape/content
  (class_uid, activity_id, severity_id, resources, actor, unmapped.tenantId,
  Failure events on rejection), and `AdminIdempotencyStore` unit tests (TTL
  expiry, overwrite, unknown-key).

---


### Summary

Task 6 completes the kill-switch durable-persistence story, verifies
the existing Redis+Postgres dual-write implementation with a comprehensive
test suite, adds kill-switch observability to the Prometheus metrics
surface, and strengthens the admin-API audit trail.

### Added

**Kill-switch test suite (`@euno/common-infra`)**

- `src/__tests__/redis-kill-switch.test.ts` — 53 unit tests covering:
  - `PostgresKillSwitchBackend`: `load`, `activateGlobalKill`,
    `deactivateGlobalKill`, `killSession`, `reviveSession`, `killAgent`,
    `reviveAgent`, `resetAll`, `migrate` (idempotent), `close`,
    table-name validation (special-character rejection, schema-qualified
    acceptance), and mixed-type round-trips.
  - `RedisKillSwitchManager` — basic operations: initial state, activate /
    deactivate global kill, session kill / revive, agent kill / revive,
    `resetAll`, `getStatus`, Redis write-through.
  - Dual-write to Postgres: every mutation (activate global, kill session,
    kill agent, revive session, revive agent, resetAll) is mirrored to the
    `PostgresKillSwitchBackend`; writes are serialised so a rapid
    kill → revive sequence lands in Postgres in the same order.
  - **Kill switch survives Redis unavailability or flush**: two complementary
    scenarios are tested. (a) Redis is *unreachable* at startup — the initial
    `refresh()` throws and the manager falls back to Postgres, seeding its
    cache from the durably stored kill state. (b) Redis is *reachable but
    empty* (e.g. after a `FLUSHALL` or cold Redis restart) — `refresh()`
    succeeds with empty state and the manager detects the empty cache and
    seeds from Postgres. Both paths leave the kill switch intact.
    A third test verifies that a non-empty Redis is *not* overlaid with
    Postgres data (authoritative Redis is always preferred over Postgres when
    Redis has content).
  - Periodic-refresh Postgres fallback: when a `refresh()` call finds Redis
    unavailable, the manager falls back to Postgres and preserves kill state.
  - Bounded-latency persistence: all three mutations (global, session, agent)
    mirror to Postgres within a single event-loop drain (< 1 s on CI).
  - Pub/sub cross-replica propagation: kill/revive/reset issued on pod-A
    propagate to pod-B's cache via the pub/sub bridge in the same event-loop
    turn; pod-B ignores echoes of its own events, malformed payloads, and
    unknown protocol versions.
  - Fail-closed semantics (default): when a Redis write fails the optimistic
    cache update is reverted so the kill does not stick locally.
  - Fail-open semantics (`failOpenOnWrite: true`): when a Redis write fails
    the local cache is kept; the kill sticks on this replica.
  - Lifecycle: `start()` and `close()` are idempotent; `refresh()` without a
    persistence backend propagates the Redis error to the caller.
  - `createKillSwitchManagerFromEnv`: returns `DefaultKillSwitchManager`
    when `REDIS_URL` is not set; attempts `RedisKillSwitchManager` when it
    is; throws in production mode when ioredis is absent.

**Kill-switch admin API tests (`@euno/tool-gateway`)**

- `tests/admin-api.test.ts` — new kill-switch describe block covering all 8
  admin endpoints:
  - `GET /admin/kill-switch/status`: initial state, reflected active kills,
    API-key authentication.
  - `POST /admin/kill-switch/global/activate`: activates global kill,
    idempotent, blocks `shouldBlock`.
  - `POST /admin/kill-switch/global/deactivate`: deactivates global kill,
    idempotent.
  - `POST /admin/kill-switch/session/:sessionId/kill`: kills named session,
    does not affect other sessions.
  - `POST /admin/kill-switch/session/:sessionId/revive`: revives killed
    session, idempotent on already-alive sessions.
  - `POST /admin/kill-switch/agent/:agentId/kill`: kills named agent, does
    not affect other agents.
  - `POST /admin/kill-switch/agent/:agentId/revive`: revives killed agent.
  - `POST /admin/kill-switch/reset`: clears all kills, idempotent.
  - Full round-trip: activate + per-entity kills → status check → reset →
    status check.

**Prometheus kill-switch observability (`bootstrap.ts`)**

Three new gauges registered in the gateway's Prometheus registry (Step 6):

| Metric | Description |
|---|---|
| `euno_gateway_kill_switch_active{global_kill="1"}` | 1 when the global kill is engaged; 0 otherwise. |
| `euno_gateway_kill_switch_active{global_kill="0"}` | 1 when any per-entity (session or agent) kill is active; 0 otherwise. |
| `euno_gateway_kill_switch_killed_sessions` | Count of session IDs currently in the kill list. |
| `euno_gateway_kill_switch_killed_agents` | Count of agent IDs currently in the kill list. |

**OCSF audit logging for kill-switch mutations (`admin-api.ts`)**

All seven kill-switch mutation endpoints now emit structured OCSF audit-log
events via `auditLogger` (in addition to the existing `logger.*` calls).
Each event includes an `eventType` field, the subject entity
(`sessionId` / `agentId`), and the `operator` identity resolved from
`X-Admin-Operator` (or `'unknown'` when the header is absent).

| Endpoint | `eventType` | Level |
|---|---|---|
| `POST /kill-switch/global/activate` | `kill_switch_global_activated` | `warn` |
| `POST /kill-switch/global/deactivate` | `kill_switch_global_deactivated` | `info` |
| `POST /kill-switch/session/:id/kill` | `kill_switch_session_killed` | `warn` |
| `POST /kill-switch/agent/:id/kill` | `kill_switch_agent_killed` | `warn` |
| `POST /kill-switch/session/:id/revive` | `kill_switch_session_revived` | `info` |
| `POST /kill-switch/agent/:id/revive` | `kill_switch_agent_revived` | `info` |
| `POST /kill-switch/reset` | `kill_switch_reset_all` | `warn` |

### Changed

- `admin-api.ts` — kill-switch route handlers now receive the `req` object
  (previously `_req`) so `resolveOperator(req)` can be called for audit
  attribution.
