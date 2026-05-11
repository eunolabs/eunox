# Changelog — @euno/tool-gateway

All notable changes to this package are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased — Stage 3, Task 6] — Kill-Switch Durable Persistence

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
