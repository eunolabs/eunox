# Distributed Kill Switch

## Overview

The Tool Gateway exposes an emergency kill switch with three scopes:

* **Global** — block every agent request.
* **Session** — block every request whose `context.sessionId` matches.
* **Agent** — block every request whose JWT `sub` (agent DID) matches.

The default implementation (`DefaultKillSwitchManager`) keeps this state
in **process-local memory only**. That is sufficient for development and
single-instance deployments, but it is **not safe for any HA
deployment**: a kill issued through `POST /admin/kill-switch/...` on
gateway pod A will not block requests routed to pod B.

This document describes the production-grade Redis-backed alternative
(`RedisKillSwitchManager`) that ships in `@euno/common`, and the
operational guidance for running it.

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Gateway       │     │   Gateway       │     │   Gateway       │
│   Pod 1         │     │   Pod 2         │     │   Pod 3         │
│ ┌─────────────┐ │     │ ┌─────────────┐ │     │ ┌─────────────┐ │
│ │ local cache │ │     │ │ local cache │ │     │ │ local cache │ │
│ └──────▲──────┘ │     │ └──────▲──────┘ │     │ └──────▲──────┘ │
└────────┼────────┘     └────────┼────────┘     └────────┼────────┘
         │ write-through         │ pub/sub event         │ pub/sub event
         │ on admin call         │ (sub-second)          │ (sub-second)
         │ + PUBLISH             │ + 30 s safety net     │ + 30 s safety net
         └───────────────┬───────┴───────────────────────┘
                         ▼
              ┌─────────────────────────────────────┐
              │               Redis                 │
              │  <prefix>global                     │
              │  <prefix>killed_sessions  (SET)     │
              │  <prefix>killed_agents    (SET)     │
              │  <prefix>events           (PUB/SUB) │
              │  (prefix = KILL_SWITCH_KEY_PREFIX,  │
              │   default "killswitch:")            │
              └─────────────────────────────────────┘
```

`KillSwitchManager` is a **synchronous** interface because
`shouldBlock()` is consulted on the hot path of every authorization
decision. To keep that contract while sharing state across pods,
`RedisKillSwitchManager` maintains an in-memory snapshot kept fresh by
three complementary mechanisms, in priority order:

1. **Write-through (issuing pod).** Every mutating call
   (`activateGlobalKill`, `killSession`, `killAgent`, `reviveSession`,
   `reviveAgent`, `resetAll`) writes to Redis first, then updates the
   local cache. The issuing pod observes its own change immediately.
2. **Pub/sub (every other pod, *primary*).** After a successful Redis
   write the issuing pod publishes a granular event on the
   `<KILL_SWITCH_KEY_PREFIX>events` channel. Every replica subscribes
   to that channel and applies the event to its local cache the moment
   it arrives — typically in single-digit milliseconds end-to-end. This
   is what makes "kill switch now" actually mean *now*: a kill issued
   on pod A during an active exfiltration is honoured cluster-wide
   before the next outbound request from pod B can complete. Each pod
   tags its own publishes with a per-process `instanceId` and ignores
   echoes of its own events (the local cache is already correct).
3. **Periodic refresh (every pod, *safety net*).** A background timer
   pulls the full state from Redis every
   `KILL_SWITCH_REFRESH_INTERVAL_MS` (default **30 s** now that pub/sub
   is the primary mechanism). Redis pub/sub is at-most-once and is
   **not** delivered to subscribers that are momentarily disconnected,
   so this timer is the convergence guarantee for any dropped message
   and re-seeds pods that have just reconnected to Redis.
4. **Initial seed.** On startup the cache is hydrated from Redis so a
   fresh pod does not start in a "no kills" state if kills are already
   in effect cluster-wide. The subscriber is wired up *before* the
   initial refresh so events emitted during start-up are not silently
   dropped.

### Event schema

Pub/sub messages are JSON, intentionally small, and forward-compatible:

```json
{ "v": 1, "src": "<instanceId>", "op": "kill_session", "id": "sess-123" }
```

`op` is one of `activate_global`, `deactivate_global`, `kill_session`,
`revive_session`, `kill_agent`, `revive_agent`, `reset_all`. Unknown
schema versions or `op` values are dropped silently — the periodic
refresh safety net guarantees convergence.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `REDIS_URL` | _(unset)_ | Redis endpoint. **Required** to enable the distributed kill switch. The same URL is reused for distributed revocation. |
| `KILL_SWITCH_KEY_PREFIX` | `killswitch:` | Prefix for kill-switch Redis keys *and* the pub/sub channel (`<prefix>events`). Override to share a Redis instance between multiple environments. |
| `KILL_SWITCH_REFRESH_INTERVAL_MS` | `30000` | Safety-net refresh interval. Pub/sub handles real-time propagation; this timer covers dropped pub/sub messages. Lower = faster recovery from a lost message at the cost of more Redis traffic. Set to `0` to disable periodic refresh (pub/sub-only — only safe if you understand the at-most-once delivery semantics). |
| `KILL_SWITCH_FAIL_OPEN_ON_WRITE` | `false` | When `true`, kill-switch writes that fail against Redis still update the local cache so this pod honours the operator's intent. Other pods only see the kill once Redis recovers. When `false`, write errors propagate so the admin API surfaces a 500. |
| `KILL_SWITCH_PUBSUB_ENABLED` | `true` | When `true` (default) the gateway opens a second Redis connection in subscribe mode and broadcasts mutations on `<KILL_SWITCH_KEY_PREFIX>events`. Disable only if you have a strict connection budget on managed Redis and accept that propagation falls back to the periodic refresh interval. |

Write failures are intentionally explicit. With the default
`KILL_SWITCH_FAIL_OPEN_ON_WRITE=false`, an admin API request that cannot write
to Redis fails and the operator should retry after fixing Redis connectivity.
With `true`, the request succeeds locally and only the current pod enforces the
kill until Redis recovers; operators should treat that mode as emergency
single-pod containment, not cluster-wide confirmation.

When `REDIS_URL` is unset the gateway logs:

```
REDIS_URL not configured, using in-memory kill-switch manager
```

and falls back to `DefaultKillSwitchManager`. Likewise, if
`REDIS_URL` is set but the `ioredis` package is not installed the
gateway logs an error and falls back to the in-memory manager so the
service can still come up — operators must still install `ioredis` to
get the distributed behaviour.

## Schema

`RedisKillSwitchManager` stores three persistent keys and one pub/sub
channel (with the configured prefix):

* `<prefix>global` — string `"1"` if the global kill is active; deleted
  otherwise.
* `<prefix>killed_sessions` — Redis `SET` of killed session ids.
* `<prefix>killed_agents` — Redis `SET` of killed agent ids.
* `<prefix>events` — Redis pub/sub channel for real-time invalidation
  events. Messages are small JSON objects (see Event schema above).
  This channel is never persisted; it is purely a delivery mechanism.

Sets are used (rather than per-id keys) so the entire population can be
refreshed in one round trip (`SMEMBERS`) and so revives are atomic
(`SREM`). Kill switches have no natural TTL — they remain in effect
until an operator explicitly revives them — so we deliberately do not
put TTLs on these keys. Operators are expected to use the admin API
(`POST /admin/kill-switch/.../revive`, `POST /admin/kill-switch/reset`)
or `redis-cli DEL`/`SREM` for cleanup.

## Failure semantics

* **Reads** are always served from the local cache and therefore never
  fail. Normal freshness is bounded by pub/sub delivery latency
  (single-digit milliseconds intra-DC). Worst-case freshness after a
  dropped pub/sub message is bounded by `KILL_SWITCH_REFRESH_INTERVAL_MS`
  (default 30 s).
* **Writes** propagate Redis errors by default (`failOpenOnWrite=false`)
  so the admin API returns 500 and operators know the kill did not
  stick. Set `KILL_SWITCH_FAIL_OPEN_ON_WRITE=true` only when local
  enforcement on the issuing pod is acceptable while Redis is
  unreachable.
* **Publish failures** are non-fatal. If the `PUBLISH` after a write
  fails (e.g. Redis is briefly unreachable after the `SET`/`SADD`
  succeeds), the write is already durable in Redis; remote replicas
  will converge on the next periodic refresh tick. The failure is
  logged at `WARN` level.
* If a periodic refresh fails the previous snapshot is retained and the
  failure is logged; the next tick will retry.

## Operational guidance

* **Re-use the same Redis instance** that you already run for
  distributed revocation (see `DISTRIBUTED_REVOCATION.md`). The two
  feature sets use disjoint key prefixes (`revoked:` vs `killswitch:`)
  and have similar availability requirements.
* **Alert on Redis connection errors.** A loss of Redis connectivity
  degrades both the pub/sub propagation path and the periodic-refresh
  safety net. Local reads keep working from cache, but a kill issued on
  one pod will not reach others until connectivity is restored.
* **Each replica opens two Redis connections:** one for normal
  commands (state I/O) and one in subscribe mode (pub/sub). This is the
  standard `ioredis` `duplicate()` pattern. Budget two connections per
  pod. Set `KILL_SWITCH_PUBSUB_ENABLED=false` to suppress the
  subscriber if your managed-Redis connection limit is tight (propagation
  will fall back to the `KILL_SWITCH_REFRESH_INTERVAL_MS` safety net).
* **`KILL_SWITCH_REFRESH_INTERVAL_MS` is now a safety net, not the
  primary propagation mechanism.** The default (30 s) is appropriate for
  most deployments. You only need to lower it if you have evidence of
  frequent pub/sub message loss (network instability between pods and
  Redis). Raising it further (e.g. 60 s) is safe as long as you trust
  the pub/sub delivery path.
* **Always test cross-pod propagation in staging.** A common failure
  mode is forgetting to set `REDIS_URL` in one environment; the
  fallback in-process behaviour is functional enough that the regression
  is easy to miss until an actual incident.
