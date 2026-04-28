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
         │ write-through         │ periodic refresh      │
         │ on admin call         │ every 5s (default)    │
         └───────────────┬───────┴───────────────────────┘
                         ▼
              ┌─────────────────────┐
              │      Redis          │
              │  killswitch:global  │
              │  killswitch:killed_sessions (SET)
              │  killswitch:killed_agents   (SET)
              └─────────────────────┘
```

`KillSwitchManager` is a **synchronous** interface because
`shouldBlock()` is consulted on the hot path of every authorization
decision. To keep that contract while sharing state across pods,
`RedisKillSwitchManager` maintains an in-memory snapshot kept fresh by:

1. **Write-through.** Every mutating call (`activateGlobalKill`,
   `killSession`, `killAgent`, `reviveSession`, `reviveAgent`,
   `resetAll`) writes to Redis first, then updates the local cache. The
   issuing pod observes its own change immediately.
2. **Periodic refresh.** A background timer pulls the full state from
   Redis every `KILL_SWITCH_REFRESH_INTERVAL_MS` (default 5 s). Other
   pods pick up remote changes within that window.
3. **Initial seed.** On startup the cache is hydrated from Redis so a
   fresh pod does not start in a "no kills" state if kills are already
   in effect cluster-wide.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `REDIS_URL` | _(unset)_ | Redis endpoint. **Required** to enable the distributed kill switch. The same URL is reused for distributed revocation. |
| `KILL_SWITCH_KEY_PREFIX` | `killswitch:` | Prefix for kill-switch Redis keys. Override to share a Redis instance between multiple environments. |
| `KILL_SWITCH_REFRESH_INTERVAL_MS` | `5000` | How often each pod refreshes its local snapshot from Redis. Lower = faster cross-pod propagation, higher Redis traffic. Set to `0` to disable periodic refresh (write-through only — **not** recommended). |
| `KILL_SWITCH_FAIL_OPEN_ON_WRITE` | `false` | When `true`, kill-switch writes that fail against Redis still update the local cache so this pod honours the operator's intent. Other pods only see the kill once Redis recovers. When `false`, write errors propagate so the admin API surfaces a 500. |

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

`RedisKillSwitchManager` stores three keys (with the configured prefix):

* `<prefix>global` — string `"1"` if the global kill is active; deleted
  otherwise.
* `<prefix>killed_sessions` — Redis `SET` of killed session ids.
* `<prefix>killed_agents` — Redis `SET` of killed agent ids.

Sets are used (rather than per-id keys) so the entire population can be
refreshed in one round trip (`SMEMBERS`) and so revives are atomic
(`SREM`). Kill switches have no natural TTL — they remain in effect
until an operator explicitly revives them — so we deliberately do not
put TTLs on these keys. Operators are expected to use the admin API
(`POST /admin/kill-switch/.../revive`, `POST /admin/kill-switch/reset`)
or `redis-cli DEL`/`SREM` for cleanup.

## Failure semantics

* **Reads** are always served from the local cache and therefore never
  fail. Their only freshness guarantee is the configured refresh
  interval (default 5 s).
* **Writes** propagate Redis errors by default (`failOpenOnWrite=false`)
  so the admin API returns 500 and operators know the kill did not
  stick. Set `KILL_SWITCH_FAIL_OPEN_ON_WRITE=true` only when local
  enforcement on the issuing pod is acceptable while Redis is
  unreachable.
* If a periodic refresh fails the previous snapshot is retained and the
  failure is logged; the next tick will retry.

## Operational guidance

* **Re-use the same Redis instance** that you already run for
  distributed revocation (see `DISTRIBUTED_REVOCATION.md`). The two
  feature sets use disjoint key prefixes (`revoked:` vs `killswitch:`)
  and have similar availability requirements.
* **Alert on Redis connection errors.** A loss of Redis connectivity
  silently degrades the cross-pod propagation guarantees of the kill
  switch even though local reads keep working.
* **Tune `KILL_SWITCH_REFRESH_INTERVAL_MS` to your incident SLO.** A 5 s
  default is a reasonable trade-off; if your incident runbook requires
  faster propagation drop it to 1–2 s, accepting the corresponding
  increase in Redis QPS (~3 lookups per pod per refresh).
* **Always test cross-pod propagation in staging.** A common failure
  mode is forgetting to set `REDIS_URL` in one environment; the
  fallback in-process behaviour is functional enough that the regression
  is easy to miss until an actual incident.
