# Distributed State: Kill Switch and Token Revocation

Both the kill switch and the token revocation list are Redis-backed distributed
state stores. They share the same `REDIS_URL`, use disjoint key prefixes
(`killswitch:` vs. `revoked:`), and have identical availability requirements.
This document covers both.

---

## Kill Switch

The Tool Gateway exposes an emergency kill switch with three scopes:

| Scope | Effect |
|-------|--------|
| **Global** | Block every agent request fleet-wide |
| **Session** | Block every request whose `context.sessionId` matches |
| **Agent** | Block every request whose JWT `sub` (agent DID) matches |

### Architecture

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

`KillSwitchManager.shouldBlock()` is on the hot path of every authorization
decision and must be synchronous. `RedisKillSwitchManager` satisfies this by
keeping an in-memory snapshot refreshed by three complementary mechanisms:

1. **Write-through (issuing pod).** Every mutating admin-API call writes to
   Redis first, then updates the local cache. The issuing pod observes its own
   change immediately.
2. **Pub/sub (every other pod, *primary*).** After a successful Redis write the
   issuing pod publishes a granular event on `<prefix>events`. Every replica
   applies it to its local cache within single-digit milliseconds.
3. **Periodic refresh (safety net).** A background timer (`KILL_SWITCH_REFRESH_INTERVAL_MS`,
   default 30 s) pulls full state from Redis. This covers dropped pub/sub
   messages and re-seeds pods that reconnected to Redis during a brief outage.
4. **Initial seed.** On startup the cache is hydrated from Redis before the
   subscriber is wired, so a fresh pod starts with current kill state.

#### Event schema

Pub/sub messages are small, forward-compatible JSON:

```json
{ "v": 1, "src": "<instanceId>", "op": "kill_session", "id": "sess-123" }
```

`op` is one of `activate_global`, `deactivate_global`, `kill_session`,
`revive_session`, `kill_agent`, `revive_agent`, `reset_all`. Unknown `op`
values are dropped silently; the periodic-refresh safety net guarantees
eventual convergence.

### Redis key schema

| Key | Type | Meaning |
|-----|------|---------|
| `<prefix>global` | String `"1"` | Global kill active; deleted when inactive |
| `<prefix>killed_sessions` | SET | Killed session IDs |
| `<prefix>killed_agents` | SET | Killed agent IDs |
| `<prefix>events` | PUB/SUB channel | Real-time invalidation events (not persisted) |

Kill switches have no natural TTL — they remain in effect until explicitly
revived via the admin API (`POST /admin/kill-switch/.../revive`) or
`redis-cli DEL`/`SREM`.

### Configuration

| Variable | Default | Meaning |
|----------|---------|---------|
| `REDIS_URL` | _(unset)_ | Redis endpoint. Required for distributed kill switch. |
| `KILL_SWITCH_KEY_PREFIX` | `killswitch:` | Prefix for all kill-switch keys and the pub/sub channel. Override to share a Redis instance across environments. |
| `KILL_SWITCH_REFRESH_INTERVAL_MS` | `30000` | Safety-net refresh interval. Set to `0` to disable (pub/sub-only). |
| `KILL_SWITCH_FAIL_OPEN_ON_WRITE` | `false` | When `true`, write failures update only the local cache; other pods see the kill only after Redis recovers. |
| `KILL_SWITCH_PUBSUB_ENABLED` | `true` | Set `false` to suppress the subscriber and rely on the periodic refresh (saves one Redis connection per pod). |

When `REDIS_URL` is unset the gateway falls back to `DefaultKillSwitchManager`
(process-local memory only) and logs:

```
REDIS_URL not configured, using in-memory kill-switch manager
```

### Failure semantics

- **Reads** are always served from the local cache and never fail. Worst-case
  staleness is bounded by `KILL_SWITCH_REFRESH_INTERVAL_MS` (default 30 s).
- **Writes** propagate Redis errors by default (`failOpenOnWrite=false`): the
  admin API returns 500 so the operator knows the kill did not stick. Use
  `KILL_SWITCH_FAIL_OPEN_ON_WRITE=true` only for emergency local containment
  while Redis is unreachable.
- **Publish failures** are non-fatal: the write is durable in Redis; remote
  replicas converge on the next periodic refresh tick. Logged at `WARN`.

### Operational guidance

- Each replica opens **two** Redis connections: one for commands and one in
  subscribe mode. Budget two connections per pod. Use
  `KILL_SWITCH_PUBSUB_ENABLED=false` if connection budget is tight.
- Alert on Redis connection errors — they degrade both the pub/sub path and
  the refresh safety net.
- `KILL_SWITCH_REFRESH_INTERVAL_MS` is a safety net, not the primary mechanism.
  The default (30 s) is appropriate for most deployments; lowering it is only
  necessary if pub/sub messages are frequently dropped.

---

## Token Revocation

### Architecture

```
┌─────────────────┐     ┌─────────────────┐
│   Gateway       │     │   Gateway       │
│   Instance 1    │     │   Instance 2    │
└────────┬────────┘     └────────┬────────┘
         │                       │
         │  isRevoked / revoke   │
         └──────────┬────────────┘
                    │
         ┌──────────▼──────────┐
         │                     │
         │   Redis (shared)    │
         │  revoked:<jti> keys │
         │  with TTL           │
         └─────────────────────┘
```

Each revocation is stored as a Redis key `revoked:<jti>` with a TTL equal to
the remaining lifetime of the token. Redis prunes expired entries automatically;
no periodic cleanup job is required. A revocation issued on one gateway
instance is visible to all others on the very next `isRevoked()` call — there
is no eventual-consistency window.

**Fail-closed semantics:** if Redis is unreachable, `isRevoked()` returns
`true` (the token is treated as revoked). This prevents a network partition from
accidentally honouring tokens that may have been revoked elsewhere. Set
`REVOCATION_FAIL_OPEN=true` to flip to availability-first semantics only if
your threat model accepts that risk.

**Production hard-failure:** when `REDIS_URL` is set and `ioredis` cannot be
loaded, the gateway **refuses to start** in production
(`NODE_ENV=production`) or multi-replica
(`EUNO_DEPLOYMENT_TIER!=single-replica`) deployments.

### Development / single-replica fallback

`InMemoryRevocationStore` (a `Map<jti, expiryUnixSeconds>`) is available only
when `REDIS_URL` is unset or when `EUNO_DEPLOYMENT_TIER=single-replica`. It is
**not** shared across processes. `createRevocationStoreFromEnv` selects the
appropriate backend automatically:

| Condition | Backend |
|-----------|---------|
| `REDIS_URL` unset | `InMemoryRevocationStore` (+ informational log) |
| `REDIS_URL` set, production or multi-replica | `RedisRevocationStore`; throws at startup if `ioredis` is missing |
| `REDIS_URL` set, development or single-replica | `RedisRevocationStore`; falls back to in-memory with error log if `ioredis` is missing |

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | _(unset)_ | Redis connection URL. Required for multi-replica deployments. |
| `REVOCATION_KEY_PREFIX` | `revoked:` | Redis key prefix for revocation entries. |
| `REVOCATION_FAIL_OPEN` | `false` | When `true`, Redis errors fall open (treat token as not revoked). |
| `REVOCATION_UNAVAILABLE_MODE` | _(none)_ | `fail-closed` (default), `503`, or `open` — controls gateway behaviour when Redis is unavailable. |

### Kubernetes deployment example

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: gateway-config
  namespace: euno-system
data:
  REDIS_URL: "redis://euno-redis:6379"
  NODE_ENV: "production"
  EUNO_DEPLOYMENT_TIER: "multi-replica"
```

For managed Redis services:

```bash
# Azure Cache for Redis (TLS)
REDIS_URL=rediss://euno-cache.redis.cache.windows.net:6380
REDIS_PASSWORD=<access-key>

# AWS ElastiCache
REDIS_URL=redis://euno-cache.abc123.use1.cache.amazonaws.com:6379

# GCP Memorystore
REDIS_URL=redis://10.0.0.3:6379
```

See `k8s/redis.yaml` for an in-cluster Redis deployment.

### Security considerations

1. **Encryption in transit:** use `rediss://` (TLS) for managed Redis endpoints.
2. **Access control:** restrict access to the revocation keyspace via Redis AUTH
   or ACL.
3. **Network isolation:** `k8s/network-policies.yaml` (`redis-network-policy`)
   allows only gateway and issuer pods to reach the Redis port.
4. **Fail-closed default:** Redis errors treat tokens as revoked — an attacker
   cannot bypass revocation by disrupting Redis connectivity.

### Monitoring

| Metric | Description |
|--------|-------------|
| `euno_gateway_revocation_list_size` | In-memory store size (always 0 when Redis is in use) |
| `euno_gateway_revocation_unavailable_total` | Revocation checks that returned 401/503 due to Redis unavailability |
| Redis `DBSIZE` / `KEYS revoked:*` | Live revocation entries across the fleet |
| Redis error logs | Logged at `error` level with fields `error`, `tokenId`, `failMode` |

### Performance

- `isRevoked` → single Redis `EXISTS` command, O(1), typically < 1 ms intra-cluster.
- `revoke` → single Redis `SET … EX` command, O(1).
- TTL-based expiry: key count tracks only active revocations.

---

## Shared Redis instance

Re-use the same Redis instance for both the kill switch and revocation (and for
the DPoP replay store and call-counter store). The four feature sets use
disjoint key prefixes (`killswitch:`, `revoked:`, `dpop:`, `capcall:`) and have
identical availability requirements. A single `REDIS_URL` wires all of them.
