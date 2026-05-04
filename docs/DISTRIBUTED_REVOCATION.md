# Distributed Token Revocation

## Overview

Token revocation in Euno is implemented using a Redis-backed distributed store that propagates revocations across every gateway replica immediately. The in-memory fallback is available only for local development and deliberate single-replica deployments (`EUNO_DEPLOYMENT_TIER=single-replica`).

## Current Implementation

### Redis-Backed Store (production)

Location: `packages/tool-gateway/src/revocation-store.ts` — `RedisRevocationStore`

Each revocation is stored as a Redis key `revoked:<jti>` with a TTL equal to the remaining lifetime of the underlying token, so Redis itself prunes expired entries automatically. A revocation issued on one gateway instance is visible to all others on the very next `isRevoked()` call — there is no eventual-consistency window.

**Fail-closed semantics:** if Redis is unreachable, `isRevoked()` returns `true` by default (the token is treated as revoked). This prevents a network partition from accidentally allowing tokens that may have been revoked elsewhere. Pass `REVOCATION_FAIL_OPEN=true` to flip to availability-first semantics, but only if your threat model accepts the risk.

**Production hard-failure:** when `REDIS_URL` is set and `ioredis` cannot be loaded, the gateway refuses to start in production (`NODE_ENV=production`) or multi-replica (`EUNO_DEPLOYMENT_TIER!=single-replica`) deployments instead of silently falling back to an in-memory store.

### In-Memory Store (development / single-replica only)

Location: `packages/tool-gateway/src/revocation-store.ts` — `InMemoryRevocationStore`

Uses a `Map<jti, expiryUnixSeconds>`. Stale entries are pruned lazily on lookup and eagerly on insert. This store is **not** shared across processes and is therefore unsuitable for any deployment where more than one gateway pod is running.

The `createRevocationStoreFromEnv` factory selects the appropriate backend:

- `REDIS_URL` **unset** → `InMemoryRevocationStore` (with an informational log)
- `REDIS_URL` **set**, `NODE_ENV=production` or `EUNO_DEPLOYMENT_TIER!=single-replica` → `RedisRevocationStore`; throws on startup if `ioredis` is missing
- `REDIS_URL` **set**, development / single-replica → `RedisRevocationStore`; falls back to in-memory with an error log if `ioredis` is missing

## Architecture

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

All mutating operations (`revoke`) and all read operations (`isRevoked`) go through the same Redis instance (or cluster), ensuring every pod sees the same revocation list.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `REDIS_URL` | (unset) | Redis connection URL. When set, `RedisRevocationStore` is used. Required for multi-replica deployments. |
| `REVOCATION_KEY_PREFIX` | `revoked:` | Redis key prefix for revocation entries. |
| `REVOCATION_FAIL_OPEN` | `false` | When `true`, Redis errors fall open (not revoked). Default is fail-closed. |

## Deployment

The revocation store shares the same Redis instance as the kill-switch manager, DPoP replay store, and maxCalls counter store. A single `REDIS_URL` wires all of them.

Kubernetes ConfigMap example:

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
# Azure Cache for Redis (TLS port 6380)
REDIS_URL=rediss://euno-cache.redis.cache.windows.net:6380
REDIS_PASSWORD=<access-key>

# AWS ElastiCache
REDIS_URL=redis://euno-cache.abc123.use1.cache.amazonaws.com:6379

# GCP Memorystore
REDIS_URL=redis://10.0.0.3:6379
```

See `k8s/redis.yaml` for an in-cluster Redis deployment suitable for non-managed environments.

## Security Considerations

1. **Encryption in transit:** use `rediss://` (TLS) for managed Redis endpoints
2. **Access control:** use Redis AUTH (`requirepass`) or Redis ACL to restrict access to the revocation keyspace
3. **Network isolation:** the `redis-network-policy` in `k8s/network-policies.yaml` allows only the gateway and issuer pods to reach the Redis port
4. **Fail-closed default:** Redis errors treat tokens as revoked — an attacker cannot bypass revocation by disrupting Redis connectivity
5. **Production hard-failure:** if `ioredis` is missing in a production deployment the gateway refuses to start rather than silently running with in-memory state

## Monitoring

| Metric | Description |
|---|---|
| `euno_gateway_revocation_list_size` | Number of entries in the **in-memory** store (always 0 when Redis is in use) |
| Redis `DBSIZE` / `KEYS revoked:*` | Number of live revocation entries across the fleet |
| Redis error logs | Logged at `error` level with fields `error`, `tokenId`, and `failMode` |

## Performance

- `isRevoked` is a single `EXISTS` command — O(1) round-trip, typically < 1 ms on an in-cluster Redis
- `revoke` is a single `SET … EX` command — O(1) round-trip
- TTL-based expiry means Redis prunes entries without a periodic job; key count tracks active revocations only

