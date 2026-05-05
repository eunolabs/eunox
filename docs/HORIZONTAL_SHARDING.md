# Horizontal Gateway Sharding (H-1)

## Problem

Every tool-gateway replica is stateless in the HTTP sense but stateful in the
authorization sense: each request touches three shared Redis data structures.

| Store | Redis operation | Hot-key risk |
|---|---|---|
| `maxCalls` call counter | `INCR` + `EXPIRE` | **High** — every authorized call increments the counter for the token's capability |
| Revocation set | `EXISTS` | Medium — one lookup per request, but the set is small |
| Kill-switch state | in-memory (background `SMEMBERS` refresh) | Low — local cache hit on hot path |
| DPoP replay nonces | `SET NX EX` | Medium — one write per request |

At scale (say, 10 replicas × 10 000 req/s) the call-counter path becomes
a Redis hot key: 100 000 `INCR` ops/s on the key space shared by all
replicas. Horizontal scaling of the gateway adds replicas without reducing
Redis load — the scaling curve is **O(N × QPS)** Redis ops per second.

## Solution

Consistent-hash each agent (keyed by the `sub` JWT claim) to a specific
gateway replica. Because **all traffic for agent A is guaranteed to reach
replica 1**:

- Agent A's `maxCalls` counter lives in replica 1's **in-process memory**.
  Zero Redis round-trips. Zero hot key.
- Replica 1's revocation / kill-switch in-memory snapshot only needs to
  cache entries for agents assigned to that shard (~1/N of the fleet). Cache
  churn and memory pressure are proportional to the per-shard population.
- DPoP replay and revocation state continue to use the shared Redis store
  for correctness across replicas (unchanged from the non-sharded deployment).

Steady-state Redis call-counter load approaches **zero**. The scaling curve
becomes **O(local)** — each new shard adds capacity without adding Redis load.

## Architecture

```
                      ┌─────────────────────────────────────────┐
Agents / MCP clients  │       Envoy Shard Router                │
──────────────────►   │  (k8s/envoy-shard-router.yaml)          │
                      │                                         │
                      │  Lua filter                             │
                      │   1. Strip client x-euno-shard-index    │
                      │   2. Decode JWT payload (base64, no sig)│
                      │   3. Extract `sub` claim                │
                      │   4. Compute fnv1a32(sub) % SHARD_COUNT │
                      │   5. Set x-euno-shard-index: N          │
                      │                                         │
                      │  Header-based routing                   │
                      │   x-euno-shard-index=0 → pod_0 cluster  │
                      │   x-euno-shard-index=1 → pod_1 cluster  │
                      │   x-euno-shard-index=2 → pod_2 cluster  │
                      │   (no header) → fallback cluster        │
                      └───────┬───────────┬───────────┬─────────┘
                              │           │           │
                    ┌─────────▼──┐ ┌──────▼──┐ ┌─────▼────┐
                    │  gateway-0 │ │gateway-1│ │gateway-2 │
                    │  shard 0   │ │ shard 1 │ │ shard 2  │
                    │            │ │         │ │          │
                    │ ┌────────┐ │ │ ┌─────┐ │ │ ┌──────┐ │
                    │ │agent A │ │ │ │ B   │ │ │ │  C   │ │
                    │ │agent D │ │ │ │ E   │ │ │ │  F   │ │
                    │ │in-mem  │ │ │ │mem  │ │ │ │ mem  │ │
                    │ │counter │ │ │ │ctr  │ │ │ │ ctr  │ │
                    │ └────────┘ │ │ └─────┘ │ │ └──────┘ │
                    └─────┬──────┘ └────┬────┘ └────┬─────┘
                          │             │            │
                          └──────┬──────┘            │
                                 │ ◄─────────────────┘
                          ┌──────▼──────┐
                          │    Redis    │  (revocation, kill-switch,
                          │             │   DPoP replay, mis-routed
                          └─────────────┘   call counters)
```

## Components

### 1. `computeAgentShardIndex` (`packages/common/src/shard.ts`)

Pure function: FNV-1a 32-bit hash of the `sub` string, then `hash % shardCount`.

```typescript
import { computeAgentShardIndex } from '@euno/common';
computeAgentShardIndex('did:web:acme.com:agent-1', 3); // → e.g. 2
```

FNV-1a is used because:
- Implementable in TypeScript, Lua (Envoy filter), Python (future tools) from
  scratch — no external dependency on either side of the LB.
- Produces a near-uniform distribution for DID strings and UUIDs.
- Deterministic across platforms with no hash randomisation.

### 2. `ShardLocalCallCounterStore` (`packages/common/src/call-counter-store.ts`)

Wraps `InMemoryCallCounterStore` (local) and `RedisCallCounterStore` (remote).

```
incrementAndGet(key, windowSeconds, agentSub?)
  ├─ agentSub == undefined          → remote (Redis)   [no-hint fallback]
  ├─ computeShardIndex(sub) == me   → local  (memory)  [fast path]
  └─ computeShardIndex(sub) != me   → remote (Redis)   [mis-route fallback]
                                       + increment euno_gateway_shard_misrouted_total
```

### 3. `ConditionContext.agentSub` (`packages/common/src/condition-registry.ts`)

The `sub` claim is threaded from `EnforcementEngine.validateActionInner` →
`buildConditionContext` → `ConditionContext.agentSub` → `maxCallsHandler` →
`store.incrementAndGet(key, window, agentSub)` so the store knows which
agent it is counting for.

### 4. Envoy Shard Router (`k8s/envoy-shard-router.yaml`)

A 2-replica Envoy deployment with:
- **Lua HTTP filter**: strips any client-supplied `x-euno-shard-index` header,
  decodes the JWT payload, extracts `sub`, and computes
  `shard_index = fnv1a32(sub) % SHARD_COUNT` — identical to
  `computeAgentShardIndex()` in `shard.ts`. Sets `x-euno-shard-index: <N>`.
- **Header-based routing**: one route per shard index value (0, 1, …, N-1),
  each targeting a dedicated per-pod cluster (`tool_gateway_pod_0`, …).
- **Per-pod clusters**: each `STRICT_DNS` cluster resolves the stable pod
  hostname (`tool-gateway-N.tool-gateway-headless.euno-system`), ensuring
  Envoy's forwarding decision matches the gateway's shard ownership check.
- **Fallback route**: requests without a valid JWT header (or `sub` claim)
  reach a round-robin cluster over all pods; the gateway falls back to Redis
  for those requests.

### 5. StatefulSet gateway (`k8s/tool-gateway.yaml`)

The gateway is now a `StatefulSet` (was `Deployment`) so each pod has a
stable ordinal suffix (e.g. `tool-gateway-2`). An init container extracts the
ordinal and writes `GATEWAY_SHARD_INDEX=2` to `/env/shard.env`. The container
`command` sources that file before `exec node` so the env var is visible to the
gateway process:

```yaml
command:
- sh
- -c
- |
  if [ -f /env/shard.env ]; then
    . /env/shard.env
    export GATEWAY_SHARD_INDEX
  fi
  exec node dist/index.js
```

### 6. Schema (`packages/common/src/config/schema.ts`)

Two new gateway env vars:
- `GATEWAY_SHARD_COUNT` — total shards; defaults to `1` (sharding off).
- `GATEWAY_SHARD_INDEX` — this pod's zero-based ordinal; defaults to `0`.

Cross-field validation rejects `GATEWAY_SHARD_INDEX >= GATEWAY_SHARD_COUNT`.

## Deployment

### Enable sharding

1. Set `GATEWAY_SHARD_COUNT` to your replica count (e.g. `3`) in
   `k8s/tool-gateway.yaml`. It must match `spec.replicas` of the StatefulSet
   **and** the Envoy upstream cluster endpoint count.

2. Apply the StatefulSet:
   ```bash
   kubectl apply -f k8s/tool-gateway.yaml
   ```

3. Apply the Envoy shard router:
   ```bash
   kubectl apply -f k8s/envoy-shard-router.yaml
   ```

4. Update your Ingress / external LoadBalancer to point at
   `envoy-shard-router:3002` instead of `tool-gateway:3002` for agent
   traffic.

5. Verify sharding is active by checking the metrics:
   ```bash
   # On any gateway pod:
   curl http://tool-gateway-0.tool-gateway-headless:3003/metrics | grep shard
   # euno_gateway_shard_info{shard_index="0",shard_count="3"} 1
   # euno_gateway_shard_local_counter_size 42
   # euno_gateway_shard_misrouted_total 0
   ```

### Add a shard (scale-out)

1. Increase `spec.replicas` in `k8s/tool-gateway.yaml` and `GATEWAY_SHARD_COUNT`
   on all existing pods.
2. Add the matching route entry and per-pod cluster in `k8s/envoy-shard-router.yaml`
   and update `SHARD_COUNT` in the Lua inline_code.
3. When the shard count changes, FNV-1a % N remaps ~1/N agents to different
   pods. Their in-memory counters are lost; the receiving pod starts counting
   from 0 until the window elapses. This is an acceptable brief under-count.
4. Rolling-update the StatefulSet after updating the config.

### Disable sharding

Set `GATEWAY_SHARD_COUNT=1` (the default). The gateway will use the Redis
call-counter store for all requests. The Envoy router can remain deployed
but will route randomly (no affinity needed when sharding is off).

## Metrics

| Metric | Type | Description |
|---|---|---|
| `euno_gateway_shard_info{shard_index,shard_count}` | Gauge | Static topology labels. Always 1. |
| `euno_gateway_shard_local_counter_size` | Gauge | In-memory call-counter entries on this shard. |
| `euno_gateway_shard_misrouted_total` | Counter | Requests routed to the wrong shard. Sustained non-zero → check router config. |
| `euno_gateway_redis_errors_total{store="call_counter"}` | Counter | Redis errors on the mis-route fallback path. |

## Security considerations

1. **JWT decoding in the router is not authenticated.** An attacker can craft
   an arbitrary `sub` to route to any shard. This is intentional — routing
   is a performance optimization, not a security boundary. The gateway still
   verifies the full JWT signature on every request.

2. **Revocation and kill-switch still use Redis.** A kill issued on any pod
   propagates to all pods sub-second via Redis pub/sub (with the
   `KILL_SWITCH_REFRESH_INTERVAL_MS` periodic refresh, default 30 s, as a
   safety net). This is unchanged from the non-sharded deployment.

3. **DPoP replay still uses Redis.** A DPoP proof received by shard 0 must
   not be accepted by shard 1. The shared Redis replay store enforces this
   for all replicas — DPoP replay tracking is not sharded in this release.

4. **Counter under-count during shard topology changes.** When a shard is
   added or removed, ~1/N agents are remapped. Their in-memory counters are
   lost; the new shard starts counting from 0 for those agents until the
   window elapses. This is an acceptable brief under-count; it is not a
   security bypass because the burst window is bounded by `windowSeconds`.
