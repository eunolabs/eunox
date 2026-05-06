# Scaling: Horizontal Sharding and Multi-Region Deployment

This document covers two complementary scaling strategies for the Tool Gateway
and Capability Issuer:

- **Horizontal sharding (H-1)** — eliminates Redis hot-key pressure at high
  request rates by pinning each agent's call counters to a specific pod.
- **Multi-region active/active (F-7)** — survives a regional outage without
  token re-issuance or revocation gaps.

Both strategies share the same Redis tier. Start with a single-region
multi-replica deployment, add sharding when call-counter Redis load becomes a
bottleneck, and add multi-region when your RTO/RPO targets require it.

---

## Part 1 — Horizontal Gateway Sharding (H-1)

### Problem

Every tool-gateway replica is stateless in the HTTP sense but stateful in the
authorization sense: each request touches shared Redis data structures.

| Store | Redis operation | Hot-key risk |
|-------|----------------|--------------|
| `maxCalls` call counter | `INCR` + `EXPIRE` | **High** — every authorized call increments the counter for the token's capability |
| Revocation set | `EXISTS` | Medium |
| Kill-switch state | in-memory (background refresh) | Low |
| DPoP replay nonces | `SET NX EX` | Medium |

At scale (e.g., 10 replicas × 10 000 req/s) the call-counter path becomes a
Redis hot key: 100 000 `INCR` ops/s on the shared key space. Horizontal scaling
adds replicas without reducing Redis load — the scaling curve is
**O(N × QPS)** Redis ops per second.

### Solution

Consistent-hash each agent (keyed by the `sub` JWT claim) to a specific gateway
replica. Because **all traffic for agent A is guaranteed to reach replica 1**:

- Agent A's `maxCalls` counter lives in replica 1's **in-process memory** —
  zero Redis round-trips, zero hot key.
- Replica 1's revocation / kill-switch snapshot only needs to cache entries for
  agents assigned to that shard (~1/N of the fleet).
- DPoP replay and revocation continue to use shared Redis for correctness.

Steady-state Redis call-counter load approaches **zero**. The scaling curve
becomes **O(local)** — each new shard adds capacity without adding Redis load.

### Architecture

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

### Components

#### `computeAgentShardIndex` (`packages/common/src/shard.ts`)

Pure function: FNV-1a 32-bit hash of the `sub` string, then `hash % shardCount`.

```typescript
import { computeAgentShardIndex } from '@euno/common';
computeAgentShardIndex('did:web:acme.com:agent-1', 3); // → e.g. 2
```

FNV-1a is used because it is implementable in TypeScript, Lua (Envoy filter),
and Python without external dependencies, and produces near-uniform distribution
for DID strings and UUIDs.

#### `ShardLocalCallCounterStore` (`packages/common/src/call-counter-store.ts`)

Wraps `InMemoryCallCounterStore` (local) and `RedisCallCounterStore` (remote):

```
incrementAndGet(key, windowSeconds, agentSub?)
  ├─ agentSub == undefined          → remote (Redis)   [no-hint fallback]
  ├─ computeShardIndex(sub) == me   → local  (memory)  [fast path]
  └─ computeShardIndex(sub) != me   → remote (Redis)   [mis-route fallback]
                                       + increment euno_gateway_shard_misrouted_total
```

#### `ConditionContext.agentSub` (`packages/common/src/condition-registry.ts`)

The `sub` claim is threaded from `EnforcementEngine.validateActionInner` →
`buildConditionContext` → `ConditionContext.agentSub` → `maxCallsHandler` →
`store.incrementAndGet(key, window, agentSub)`.

#### Envoy Shard Router (`k8s/envoy-shard-router.yaml`)

A 2-replica Envoy deployment with:
- **Lua HTTP filter**: strips any client-supplied `x-euno-shard-index` header,
  decodes JWT payload, computes `fnv1a32(sub) % SHARD_COUNT`, sets
  `x-euno-shard-index: <N>`.
- **Header-based routing**: one route per shard index, each targeting a
  dedicated per-pod cluster (`tool_gateway_pod_0`, …).
- **Fallback route**: requests without a valid JWT `sub` reach a round-robin
  cluster; the gateway falls back to Redis for those requests.

#### StatefulSet gateway (`k8s/tool-gateway.yaml`)

The gateway is a `StatefulSet` (stable pod ordinals). An init container
extracts the ordinal and writes `GATEWAY_SHARD_INDEX=<N>` to `/env/shard.env`.

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `GATEWAY_SHARD_COUNT` | `1` (sharding off) | Total shards; must match `spec.replicas` and the Envoy upstream count. |
| `GATEWAY_SHARD_INDEX` | `0` | This pod's zero-based ordinal. Cross-field validation rejects `GATEWAY_SHARD_INDEX >= GATEWAY_SHARD_COUNT`. |

### Deployment

#### Enable sharding

1. Set `GATEWAY_SHARD_COUNT` to your replica count in `k8s/tool-gateway.yaml`.
2. Apply the StatefulSet: `kubectl apply -f k8s/tool-gateway.yaml`
3. Apply the Envoy shard router: `kubectl apply -f k8s/envoy-shard-router.yaml`
4. Update your Ingress to point at `envoy-shard-router:3002` instead of
   `tool-gateway:3002`.
5. Verify: `curl http://tool-gateway-0.tool-gateway-headless:3003/metrics | grep shard`

#### Add a shard (scale-out)

1. Increase `spec.replicas` in `k8s/tool-gateway.yaml` and `GATEWAY_SHARD_COUNT`.
2. Add the matching route and per-pod cluster in `k8s/envoy-shard-router.yaml`.
3. When shard count changes, ~1/N agents are remapped; their in-memory counters
   are lost and the new shard starts from 0 until the window elapses. This is
   an acceptable brief under-count, not a security bypass.
4. Rolling-update the StatefulSet.

#### Disable sharding

Set `GATEWAY_SHARD_COUNT=1`. The gateway uses Redis for all call counters.

### Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `euno_gateway_shard_info{shard_index,shard_count}` | Gauge | Static topology labels. Always 1. |
| `euno_gateway_shard_local_counter_size` | Gauge | In-memory call-counter entries on this shard. |
| `euno_gateway_shard_misrouted_total` | Counter | Requests routed to the wrong shard. Sustained non-zero → check router config. |
| `euno_gateway_redis_errors_total{store="call_counter"}` | Counter | Redis errors on the mis-route fallback path. |

### Security considerations

1. **JWT decoding in the router is not authenticated.** An attacker can craft
   an arbitrary `sub` to route to any shard. This is intentional — routing is a
   performance optimization, not a security boundary. The gateway still verifies
   the full JWT signature on every request.
2. **Revocation and kill-switch still use Redis.** A kill issued on any pod
   propagates to all pods sub-second via Redis pub/sub. This is unchanged from
   the non-sharded deployment.
3. **DPoP replay still uses Redis.** A DPoP proof received by shard 0 must not
   be accepted by shard 1. The shared Redis replay store enforces this.

---

## Part 2 — Multi-Region Active/Active (F-7)

### Goals and non-goals

**Goals**
- Survive a regional outage with no token re-issuance required and no
  per-token revocation gap.
- Keep the F-1 issuance rate-limit budget shared across regions for any single
  `(tenantId, userId, agentId)`.
- Allow a token minted in region A to be validated and enforced in region B
  without round-tripping back to A.
- Preserve audit attribution: every record traces back to the region that
  produced it.

**Non-goals**
- Single-write-region designs (active/passive) — supported as a subset; all
  configuration here still applies.
- Region-pinning enforcement — the `region` claim is informational; add a
  deployment-specific policy condition if you need pinning.
- Cross-region distributed transactions — Euno's data model is CRDT-friendly.

### Topology

```
                 ┌──────────────────────┐
                 │   Global LB / DNS    │
                 └─────────┬────────────┘
           ┌───────────────┼─────────────────┐
           │               │                 │
   ┌───────▼──────┐ ┌──────▼───────┐ ┌──────▼───────┐
   │  Region A    │ │   Region B    │ │   Region N    │
   │  (eastus2)   │ │ (westeurope)  │ │   (...)       │
   │              │ │               │ │               │
   │  Issuer-A    │ │   Issuer-B    │ │   Issuer-N    │
   │  Gateway-A   │ │   Gateway-B   │ │   Gateway-N   │
   │      │       │ │       │       │ │       │       │
   └──────┼───────┘ └───────┼───────┘ └───────┼───────┘
          │                 │                 │
          └─────────┬───────┴─────────────────┘
                    ▼
        Globally-replicated Redis (Redis Enterprise CRDB,
        Azure Cache for Redis Geo-replication, ElastiCache
        Global Datastore, GCP Memorystore active-active, …)
        ─────────────────────────────────────────────────
        Stores (write-through, region-agnostic):
          - F-1 issuance rate-limit counters    (key: issrl:<tenant>|<user>|<agent>)
          - revocation list                     (key: revoked:<jti>)
          - kill-switch state                   (key: killswitch:*)
          - maxCalls call-counter store         (key: capcall:<jti>)
```

Each region is a **complete** Euno deployment. Redis is the only required
cross-region resource.

### Replication contract

| Primitive | Key shape | Convergence requirement | Failure mode if Redis is partitioned |
|-----------|-----------|------------------------|--------------------------------------|
| F-1 rate-limit | `issrl:<tenant>\|<user>\|<agent>` | Eventually consistent within `windowSeconds` | Issuer fails closed (`RATE_LIMIT_EXCEEDED`). Flip `ISSUANCE_RATE_LIMIT_FAIL_CLOSED=false` if degraded service is preferable. |
| Revocation list | `revoked:<jti>` | Strong consistency on read | Gateway fails closed. Documented fail-open knob available. |
| Kill-switch | `killswitch:*` | Sub-second via pub/sub; 30 s safety net | Last known state served from per-process cache; read-only until partition heals. |
| maxCalls counters | `capcall:<jti>` | Eventually consistent within call-counter window | Fails closed on affected token. |

#### Redis tier requirements

1. A write in region A is observable in region B within the F-1 window
   length (default 60 s).
2. `INCR` is atomic per key.
3. `EXPIRE` (PTTL) is honoured globally.

Redis Enterprise active-active CRDB, Azure Cache for Redis Geo-replication,
ElastiCache Global Datastore, and Memorystore active-active all satisfy these.
If your tier cannot, run active/passive instead.

### Configuration per region

Each region **must** set:

**Issuer:**
- `ISSUER_REGION=<short-tag>` (e.g. `eastus2`) — surfaced on every minted
  token's `region` claim, every `AuditLogEntry.region`, every request span,
  and the `/.well-known/capability-issuer` discovery doc.
- `REDIS_URL` pointing at the regional endpoint of the globally-replicated tier.
- `ISSUANCE_RATE_LIMIT_ENABLED=true` and tuned `ISSUANCE_RATE_LIMIT_MAX` /
  `ISSUANCE_RATE_LIMIT_WINDOW_SECONDS`.

**Gateway:**
- `GATEWAY_REGION=<short-tag>` (same tag as the co-located issuer).
- `REDIS_URL` pointing at the regional endpoint.
- Existing `KILL_SWITCH_*`, `REVOCATION_*`, `CALL_COUNTER_*` env vars — they
  become cross-region the moment they share Redis. No code changes required.

### Signing keys

Pick one strategy and apply it consistently:

| Strategy | Description |
|----------|-------------|
| **Shared key (simplest)** | Every region uses the same KMS key (cross-region KMS replication). Every region's JWKS is identical. Gateways do not need to know which region issued a token. |
| **Per-region key** | Each region uses its own KMS key with a globally-unique `kid`. Gateways are configured with the JWKS endpoint of every region and select the matching `kid` per inbound token. |

### Token lineage across regions

The `region` claim records the region that minted the **root** of the lineage.
Attenuation and renewal in a different region preserve the parent's `region`
value:

```
Region A issues   → token T1  { region: "A", jti: "j1" }
Region B renews   → token T2  { region: "A", jti: "j2", parent: "j1" }
Region B attenuates T2
                  → token T3  { region: "A", jti: "j3", parent: "j2" }
```

The `region` field on `AuditLogEntry` is stamped from the **executing** region
if you also need to know which region most recently extended the lineage.

### RTO / RPO targets

| Failure mode | Target RPO | Target RTO | Notes |
|--------------|-----------|-----------|-------|
| Single issuer pod loss | 0 | < 30 s | Standard k8s rolling replacement. |
| Single region loss | 0 (Redis CRDB) | < global LB TTL | Pull region from global LB/DNS. In-flight tokens remain valid in other regions. |
| Redis partial outage (one region) | 0 | < 30 s | Losing region's issuer fails closed. Other regions unaffected. |
| Total Redis outage | up to one window | depends on tier | All safety primitives fail closed by default. |

### Failover drill checklist

Run once per quarter against non-production and once per year against
production.

**Pre-flight**
- [ ] Confirm `ISSUER_REGION` and `GATEWAY_REGION` are set in every region
      (`curl /.well-known/capability-issuer` — `region` field MUST be present).
- [ ] Confirm Redis cross-region replication is healthy (lag < 1 s).
- [ ] Confirm both regions accept a test token minted in either region.

**Failover**
- [ ] Pull region A from the global LB.
- [ ] Verify in-flight tokens stamped `region: "A"` continue to validate at
      gateway B (check B's audit logs).
- [ ] Issue a new token in region B; verify its `region` claim is `"B"`.
- [ ] Trigger the F-1 limit from region B; confirm the next attempt from
      region A is still denied (proves the budget is shared via Redis).

**Failback**
- [ ] Re-add region A to the LB.
- [ ] Verify split traffic returns to both regions (decisions counter labelled
      by `euno.region` shows both).
- [ ] Verify a `revoke` in region A is honoured in region B within one
      revocation refresh interval.

**Post-mortem**
- [ ] Capture the F-1 deny rate, decision deny rate, and audit volume from both
      regions for the duration. Diff against the pre-flight baseline.

### Limitations

- Tokens without a `region` claim are valid; single-region deployments need not
  configure anything.
- A multi-region deployment without a globally-replicated Redis tier is **not
  supported**. Without it, run active/passive.
- Cross-region revocation latency is bounded by the Redis replication lag, not
  by Euno.
- Region-pinning (rejecting a token because it was minted in a different region)
  is not enforced by default; add a deployment-specific policy condition if
  needed.
