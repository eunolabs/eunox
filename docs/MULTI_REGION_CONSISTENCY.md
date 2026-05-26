# Multi-Region Consistency Model

This document describes the consistency guarantees, partition tolerance behavior,
and multi-region deployment model for the Euno platform. It answers the
questions posed in OQ-5 of the
[Technical Architecture Review](TECHNICAL_REVIEW_2026_05_26.md).

---

## 1. Overview

Euno supports three deployment tiers with increasing consistency complexity:

| Tier | Redis | Consistency Model | Target SLA |
|------|-------|------------------|------------|
| `single-replica` | Not required | Strong (single process) | 99.9% |
| `multi-replica` | Required | Eventual (sub-second propagation) | 99.95% |
| `multi-region-active-active` | Cross-region replication | Eventual (seconds-level propagation) | 99.99% |

This document focuses on the multi-region tier, where **eventual consistency**
is the fundamental trade-off for geographic redundancy and partition tolerance.

---

## 2. Distributed State Components

### 2.1 State Classification

| Component | State Type | Consistency Requirement | Failure Mode |
|-----------|-----------|------------------------|-------------|
| **Kill switch** | Safety-critical | Eventual (bounded staleness) | Fail-closed |
| **Token revocation** | Safety-critical | Eventual (bounded staleness) | Fail-closed |
| **Rate limiter** | Best-effort | Approximate | Fail-open |
| **Call counter** | Best-effort | Approximate | Fail-open |
| **DPoP replay cache** | Integrity | Per-region (no cross-region) | Fail-closed |
| **Audit ledger** | Compliance-critical | Append-only, eventually durable | Fail-closed (signing) |

### 2.2 Safety-Critical vs. Best-Effort

**Safety-critical components** (kill switch, revocation) use **fail-closed**
semantics: when state is uncertain, deny access. This may cause false denials
during partitions but never false allows.

**Best-effort components** (rate limiter, call counter) use **fail-open**
semantics: when state is uncertain, allow access with degraded accuracy. This
may allow over-limit requests during partitions but preserves availability.

---

## 3. Kill Switch Consistency

### 3.1 Architecture (Multi-Region)

```
Region A                              Region B
┌──────────────────────┐              ┌──────────────────────┐
│  Gateway Pods        │              │  Gateway Pods        │
│  ├── Local cache     │              │  ├── Local cache     │
│  └── Pub/sub listener│              │  └── Pub/sub listener│
└──────────┬───────────┘              └──────────┬───────────┘
           │                                      │
           ▼                                      ▼
┌──────────────────────┐              ┌──────────────────────┐
│  Redis Primary       │◄────────────►│  Redis Replica       │
│  (Region A)          │  Replication │  (Region B)          │
└──────────────────────┘              └──────────────────────┘
```

### 3.2 Propagation Mechanisms

The kill switch uses four complementary propagation mechanisms:

| Mechanism | Latency | Purpose |
|-----------|---------|---------|
| 1. Write-through | Immediate (issuing pod) | Local consistency |
| 2. Redis pub/sub | < 10ms (same region) | Cross-pod propagation |
| 3. Redis replication | 1–5ms (same region), 50–200ms (cross-region) | Cross-region propagation |
| 4. Safety-net refresh | 30s (configurable) | Catch missed pub/sub events |

### 3.3 Worst-Case Staleness

| Scenario | Maximum Staleness | Explanation |
|----------|------------------|-------------|
| Same pod | 0 | Write-through |
| Same region, different pod | < 1s | Pub/sub + local cache refresh |
| Cross-region, no partition | < 30s | Replication lag + safety-net refresh |
| Cross-region, during partition | 30s after partition heals | Safety-net catches up |

**Operator implication:** After activating a kill switch, wait up to 30 seconds
before assuming all regions have applied the change. In practice, propagation
is typically under 1 second within a region.

### 3.4 Split-Brain Behavior

If a network partition splits regions:

```
Region A (has Redis primary)          Region B (has Redis replica)
┌─────────────────────────┐           ┌─────────────────────────┐
│ ✓ Can write kill switch │           │ ✗ Cannot write          │
│ ✓ Can read latest state │           │ ~ Reads stale state     │
│                         │           │ ✓ Fail-closed on doubt  │
└─────────────────────────┘           └─────────────────────────┘
                        PARTITION
```

**During partition:**
- Region A (primary): Full kill switch functionality
- Region B (replica): Reads last-known state; **fail-closed** if Redis
  becomes unreachable (blocks all requests)

**After partition heals:**
- Redis replication catches up automatically
- Safety-net refresh (30s) ensures all pods re-sync
- No manual intervention required

---

## 4. Token Revocation Consistency

### 4.1 Key Schema

```
revoked:<jti> = "1"    TTL = remaining token lifetime
```

Each revocation is a Redis key with TTL matching the token's remaining lifetime.
When the token would have expired anyway, the revocation key auto-deletes.

### 4.2 Multi-Region Behavior

| Scenario | Behavior |
|----------|----------|
| Revoke in Region A | Key written to primary → replicated to Region B |
| Agent presents revoked token in Region B | Verified against local replica |
| Replication lag | Agent may use token for duration of lag (typically < 200ms) |
| Redis unavailable | **Fail-closed**: token treated as revoked |

### 4.3 Revocation Consistency Guarantees

- **Within region**: Revocation effective within 1 second (pub/sub)
- **Cross-region**: Revocation effective within replication lag + safety-net
  (typically < 1s, worst case 30s)
- **During partition**: Fail-closed — if revocation state is unknown, token
  is denied

### 4.4 Edge Case: Revoke During Partition

If a token is revoked in Region A while Region B is partitioned:
1. Region B continues serving the token (using last-known state)
2. After partition heals, revocation replicates to Region B
3. Token is then denied in Region B
4. **Maximum exposure window**: Duration of partition (bounded by token TTL)

**Mitigation**: Use short token TTLs (5–15 min). Even without revocation
propagation, the token expires naturally.

---

## 5. Rate Limiter Consistency

### 5.1 Multi-Region Rate Limiting

Rate limits are **per-region** in multi-region deployments. Each region
maintains independent rate limit state in its Redis instance.

```
Region A: agent-x rate = 50/min (local)
Region B: agent-x rate = 50/min (local)
Total actual: agent-x could use 100/min across regions
```

### 5.2 Design Decision

Cross-region rate limiting with strong consistency would require:
- Cross-region Redis reads on every request (latency: 50–200ms)
- Or distributed counter with CRDTs (complexity)
- Or central rate limit service (single point of failure)

**Chosen approach**: Per-region limits with **fail-open** semantics.

**Justification:**
- Rate limiting is a best-effort safeguard, not a security boundary
- True abuse prevention uses capability conditions (action counts, time windows)
- Per-region limits still provide meaningful protection
- Operators can set per-region limits to `global_limit / num_regions`

### 5.3 Fail-Open Behavior

When Redis is unavailable, the rate limiter falls back to an in-memory limiter:

```go
// From pkg/ratelimit/resilient.go (simplified)
result, err := redisLimiter.Allow(ctx, key)
if err != nil {
    // Redis unavailable — use in-memory fallback
    return inMemoryLimiter.Allow(ctx, key)
}
```

---

## 6. Audit Ledger Consistency

### 6.1 Consistency Model

The audit ledger is **append-only** with **at-least-once** delivery semantics:

| Property | Guarantee |
|----------|-----------|
| Ordering | Causally ordered within a session; globally unordered |
| Delivery | At-least-once (retry on failure) |
| Durability | Persisted to backend after successful enqueue |
| Immutability | Append-only; no updates or deletes |

### 6.2 Multi-Region Audit Architecture

```
Region A                              Region B
┌──────────────────────┐              ┌──────────────────────┐
│  Gateway → Audit     │              │  Gateway → Audit     │
│  Transport → Backend │              │  Transport → Backend │
└──────────┬───────────┘              └──────────┬───────────┘
           │                                      │
           ▼                                      ▼
┌──────────────────────┐              ┌──────────────────────┐
│  PostgreSQL          │              │  PostgreSQL          │
│  (Regional)          │              │  (Regional)          │
└──────────┬───────────┘              └──────────┬───────────┘
           │                                      │
           └──────────────┬───────────────────────┘
                          ▼
              ┌──────────────────────┐
              │  Cross-Chain Anchor  │
              │  (S3 Object Lock)    │
              │  (Immutable backup)  │
              └──────────────────────┘
```

### 6.3 Cross-Region Consistency

Each region writes to its own PostgreSQL instance. For compliance requirements
(SOC 2, HIPAA), the **cross-chain anchor** provides:

- **Secondary copy**: Audit events written to S3 with Object Lock (WORM)
- **Tamper evidence**: Events are cryptographically signed before storage
- **Cross-region durability**: S3 provides 11 nines of durability
- **Reconciliation**: Periodic comparison between regional DBs and anchor

### 6.4 Audit Overflow Policy

When the audit transport's buffer is full, events are **dropped** (not blocked):

- `Enqueue()` returns `ErrBatchFull` immediately
- Metric: `audit_enqueue_total{status="dropped"}` is incremented
- The enforcement hot path is never blocked by audit backpressure
- Dropped events are logged with context for manual reconciliation

See [Audit Chain Architecture](AUDIT_CHAIN_ARCHITECTURE.md) for full details.

---

## 7. Network Partition Behavior

### 7.1 Partition Scenarios

| Partition | Region A (Primary) | Region B (Replica) |
|-----------|-------------------|-------------------|
| **Inter-region network** | Full functionality | Read-only Redis; stale state |
| **Redis primary failure** | Sentinel/failover promotes replica | Becomes new primary |
| **Full Region A outage** | Unavailable | Takes over (if DNS/LB configured) |
| **DNS failure** | Agents cannot reach services | Same |

### 7.2 Expected Behavior During Partition

```
Timeline:
T=0     Partition begins
T=0-1s  Region B serves requests using cached state (local cache + Redis replica)
T=1-30s Region B's safety-net refresh detects stale state
T=30s   If Redis unreachable: fail-closed for safety-critical components
        If Redis available (replica): continues with last-replicated state
T=?     Partition heals
T=?+30s Full convergence (safety-net refresh catches up)
```

### 7.3 Operator Runbook

During a detected partition:

1. **Verify partition scope**: Check Redis replication status via `INFO replication`
2. **Assess impact**: Safety-critical components (kill switch, revocation) are
   fail-closed; best-effort components continue working
3. **Monitor metrics**:
   - `redis_failover_events_total` — failover count
   - `killswitch_cache_age_seconds` — staleness of local cache
   - `revocation_cache_hit_total{source="fallback"}` — fallback cache usage
4. **Do NOT manually intervene** unless partition persists > 5 minutes
5. **After partition heals**: Verify convergence via safety-net refresh logs

---

## 8. Deployment Topologies

### 8.1 Active-Passive (Recommended for Most Deployments)

```
Region A (Active)                 Region B (Passive)
├── All traffic                   ├── Hot standby
├── Redis primary                 ├── Redis replica (read-only)
├── PostgreSQL primary            ├── PostgreSQL replica
└── Full service mesh             └── Services ready to activate
```

- **Failover time**: 30–60s (DNS TTL + service startup)
- **Data loss window**: Redis replication lag (typically < 1s)
- **Consistency**: Strong within active region; bounded staleness in standby

### 8.2 Active-Active (For 99.99% SLA Requirements)

```
Region A (Active)                 Region B (Active)
├── Receives traffic              ├── Receives traffic
├── Redis primary/replica         ├── Redis primary/replica
├── PostgreSQL (local writes)     ├── PostgreSQL (local writes)
└── GeoDNS routing                └── GeoDNS routing
```

- **Consistency**: Eventual (cross-region replication lag)
- **Trade-offs**:
  - Rate limits are per-region (not global)
  - Kill switch propagation: up to 30s cross-region
  - Audit events may arrive out of order globally
- **Recommendation**: Use only when geographic latency requirements justify the
  complexity

### 8.3 Cloud-Specific Recommendations

| Cloud | Redis HA | Database HA | Recommended Topology |
|-------|---------|-------------|---------------------|
| **AWS** | ElastiCache Global Datastore | Aurora Global Database | Active-passive with < 1s replication |
| **Azure** | Azure Cache for Redis (geo-replication) | Azure SQL Geo-Replication | Active-passive with auto-failover groups |
| **GCP** | Memorystore (cross-region replication) | Cloud SQL (cross-region replicas) | Active-passive with Cloud DNS failover |

---

## 9. DPoP Replay Cache

### 9.1 Per-Region Design

The DPoP JTI replay cache is **intentionally per-region** (not replicated):

- DPoP proofs are bound to specific URLs (including region-specific endpoints)
- Cross-region replay is inherently prevented by URL binding
- Replicating JTI caches would add latency without security benefit
- Each region maintains its own JTI set with TTL-based cleanup

### 9.2 Consistency Guarantee

- **Within region**: Strong (single Redis instance)
- **Cross-region**: Not applicable (proofs are URL-bound)

---

## 10. Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `EUNO_DEPLOYMENT_TIER` | `single-replica` | Deployment tier |
| `KILL_SWITCH_REFRESH_INTERVAL_MS` | 30000 | Safety-net refresh interval |
| `KILL_SWITCH_PUBSUB_ENABLED` | true | Enable pub/sub propagation |
| `REVOCATION_UNAVAILABLE_MODE` | `fail-closed` | Behavior when Redis unreachable |
| `REDIS_URL` | — | Primary Redis URL |
| `REDIS_REPLICA_URL` | — | Read-replica URL (multi-region) |

---

## 11. Consistency Guarantees Summary

| Property | Single-Replica | Multi-Replica | Multi-Region |
|----------|---------------|---------------|-------------|
| Kill switch latency | 0 | < 1s | < 30s |
| Revocation latency | 0 | < 1s | < 30s |
| Rate limit accuracy | Exact | Exact (shared Redis) | Approximate (per-region) |
| Audit ordering | Total | Causal (per-session) | Causal (per-session) |
| DPoP replay protection | Strong | Strong | Strong (per-region) |
| Partition tolerance | N/A | Redis failover | Fail-closed safety / fail-open best-effort |

---

## 12. Related Documents

- [Distributed State](DISTRIBUTED_STATE.md) — Kill switch and revocation architecture details
- [Redis Failure Modes](REDIS_FAILURE_MODES.md) — Fail-open vs. fail-closed policies
- [Deployment Guide](DEPLOYMENT.md) — Production deployment patterns
- [Deploy on EKS](deploy-eks.md) — AWS-specific multi-region guidance
- [Deploy on GKE](deploy-gke.md) — GCP-specific multi-region guidance
- [Multi-Cloud](multi-cloud.md) — Cross-cloud deployment patterns
- [Audit Chain Architecture](AUDIT_CHAIN_ARCHITECTURE.md) — Audit consistency model
