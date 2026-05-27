# Audit Chain Architecture & Trade-offs

**Status:** Living document
**Last Updated:** 2026-05-26

---

## Overview

The eunox audit system maintains tamper-evident, cryptographically-linked records using HMAC-SHA256 hash chains. Each audit record is digitally signed (Ed25519/RSA/ECDSA via KMS) and linked to its predecessor through a chain hash, providing append-only integrity guarantees.

---

## Chain Hash Mechanics

Each record's `chain_hash` is computed as:

```
chain_hash = HMAC-SHA256(
    key:     previous_record.chain_hash  (or "genesis" for the first record),
    message: record_id | timestamp_rfc3339nano | signature
)
```

This ensures:

- **Tamper evidence:** Altering any past record invalidates all subsequent chain hashes.
- **Ordering proof:** The chain establishes a cryptographic total order within each chain.
- **Non-repudiation:** Each record's signature is bound to its position in the chain.

---

## Backend Implementations

### `PostgresLedgerBackend` — Single-Writer (Advisory Lock)

**Package:** `pkg/audit/backend.go`

Uses a PostgreSQL advisory lock (default ID: `8675309`) to enforce single-writer semantics:

```
Replica A: AcquireLock() → Append() → ... → ReleaseLock()
Replica B: AcquireLock() → ErrLockContention (must retry or route elsewhere)
```

| Property | Value |
|----------|-------|
| Consistency | Strong — single global chain |
| Concurrency | Single-writer only |
| Verification | Simple — linear chain traversal |
| Failure mode | `ErrLockContention` on competing writers |

**When to use:**

- Single-replica deployments
- Staging/development environments
- Compliance scenarios requiring a single provable chain of custody
- Throughput ≤ 1,000 records/sec (bounded by PostgreSQL single-row insert latency)

**Limitations:**

- Only one gateway replica can write to the audit store at a time
- Under high load, competing replicas receive `ErrLockContention`
- No horizontal write scaling

---

### `PerReplicaPostgresLedgerBackend` — Lock-Free (Per-Replica Chains)

**Package:** `pkg/audit/backend.go`

Each replica maintains an independent HMAC chain identified by `replica_id`. No advisory lock is required:

```
Replica A (chain "replica-a"): Append(seqNum=1) → Append(seqNum=2) → ...
Replica B (chain "replica-b"): Append(seqNum=1) → Append(seqNum=2) → ...
```

| Property | Value |
|----------|-------|
| Consistency | Per-replica — eventual global via anchoring |
| Concurrency | Unlimited (one chain per replica) |
| Verification | Per-chain linear + cross-chain anchors |
| Failure mode | Partition-tolerant |

**When to use:**

- Multi-replica horizontal scaling (HPA-driven)
- High-throughput deployments (> 1,000 records/sec aggregate)
- Active-active multi-region deployments
- Environments where write contention is unacceptable

**Limitations:**

- No single global chain — cross-chain verification requires anchor reconciliation
- Verification complexity: O(replicas × records) vs O(records) for single-writer
- Chain anchoring adds storage overhead (`chain_anchors` table)

---

## Cross-Chain Anchoring

The `chain_anchors` table provides periodic consistency checkpoints:

```sql
CREATE TABLE chain_anchors (
    anchor_id     TEXT PRIMARY KEY,
    replica_id    TEXT NOT NULL,
    sequence_num  BIGINT NOT NULL,
    chain_hash    TEXT NOT NULL,
    merkle_root   TEXT NOT NULL,    -- Merkle root of records since last anchor
    backend       TEXT NOT NULL,    -- External anchoring backend (e.g., "blockchain", "notary")
    external_ref  TEXT NOT NULL,    -- External reference (tx hash, notary ID)
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

**Anchor semantics:**

1. Each anchor captures a snapshot of a replica's chain state at a specific sequence number.
2. The `merkle_root` covers all records from the previous anchor to this one, enabling efficient batch verification.
3. `external_ref` optionally links to an external notarization service for additional trust guarantees.

**Reconciliation strategy:**

- Anchors are created periodically (configurable interval) or at replica shutdown.
- Cross-chain verification: verify each replica's chain independently, then verify anchors form a consistent timeline.
- For audit export: merge replica chains by timestamp, verify per-chain hashes, then verify anchor consistency.

---

## Choosing a Backend

| Criteria | Single-Writer | Per-Replica |
|----------|:---:|:---:|
| Replicas | 1 | N |
| Throughput (records/sec) | ≤ 1,000 | 1,000 × N |
| Chain verification | Trivial | Per-replica + anchors |
| Compliance (single chain of custody) | ✅ | ❌ (multiple chains) |
| Zero lock contention | ❌ | ✅ |
| Horizontal autoscaling | ❌ | ✅ |
| Disaster recovery simplicity | Simple | Complex (per-replica restore) |

**Decision matrix:**

- **`EUNO_DEPLOYMENT_TIER=single-replica`** → Use `PostgresLedgerBackend`
- **`EUNO_DEPLOYMENT_TIER=multi-replica`** → Use `PerReplicaPostgresLedgerBackend`
- **`EUNO_DEPLOYMENT_TIER=multi-region-active-active`** → Use `PerReplicaPostgresLedgerBackend` with regional anchoring

---

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `EUNO_DEPLOYMENT_TIER` | `single-replica` | Determines backend selection |

`AUDIT_ADVISORY_LOCK_ID`, `AUDIT_REPLICA_ID`, and `AUDIT_ANCHOR_INTERVAL_SECONDS` are architecture-level tuning concepts documented here, but they are not currently exposed as first-class environment variables in this Go codebase.

---

## Future Considerations

### Event Streaming Transport

For very high-throughput deployments (> 10,000 records/sec), consider a Kafka/NATS-based audit transport:

- **Producer:** Each replica publishes signed records to a partitioned topic.
- **Consumer:** A dedicated service consumes, verifies, and persists to PostgreSQL.
- **Benefits:** Decouples write latency from persistence latency; enables fan-out to multiple sinks.
- **Trade-off:** Eventual consistency; requires idempotent consumers.

### Chain Pruning

For long-running deployments, chain pruning with checkpoint preservation:

1. Create an anchor at the prune boundary.
2. Archive records below the boundary to cold storage.
3. Retain the anchor as the new genesis for the active chain.
4. Verification of pruned records requires retrieving archived data.

---

## Transport Buffer Overflow Policy

**Package:** `pkg/audit/transport.go`

The OCSF audit transports (HTTP, Azure Sentinel) use a bounded, buffered channel for internal event queuing. The `Enqueue()` method is **non-blocking by design**:

| Condition | Behavior | Metric |
|-----------|----------|--------|
| Buffer has capacity | Event queued for batched delivery | `audit_enqueue_total{status="success"}` |
| Buffer is full | Event is **dropped immediately** — returns `ErrBatchFull` | `audit_enqueue_total{status="dropped"}` |
| Transport is closed | Returns `ErrTransportClosed` | — |

### Design Rationale

The enforcement hot path (token validation → audit write → response) must not block on slow or unavailable SIEM sinks. A blocking `Enqueue` would cause latency spikes on the enforcement path when the transport sink is degraded, effectively coupling availability of the governance system to availability of the telemetry backend.

### Operator Implications

1. **Dropped events are permanently lost** from the transport's perspective. However, the primary audit record is always persisted to the PostgreSQL ledger backend *before* transport forwarding. The transport is a secondary fan-out mechanism for SIEM integration — the ledger is the source of truth.

2. **Monitoring:** Operators MUST alert on `audit_enqueue_total{status="dropped"} > 0`. A non-zero drop rate indicates either:
   - The SIEM sink is too slow (increase sink concurrency or throughput)
   - The buffer is undersized for the burst pattern (increase `BufferSize` in `TransportConfig`)
   - A network partition between the gateway and the SIEM endpoint

3. **Reconciliation:** If drops occur, operators can reconcile by querying the PostgreSQL audit ledger (via `GET /api/v1/audit/export`) for the affected time window and re-ingesting into the SIEM.

4. **Buffer sizing:** The default buffer size is 10,000 events. At a typical audit record size of ~2 KB, this represents ~20 MB of in-memory buffering. For sustained throughput of 1,000 events/sec with a 5-second flush interval, the buffer can absorb ~2 flush cycles of backpressure.

### Alternative Policies (Not Currently Implemented)

For deployments requiring zero audit event loss on the transport path:

- **Disk write-aside:** On buffer full, write events to a local WAL file for later replay. Adds disk I/O to the hot path but guarantees eventual delivery.
- **Synchronous delivery:** Block `Enqueue` until space is available. Couples enforcement latency to SIEM availability — not recommended for production.
- **Back-pressure signaling:** Return a specific error that causes the caller to apply admission control (reject new requests until buffer drains).

These alternatives are documented here for future consideration but are not implemented in the current release. The PostgreSQL ledger guarantees no audit data loss; the transport overflow policy only affects real-time SIEM forwarding.

---

## Verification API

Chain integrity can be verified via the `GetChainSegment` API:

```go
// Verify a contiguous segment of the chain.
segment, err := queryStore.GetChainSegment(ctx, replicaID, fromSeq, toSeq)
for i, record := range segment {
    if !VerifyChainHash(&record) {
        // Chain integrity violation at sequence number record.SequenceNum
    }
}
```

For cross-replica verification, verify each replica's chain independently, then verify that anchor timestamps are consistent across replicas.

---

*See also: [architecture.md](./architecture.md), [schema-migrations.md](./schema-migrations.md)*
