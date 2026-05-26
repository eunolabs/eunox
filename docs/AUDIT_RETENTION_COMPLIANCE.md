# Audit Retention and Compliance Strategy

> **Audience:** Compliance officers, security engineers, and operators
> managing audit data lifecycle in eunox deployments.

---

## Table of Contents

1. [Overview](#overview)
2. [Retention Policy](#retention-policy)
3. [HMAC Chain and Deletion](#hmac-chain-and-deletion)
4. [Chain-Compatible Pruning](#chain-compatible-pruning)
5. [Archive Strategy](#archive-strategy)
6. [Compliance Targets](#compliance-targets)
7. [GDPR Considerations](#gdpr-considerations)
8. [Operational Procedures](#operational-procedures)
9. [Verification and Integrity](#verification-and-integrity)
10. [Configuration Reference](#configuration-reference)

---

## Overview

The eunox audit system provides a **tamper-evident, cryptographically
linked** record of all enforcement decisions, token lifecycle events, and
administrative actions. The audit trail uses a dual-layer integrity model:

1. **HMAC-SHA256 chain:** Each record's `chain_hash` is computed from the
   previous record's hash, creating an ordered, tamper-evident sequence
2. **Digital signatures:** Each record is independently signed via KMS
   (Ed25519/ECDSA/RSA), enabling offline verification without the HMAC
   secret

This document defines the retention, archival, and compliance strategy for
managing audit data through its lifecycle.

---

## Retention Policy

### Default Retention Periods

| Data Category | Retention Period | Justification |
|---------------|-----------------|---------------|
| Enforcement decisions | 90 days (hot) + 2 years (archive) | Incident investigation + compliance |
| Token issuance events | 90 days (hot) + 2 years (archive) | Security audit trail |
| Administrative actions | 90 days (hot) + 7 years (archive) | SOC 2 + regulatory |
| Partner federation events | 90 days (hot) + 7 years (archive) | Cross-org accountability |
| Kill switch activations | Permanent | Critical security events |

### Storage Tiers

```
┌──────────────────────────────────────────────────────────────┐
│  HOT TIER (PostgreSQL)                                        │
│  Retention: 90 days                                           │
│  Access: Real-time queries via /api/v1/audit/records          │
│  Performance: Indexed for sub-second queries                  │
├──────────────────────────────────────────────────────────────┤
│  WARM TIER (Object Storage — standard class)                  │
│  Retention: 90 days – 2 years                                 │
│  Access: Batch retrieval via /api/v1/audit/export             │
│  Performance: Minutes for large exports                       │
├──────────────────────────────────────────────────────────────┤
│  COLD TIER (Object Storage — archive class)                   │
│  Retention: 2 – 7 years                                       │
│  Access: Restore request required (hours)                     │
│  Performance: Hours for retrieval                             │
├──────────────────────────────────────────────────────────────┤
│  DELETED                                                      │
│  After retention period expires                               │
│  Verified via anchor checkpoints before deletion              │
└──────────────────────────────────────────────────────────────┘
```

---

## HMAC Chain and Deletion

### Chain Integrity Model

Each audit record contains:

```
record[n].chain_hash = HMAC-SHA256(
    key:     record[n-1].chain_hash,    // previous hash (or "genesis")
    message: record[n].id | record[n].timestamp | record[n].signature
)
```

**Implication:** Deleting any record breaks the chain for all subsequent
records. The chain hash of record N+1 depends on record N's hash, so
removing N makes N+1's hash unverifiable against its `previous_hash` field.

### Why Direct Deletion Is Unsafe

| Operation | Impact |
|-----------|--------|
| Delete middle record | Breaks chain from that point forward |
| Modify any field | Changes `chain_hash`, invalidating successors |
| Delete from beginning | Entire chain becomes unverifiable |
| Delete from end | Only affects future appends (safe for pruning) |

---

## Chain-Compatible Pruning

### Anchor-Based Pruning Protocol

The safe pruning strategy uses **chain anchors** as verified checkpoints:

```
Records: [1] ← [2] ← [3] ← [4] ← [5] ← [6] ← [7] ← [8] ← [9] ← [10]
                              ▲                                        ▲
                           Anchor A                                 Anchor B
                        (records 1–4)                            (records 5–10)
```

**Steps:**

1. **Create anchor at prune boundary:**
   ```sql
   -- Anchor captures: replica_id, sequence range, chain_hash at boundary,
   -- and Merkle root of all records in the segment
   INSERT INTO chain_anchors (anchor_id, replica_id, sequence_num, chain_hash, merkle_root, backend, external_ref)
   VALUES ('anchor-A', 'replica-1', 4, '<hash-at-4>', '<merkle-root-1-to-4>', 's3', 's3://bucket/anchor-A.json');
   ```

2. **Archive records below boundary to cold storage:**
   - Export records 1–4 as signed JSON-lines to object storage
   - Include the Merkle tree for independent verification
   - Use S3 Object Lock (Compliance mode) to prevent tampering

3. **Verify archive integrity:**
   - Recompute Merkle root from archived records
   - Compare with anchor's `merkle_root`
   - Verify each record's digital signature independently

4. **Delete pruned records from hot tier:**
   ```sql
   DELETE FROM audit_records
   WHERE replica_id = 'replica-1' AND sequence_num <= 4;
   ```

5. **Anchor becomes new genesis:**
   - Record 5's `previous_hash` matches the anchor's `chain_hash`
   - Chain verification continues from the anchor forward
   - Full historical verification requires archive retrieval

### External Anchoring Backends

| Backend | Immutability Guarantee | Use Case |
|---------|------------------------|----------|
| AWS S3 Object Lock | Compliance mode (WORM) | Standard deployments |
| Azure Confidential Ledger | Blockchain-backed | High-assurance |
| Azure Blob (immutable) | Time-based retention lock | Azure deployments |
| GCS (retention policy) | Bucket-level lock | GCP deployments |

---

## Archive Strategy

### Archive Format

Archived segments are stored as **signed bundles**:

```
archive-segment-{replica_id}-{start_seq}-{end_seq}.jsonl.gz
├── record[start] (JSON line)
├── record[start+1] (JSON line)
├── ...
├── record[end] (JSON line)
└── manifest.json
    ├── anchor_id
    ├── merkle_root
    ├── record_count
    ├── time_range (start..end)
    ├── signing_key_id
    └── bundle_signature
```

### Archive Lifecycle

| Cloud | Hot → Warm | Warm → Cold | Cold → Delete |
|-------|------------|-------------|---------------|
| AWS | S3 Lifecycle: Standard → IA (90 days) | IA → Glacier (2 years) | Glacier expiry (7 years) |
| Azure | Blob: Hot → Cool (90 days) | Cool → Archive (2 years) | Archive expiry (7 years) |
| GCP | GCS: Standard → Nearline (90 days) | Nearline → Coldline (2 years) | Coldline expiry (7 years) |

### Backup Integration

The archive strategy integrates with database backup:

- **WAL archival:** Continuous PostgreSQL WAL shipping provides point-in-time
  recovery for the hot tier (RPO: 1 hour)
- **Archive independence:** Cold-tier archives are independent of database
  backups — they are self-contained and self-verifiable
- **Dual write:** Anchors are written to both the database and external
  storage for redundancy

---

## Compliance Targets

### SOC 2 Type II

| Control | Requirement | Eunox Implementation |
|---------|-------------|---------------------|
| CC6.1 | Logical access controls logged | All enforcement decisions audited |
| CC6.2 | Access provisioning tracked | Token issuance and revocation recorded |
| CC7.1 | System operations monitored | Admin actions with operator attribution |
| CC7.2 | Anomaly detection supported | Audit export in OCSF v1.1 for SIEM |
| CC8.1 | Change management tracked | Policy changes audited |

**Retention requirement:** Minimum 1 year for SOC 2 audit evidence.

### HIPAA

| Requirement | Implementation |
|-------------|---------------|
| 45 CFR § 164.312(b) | Audit trail for PHI access (6 years) |
| 45 CFR § 164.530(j) | Documentation retention (6 years) |
| Integrity controls | HMAC chain + digital signatures |
| Access controls | Tenant-scoped queries |

### PCI DSS v4.0

| Requirement | Implementation |
|-------------|---------------|
| 10.2 | All access to cardholder data logged |
| 10.3 | Sufficient detail in audit entries |
| 10.5 | Audit trail integrity (HMAC chain) |
| 10.7 | Retain for at least 12 months (3 months immediately available) |

### GDPR

See [dedicated section below](#gdpr-considerations).

---

## GDPR Considerations

### Right to Erasure (Article 17)

The HMAC chain creates tension with GDPR's right to erasure. Eunox resolves
this through **pseudonymization and selective redaction**:

#### Strategy 1: Pseudonymized Actor IDs (Recommended)

Store pseudonymized identifiers in audit records instead of PII:

```json
{
  "actor": "sha256:a1b2c3...",  // Hash of user identifier
  "tenant_id": "acme"
}
```

- The mapping `user_email → sha256_hash` is stored separately
- Erasure request → delete the mapping, rendering audit records
  non-attributable (functionally anonymized)
- Chain integrity is preserved (no record modification needed)

#### Strategy 2: Redaction with Attestation

For records that must contain identifiable information:

1. Create a **redaction attestation** record in the chain
2. Overwrite PII fields with `[REDACTED:erasure-request-{id}]`
3. The redaction itself is an auditable event
4. Chain integrity: The `chain_hash` covers the original signature (which
   covers original content), so post-hoc redaction is detectable but
   acceptable as a documented compliance action

#### Strategy 3: Segment Deletion (Last Resort)

If an entire segment must be removed:

1. Create anchor before and after the segment
2. Archive the segment with access controls
3. Delete from hot tier
4. Document the gap with a "compliance deletion" anchor
5. Chain verification skips the gap via anchor-to-anchor validation

### Data Minimization (Article 5(1)(c))

- Audit records store the minimum information needed for security
  accountability
- Capability token content is not stored (only the enforcement decision)
- User identifiers are pseudonymized by default
- IP addresses are retained only for rate-limiting forensics (configurable)

### Data Retention Limits (Article 5(1)(e))

Retention periods are defined per data category (see [Retention Policy](#retention-policy)).
Automated lifecycle policies enforce deletion after the configured period.
No audit data is retained indefinitely except critical security events
(kill switch activations).

---

## Operational Procedures

### Configuring Retention

Retention is managed via object storage lifecycle policies. Example for AWS:

```json
{
  "Rules": [
    {
      "ID": "audit-hot-to-warm",
      "Filter": {"Prefix": "audit/hot/"},
      "Transitions": [
        {"Days": 90, "StorageClass": "STANDARD_IA"}
      ]
    },
    {
      "ID": "audit-warm-to-cold",
      "Filter": {"Prefix": "audit/warm/"},
      "Transitions": [
        {"Days": 730, "StorageClass": "GLACIER"}
      ]
    },
    {
      "ID": "audit-cold-expiry",
      "Filter": {"Prefix": "audit/cold/"},
      "Expiration": {"Days": 2555}
    }
  ]
}
```

### Running a Prune Cycle

```bash
# 1. Identify prune boundary (records older than 90 days)
BOUNDARY_SEQ=$(psql -t -c "SELECT max(sequence_num) FROM audit_records WHERE timestamp < NOW() - INTERVAL '90 days'")

# 2. Create anchor at boundary via offline anchoring job
# (gateway does not currently expose an HTTP /admin audit anchor endpoint)
# Use tooling built on pkg/audit/anchor.go.

# 3. Export and archive records
curl "https://gateway:3002/api/v1/audit/export?tenant_id=$TENANT_ID" \
  -H "Authorization: ******" \
  -o "archive-segment.jsonl.gz"

# 4. Upload to archive storage with Object Lock
aws s3 cp archive-segment.jsonl.gz \
  s3://eunox-audit-archive/segments/ \
  --object-lock-mode COMPLIANCE \
  --object-lock-retain-until-date "2033-05-26T00:00:00Z"

# 5. Verify archive integrity
# (verify Merkle root matches anchor)

# 6. Delete pruned records
psql -c "DELETE FROM audit_records WHERE sequence_num <= $BOUNDARY_SEQ"
```

### Verifying Chain Integrity

```bash
# Verify current chain
curl "https://gateway:3002/api/v1/audit/chain-proof?replica_id=replica-1&from_seq=1&to_seq=1000000" \
  -H "Authorization: ******"

# Response includes:
# - replica_id, from_seq, to_seq
# - count, valid
# - broken_at_seq (when valid=false)
# - first_hash / last_hash
```

---

## Verification and Integrity

### Online Verification

The gateway exposes chain verification endpoints:

| Endpoint | Purpose |
|----------|---------|
| `GET /api/v1/audit/chain-proof` | Verify hot-tier chain integrity |
| `GET /api/v1/audit/signing-keys` | Export public keys for offline verification |
| `GET /api/v1/audit/export` | Export records in OCSF v1.1 format |

### Offline Verification

Archived segments can be verified independently:

1. **Signature verification:** Each record's signature is verifiable with
   the signing public key (exported via `/api/v1/audit/signing-keys`)
2. **Chain verification:** Recompute chain hashes from the segment's anchor
   hash forward (no deploy-time secret is required)
3. **Merkle verification:** Recompute Merkle root and compare with anchor

### Tamper Detection

| Modification | Detection Method |
|-------------|------------------|
| Record content changed | Signature verification fails |
| Record deleted (middle) | Chain hash mismatch on successor |
| Record inserted | Sequence number gap or chain break |
| Record reordered | Timestamp / sequence monotonicity violation |
| Anchor modified | External storage integrity (Object Lock) |

---

## Configuration Reference (Proposed / Future)

> The following variables describe a proposed automation surface. They are
> not currently wired in the Go runtime configuration.

| Variable | Default | Description |
|----------|---------|-------------|
| `AUDIT_HOT_RETENTION_DAYS` | 90 | Days before records are eligible for archival |
| `AUDIT_ARCHIVE_BACKEND` | `s3` | Archive storage backend (s3, azure-blob, gcs) |
| `AUDIT_ARCHIVE_BUCKET` | — | Object storage bucket for archives |
| `AUDIT_ANCHOR_BACKEND` | `s3` | Anchor storage backend |
| `AUDIT_PRUNE_ENABLED` | `false` | Enable automated pruning (requires archive backend) |
| `AUDIT_PRUNE_SCHEDULE` | `0 2 * * 0` | Cron schedule for prune cycles (weekly default) |
| `AUDIT_MERKLE_VERIFY_ON_PRUNE` | `true` | Verify Merkle root before deleting records |

---

*Document created as part of Phase 4 (OQ-3) of the architecture review.*
