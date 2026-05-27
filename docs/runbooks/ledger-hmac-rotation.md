# Runbook: Audit Ledger HMAC Secret Rotation

> **Applies to:** `PostgresLedgerBackend` and `PerReplicaPostgresLedgerBackend`  
> **File:** `pkg/audit/audit.go`

---

## Overview

Every row in the audit ledger stores a `row_hmac` column:

```
HMAC-SHA256(hmacSecret, seq || ":" || previousHash || ":" || recordHash || ":" || replicaId)
```

This HMAC allows offline tamper detection: anyone who modifies a ledger row without knowing the `hmacSecret` will produce a detectable mismatch. The append-only model (no UPDATEs ever) means **historical rows cannot be altered without detection**, as long as the `hmacSecret` was different from the database admin credentials.

---

## Provisioning the `hmacSecret`

The `hmacSecret` is passed as the `AUDIT_LEDGER_HMAC_SECRET` environment variable (or injected via `PostgresLedgerBackend({ hmacSecret: ... })`). It must decode to **at least 32 bytes (256 bits)**.

### Generating a new secret

```bash
# Hex format (recommended — clearly typed, hard to accidentally truncate)
openssl rand -hex 32
# → e.g. a3f2b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2

# Base64 format (also accepted)
openssl rand -base64 32
```

Store the secret in your key-management system (e.g. Azure Key Vault, AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault). Never commit it to source control or environment files.

### Accepted formats

| Format                | Example                   | Minimum length            |
| --------------------- | ------------------------- | ------------------------- |
| 64-char lowercase hex | `openssl rand -hex 32`    | 64 hex chars (= 32 bytes) |
| Base64                | `openssl rand -base64 32` | decodes to ≥ 32 bytes     |
| Raw UTF-8             | any printable string      | 32 chars                  |

---

## Why HMAC rotation is complex

**Rotating `hmacSecret` invalidates every existing row's HMAC.** The stored `row_hmac` was computed with the old secret; the backend computes a fresh HMAC with the new secret and the two values will never match — `verifyRowHmac` returns `false` for every historical row, defeating tamper detection for all pre-rotation records.

There are three safe rotation strategies:

---

## Strategy A: New table (recommended for production)

Create a new ledger table, configure the backend to write to it with the new secret, and retire the old table as read-only archival.

### Steps

1. **Generate and provision the new secret** (see §Provisioning above).

2. **Create the new table** by pointing the backend at a new table name:

   ```bash
   AUDIT_LEDGER_TABLE=eunox_audit_ledger_v2   # new table name
   AUDIT_LEDGER_HMAC_SECRET=<new-secret>
   AUDIT_LEDGER_SCHEMA_INIT=true              # let the backend run CREATE TABLE IF NOT EXISTS
   ```

3. **Deploy the new configuration.** New audit events are written to `eunox_audit_ledger_v2` with HMACs computed using the new secret. Old events remain in `eunox_audit_ledger` with HMACs verifiable using the old secret.

4. **Keep the old secret available** for offline HMAC verification of historical rows until you no longer need to verify them (or until the retention window expires).

5. **Archive / drop the old table** once the retention window expires and the old secret can be decommissioned.

### Verification

```sql
-- Verify recent rows in the new table using pgcrypto (requires the new secret).
-- Replace $NEW_SECRET_HEX with the 64-char hex-encoded new secret.
-- The HMAC message format is: seq:previousHash:recordHash:replicaId
SELECT
  seq,
  CASE
    WHEN row_hmac = hmac(
      (seq::text || ':' || previous_hash || ':' || record_hash || ':' || replica_id)::bytea,
      decode('$NEW_SECRET_HEX', 'hex'),
      'sha256'
    ) THEN 'OK'
    ELSE 'TAMPERED'
  END AS hmac_status
FROM eunox_audit_ledger_v2
WHERE seq BETWEEN 1 AND 100
ORDER BY seq;
```

---

## Strategy B: Dual-secret verification during the rotation window

For deployments that cannot tolerate table recreation, add a `verifyHmac(oldSecret)` fallback path during the rotation window:

1. **Generate the new secret** but do NOT yet restart the gateway.

2. **Run the backfill script** to recompute `row_hmac` for every existing row using the new secret (requires an exclusive maintenance window and disabling writes):

   ```sql
   -- CAUTION: requires AUDIT_LEDGER_WRITE_LOCK during this operation.
   -- Replace $NEW_SECRET_HEX with the hex-encoded new secret.
   -- pgcrypto hmac() produces the same HMAC-SHA256 as Go's
   --   hmac.New(sha256.New, secret).Write(message).Sum(nil)
   -- The message format matches the gateway: seq:previousHash:recordHash:replicaId
   UPDATE eunox_audit_ledger SET row_hmac = (
     hmac(
       (seq::text || ':' || previous_hash || ':' || record_hash || ':' || replica_id)::bytea,
       decode($NEW_SECRET_HEX, 'hex'),
       'sha256'
     )
   );
   ```

   > **Prerequisites:** The `pgcrypto` extension must be installed
   > (`CREATE EXTENSION IF NOT EXISTS pgcrypto`). The `$NEW_SECRET_HEX`
   > placeholder must be replaced with the actual hex-encoded secret value
   > (e.g. a 32-byte value as 64 hex characters). Alternatively, use an
   > offline script that reads, recomputes, and updates each row in batches.

3. **Deploy the new secret.** HMACs for all rows now match the new secret.

4. **Decommission the old secret.**

### Risk

Any tampering that occurred between step 1 and step 2 is overwritten by the backfill and will not be detected afterwards. This window is acceptable only during a planned maintenance window with reduced blast radius (no live traffic writing to the ledger).

---

## Strategy C: Per-row secret versioning (future hardening)

A future enhancement would store a `secret_version` column alongside `row_hmac` so the backend can select the correct HMAC secret for each row during verification. This allows rolling rotations without a maintenance window. This is **not yet implemented**; see the issue tracker for `LEDGER-HMAC-VERSIONING`.

---

## Deployment documentation

### Environment variables

| Variable                   | Description                                                                                   |
| -------------------------- | --------------------------------------------------------------------------------------------- |
| `AUDIT_LEDGER_HMAC_SECRET` | HMAC-SHA-256 secret (hex, base64, or UTF-8). Required when `ENABLE_CRYPTOGRAPHIC_AUDIT=true`. |
| `AUDIT_LEDGER_TABLE`       | Postgres table name (default `eunox_audit_ledger`). Change this for Strategy A rotation.      |
| `AUDIT_LEDGER_SCHEMA_INIT` | Set `true` to run `CREATE TABLE IF NOT EXISTS` on startup.                                    |

### Kubernetes / Helm

In production, provision `AUDIT_LEDGER_HMAC_SECRET` from a Kubernetes Secret object backed by an external secrets manager:

```yaml
# k8s/gateway-secret.yaml (managed by External Secrets Operator / Sealed Secrets)
apiVersion: v1
kind: Secret
metadata:
  name: gateway-audit-ledger-secrets
type: Opaque
stringData:
  AUDIT_LEDGER_HMAC_SECRET: "<injected-by-esm>"
```

Reference it in the gateway Deployment:

```yaml
env:
  - name: AUDIT_LEDGER_HMAC_SECRET
    valueFrom:
      secretKeyRef:
        name: gateway-audit-ledger-secrets
        key: AUDIT_LEDGER_HMAC_SECRET
```

### Cross-references

- `pkg/audit/audit.go` — backend implementation, `verifyRowHmac()` function
- `docs/architecture.md §7` — audit ledger design
