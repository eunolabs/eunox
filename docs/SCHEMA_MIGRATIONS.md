# Schema Migrations

**Status:** Living document
**Last Updated:** 2026-05-26

---

## Overview

eunox uses a custom migration framework (`internal/migrate`) for database schema management. The framework provides:

- **Advisory locking** for safe multi-instance deployments
- **Dirty state detection** for recovery from failed migrations
- **Rollback safety validation** — every `.up.sql` must have a corresponding `.down.sql`
- **Pre-migration backup hooks** for destructive changes

---

## Migration File Convention

### Naming

```
NNN_description.{up,down}.sql
```

- `NNN`: Sequential positive integer (001, 002, 003…) — no gaps allowed.
- `description`: Snake-case summary of the change (e.g., `create_audit_records`, `add_expiry_index`).
- Direction suffix: `.up.sql` for forward migration, `.down.sql` for rollback.

### Requirements

1. Every `.up.sql` **must** have a corresponding `.down.sql` (enforced by the runner and CI).
2. All SQL files **must** include the BSL license header:
   ```sql
   -- Copyright 2026 Eunox Authors
   -- SPDX-License-Identifier: BUSL-1.1
   ```
3. Use `IF NOT EXISTS` / `IF EXISTS` guards for idempotency where appropriate.
4. Down migrations must be the **exact inverse** of the corresponding up migration.

### Directory Structure

```
migrations/
├── audit/
│   ├── 001_create_audit_records.up.sql
│   └── 001_create_audit_records.down.sql
└── minter/
    ├── 001_create_api_keys.up.sql
    └── 001_create_api_keys.down.sql
```

Each service domain has its own migration directory. The migration runner operates independently per domain.

---

## Schema Reference

### Audit Domain

#### `audit_records` — Immutable Append-Only Ledger

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | TEXT | PRIMARY KEY | Unique record identifier (UUID) |
| `sequence_num` | BIGINT | NOT NULL | Monotonic sequence within the chain |
| `replica_id` | TEXT | NOT NULL | Producing replica identifier |
| `tenant_id` | TEXT | NOT NULL | Tenant scope |
| `timestamp` | TIMESTAMPTZ | NOT NULL, DEFAULT NOW() | Event occurrence time |
| `event_type` | TEXT | NOT NULL | Event classification |
| `actor_user_id` | TEXT | NOT NULL, DEFAULT '' | Performing user |
| `actor_tenant_id` | TEXT | NOT NULL, DEFAULT '' | Actor's tenant |
| `action` | TEXT | NOT NULL | Action performed |
| `resource_uid` | TEXT | NOT NULL, DEFAULT '' | Target resource UID |
| `resource_type` | TEXT | NOT NULL, DEFAULT '' | Target resource type |
| `outcome` | TEXT | NOT NULL | Result (success/failure) |
| `detail` | JSONB | nullable | Structured event detail |
| `signature` | TEXT | NOT NULL | Digital signature (base64url) |
| `algorithm` | TEXT | NOT NULL | Signing algorithm |
| `key_id` | TEXT | NOT NULL | Signing key identifier |
| `chain_hash` | TEXT | NOT NULL | HMAC chain hash |
| `previous_hash` | TEXT | NOT NULL, DEFAULT '' | Previous record's chain hash |
| `ocsf_event` | JSONB | nullable | Full OCSF event for export |
| `metadata` | JSONB | NOT NULL, DEFAULT '{}' | Operator-defined key-value metadata |
| `created_at` | TIMESTAMPTZ | NOT NULL, DEFAULT NOW() | Persistence timestamp |

**Indexes:**

| Name | Columns | Type | Purpose |
|------|---------|------|---------|
| `idx_audit_records_tenant_timestamp` | `(tenant_id, timestamp DESC)` | B-tree | Chronological per-tenant queries |
| `idx_audit_records_event_type` | `(event_type)` | B-tree | Event type filtering |
| `idx_audit_records_replica_seq` | `(replica_id, sequence_num)` | Unique | Chain traversal & integrity |
| `idx_audit_records_actor` | `(actor_user_id)` | B-tree | Actor lookups |

#### `chain_anchors` — Cross-Chain Anchoring Checkpoints

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `anchor_id` | TEXT | PRIMARY KEY | Unique anchor identifier |
| `replica_id` | TEXT | NOT NULL | Source replica |
| `sequence_num` | BIGINT | NOT NULL | Anchor sequence position |
| `chain_hash` | TEXT | NOT NULL | Chain hash at anchor point |
| `merkle_root` | TEXT | NOT NULL | Merkle root of interval |
| `backend` | TEXT | NOT NULL, DEFAULT '' | External anchoring backend |
| `external_ref` | TEXT | NOT NULL, DEFAULT '' | External reference |
| `created_at` | TIMESTAMPTZ | NOT NULL, DEFAULT NOW() | Anchor creation time |

**Indexes:**

| Name | Columns | Type | Purpose |
|------|---------|------|---------|
| `idx_chain_anchors_replica` | `(replica_id, sequence_num DESC)` | B-tree | Anchor lookups by replica |

---

### Minter Domain

#### `api_keys` — Hashed API Key Storage

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `key_id` | TEXT | PRIMARY KEY | Key identifier (public) |
| `secret_hash` | TEXT | NOT NULL | HMAC-SHA256 hash of key secret |
| `tenant_id` | TEXT | NOT NULL | Owning tenant |
| `description` | TEXT | NOT NULL, DEFAULT '' | Human-readable description |
| `created_at` | TIMESTAMPTZ | NOT NULL, DEFAULT NOW() | Creation time |
| `expires_at` | TIMESTAMPTZ | nullable | Expiration time |
| `revoked_at` | TIMESTAMPTZ | nullable | Revocation time |
| `created_by` | TEXT | NOT NULL, DEFAULT '' | Creating operator |
| `metadata` | JSONB | NOT NULL, DEFAULT '{}' | Key-value metadata |

**Indexes:**

| Name | Columns | Purpose |
|------|---------|---------|
| `idx_api_keys_tenant_id` | `(tenant_id)` | Tenant scoped queries |
| `idx_api_keys_created_at` | `(created_at DESC)` | Chronological listing |

#### `key_policies` — API Key Policies

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `policy_id` | TEXT | PRIMARY KEY | Policy identifier |
| `tenant_id` | TEXT | NOT NULL | Owning tenant |
| `name` | TEXT | NOT NULL | Policy name |
| `description` | TEXT | NOT NULL, DEFAULT '' | Human-readable description |
| `rules` | JSONB | NOT NULL, DEFAULT '{}' | Policy rules |
| `created_at` | TIMESTAMPTZ | NOT NULL, DEFAULT NOW() | Creation time |
| `updated_at` | TIMESTAMPTZ | NOT NULL, DEFAULT NOW() | Last modification time |
| `created_by` | TEXT | NOT NULL, DEFAULT '' | Creating operator |

**Indexes:**

| Name | Columns | Type | Purpose |
|------|---------|------|---------|
| `idx_key_policies_tenant_id` | `(tenant_id)` | B-tree | Tenant scoped queries |
| `idx_key_policies_tenant_name` | `(tenant_id, name)` | Unique | Policy name uniqueness per tenant |

---

## Migration Runner

### Usage

```go
import "github.com/edgeobs/eunox/internal/migrate"

runner, err := migrate.NewRunner(&migrate.Config{
    Source:     os.DirFS("migrations/audit"),
    Store:      postgresStateStore,
    Executor:   postgresSQLExecutor,
    Locker:     advisoryLocker,        // Optional: for multi-instance safety
    BackupHook: preBackupFunc,         // Optional: called before migrations
    Logger:     slog.Default(),
})

// Apply all pending migrations
applied, err := runner.MigrateUp(ctx)

// Roll back one migration
err = runner.MigrateDown(ctx)

// Check pending migrations (useful for health checks)
pending, err := runner.Pending(ctx)
```

### Safety Guarantees

1. **Advisory locking:** Prevents concurrent migration execution across replicas.
2. **Dirty state detection:** If a previous migration failed mid-execution, the runner refuses to proceed until manually resolved.
3. **Rollback validation:** Before applying any migration, the runner verifies all up migrations have corresponding down migrations.
4. **Atomic marking:** Each migration is marked dirty before execution and clean after, enabling precise failure recovery.

---

## CI Validation

Migration files are validated in CI via the `migration-validation` job:

1. **File existence:** Every `.up.sql` has a matching `.down.sql`.
2. **Sequential numbering:** Version numbers are contiguous (no gaps).
3. **SQL syntax:** Basic SQL syntax validation via SQLite dry-run.
4. **License headers:** All files include the BSL license header.
5. **Naming convention:** Filenames follow `NNN_description.{up,down}.sql`.

---

## Adding a New Migration

1. Determine the next version number (current max + 1).
2. Create both files:
   ```
   migrations/<domain>/NNN_description.up.sql
   migrations/<domain>/NNN_description.down.sql
   ```
3. Include the license header in both files.
4. Ensure the down migration is the exact inverse of the up migration.
5. Run `make test` to verify the migration is recognized and valid.

---

## Startup Validation

Each service validates its migration state at startup:

1. Connects to the database.
2. Checks for dirty state (failed previous migration).
3. Verifies current version matches expected version.
4. If pending migrations exist, applies them (when `MIGRATE_ON_STARTUP=true`) or logs a warning.

This ensures schema drift is detected early and prevents services from operating against an unexpected schema.

---

*See also: [AUDIT_CHAIN_ARCHITECTURE.md](./AUDIT_CHAIN_ARCHITECTURE.md), [DEPLOYMENT.md](./DEPLOYMENT.md)*
