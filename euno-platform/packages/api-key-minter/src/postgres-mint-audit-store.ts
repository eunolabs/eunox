/**
 * PostgresMintAuditStore — append-only Postgres-backed mint audit store
 * ────────────────────────────────────────────────────────────────────────────
 * Implements {@link MintAuditStore} with an append-only Postgres table.
 *
 * ## Threat-model requirement — separate credentials
 *
 * The minter threat model (docs/security/minter-threat-model.md §6) requires
 * that the mint-audit store uses **credentials separate from the minter's
 * main credentials**.  The intent is that a compromised minter process cannot
 * retroactively delete or alter its own audit trail.
 *
 * In practice this means:
 *
 *   1. The Postgres role used by the minter (`MINTER_DB_URL`) has
 *      `INSERT`-only privileges on `mint_audit`.
 *   2. A separate read-only role (`MINTER_AUDIT_DB_URL`) has `SELECT`-only
 *      privileges on the same table and is used by the incident-response
 *      tool / admin API, NOT by the minter process itself.
 *   3. The `id` column is `GENERATED ALWAYS AS IDENTITY` (Postgres 10+), which
 *      prevents the inserting role from overriding the sequence even if it
 *      accidentally has more privileges than intended.
 *   4. No `UPDATE` or `DELETE` privileges are granted to either role.
 *
 * ## DDL
 *
 * ```sql
 * CREATE TABLE IF NOT EXISTS mint_audit (
 *   id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 *   key_prefix  TEXT        NOT NULL,
 *   tenant_id   TEXT        NOT NULL,
 *   agent_id    TEXT        NOT NULL,
 *   session_id  TEXT        NOT NULL,
 *   jti         TEXT        NOT NULL UNIQUE,
 *   policy_id   TEXT        NOT NULL,
 *   issued_at   TIMESTAMPTZ NOT NULL,
 *   expires_at  BIGINT      NOT NULL,
 *   kid         TEXT        NOT NULL,
 *   result      TEXT        NOT NULL DEFAULT 'minted',
 *   reason      TEXT
 * );
 *
 * -- Indexes for blast-radius enumeration queries (threat model §2–3)
 * CREATE INDEX IF NOT EXISTS mint_audit_kid_idx       ON mint_audit (kid);
 * CREATE INDEX IF NOT EXISTS mint_audit_tenant_id_idx ON mint_audit (tenant_id);
 * CREATE INDEX IF NOT EXISTS mint_audit_result_idx    ON mint_audit (result)
 *   WHERE result != 'minted';  -- partial index for key-lifecycle events only
 * ```
 */

import { MintAuditRecord, MintAuditStore } from './mint-audit';

// ── Minimal PgPool interface (structural typing; no hard pg dep) ──────────────

/**
 * Minimal subset of the `pg.Pool` / `pg.Client` surface used by this class.
 * Using a structural interface keeps `@euno/api-key-minter` from declaring `pg`
 * as a hard dependency — callers construct the pool and pass it in.
 */
export interface MintAuditPgPool {
  query(text: string, values?: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
}

// ── Schema ────────────────────────────────────────────────────────────────────

/**
 * DDL executed by {@link PostgresMintAuditStore.ensureSchema}.
 * The `mint_audit` table is intentionally narrow: only the columns needed for
 * blast-radius enumeration and key-rotation auditing are present.
 */
export const MINT_AUDIT_DDL = `
CREATE TABLE IF NOT EXISTS mint_audit (
  id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  key_prefix  TEXT        NOT NULL,
  tenant_id   TEXT        NOT NULL,
  agent_id    TEXT        NOT NULL,
  session_id  TEXT        NOT NULL,
  jti         TEXT        NOT NULL UNIQUE,
  policy_id   TEXT        NOT NULL,
  issued_at   TIMESTAMPTZ NOT NULL,
  expires_at  BIGINT      NOT NULL,
  kid         TEXT        NOT NULL,
  result      TEXT        NOT NULL DEFAULT 'minted',
  reason      TEXT
);
CREATE INDEX IF NOT EXISTS mint_audit_kid_idx       ON mint_audit (kid);
CREATE INDEX IF NOT EXISTS mint_audit_tenant_id_idx ON mint_audit (tenant_id);
CREATE INDEX IF NOT EXISTS mint_audit_result_idx    ON mint_audit (result)
  WHERE result != 'minted';
`.trim();

// ── PostgresMintAuditStore ────────────────────────────────────────────────────

/**
 * Append-only Postgres-backed implementation of {@link MintAuditStore}.
 *
 * ### Append-only guarantee
 *
 * Only `INSERT` is ever issued against the `mint_audit` table.  There are no
 * `UPDATE` or `DELETE` calls.  Deploy with a Postgres role that has `INSERT`
 * and `SELECT` only (not `UPDATE`, `DELETE`, or `TRUNCATE`) to enforce this
 * at the database level.
 *
 * ### Usage
 *
 * ```typescript
 * import { Pool } from 'pg';
 * import { PostgresMintAuditStore } from '@euno/api-key-minter';
 *
 * const pool = new Pool({ connectionString: process.env.MINTER_AUDIT_DB_URL });
 * const auditStore = new PostgresMintAuditStore(pool);
 * await auditStore.ensureSchema();  // idempotent; run at startup
 * ```
 */
export class PostgresMintAuditStore implements MintAuditStore {
  constructor(private readonly pool: MintAuditPgPool) {}

  /**
   * Create the `mint_audit` table and its indexes if they do not yet exist.
   *
   * This method is idempotent (`IF NOT EXISTS`) and safe to call at every
   * process start.  For production deployments, prefer running migrations
   * with a dedicated migration tool and a privileged role.
   */
  async ensureSchema(): Promise<void> {
    // Split on ';' and execute each statement individually because the pg
    // driver does not support multi-statement queries in a single `query()`
    // call by default.
    const statements = MINT_AUDIT_DDL.split(';')
      .map(s => s.trim())
      .filter(s => s.length > 0);
    for (const statement of statements) {
      await this.pool.query(statement);
    }
  }

  /**
   * Insert a mint audit record.
   *
   * The database column `id` is `GENERATED ALWAYS AS IDENTITY` — it is never
   * supplied by the application layer, preventing an inserting-role from
   * overriding the sequence.
   *
   * @throws When the database `INSERT` fails (e.g. duplicate `jti`).
   */
  async record(entry: MintAuditRecord): Promise<void> {
    await this.pool.query(
      `INSERT INTO mint_audit
         (key_prefix, tenant_id, agent_id, session_id, jti, policy_id,
          issued_at, expires_at, kid, result, reason)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [
        entry.keyPrefix,
        entry.tenantId,
        entry.agentId,
        entry.sessionId,
        entry.jti,
        entry.policyId,
        entry.issuedAt,
        entry.expiresAt,
        entry.kid,
        entry.result ?? 'minted',
        entry.reason ?? null,
      ],
    );
  }

  /**
   * Retrieve audit records for a tenant, most-recent first, up to `limit` rows.
   *
   * Uses the `mint_audit_tenant_id_idx` index so the query is O(limit) for
   * any tenant regardless of total table size.
   */
  async listByTenant(tenantId: string, limit = 100): Promise<MintAuditRecord[]> {
    const { rows } = await this.pool.query(
      `SELECT id, key_prefix, tenant_id, agent_id, session_id, jti, policy_id,
              issued_at, expires_at, kid, result, reason
       FROM mint_audit
       WHERE tenant_id = $1
       ORDER BY id DESC
       LIMIT $2`,
      [tenantId, limit],
    );

    return rows.map(row => ({
      id: row['id'] as number,
      keyPrefix: row['key_prefix'] as string,
      tenantId: row['tenant_id'] as string,
      agentId: row['agent_id'] as string,
      sessionId: row['session_id'] as string,
      jti: row['jti'] as string,
      policyId: row['policy_id'] as string,
      issuedAt:
        row['issued_at'] instanceof Date
          ? (row['issued_at'] as Date).toISOString()
          : String(row['issued_at']),
      expiresAt: Number(row['expires_at']),
      kid: row['kid'] as string,
      result: (row['result'] as string | null) as MintAuditRecord['result'],
      reason: (row['reason'] as string | null) ?? undefined,
    }));
  }
}
