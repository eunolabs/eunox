/**
 * PostgresRolePolicyStore — durable Postgres-backed role-capability policy
 * store (Stage 4 Task 3).
 *
 * Persists the active {@link RoleCapabilityPolicy} to a `role_policies` table
 * so that admin mutations survive restarts and rolling deploys.  The table
 * is an append-only log: each `save()` call inserts a new row rather than
 * updating in place, providing a full mutation history for audit purposes.
 * `loadLatest()` returns the most recently inserted row.
 *
 * ## Schema
 *
 * ```sql
 * CREATE TABLE IF NOT EXISTS role_policies (
 *   id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 *   policy_json JSONB        NOT NULL,
 *   operator_id TEXT         NOT NULL,
 *   created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
 * );
 * CREATE INDEX IF NOT EXISTS role_policies_created_idx
 *   ON role_policies (created_at DESC);
 * ```
 *
 * ## Structural typing
 *
 * The class depends only on the {@link RolePolicyPgPool} structural interface
 * (a subset of `pg.Pool`) so that callers can inject any pool implementation
 * without declaring `pg` as a hard peer dependency of this package.
 */

import { RoleCapabilityPolicy, validateRoleCapabilityPolicy } from '@euno/common';

// ── Minimal PgPool interface (structural typing; no hard pg dep) ───────────

/**
 * Minimal subset of the `pg.Pool` / `pg.Client` surface used by this class.
 * Using a structural interface keeps `@euno/capability-issuer` from declaring
 * `pg` as a hard dependency — callers construct the pool and pass it in.
 */
export interface RolePolicyPgPool {
  query(text: string, values?: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
}

// ── Schema DDL ─────────────────────────────────────────────────────────────

/**
 * DDL executed by {@link PostgresRolePolicyStore.ensureSchema}.
 * Safe to run at every process start (`IF NOT EXISTS`).
 */
export const ROLE_POLICY_DDL = `
CREATE TABLE IF NOT EXISTS role_policies (
  id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  policy_json JSONB        NOT NULL,
  operator_id TEXT         NOT NULL,
  created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS role_policies_created_idx
  ON role_policies (created_at DESC);
`.trim();

// ── Record type ────────────────────────────────────────────────────────────

/** A row returned by {@link PostgresRolePolicyStore.loadLatest}. */
export interface RolePolicyRecord {
  /** Numeric primary key (database-assigned). */
  id: number;
  /** The validated, parsed role-capability policy. */
  policy: RoleCapabilityPolicy;
  /** Identity of the operator who committed this version. */
  operatorId: string;
  /** ISO 8601 timestamp when this row was inserted. */
  createdAt: string;
}

// ── Store ──────────────────────────────────────────────────────────────────

/**
 * Postgres-backed role-capability policy store.
 *
 * Persists role → capability policy snapshots to an append-only
 * `role_policies` table.  The most recent row is the active policy.
 */
export class PostgresRolePolicyStore {
  private readonly pool: RolePolicyPgPool;

  constructor(pool: RolePolicyPgPool) {
    this.pool = pool;
  }

  /**
   * Create the `role_policies` table and index if they do not yet exist.
   * Idempotent — safe to call at every startup.
   */
  async ensureSchema(): Promise<void> {
    // Execute each statement individually; `pg` does not support multi-
    // statement strings in a single `query()` call without using a
    // transaction helper.
    const statements = ROLE_POLICY_DDL.split(';')
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    for (const stmt of statements) {
      await this.pool.query(stmt + ';');
    }
  }

  /**
   * Load the most recently saved policy from the database.
   * Returns `null` when the table is empty (no policy has been persisted
   * yet — the caller should fall back to the file-based or in-code default).
   */
  async loadLatest(): Promise<RolePolicyRecord | null> {
    const result = await this.pool.query(
      `SELECT id, policy_json, operator_id, created_at
         FROM role_policies
        ORDER BY id DESC
        LIMIT 1`,
    );
    if (result.rows.length === 0) {
      return null;
    }
    const row = result.rows[0]!;
    const parsed = validateRoleCapabilityPolicy(row['policy_json']);
    return {
      id: Number(row['id']),
      policy: parsed,
      operatorId: String(row['operator_id']),
      createdAt:
        row['created_at'] instanceof Date
          ? (row['created_at'] as Date).toISOString()
          : String(row['created_at']),
    };
  }

  /**
   * Persist a new policy version.  The policy is validated before being
   * written; an error thrown by {@link validateRoleCapabilityPolicy} will
   * propagate to the caller without touching the database.
   *
   * @param policy    The new role → capability policy to persist.
   * @param operatorId  Identity of the operator making the change (from
   *                    the admin JWT `sub` claim or `'shared-key'` when
   *                    the deprecated X-Admin-Key path is used).
   * @returns The row ID assigned by Postgres.
   */
  async save(policy: RoleCapabilityPolicy, operatorId: string): Promise<number> {
    // Re-validate so the data stored is always well-formed, even if the
    // caller skips prior validation.
    validateRoleCapabilityPolicy(policy);

    const result = await this.pool.query(
      `INSERT INTO role_policies (policy_json, operator_id)
       VALUES ($1, $2)
       RETURNING id`,
      [JSON.stringify(policy), operatorId],
    );
    return Number(result.rows[0]!['id']);
  }
}
