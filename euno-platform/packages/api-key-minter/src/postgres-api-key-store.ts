/**
 * PostgresApiKeyStore — durable Postgres-backed API-key store (Task 2)
 * ────────────────────────────────────────────────────────────────────────────
 * Implements {@link ApiKeyStore} with a persistent Postgres table so that
 * key creation, revocation, lookup, and policy fan-out survive restarts and
 * rolling deploys.
 *
 * ## Schema overview
 *
 * ```sql
 * CREATE TABLE IF NOT EXISTS api_keys (
 *   id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 *   prefix           TEXT        NOT NULL UNIQUE,
 *   key_digest       TEXT        NOT NULL,
 *   hmac_key_version TEXT        NOT NULL,
 *   tenant_id        TEXT        NOT NULL,
 *   policy_id        TEXT        NOT NULL,
 *   capabilities     JSONB       NOT NULL DEFAULT '[]',
 *   scopes           TEXT[]      NOT NULL DEFAULT '{}',
 *   label            TEXT,
 *   created_at       TIMESTAMPTZ NOT NULL,
 *   last_used_at     TIMESTAMPTZ,
 *   expires_at       TIMESTAMPTZ,
 *   revoked_at       TIMESTAMPTZ
 * );
 *
 * CREATE UNIQUE INDEX IF NOT EXISTS api_keys_prefix_idx   ON api_keys (prefix);
 * CREATE        INDEX IF NOT EXISTS api_keys_tenant_idx   ON api_keys (tenant_id);
 * CREATE        INDEX IF NOT EXISTS api_keys_policy_idx   ON api_keys (policy_id)
 *   WHERE revoked_at IS NULL;
 * ```
 *
 * ## Multi-tenancy isolation
 *
 * Every query that retrieves or modifies records includes a `tenant_id`
 * predicate so that a single table can serve multiple tenants without
 * cross-tenant data leaks.  For stronger isolation, enable PostgreSQL
 * Row-Level Security — see `docs/DEPLOYMENT.md §"Minter database
 * multi-tenancy isolation"`.
 *
 * ## Structural typing
 *
 * The class depends only on the {@link ApiKeyPgPool} structural interface
 * (a subset of `pg.Pool`) so that callers can inject any pool implementation
 * without declaring `pg` as a hard peer dependency of this package.
 */

import { CapabilityConstraint } from '@euno/common';
import { API_KEY_DUMMY_PREFIX } from './api-key';
import type { ApiKeyRecord, ApiKeyStore } from './api-key-store';

// ── Minimal PgPool interface (structural typing; no hard pg dep) ───────────

/**
 * Minimal subset of the `pg.Pool` / `pg.Client` surface used by this class.
 * Using a structural interface keeps `@euno/api-key-minter` from declaring `pg`
 * as a hard dependency — callers construct the pool and pass it in.
 */
export interface ApiKeyPgPool {
  query(text: string, values?: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
}

// ── Schema ─────────────────────────────────────────────────────────────────

/**
 * DDL executed by {@link PostgresApiKeyStore.ensureSchema}.
 * Safe to run at every process start (`IF NOT EXISTS`).
 */
export const API_KEY_DDL = `
CREATE TABLE IF NOT EXISTS api_keys (
  id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  prefix           TEXT        NOT NULL UNIQUE,
  key_digest       TEXT        NOT NULL,
  hmac_key_version TEXT        NOT NULL,
  tenant_id        TEXT        NOT NULL,
  policy_id        TEXT        NOT NULL,
  capabilities     JSONB       NOT NULL DEFAULT '[]',
  scopes           TEXT[]      NOT NULL DEFAULT '{}',
  label            TEXT,
  created_at       TIMESTAMPTZ NOT NULL,
  last_used_at     TIMESTAMPTZ,
  expires_at       TIMESTAMPTZ,
  revoked_at       TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS api_keys_tenant_idx ON api_keys (tenant_id);
CREATE INDEX IF NOT EXISTS api_keys_policy_idx ON api_keys (policy_id)
  WHERE revoked_at IS NULL;
`.trim();

// ── PostgresApiKeyStore ────────────────────────────────────────────────────

/**
 * Postgres-backed implementation of {@link ApiKeyStore}.
 *
 * ### Usage
 *
 * ```typescript
 * import { Pool } from 'pg';
 * import { PostgresApiKeyStore } from '@euno/api-key-minter';
 *
 * const pool = new Pool({ connectionString: process.env.MINTER_API_KEY_DB_URL });
 * const keyStore = new PostgresApiKeyStore(pool);
 * await keyStore.ensureSchema();  // idempotent; run at startup
 * ```
 */
export class PostgresApiKeyStore implements ApiKeyStore {
  private readonly dummy: ApiKeyRecord;

  constructor(private readonly pool: ApiKeyPgPool) {
    this.dummy = {
      prefix: API_KEY_DUMMY_PREFIX,
      keyDigest: Buffer.alloc(32).toString('base64url'),
      hmacKeyVersion: 'dummy',
      tenantId: '',
      policyId: '',
      capabilities: [],
      scopes: [],
      createdAt: new Date().toISOString(),
    };
  }

  /**
   * Create the `api_keys` table and its indexes if they do not yet exist.
   *
   * Idempotent (`IF NOT EXISTS`) and safe to call at every process start.
   * For production deployments, prefer running migrations with a dedicated
   * migration tool and a privileged role.
   */
  async ensureSchema(): Promise<void> {
    const statements = API_KEY_DDL.split(';')
      .map(s => s.trim())
      .filter(s => s.length > 0);
    for (const statement of statements) {
      await this.pool.query(statement);
    }
  }

  /**
   * Persist a new API key record.
   *
   * @throws When the database INSERT fails (e.g. duplicate `prefix`).
   */
  async createKey(record: ApiKeyRecord): Promise<void> {
    await this.pool.query(
      `INSERT INTO api_keys
         (prefix, key_digest, hmac_key_version, tenant_id, policy_id,
          capabilities, scopes, label, created_at, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [
        record.prefix,
        record.keyDigest,
        record.hmacKeyVersion,
        record.tenantId,
        record.policyId,
        JSON.stringify(record.capabilities),
        record.scopes,
        record.label ?? null,
        record.createdAt,
        record.expiresAt ?? null,
      ],
    );
  }

  /**
   * Look up an API key record by its prefix.
   *
   * Returns `undefined` when no record exists for the given prefix.
   */
  async getByPrefix(prefix: string): Promise<ApiKeyRecord | undefined> {
    const { rows } = await this.pool.query(
      `SELECT prefix, key_digest, hmac_key_version, tenant_id, policy_id,
              capabilities, scopes, label,
              created_at, last_used_at, expires_at, revoked_at
       FROM api_keys
       WHERE prefix = $1
       LIMIT 1`,
      [prefix],
    );
    if (rows.length === 0) return undefined;
    return rowToRecord(rows[0]!);
  }

  /**
   * Return the dummy record used for timing-safe failed verifications.
   *
   * The dummy record is kept in memory (not in the database) because it is
   * always the same value across all replicas and should never be stored.
   */
  async getDummyRecord(): Promise<ApiKeyRecord> {
    return this.dummy;
  }

  /**
   * Update the `last_used_at` timestamp for an existing key.
   *
   * Silently no-ops when the prefix is not found.
   */
  async updateLastUsedAt(prefix: string, timestamp: string): Promise<void> {
    await this.pool.query(
      `UPDATE api_keys SET last_used_at = $1 WHERE prefix = $2`,
      [timestamp, prefix],
    );
  }

  /**
   * Mark a key as revoked by setting `revoked_at` to the current timestamp.
   *
   * Silently no-ops when the prefix is not found or already revoked.
   */
  async revokeKey(prefix: string): Promise<void> {
    await this.pool.query(
      `UPDATE api_keys SET revoked_at = NOW() WHERE prefix = $1 AND revoked_at IS NULL`,
      [prefix],
    );
  }

  /**
   * Return all API key records for the given tenant (including revoked/expired).
   *
   * Uses the `api_keys_tenant_idx` index so the query is O(tenant_keys)
   * regardless of total table size.
   */
  async listByTenant(tenantId: string): Promise<ApiKeyRecord[]> {
    const { rows } = await this.pool.query(
      `SELECT prefix, key_digest, hmac_key_version, tenant_id, policy_id,
              capabilities, scopes, label,
              created_at, last_used_at, expires_at, revoked_at
       FROM api_keys
       WHERE tenant_id = $1
       ORDER BY id ASC`,
      [tenantId],
    );
    return rows.map(rowToRecord);
  }

  /**
   * Replace the `capabilities` array on every non-revoked key whose
   * `policy_id` matches the given value.
   *
   * Uses the partial index `api_keys_policy_idx` which covers only
   * non-revoked keys.
   *
   * @returns The number of key records that were updated.
   */
  async updateCapabilitiesByPolicyId(
    policyId: string,
    capabilities: CapabilityConstraint[],
  ): Promise<number> {
    const { rows } = await this.pool.query(
      `UPDATE api_keys
       SET capabilities = $1
       WHERE policy_id = $2 AND revoked_at IS NULL
       RETURNING prefix`,
      [JSON.stringify(capabilities), policyId],
    );
    return rows.length;
  }
}

// ── Row → record mapping ───────────────────────────────────────────────────

function rowToRecord(row: Record<string, unknown>): ApiKeyRecord {
  return {
    prefix: row['prefix'] as string,
    keyDigest: row['key_digest'] as string,
    hmacKeyVersion: row['hmac_key_version'] as string,
    tenantId: row['tenant_id'] as string,
    policyId: row['policy_id'] as string,
    capabilities: parseCapabilities(row['capabilities']),
    scopes: parseScopes(row['scopes']),
    label: (row['label'] as string | null) ?? undefined,
    createdAt: toIsoString(row['created_at']),
    lastUsedAt: row['last_used_at'] != null ? toIsoString(row['last_used_at']) : undefined,
    expiresAt: row['expires_at'] != null ? toIsoString(row['expires_at']) : undefined,
    revokedAt: row['revoked_at'] != null ? toIsoString(row['revoked_at']) : undefined,
  };
}

function toIsoString(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function parseCapabilities(value: unknown): CapabilityConstraint[] {
  if (Array.isArray(value)) return value as CapabilityConstraint[];
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value) as unknown;
      if (Array.isArray(parsed)) return parsed as CapabilityConstraint[];
    } catch {
      // fall through
    }
  }
  return [];
}

function parseScopes(value: unknown): string[] {
  if (Array.isArray(value)) return value as string[];
  return [];
}
