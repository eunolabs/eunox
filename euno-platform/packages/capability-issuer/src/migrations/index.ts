/**
 * IssuerMigrationRunner — Postgres schema migrations for the capability issuer.
 *
 * Creates the `templates`, `template_versions`, and `template_assignments`
 * tables used by the manifest-template store (Task 6 of Stage 4).
 *
 * Design mirrors `PostgresLedgerBackend.migrate()` in
 * `common-infra/src/ledger-signer.ts`: idempotent (`CREATE … IF NOT EXISTS`),
 * safe to run at every process start, and schema-isolated under a configurable
 * Postgres schema name (`euno_issuer` by default).
 *
 * Lifecycle:
 *   1. Call `migrate()` once at startup when `ISSUER_DB_SCHEMA_INIT=true`.
 *   2. For production deployments prefer a dedicated migration tool with a
 *      privileged role; this runner is provided as a convenience and a
 *      development / smoke-test shortcut.
 */

// ── Minimal PgPool structural interface ───────────────────────────────────

/**
 * Minimal subset of `pg.Pool` / `pg.Client` used here.
 * Using a structural interface keeps this module from declaring `pg`
 * as a hard dependency.
 */
export interface IssuerPgPool {
  query(text: string, values?: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
  /**
   * Checkout a dedicated client for transaction management.
   * Matches the `pg.Pool.connect()` contract.
   */
  connect(): Promise<IssuerPgClient>;
}

/** Minimal pg.Client shape required for transaction management. */
export interface IssuerPgClient {
  query(text: string, values?: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
  release(): void;
}

// ── DDL ────────────────────────────────────────────────────────────────────

/**
 * Generate the DDL for all issuer tables, scoped to the given schema name.
 *
 * @param schema Postgres schema name (default `euno_issuer`).
 *
 * @internal Exposed as a function (rather than a top-level constant) so that
 * tests can customise the schema name and run against an in-process stub
 * without conflicting with a real `euno_issuer` schema.
 */
export function buildIssuerDdl(schema: string): string {
  return `
CREATE SCHEMA IF NOT EXISTS ${schema};

-- One row per template identity (not per version).
CREATE TABLE IF NOT EXISTS ${schema}.templates (
  template_id      TEXT        NOT NULL,
  owner_tenant_id  TEXT        NOT NULL,
  name             TEXT        NOT NULL,
  created_by       TEXT        NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at       TIMESTAMPTZ,
  PRIMARY KEY (template_id)
);

CREATE INDEX IF NOT EXISTS idx_templates_owner
  ON ${schema}.templates (owner_tenant_id)
  WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_templates_name_unique
  ON ${schema}.templates (owner_tenant_id, name)
  WHERE deleted_at IS NULL;

-- Immutable per (template_id, version). Editing creates a new version.
CREATE TABLE IF NOT EXISTS ${schema}.template_versions (
  template_id  TEXT        NOT NULL REFERENCES ${schema}.templates (template_id),
  version      INTEGER     NOT NULL,
  manifest     JSONB       NOT NULL,
  policy_hash  TEXT        NOT NULL,
  created_by   TEXT        NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (template_id, version)
);

CREATE INDEX IF NOT EXISTS idx_template_versions_template_id
  ON ${schema}.template_versions (template_id, version DESC);

-- Binds a template version to a (tenantId, agentId, role) triple.
CREATE TABLE IF NOT EXISTS ${schema}.template_assignments (
  assignment_id    TEXT        NOT NULL,
  template_id      TEXT        NOT NULL REFERENCES ${schema}.templates (template_id),
  template_version INTEGER     NOT NULL,
  tenant_id        TEXT        NOT NULL,
  agent_id         TEXT        NOT NULL,
  role             TEXT        NOT NULL,
  assigned_by      TEXT        NOT NULL,
  assigned_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at       TIMESTAMPTZ,
  FOREIGN KEY (template_id, template_version)
    REFERENCES ${schema}.template_versions (template_id, version),
  PRIMARY KEY (assignment_id)
);

CREATE INDEX IF NOT EXISTS idx_template_assignments_lookup
  ON ${schema}.template_assignments (tenant_id, agent_id, role)
  WHERE revoked_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_template_assignments_active_unique
  ON ${schema}.template_assignments (tenant_id, agent_id, role)
  WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_template_assignments_template
  ON ${schema}.template_assignments (template_id, assigned_at DESC);
`.trim();
}

// ── IssuerMigrationRunner ──────────────────────────────────────────────────

export class IssuerMigrationRunner {
  private readonly pool: IssuerPgPool;
  private readonly schema: string;

  constructor(pool: IssuerPgPool, schema = 'euno_issuer') {
    this.pool = pool;
    this.schema = schema;
  }

  /**
   * Create all issuer tables and indexes if they do not yet exist.
   *
   * Idempotent — safe to call at every process start.
   */
  async migrate(): Promise<void> {
    const ddl = buildIssuerDdl(this.schema);
    // Split on semicolons and execute each statement individually.
    // This matches the pattern used in `PostgresApiKeyStore.ensureSchema()`.
    const statements = ddl
      .split(';')
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    for (const statement of statements) {
      await this.pool.query(statement);
    }
  }
}
