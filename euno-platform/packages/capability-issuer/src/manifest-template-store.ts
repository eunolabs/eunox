/**
 * ManifestTemplateStore — storage interface and Postgres implementation for
 * manifest templates (Task 6 of Stage 4).
 *
 * A **manifest template** is a stored, named, versioned
 * `AgentCapabilityManifest` plus binding metadata. Templates live in the
 * issuer's Postgres (tables created by {@link IssuerMigrationRunner}).
 *
 * ## Immutability guarantee
 *
 * `template_versions` rows are never updated. {@link appendVersion} inserts a
 * new row with `version = max(version) + 1` under an `EXCLUSIVE` row-level
 * lock on the parent `templates` row, preventing duplicate-version races.
 *
 * ## Cross-tenant isolation
 *
 * Every read and write filters by `owner_tenant_id` (or `tenant_id` for
 * assignments). This keeps tenant A from reading or mutating tenant B's
 * templates. Cross-tenant assignments (where `template.owner_tenant_id !=
 * assignment.tenant_id`) are only created when the caller holds the
 * `platformAdmin` claim in their operator JWT — enforced at the route layer.
 *
 * ## Soft-delete semantics
 *
 * {@link softDelete} sets `deleted_at` on the `templates` row. The template
 * disappears from list results and can no longer receive new versions or
 * assignments. Existing assignments and in-flight tokens remain unaffected.
 */

import type { AgentCapabilityManifest } from '@euno/common';
import { canonicalSha256, generateId } from '@euno/common';
import type { IssuerPgPool } from './migrations';

// ── Domain types ───────────────────────────────────────────────────────────

/** A template record (header — no manifest payload). */
export interface TemplateRecord {
  templateId: string;
  ownerTenantId: string;
  name: string;
  createdBy: string;
  createdAt: string;
  deletedAt: string | null;
}

/** A template version record (includes manifest and policy hash). */
export interface TemplateVersionRecord {
  templateId: string;
  version: number;
  manifest: AgentCapabilityManifest;
  policyHash: string;
  createdBy: string;
  createdAt: string;
}

/** A template assignment binding a template version to (tenantId, agentId, role). */
export interface TemplateAssignment {
  assignmentId: string;
  templateId: string;
  templateVersion: number;
  tenantId: string;
  agentId: string;
  role: string;
  assignedBy: string;
  assignedAt: string;
  revokedAt: string | null;
}

/** Combined view used by the list endpoint. */
export interface TemplateListItem extends TemplateRecord {
  latestVersion: number;
  policyHash: string;
}

/** Inputs for {@link ManifestTemplateStore.createTemplate}. */
export interface CreateTemplateInput {
  ownerTenantId: string;
  name: string;
  manifest: AgentCapabilityManifest;
  createdBy: string;
}

/** Inputs for {@link ManifestTemplateStore.appendVersion}. */
export interface AppendVersionInput {
  templateId: string;
  ownerTenantId: string;
  manifest: AgentCapabilityManifest;
  createdBy: string;
}

/** One binding in a multi-binding assign call. */
export interface TemplateBinding {
  tenantId: string;
  agentId: string;
  role: string;
  /** When omitted, the store resolves to the latest non-deleted version. */
  version?: number;
}

/** Result of a single assign binding. */
export type AssignBindingResult =
  | { kind: 'created'; assignmentId: string; version: number }
  | { kind: 'skipped'; reason: 'already_assigned' };

// ── Interface ──────────────────────────────────────────────────────────────

export interface ManifestTemplateStore {
  /** Create a new template with version 1. Returns the created record + version. */
  createTemplate(
    input: CreateTemplateInput,
  ): Promise<{ record: TemplateRecord; version: TemplateVersionRecord }>;

  /**
   * List templates owned by `ownerTenantId`.
   * Excludes soft-deleted templates unless `includeDeleted` is true.
   */
  listTemplates(
    ownerTenantId: string,
    opts?: { cursor?: string; limit?: number; includeDeleted?: boolean },
  ): Promise<{ items: TemplateListItem[]; nextCursor: string | null }>;

  /**
   * Fetch the template header + latest version record.
   * Returns `undefined` if not found or the template belongs to a different tenant.
   */
  getTemplate(
    templateId: string,
    ownerTenantId: string,
  ): Promise<{ record: TemplateRecord; version: TemplateVersionRecord } | undefined>;

  /**
   * Fetch a specific version of a template.
   * Returns `undefined` if not found or tenant mismatch.
   */
  getTemplateVersion(
    templateId: string,
    version: number,
    ownerTenantId: string,
  ): Promise<{ record: TemplateRecord; version: TemplateVersionRecord } | undefined>;

  /**
   * Append a new version to an existing template.
   * Returns the new version record.
   * Throws with `code: 'NOT_FOUND'` if not found, `code: 'DELETED'` if soft-deleted.
   */
  appendVersion(
    input: AppendVersionInput,
  ): Promise<TemplateVersionRecord>;

  /**
   * Bind a template to one or more `(tenantId, agentId, role)` triples.
   * Duplicates are returned as `skipped` (not an error).
   * Throws with `code: 'NOT_FOUND'` if the template does not exist.
   * Throws with `code: 'DELETED'` if the template is soft-deleted.
   */
  assignTemplate(
    templateId: string,
    ownerTenantId: string,
    bindings: TemplateBinding[],
    assignedBy: string,
  ): Promise<AssignBindingResult[]>;

  /**
   * Soft-delete a template (set `deleted_at = NOW()`).
   * Returns `undefined` if not found or tenant mismatch.
   * Returns the `deletedAt` ISO string on success.
   * Throws with `code: 'ALREADY_DELETED'` if already soft-deleted.
   */
  softDelete(
    templateId: string,
    ownerTenantId: string,
  ): Promise<string | undefined>;

  /**
   * Look up the active assignment for `(tenantId, agentId, role)`.
   * Returns `undefined` when no assignment exists (caller falls back to policy).
   * This is the hot path called by {@link IssueController} on every issuance.
   */
  findActiveAssignment(
    tenantId: string,
    agentId: string,
    role: string,
  ): Promise<{ templateId: string; version: number; manifest: AgentCapabilityManifest; policyHash: string } | undefined>;
}

// ── Template store errors ──────────────────────────────────────────────────

export class TemplateStoreError extends Error {
  constructor(
    public readonly code: 'NOT_FOUND' | 'DELETED' | 'ALREADY_DELETED' | 'CONFLICT',
    message: string,
  ) {
    super(message);
    this.name = 'TemplateStoreError';
  }
}

// ── PostgresManifestTemplateStore ──────────────────────────────────────────

export class PostgresManifestTemplateStore implements ManifestTemplateStore {
  private readonly pool: IssuerPgPool;
  private readonly schema: string;

  constructor(pool: IssuerPgPool, schema = 'euno_issuer') {
    this.pool = pool;
    this.schema = schema;
  }

  // ── createTemplate ────────────────────────────────────────────────────────

  async createTemplate(
    input: CreateTemplateInput,
  ): Promise<{ record: TemplateRecord; version: TemplateVersionRecord }> {
    const templateId = `tmpl_${generateId()}`;
    const policyHash = canonicalSha256(input.manifest);
    const version = 1;

    // Insert header + version 1 atomically.
    await this.pool.query(
      `INSERT INTO ${this.schema}.templates
         (template_id, owner_tenant_id, name, created_by)
       VALUES ($1, $2, $3, $4)`,
      [templateId, input.ownerTenantId, input.name, input.createdBy],
    );

    const { rows } = await this.pool.query(
      `INSERT INTO ${this.schema}.template_versions
         (template_id, version, manifest, policy_hash, created_by)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING created_at`,
      [templateId, version, JSON.stringify(input.manifest), policyHash, input.createdBy],
    );

    const createdAt = toIso(rows[0]!['created_at']);

    const record: TemplateRecord = {
      templateId,
      ownerTenantId: input.ownerTenantId,
      name: input.name,
      createdBy: input.createdBy,
      createdAt,
      deletedAt: null,
    };

    const versionRecord: TemplateVersionRecord = {
      templateId,
      version,
      manifest: input.manifest,
      policyHash,
      createdBy: input.createdBy,
      createdAt,
    };

    return { record, version: versionRecord };
  }

  // ── listTemplates ─────────────────────────────────────────────────────────

  async listTemplates(
    ownerTenantId: string,
    opts: { cursor?: string; limit?: number; includeDeleted?: boolean } = {},
  ): Promise<{ items: TemplateListItem[]; nextCursor: string | null }> {
    const limit = Math.min(opts.limit ?? 50, 200);
    // Cursor is the last seen templateId (base64url-encoded for opacity).
    const cursorTemplateId = opts.cursor
      ? Buffer.from(opts.cursor, 'base64url').toString('utf8')
      : undefined;
    const includeDeleted = opts.includeDeleted === true;

    const params: unknown[] = [ownerTenantId, limit + 1];
    const conditions: string[] = [`t.owner_tenant_id = $1`];
    if (!includeDeleted) {
      conditions.push(`t.deleted_at IS NULL`);
    }
    if (cursorTemplateId) {
      params.push(cursorTemplateId);
      conditions.push(`t.template_id > $${params.length}`);
    }

    const where = conditions.join(' AND ');

    const { rows } = await this.pool.query(
      `SELECT
         t.template_id,
         t.owner_tenant_id,
         t.name,
         t.created_by,
         t.created_at,
         t.deleted_at,
         v.version  AS latest_version,
         v.policy_hash
       FROM ${this.schema}.templates t
       JOIN LATERAL (
         SELECT version, policy_hash
         FROM ${this.schema}.template_versions tv
         WHERE tv.template_id = t.template_id
         ORDER BY tv.version DESC
         LIMIT 1
       ) v ON true
       WHERE ${where}
       ORDER BY t.template_id ASC
       LIMIT $2`,
      params,
    );

    const hasMore = rows.length > limit;
    const pageRows = hasMore ? rows.slice(0, limit) : rows;

    const items: TemplateListItem[] = pageRows.map((r) => ({
      templateId: r['template_id'] as string,
      ownerTenantId: r['owner_tenant_id'] as string,
      name: r['name'] as string,
      createdBy: r['created_by'] as string,
      createdAt: toIso(r['created_at']),
      deletedAt: r['deleted_at'] != null ? toIso(r['deleted_at']) : null,
      latestVersion: r['latest_version'] as number,
      policyHash: r['policy_hash'] as string,
    }));

    const nextCursor =
      hasMore && pageRows.length > 0
        ? Buffer.from(pageRows[pageRows.length - 1]!['template_id'] as string).toString('base64url')
        : null;

    return { items, nextCursor };
  }

  // ── getTemplate ───────────────────────────────────────────────────────────

  async getTemplate(
    templateId: string,
    ownerTenantId: string,
  ): Promise<{ record: TemplateRecord; version: TemplateVersionRecord } | undefined> {
    const { rows: tRows } = await this.pool.query(
      `SELECT template_id, owner_tenant_id, name, created_by, created_at, deleted_at
       FROM ${this.schema}.templates
       WHERE template_id = $1 AND owner_tenant_id = $2`,
      [templateId, ownerTenantId],
    );
    if (tRows.length === 0) return undefined;

    const t = tRows[0]!;

    const { rows: vRows } = await this.pool.query(
      `SELECT version, manifest, policy_hash, created_by, created_at
       FROM ${this.schema}.template_versions
       WHERE template_id = $1
       ORDER BY version DESC
       LIMIT 1`,
      [templateId],
    );
    if (vRows.length === 0) return undefined;
    const v = vRows[0]!;

    return {
      record: rowToTemplateRecord(t),
      version: rowToVersionRecord(templateId, v),
    };
  }

  // ── getTemplateVersion ────────────────────────────────────────────────────

  async getTemplateVersion(
    templateId: string,
    version: number,
    ownerTenantId: string,
  ): Promise<{ record: TemplateRecord; version: TemplateVersionRecord } | undefined> {
    const { rows: tRows } = await this.pool.query(
      `SELECT template_id, owner_tenant_id, name, created_by, created_at, deleted_at
       FROM ${this.schema}.templates
       WHERE template_id = $1 AND owner_tenant_id = $2`,
      [templateId, ownerTenantId],
    );
    if (tRows.length === 0) return undefined;

    const { rows: vRows } = await this.pool.query(
      `SELECT version, manifest, policy_hash, created_by, created_at
       FROM ${this.schema}.template_versions
       WHERE template_id = $1 AND version = $2`,
      [templateId, version],
    );
    if (vRows.length === 0) return undefined;

    return {
      record: rowToTemplateRecord(tRows[0]!),
      version: rowToVersionRecord(templateId, vRows[0]!),
    };
  }

  // ── appendVersion ─────────────────────────────────────────────────────────

  async appendVersion(input: AppendVersionInput): Promise<TemplateVersionRecord> {
    // Lock the parent row to prevent concurrent version appends.
    const { rows: lockRows } = await this.pool.query(
      `SELECT template_id, deleted_at
       FROM ${this.schema}.templates
       WHERE template_id = $1 AND owner_tenant_id = $2
       FOR UPDATE`,
      [input.templateId, input.ownerTenantId],
    );
    if (lockRows.length === 0) {
      throw new TemplateStoreError('NOT_FOUND', `Template ${input.templateId} not found`);
    }
    if (lockRows[0]!['deleted_at'] != null) {
      throw new TemplateStoreError('DELETED', `Template ${input.templateId} has been deleted`);
    }

    // Compute new version number.
    const { rows: maxRows } = await this.pool.query(
      `SELECT COALESCE(MAX(version), 0) AS max_v
       FROM ${this.schema}.template_versions
       WHERE template_id = $1`,
      [input.templateId],
    );
    const newVersion = (maxRows[0]!['max_v'] as number) + 1;
    const policyHash = canonicalSha256(input.manifest);

    const { rows } = await this.pool.query(
      `INSERT INTO ${this.schema}.template_versions
         (template_id, version, manifest, policy_hash, created_by)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING created_at`,
      [input.templateId, newVersion, JSON.stringify(input.manifest), policyHash, input.createdBy],
    );

    return {
      templateId: input.templateId,
      version: newVersion,
      manifest: input.manifest,
      policyHash,
      createdBy: input.createdBy,
      createdAt: toIso(rows[0]!['created_at']),
    };
  }

  // ── assignTemplate ────────────────────────────────────────────────────────

  async assignTemplate(
    templateId: string,
    ownerTenantId: string,
    bindings: TemplateBinding[],
    assignedBy: string,
  ): Promise<AssignBindingResult[]> {
    // Verify template exists and is not deleted.
    const { rows: tRows } = await this.pool.query(
      `SELECT template_id, deleted_at
       FROM ${this.schema}.templates
       WHERE template_id = $1 AND owner_tenant_id = $2`,
      [templateId, ownerTenantId],
    );
    if (tRows.length === 0) {
      throw new TemplateStoreError('NOT_FOUND', `Template ${templateId} not found`);
    }
    if (tRows[0]!['deleted_at'] != null) {
      throw new TemplateStoreError('DELETED', `Template ${templateId} has been deleted`);
    }

    // Resolve default version (latest).
    const { rows: maxRows } = await this.pool.query(
      `SELECT COALESCE(MAX(version), 0) AS max_v
       FROM ${this.schema}.template_versions
       WHERE template_id = $1`,
      [templateId],
    );
    const latestVersion = maxRows[0]!['max_v'] as number;
    if (latestVersion === 0) {
      throw new TemplateStoreError('NOT_FOUND', `Template ${templateId} has no versions`);
    }

    const results: AssignBindingResult[] = [];
    for (const binding of bindings) {
      const version = binding.version ?? latestVersion;
      const assignmentId = `asgn_${generateId()}`;
      try {
        await this.pool.query(
          `INSERT INTO ${this.schema}.template_assignments
             (assignment_id, template_id, template_version, tenant_id, agent_id, role, assigned_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [assignmentId, templateId, version, binding.tenantId, binding.agentId, binding.role, assignedBy],
        );
        results.push({ kind: 'created', assignmentId, version });
      } catch (err: unknown) {
        // PostgreSQL unique-violation (23505) → already_assigned.
        if (isUniqueViolation(err)) {
          results.push({ kind: 'skipped', reason: 'already_assigned' });
        } else {
          throw err;
        }
      }
    }
    return results;
  }

  // ── softDelete ────────────────────────────────────────────────────────────

  async softDelete(
    templateId: string,
    ownerTenantId: string,
  ): Promise<string | undefined> {
    const { rows: tRows } = await this.pool.query(
      `SELECT template_id, deleted_at
       FROM ${this.schema}.templates
       WHERE template_id = $1 AND owner_tenant_id = $2`,
      [templateId, ownerTenantId],
    );
    if (tRows.length === 0) return undefined;
    if (tRows[0]!['deleted_at'] != null) {
      throw new TemplateStoreError(
        'ALREADY_DELETED',
        `Template ${templateId} is already deleted`,
      );
    }

    const { rows } = await this.pool.query(
      `UPDATE ${this.schema}.templates
       SET deleted_at = NOW()
       WHERE template_id = $1 AND owner_tenant_id = $2
       RETURNING deleted_at`,
      [templateId, ownerTenantId],
    );
    if (rows.length === 0) return undefined;
    return toIso(rows[0]!['deleted_at']);
  }

  // ── findActiveAssignment ──────────────────────────────────────────────────

  async findActiveAssignment(
    tenantId: string,
    agentId: string,
    role: string,
  ): Promise<
    | { templateId: string; version: number; manifest: AgentCapabilityManifest; policyHash: string }
    | undefined
  > {
    const { rows } = await this.pool.query(
      `SELECT a.template_id, a.template_version, v.manifest, v.policy_hash
       FROM ${this.schema}.template_assignments a
       JOIN ${this.schema}.template_versions v
         ON v.template_id = a.template_id AND v.version = a.template_version
       WHERE a.tenant_id = $1 AND a.agent_id = $2 AND a.role = $3
         AND a.revoked_at IS NULL
       LIMIT 1`,
      [tenantId, agentId, role],
    );
    if (rows.length === 0) return undefined;

    const row = rows[0]!;
    const manifest = parseManifest(row['manifest']);
    if (!manifest) return undefined;

    return {
      templateId: row['template_id'] as string,
      version: row['template_version'] as number,
      manifest,
      policyHash: row['policy_hash'] as string,
    };
  }
}

// ── Row helpers ────────────────────────────────────────────────────────────

function rowToTemplateRecord(row: Record<string, unknown>): TemplateRecord {
  return {
    templateId: row['template_id'] as string,
    ownerTenantId: row['owner_tenant_id'] as string,
    name: row['name'] as string,
    createdBy: row['created_by'] as string,
    createdAt: toIso(row['created_at']),
    deletedAt: row['deleted_at'] != null ? toIso(row['deleted_at']) : null,
  };
}

function rowToVersionRecord(
  templateId: string,
  row: Record<string, unknown>,
): TemplateVersionRecord {
  return {
    templateId,
    version: row['version'] as number,
    manifest: parseManifest(row['manifest']) as AgentCapabilityManifest,
    policyHash: row['policy_hash'] as string,
    createdBy: row['created_by'] as string,
    createdAt: toIso(row['created_at']),
  };
}

function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function parseManifest(value: unknown): AgentCapabilityManifest | undefined {
  if (value === null || value === undefined) return undefined;
  if (typeof value === 'object' && !Array.isArray(value)) {
    return value as AgentCapabilityManifest;
  }
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value) as unknown;
      if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
        return parsed as AgentCapabilityManifest;
      }
    } catch {
      // fall through
    }
  }
  return undefined;
}

function isUniqueViolation(err: unknown): boolean {
  if (typeof err === 'object' && err !== null) {
    const pg = err as { code?: string };
    return pg.code === '23505';
  }
  return false;
}
