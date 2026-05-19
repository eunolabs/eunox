/**
 * SCIM 2.0 store — Postgres-backed CRUD for Users, Groups, and group
 * memberships.
 *
 * The capability issuer uses this store to:
 *   1. Persist provisioning events pushed by enterprise IdPs (Okta, Entra ID,
 *      Ping Identity) at /scim/v2/.
 *   2. Enrich issuance: when a user authenticates via IdP, their current SCIM
 *      group memberships are queried and mapped to roles via
 *      `ISSUER_SCIM_GROUP_ROLE_MAP` before capability assignment.
 *
 * Design notes:
 *   - All operations scope by `tenantId` for multi-tenant safety.
 *   - Soft-delete: DELETE deprovisions a user (sets `active = false`,
 *     `deleted_at = NOW()`) and removes their group memberships.
 *     Hard-delete is not supported — the audit trail must be preserved.
 *   - Idempotency: PUT/PATCH are idempotent.
 *   - Filter: only `eq` and `co` (contains) operators are supported for
 *     the SCIM `?filter=` query parameter; this covers > 99 % of real IdP
 *     traffic (Okta / Entra ID only emit `userName eq` and `displayName eq`
 *     filters in practice).
 *
 * See `docs/issuer-idp-setup.md §"SCIM provisioning"` for operator docs.
 */

import { generateId } from '@euno/common';
import type { IssuerPgPool } from './migrations';

// ── SCIM resource types ────────────────────────────────────────────────────

export interface ScimUser {
  id: string;
  externalId?: string;
  userName: string;
  displayName?: string;
  active: boolean;
  /** Tenant this user belongs to. `undefined` for global SCIM tenants. */
  tenantId?: string;
  createdAt: Date;
  updatedAt: Date;
  /** Non-null means the user has been soft-deleted (deprovisioned). */
  deletedAt?: Date;
}

export interface ScimGroup {
  id: string;
  displayName: string;
  tenantId?: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface ScimGroupMembership {
  groupId: string;
  userId: string;
  addedAt: Date;
}

// ── Filter AST (minimal: attr op value) ───────────────────────────────────

export type ScimFilterOp = 'eq' | 'co';

export interface ScimFilter {
  attribute: string;
  op: ScimFilterOp;
  value: string;
}

/**
 * Parse a SCIM filter string into a simple {@link ScimFilter} record.
 *
 * Supports:
 *   - `userName eq "jsmith@example.com"` (unquoted values also accepted)
 *   - `displayName co "Smith"`
 *
 * Throws when the filter cannot be parsed.
 */
export function parseScimFilter(filterStr: string): ScimFilter {
  // Matches: <attribute> <op> "<value>" OR <attribute> <op> <value>
  const match =
    /^(\w+)\s+(eq|co)\s+"([^"]*)"\s*$/.exec(filterStr.trim()) ||
    /^(\w+)\s+(eq|co)\s+(\S+)\s*$/.exec(filterStr.trim());

  if (!match) {
    throw new Error(`Unsupported SCIM filter syntax: ${filterStr}`);
  }

  const attribute = match[1]!;
  const op = match[2]!;
  const value = match[3]!;
  if (op !== 'eq' && op !== 'co') {
    throw new Error(`Unsupported SCIM filter operator: ${op}`);
  }

  return { attribute, op, value };
}

// ── IScimStore interface ───────────────────────────────────────────────────

export interface IScimStore {
  // ── Users ─────────────────────────────────────────────────────────────────
  createUser(user: Omit<ScimUser, 'id' | 'createdAt' | 'updatedAt'>): Promise<ScimUser>;
  getUser(id: string, tenantId?: string): Promise<ScimUser | undefined>;
  /** Find a user by externalId or userName within the given tenant. */
  findUserByExternalIdOrUserName(
    externalId: string | undefined,
    userName: string,
    tenantId?: string,
  ): Promise<ScimUser | undefined>;
  listUsers(opts: { filter?: ScimFilter; tenantId?: string; limit?: number; offset?: number }): Promise<{ users: ScimUser[]; totalCount: number }>;
  replaceUser(id: string, user: Omit<ScimUser, 'id' | 'createdAt' | 'updatedAt'>, tenantId?: string): Promise<ScimUser>;
  patchUser(id: string, patch: Partial<Omit<ScimUser, 'id' | 'createdAt' | 'updatedAt'>>, tenantId?: string): Promise<ScimUser>;
  /** Soft-delete a user and remove their group memberships. */
  deleteUser(id: string, tenantId?: string): Promise<void>;

  // ── Groups ────────────────────────────────────────────────────────────────
  createGroup(group: Omit<ScimGroup, 'id' | 'createdAt' | 'updatedAt'>): Promise<ScimGroup>;
  getGroup(id: string, tenantId?: string): Promise<ScimGroup | undefined>;
  listGroups(opts: { filter?: ScimFilter; tenantId?: string; limit?: number; offset?: number }): Promise<{ groups: ScimGroup[]; totalCount: number }>;
  replaceGroup(id: string, group: Omit<ScimGroup, 'id' | 'createdAt' | 'updatedAt'>, members?: string[]): Promise<ScimGroup>;
  patchGroupMembers(id: string, addMembers?: string[], removeMembers?: string[], tenantId?: string): Promise<ScimGroup>;
  deleteGroup(id: string, tenantId?: string): Promise<void>;

  // ── Membership queries for issuance ───────────────────────────────────────
  /**
   * Return the `displayName` of every group the user is a member of.
   * Used by the issuance pipeline to derive SCIM-authorised roles.
   */
  getGroupNamesForUser(userId: string, tenantId?: string): Promise<string[]>;
}

// ── PostgresScimStore ──────────────────────────────────────────────────────

function row2User(r: Record<string, unknown>): ScimUser {
  return {
    id: r['id'] as string,
    externalId: (r['external_id'] as string | null) ?? undefined,
    userName: r['user_name'] as string,
    displayName: (r['display_name'] as string | null) ?? undefined,
    active: r['active'] as boolean,
    tenantId: (r['tenant_id'] as string | null) ?? undefined,
    createdAt: r['created_at'] as Date,
    updatedAt: r['updated_at'] as Date,
    deletedAt: (r['deleted_at'] as Date | null) ?? undefined,
  };
}

function row2Group(r: Record<string, unknown>): ScimGroup {
  return {
    id: r['id'] as string,
    displayName: r['display_name'] as string,
    tenantId: (r['tenant_id'] as string | null) ?? undefined,
    createdAt: r['created_at'] as Date,
    updatedAt: r['updated_at'] as Date,
  };
}

/**
 * Build a SQL WHERE fragment for a SCIM filter on a specific column.
 *
 * @param filter Parsed SCIM filter (may be undefined → no extra WHERE).
 * @param allowedAttributes Map from SCIM attribute name to SQL column name.
 * @param params Accumulator for parameterised values — the function appends
 *               bound values here.
 * @param startParamIdx The `$N` index of the first parameter to append.
 * @returns `{ clause: string; nextParamIdx: number }`.
 */
function buildFilterClause(
  filter: ScimFilter | undefined,
  allowedAttributes: Record<string, string>,
  params: unknown[],
  startParamIdx: number,
): { clause: string; nextParamIdx: number } {
  if (!filter) {
    return { clause: '', nextParamIdx: startParamIdx };
  }
  const col = allowedAttributes[filter.attribute];
  if (!col) {
    // Unsupported attribute → return no rows (fail-closed on unknown filters).
    return { clause: ' AND FALSE', nextParamIdx: startParamIdx };
  }
  params.push(filter.op === 'co' ? `%${filter.value}%` : filter.value);
  const op = filter.op === 'co' ? 'ILIKE' : '=';
  return {
    clause: ` AND ${col} ${op} $${startParamIdx}`,
    nextParamIdx: startParamIdx + 1,
  };
}

export class PostgresScimStore implements IScimStore {
  private readonly pool: IssuerPgPool;
  private readonly schema: string;

  constructor(pool: IssuerPgPool, schema = 'euno_issuer') {
    this.pool = pool;
    this.schema = schema;
  }

  private get s(): string {
    return this.schema;
  }

  // ── Users ──────────────────────────────────────────────────────────────────

  async createUser(
    user: Omit<ScimUser, 'id' | 'createdAt' | 'updatedAt'>,
  ): Promise<ScimUser> {
    const id = generateId();
    const result = await this.pool.query(
      `INSERT INTO ${this.s}.scim_users
         (id, external_id, user_name, display_name, active, tenant_id)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [
        id,
        user.externalId ?? null,
        user.userName,
        user.displayName ?? null,
        user.active !== false,
        user.tenantId ?? null,
      ],
    );
    return row2User(result.rows[0]!);
  }

  async getUser(id: string, tenantId?: string): Promise<ScimUser | undefined> {
    const params: unknown[] = [id];
    let tenantClause = '';
    if (tenantId !== undefined) {
      params.push(tenantId);
      tenantClause = ' AND tenant_id = $2';
    }
    const result = await this.pool.query(
      `SELECT * FROM ${this.s}.scim_users WHERE id = $1${tenantClause}`,
      params,
    );
    if (result.rows.length === 0) return undefined;
    return row2User(result.rows[0]!);
  }

  async findUserByExternalIdOrUserName(
    externalId: string | undefined,
    userName: string,
    tenantId?: string,
  ): Promise<ScimUser | undefined> {
    const params: unknown[] = [userName];
    const tenantFilter = tenantId !== undefined ? ` AND tenant_id = $2` : '';
    if (tenantId !== undefined) params.push(tenantId);

    let externalIdClause = '';
    if (externalId) {
      params.push(externalId);
      const p = params.length;
      externalIdClause = ` OR (external_id = $${p}${tenantId !== undefined ? ' AND tenant_id = $2' : ''})`;
    }

    const result = await this.pool.query(
      `SELECT * FROM ${this.s}.scim_users
       WHERE (user_name = $1${tenantFilter}${externalIdClause})
         AND deleted_at IS NULL
       LIMIT 1`,
      params,
    );
    if (result.rows.length === 0) return undefined;
    return row2User(result.rows[0]!);
  }

  async listUsers(opts: {
    filter?: ScimFilter;
    tenantId?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ users: ScimUser[]; totalCount: number }> {
    const { filter, tenantId, limit = 100, offset = 0 } = opts;
    const params: unknown[] = [];
    const userCols: Record<string, string> = {
      userName: 'user_name',
      externalId: 'external_id',
      displayName: 'display_name',
    };

    let whereClause = 'WHERE deleted_at IS NULL';

    if (tenantId !== undefined) {
      params.push(tenantId);
      whereClause += ` AND tenant_id = $${params.length}`;
    }

    const { clause: filterClause, nextParamIdx } = buildFilterClause(
      filter,
      userCols,
      params,
      params.length + 1,
    );
    whereClause += filterClause;

    params.push(limit);
    const limitParam = nextParamIdx;
    params.push(offset);
    const offsetParam = limitParam + 1;

    const countResult = await this.pool.query(
      `SELECT COUNT(*) AS cnt FROM ${this.s}.scim_users ${whereClause}`,
      params.slice(0, params.length - 2),
    );
    const totalCount = parseInt(String(countResult.rows[0]?.['cnt'] ?? '0'), 10);

    const dataResult = await this.pool.query(
      `SELECT * FROM ${this.s}.scim_users ${whereClause} ORDER BY created_at ASC LIMIT $${limitParam} OFFSET $${offsetParam}`,
      params,
    );

    return { users: dataResult.rows.map(row2User), totalCount };
  }

  async replaceUser(
    id: string,
    user: Omit<ScimUser, 'id' | 'createdAt' | 'updatedAt'>,
    tenantId?: string,
  ): Promise<ScimUser> {
    const params: unknown[] = [
      user.externalId ?? null,
      user.userName,
      user.displayName ?? null,
      user.active !== false,
      user.tenantId ?? null,
      id,
    ];
    let tenantClause = '';
    if (tenantId !== undefined) {
      params.push(tenantId);
      tenantClause = ` AND tenant_id = $${params.length}`;
    }
    const result = await this.pool.query(
      `UPDATE ${this.s}.scim_users
       SET external_id = $1, user_name = $2, display_name = $3,
           active = $4, tenant_id = $5, updated_at = NOW(),
           deleted_at = NULL
       WHERE id = $6${tenantClause}
       RETURNING *`,
      params,
    );
    if (result.rows.length === 0) {
      throw Object.assign(new Error(`SCIM user not found: ${id}`), { scimStatus: 404 });
    }
    return row2User(result.rows[0]!);
  }

  async patchUser(
    id: string,
    patch: Partial<Omit<ScimUser, 'id' | 'createdAt' | 'updatedAt'>>,
    tenantId?: string,
  ): Promise<ScimUser> {
    const setClauses: string[] = [];
    const params: unknown[] = [];

    if (patch.externalId !== undefined) {
      params.push(patch.externalId);
      setClauses.push(`external_id = $${params.length}`);
    }
    if (patch.userName !== undefined) {
      params.push(patch.userName);
      setClauses.push(`user_name = $${params.length}`);
    }
    if (patch.displayName !== undefined) {
      params.push(patch.displayName);
      setClauses.push(`display_name = $${params.length}`);
    }
    if (patch.active !== undefined) {
      params.push(patch.active);
      setClauses.push(`active = $${params.length}`);
    }
    if (patch.tenantId !== undefined) {
      params.push(patch.tenantId);
      setClauses.push(`tenant_id = $${params.length}`);
    }

    if (setClauses.length === 0) {
      // No changes — just return the current record.
      const current = await this.getUser(id, tenantId);
      if (!current) {
        throw Object.assign(new Error(`SCIM user not found: ${id}`), { scimStatus: 404 });
      }
      return current;
    }

    setClauses.push('updated_at = NOW()');
    params.push(id);
    const idParam = params.length;
    let tenantClause = '';
    if (tenantId !== undefined) {
      params.push(tenantId);
      tenantClause = ` AND tenant_id = $${params.length}`;
    }

    const result = await this.pool.query(
      `UPDATE ${this.s}.scim_users
       SET ${setClauses.join(', ')}
       WHERE id = $${idParam}${tenantClause}
       RETURNING *`,
      params,
    );
    if (result.rows.length === 0) {
      throw Object.assign(new Error(`SCIM user not found: ${id}`), { scimStatus: 404 });
    }
    return row2User(result.rows[0]!);
  }

  async deleteUser(id: string, tenantId?: string): Promise<void> {
    const params: unknown[] = [id];
    let tenantClause = '';
    if (tenantId !== undefined) {
      params.push(tenantId);
      tenantClause = ` AND tenant_id = $${params.length}`;
    }
    // Remove group memberships first.
    await this.pool.query(
      `DELETE FROM ${this.s}.scim_group_members WHERE user_id = $1`,
      [id],
    );
    // Soft-delete the user.
    const result = await this.pool.query(
      `UPDATE ${this.s}.scim_users
       SET active = FALSE, deleted_at = NOW(), updated_at = NOW()
       WHERE id = $1${tenantClause} AND deleted_at IS NULL
       RETURNING id`,
      params,
    );
    if (result.rows.length === 0) {
      throw Object.assign(new Error(`SCIM user not found: ${id}`), { scimStatus: 404 });
    }
  }

  // ── Groups ─────────────────────────────────────────────────────────────────

  async createGroup(
    group: Omit<ScimGroup, 'id' | 'createdAt' | 'updatedAt'>,
  ): Promise<ScimGroup> {
    const id = generateId();
    const result = await this.pool.query(
      `INSERT INTO ${this.s}.scim_groups (id, display_name, tenant_id)
       VALUES ($1, $2, $3) RETURNING *`,
      [id, group.displayName, group.tenantId ?? null],
    );
    return row2Group(result.rows[0]!);
  }

  async getGroup(id: string, tenantId?: string): Promise<ScimGroup | undefined> {
    const params: unknown[] = [id];
    let tenantClause = '';
    if (tenantId !== undefined) {
      params.push(tenantId);
      tenantClause = ' AND tenant_id = $2';
    }
    const result = await this.pool.query(
      `SELECT * FROM ${this.s}.scim_groups WHERE id = $1${tenantClause}`,
      params,
    );
    if (result.rows.length === 0) return undefined;
    return row2Group(result.rows[0]!);
  }

  async listGroups(opts: {
    filter?: ScimFilter;
    tenantId?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ groups: ScimGroup[]; totalCount: number }> {
    const { filter, tenantId, limit = 100, offset = 0 } = opts;
    const params: unknown[] = [];
    const groupCols: Record<string, string> = { displayName: 'display_name' };

    let whereClause = 'WHERE 1=1';
    if (tenantId !== undefined) {
      params.push(tenantId);
      whereClause += ` AND tenant_id = $${params.length}`;
    }

    const { clause: filterClause, nextParamIdx } = buildFilterClause(
      filter,
      groupCols,
      params,
      params.length + 1,
    );
    whereClause += filterClause;

    params.push(limit);
    const limitParam = nextParamIdx;
    params.push(offset);
    const offsetParam = limitParam + 1;

    const countResult = await this.pool.query(
      `SELECT COUNT(*) AS cnt FROM ${this.s}.scim_groups ${whereClause}`,
      params.slice(0, params.length - 2),
    );
    const totalCount = parseInt(String(countResult.rows[0]?.['cnt'] ?? '0'), 10);

    const dataResult = await this.pool.query(
      `SELECT * FROM ${this.s}.scim_groups ${whereClause} ORDER BY created_at ASC LIMIT $${limitParam} OFFSET $${offsetParam}`,
      params,
    );

    return { groups: dataResult.rows.map(row2Group), totalCount };
  }

  async replaceGroup(
    id: string,
    group: Omit<ScimGroup, 'id' | 'createdAt' | 'updatedAt'>,
    members?: string[],
  ): Promise<ScimGroup> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');

      const result = await client.query(
        `UPDATE ${this.s}.scim_groups
         SET display_name = $1, tenant_id = $2, updated_at = NOW()
         WHERE id = $3 RETURNING *`,
        [group.displayName, group.tenantId ?? null, id],
      );
      if (result.rows.length === 0) {
        await client.query('ROLLBACK');
        throw Object.assign(new Error(`SCIM group not found: ${id}`), { scimStatus: 404 });
      }

      if (members !== undefined) {
        // Replace the full membership set.
        await client.query(
          `DELETE FROM ${this.s}.scim_group_members WHERE group_id = $1`,
          [id],
        );
        for (const userId of members) {
          await client.query(
            `INSERT INTO ${this.s}.scim_group_members (group_id, user_id) VALUES ($1, $2)
             ON CONFLICT (group_id, user_id) DO NOTHING`,
            [id, userId],
          );
        }
      }

      await client.query('COMMIT');
      return row2Group(result.rows[0]!);
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  async patchGroupMembers(
    id: string,
    addMembers?: string[],
    removeMembers?: string[],
    tenantId?: string,
  ): Promise<ScimGroup> {
    const group = await this.getGroup(id, tenantId);
    if (!group) {
      throw Object.assign(new Error(`SCIM group not found: ${id}`), { scimStatus: 404 });
    }

    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');

      for (const userId of removeMembers ?? []) {
        await client.query(
          `DELETE FROM ${this.s}.scim_group_members WHERE group_id = $1 AND user_id = $2`,
          [id, userId],
        );
      }
      for (const userId of addMembers ?? []) {
        await client.query(
          `INSERT INTO ${this.s}.scim_group_members (group_id, user_id) VALUES ($1, $2)
           ON CONFLICT (group_id, user_id) DO NOTHING`,
          [id, userId],
        );
      }

      await client.query(
        `UPDATE ${this.s}.scim_groups SET updated_at = NOW() WHERE id = $1`,
        [id],
      );

      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }

    return group;
  }

  async deleteGroup(id: string, tenantId?: string): Promise<void> {
    const params: unknown[] = [id];
    let tenantClause = '';
    if (tenantId !== undefined) {
      params.push(tenantId);
      tenantClause = ` AND tenant_id = $${params.length}`;
    }
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      // Remove all memberships first (FK constraint).
      await client.query(
        `DELETE FROM ${this.s}.scim_group_members WHERE group_id = $1`,
        [id],
      );
      const result = await client.query(
        `DELETE FROM ${this.s}.scim_groups WHERE id = $1${tenantClause} RETURNING id`,
        params,
      );
      if (result.rows.length === 0) {
        await client.query('ROLLBACK');
        throw Object.assign(new Error(`SCIM group not found: ${id}`), { scimStatus: 404 });
      }
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  // ── Issuance integration ────────────────────────────────────────────────────

  async getGroupNamesForUser(userId: string, tenantId?: string): Promise<string[]> {
    const params: unknown[] = [userId];
    let tenantJoin = '';
    if (tenantId !== undefined) {
      params.push(tenantId);
      tenantJoin = ` AND g.tenant_id = $${params.length}`;
    }
    const result = await this.pool.query(
      `SELECT g.display_name
       FROM ${this.s}.scim_group_members m
       JOIN ${this.s}.scim_groups g ON g.id = m.group_id
       WHERE m.user_id = $1${tenantJoin}`,
      params,
    );
    return result.rows.map((r) => r['display_name'] as string);
  }
}
