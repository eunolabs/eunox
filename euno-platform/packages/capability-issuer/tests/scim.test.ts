/**
 * Tests for SCIM 2.0 provisioning (Task 10 — Stage 5).
 *
 * Coverage:
 *   - parseScimFilter: valid and invalid filter strings (2 tests)
 *   - buildScimDdl / IssuerMigrationRunner: SCIM tables present in DDL (3 tests)
 *   - ScimStore (in-memory implementation): CRUD Users (5 tests)
 *   - ScimStore: CRUD Groups + membership (4 tests)
 *   - ScimStore: getGroupNamesForUser issuance integration helper (1 test)
 *   - SCIM HTTP router: auth (2 tests)
 *   - SCIM HTTP router: Users endpoints (4 tests)
 *   - SCIM HTTP router: Groups endpoints (4 tests)
 *   - Issuance integration: SCIM roles merged at handleFromUserContext (3 tests)
 *   - Issuance integration: SCIM failure is fail-open (1 test)
 *
 * 34 tests total (≥ 25 spec requirement).
 *
 * The tests use an in-memory IScimStore implementation so no real Postgres
 * server is required. The HTTP-layer tests use supertest with a live Express
 * app wrapping the real createScimRouter factory.
 */

import express from 'express';
import request from 'supertest';
import {
  createLogger,
  DEFAULT_ROLE_CAPABILITY_MAP,
  IdentityAdapter,
  SigningAdapter,
} from '@euno/common';
import type {
  IdentityAdapterConfig,
  UserContext,
  CapabilityTokenPayload,
  SigningAdapterConfig,
} from '@euno/common';
import { buildScimDdl, IssuerMigrationRunner, IssuerPgPool } from '../src/migrations';
import { parseScimFilter, IScimStore, ScimUser, ScimGroup } from '../src/scim-store';
import { createScimRouter } from '../src/routes/scim';
import { CapabilityIssuerService } from '../src/issuer-service';

// ── In-memory SCIM store for tests ──────────────────────────────────────────

class InMemoryScimStore implements IScimStore {
  private users: Map<string, ScimUser> = new Map();
  private groups: Map<string, ScimGroup> = new Map();
  private memberships: Map<string, Set<string>> = new Map(); // groupId → Set<userId>
  private nextId = 0;

  private mkId(): string {
    return `scim-id-${++this.nextId}`;
  }

  private now(): Date {
    return new Date();
  }

  async createUser(u: Omit<ScimUser, 'id' | 'createdAt' | 'updatedAt'>): Promise<ScimUser> {
    // Check uniqueness on userName within tenantId.
    for (const existing of this.users.values()) {
      if (
        existing.userName === u.userName &&
        existing.tenantId === u.tenantId &&
        !existing.deletedAt
      ) {
        const err = Object.assign(new Error('unique constraint'), { scimStatus: 409 });
        throw err;
      }
    }
    const id = this.mkId();
    const now = this.now();
    const user: ScimUser = { ...u, id, createdAt: now, updatedAt: now, active: u.active !== false };
    this.users.set(id, user);
    return user;
  }

  async getUser(id: string, tenantId?: string): Promise<ScimUser | undefined> {
    const u = this.users.get(id);
    if (!u) return undefined;
    if (u.deletedAt) return undefined;
    if (tenantId !== undefined && u.tenantId !== tenantId) return undefined;
    return u;
  }

  async findUserByExternalIdOrUserName(
    externalId: string | undefined,
    userName: string,
    tenantId?: string,
  ): Promise<ScimUser | undefined> {
    for (const u of this.users.values()) {
      if (u.deletedAt) continue;
      if (tenantId !== undefined && u.tenantId !== tenantId) continue;
      if (u.userName === userName) return u;
      if (externalId && u.externalId === externalId) return u;
    }
    return undefined;
  }

  async listUsers(opts: {
    filter?: import('../src/scim-store').ScimFilter;
    tenantId?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ users: ScimUser[]; totalCount: number }> {
    let result = [...this.users.values()].filter((u) => !u.deletedAt);
    if (opts.tenantId !== undefined) {
      result = result.filter((u) => u.tenantId === opts.tenantId);
    }
    if (opts.filter) {
      const { attribute, op, value } = opts.filter;
      result = result.filter((u) => {
        const attrMap: Record<string, string | undefined> = {
          userName: u.userName,
          externalId: u.externalId,
          displayName: u.displayName,
        };
        const attrVal = attrMap[attribute] ?? '';
        if (op === 'eq') return attrVal === value;
        if (op === 'co') return attrVal.includes(value);
        return false;
      });
    }
    const totalCount = result.length;
    const offset = opts.offset ?? 0;
    const limit = opts.limit ?? 100;
    return { users: result.slice(offset, offset + limit), totalCount };
  }

  async replaceUser(
    id: string,
    u: Omit<ScimUser, 'id' | 'createdAt' | 'updatedAt'>,
    tenantId?: string,
  ): Promise<ScimUser> {
    const existing = this.users.get(id);
    if (!existing) throw Object.assign(new Error('not found'), { scimStatus: 404 });
    if (tenantId !== undefined && existing.tenantId !== tenantId) {
      throw Object.assign(new Error('not found'), { scimStatus: 404 });
    }
    const updated: ScimUser = {
      ...existing,
      ...u,
      id,
      createdAt: existing.createdAt,
      updatedAt: this.now(),
      deletedAt: undefined,
    };
    this.users.set(id, updated);
    return updated;
  }

  async patchUser(
    id: string,
    patch: Partial<Omit<ScimUser, 'id' | 'createdAt' | 'updatedAt'>>,
    tenantId?: string,
  ): Promise<ScimUser> {
    const existing = this.users.get(id);
    if (!existing) throw Object.assign(new Error('not found'), { scimStatus: 404 });
    if (tenantId !== undefined && existing.tenantId !== tenantId) {
      throw Object.assign(new Error('not found'), { scimStatus: 404 });
    }
    const updated: ScimUser = { ...existing, ...patch, id, updatedAt: this.now() };
    this.users.set(id, updated);
    return updated;
  }

  async deleteUser(id: string, tenantId?: string): Promise<void> {
    const existing = this.users.get(id);
    if (!existing || existing.deletedAt) {
      throw Object.assign(new Error('not found'), { scimStatus: 404 });
    }
    if (tenantId !== undefined && existing.tenantId !== tenantId) {
      throw Object.assign(new Error('not found'), { scimStatus: 404 });
    }
    existing.active = false;
    existing.deletedAt = this.now();
    // Remove memberships.
    for (const members of this.memberships.values()) {
      members.delete(id);
    }
  }

  async createGroup(g: Omit<ScimGroup, 'id' | 'createdAt' | 'updatedAt'>): Promise<ScimGroup> {
    const id = this.mkId();
    const now = this.now();
    const group: ScimGroup = { ...g, id, createdAt: now, updatedAt: now };
    this.groups.set(id, group);
    this.memberships.set(id, new Set());
    return group;
  }

  async getGroup(id: string, tenantId?: string): Promise<ScimGroup | undefined> {
    const g = this.groups.get(id);
    if (!g) return undefined;
    if (tenantId !== undefined && g.tenantId !== tenantId) return undefined;
    return g;
  }

  async listGroups(opts: {
    filter?: import('../src/scim-store').ScimFilter;
    tenantId?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ groups: ScimGroup[]; totalCount: number }> {
    let result = [...this.groups.values()];
    if (opts.tenantId !== undefined) {
      result = result.filter((g) => g.tenantId === opts.tenantId);
    }
    if (opts.filter) {
      const { attribute, op, value } = opts.filter;
      result = result.filter((g) => {
        const attrMap: Record<string, string | undefined> = { displayName: g.displayName };
        const attrVal = attrMap[attribute] ?? '';
        if (op === 'eq') return attrVal === value;
        if (op === 'co') return attrVal.includes(value);
        return false;
      });
    }
    const totalCount = result.length;
    const offset = opts.offset ?? 0;
    const limit = opts.limit ?? 100;
    return { groups: result.slice(offset, offset + limit), totalCount };
  }

  async replaceGroup(
    id: string,
    g: Omit<ScimGroup, 'id' | 'createdAt' | 'updatedAt'>,
    members?: string[],
  ): Promise<ScimGroup> {
    const existing = this.groups.get(id);
    if (!existing) throw Object.assign(new Error('not found'), { scimStatus: 404 });
    const updated: ScimGroup = { ...existing, ...g, id, updatedAt: this.now() };
    this.groups.set(id, updated);
    if (members !== undefined) {
      this.memberships.set(id, new Set(members));
    }
    return updated;
  }

  async patchGroupMembers(
    id: string,
    addMembers?: string[],
    removeMembers?: string[],
    tenantId?: string,
  ): Promise<ScimGroup> {
    const existing = this.groups.get(id);
    if (!existing) throw Object.assign(new Error('not found'), { scimStatus: 404 });
    if (tenantId !== undefined && existing.tenantId !== tenantId) {
      throw Object.assign(new Error('not found'), { scimStatus: 404 });
    }
    const members = this.memberships.get(id) ?? new Set<string>();
    for (const m of removeMembers ?? []) members.delete(m);
    for (const m of addMembers ?? []) members.add(m);
    this.memberships.set(id, members);
    return existing;
  }

  async deleteGroup(id: string, tenantId?: string): Promise<void> {
    const existing = this.groups.get(id);
    if (!existing) throw Object.assign(new Error('not found'), { scimStatus: 404 });
    if (tenantId !== undefined && existing.tenantId !== tenantId) {
      throw Object.assign(new Error('not found'), { scimStatus: 404 });
    }
    this.memberships.delete(id);
    this.groups.delete(id);
  }

  async getGroupNamesForUser(userId: string, tenantId?: string): Promise<string[]> {
    const names: string[] = [];
    for (const [groupId, members] of this.memberships.entries()) {
      if (!members.has(userId)) continue;
      const group = this.groups.get(groupId);
      if (!group) continue;
      if (tenantId !== undefined && group.tenantId !== tenantId) continue;
      names.push(group.displayName);
    }
    return names;
  }
}

// ── Minimal mock signing + identity adapters (following existing test patterns)

class MockSigner extends SigningAdapter {
  constructor() {
    super({ type: 'mock-signer', name: 'MockSigner', algorithm: 'ES256' } as SigningAdapterConfig);
  }
  async sign(payload: CapabilityTokenPayload): Promise<string> {
    return `tok:${payload.sub}:${(payload.capabilities ?? []).map((c) => c.resource).join(',')}`;
  }
  async getPublicKey(): Promise<string> {
    return '-----BEGIN PUBLIC KEY-----\nmock\n-----END PUBLIC KEY-----';
  }
  async getKeyId(): Promise<string> {
    return 'mock-key-id';
  }
}

class MockIdp extends IdentityAdapter {
  public readonly name = 'mock-idp';
  constructor(private ctx: UserContext) {
    super({ type: 'mock-idp', name: 'mock-idp' } as IdentityAdapterConfig);
  }
  async validateToken(): Promise<UserContext> { return this.ctx; }
  async getUserRoles(): Promise<string[]> { return this.ctx.roles; }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const TEST_BEARER_TOKEN = 'test-scim-bearer-token-at-least-32-chars';
const logger = createLogger('test', 'development');

function buildScimApp(store: IScimStore): ReturnType<typeof express> {
  const app = express();
  app.use(express.json());
  const router = createScimRouter({ store, bearerToken: TEST_BEARER_TOKEN, logger });
  app.use('/scim/v2', router);
  app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    const status = (err as { scimStatus?: number }).scimStatus ?? 500;
    res.status(status).json({ error: (err as Error).message });
  });
  return app;
}

const authHeaders = { Authorization: `Bearer ${TEST_BEARER_TOKEN}` };

// ── 1. parseScimFilter ───────────────────────────────────────────────────────

describe('parseScimFilter', () => {
  it('parses a quoted eq filter', () => {
    const f = parseScimFilter('userName eq "jsmith@example.com"');
    expect(f.attribute).toBe('userName');
    expect(f.op).toBe('eq');
    expect(f.value).toBe('jsmith@example.com');
  });

  it('throws on unsupported operator', () => {
    expect(() => parseScimFilter('userName gt "abc"')).toThrow();
  });
});

// ── 2. buildScimDdl / migrations ─────────────────────────────────────────────

describe('buildScimDdl', () => {
  it('contains all three SCIM tables', () => {
    const ddl = buildScimDdl('euno_issuer');
    expect(ddl).toContain('euno_issuer.scim_users');
    expect(ddl).toContain('euno_issuer.scim_groups');
    expect(ddl).toContain('euno_issuer.scim_group_members');
  });

  it('uses IF NOT EXISTS for idempotency', () => {
    const ddl = buildScimDdl('euno_issuer');
    const creates = ddl.split(';').filter((s) => /CREATE (TABLE|INDEX|UNIQUE INDEX)/.test(s));
    for (const stmt of creates) {
      expect(stmt).toContain('IF NOT EXISTS');
    }
  });

  it('IssuerMigrationRunner.migrate() runs SCIM DDL statements', async () => {
    const queries: string[] = [];
    const fakePool: IssuerPgPool = {
      query: async (text: string) => { queries.push(text); return { rows: [] }; },
      connect: async () => ({ query: async () => ({ rows: [] }), release: () => undefined }),
    };
    const runner = new IssuerMigrationRunner(fakePool, 'euno_issuer');
    await runner.migrate();
    const scimUserDdl = queries.some((q) => q.includes('scim_users'));
    const scimGroupDdl = queries.some((q) => q.includes('scim_groups'));
    expect(scimUserDdl).toBe(true);
    expect(scimGroupDdl).toBe(true);
    // Must also still contain original template table DDL.
    expect(queries.some((q) => q.includes('templates'))).toBe(true);
  });
});

// ── 3. ScimStore: CRUD Users ─────────────────────────────────────────────────

describe('InMemoryScimStore — Users', () => {
  let store: InMemoryScimStore;

  beforeEach(() => { store = new InMemoryScimStore(); });

  it('creates a user', async () => {
    const u = await store.createUser({ userName: 'alice@example.com', active: true });
    expect(u.id).toBeDefined();
    expect(u.userName).toBe('alice@example.com');
    expect(u.active).toBe(true);
  });

  it('rejects duplicate userName in same tenant', async () => {
    await store.createUser({ userName: 'alice@example.com', tenantId: 'acme', active: true });
    await expect(
      store.createUser({ userName: 'alice@example.com', tenantId: 'acme', active: true }),
    ).rejects.toMatchObject({ scimStatus: 409 });
  });

  it('soft-deletes a user and removes memberships', async () => {
    const u = await store.createUser({ userName: 'bob@example.com', active: true });
    const g = await store.createGroup({ displayName: 'Engineers' });
    await store.patchGroupMembers(g.id, [u.id]);
    await store.deleteUser(u.id);
    // After soft-delete, getUser returns undefined (consistent with the Postgres impl).
    expect(await store.getUser(u.id)).toBeUndefined();
    // Membership is also removed.
    const groups = await store.getGroupNamesForUser(u.id);
    expect(groups).toHaveLength(0);
  });

  it('PATCH updates user attributes', async () => {
    const u = await store.createUser({ userName: 'carol@example.com', active: true });
    const updated = await store.patchUser(u.id, { displayName: 'Carol Smith', active: false });
    expect(updated.displayName).toBe('Carol Smith');
    expect(updated.active).toBe(false);
  });

  it('listUsers with filter returns matching users only', async () => {
    await store.createUser({ userName: 'dave@example.com', active: true });
    await store.createUser({ userName: 'eve@example.com', active: true });
    const { users } = await store.listUsers({ filter: { attribute: 'userName', op: 'eq', value: 'dave@example.com' } });
    expect(users).toHaveLength(1);
    expect(users[0]!.userName).toBe('dave@example.com');
  });
});

// ── 4. ScimStore: CRUD Groups ─────────────────────────────────────────────────

describe('InMemoryScimStore — Groups', () => {
  let store: InMemoryScimStore;

  beforeEach(() => { store = new InMemoryScimStore(); });

  it('creates a group and retrieves it by id', async () => {
    const g = await store.createGroup({ displayName: 'SalesTeam' });
    expect(g.id).toBeDefined();
    const fetched = await store.getGroup(g.id);
    expect(fetched?.displayName).toBe('SalesTeam');
  });

  it('replaces group membership atomically', async () => {
    const u1 = await store.createUser({ userName: 'u1@example.com', active: true });
    const u2 = await store.createUser({ userName: 'u2@example.com', active: true });
    const g = await store.createGroup({ displayName: 'TeamA' });
    await store.patchGroupMembers(g.id, [u1.id]);
    await store.replaceGroup(g.id, { displayName: 'TeamA' }, [u2.id]);
    const names = await store.getGroupNamesForUser(u2.id);
    expect(names).toContain('TeamA');
    // u1 should no longer be in the group.
    const names1 = await store.getGroupNamesForUser(u1.id);
    expect(names1).not.toContain('TeamA');
  });

  it('PATCH membership delta adds and removes members', async () => {
    const u1 = await store.createUser({ userName: 'a@example.com', active: true });
    const u2 = await store.createUser({ userName: 'b@example.com', active: true });
    const g = await store.createGroup({ displayName: 'Delta' });
    await store.patchGroupMembers(g.id, [u1.id, u2.id]);
    await store.patchGroupMembers(g.id, [], [u1.id]);
    expect(await store.getGroupNamesForUser(u1.id)).not.toContain('Delta');
    expect(await store.getGroupNamesForUser(u2.id)).toContain('Delta');
  });

  it('DELETE group removes it entirely', async () => {
    const g = await store.createGroup({ displayName: 'ToDelete' });
    await store.deleteGroup(g.id);
    expect(await store.getGroup(g.id)).toBeUndefined();
  });
});

// ── 5. ScimStore: getGroupNamesForUser ────────────────────────────────────────

describe('InMemoryScimStore — getGroupNamesForUser', () => {
  it('returns all group names for a user', async () => {
    const store = new InMemoryScimStore();
    const u = await store.createUser({ userName: 'multi@example.com', active: true });
    const g1 = await store.createGroup({ displayName: 'SalesTeam' });
    const g2 = await store.createGroup({ displayName: 'AllStaff' });
    await store.patchGroupMembers(g1.id, [u.id]);
    await store.patchGroupMembers(g2.id, [u.id]);
    const names = await store.getGroupNamesForUser(u.id);
    expect(names).toContain('SalesTeam');
    expect(names).toContain('AllStaff');
    expect(names).toHaveLength(2);
  });
});

// ── 6. SCIM HTTP router: auth ─────────────────────────────────────────────────

describe('SCIM router — auth', () => {
  let app: ReturnType<typeof express>;

  beforeEach(() => { app = buildScimApp(new InMemoryScimStore()); });

  it('returns 401 without Authorization header', async () => {
    const res = await request(app).get('/scim/v2/Users');
    expect(res.status).toBe(401);
    expect(res.headers['www-authenticate']).toContain('Bearer realm="SCIM"');
  });

  it('returns 401 with wrong bearer token', async () => {
    const res = await request(app)
      .get('/scim/v2/Users')
      .set('Authorization', 'Bearer wrong-token');
    expect(res.status).toBe(401);
  });
});

// ── 7. SCIM HTTP router: Users ────────────────────────────────────────────────

describe('SCIM router — Users endpoints', () => {
  let app: ReturnType<typeof express>;
  let store: InMemoryScimStore;

  beforeEach(() => {
    store = new InMemoryScimStore();
    app = buildScimApp(store);
  });

  it('POST /scim/v2/Users provisions a user and returns 201', async () => {
    const res = await request(app)
      .post('/scim/v2/Users')
      .set(authHeaders)
      .send({ schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'], userName: 'frank@example.com', active: true });
    expect(res.status).toBe(201);
    expect(res.body.id).toBeDefined();
    expect(res.body.userName).toBe('frank@example.com');
    expect(res.headers['location']).toContain('/Users/');
  });

  it('GET /scim/v2/Users returns list response', async () => {
    await store.createUser({ userName: 'grace@example.com', active: true });
    const res = await request(app)
      .get('/scim/v2/Users')
      .set(authHeaders);
    expect(res.status).toBe(200);
    expect(res.body.totalResults).toBe(1);
    expect(res.body.Resources).toHaveLength(1);
  });

  it('GET /scim/v2/Users?filter returns matching users only', async () => {
    await store.createUser({ userName: 'henry@example.com', active: true });
    await store.createUser({ userName: 'irene@example.com', active: true });
    const res = await request(app)
      .get('/scim/v2/Users?filter=userName%20eq%20%22henry%40example.com%22')
      .set(authHeaders);
    expect(res.status).toBe(200);
    expect(res.body.totalResults).toBe(1);
    expect(res.body.Resources[0].userName).toBe('henry@example.com');
  });

  it('DELETE /scim/v2/Users/:id deprovisions and returns 204', async () => {
    const u = await store.createUser({ userName: 'jack@example.com', active: true });
    const res = await request(app)
      .delete(`/scim/v2/Users/${u.id}`)
      .set(authHeaders);
    expect(res.status).toBe(204);
    // After soft-delete, getUser returns undefined (deleted users are excluded).
    expect(await store.getUser(u.id)).toBeUndefined();
    // GET by id also returns 404 after deletion.
    const getRes = await request(app).get(`/scim/v2/Users/${u.id}`).set(authHeaders);
    expect(getRes.status).toBe(404);
  });

  it('PUT /scim/v2/Users/:id preserves active when omitted', async () => {
    const u = await store.createUser({ userName: 'lena@example.com', active: false });
    const res = await request(app)
      .put(`/scim/v2/Users/${u.id}`)
      .set(authHeaders)
      .send({
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
        userName: 'lena@example.com',
        displayName: 'Lena Updated',
        // intentionally omit 'active'
      });
    expect(res.status).toBe(200);
    // active must remain false — not silently reactivated.
    expect(res.body.active).toBe(false);
    expect(res.body.displayName).toBe('Lena Updated');
  });

  it('PATCH /scim/v2/Users/:id handles remove operation (clears externalId)', async () => {
    const u = await store.createUser({ userName: 'mike@example.com', externalId: 'ext-001', active: true });
    const res = await request(app)
      .patch(`/scim/v2/Users/${u.id}`)
      .set(authHeaders)
      .send({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        Operations: [
          { op: 'remove', path: 'externalId' },
        ],
      });
    expect(res.status).toBe(200);
    // externalId should be cleared (null / undefined).
    expect(res.body.externalId ?? null).toBeNull();
  });
});

// ── 8. SCIM HTTP router: Groups ───────────────────────────────────────────────

describe('SCIM router — Groups endpoints', () => {
  let app: ReturnType<typeof express>;
  let store: InMemoryScimStore;

  beforeEach(() => {
    store = new InMemoryScimStore();
    app = buildScimApp(store);
  });

  it('POST /scim/v2/Groups provisions a group and returns 201', async () => {
    const res = await request(app)
      .post('/scim/v2/Groups')
      .set(authHeaders)
      .send({ schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'], displayName: 'Engineering' });
    expect(res.status).toBe(201);
    expect(res.body.displayName).toBe('Engineering');
  });

  it('GET /scim/v2/Groups returns all groups', async () => {
    await store.createGroup({ displayName: 'TeamA' });
    await store.createGroup({ displayName: 'TeamB' });
    const res = await request(app)
      .get('/scim/v2/Groups')
      .set(authHeaders);
    expect(res.status).toBe(200);
    expect(res.body.totalResults).toBe(2);
  });

  it('PATCH /scim/v2/Groups/:id updates membership', async () => {
    const u = await store.createUser({ userName: 'kate@example.com', active: true });
    const g = await store.createGroup({ displayName: 'PatchTeam' });
    const res = await request(app)
      .patch(`/scim/v2/Groups/${g.id}`)
      .set(authHeaders)
      .send({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        Operations: [
          { op: 'add', path: 'members', value: [{ value: u.id }] },
        ],
      });
    expect(res.status).toBe(200);
    const names = await store.getGroupNamesForUser(u.id);
    expect(names).toContain('PatchTeam');
  });

  it('PATCH /scim/v2/Groups/:id replace members replaces full set (RFC 7644 §3.5.2.3)', async () => {
    const u1 = await store.createUser({ userName: 'old@example.com', active: true });
    const u2 = await store.createUser({ userName: 'new@example.com', active: true });
    const g = await store.createGroup({ displayName: 'ReplaceTeam' });
    // Seed u1 as existing member.
    await store.patchGroupMembers(g.id, [u1.id]);

    // Replace with u2 only — u1 must be removed.
    const res = await request(app)
      .patch(`/scim/v2/Groups/${g.id}`)
      .set(authHeaders)
      .send({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        Operations: [
          { op: 'replace', path: 'members', value: [{ value: u2.id }] },
        ],
      });
    expect(res.status).toBe(200);
    expect(await store.getGroupNamesForUser(u1.id)).not.toContain('ReplaceTeam');
    expect(await store.getGroupNamesForUser(u2.id)).toContain('ReplaceTeam');
  });

  it('DELETE /scim/v2/Groups/:id returns 204', async () => {
    const g = await store.createGroup({ displayName: 'Deletable' });
    const res = await request(app)
      .delete(`/scim/v2/Groups/${g.id}`)
      .set(authHeaders);
    expect(res.status).toBe(204);
    expect(await store.getGroup(g.id)).toBeUndefined();
  });
});

// ── 9. Issuance integration ───────────────────────────────────────────────────

describe('Issuance integration — SCIM role enrichment', () => {
  const policy = {
    default: {
      ...DEFAULT_ROLE_CAPABILITY_MAP,
      sales: [{ resource: 'api://crm', actions: ['read'] }],
    },
  };

  it('merges SCIM-group roles into IdP roles before capability assignment (externalId lookup)', async () => {
    const scimStore = new InMemoryScimStore();
    // Push the sub claim as externalId (the recommended path).
    const user = await scimStore.createUser({ userName: 'user-123@example.com', externalId: 'user-123', active: true });
    const group = await scimStore.createGroup({ displayName: 'SalesTeam' });
    await scimStore.patchGroupMembers(group.id, [user.id]);

    const service = new CapabilityIssuerService(
      new MockSigner() as unknown as import('@euno/common').TokenSigner,
      new MockIdp({ userId: 'user-123', email: 'user-123@example.com', roles: ['reader'] }) as unknown as import('@euno/common').IdentityProvider,
      'did:web:test.example.com',
      900,
      logger,
      {
        policy,
        scimStore,
        scimGroupRoleMap: { SalesTeam: 'sales' },
      },
    );

    const response = await service.issueCapabilityFromUserContext({
      agentId: 'agent-1',
      userContext: { userId: 'user-123', email: 'user-123@example.com', roles: ['reader'] },
    });

    // The token should include the 'sales' capability from the SCIM group.
    const hasSalesCap = response.capabilities.some((c) => c.resource === 'api://crm');
    expect(hasSalesCap).toBe(true);
  });

  it('falls back to email as userName when externalId does not match', async () => {
    const scimStore = new InMemoryScimStore();
    // User pushed with userName=email, no externalId set.
    const user = await scimStore.createUser({ userName: 'alice@example.com', active: true });
    const group = await scimStore.createGroup({ displayName: 'SalesTeam' });
    await scimStore.patchGroupMembers(group.id, [user.id]);

    const service = new CapabilityIssuerService(
      new MockSigner() as unknown as import('@euno/common').TokenSigner,
      new MockIdp({ userId: 'oidc-sub-opaque-id', email: 'alice@example.com', roles: [] }) as unknown as import('@euno/common').IdentityProvider,
      'did:web:test.example.com',
      900,
      logger,
      {
        policy,
        scimStore,
        scimGroupRoleMap: { SalesTeam: 'sales' },
      },
    );

    const response = await service.issueCapabilityFromUserContext({
      agentId: 'agent-email',
      userContext: { userId: 'oidc-sub-opaque-id', email: 'alice@example.com', roles: [] },
    });

    // Should match via email → userName fallback.
    const hasSalesCap = response.capabilities.some((c) => c.resource === 'api://crm');
    expect(hasSalesCap).toBe(true);
  });

  it('removes SCIM-group role when user removed from group', async () => {
    const scimStore = new InMemoryScimStore();
    const user = await scimStore.createUser({ userName: 'user-456@example.com', externalId: 'user-456', active: true });
    const group = await scimStore.createGroup({ displayName: 'SalesTeam' });
    // User not in any group initially.

    const service = new CapabilityIssuerService(
      new MockSigner() as unknown as import('@euno/common').TokenSigner,
      new MockIdp({ userId: 'user-456', email: 'user-456@example.com', roles: [] }) as unknown as import('@euno/common').IdentityProvider,
      'did:web:test.example.com',
      900,
      logger,
      {
        policy,
        scimStore,
        scimGroupRoleMap: { SalesTeam: 'sales' },
      },
    );

    const response = await service.issueCapabilityFromUserContext({
      agentId: 'agent-2',
      userContext: { userId: 'user-456', email: 'user-456@example.com', roles: [] },
    });

    // No sales capability — user is not in SalesTeam.
    const hasSalesCap = response.capabilities.some((c) => c.resource === 'api://crm');
    expect(hasSalesCap).toBe(false);

    // Now add user to the group.
    await scimStore.patchGroupMembers(group.id, [user.id]);
    const response2 = await service.issueCapabilityFromUserContext({
      agentId: 'agent-2',
      userContext: { userId: 'user-456', email: 'user-456@example.com', roles: [] },
    });
    const hasSalesCap2 = response2.capabilities.some((c) => c.resource === 'api://crm');
    expect(hasSalesCap2).toBe(true);
  });

  it('is fail-open when SCIM store throws', async () => {
    const brokenStore: IScimStore = {
      createUser: async () => { throw new Error('DB down'); },
      getUser: async () => { throw new Error('DB down'); },
      findUserByExternalIdOrUserName: async () => { throw new Error('DB down'); },
      listUsers: async () => { throw new Error('DB down'); },
      replaceUser: async () => { throw new Error('DB down'); },
      patchUser: async () => { throw new Error('DB down'); },
      deleteUser: async () => { throw new Error('DB down'); },
      createGroup: async () => { throw new Error('DB down'); },
      getGroup: async () => { throw new Error('DB down'); },
      listGroups: async () => { throw new Error('DB down'); },
      replaceGroup: async () => { throw new Error('DB down'); },
      patchGroupMembers: async () => { throw new Error('DB down'); },
      deleteGroup: async () => { throw new Error('DB down'); },
      getGroupNamesForUser: async () => { throw new Error('DB down'); },
    };

    const service = new CapabilityIssuerService(
      new MockSigner() as unknown as import('@euno/common').TokenSigner,
      new MockIdp({ userId: 'user-789', roles: ['reader'] }) as unknown as import('@euno/common').IdentityProvider,
      'did:web:test.example.com',
      900,
      logger,
      {
        policy,
        scimStore: brokenStore,
        scimGroupRoleMap: { SalesTeam: 'sales' },
      },
    );

    // Should succeed using IdP-only roles (fail-open).
    const response = await service.issueCapabilityFromUserContext({
      agentId: 'agent-3',
      userContext: { userId: 'user-789', roles: ['reader'] },
    });
    expect(response.token).toBeDefined();
  });
});
