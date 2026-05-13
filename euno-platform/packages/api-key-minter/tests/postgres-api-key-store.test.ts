/**
 * PostgresApiKeyStore — unit tests (Task 2)
 * ────────────────────────────────────────────────────────────────────────────
 * Tests cover:
 *
 *   1. **Schema creation** — `ensureSchema()` executes the DDL statements.
 *   2. **createKey()** — inserts a new key; fails on duplicate prefix.
 *   3. **getByPrefix()** — returns the record or undefined.
 *   4. **getDummyRecord()** — always returns the fixed dummy record.
 *   5. **updateLastUsedAt()** — issues an UPDATE with the given timestamp.
 *   6. **revokeKey()** — sets revoked_at; no-ops on already-revoked key.
 *   7. **listByTenant()** — scoped SELECT; excludes other tenants.
 *   8. **updateCapabilitiesByPolicyId()** — updates non-revoked keys; returns count.
 *   9. **Row mapping** — Date objects in timestamps converted to ISO strings;
 *      JSONB capabilities parsed from strings and arrays.
 *  10. **DDL** — `API_KEY_DDL` is a non-empty string containing the expected table.
 */

import { PostgresApiKeyStore, API_KEY_DDL } from '../src/postgres-api-key-store';
import type { ApiKeyRecord } from '../src/api-key-store';

// ── In-memory Postgres mock ───────────────────────────────────────────────────

interface QueryCall {
  text: string;
  values?: unknown[];
}

/**
 * Minimal in-memory mock of `pg.Pool` that stores rows in a Map and verifies
 * the SQL operations issued by the store.
 */
class MockPgPool {
  readonly queryCalls: QueryCall[] = [];
  /** Rows keyed by prefix. */
  private readonly rows = new Map<string, Record<string, unknown>>();
  private autoId = 1;

  /** If set, the next query() call rejects with this error. */
  nextError: Error | null = null;

  async query(
    text: string,
    values?: unknown[],
  ): Promise<{ rows: Record<string, unknown>[] }> {
    this.queryCalls.push({ text, values });

    if (this.nextError) {
      const err = this.nextError;
      this.nextError = null;
      throw err;
    }

    // Collapse whitespace so multiline SQL is matched reliably.
    const normalized = text.replace(/\s+/g, ' ').trim();

    // DDL
    if (/^CREATE /i.test(normalized)) return { rows: [] };

    // INSERT
    if (/^INSERT INTO api_keys/i.test(normalized)) {
      const [
        prefix, keyDigest, hmacKeyVersion, tenantId, policyId,
        capabilities, scopes, label, createdAt, expiresAt,
      ] = (values ?? []) as unknown[];

      if (this.rows.has(prefix as string)) {
        const err = new Error('duplicate key value violates unique constraint "api_keys_prefix_key"');
        (err as NodeJS.ErrnoException).code = '23505';
        throw err;
      }

      this.rows.set(prefix as string, {
        id: this.autoId++,
        prefix,
        key_digest: keyDigest,
        hmac_key_version: hmacKeyVersion,
        tenant_id: tenantId,
        policy_id: policyId,
        capabilities: capabilities,
        scopes: scopes,
        label: label ?? null,
        created_at: createdAt,
        last_used_at: null,
        expires_at: expiresAt ?? null,
        revoked_at: null,
      });
      return { rows: [] };
    }

    // UPDATE last_used_at
    if (/^UPDATE api_keys SET last_used_at/i.test(normalized)) {
      const [timestamp, prefix] = (values ?? []) as [string, string];
      const row = this.rows.get(prefix);
      if (row) row['last_used_at'] = timestamp;
      return { rows: [] };
    }

    // UPDATE revoke
    if (/^UPDATE api_keys SET revoked_at/i.test(normalized)) {
      const [prefix] = (values ?? []) as [string];
      const row = this.rows.get(prefix);
      if (row && row['revoked_at'] == null) {
        row['revoked_at'] = new Date().toISOString();
      }
      return { rows: [] };
    }

    // UPDATE capabilities by policy_id — returns RETURNING prefix rows
    if (/^UPDATE api_keys SET capabilities/i.test(normalized)) {
      const [capabilities, policyId] = (values ?? []) as [unknown, string];
      const updated: Record<string, unknown>[] = [];
      for (const row of this.rows.values()) {
        if (row['policy_id'] === policyId && row['revoked_at'] == null) {
          row['capabilities'] = capabilities;
          updated.push({ prefix: row['prefix'] });
        }
      }
      return { rows: updated };
    }

    // SELECT by prefix
    if (/SELECT .* FROM api_keys WHERE prefix/i.test(normalized)) {
      const [prefix] = (values ?? []) as [string];
      const row = this.rows.get(prefix);
      return { rows: row ? [row] : [] };
    }

    // SELECT by tenant
    if (/SELECT .* FROM api_keys WHERE tenant_id/i.test(normalized)) {
      const [tenantId] = (values ?? []) as [string];
      const filtered = Array.from(this.rows.values())
        .filter(r => r['tenant_id'] === tenantId)
        .sort((a, b) => (a['id'] as number) - (b['id'] as number));
      return { rows: filtered };
    }

    return { rows: [] };
  }
}

// ── Record factory ────────────────────────────────────────────────────────────

function makeRecord(overrides: Partial<ApiKeyRecord> = {}): ApiKeyRecord {
  return {
    prefix: `sk-${Math.random().toString(36).slice(2, 10)}`,
    keyDigest: Buffer.alloc(32).toString('base64url'),
    hmacKeyVersion: 'v1',
    tenantId: 'tenant-a',
    policyId: 'policy-1',
    capabilities: [],
    scopes: ['enforce'],
    label: undefined,
    createdAt: new Date().toISOString(),
    ...overrides,
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('PostgresApiKeyStore', () => {
  let pool: MockPgPool;
  let store: PostgresApiKeyStore;

  beforeEach(() => {
    pool = new MockPgPool();
    store = new PostgresApiKeyStore(pool);
  });

  // ── ensureSchema ────────────────────────────────────────────────────────────

  describe('ensureSchema()', () => {
    it('executes DDL statements', async () => {
      await store.ensureSchema();
      expect(pool.queryCalls.length).toBeGreaterThan(0);
      const allSql = pool.queryCalls.map(q => q.text).join('\n');
      expect(allSql).toMatch(/CREATE TABLE IF NOT EXISTS api_keys/);
    });

    it('executes each DDL statement as a separate query (no multi-statement)', async () => {
      await store.ensureSchema();
      for (const call of pool.queryCalls) {
        expect(call.text.split(';').filter(s => s.trim().length > 0)).toHaveLength(1);
      }
    });

    it('is idempotent — can be called multiple times without error', async () => {
      await store.ensureSchema();
      await store.ensureSchema();
      expect(pool.queryCalls.length).toBeGreaterThan(0);
    });

    it('exports API_KEY_DDL as a non-empty string with the expected table', () => {
      expect(typeof API_KEY_DDL).toBe('string');
      expect(API_KEY_DDL.length).toBeGreaterThan(0);
      expect(API_KEY_DDL).toMatch(/CREATE TABLE IF NOT EXISTS api_keys/);
    });
  });

  // ── createKey ───────────────────────────────────────────────────────────────

  describe('createKey()', () => {
    it('issues an INSERT with all required fields', async () => {
      const rec = makeRecord({ label: 'my-key', expiresAt: '2030-01-01T00:00:00.000Z' });
      await store.createKey(rec);
      const inserts = pool.queryCalls.filter(q => /^INSERT/i.test(q.text.trim()));
      expect(inserts).toHaveLength(1);
      const vals = inserts[0]!.values as unknown[];
      expect(vals).toContain(rec.prefix);
      expect(vals).toContain(rec.keyDigest);
      expect(vals).toContain(rec.tenantId);
      expect(vals).toContain(rec.policyId);
      expect(vals).toContain('my-key');
      expect(vals).toContain('2030-01-01T00:00:00.000Z');
    });

    it('passes null for optional label when not provided', async () => {
      const rec = makeRecord({ label: undefined });
      await store.createKey(rec);
      const vals = pool.queryCalls.find(q => /^INSERT/i.test(q.text.trim()))!.values as unknown[];
      expect(vals).toContain(null);
    });

    it('passes null for expiresAt when not provided', async () => {
      const rec = makeRecord({ expiresAt: undefined });
      await store.createKey(rec);
      const vals = pool.queryCalls.find(q => /^INSERT/i.test(q.text.trim()))!.values as unknown[];
      // last value is expiresAt
      expect(vals[vals.length - 1]).toBeNull();
    });

    it('propagates database errors (e.g. duplicate prefix)', async () => {
      const rec = makeRecord();
      await store.createKey(rec);
      // Inserting the same prefix twice should reject
      await expect(store.createKey(rec)).rejects.toThrow(/duplicate key/i);
    });
  });

  // ── getByPrefix ─────────────────────────────────────────────────────────────

  describe('getByPrefix()', () => {
    it('returns the record for an existing prefix', async () => {
      const rec = makeRecord({ tenantId: 'tenant-a', label: 'test' });
      await store.createKey(rec);
      const found = await store.getByPrefix(rec.prefix);
      expect(found).toBeDefined();
      expect(found!.prefix).toBe(rec.prefix);
      expect(found!.tenantId).toBe('tenant-a');
    });

    it('returns undefined for an unknown prefix', async () => {
      const result = await store.getByPrefix('sk-unknown');
      expect(result).toBeUndefined();
    });

    it('issues a SELECT LIMIT 1 query', async () => {
      await store.getByPrefix('sk-test');
      const selects = pool.queryCalls.filter(q => /^SELECT/i.test(q.text.trim()));
      expect(selects).toHaveLength(1);
      expect(selects[0]!.text).toMatch(/LIMIT 1/);
    });
  });

  // ── getDummyRecord ───────────────────────────────────────────────────────────

  describe('getDummyRecord()', () => {
    it('returns a record without querying the database', async () => {
      const dummy = await store.getDummyRecord();
      expect(dummy).toBeDefined();
      expect(pool.queryCalls).toHaveLength(0);
    });

    it('returns the same dummy record on repeated calls', async () => {
      const a = await store.getDummyRecord();
      const b = await store.getDummyRecord();
      expect(a.prefix).toBe(b.prefix);
      expect(a.keyDigest).toBe(b.keyDigest);
    });

    it('dummy record has empty tenantId', async () => {
      const dummy = await store.getDummyRecord();
      expect(dummy.tenantId).toBe('');
    });
  });

  // ── updateLastUsedAt ────────────────────────────────────────────────────────

  describe('updateLastUsedAt()', () => {
    it('issues an UPDATE SET last_used_at query', async () => {
      await store.updateLastUsedAt('sk-test', '2026-01-01T00:00:00.000Z');
      const updates = pool.queryCalls.filter(q => /^UPDATE/i.test(q.text.trim()));
      expect(updates).toHaveLength(1);
      expect(updates[0]!.text).toMatch(/last_used_at/);
      expect(updates[0]!.values).toEqual(['2026-01-01T00:00:00.000Z', 'sk-test']);
    });

    it('reflects updated timestamp on getByPrefix after update', async () => {
      const rec = makeRecord();
      await store.createKey(rec);
      await store.updateLastUsedAt(rec.prefix, '2026-06-01T12:00:00.000Z');
      const found = await store.getByPrefix(rec.prefix);
      expect(found!.lastUsedAt).toBe('2026-06-01T12:00:00.000Z');
    });
  });

  // ── revokeKey ───────────────────────────────────────────────────────────────

  describe('revokeKey()', () => {
    it('issues an UPDATE SET revoked_at query', async () => {
      await store.revokeKey('sk-test');
      const updates = pool.queryCalls.filter(q => /^UPDATE/i.test(q.text.trim()));
      expect(updates).toHaveLength(1);
      expect(updates[0]!.text).toMatch(/revoked_at/);
    });

    it('sets revoked_at on the record', async () => {
      const rec = makeRecord();
      await store.createKey(rec);
      await store.revokeKey(rec.prefix);
      const found = await store.getByPrefix(rec.prefix);
      expect(found!.revokedAt).toBeDefined();
    });

    it('does not double-revoke (WHERE revoked_at IS NULL predicate)', async () => {
      const rec = makeRecord();
      await store.createKey(rec);
      await store.revokeKey(rec.prefix);
      const firstRevoke = (await store.getByPrefix(rec.prefix))!.revokedAt;
      await store.revokeKey(rec.prefix);
      const secondRevoke = (await store.getByPrefix(rec.prefix))!.revokedAt;
      // revoked_at must not change after double-revoke
      expect(firstRevoke).toBe(secondRevoke);
    });
  });

  // ── listByTenant ────────────────────────────────────────────────────────────

  describe('listByTenant()', () => {
    it('returns only records for the given tenant', async () => {
      const recA = makeRecord({ tenantId: 'tenant-a' });
      const recB = makeRecord({ tenantId: 'tenant-b' });
      await store.createKey(recA);
      await store.createKey(recB);
      const results = await store.listByTenant('tenant-a');
      expect(results).toHaveLength(1);
      expect(results[0]!.tenantId).toBe('tenant-a');
    });

    it('returns empty array when no records exist for tenant', async () => {
      const results = await store.listByTenant('tenant-nobody');
      expect(results).toHaveLength(0);
    });

    it('returns revoked keys too', async () => {
      const rec = makeRecord({ tenantId: 'tenant-a' });
      await store.createKey(rec);
      await store.revokeKey(rec.prefix);
      const results = await store.listByTenant('tenant-a');
      expect(results).toHaveLength(1);
      expect(results[0]!.revokedAt).toBeDefined();
    });

    it('returns multiple keys in insertion order', async () => {
      const prefixes: string[] = [];
      for (let i = 0; i < 3; i++) {
        const rec = makeRecord({ tenantId: 'tenant-a' });
        await store.createKey(rec);
        prefixes.push(rec.prefix);
      }
      const results = await store.listByTenant('tenant-a');
      expect(results.map(r => r.prefix)).toEqual(prefixes);
    });
  });

  // ── updateCapabilitiesByPolicyId ────────────────────────────────────────────

  describe('updateCapabilitiesByPolicyId()', () => {
    it('updates capabilities on non-revoked keys with matching policy_id', async () => {
      const rec1 = makeRecord({ tenantId: 'tenant-a', policyId: 'policy-x' });
      const rec2 = makeRecord({ tenantId: 'tenant-b', policyId: 'policy-x' });
      await store.createKey(rec1);
      await store.createKey(rec2);

      const newCaps = [{ tool: 'search', allow: true }] as never;
      const count = await store.updateCapabilitiesByPolicyId('policy-x', newCaps);
      expect(count).toBe(2);
    });

    it('does not update revoked keys', async () => {
      const rec = makeRecord({ tenantId: 'tenant-a', policyId: 'policy-y' });
      await store.createKey(rec);
      await store.revokeKey(rec.prefix);

      const count = await store.updateCapabilitiesByPolicyId('policy-y', []);
      expect(count).toBe(0);
    });

    it('returns 0 when no keys match the policy_id', async () => {
      const count = await store.updateCapabilitiesByPolicyId('policy-nonexistent', []);
      expect(count).toBe(0);
    });

    it('issues an UPDATE query', async () => {
      await store.updateCapabilitiesByPolicyId('policy-x', []);
      const updates = pool.queryCalls.filter(q => /^UPDATE/i.test(q.text.trim()));
      expect(updates).toHaveLength(1);
      expect(updates[0]!.text).toMatch(/capabilities/);
      expect(updates[0]!.text).toMatch(/policy_id/);
    });
  });

  // ── Row mapping ─────────────────────────────────────────────────────────────

  describe('row mapping', () => {
    it('converts Date object in created_at to ISO string', async () => {
      const now = new Date();
      const spy = jest.spyOn(pool, 'query').mockImplementationOnce(async () => ({
        rows: [
          {
            prefix: 'sk-datetest',
            key_digest: 'digest',
            hmac_key_version: 'v1',
            tenant_id: 'tenant-a',
            policy_id: 'policy-1',
            capabilities: '[]',
            scopes: ['enforce'],
            label: null,
            created_at: now,
            last_used_at: null,
            expires_at: null,
            revoked_at: null,
          },
        ],
      }));

      const result = await store.getByPrefix('sk-datetest');
      spy.mockRestore();

      expect(result).toBeDefined();
      expect(typeof result!.createdAt).toBe('string');
      expect(result!.createdAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    });

    it('parses capabilities from a JSON string (JSONB text mode)', async () => {
      const caps = [{ tool: 'bash', allow: true }];
      const spy = jest.spyOn(pool, 'query').mockImplementationOnce(async () => ({
        rows: [
          {
            prefix: 'sk-captest',
            key_digest: 'digest',
            hmac_key_version: 'v1',
            tenant_id: 'tenant-a',
            policy_id: 'policy-1',
            capabilities: JSON.stringify(caps),
            scopes: ['enforce'],
            label: null,
            created_at: new Date().toISOString(),
            last_used_at: null,
            expires_at: null,
            revoked_at: null,
          },
        ],
      }));

      const result = await store.getByPrefix('sk-captest');
      spy.mockRestore();

      expect(result!.capabilities).toEqual(caps);
    });

    it('parses capabilities from an array (JSONB binary mode)', async () => {
      const caps = [{ tool: 'read', allow: false }];
      const spy = jest.spyOn(pool, 'query').mockImplementationOnce(async () => ({
        rows: [
          {
            prefix: 'sk-caparray',
            key_digest: 'digest',
            hmac_key_version: 'v1',
            tenant_id: 'tenant-a',
            policy_id: 'policy-1',
            capabilities: caps,
            scopes: ['enforce'],
            label: null,
            created_at: new Date().toISOString(),
            last_used_at: null,
            expires_at: null,
            revoked_at: null,
          },
        ],
      }));

      const result = await store.getByPrefix('sk-caparray');
      spy.mockRestore();

      expect(result!.capabilities).toEqual(caps);
    });

    it('returns undefined for optional fields when null in DB', async () => {
      const rec = makeRecord({ label: undefined, expiresAt: undefined });
      await store.createKey(rec);
      const found = await store.getByPrefix(rec.prefix);
      expect(found!.label).toBeUndefined();
      expect(found!.expiresAt).toBeUndefined();
      expect(found!.lastUsedAt).toBeUndefined();
      expect(found!.revokedAt).toBeUndefined();
    });
  });
});
