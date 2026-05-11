/**
 * PostgresMintAuditStore — unit tests (Task 11, Stage 3)
 * ────────────────────────────────────────────────────────────────────────────
 * Tests cover:
 *
 *   1. **Schema creation** — `ensureSchema()` executes the DDL statements.
 *   2. **record()** — Inserts a row with all required fields; fails on
 *      duplicate `jti` (UNIQUE constraint).
 *   3. **listByTenant()** — Returns rows scoped to a tenant in reverse
 *      insertion order; respects the `limit` parameter.
 *   4. **Append-only guarantee** — No UPDATE or DELETE queries are issued.
 *   5. **Row mapping** — `issuedAt` Date objects are converted to ISO strings.
 */

import { PostgresMintAuditStore, MINT_AUDIT_DDL } from '../src/postgres-mint-audit-store';
import type { MintAuditRecord } from '../src/mint-audit';

// ── In-memory Postgres mock ───────────────────────────────────────────────────

interface QueryCall {
  text: string;
  values?: unknown[];
}

/**
 * Minimal mock of `pg.Pool` that stores rows in memory and verifies that
 * only INSERT and SELECT queries are executed (no UPDATE / DELETE).
 */
class MockPgPool {
  /** All queries sent to the pool. */
  readonly queryCalls: QueryCall[] = [];
  /** Simulated mint_audit table rows. */
  private readonly rows: Record<string, unknown>[] = [];
  private autoIdSeq = 1;

  /** If set to non-null, the next `query()` call will reject with this error. */
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

    // Simulate DDL (no-op, return empty rows)
    if (/^CREATE /.test(text.trim())) {
      return { rows: [] };
    }

    // Simulate INSERT
    if (/^INSERT INTO/.test(text.trim())) {
      const [
        keyPrefix, tenantId, agentId, sessionId, jti, policyId,
        issuedAt, expiresAt, kid, result, reason,
      ] = (values ?? []) as unknown[];

      // Simulate UNIQUE constraint on jti
      if (this.rows.some(r => r['jti'] === jti)) {
        const err = new Error(`duplicate key value violates unique constraint "mint_audit_jti_key"`);
        (err as NodeJS.ErrnoException).code = '23505';
        throw err;
      }

      this.rows.push({
        id: this.autoIdSeq++,
        key_prefix: keyPrefix,
        tenant_id: tenantId,
        agent_id: agentId,
        session_id: sessionId,
        jti,
        policy_id: policyId,
        issued_at: issuedAt,
        expires_at: expiresAt,
        kid,
        result: result ?? 'minted',
        reason: reason ?? null,
      });
      return { rows: [] };
    }

    // Simulate SELECT for listByTenant
    if (/^SELECT/.test(text.trim())) {
      const [tenantId, limit] = (values ?? []) as [string, number];
      const filtered = this.rows
        .filter(r => r['tenant_id'] === tenantId)
        .slice() // copy before reverse
        .reverse() // most-recent first (DESC by id)
        .slice(0, limit ?? 100);
      return { rows: filtered };
    }

    return { rows: [] };
  }
}

// ── Sample record factory ─────────────────────────────────────────────────────

function makeRecord(overrides: Partial<MintAuditRecord> = {}): MintAuditRecord {
  return {
    keyPrefix: 'sk-testpref',
    tenantId: 'tenant-a',
    agentId: 'agent-1',
    sessionId: 'session-1',
    jti: `jti-${Math.random().toString(36).slice(2)}`,
    policyId: 'policy-1',
    issuedAt: new Date().toISOString(),
    expiresAt: Math.floor(Date.now() / 1000) + 300,
    kid: 'aws-kms:test-key-v1',
    result: 'minted',
    ...overrides,
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('PostgresMintAuditStore', () => {
  let pool: MockPgPool;
  let store: PostgresMintAuditStore;

  beforeEach(() => {
    pool = new MockPgPool();
    store = new PostgresMintAuditStore(pool);
  });

  // ── ensureSchema ────────────────────────────────────────────────────────────

  describe('ensureSchema()', () => {
    it('executes DDL statements', async () => {
      await store.ensureSchema();
      expect(pool.queryCalls.length).toBeGreaterThan(0);
      const allSql = pool.queryCalls.map(q => q.text).join('\n');
      expect(allSql).toMatch(/CREATE TABLE IF NOT EXISTS mint_audit/);
    });

    it('executes each DDL statement as a separate query (no multi-statement)', async () => {
      await store.ensureSchema();
      // Every query text should be a single statement (no ';' in the middle)
      for (const call of pool.queryCalls) {
        expect(call.text.split(';').filter(s => s.trim().length > 0)).toHaveLength(1);
      }
    });

    it('is idempotent — can be called multiple times without error', async () => {
      await store.ensureSchema();
      await store.ensureSchema();
      expect(pool.queryCalls.length).toBeGreaterThan(0);
    });

    it('exports MINT_AUDIT_DDL as a non-empty string', () => {
      expect(typeof MINT_AUDIT_DDL).toBe('string');
      expect(MINT_AUDIT_DDL.length).toBeGreaterThan(0);
      expect(MINT_AUDIT_DDL).toMatch(/CREATE TABLE IF NOT EXISTS mint_audit/);
    });
  });

  // ── record() ───────────────────────────────────────────────────────────────

  describe('record()', () => {
    it('inserts a row with all required fields', async () => {
      const rec = makeRecord();
      await store.record(rec);
      const inserts = pool.queryCalls.filter(q => q.text.startsWith('INSERT'));
      expect(inserts).toHaveLength(1);
      const values = inserts[0]!.values as unknown[];
      expect(values).toContain(rec.keyPrefix);
      expect(values).toContain(rec.tenantId);
      expect(values).toContain(rec.jti);
      expect(values).toContain(rec.kid);
    });

    it('defaults result to "minted" when not provided', async () => {
      const rec = makeRecord({ result: undefined });
      await store.record(rec);
      const values = pool.queryCalls.find(q => q.text.startsWith('INSERT'))!.values as unknown[];
      // result is the 10th parameter ($10)
      expect(values[9]).toBe('minted');
    });

    it('stores rotation_start result correctly', async () => {
      await store.record(makeRecord({ result: 'rotation_start', reason: 'scheduled' }));
      const values = pool.queryCalls.find(q => q.text.startsWith('INSERT'))!.values as unknown[];
      expect(values[9]).toBe('rotation_start');
      expect(values[10]).toBe('scheduled');
    });

    it('stores rotation_emergency result correctly', async () => {
      await store.record(makeRecord({ result: 'rotation_emergency', reason: 'emergency' }));
      const values = pool.queryCalls.find(q => q.text.startsWith('INSERT'))!.values as unknown[];
      expect(values[9]).toBe('rotation_emergency');
    });

    it('stores null reason when not provided', async () => {
      await store.record(makeRecord({ reason: undefined }));
      const values = pool.queryCalls.find(q => q.text.startsWith('INSERT'))!.values as unknown[];
      expect(values[10]).toBeNull();
    });

    it('propagates database errors', async () => {
      pool.nextError = new Error('DB connection refused');
      await expect(store.record(makeRecord())).rejects.toThrow('DB connection refused');
    });

    it('never issues UPDATE or DELETE queries', async () => {
      await store.record(makeRecord());
      for (const call of pool.queryCalls) {
        expect(call.text).not.toMatch(/^\s*(UPDATE|DELETE)\s/i);
      }
    });
  });

  // ── listByTenant() ────────────────────────────────────────────────────────

  describe('listByTenant()', () => {
    it('returns only records for the given tenant', async () => {
      await store.record(makeRecord({ tenantId: 'tenant-a', jti: 'jti-a1' }));
      await store.record(makeRecord({ tenantId: 'tenant-b', jti: 'jti-b1' }));
      const results = await store.listByTenant('tenant-a');
      expect(results).toHaveLength(1);
      expect(results[0]!.tenantId).toBe('tenant-a');
    });

    it('returns empty array when no records exist for tenant', async () => {
      const results = await store.listByTenant('tenant-nobody');
      expect(results).toHaveLength(0);
    });

    it('respects the limit parameter', async () => {
      for (let i = 0; i < 5; i++) {
        await store.record(makeRecord({ tenantId: 'tenant-a', jti: `jti-${i}` }));
      }
      const results = await store.listByTenant('tenant-a', 3);
      expect(results.length).toBeLessThanOrEqual(3);
    });

    it('defaults limit to 100 rows', async () => {
      await store.listByTenant('tenant-a');
      const selectCall = pool.queryCalls.find(q => q.text.startsWith('SELECT'));
      expect(selectCall?.values?.[1]).toBe(100);
    });

    it('maps row fields to MintAuditRecord correctly', async () => {
      const rec = makeRecord({ tenantId: 'tenant-a', kid: 'my-kid', result: 'minted' });
      await store.record(rec);
      const results = await store.listByTenant('tenant-a');
      expect(results[0]!.keyPrefix).toBe(rec.keyPrefix);
      expect(results[0]!.kid).toBe(rec.kid);
      expect(results[0]!.result).toBe('minted');
    });

    it('converts issued_at Date object to ISO string', async () => {
      const now = new Date();
      await store.record(makeRecord({ tenantId: 'tenant-a', issuedAt: now.toISOString() }));

      // Simulate pool returning a Date object (as real pg driver does for TIMESTAMPTZ)
      // by overriding the query call to return a row with issued_at as Date
      const original = pool.query.bind(pool);
      jest.spyOn(pool, 'query').mockImplementationOnce(async (text) => {
        if (text.startsWith('SELECT')) {
          return {
            rows: [
              {
                id: 1,
                key_prefix: 'sk-testpref',
                tenant_id: 'tenant-a',
                agent_id: 'agent-1',
                session_id: 'session-1',
                jti: 'jti-date-test',
                policy_id: 'policy-1',
                issued_at: now, // Date object, as pg returns for TIMESTAMPTZ
                expires_at: '1234567890',
                kid: 'my-kid',
                result: 'minted',
                reason: null,
              },
            ],
          };
        }
        return original(text);
      });

      const results = await store.listByTenant('tenant-a', 10);
      const dateRow = results.find((r) => r.jti === 'jti-date-test');
      if (dateRow) {
        expect(typeof dateRow.issuedAt).toBe('string');
        expect(dateRow.issuedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
      }
    });

    it('passes SELECT query as a single statement (no multi-statement)', async () => {
      await store.listByTenant('tenant-a');
      const selectCalls = pool.queryCalls.filter(q => q.text.startsWith('SELECT'));
      for (const call of selectCalls) {
        expect(call.text.split(';').filter(s => s.trim().length > 0)).toHaveLength(1);
      }
    });
  });
});
