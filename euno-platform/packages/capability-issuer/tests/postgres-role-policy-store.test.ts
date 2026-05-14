/**
 * Unit tests for PostgresRolePolicyStore (Task 3 — Stage 4 production hardening).
 *
 * These tests verify that the store correctly:
 *   - Creates the schema (DDL idempotency)
 *   - Persists and retrieves role-capability policies
 *   - Returns null when the table is empty
 *   - Validates the policy before saving
 *   - Handles the `created_at` field as both a Date and a string
 */

import { PostgresRolePolicyStore, RolePolicyPgPool, ROLE_POLICY_DDL } from '../src/postgres-role-policy-store';
import { RoleCapabilityPolicy } from '@euno/common';

// ── Minimal in-memory fake pool ─────────────────────────────────────────────

interface StoredRow {
  id: number;
  policy_json: unknown;
  operator_id: string;
  created_at: Date;
}

/**
 * Lightweight in-memory Postgres pool fake.  Supports the three query
 * patterns used by PostgresRolePolicyStore: DDL statements, SELECT, and
 * INSERT RETURNING.
 *
 * The DDL branch accepts multi-statement strings (the real `pg` client
 * uses the simple query protocol for parameter-free calls, which supports
 * multiple statements in one call — matching the `ensureSchema()` approach).
 */
function makeFakePool(rows: StoredRow[] = []): RolePolicyPgPool & { rows: StoredRow[]; insertCount: number } {
  let nextId = rows.length + 1;
  let insertCount = 0;
  return {
    rows,
    get insertCount() { return insertCount; },
    async query(text: string, values?: unknown[]) {
      const t = text.trim().toUpperCase();

      // ── DDL (CREATE TABLE / INDEX — may be a multi-statement string) ──
      if (t.includes('CREATE TABLE') || t.includes('CREATE INDEX')) {
        return { rows: [] };
      }

      // ── SELECT (loadLatest) ────────────────────────────────────────
      if (t.startsWith('SELECT')) {
        const sorted = [...rows].sort((a, b) => b.id - a.id);
        return { rows: sorted.slice(0, 1) as unknown as Record<string, unknown>[] };
      }

      // ── INSERT … RETURNING (save) ──────────────────────────────────
      if (t.startsWith('INSERT')) {
        insertCount++;
        const id = nextId++;
        const [policyJson, operatorId] = values as [string, string];
        const row: StoredRow = {
          id,
          policy_json: JSON.parse(policyJson),
          operator_id: operatorId,
          created_at: new Date(),
        };
        rows.push(row);
        return { rows: [{ id } as Record<string, unknown>] };
      }

      return { rows: [] };
    },
  };
}

// ── Fixtures ────────────────────────────────────────────────────────────────

const SIMPLE_POLICY: RoleCapabilityPolicy = {
  default: {
    'Agent.ReadWrite.All': [
      { resource: 'api://agent-service/**', actions: ['read', 'write'] },
    ],
    'Agent.Read.All': [
      { resource: 'api://agent-service/**', actions: ['read'] },
    ],
  },
};

const MULTI_TENANT_POLICY: RoleCapabilityPolicy = {
  default: {
    'Agent.ReadWrite.All': [
      { resource: 'api://agent-service/**', actions: ['read', 'write'] },
    ],
  },
  tenants: {
    'tenant-abc': {
      'Agent.Admin': [
        { resource: 'api://agent-service/**', actions: ['read', 'write', 'delete'] },
      ],
    },
  },
};

// ── Tests ────────────────────────────────────────────────────────────────────

describe('PostgresRolePolicyStore', () => {
  // ── ensureSchema ─────────────────────────────────────────────────────────

  describe('ensureSchema()', () => {
    it('executes all DDL statements without error', async () => {
      const pool = makeFakePool();
      const store = new PostgresRolePolicyStore(pool);
      await expect(store.ensureSchema()).resolves.toBeUndefined();
    });

    it('is idempotent (safe to call multiple times)', async () => {
      const pool = makeFakePool();
      const store = new PostgresRolePolicyStore(pool);
      await store.ensureSchema();
      await expect(store.ensureSchema()).resolves.toBeUndefined();
    });

    it('ROLE_POLICY_DDL export contains CREATE TABLE and CREATE INDEX', () => {
      expect(ROLE_POLICY_DDL).toContain('CREATE TABLE IF NOT EXISTS role_policies');
      expect(ROLE_POLICY_DDL).toContain('policy_json');
      expect(ROLE_POLICY_DDL).toContain('operator_id');
      expect(ROLE_POLICY_DDL).toContain('CREATE INDEX IF NOT EXISTS role_policies_created_idx');
    });
  });

  // ── loadLatest ────────────────────────────────────────────────────────────

  describe('loadLatest()', () => {
    it('returns null when the table is empty', async () => {
      const pool = makeFakePool([]);
      const store = new PostgresRolePolicyStore(pool);
      const result = await store.loadLatest();
      expect(result).toBeNull();
    });

    it('returns the most recently inserted row', async () => {
      const pool = makeFakePool([
        { id: 1, policy_json: SIMPLE_POLICY, operator_id: 'op-1', created_at: new Date('2024-01-01') },
        { id: 2, policy_json: MULTI_TENANT_POLICY, operator_id: 'op-2', created_at: new Date('2024-01-02') },
      ]);
      const store = new PostgresRolePolicyStore(pool);
      const result = await store.loadLatest();
      expect(result).not.toBeNull();
      expect(result!.id).toBe(2);
      expect(result!.operatorId).toBe('op-2');
    });

    it('parses the policy_json field into a RoleCapabilityPolicy', async () => {
      const pool = makeFakePool([
        { id: 1, policy_json: SIMPLE_POLICY, operator_id: 'op-1', created_at: new Date() },
      ]);
      const store = new PostgresRolePolicyStore(pool);
      const result = await store.loadLatest();
      expect(result!.policy).toEqual(SIMPLE_POLICY);
      expect(result!.policy.default['Agent.ReadWrite.All']).toEqual([
        { resource: 'api://agent-service/**', actions: ['read', 'write'] },
      ]);
    });

    it('converts created_at Date to ISO string', async () => {
      const createdAt = new Date('2024-06-15T12:00:00.000Z');
      const pool = makeFakePool([
        { id: 1, policy_json: SIMPLE_POLICY, operator_id: 'op-1', created_at: createdAt },
      ]);
      const store = new PostgresRolePolicyStore(pool);
      const result = await store.loadLatest();
      expect(result!.createdAt).toBe('2024-06-15T12:00:00.000Z');
    });

    it('handles created_at as a raw string (some driver versions)', async () => {
      const pool: RolePolicyPgPool = {
        async query(text) {
          const t = text.trim().toUpperCase();
          if (t.startsWith('SELECT')) {
            return {
              rows: [{
                id: 1,
                policy_json: SIMPLE_POLICY,
                operator_id: 'op-1',
                created_at: '2024-01-01T00:00:00Z',
              }],
            };
          }
          return { rows: [] };
        },
      };
      const store = new PostgresRolePolicyStore(pool);
      const result = await store.loadLatest();
      expect(result!.createdAt).toBe('2024-01-01T00:00:00Z');
    });
  });

  // ── save ──────────────────────────────────────────────────────────────────

  describe('save()', () => {
    it('persists a valid policy and returns a numeric row ID', async () => {
      const pool = makeFakePool();
      const store = new PostgresRolePolicyStore(pool);
      const id = await store.save(SIMPLE_POLICY, 'op-1');
      expect(typeof id).toBe('number');
      expect(id).toBeGreaterThan(0);
    });

    it('stores the policy so loadLatest() returns it', async () => {
      const pool = makeFakePool();
      const store = new PostgresRolePolicyStore(pool);
      await store.save(SIMPLE_POLICY, 'op-1');
      const record = await store.loadLatest();
      expect(record).not.toBeNull();
      expect(record!.policy).toEqual(SIMPLE_POLICY);
      expect(record!.operatorId).toBe('op-1');
    });

    it('persists multiple versions; loadLatest returns the newest', async () => {
      const pool = makeFakePool();
      const store = new PostgresRolePolicyStore(pool);
      await store.save(SIMPLE_POLICY, 'op-1');
      await store.save(MULTI_TENANT_POLICY, 'op-2');
      const record = await store.loadLatest();
      expect(record!.operatorId).toBe('op-2');
      expect(record!.policy).toEqual(MULTI_TENANT_POLICY);
    });

    it('records the operatorId in the persisted row', async () => {
      const pool = makeFakePool();
      const store = new PostgresRolePolicyStore(pool);
      await store.save(SIMPLE_POLICY, 'operator@example.com');
      const record = await store.loadLatest();
      expect(record!.operatorId).toBe('operator@example.com');
    });

    it('throws and does not write when the policy is invalid', async () => {
      const pool = makeFakePool();
      const store = new PostgresRolePolicyStore(pool);
      // An invalid policy (missing `default` key) should throw at save() time
      await expect(
        store.save({ notADefaultKey: {} } as unknown as RoleCapabilityPolicy, 'op-1'),
      ).rejects.toThrow();
      // Validation throws before any INSERT — pool must not have been written to.
      expect(pool.insertCount).toBe(0);
      // Confirm the table is still empty (cross-check via loadLatest).
      const record = await store.loadLatest();
      expect(record).toBeNull();
    });
  });
});
