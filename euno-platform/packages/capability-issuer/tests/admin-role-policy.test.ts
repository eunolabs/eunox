/**
 * Integration tests for the admin role-policy routes (Task 3).
 *
 * Tests cover:
 *
 *   1. Unauthenticated / wrong credentials → 401
 *   2. X-Admin-Key shared-secret authentication → 200
 *   3. Invalid policy body → 400
 *   4. Successful PUT: persists to store, calls onPolicyUpdated, returns 200
 *   5. Successful GET: returns current policy
 *   6. Hot-reload: PUT updates the policy visible via getCurrentPolicy()
 *   7. OCSF-shape audit log entry emitted on successful PUT (mirrors mintTotal audit pattern)
 *   8. JWT primary auth path: valid JWT → 200, invalid JWT → 401
 *   9. Deprecated X-Admin-Key path logs a deprecation warning when JWT verifier is configured
 */

import express, { Request, Response, NextFunction } from 'express';
import request from 'supertest';
import { createAdminRolePolicyRouter } from '../src/routes/admin-role-policy';
import { PostgresRolePolicyStore, RolePolicyPgPool } from '../src/postgres-role-policy-store';
import { RoleCapabilityPolicy } from '@euno/common';
import { AdminJwtVerifier } from '../src/admin-jwt-verifier';

// ── Fixtures ─────────────────────────────────────────────────────────────────

const VALID_POLICY: RoleCapabilityPolicy = {
  default: {
    'Agent.ReadWrite.All': [
      { resource: 'api://agent-service/**', actions: ['read', 'write'] },
    ],
    'Agent.Read.All': [
      { resource: 'api://agent-service/**', actions: ['read'] },
    ],
  },
};

const UPDATED_POLICY: RoleCapabilityPolicy = {
  default: {
    'Agent.ReadWrite.All': [
      { resource: 'api://agent-service/**', actions: ['read', 'write', 'execute'] },
    ],
    'Agent.Admin': [
      { resource: 'api://agent-service/**', actions: ['read', 'write', 'delete'] },
    ],
  },
};

const ADMIN_API_KEY = 'super-secret-test-admin-key-32-chars-minimum';

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeFakePool(rows: { id: number; policy_json: unknown; operator_id: string; created_at: Date }[] = []): RolePolicyPgPool {
  let nextId = rows.length + 1;
  return {
    async query(text: string, values?: unknown[]) {
      const t = text.trim().toUpperCase();
      if (t.startsWith('CREATE TABLE') || t.startsWith('CREATE INDEX')) {
        return { rows: [] };
      }
      if (t.startsWith('SELECT')) {
        const sorted = [...rows].sort((a, b) => b.id - a.id);
        return { rows: sorted.slice(0, 1) as Record<string, unknown>[] };
      }
      if (t.startsWith('INSERT')) {
        const id = nextId++;
        const [policyJson, operatorId] = values as [string, string];
        rows.push({ id, policy_json: JSON.parse(policyJson), operator_id: operatorId, created_at: new Date() });
        return { rows: [{ id } as Record<string, unknown>] };
      }
      return { rows: [] };
    },
  };
}

function makeApp(overrides: {
  jwtVerifier?: AdminJwtVerifier;
  policyStore?: PostgresRolePolicyStore;
  onPolicyUpdated?: jest.Mock;
  initialPolicy?: RoleCapabilityPolicy;
  logger?: ReturnType<typeof makeLogger>;
} = {}) {
  let currentPolicy: RoleCapabilityPolicy = overrides.initialPolicy ?? VALID_POLICY;
  const policyUpdated = overrides.onPolicyUpdated ?? jest.fn((p, _op) => { currentPolicy = p; });
  const logger = overrides.logger ?? makeLogger();

  const app = express();
  app.use(express.json());
  app.use(
    createAdminRolePolicyRouter({
      adminApiKey: ADMIN_API_KEY,
      jwtVerifier: overrides.jwtVerifier,
      getPolicyStore: () => overrides.policyStore,
      onPolicyUpdated: policyUpdated,
      getCurrentPolicy: () => currentPolicy,
      logger,
    }),
  );
  // Error handler
  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    const status = (err as { statusCode?: number }).statusCode ?? 500;
    res.status(status).json({ error: { code: (err as { code?: string }).code, message: err.message } });
  });
  return { app, policyUpdated, logger, getCurrentPolicy: () => currentPolicy };
}

function makeLogger() {
  return {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  } as unknown as ReturnType<typeof import('@euno/common').createLogger>;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('Admin role-policy routes (Task 3)', () => {
  // ── Authentication ──────────────────────────────────────────────────────

  describe('Authentication', () => {
    it('PUT /api/v1/admin/role-policy → 401 with no credentials', async () => {
      const { app } = makeApp();
      const res = await request(app).put('/api/v1/admin/role-policy').send(VALID_POLICY);
      expect(res.status).toBe(401);
    });

    it('PUT /api/v1/admin/role-policy → 401 with wrong X-Admin-Key', async () => {
      const { app } = makeApp();
      const res = await request(app)
        .put('/api/v1/admin/role-policy')
        .set('X-Admin-Key', 'wrong-key')
        .send(VALID_POLICY);
      expect(res.status).toBe(401);
    });

    it('GET /api/v1/admin/role-policy → 401 with no credentials', async () => {
      const { app } = makeApp();
      const res = await request(app).get('/api/v1/admin/role-policy');
      expect(res.status).toBe(401);
    });

    it('PUT accepts request with correct X-Admin-Key', async () => {
      const { app } = makeApp();
      const res = await request(app)
        .put('/api/v1/admin/role-policy')
        .set('X-Admin-Key', ADMIN_API_KEY)
        .send(VALID_POLICY);
      expect(res.status).toBe(200);
    });

    it('GET accepts request with correct X-Admin-Key', async () => {
      const { app } = makeApp();
      const res = await request(app)
        .get('/api/v1/admin/role-policy')
        .set('X-Admin-Key', ADMIN_API_KEY);
      expect(res.status).toBe(200);
    });
  });

  // ── PUT /api/v1/admin/role-policy ────────────────────────────────────────

  describe('PUT /api/v1/admin/role-policy', () => {
    it('returns 400 for an invalid policy body', async () => {
      const { app } = makeApp();
      const res = await request(app)
        .put('/api/v1/admin/role-policy')
        .set('X-Admin-Key', ADMIN_API_KEY)
        .send({ notValid: true });
      expect(res.status).toBe(400);
      expect(res.body.error.message).toMatch(/role policy validation failed/i);
    });

    it('returns 400 for empty body', async () => {
      const { app } = makeApp();
      const res = await request(app)
        .put('/api/v1/admin/role-policy')
        .set('X-Admin-Key', ADMIN_API_KEY)
        .send({});
      expect(res.status).toBe(400);
    });

    it('invokes onPolicyUpdated with the new policy', async () => {
      const onPolicyUpdated = jest.fn();
      const { app } = makeApp({ onPolicyUpdated });
      await request(app)
        .put('/api/v1/admin/role-policy')
        .set('X-Admin-Key', ADMIN_API_KEY)
        .send(UPDATED_POLICY);
      expect(onPolicyUpdated).toHaveBeenCalledTimes(1);
      expect(onPolicyUpdated.mock.calls[0][0]).toEqual(UPDATED_POLICY);
    });

    it('sets operatorId to "x-admin-key" when X-Admin-Key is used', async () => {
      const onPolicyUpdated = jest.fn();
      const { app } = makeApp({ onPolicyUpdated });
      await request(app)
        .put('/api/v1/admin/role-policy')
        .set('X-Admin-Key', ADMIN_API_KEY)
        .send(UPDATED_POLICY);
      const operatorId = onPolicyUpdated.mock.calls[0]?.[1] as string;
      expect(operatorId).toBe('x-admin-key');
    });

    it('persists to policyStore.save() when a store is configured', async () => {
      const pool = makeFakePool();
      const policyStore = new PostgresRolePolicyStore(pool);
      const saveSpy = jest.spyOn(policyStore, 'save');
      const { app } = makeApp({ policyStore });
      await request(app)
        .put('/api/v1/admin/role-policy')
        .set('X-Admin-Key', ADMIN_API_KEY)
        .send(UPDATED_POLICY);
      expect(saveSpy).toHaveBeenCalledWith(UPDATED_POLICY, 'x-admin-key');
    });

    it('includes rowId in the response when a store is configured', async () => {
      const pool = makeFakePool();
      const policyStore = new PostgresRolePolicyStore(pool);
      const { app } = makeApp({ policyStore });
      const res = await request(app)
        .put('/api/v1/admin/role-policy')
        .set('X-Admin-Key', ADMIN_API_KEY)
        .send(UPDATED_POLICY);
      expect(res.status).toBe(200);
      expect(typeof res.body.rowId).toBe('number');
    });

    it('does NOT include rowId in the response when no store is configured', async () => {
      const { app } = makeApp({ policyStore: undefined });
      const res = await request(app)
        .put('/api/v1/admin/role-policy')
        .set('X-Admin-Key', ADMIN_API_KEY)
        .send(VALID_POLICY);
      expect(res.status).toBe(200);
      expect(res.body.rowId).toBeUndefined();
    });

    it('returns defaultRoles and tenantOverrides in the response', async () => {
      const { app } = makeApp();
      const policy: RoleCapabilityPolicy = {
        default: {
          RoleA: [{ resource: 'api://svc/a', actions: ['read'] }],
          RoleB: [{ resource: 'api://svc/b', actions: ['write'] }],
        },
        tenants: {
          'tenant-1': {
            AdminRole: [{ resource: 'api://admin/**', actions: ['read', 'write'] }],
          },
        },
      };
      const res = await request(app)
        .put('/api/v1/admin/role-policy')
        .set('X-Admin-Key', ADMIN_API_KEY)
        .send(policy);
      expect(res.status).toBe(200);
      expect(res.body.defaultRoles).toEqual(['RoleA', 'RoleB']);
      expect(res.body.tenantOverrides).toEqual(['tenant-1']);
    });
  });

  // ── GET /api/v1/admin/role-policy ────────────────────────────────────────

  describe('GET /api/v1/admin/role-policy', () => {
    it('returns the current policy as JSON', async () => {
      const { app } = makeApp({ initialPolicy: VALID_POLICY });
      const res = await request(app)
        .get('/api/v1/admin/role-policy')
        .set('X-Admin-Key', ADMIN_API_KEY);
      expect(res.status).toBe(200);
      expect(res.body).toEqual(VALID_POLICY);
    });
  });

  // ── Hot-reload ────────────────────────────────────────────────────────────

  describe('Hot-reload (in-memory policy update)', () => {
    it('GET returns the updated policy after a successful PUT', async () => {
      const { app, getCurrentPolicy } = makeApp({ initialPolicy: VALID_POLICY });

      // PUT a new policy
      await request(app)
        .put('/api/v1/admin/role-policy')
        .set('X-Admin-Key', ADMIN_API_KEY)
        .send(UPDATED_POLICY);

      // GET should reflect the new policy
      const getRes = await request(app)
        .get('/api/v1/admin/role-policy')
        .set('X-Admin-Key', ADMIN_API_KEY);
      expect(getRes.status).toBe(200);
      expect(getRes.body).toEqual(UPDATED_POLICY);

      // The getCurrentPolicy getter should also return the updated policy
      expect(getCurrentPolicy()).toEqual(UPDATED_POLICY);
    });

    it('sequential PUTs each update the active policy', async () => {
      const { app, getCurrentPolicy } = makeApp({ initialPolicy: VALID_POLICY });

      const policy2: RoleCapabilityPolicy = {
        default: { RoleX: [{ resource: 'api://svc/x', actions: ['read'] }] },
      };
      const policy3: RoleCapabilityPolicy = {
        default: { RoleY: [{ resource: 'api://svc/y', actions: ['write'] }] },
      };

      await request(app).put('/api/v1/admin/role-policy').set('X-Admin-Key', ADMIN_API_KEY).send(policy2);
      expect(getCurrentPolicy()).toEqual(policy2);

      await request(app).put('/api/v1/admin/role-policy').set('X-Admin-Key', ADMIN_API_KEY).send(policy3);
      expect(getCurrentPolicy()).toEqual(policy3);
    });
  });

  // ── OCSF authorization audit event ───────────────────────────────────────

  describe('OCSF authorization audit event (mintTotal audit pattern)', () => {
    it('emits an audit log entry on successful PUT', async () => {
      const logger = makeLogger();
      const { app } = makeApp({ logger });

      await request(app)
        .put('/api/v1/admin/role-policy')
        .set('X-Admin-Key', ADMIN_API_KEY)
        .send(VALID_POLICY);

      expect(logger.info).toHaveBeenCalled();

      // Find the audit log call
      const calls = (logger.info as jest.Mock).mock.calls as [string, Record<string, unknown>][];
      const auditCall = calls.find(([msg]) => msg === 'Role policy updated via admin API');
      expect(auditCall).toBeDefined();

      const logEntry = auditCall![1] as Record<string, unknown>;

      // OCSF Authorization event shape: id, timestamp, eventType, agentId, userId, decision
      expect(typeof logEntry['id']).toBe('string');
      expect(typeof logEntry['timestamp']).toBe('string');
      expect(logEntry['eventType']).toBe('issuance');
      expect(logEntry['agentId']).toBe('admin');
      expect(logEntry['decision']).toBe('allow');

      // Operator identity is captured
      const metadata = logEntry['metadata'] as Record<string, unknown>;
      expect(metadata['operation']).toBe('role_policy_update');
      expect(metadata['operator']).toBe('x-admin-key');
    });

    it('audit log entry includes the updated role list', async () => {
      const logger = makeLogger();
      const { app } = makeApp({ logger });

      const policy: RoleCapabilityPolicy = {
        default: {
          RoleAlpha: [{ resource: 'api://svc/alpha', actions: ['read'] }],
          RoleBeta: [{ resource: 'api://svc/beta', actions: ['write'] }],
        },
      };

      await request(app)
        .put('/api/v1/admin/role-policy')
        .set('X-Admin-Key', ADMIN_API_KEY)
        .send(policy);

      const calls = (logger.info as jest.Mock).mock.calls as [string, Record<string, unknown>][];
      const auditCall = calls.find(([msg]) => msg === 'Role policy updated via admin API');
      const metadata = (auditCall![1] as Record<string, unknown>)['metadata'] as Record<string, unknown>;
      expect(metadata['defaultRoles']).toEqual(['RoleAlpha', 'RoleBeta']);
    });

    it('does NOT emit audit log on failed PUT (invalid policy)', async () => {
      const logger = makeLogger();
      const { app } = makeApp({ logger });

      await request(app)
        .put('/api/v1/admin/role-policy')
        .set('X-Admin-Key', ADMIN_API_KEY)
        .send({ invalid: 'data' });

      const calls = (logger.info as jest.Mock).mock.calls as [string, unknown][];
      const auditCall = calls.find(([msg]) => msg === 'Role policy updated via admin API');
      expect(auditCall).toBeUndefined();
    });

    it('does NOT emit audit log on failed authentication', async () => {
      const logger = makeLogger();
      const { app } = makeApp({ logger });

      await request(app)
        .put('/api/v1/admin/role-policy')
        .set('X-Admin-Key', 'wrong-key')
        .send(VALID_POLICY);

      const calls = (logger.info as jest.Mock).mock.calls as [string, unknown][];
      const auditCall = calls.find(([msg]) => msg === 'Role policy updated via admin API');
      expect(auditCall).toBeUndefined();
    });
  });

  // ── JWT primary auth path ──────────────────────────────────────────────

  describe('JWT authentication path', () => {
    it('accepts Bearer JWT when jwtVerifier is configured and JWT is valid', async () => {
      const onPolicyUpdated = jest.fn();
      const jwtVerifier: AdminJwtVerifier = {
        verify: jest.fn().mockResolvedValue({ operatorId: 'jwt-operator@example.com', scopes: [] }),
      } as unknown as AdminJwtVerifier;

      const { app } = makeApp({ jwtVerifier, onPolicyUpdated });
      const res = await request(app)
        .put('/api/v1/admin/role-policy')
        .set('Authorization', 'Bearer valid.jwt.token')
        .send(VALID_POLICY);

      expect(res.status).toBe(200);
      // operatorId from JWT sub claim is used
      expect(onPolicyUpdated.mock.calls[0][1]).toBe('jwt-operator@example.com');
    });

    it('rejects Bearer JWT when jwtVerifier returns an error', async () => {
      const jwtVerifier: AdminJwtVerifier = {
        verify: jest.fn().mockRejectedValue(new Error('Invalid token')),
      } as unknown as AdminJwtVerifier;

      const { app } = makeApp({ jwtVerifier });
      const res = await request(app)
        .put('/api/v1/admin/role-policy')
        .set('Authorization', 'Bearer invalid.jwt.token')
        .send(VALID_POLICY);

      expect(res.status).toBe(401);
    });

    it('falls back to X-Admin-Key when no Bearer header is present (JWT verifier configured)', async () => {
      const jwtVerifier: AdminJwtVerifier = {
        verify: jest.fn().mockRejectedValue(new Error('should not be called')),
      } as unknown as AdminJwtVerifier;

      const { app } = makeApp({ jwtVerifier });
      const res = await request(app)
        .put('/api/v1/admin/role-policy')
        .set('X-Admin-Key', ADMIN_API_KEY)
        .send(VALID_POLICY);

      expect(res.status).toBe(200);
      // jwtVerifier.verify was NOT called (no Bearer header)
      expect((jwtVerifier.verify as jest.Mock)).not.toHaveBeenCalled();
    });

    it('logs a deprecation warning when X-Admin-Key is used with a jwtVerifier configured', async () => {
      const logger = makeLogger();
      const jwtVerifier: AdminJwtVerifier = {
        verify: jest.fn(),
      } as unknown as AdminJwtVerifier;

      const { app } = makeApp({ jwtVerifier, logger });
      await request(app)
        .put('/api/v1/admin/role-policy')
        .set('X-Admin-Key', ADMIN_API_KEY)
        .send(VALID_POLICY);

      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining('deprecated'),
        expect.anything(),
      );
    });
  });
});
