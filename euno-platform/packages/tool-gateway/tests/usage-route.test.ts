/**
 * Tests for the billing usage admin route (Task 17).
 *
 * Covers:
 *  - GET /admin/usage  (all tenants)
 *  - GET /admin/usage?tenantId=<id>  (single tenant)
 *  - POST /admin/usage/reset  (global reset)
 *  - POST /admin/usage/reset  (per-tenant reset via body)
 *
 * These tests wire the usage router directly onto a minimal Express app
 * so they don't need the full gateway machinery.
 */

import express, { Express } from 'express';
import request from 'supertest';
import { InMemoryUsageMeter } from '@euno/common';
import { mountUsageRoutes } from '../src/routes/usage';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

function buildApp(
  meter: InMemoryUsageMeter,
  auditRetentionDays?: number,
): Express {
  const app = express();
  app.use(express.json());
  const router = express.Router();
  mountUsageRoutes(router, { usageMeter: meter, auditRetentionDays });
  app.use('/', router);
  return app;
}

// ---------------------------------------------------------------------------
// GET /usage
// ---------------------------------------------------------------------------

describe('GET /usage', () => {
  it('returns an empty tenant list when no activity has been recorded', async () => {
    const meter = new InMemoryUsageMeter();
    const app = buildApp(meter);

    const res = await request(app).get('/usage');
    expect(res.status).toBe(200);
    expect(res.body.tenants).toEqual([]);
    expect(typeof res.body.snapshotAt).toBe('string');
    expect(new Date(res.body.snapshotAt).toISOString()).toBe(res.body.snapshotAt);
  });

  it('includes auditRetentionDays when configured', async () => {
    const meter = new InMemoryUsageMeter();
    const app = buildApp(meter, 7);

    const res = await request(app).get('/usage');
    expect(res.status).toBe(200);
    expect(res.body.auditRetentionDays).toBe(7);
  });

  it('omits auditRetentionDays when not configured', async () => {
    const meter = new InMemoryUsageMeter();
    const app = buildApp(meter, undefined);

    const res = await request(app).get('/usage');
    expect(res.status).toBe(200);
    expect(res.body).not.toHaveProperty('auditRetentionDays');
  });

  it('returns all tenants sorted by tenantId', async () => {
    const meter = new InMemoryUsageMeter();
    meter.recordEnforcement('zztenant', 'allow');
    meter.recordEnforcement('aatenant', 'deny');
    meter.recordEnforcement('mmtenant', 'allow');

    const app = buildApp(meter);
    const res = await request(app).get('/usage');

    expect(res.status).toBe(200);
    const ids = res.body.tenants.map((t: { tenantId: string }) => t.tenantId);
    expect(ids).toEqual(['aatenant', 'mmtenant', 'zztenant']);
  });

  it('returns correct counters for each tenant', async () => {
    const meter = new InMemoryUsageMeter();
    meter.recordEnforcement('t1', 'allow');
    meter.recordEnforcement('t1', 'allow');
    meter.recordEnforcement('t1', 'deny');
    meter.recordKillSwitchInvocation('t1');

    const app = buildApp(meter);
    const res = await request(app).get('/usage');

    expect(res.status).toBe(200);
    const t1 = res.body.tenants.find((t: { tenantId: string }) => t.tenantId === 't1');
    expect(t1).toBeDefined();
    expect(t1.enforcementEvents).toBe(3);
    expect(t1.allowDecisions).toBe(2);
    expect(t1.denyDecisions).toBe(1);
    expect(t1.killSwitchInvocations).toBe(1);
    expect(typeof t1.periodStart).toBe('string');
  });

  it('does not include tenants that only appear in getUsage (never recorded)', async () => {
    const meter = new InMemoryUsageMeter();
    // Calling getUsage for an unknown tenant must NOT create a store entry.
    meter.getUsage('phantom');

    const app = buildApp(meter);
    const res = await request(app).get('/usage');

    expect(res.body.tenants).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// GET /usage?tenantId=<id>
// ---------------------------------------------------------------------------

describe('GET /usage?tenantId', () => {
  it('returns a single-element tenants array for a known tenant', async () => {
    const meter = new InMemoryUsageMeter();
    meter.recordEnforcement('acme', 'allow');
    meter.recordEnforcement('other', 'deny');

    const app = buildApp(meter);
    const res = await request(app).get('/usage?tenantId=acme');

    expect(res.status).toBe(200);
    expect(res.body.tenants).toHaveLength(1);
    expect(res.body.tenants[0].tenantId).toBe('acme');
    expect(res.body.tenants[0].allowDecisions).toBe(1);
  });

  it('returns a zero-count snapshot for an unknown tenant', async () => {
    const meter = new InMemoryUsageMeter();
    const app = buildApp(meter);

    const res = await request(app).get('/usage?tenantId=unknown');

    expect(res.status).toBe(200);
    expect(res.body.tenants).toHaveLength(1);
    expect(res.body.tenants[0].tenantId).toBe('unknown');
    expect(res.body.tenants[0].enforcementEvents).toBe(0);
  });

  it('ignores empty tenantId query param and returns all tenants', async () => {
    const meter = new InMemoryUsageMeter();
    meter.recordEnforcement('t1', 'allow');

    const app = buildApp(meter);
    const res = await request(app).get('/usage?tenantId=');

    expect(res.status).toBe(200);
    expect(res.body.tenants).toHaveLength(1);
  });

  it('treats whitespace-only tenantId as absent and returns all tenants', async () => {
    const meter = new InMemoryUsageMeter();
    meter.recordEnforcement('t1', 'allow');

    const app = buildApp(meter);
    const res = await request(app).get('/usage?tenantId=   ');

    expect(res.status).toBe(200);
    // Whitespace-only should not be treated as a valid tenantId filter.
    expect(res.body.tenants).toHaveLength(1);
    expect(res.body.tenants[0].tenantId).toBe('t1');
  });
});

// ---------------------------------------------------------------------------
// POST /usage/reset
// ---------------------------------------------------------------------------

describe('POST /usage/reset', () => {
  it('resets all tenants when no body is provided', async () => {
    const meter = new InMemoryUsageMeter();
    meter.recordEnforcement('t1', 'allow');
    meter.recordEnforcement('t2', 'deny');

    const app = buildApp(meter);
    const res = await request(app).post('/usage/reset').send({});

    expect(res.status).toBe(200);
    expect(res.body.message).toMatch(/all tenants/i);
    expect(typeof res.body.resetAt).toBe('string');
    expect(res.body).not.toHaveProperty('tenantId');

    // Verify counters are actually reset.
    const snap1 = meter.getUsage('t1');
    const snap2 = meter.getUsage('t2');
    expect(snap1.enforcementEvents).toBe(0);
    expect(snap2.enforcementEvents).toBe(0);
  });

  it('resets only the specified tenant when tenantId body field is set', async () => {
    const meter = new InMemoryUsageMeter();
    meter.recordEnforcement('t1', 'allow');
    meter.recordEnforcement('t2', 'deny');

    const app = buildApp(meter);
    const res = await request(app)
      .post('/usage/reset')
      .send({ tenantId: 't1' });

    expect(res.status).toBe(200);
    expect(res.body.tenantId).toBe('t1');
    expect(res.body.message).toContain('t1');

    expect(meter.getUsage('t1').enforcementEvents).toBe(0);
    expect(meter.getUsage('t2').enforcementEvents).toBe(1);
  });

  it('ignores empty tenantId body field and resets all tenants', async () => {
    const meter = new InMemoryUsageMeter();
    meter.recordEnforcement('t1', 'allow');

    const app = buildApp(meter);
    const res = await request(app)
      .post('/usage/reset')
      .send({ tenantId: '' });

    expect(res.status).toBe(200);
    expect(res.body.message).toMatch(/all tenants/i);
    expect(meter.getUsage('t1').enforcementEvents).toBe(0);
  });

  it('is idempotent for a tenantId that has never been seen', async () => {
    const meter = new InMemoryUsageMeter();
    const app = buildApp(meter);

    const res = await request(app)
      .post('/usage/reset')
      .send({ tenantId: 'nonexistent' });

    expect(res.status).toBe(200);
  });

  it('returns a valid ISO-8601 resetAt timestamp', async () => {
    const meter = new InMemoryUsageMeter();
    const app = buildApp(meter);
    const res = await request(app).post('/usage/reset').send({});

    expect(new Date(res.body.resetAt).toISOString()).toBe(res.body.resetAt);
  });
});

// ---------------------------------------------------------------------------
// Task 10 — issuance/renewal counters in API response; PII stripping
// ---------------------------------------------------------------------------

describe('GET /usage — issuance and renewal counters (Task 10)', () => {
  it('includes issuanceEvents and renewalEvents in the tenant snapshot', async () => {
    const meter = new InMemoryUsageMeter();
    meter.recordIssuance('t1', 'alice@corp.com');
    meter.recordIssuance('t1', 'bob@corp.com');
    meter.recordRenewal('t1', 'alice@corp.com');

    const app = buildApp(meter);
    const res = await request(app).get('/usage');

    expect(res.status).toBe(200);
    const t1 = res.body.tenants.find((t: { tenantId: string }) => t.tenantId === 't1');
    expect(t1.issuanceEvents).toBe(2);
    expect(t1.renewalEvents).toBe(1);
  });

  it('does NOT expose issuancesByUser in the API response (PII stripping)', async () => {
    const meter = new InMemoryUsageMeter();
    meter.recordIssuance('t1', 'alice@corp.com');

    const app = buildApp(meter);
    const res = await request(app).get('/usage');

    const t1 = res.body.tenants.find((t: { tenantId: string }) => t.tenantId === 't1');
    expect(t1).not.toHaveProperty('issuancesByUser');
  });

  it('does NOT expose renewalsByUser in the API response (PII stripping)', async () => {
    const meter = new InMemoryUsageMeter();
    meter.recordRenewal('t1', 'alice@corp.com');

    const app = buildApp(meter);
    const res = await request(app).get('/usage');

    const t1 = res.body.tenants.find((t: { tenantId: string }) => t.tenantId === 't1');
    expect(t1).not.toHaveProperty('renewalsByUser');
  });

  it('does NOT expose per-user fields for the ?tenantId= targeted query either', async () => {
    const meter = new InMemoryUsageMeter();
    meter.recordIssuance('acme', 'alice@corp.com');
    meter.recordRenewal('acme', 'bob@corp.com');

    const app = buildApp(meter);
    const res = await request(app).get('/usage?tenantId=acme');

    expect(res.status).toBe(200);
    const snap = res.body.tenants[0];
    expect(snap.issuanceEvents).toBe(1);
    expect(snap.renewalEvents).toBe(1);
    expect(snap).not.toHaveProperty('issuancesByUser');
    expect(snap).not.toHaveProperty('renewalsByUser');
  });
});
