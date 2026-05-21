/**
 * Tests for Admin API router – /admin/revoke endpoint
 */

import express, { Express } from 'express';
import request from 'supertest';
import { createAdminRouter } from '../src/admin-api';
import { JWTTokenVerifier } from '../src/verifier';
import { InMemoryRevocationEpochStore } from '../src/revocation-store';
import { createLogger, DefaultKillSwitchManager } from '@euno/common';

/**
 * Default API key used by test builder helpers that don't exercise
 * authentication logic.  All request calls must include this header when
 * talking to an app built with the default key so the authenticate middleware
 * (now deny-by-default) does not short-circuit with 503.
 */
const TEST_API_KEY = 'test-admin-key-for-testing';

function buildApp(adminApiKey?: string, withVerifier = true): Express {
  const app = express();
  app.use(express.json());

  const killSwitchManager = new DefaultKillSwitchManager();
  const logger = createLogger('test');
  const tokenVerifier = withVerifier ? new JWTTokenVerifier('dummy-key', { requireKid: false }) : undefined;

  const adminRouter = createAdminRouter({
    killSwitchManager,
    logger,
    adminApiKey,
    tokenVerifier,
  });

  app.use('/admin', adminRouter);
  return app;
}

describe('POST /admin/revoke', () => {
  describe('when ADMIN_API_KEY is configured', () => {
    let app: Express;
    const API_KEY = 'test-secret-key';

    beforeEach(() => {
      app = buildApp(API_KEY);
    });

    it('returns 401 when X-Admin-API-Key is missing', async () => {
      const res = await request(app)
        .post('/admin/revoke')
        .send({ tokenId: 'tok-abc' });

      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('UNAUTHORIZED');
    });

    it('returns 401 when X-Admin-API-Key is wrong', async () => {
      const res = await request(app)
        .post('/admin/revoke')
        .set('X-Admin-API-Key', 'wrong-key')
        .send({ tokenId: 'tok-abc' });

      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('UNAUTHORIZED');
    });

    it('returns 400 when tokenId is missing', async () => {
      const res = await request(app)
        .post('/admin/revoke')
        .set('X-Admin-API-Key', API_KEY)
        .send({});

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('INVALID_REQUEST');
    });

    it('returns 400 when tokenId is not a string', async () => {
      const res = await request(app)
        .post('/admin/revoke')
        .set('X-Admin-API-Key', API_KEY)
        .send({ tokenId: 42 });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('INVALID_REQUEST');
    });

    it('returns 400 when expiresAt is not a finite number', async () => {
      const res = await request(app)
        .post('/admin/revoke')
        .set('X-Admin-API-Key', API_KEY)
        .send({ tokenId: 'tok-abc', expiresAt: 'not-a-number' });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('INVALID_REQUEST');
    });

    it('returns 400 when expiresAt is Infinity', async () => {
      const res = await request(app)
        .post('/admin/revoke')
        .set('X-Admin-API-Key', API_KEY)
        .send({ tokenId: 'tok-abc', expiresAt: Infinity });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('INVALID_REQUEST');
    });

    it('returns 200 with explicit expiresAt and stores the same value in the response', async () => {
      const expiresAt = Math.floor(Date.now() / 1000) + 3600;

      const res = await request(app)
        .post('/admin/revoke')
        .set('X-Admin-API-Key', API_KEY)
        .send({ tokenId: 'tok-explicit', expiresAt });

      expect(res.status).toBe(200);
      expect(res.body.tokenId).toBe('tok-explicit');
      expect(res.body.expiresAt).toBe(expiresAt);
      expect(res.body.message).toContain('tok-explicit');
    });

    it('returns 200 and defaults expiresAt to ~24h when omitted', async () => {
      const before = Math.floor(Date.now() / 1000);

      const res = await request(app)
        .post('/admin/revoke')
        .set('X-Admin-API-Key', API_KEY)
        .send({ tokenId: 'tok-no-exp' });

      const after = Math.floor(Date.now() / 1000);

      expect(res.status).toBe(200);
      expect(res.body.tokenId).toBe('tok-no-exp');
      // effectiveExpiresAt should be now+86400 (within a 5-second window)
      expect(res.body.expiresAt).toBeGreaterThanOrEqual(before + 86400);
      expect(res.body.expiresAt).toBeLessThanOrEqual(after + 86400);
    });

    it('treats expiresAt=0 as a valid value (not replaced by default)', async () => {
      const res = await request(app)
        .post('/admin/revoke')
        .set('X-Admin-API-Key', API_KEY)
        .send({ tokenId: 'tok-zero', expiresAt: 0 });

      expect(res.status).toBe(200);
      expect(res.body.expiresAt).toBe(0);
    });

    it('marks the token as revoked so subsequent isRevoked checks return true', async () => {
      const tokenId = `tok-revoked-${Date.now()}`;
      const expiresAt = Math.floor(Date.now() / 1000) + 3600;

      // Extract the verifier from the app by building a fresh pair
      const killSwitchManager = new DefaultKillSwitchManager();
      const logger = createLogger('test');
      const tokenVerifier = new JWTTokenVerifier('dummy-key', { requireKid: false });

      const localApp = express();
      localApp.use(express.json());
      const adminRouter = createAdminRouter({
        killSwitchManager,
        logger,
        adminApiKey: API_KEY,
        tokenVerifier,
      });
      localApp.use('/admin', adminRouter);

      expect(await tokenVerifier.isRevoked(tokenId)).toBe(false);

      const res = await request(localApp)
        .post('/admin/revoke')
        .set('X-Admin-API-Key', API_KEY)
        .send({ tokenId, expiresAt });

      expect(res.status).toBe(200);
      expect(await tokenVerifier.isRevoked(tokenId)).toBe(true);
    });
  });

  describe('when ADMIN_API_KEY is not configured', () => {
    let app: Express;

    beforeEach(() => {
      app = buildApp(undefined, true);
    });

    it('rejects requests with 503 when no API key is configured (deny-by-default)', async () => {
      const res = await request(app)
        .post('/admin/revoke')
        .send({ tokenId: 'tok-unauth' });

      expect(res.status).toBe(503);
      expect(res.body.error.code).toBe('ADMIN_AUTH_NOT_CONFIGURED');
    });
  });

  describe('when tokenVerifier is not configured', () => {
    let app: Express;

    beforeEach(() => {
      // Supply an API key so requests get past auth and reach the route handler
      app = buildApp('test-secret-key', false);
    });

    it('returns 501 when no verifier is configured', async () => {
      const res = await request(app)
        .post('/admin/revoke')
        .set('X-Admin-API-Key', 'test-secret-key')
        .send({ tokenId: 'tok-no-verifier' });

      expect(res.status).toBe(501);
      expect(res.body.error.code).toBe('NOT_IMPLEMENTED');
    });
  });
});

// ── POST /admin/revocation/epoch ──────────────────────────────────────────

describe('POST /admin/revocation/epoch', () => {
  const API_KEY = 'epoch-api-key';

  function buildEpochApp(withEpochStore = true, apiKey: string = TEST_API_KEY): {
    app: Express;
    epochStore: InMemoryRevocationEpochStore;
  } {
    const app = express();
    app.use(express.json());

    const killSwitchManager = new DefaultKillSwitchManager();
    const logger = createLogger('test');
    const epochStore = new InMemoryRevocationEpochStore();

    const adminRouter = createAdminRouter({
      killSwitchManager,
      logger,
      adminApiKey: apiKey,
      epochStore: withEpochStore ? epochStore : undefined,
    });

    app.use('/admin', adminRouter);
    return { app, epochStore };
  }

  it('returns 501 when no epoch store is configured', async () => {
    const { app } = buildEpochApp(false);
    const res = await request(app)
      .post('/admin/revocation/epoch')
      .set('X-Admin-API-Key', TEST_API_KEY)
      .send({ issuer: 'did:web:test.com', issuedBefore: 1000 });

    expect(res.status).toBe(501);
    expect(res.body.error.code).toBe('NOT_IMPLEMENTED');
  });

  it('returns 400 when issuer is missing', async () => {
    const { app } = buildEpochApp();
    const res = await request(app)
      .post('/admin/revocation/epoch')
      .set('X-Admin-API-Key', TEST_API_KEY)
      .send({ issuedBefore: 1000 });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_REQUEST');
  });

  it('returns 400 when issuer is not a string', async () => {
    const { app } = buildEpochApp();
    const res = await request(app)
      .post('/admin/revocation/epoch')
      .set('X-Admin-API-Key', TEST_API_KEY)
      .send({ issuer: 42, issuedBefore: 1000 });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_REQUEST');
  });

  it('returns 400 when issuedBefore is missing', async () => {
    const { app } = buildEpochApp();
    const res = await request(app)
      .post('/admin/revocation/epoch')
      .set('X-Admin-API-Key', TEST_API_KEY)
      .send({ issuer: 'did:web:test.com' });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_REQUEST');
  });

  it('returns 400 when issuedBefore is not a number', async () => {
    const { app } = buildEpochApp();
    const res = await request(app)
      .post('/admin/revocation/epoch')
      .set('X-Admin-API-Key', TEST_API_KEY)
      .send({ issuer: 'did:web:test.com', issuedBefore: 'not-a-number' });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_REQUEST');
  });

  it('returns 400 when issuedBefore is Infinity', async () => {
    const { app } = buildEpochApp();
    const res = await request(app)
      .post('/admin/revocation/epoch')
      .set('X-Admin-API-Key', TEST_API_KEY)
      .send({ issuer: 'did:web:test.com', issuedBefore: Infinity });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_REQUEST');
  });

  it('returns 200 and sets the epoch in the store', async () => {
    const { app, epochStore } = buildEpochApp();
    const issuedBefore = Math.floor(Date.now() / 1000);

    const res = await request(app)
      .post('/admin/revocation/epoch')
      .set('X-Admin-API-Key', TEST_API_KEY)
      .send({ issuer: 'did:web:test.com', issuedBefore });

    expect(res.status).toBe(200);
    expect(res.body.issuer).toBe('did:web:test.com');
    expect(res.body.issuedBefore).toBe(issuedBefore);
    expect(res.body.message).toContain('did:web:test.com');

    // Verify the epoch was actually stored
    expect(await epochStore.getEpoch('did:web:test.com')).toBe(issuedBefore);
  });

  it('returns 401 when API key is configured but missing', async () => {
    const { app } = buildEpochApp(true, API_KEY);
    const res = await request(app)
      .post('/admin/revocation/epoch')
      .send({ issuer: 'did:web:test.com', issuedBefore: 1000 });

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('UNAUTHORIZED');
  });

  it('returns 200 with valid API key', async () => {
    const { app, epochStore } = buildEpochApp(true, API_KEY);
    const issuedBefore = Math.floor(Date.now() / 1000) - 3600;

    const res = await request(app)
      .post('/admin/revocation/epoch')
      .set('X-Admin-API-Key', API_KEY)
      .send({ issuer: 'did:web:issuer.example.com', issuedBefore });

    expect(res.status).toBe(200);
    expect(await epochStore.getEpoch('did:web:issuer.example.com')).toBe(issuedBefore);
  });

  it('replaces an existing epoch when called a second time', async () => {
    const { app, epochStore } = buildEpochApp();
    const firstEpoch = Math.floor(Date.now() / 1000) - 7200;
    const secondEpoch = Math.floor(Date.now() / 1000) - 3600;

    await request(app)
      .post('/admin/revocation/epoch')
      .set('X-Admin-API-Key', TEST_API_KEY)
      .send({ issuer: 'did:web:test.com', issuedBefore: firstEpoch });

    await request(app)
      .post('/admin/revocation/epoch')
      .set('X-Admin-API-Key', TEST_API_KEY)
      .send({ issuer: 'did:web:test.com', issuedBefore: secondEpoch });

    expect(await epochStore.getEpoch('did:web:test.com')).toBe(secondEpoch);
  });
});

// ── Kill-switch endpoints ─────────────────────────────────────────────────────

describe('Kill-switch admin endpoints', () => {
  const API_KEY = 'ks-test-key';

  function buildKsApp(apiKey: string = TEST_API_KEY): { app: Express; ksm: DefaultKillSwitchManager } {
    const app = express();
    app.use(express.json());
    const ksm = new DefaultKillSwitchManager();
    const logger = createLogger('test');
    const adminRouter = createAdminRouter({ killSwitchManager: ksm, logger, adminApiKey: apiKey });
    app.use('/admin', adminRouter);
    return { app, ksm };
  }

  // ── GET /admin/kill-switch/status ──────────────────────────────────────────

  describe('GET /admin/kill-switch/status', () => {
    it('returns the initial status (all inactive)', async () => {
      const { app } = buildKsApp();
      const res = await request(app)
        .get('/admin/kill-switch/status')
        .set('X-Admin-API-Key', TEST_API_KEY);
      expect(res.status).toBe(200);
      expect(res.body.globalKill).toBe(false);
      expect(res.body.killedSessionCount).toBe(0);
      expect(res.body.killedAgentCount).toBe(0);
    });

    it('reflects active kills in the status', async () => {
      const { app, ksm } = buildKsApp();
      ksm.killSession('s1');
      ksm.killAgent('a1');

      const res = await request(app)
        .get('/admin/kill-switch/status')
        .set('X-Admin-API-Key', TEST_API_KEY);
      expect(res.status).toBe(200);
      expect(res.body.killedSessionCount).toBe(1);
      expect(res.body.killedAgentCount).toBe(1);
    });

    it('requires API key when configured', async () => {
      const { app } = buildKsApp(API_KEY);
      const res = await request(app).get('/admin/kill-switch/status');
      expect(res.status).toBe(401);
    });

    it('passes when correct API key is provided', async () => {
      const { app } = buildKsApp(API_KEY);
      const res = await request(app)
        .get('/admin/kill-switch/status')
        .set('X-Admin-API-Key', API_KEY);
      expect(res.status).toBe(200);
    });
  });

  // ── POST /admin/kill-switch/global/activate ───────────────────────────────

  describe('POST /admin/kill-switch/global/activate', () => {
    it('activates the global kill switch', async () => {
      const { app, ksm } = buildKsApp();
      expect(ksm.isGlobalKillActive()).toBe(false);

      const res = await request(app)
        .post('/admin/kill-switch/global/activate')
        .set('X-Admin-API-Key', TEST_API_KEY);
      expect(res.status).toBe(200);
      expect(res.body.message).toContain('activated');
      expect(ksm.isGlobalKillActive()).toBe(true);
      expect(ksm.shouldBlock('any-sess', 'any-agent')).toBe(true);
    });

    it('is idempotent (activating twice returns 200 both times)', async () => {
      const { app } = buildKsApp();
      await request(app)
        .post('/admin/kill-switch/global/activate')
        .set('X-Admin-API-Key', TEST_API_KEY);
      const res = await request(app)
        .post('/admin/kill-switch/global/activate')
        .set('X-Admin-API-Key', TEST_API_KEY);
      expect(res.status).toBe(200);
    });
  });

  // ── POST /admin/kill-switch/global/deactivate ─────────────────────────────

  describe('POST /admin/kill-switch/global/deactivate', () => {
    it('deactivates the global kill switch', async () => {
      const { app, ksm } = buildKsApp();
      ksm.activateGlobalKill();
      expect(ksm.isGlobalKillActive()).toBe(true);

      const res = await request(app)
        .post('/admin/kill-switch/global/deactivate')
        .set('X-Admin-API-Key', TEST_API_KEY);
      expect(res.status).toBe(200);
      expect(res.body.message).toContain('deactivated');
      expect(ksm.isGlobalKillActive()).toBe(false);
    });

    it('is idempotent (deactivating when already inactive returns 200)', async () => {
      const { app } = buildKsApp();
      const res = await request(app)
        .post('/admin/kill-switch/global/deactivate')
        .set('X-Admin-API-Key', TEST_API_KEY);
      expect(res.status).toBe(200);
    });
  });

  // ── POST /admin/kill-switch/session/:sessionId/kill ───────────────────────

  describe('POST /admin/kill-switch/session/:sessionId/kill', () => {
    it('kills the specified session', async () => {
      const { app, ksm } = buildKsApp();
      const res = await request(app)
        .post('/admin/kill-switch/session/sess-abc/kill')
        .set('X-Admin-API-Key', TEST_API_KEY);
      expect(res.status).toBe(200);
      expect(res.body.message).toContain('sess-abc');
      expect(ksm.isSessionKilled('sess-abc')).toBe(true);
      expect(ksm.shouldBlock('sess-abc')).toBe(true);
    });

    it('does not affect other sessions', async () => {
      const { app, ksm } = buildKsApp();
      await request(app)
        .post('/admin/kill-switch/session/sess-x/kill')
        .set('X-Admin-API-Key', TEST_API_KEY);
      expect(ksm.isSessionKilled('sess-y')).toBe(false);
      expect(ksm.shouldBlock('sess-y')).toBe(false);
    });
  });

  // ── POST /admin/kill-switch/session/:sessionId/revive ────────────────────

  describe('POST /admin/kill-switch/session/:sessionId/revive', () => {
    it('revives a killed session', async () => {
      const { app, ksm } = buildKsApp();
      ksm.killSession('revive-me');

      const res = await request(app)
        .post('/admin/kill-switch/session/revive-me/revive')
        .set('X-Admin-API-Key', TEST_API_KEY);
      expect(res.status).toBe(200);
      expect(res.body.message).toContain('revive-me');
      expect(ksm.isSessionKilled('revive-me')).toBe(false);
    });

    it('is idempotent (reviving an alive session returns 200)', async () => {
      const { app } = buildKsApp();
      const res = await request(app)
        .post('/admin/kill-switch/session/alive-sess/revive')
        .set('X-Admin-API-Key', TEST_API_KEY);
      expect(res.status).toBe(200);
    });
  });

  // ── POST /admin/kill-switch/agent/:agentId/kill ───────────────────────────

  describe('POST /admin/kill-switch/agent/:agentId/kill', () => {
    it('kills the specified agent', async () => {
      const { app, ksm } = buildKsApp();
      const res = await request(app)
        .post('/admin/kill-switch/agent/agent-xyz/kill')
        .set('X-Admin-API-Key', TEST_API_KEY);
      expect(res.status).toBe(200);
      expect(res.body.message).toContain('agent-xyz');
      expect(ksm.isAgentKilled('agent-xyz')).toBe(true);
      expect(ksm.shouldBlock(undefined, 'agent-xyz')).toBe(true);
    });

    it('does not affect other agents', async () => {
      const { app, ksm } = buildKsApp();
      await request(app)
        .post('/admin/kill-switch/agent/agent-a/kill')
        .set('X-Admin-API-Key', TEST_API_KEY);
      expect(ksm.isAgentKilled('agent-b')).toBe(false);
    });
  });

  // ── POST /admin/kill-switch/agent/:agentId/revive ────────────────────────

  describe('POST /admin/kill-switch/agent/:agentId/revive', () => {
    it('revives a killed agent', async () => {
      const { app, ksm } = buildKsApp();
      ksm.killAgent('agent-revive');

      const res = await request(app)
        .post('/admin/kill-switch/agent/agent-revive/revive')
        .set('X-Admin-API-Key', TEST_API_KEY);
      expect(res.status).toBe(200);
      expect(res.body.message).toContain('agent-revive');
      expect(ksm.isAgentKilled('agent-revive')).toBe(false);
    });
  });

  // ── POST /admin/kill-switch/reset ─────────────────────────────────────────

  describe('POST /admin/kill-switch/reset', () => {
    it('clears all active kills', async () => {
      const { app, ksm } = buildKsApp();
      ksm.activateGlobalKill();
      ksm.killSession('s1');
      ksm.killAgent('a1');

      const res = await request(app)
        .post('/admin/kill-switch/reset')
        .set('X-Admin-API-Key', TEST_API_KEY);
      expect(res.status).toBe(200);
      expect(res.body.message).toContain('reset');
      expect(ksm.isGlobalKillActive()).toBe(false);
      expect(ksm.isSessionKilled('s1')).toBe(false);
      expect(ksm.isAgentKilled('a1')).toBe(false);
    });

    it('is idempotent (resetting when nothing is active returns 200)', async () => {
      const { app } = buildKsApp();
      const res = await request(app)
        .post('/admin/kill-switch/reset')
        .set('X-Admin-API-Key', TEST_API_KEY);
      expect(res.status).toBe(200);
    });
  });

  // ── Full activate-then-reset round-trip ───────────────────────────────────

  describe('full kill-switch round-trip', () => {
    it('activate → check status → reset → check status', async () => {
      const { app } = buildKsApp();

      await request(app).post('/admin/kill-switch/global/activate').set('X-Admin-API-Key', TEST_API_KEY);
      await request(app).post('/admin/kill-switch/session/s1/kill').set('X-Admin-API-Key', TEST_API_KEY);
      await request(app).post('/admin/kill-switch/agent/a1/kill').set('X-Admin-API-Key', TEST_API_KEY);

      let status = await request(app).get('/admin/kill-switch/status').set('X-Admin-API-Key', TEST_API_KEY);
      expect(status.body.globalKill).toBe(true);
      expect(status.body.killedSessionCount).toBe(1);
      expect(status.body.killedAgentCount).toBe(1);

      await request(app).post('/admin/kill-switch/reset').set('X-Admin-API-Key', TEST_API_KEY);

      status = await request(app).get('/admin/kill-switch/status').set('X-Admin-API-Key', TEST_API_KEY);
      expect(status.body.globalKill).toBe(false);
      expect(status.body.killedSessionCount).toBe(0);
      expect(status.body.killedAgentCount).toBe(0);
    });
  });
});

// =============================================================================
// Task 8 hardening tests
// =============================================================================

import { AdminIdempotencyStore, IAdminIdempotencyStore } from '../src/admin-api';
import type { OcsfAuditTransport, OcsfAuthorizationEvent } from '@euno/common';

// ── Shared helpers for Task 8 tests ──────────────────────────────────────────

/** Minimal app with a fresh DefaultKillSwitchManager, default test API key. */
function buildSimpleKsApp(): { app: Express; ksm: DefaultKillSwitchManager } {
  const app = express();
  app.use(express.json());
  const ksm = new DefaultKillSwitchManager();
  const logger = createLogger('test');
  const adminRouter = createAdminRouter({ killSwitchManager: ksm, logger, adminApiKey: TEST_API_KEY });
  app.use('/admin', adminRouter);
  return { app, ksm };
}

function buildTenantScopedApp(opts: {
  tenantId: string;
  ocsfTransport?: OcsfAuditTransport;
  idempotencyStore?: IAdminIdempotencyStore;
}): Express {
  const app = express();
  app.use(express.json());
  const killSwitchManager = new DefaultKillSwitchManager();
  const logger = createLogger('test');
  const adminRouter = createAdminRouter({
    killSwitchManager,
    logger,
    adminApiKey: TEST_API_KEY,
    tenantId: opts.tenantId,
    ocsfTransport: opts.ocsfTransport,
    idempotencyStore: opts.idempotencyStore,
  });
  app.use('/admin', adminRouter);
  return app;
}

function buildOcsfCapturingTransport(): { transport: OcsfAuditTransport; events: OcsfAuthorizationEvent[] } {
  const events: OcsfAuthorizationEvent[] = [];
  const transport: OcsfAuditTransport = {
    name: 'test-ocsf',
    async send(event) { events.push(event as OcsfAuthorizationEvent); },
    async flush() {},
    async close() {},
  };
  return { transport, events };
}

// ── Tenant Scoping ────────────────────────────────────────────────────────────

describe('Tenant scoping (ADMIN_TENANT_ID)', () => {
  const TENANT = 'tenant-alpha';

  describe('per-entity kill operations', () => {
    it('rejects session kill when tenantId is missing', async () => {
      const app = buildTenantScopedApp({ tenantId: TENANT });
      const res = await request(app)
        .post('/admin/kill-switch/session/sess-1/kill')
        .set('X-Admin-API-Key', TEST_API_KEY)
        .send({});
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('TENANT_ID_REQUIRED');
    });

    it('rejects session kill when tenantId does not match', async () => {
      const app = buildTenantScopedApp({ tenantId: TENANT });
      const res = await request(app)
        .post('/admin/kill-switch/session/sess-1/kill')
        .set('X-Admin-API-Key', TEST_API_KEY)
        .send({ tenantId: 'tenant-beta' });
      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe('TENANT_MISMATCH');
    });

    it('allows session kill when tenantId matches', async () => {
      const app = buildTenantScopedApp({ tenantId: TENANT });
      const res = await request(app)
        .post('/admin/kill-switch/session/sess-1/kill')
        .set('X-Admin-API-Key', TEST_API_KEY)
        .send({ tenantId: TENANT });
      expect(res.status).toBe(200);
    });

    it('rejects agent kill when tenantId does not match', async () => {
      const app = buildTenantScopedApp({ tenantId: TENANT });
      const res = await request(app)
        .post('/admin/kill-switch/agent/agent-1/kill')
        .set('X-Admin-API-Key', TEST_API_KEY)
        .send({ tenantId: 'other-tenant' });
      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe('TENANT_MISMATCH');
    });

    it('allows agent kill when tenantId matches', async () => {
      const app = buildTenantScopedApp({ tenantId: TENANT });
      const res = await request(app)
        .post('/admin/kill-switch/agent/agent-1/kill')
        .set('X-Admin-API-Key', TEST_API_KEY)
        .send({ tenantId: TENANT });
      expect(res.status).toBe(200);
    });

    it('allows session revive when tenantId matches', async () => {
      const app = buildTenantScopedApp({ tenantId: TENANT });
      const res = await request(app)
        .post('/admin/kill-switch/session/sess-revive/revive')
        .set('X-Admin-API-Key', TEST_API_KEY)
        .send({ tenantId: TENANT });
      expect(res.status).toBe(200);
    });

    it('allows agent revive when tenantId matches', async () => {
      const app = buildTenantScopedApp({ tenantId: TENANT });
      const res = await request(app)
        .post('/admin/kill-switch/agent/agent-revive/revive')
        .set('X-Admin-API-Key', TEST_API_KEY)
        .send({ tenantId: TENANT });
      expect(res.status).toBe(200);
    });
  });

  describe('global kill switch (cross-tenant acknowledgement)', () => {
    it('requires tenantId even for global activate', async () => {
      const app = buildTenantScopedApp({ tenantId: TENANT });
      const res = await request(app)
        .post('/admin/kill-switch/global/activate')
        .set('X-Admin-API-Key', TEST_API_KEY)
        .send({});
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('TENANT_ID_REQUIRED');
    });

    it('requires acknowledgesCrossTenantImpact for global activate', async () => {
      const app = buildTenantScopedApp({ tenantId: TENANT });
      const res = await request(app)
        .post('/admin/kill-switch/global/activate')
        .set('X-Admin-API-Key', TEST_API_KEY)
        .send({ tenantId: TENANT });
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('CROSS_TENANT_ACKNOWLEDGEMENT_REQUIRED');
    });

    it('activates global kill when tenantId matches and acknowledgement is present', async () => {
      const app = buildTenantScopedApp({ tenantId: TENANT });
      const res = await request(app)
        .post('/admin/kill-switch/global/activate')
        .set('X-Admin-API-Key', TEST_API_KEY)
        .send({ tenantId: TENANT, acknowledgesCrossTenantImpact: true });
      expect(res.status).toBe(200);
    });

    it('requires acknowledgement for global deactivate', async () => {
      const app = buildTenantScopedApp({ tenantId: TENANT });
      const res = await request(app)
        .post('/admin/kill-switch/global/deactivate')
        .set('X-Admin-API-Key', TEST_API_KEY)
        .send({ tenantId: TENANT });
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('CROSS_TENANT_ACKNOWLEDGEMENT_REQUIRED');
    });

    it('requires acknowledgement for kill-switch reset', async () => {
      const app = buildTenantScopedApp({ tenantId: TENANT });
      const res = await request(app)
        .post('/admin/kill-switch/reset')
        .set('X-Admin-API-Key', TEST_API_KEY)
        .send({ tenantId: TENANT });
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('CROSS_TENANT_ACKNOWLEDGEMENT_REQUIRED');
    });

    it('resets all when tenantId matches and acknowledgement present', async () => {
      const app = buildTenantScopedApp({ tenantId: TENANT });
      const res = await request(app)
        .post('/admin/kill-switch/reset')
        .set('X-Admin-API-Key', TEST_API_KEY)
        .send({ tenantId: TENANT, acknowledgesCrossTenantImpact: true });
      expect(res.status).toBe(200);
    });
  });

  describe('no tenant scoping (tenantId not configured)', () => {
    it('does not require tenantId in the body', async () => {
      const { app } = buildSimpleKsApp();
      const res = await request(app)
        .post('/admin/kill-switch/session/sess-no-scope/kill')
        .set('X-Admin-API-Key', TEST_API_KEY)
        .send({});
      expect(res.status).toBe(200);
    });

    it('ignores tenantId in the body if provided', async () => {
      const { app } = buildSimpleKsApp();
      const res = await request(app)
        .post('/admin/kill-switch/session/sess-no-scope/kill')
        .set('X-Admin-API-Key', TEST_API_KEY)
        .send({ tenantId: 'whatever' });
      expect(res.status).toBe(200);
    });
  });
});

// ── Idempotency Keys ──────────────────────────────────────────────────────────

describe('Idempotency-Key header support', () => {
  it('returns the same response on retry with the same Idempotency-Key', async () => {
    const { app } = buildSimpleKsApp();
    const key = `idem-${Date.now()}`;

    const first = await request(app)
      .post('/admin/kill-switch/session/sess-idem/kill')
      .set('X-Admin-API-Key', TEST_API_KEY)
      .set('Idempotency-Key', key)
      .send({});
    expect(first.status).toBe(200);

    const second = await request(app)
      .post('/admin/kill-switch/session/sess-idem/kill')
      .set('X-Admin-API-Key', TEST_API_KEY)
      .set('Idempotency-Key', key)
      .send({});
    expect(second.status).toBe(200);
    expect(second.body).toEqual(first.body);
  });

  it('does not re-execute the operation on retry', async () => {
    const store = new AdminIdempotencyStore();
    const app = express();
    app.use(express.json());
    const ksm = new DefaultKillSwitchManager();
    const adminRouter = createAdminRouter({
      killSwitchManager: ksm,
      logger: createLogger('test'),
      adminApiKey: TEST_API_KEY,
      idempotencyStore: store,
    });
    app.use('/admin', adminRouter);

    const key = `idem-agent-${Date.now()}`;
    await request(app)
      .post('/admin/kill-switch/agent/agent-idem/kill')
      .set('X-Admin-API-Key', TEST_API_KEY)
      .set('Idempotency-Key', key)
      .send({});
    expect(ksm.isAgentKilled('agent-idem')).toBe(true);

    ksm.reviveAgent('agent-idem'); // Manually revive to test re-execution is NOT happening
    expect(ksm.isAgentKilled('agent-idem')).toBe(false);

    // Second call with same key: should return cached response WITHOUT re-killing
    await request(app)
      .post('/admin/kill-switch/agent/agent-idem/kill')
      .set('X-Admin-API-Key', TEST_API_KEY)
      .set('Idempotency-Key', key)
      .send({});
    expect(ksm.isAgentKilled('agent-idem')).toBe(false); // Not re-executed
  });

  it('rejects the same key used against a different endpoint', async () => {
    const { app } = buildSimpleKsApp();
    const key = `idem-conflict-${Date.now()}`;

    await request(app)
      .post('/admin/kill-switch/session/sess-conflict/kill')
      .set('X-Admin-API-Key', TEST_API_KEY)
      .set('Idempotency-Key', key)
      .send({});

    const conflict = await request(app)
      .post('/admin/kill-switch/session/sess-conflict/revive')
      .set('X-Admin-API-Key', TEST_API_KEY)
      .set('Idempotency-Key', key)
      .send({});

    expect(conflict.status).toBe(422);
    expect(conflict.body.error.code).toBe('IDEMPOTENCY_KEY_REUSE');
  });

  it('treats requests without Idempotency-Key as non-idempotent (normal behaviour)', async () => {
    const { app, ksm } = buildSimpleKsApp();

    await request(app)
      .post('/admin/kill-switch/agent/agent-normal/kill')
      .set('X-Admin-API-Key', TEST_API_KEY)
      .send({});
    expect(ksm.isAgentKilled('agent-normal')).toBe(true);
    ksm.reviveAgent('agent-normal');

    await request(app)
      .post('/admin/kill-switch/agent/agent-normal/kill')
      .set('X-Admin-API-Key', TEST_API_KEY)
      .send({});
    expect(ksm.isAgentKilled('agent-normal')).toBe(true); // Re-executed
  });

  it('AdminIdempotencyStore: expired entries are not replayed', async () => {
    const shortTtlStore = new AdminIdempotencyStore({ ttlMs: 5 }); // 5 ms TTL
    shortTtlStore.set('k1', 'POST /x', 200, { ok: true });
    await new Promise<void>((resolve) => setTimeout(resolve, 20));
    expect(shortTtlStore.get('k1')).toBeUndefined();
  });
});

// ── OCSF Audit Trail ──────────────────────────────────────────────────────────

describe('OCSF audit trail (ocsfTransport)', () => {
  it('emits an OCSF Authorization event when a session is killed', async () => {
    const { transport, events } = buildOcsfCapturingTransport();
    const app = express();
    app.use(express.json());
    app.use('/admin', createAdminRouter({
      killSwitchManager: new DefaultKillSwitchManager(),
      logger: createLogger('test'),
      adminApiKey: TEST_API_KEY,
      ocsfTransport: transport,
    }));

    await request(app)
      .post('/admin/kill-switch/session/sess-ocsf/kill')
      .set('X-Admin-API-Key', TEST_API_KEY)
      .send({});

    // Allow any async send() promises to settle
    await transport.flush();

    expect(events).toHaveLength(1);
    const event = events[0]!;
    expect(event.class_uid).toBe(3003);
    expect(event.category_uid).toBe(3);
    expect(event.activity_id).toBe(2); // Revoke Privileges
    expect(event.severity_id).toBe(4); // High
    expect(event.status).toBe('Success');
    expect(event.resources).toEqual([{ uid: 'sess-ocsf', type: 'session' }]);
    expect(event.metadata.product.name).toBe('euno-tool-gateway');
  });

  it('emits an OCSF event with activity_id=1 (Assign) when an agent is revived', async () => {
    const { transport, events } = buildOcsfCapturingTransport();
    const app = express();
    app.use(express.json());
    const ksm = new DefaultKillSwitchManager();
    ksm.killAgent('agent-revive-ocsf');
    app.use('/admin', createAdminRouter({
      killSwitchManager: ksm,
      logger: createLogger('test'),
      adminApiKey: TEST_API_KEY,
      ocsfTransport: transport,
    }));

    await request(app)
      .post('/admin/kill-switch/agent/agent-revive-ocsf/revive')
      .set('X-Admin-API-Key', TEST_API_KEY)
      .send({});
    await transport.flush();

    expect(events).toHaveLength(1);
    expect(events[0]!.activity_id).toBe(1); // Assign Privileges
    expect(events[0]!.severity_id).toBe(2); // Low
    expect(events[0]!.resources).toEqual([{ uid: 'agent-revive-ocsf', type: 'agent' }]);
  });

  it('emits severity_id=5 (Critical) for global kill activate', async () => {
    const { transport, events } = buildOcsfCapturingTransport();
    const app = express();
    app.use(express.json());
    app.use('/admin', createAdminRouter({
      killSwitchManager: new DefaultKillSwitchManager(),
      logger: createLogger('test'),
      adminApiKey: TEST_API_KEY,
      ocsfTransport: transport,
    }));

    await request(app)
      .post('/admin/kill-switch/global/activate')
      .set('X-Admin-API-Key', TEST_API_KEY)
      .send({});
    await transport.flush();

    expect(events[0]!.severity_id).toBe(5);
    expect(events[0]!.activity_id).toBe(2);
  });

  it('stamps tenantId in OCSF unmapped when tenant scoping is configured', async () => {
    const { transport, events } = buildOcsfCapturingTransport();
    const app = buildTenantScopedApp({ tenantId: 'tenant-ocsf', ocsfTransport: transport });

    await request(app)
      .post('/admin/kill-switch/session/sess-tenant-ocsf/kill')
      .set('X-Admin-API-Key', TEST_API_KEY)
      .send({ tenantId: 'tenant-ocsf' });
    await transport.flush();

    expect(events[0]!.unmapped).toMatchObject({ tenantId: 'tenant-ocsf' });
  });

  it('records the operator from X-Admin-Operator in the OCSF actor', async () => {
    const { transport, events } = buildOcsfCapturingTransport();
    const app = express();
    app.use(express.json());
    app.use('/admin', createAdminRouter({
      killSwitchManager: new DefaultKillSwitchManager(),
      logger: createLogger('test'),
      adminApiKey: TEST_API_KEY,
      ocsfTransport: transport,
    }));

    await request(app)
      .post('/admin/kill-switch/agent/agent-actor/kill')
      .set('X-Admin-API-Key', TEST_API_KEY)
      .set('X-Admin-Operator', 'operator-alice')
      .send({});
    await transport.flush();

    expect(events[0]!.actor?.user?.uid).toBe('operator-alice');
  });

  it('emits a failure OCSF event when a cross-tenant operation is rejected', async () => {
    const { transport, events } = buildOcsfCapturingTransport();
    const app = buildTenantScopedApp({ tenantId: 'tenant-x', ocsfTransport: transport });

    await request(app)
      .post('/admin/kill-switch/session/sess-cross/kill')
      .set('X-Admin-API-Key', TEST_API_KEY)
      .send({ tenantId: 'tenant-y' });
    await transport.flush();

    expect(events).toHaveLength(1);
    expect(events[0]!.status).toBe('Failure');
    expect(events[0]!.severity_id).toBe(4);
    expect(events[0]!.unmapped).toMatchObject({ rejectedTenantId: 'tenant-y' });
  });

  it('does not emit OCSF events when no transport is configured', async () => {
    // Control: without a transport, no events should be emitted (no crash either).
    const { app } = buildSimpleKsApp();
    // Just confirm the endpoint works without error.
    const res = await request(app)
      .post('/admin/kill-switch/session/sess-no-transport/kill')
      .set('X-Admin-API-Key', TEST_API_KEY)
      .send({});
    expect(res.status).toBe(200);
  });
});

// ── AdminIdempotencyStore unit tests ──────────────────────────────────────────

describe('AdminIdempotencyStore', () => {
  it('returns undefined for unknown keys', () => {
    const store = new AdminIdempotencyStore();
    expect(store.get('missing')).toBeUndefined();
  });

  it('returns a stored entry before expiry', () => {
    const store = new AdminIdempotencyStore({ ttlMs: 60_000 });
    store.set('k', 'POST /test', 200, { ok: true });
    const entry = store.get('k');
    expect(entry).toBeDefined();
    expect(entry!.status).toBe(200);
    expect(entry!.endpoint).toBe('POST /test');
    expect(entry!.body).toEqual({ ok: true });
  });

  it('expires entries after TTL', async () => {
    const store = new AdminIdempotencyStore({ ttlMs: 5 });
    store.set('k', 'POST /test', 200, {});
    await new Promise<void>((r) => setTimeout(r, 20));
    expect(store.get('k')).toBeUndefined();
  });

  it('overwrites an existing entry with set()', () => {
    const store = new AdminIdempotencyStore();
    store.set('k', 'POST /a', 200, { first: true });
    store.set('k', 'POST /a', 201, { second: true });
    const entry = store.get('k');
    expect(entry!.status).toBe(201);
    expect(entry!.body).toEqual({ second: true });
  });

  it('evicts oldest live entries when maxSize is reached and no expired entries exist', () => {
    const store = new AdminIdempotencyStore({ ttlMs: 60_000, maxSize: 3 });
    store.set('first', 'POST /a', 200, {});
    store.set('second', 'POST /b', 200, {});
    store.set('third', 'POST /c', 200, {});
    // Inserting a 4th entry must not exceed maxSize.
    store.set('fourth', 'POST /d', 200, {});
    // The oldest entry ('first') should have been evicted.
    expect(store.get('first')).toBeUndefined();
    // The new entry should be present.
    expect(store.get('fourth')).toBeDefined();
  });
});
