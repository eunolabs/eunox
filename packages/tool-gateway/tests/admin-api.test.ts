/**
 * Tests for Admin API router – /admin/revoke endpoint
 */

import express, { Express } from 'express';
import request from 'supertest';
import { createAdminRouter } from '../src/admin-api';
import { JWTTokenVerifier } from '../src/verifier';
import { InMemoryRevocationEpochStore } from '../src/revocation-store';
import { createLogger, DefaultKillSwitchManager } from '@euno/common';

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

    it('allows requests without authentication', async () => {
      const res = await request(app)
        .post('/admin/revoke')
        .send({ tokenId: 'tok-unauth' });

      expect(res.status).toBe(200);
    });
  });

  describe('when tokenVerifier is not configured', () => {
    let app: Express;

    beforeEach(() => {
      app = buildApp(undefined, false);
    });

    it('returns 501 when no verifier is configured', async () => {
      const res = await request(app)
        .post('/admin/revoke')
        .send({ tokenId: 'tok-no-verifier' });

      expect(res.status).toBe(501);
      expect(res.body.error.code).toBe('NOT_IMPLEMENTED');
    });
  });
});

// ── POST /admin/revocation/epoch ──────────────────────────────────────────

describe('POST /admin/revocation/epoch', () => {
  const API_KEY = 'epoch-api-key';

  function buildEpochApp(withEpochStore = true, apiKey?: string): {
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
      .send({ issuer: 'did:web:test.com', issuedBefore: 1000 });

    expect(res.status).toBe(501);
    expect(res.body.error.code).toBe('NOT_IMPLEMENTED');
  });

  it('returns 400 when issuer is missing', async () => {
    const { app } = buildEpochApp();
    const res = await request(app)
      .post('/admin/revocation/epoch')
      .send({ issuedBefore: 1000 });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_REQUEST');
  });

  it('returns 400 when issuer is not a string', async () => {
    const { app } = buildEpochApp();
    const res = await request(app)
      .post('/admin/revocation/epoch')
      .send({ issuer: 42, issuedBefore: 1000 });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_REQUEST');
  });

  it('returns 400 when issuedBefore is missing', async () => {
    const { app } = buildEpochApp();
    const res = await request(app)
      .post('/admin/revocation/epoch')
      .send({ issuer: 'did:web:test.com' });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_REQUEST');
  });

  it('returns 400 when issuedBefore is not a number', async () => {
    const { app } = buildEpochApp();
    const res = await request(app)
      .post('/admin/revocation/epoch')
      .send({ issuer: 'did:web:test.com', issuedBefore: 'not-a-number' });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_REQUEST');
  });

  it('returns 400 when issuedBefore is Infinity', async () => {
    const { app } = buildEpochApp();
    const res = await request(app)
      .post('/admin/revocation/epoch')
      .send({ issuer: 'did:web:test.com', issuedBefore: Infinity });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_REQUEST');
  });

  it('returns 200 and sets the epoch in the store', async () => {
    const { app, epochStore } = buildEpochApp();
    const issuedBefore = Math.floor(Date.now() / 1000);

    const res = await request(app)
      .post('/admin/revocation/epoch')
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
      .send({ issuer: 'did:web:test.com', issuedBefore: firstEpoch });

    await request(app)
      .post('/admin/revocation/epoch')
      .send({ issuer: 'did:web:test.com', issuedBefore: secondEpoch });

    expect(await epochStore.getEpoch('did:web:test.com')).toBe(secondEpoch);
  });
});
