import * as crypto from 'crypto';
import request from 'supertest';
import { createMinterApp } from '../src/app-factory';
import { ApiKeyVerifier } from '../src/api-key-verifier';
import { InMemoryApiKeyStore } from '../src/api-key-store';
import { TokenMinter } from '../src/token-minter';
import { LocalTokenSigner } from '../src/local-token-signer';
import { InMemoryMintAuditStore } from '../src/mint-audit';
import { InMemoryMintRateLimiter } from '../src/mint-rate-limiter';
import { createLogger } from '@euno/common';

const logger = createLogger('test-admin');
const ADMIN_KEY = 'test-admin-secret';

async function buildApp() {
  const pepper = { version: 'v1', key: crypto.randomBytes(32) };
  const store = new InMemoryApiKeyStore();
  const signer = await LocalTokenSigner.generate('RS256');
  const auditStore = new InMemoryMintAuditStore();
  const rateLimiter = new InMemoryMintRateLimiter({ maxMintsPerWindow: 100, windowSeconds: 60 });
  const verifier = new ApiKeyVerifier({ store, peppers: [pepper] });
  const minter = new TokenMinter({ signer, issuerDid: 'did:web:test', gatewayAudience: 'tool-gateway' });

  const app = createMinterApp({
    mintRouterOpts: { verifier, minter, auditStore, rateLimiter, logger },
    adminKeysRouterOpts: { keyStore: store, peppers: [pepper], adminApiKey: ADMIN_KEY, logger },
    logger,
  });

  return { app, store, pepper };
}

const validBody = {
  tenantId: 'tenant-1',
  policyId: 'policy-1',
  capabilities: [],
  scopes: ['enforce'],
};

describe('POST /admin/v1/keys', () => {
  it('creates a key and returns prefix and raw with valid admin auth', async () => {
    const { app } = await buildApp();
    const res = await request(app)
      .post('/admin/v1/keys')
      .set('X-Admin-Key', ADMIN_KEY)
      .send(validBody);

    expect(res.status).toBe(201);
    expect(typeof res.body.prefix).toBe('string');
    expect(typeof res.body.raw).toBe('string');
    expect(res.body.raw).toMatch(/^sk-/);
  });

  it('returns 401 without admin auth', async () => {
    const { app } = await buildApp();
    const res = await request(app)
      .post('/admin/v1/keys')
      .send(validBody);
    expect(res.status).toBe(401);
  });

  it('returns 401 with wrong admin key', async () => {
    const { app } = await buildApp();
    const res = await request(app)
      .post('/admin/v1/keys')
      .set('X-Admin-Key', 'wrong-key')
      .send(validBody);
    expect(res.status).toBe(401);
  });

  it('returns 400 for missing tenantId', async () => {
    const { app } = await buildApp();
    const res = await request(app)
      .post('/admin/v1/keys')
      .set('X-Admin-Key', ADMIN_KEY)
      .send({ policyId: 'p', capabilities: [] });
    expect(res.status).toBe(400);
  });

  it('raw key is only shown once (not stored in response)', async () => {
    const { app } = await buildApp();
    const res = await request(app)
      .post('/admin/v1/keys')
      .set('X-Admin-Key', ADMIN_KEY)
      .send(validBody);
    expect(res.status).toBe(201);
    expect(res.body.message).toMatch(/not be shown again/i);
  });
});

describe('GET /admin/v1/keys', () => {
  it('returns keys list for valid tenantId', async () => {
    const { app } = await buildApp();
    // Create a key first
    await request(app)
      .post('/admin/v1/keys')
      .set('X-Admin-Key', ADMIN_KEY)
      .send(validBody);

    const res = await request(app)
      .get('/admin/v1/keys?tenantId=tenant-1')
      .set('X-Admin-Key', ADMIN_KEY);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.keys)).toBe(true);
    expect(res.body.keys.length).toBeGreaterThan(0);
  });

  it('returns 400 for missing tenantId', async () => {
    const { app } = await buildApp();
    const res = await request(app)
      .get('/admin/v1/keys')
      .set('X-Admin-Key', ADMIN_KEY);
    expect(res.status).toBe(400);
  });

  it('does not return keyDigest in response', async () => {
    const { app } = await buildApp();
    await request(app)
      .post('/admin/v1/keys')
      .set('X-Admin-Key', ADMIN_KEY)
      .send(validBody);

    const res = await request(app)
      .get('/admin/v1/keys?tenantId=tenant-1')
      .set('X-Admin-Key', ADMIN_KEY);

    expect(res.status).toBe(200);
    for (const key of res.body.keys as Record<string, unknown>[]) {
      expect(key['keyDigest']).toBeUndefined();
    }
  });
});

describe('DELETE /admin/v1/keys/:prefix', () => {
  it('revokes an existing key', async () => {
    const { app } = await buildApp();
    const createRes = await request(app)
      .post('/admin/v1/keys')
      .set('X-Admin-Key', ADMIN_KEY)
      .send(validBody);
    const { prefix } = createRes.body as { prefix: string };

    const res = await request(app)
      .delete(`/admin/v1/keys/${prefix}`)
      .set('X-Admin-Key', ADMIN_KEY);

    expect(res.status).toBe(200);
    expect(res.body.prefix).toBe(prefix);
    expect(typeof res.body.revokedAt).toBe('string');
  });

  it('returns 404 for already revoked key', async () => {
    const { app } = await buildApp();
    const createRes = await request(app)
      .post('/admin/v1/keys')
      .set('X-Admin-Key', ADMIN_KEY)
      .send(validBody);
    const { prefix } = createRes.body as { prefix: string };

    // Revoke once
    await request(app)
      .delete(`/admin/v1/keys/${prefix}`)
      .set('X-Admin-Key', ADMIN_KEY);

    // Try to revoke again
    const res = await request(app)
      .delete(`/admin/v1/keys/${prefix}`)
      .set('X-Admin-Key', ADMIN_KEY);
    expect(res.status).toBe(404);
  });

  it('returns 404 for non-existent prefix', async () => {
    const { app } = await buildApp();
    const res = await request(app)
      .delete('/admin/v1/keys/nonexistent')
      .set('X-Admin-Key', ADMIN_KEY);
    expect(res.status).toBe(404);
  });
});
