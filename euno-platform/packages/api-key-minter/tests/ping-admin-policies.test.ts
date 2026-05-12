import * as crypto from 'crypto';
import request from 'supertest';
import { createMinterApp } from '../src/app-factory';
import { ApiKeyVerifier } from '../src/api-key-verifier';
import { InMemoryApiKeyStore } from '../src/api-key-store';
import { TokenMinter } from '../src/token-minter';
import { LocalTokenSigner } from '../src/local-token-signer';
import { InMemoryMintAuditStore } from '../src/mint-audit';
import { InMemoryMintRateLimiter } from '../src/mint-rate-limiter';
import { generateApiKey } from '../src/api-key';
import { createLogger } from '@euno/common';

const logger = createLogger('test-ping-policy');
const ADMIN_KEY = 'test-admin-secret';

async function buildApp() {
  const pepper = { version: 'v1', key: crypto.randomBytes(32) };
  const store = new InMemoryApiKeyStore();
  const signer = await LocalTokenSigner.generate('RS256');
  const auditStore = new InMemoryMintAuditStore();
  const rateLimiter = new InMemoryMintRateLimiter({ maxMintsPerWindow: 100, windowSeconds: 60 });

  // Create a valid API key for use in tests
  const key = generateApiKey();
  const keyDigest = crypto
    .createHmac('sha256', pepper.key)
    .update(key.secret, 'utf8')
    .digest()
    .toString('base64url');
  await store.createKey({
    prefix: key.prefix,
    keyDigest,
    hmacKeyVersion: pepper.version,
    tenantId: 'tenant-1',
    policyId: 'policy-1',
    capabilities: [],
    scopes: ['enforce', 'admin'],
    createdAt: new Date().toISOString(),
  });

  const verifier = new ApiKeyVerifier({ store, peppers: [pepper] });
  const minter = new TokenMinter({
    signer,
    issuerDid: 'did:web:test',
    gatewayAudience: 'tool-gateway',
  });

  const app = createMinterApp({
    mintRouterOpts: { verifier, minter, auditStore, rateLimiter, logger },
    adminKeysRouterOpts: { keyStore: store, peppers: [pepper], adminApiKey: ADMIN_KEY, logger },
    logger,
  });

  return { app, key, store };
}

// ---------------------------------------------------------------------------
// GET /api/v1/ping
// ---------------------------------------------------------------------------

describe('GET /api/v1/ping', () => {
  it('returns 200 with tenantId/policyId/scopes for a valid Bearer API key', async () => {
    const { app, key } = await buildApp();
    const res = await request(app)
      .get('/api/v1/ping')
      .set('Authorization', `Bearer ${key.raw}`);

    expect(res.status).toBe(200);
    expect(res.body.valid).toBe(true);
    expect(res.body.tenantId).toBe('tenant-1');
    expect(res.body.policyId).toBe('policy-1');
    expect(Array.isArray(res.body.scopes)).toBe(true);
    expect(res.body.scopes).toContain('enforce');
  });

  it('returns 401 when no Authorization header is provided', async () => {
    const { app } = await buildApp();
    const res = await request(app).get('/api/v1/ping');
    expect(res.status).toBe(401);
  });

  it('returns 401 for an invalid API key', async () => {
    const { app } = await buildApp();
    const fake = generateApiKey();
    const res = await request(app)
      .get('/api/v1/ping')
      .set('Authorization', `Bearer ${fake.raw}`);
    expect(res.status).toBe(401);
  });

  it('returns 401 for a revoked API key', async () => {
    const { app, key, store } = await buildApp();
    await store.revokeKey(key.prefix);
    const res = await request(app)
      .get('/api/v1/ping')
      .set('Authorization', `Bearer ${key.raw}`);
    expect(res.status).toBe(401);
  });

  it('does not include keyDigest or sensitive fields in the response', async () => {
    const { app, key } = await buildApp();
    const res = await request(app)
      .get('/api/v1/ping')
      .set('Authorization', `Bearer ${key.raw}`);
    expect(res.status).toBe(200);
    expect(res.body.keyDigest).toBeUndefined();
    expect(res.body.hmacKeyVersion).toBeUndefined();
  });

  it('returns 429 when IP-based rate limit is exceeded', async () => {
    // Build an app with a very tight rate limit (1 request per window).
    const pepper = { version: 'v1', key: crypto.randomBytes(32) };
    const store = new InMemoryApiKeyStore();
    const signer = await LocalTokenSigner.generate('RS256');
    const auditStore = new InMemoryMintAuditStore();
    const tightLimiter = new InMemoryMintRateLimiter({ maxMintsPerWindow: 1, windowSeconds: 60 });

    const key = generateApiKey();
    const keyDigest = crypto.createHmac('sha256', pepper.key).update(key.secret, 'utf8').digest().toString('base64url');
    await store.createKey({
      prefix: key.prefix, keyDigest, hmacKeyVersion: pepper.version,
      tenantId: 'tenant-rate', policyId: 'policy-rate', capabilities: [],
      scopes: ['enforce'], createdAt: new Date().toISOString(),
    });

    const verifier = new ApiKeyVerifier({ store, peppers: [pepper] });
    const minter = new TokenMinter({ signer, issuerDid: 'did:web:test', gatewayAudience: 'gw' });
    const tightApp = createMinterApp({
      mintRouterOpts: { verifier, minter, auditStore, rateLimiter: tightLimiter, logger },
      adminKeysRouterOpts: { keyStore: store, peppers: [pepper], adminApiKey: ADMIN_KEY, logger },
      logger,
    });

    // First request should succeed.
    const first = await request(tightApp).get('/api/v1/ping').set('Authorization', `Bearer ${key.raw}`);
    expect(first.status).toBe(200);

    // Second request from the same IP should be rate-limited.
    const second = await request(tightApp).get('/api/v1/ping').set('Authorization', `Bearer ${key.raw}`);
    expect(second.status).toBe(429);
    expect(second.headers['retry-after']).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// POST /admin/v1/policies
// ---------------------------------------------------------------------------

describe('POST /admin/v1/policies', () => {
  const validManifest = {
    name: 'test-agent',
    agentId: 'agent-1',
    version: '1.0.0',
    requiredCapabilities: [
      { resource: '/api', actions: ['read'], conditions: [] },
    ],
  };

  it('returns 200 and updates capabilities for matching keys', async () => {
    const { app } = await buildApp();
    const res = await request(app)
      .post('/admin/v1/policies')
      .set('X-Admin-Key', ADMIN_KEY)
      .send({ policyId: 'policy-1', manifest: validManifest });

    expect(res.status).toBe(200);
    expect(res.body.policyId).toBe('policy-1');
    expect(typeof res.body.updatedKeys).toBe('number');
    expect(res.body.updatedKeys).toBeGreaterThanOrEqual(1);
    expect(typeof res.body.capabilityCount).toBe('number');
  });

  it('returns 200 with updatedKeys=0 when policyId matches no keys', async () => {
    const { app } = await buildApp();
    const res = await request(app)
      .post('/admin/v1/policies')
      .set('X-Admin-Key', ADMIN_KEY)
      .send({ policyId: 'nonexistent-policy', manifest: validManifest });

    expect(res.status).toBe(200);
    expect(res.body.updatedKeys).toBe(0);
  });

  it('returns 401 when X-Admin-Key is missing', async () => {
    const { app } = await buildApp();
    const res = await request(app)
      .post('/admin/v1/policies')
      .send({ policyId: 'policy-1', manifest: validManifest });
    expect(res.status).toBe(401);
  });

  it('returns 401 for wrong X-Admin-Key', async () => {
    const { app } = await buildApp();
    const res = await request(app)
      .post('/admin/v1/policies')
      .set('X-Admin-Key', 'wrong-key')
      .send({ policyId: 'policy-1', manifest: validManifest });
    expect(res.status).toBe(401);
  });

  it('returns 400 when policyId is missing', async () => {
    const { app } = await buildApp();
    const res = await request(app)
      .post('/admin/v1/policies')
      .set('X-Admin-Key', ADMIN_KEY)
      .send({ manifest: validManifest });
    expect(res.status).toBe(400);
    expect(res.body.error.message).toMatch(/policyId/);
  });

  it('returns 400 when manifest is missing', async () => {
    const { app } = await buildApp();
    const res = await request(app)
      .post('/admin/v1/policies')
      .set('X-Admin-Key', ADMIN_KEY)
      .send({ policyId: 'policy-1' });
    expect(res.status).toBe(400);
    expect(res.body.error.message).toMatch(/manifest/);
  });

  it('returns 400 when manifest fails schema validation', async () => {
    const { app } = await buildApp();
    const invalidManifest = { name: 'bad' }; // missing required fields
    const res = await request(app)
      .post('/admin/v1/policies')
      .set('X-Admin-Key', ADMIN_KEY)
      .send({ policyId: 'policy-1', manifest: invalidManifest });
    expect(res.status).toBe(400);
    expect(res.body.error.message).toMatch(/manifest validation failed/);
  });

  it('propagates capabilities to matching API keys in the store', async () => {
    const { app, store } = await buildApp();
    const capabilities = [
      {
        resource: '/api',
        actions: ['read'],
        conditions: [{ type: 'timeWindow', notBefore: '2020-01-01T00:00:00Z', notAfter: '2099-01-01T00:00:00Z' }],
      },
    ];
    const manifest = { ...validManifest, requiredCapabilities: capabilities };

    const res = await request(app)
      .post('/admin/v1/policies')
      .set('X-Admin-Key', ADMIN_KEY)
      .send({ policyId: 'policy-1', manifest });

    expect(res.status).toBe(200);

    // Verify the store now has the updated capabilities
    const keys = await store.listByTenant('tenant-1');
    const updated = keys.find((k) => k.policyId === 'policy-1');
    expect(updated?.capabilities).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// InMemoryApiKeyStore.updateCapabilitiesByPolicyId()
// ---------------------------------------------------------------------------

describe('InMemoryApiKeyStore.updateCapabilitiesByPolicyId()', () => {
  it('returns 0 when no keys match policyId', async () => {
    const store = new InMemoryApiKeyStore();
    const count = await store.updateCapabilitiesByPolicyId('nonexistent', []);
    expect(count).toBe(0);
  });

  it('updates capabilities for matching non-revoked keys', async () => {
    const store = new InMemoryApiKeyStore();
    await store.createKey({
      prefix: 'prefix1',
      keyDigest: Buffer.alloc(32).toString('base64url'),
      hmacKeyVersion: 'v1',
      tenantId: 'tenant-1',
      policyId: 'policy-A',
      capabilities: [],
      scopes: ['enforce'],
      createdAt: new Date().toISOString(),
    });

    const newCaps = [{ resource: '/api', actions: ['read'], conditions: [] }];
    const count = await store.updateCapabilitiesByPolicyId('policy-A', newCaps);
    expect(count).toBe(1);

    const key = await store.getByPrefix('prefix1');
    expect(key?.capabilities).toHaveLength(1);
    expect(key?.capabilities[0]?.resource).toBe('/api');
  });

  it('does not update revoked keys', async () => {
    const store = new InMemoryApiKeyStore();
    await store.createKey({
      prefix: 'prefix2',
      keyDigest: Buffer.alloc(32).toString('base64url'),
      hmacKeyVersion: 'v1',
      tenantId: 'tenant-1',
      policyId: 'policy-B',
      capabilities: [],
      scopes: ['enforce'],
      createdAt: new Date().toISOString(),
    });
    await store.revokeKey('prefix2');

    const count = await store.updateCapabilitiesByPolicyId('policy-B', [
      { resource: '/api', actions: ['read'], conditions: [] },
    ]);
    expect(count).toBe(0);

    const key = await store.getByPrefix('prefix2');
    expect(key?.capabilities).toHaveLength(0);
  });

  it('updates multiple keys with the same policyId', async () => {
    const store = new InMemoryApiKeyStore();
    for (let i = 0; i < 3; i++) {
      await store.createKey({
        prefix: `prefix-multi-${i}`,
        keyDigest: Buffer.alloc(32).toString('base64url'),
        hmacKeyVersion: 'v1',
        tenantId: 'tenant-1',
        policyId: 'shared-policy',
        capabilities: [],
        scopes: ['enforce'],
        createdAt: new Date().toISOString(),
      });
    }

    const count = await store.updateCapabilitiesByPolicyId('shared-policy', []);
    expect(count).toBe(3);
  });
});
