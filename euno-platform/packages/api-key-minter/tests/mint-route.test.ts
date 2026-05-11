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

const logger = createLogger('test-mint');

async function buildApp(opts: { maxMints?: number } = {}) {
  const pepper = { version: 'v1', key: crypto.randomBytes(32) };
  const store = new InMemoryApiKeyStore();
  const signer = await LocalTokenSigner.generate('RS256');
  const auditStore = new InMemoryMintAuditStore();
  const rateLimiter = new InMemoryMintRateLimiter({
    maxMintsPerWindow: opts.maxMints ?? 100,
    windowSeconds: 60,
  });

  // Create an API key in the store
  const key = generateApiKey();
  const keyDigest = crypto.createHmac('sha256', pepper.key).update(key.secret, 'utf8').digest().toString('base64url');
  await store.createKey({
    prefix: key.prefix,
    keyDigest,
    hmacKeyVersion: pepper.version,
    tenantId: 'tenant-test',
    policyId: 'policy-test',
    capabilities: [],
    scopes: ['enforce'],
    createdAt: new Date().toISOString(),
  });

  const verifier = new ApiKeyVerifier({ store, peppers: [pepper] });
  const minter = new TokenMinter({
    signer,
    issuerDid: 'did:web:minter.test',
    gatewayAudience: 'tool-gateway',
    ttlSeconds: 300,
  });

  const app = createMinterApp({
    mintRouterOpts: { verifier, minter, auditStore, rateLimiter, logger },
    adminKeysRouterOpts: { keyStore: store, peppers: [pepper], adminApiKey: 'admin-secret', logger },
    logger,
  });

  return { app, key, auditStore };
}

describe('POST /mint', () => {
  it('returns 200 with capabilityToken and expiresAt for valid key', async () => {
    const { app, key } = await buildApp();
    const res = await request(app)
      .post('/mint')
      .set('Authorization', `Bearer ${key.raw}`)
      .send({ agentId: 'agent-1', sessionId: 'session-1' });

    expect(res.status).toBe(200);
    expect(typeof res.body.capabilityToken).toBe('string');
    expect(typeof res.body.expiresAt).toBe('number');
  });

  it('returns 401 for missing Authorization header', async () => {
    const { app } = await buildApp();
    const res = await request(app)
      .post('/mint')
      .send({ agentId: 'agent-1', sessionId: 'session-1' });
    expect(res.status).toBe(401);
  });

  it('returns 401 for invalid API key', async () => {
    const { app } = await buildApp();
    const fakeKey = generateApiKey();
    const res = await request(app)
      .post('/mint')
      .set('Authorization', `Bearer ${fakeKey.raw}`)
      .send({ agentId: 'agent-1', sessionId: 'session-1' });
    expect(res.status).toBe(401);
  });

  it('returns 429 when rate limit exceeded', async () => {
    const { app, key } = await buildApp({ maxMints: 1 });
    // First request succeeds
    await request(app)
      .post('/mint')
      .set('Authorization', `Bearer ${key.raw}`)
      .send({ agentId: 'agent-1', sessionId: 'session-1' });
    // Second request should be rate-limited
    const res = await request(app)
      .post('/mint')
      .set('Authorization', `Bearer ${key.raw}`)
      .send({ agentId: 'agent-1', sessionId: 'session-1' });
    expect(res.status).toBe(429);
    expect(res.headers['retry-after']).toBeDefined();
  });

  it('returns 400 for missing agentId', async () => {
    const { app, key } = await buildApp();
    const res = await request(app)
      .post('/mint')
      .set('Authorization', `Bearer ${key.raw}`)
      .send({ sessionId: 'session-1' });
    expect(res.status).toBe(400);
  });

  it('returns 400 for missing sessionId', async () => {
    const { app, key } = await buildApp();
    const res = await request(app)
      .post('/mint')
      .set('Authorization', `Bearer ${key.raw}`)
      .send({ agentId: 'agent-1' });
    expect(res.status).toBe(400);
  });
});
