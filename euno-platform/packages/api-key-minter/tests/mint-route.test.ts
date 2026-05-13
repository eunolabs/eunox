import * as crypto from 'crypto';
import request from 'supertest';
import { createMinterApp } from '../src/app-factory';
import { ApiKeyVerifier } from '../src/api-key-verifier';
import { InMemoryApiKeyStore } from '../src/api-key-store';
import { TokenMinter } from '../src/token-minter';
import { LocalTokenSigner } from '../src/local-token-signer';
import { InMemoryMintAuditStore, MintAuditStore } from '../src/mint-audit';
import { InMemoryMintRateLimiter } from '../src/mint-rate-limiter';
import { generateApiKey } from '../src/api-key';
import { minterMetrics } from '../src/metrics';
import { createLogger } from '@euno/common';

const logger = createLogger('test-mint');

async function buildApp(opts: { maxMints?: number; auditStore?: MintAuditStore } = {}) {
  const pepper = { version: 'v1', key: crypto.randomBytes(32) };
  const store = new InMemoryApiKeyStore();
  const signer = await LocalTokenSigner.generate('RS256');
  const auditStore = opts.auditStore ?? new InMemoryMintAuditStore();
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

  it('records authentication_failed metric with tenant=unknown when verify() throws', async () => {
    await minterMetrics.registry.resetMetrics();
    const { app } = await buildApp();
    const fakeKey = generateApiKey(); // unknown key — verify() will throw
    await request(app)
      .post('/mint')
      .set('Authorization', `Bearer ${fakeKey.raw}`)
      .send({ agentId: 'agent-1', sessionId: 'session-1' });
    const metrics = await minterMetrics.registry.metrics();
    expect(metrics).toMatch(/euno_minter_mint_total.*tenant="unknown".*result="authentication_failed"/);
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

// ---------------------------------------------------------------------------
// Distributed tracing (DI-5): tracingMiddleware is mounted in createMinterApp
// ---------------------------------------------------------------------------

describe('Minter tracing middleware (DI-5)', () => {
  it('echoes traceparent response header when inbound traceparent is provided', async () => {
    const { app, key } = await buildApp();
    const inboundTraceparent = '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01';

    const res = await request(app)
      .post('/mint')
      .set('Authorization', `Bearer ${key.raw}`)
      .set('traceparent', inboundTraceparent)
      .send({ agentId: 'agent-1', sessionId: 'session-1' });

    expect(res.status).toBe(200);
    // The tracingMiddleware must echo the traceparent back so the caller can
    // correlate its own span with the minter's server span.
    expect(res.headers['traceparent']).toBeDefined();
    // The echoed header must carry the same trace-id as the inbound header.
    const echoed = res.headers['traceparent'] as string;
    expect(echoed).toMatch(/^00-0af7651916cd43dd8448eb211c80319c-[0-9a-f]{16}-/);
  });

  it('still serves requests when no traceparent header is provided', async () => {
    const { app, key } = await buildApp();

    const res = await request(app)
      .post('/mint')
      .set('Authorization', `Bearer ${key.raw}`)
      .send({ agentId: 'agent-1', sessionId: 'session-1' });

    expect(res.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// Acknowledged audit persistence (Task 3)
// ---------------------------------------------------------------------------

describe('POST /mint — acknowledged audit persistence (Task 3)', () => {
  it('returns 503 when the audit store throws', async () => {
    const failingAuditStore: MintAuditStore = {
      record: async () => { throw new Error('DB connection lost'); },
      listByTenant: async () => [],
    };
    const { app, key } = await buildApp({ auditStore: failingAuditStore });

    const res = await request(app)
      .post('/mint')
      .set('Authorization', `Bearer ${key.raw}`)
      .send({ agentId: 'agent-1', sessionId: 'session-1' });

    expect(res.status).toBe(503);
  });

  it('increments euno_minter_audit_failure_total when audit store throws', async () => {
    await minterMetrics.registry.resetMetrics();

    const failingAuditStore: MintAuditStore = {
      record: async () => { throw new Error('audit write failed'); },
      listByTenant: async () => [],
    };
    const { app, key } = await buildApp({ auditStore: failingAuditStore });

    await request(app)
      .post('/mint')
      .set('Authorization', `Bearer ${key.raw}`)
      .send({ agentId: 'agent-1', sessionId: 'session-1' });

    const metrics = await minterMetrics.registry.metrics();
    expect(metrics).toMatch(/euno_minter_audit_failure_total.*stage="write"/);
  });

  it('records audit_failure result label in mintTotal when audit store throws', async () => {
    await minterMetrics.registry.resetMetrics();

    const failingAuditStore: MintAuditStore = {
      record: async () => { throw new Error('audit write failed'); },
      listByTenant: async () => [],
    };
    const { app, key } = await buildApp({ auditStore: failingAuditStore });

    await request(app)
      .post('/mint')
      .set('Authorization', `Bearer ${key.raw}`)
      .send({ agentId: 'agent-1', sessionId: 'session-1' });

    const metrics = await minterMetrics.registry.metrics();
    expect(metrics).toMatch(/euno_minter_mint_total.*result="audit_failure"/);
  });

  it('does NOT return the capability token when audit store throws', async () => {
    const failingAuditStore: MintAuditStore = {
      record: async () => { throw new Error('audit write failed'); },
      listByTenant: async () => [],
    };
    const { app, key } = await buildApp({ auditStore: failingAuditStore });

    const res = await request(app)
      .post('/mint')
      .set('Authorization', `Bearer ${key.raw}`)
      .send({ agentId: 'agent-1', sessionId: 'session-1' });

    expect(res.body.capabilityToken).toBeUndefined();
  });

  it('returns 200 and records audit entry when audit store succeeds', async () => {
    const { app, key, auditStore } = await buildApp();

    const res = await request(app)
      .post('/mint')
      .set('Authorization', `Bearer ${key.raw}`)
      .send({ agentId: 'agent-1', sessionId: 'session-1' });

    expect(res.status).toBe(200);
    // The audit store must have the record for the minted token
    const entries = await auditStore.listByTenant('tenant-test');
    expect(entries).toHaveLength(1);
    expect(entries[0]!.result).toBe('minted');
  });

  it('restores the rate-limit slot when the audit store fails (retry is not 429d)', async () => {
    // Use maxMints=1 so the second request would normally be 429'd.
    // If the rate-limit slot is correctly restored after the audit failure,
    // the retry should receive 503 (not 429).
    const failingAuditStore: MintAuditStore = {
      record: async () => { throw new Error('audit write failed'); },
      listByTenant: async () => [],
    };
    const { app, key } = await buildApp({ maxMints: 1, auditStore: failingAuditStore });

    // First request: rate-limit slot is consumed but returned on audit failure → 503.
    const first = await request(app)
      .post('/mint')
      .set('Authorization', `Bearer ${key.raw}`)
      .send({ agentId: 'agent-1', sessionId: 'session-1' });
    expect(first.status).toBe(503);

    // Second request: slot was restored, so this should also get 503 (not 429).
    const retry = await request(app)
      .post('/mint')
      .set('Authorization', `Bearer ${key.raw}`)
      .send({ agentId: 'agent-1', sessionId: 'session-1' });
    expect(retry.status).toBe(503);
  });
});
