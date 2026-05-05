/**
 * Storage Grant Service — integration tests.
 *
 * Covers:
 *  - JWT verification (valid, expired, wrong issuer, wrong audience,
 *    malformed).
 *  - Capability-presence check (no storage:// → 403).
 *  - Successful grant minting with a stubbed StorageGrantService.
 *  - Health / metadata endpoints.
 *  - Error response shapes.
 */

import supertest from 'supertest';
import * as jose from 'jose';
import { createStorageGrantApp, StorageGrantAppOptions } from '../src/app';
import { StorageGrantService, AzureStorageGrantMinter } from '@euno/capability-issuer';
import { CapabilityTokenPayload, StorageGrant, createLogger, CAPABILITY_TOKEN_SCHEMA_VERSION } from '@euno/common';

// ---------------------------------------------------------------------------
// JWT helpers
// ---------------------------------------------------------------------------

const ISSUER_DID = 'did:web:test-issuer.example.com';
const AUDIENCE = 'tool-gateway:test';
const AGENT_ID = 'agent-test-1';

let privateKey: jose.KeyLike;
let publicKey: jose.KeyLike;

beforeAll(async () => {
  const kp = await jose.generateKeyPair('RS256');
  privateKey = kp.privateKey;
  publicKey = kp.publicKey;
});

async function signCapabilityToken(
  capabilities: CapabilityTokenPayload['capabilities'],
  overrides: Partial<{ exp: number; iss: string; aud: string; schemaVersion: string }> = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new jose.SignJWT({
    sub: AGENT_ID,
    iss: overrides.iss ?? ISSUER_DID,
    aud: overrides.aud ?? AUDIENCE,
    iat: now,
    exp: overrides.exp ?? now + 900,
    jti: `jti-${Math.random().toString(36).slice(2)}`,
    schemaVersion: overrides.schemaVersion ?? CAPABILITY_TOKEN_SCHEMA_VERSION,
    capabilities,
    authorizedBy: { userId: 'user-1', roles: ['Admin'], tenantId: 'tenant-1' },
  })
    .setProtectedHeader({ alg: 'RS256' })
    .sign(privateKey);
}

// ---------------------------------------------------------------------------
// Service fixtures
// ---------------------------------------------------------------------------

const logger = createLogger('storage-grant-service-test', 'test');

function makeEnabledStorageGrantService(): StorageGrantService {
  const minter = new AzureStorageGrantMinter({
    clientFactory: () => ({
      accountName: 'testaccount',
      getUserDelegationKey: async () => ({}),
    }),
    signer: () => ({ sasToken: 'test-sas', url: 'https://testaccount.blob.core.windows.net/foo?test-sas' }),
  });
  return new StorageGrantService({ enabled: true, minters: { 'azure-blob': minter } });
}

function buildApp(serviceOpts: Partial<StorageGrantAppOptions> = {}): ReturnType<typeof supertest> {
  const app = createStorageGrantApp({
    issuerDid: ISSUER_DID,
    audience: AUDIENCE,
    verificationKey: publicKey,
    storageGrantService: makeEnabledStorageGrantService(),
    logger,
    environment: 'test',
    ...serviceOpts,
  });
  return supertest(app);
}

// ---------------------------------------------------------------------------
// Health / metadata
// ---------------------------------------------------------------------------

describe('GET /health', () => {
  it('returns 200 healthy', async () => {
    const res = await buildApp().get('/health');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: 'healthy', service: 'storage-grant-service' });
  });
});

describe('GET /health/ready', () => {
  it('returns 200 when the service is enabled', async () => {
    const res = await buildApp().get('/health/ready');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ready');
  });

  it('returns 503 when the service is not enabled', async () => {
    const disabledService = new StorageGrantService({ enabled: false });
    const res = await buildApp({ storageGrantService: disabledService }).get('/health/ready');
    expect(res.status).toBe(503);
  });
});

describe('GET /.well-known/storage-grant-service', () => {
  it('returns metadata', async () => {
    const res = await buildApp().get('/.well-known/storage-grant-service');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      service: 'storage-grant-service',
      issuerDid: ISSUER_DID,
      audience: AUDIENCE,
    });
  });
});

// ---------------------------------------------------------------------------
// POST /api/v1/storage-grants — auth checks
// ---------------------------------------------------------------------------

describe('POST /api/v1/storage-grants — authentication', () => {
  it('returns 401 when Authorization header is missing', async () => {
    const res = await buildApp().post('/api/v1/storage-grants').send({ agentId: AGENT_ID });
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('AUTHENTICATION_FAILED');
  });

  it('returns 401 for a malformed JWT', async () => {
    const res = await buildApp()
      .post('/api/v1/storage-grants')
      .set('Authorization', 'Bearer not.a.jwt')
      .send({ agentId: AGENT_ID });
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('INVALID_TOKEN');
  });

  it('returns 401 for an expired JWT', async () => {
    const token = await signCapabilityToken(
      [{ resource: 'storage://azure/bucket/file.csv', actions: ['read'] }],
      { exp: Math.floor(Date.now() / 1000) - 60 },
    );
    const res = await buildApp()
      .post('/api/v1/storage-grants')
      .set('Authorization', `Bearer ${token}`)
      .send({ agentId: AGENT_ID });
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('EXPIRED_TOKEN');
  });

  it('returns 401 when the issuer DID does not match', async () => {
    const token = await signCapabilityToken(
      [{ resource: 'storage://azure/bucket/file.csv', actions: ['read'] }],
      { iss: 'did:web:rogue-issuer.example.com' },
    );
    const res = await buildApp()
      .post('/api/v1/storage-grants')
      .set('Authorization', `Bearer ${token}`)
      .send({ agentId: AGENT_ID });
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('INVALID_TOKEN');
  });

  it('returns 401 when the audience does not match', async () => {
    const token = await signCapabilityToken(
      [{ resource: 'storage://azure/bucket/file.csv', actions: ['read'] }],
      { aud: 'wrong-audience' },
    );
    const res = await buildApp()
      .post('/api/v1/storage-grants')
      .set('Authorization', `Bearer ${token}`)
      .send({ agentId: AGENT_ID });
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('INVALID_TOKEN');
  });
});

// ---------------------------------------------------------------------------
// POST /api/v1/storage-grants — payload shape checks
// ---------------------------------------------------------------------------

describe('POST /api/v1/storage-grants — payload shape validation', () => {
  it('returns 401 for a token with an unsupported schemaVersion', async () => {
    const token = await signCapabilityToken(
      [{ resource: 'storage://azure/bucket/file.csv', actions: ['read'] }],
      { schemaVersion: '0.9' },
    );
    const res = await buildApp()
      .post('/api/v1/storage-grants')
      .set('Authorization', `Bearer ${token}`)
      .send({ agentId: AGENT_ID });
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('INVALID_TOKEN');
  });
});

// ---------------------------------------------------------------------------
// POST /api/v1/storage-grants — capability checks
// ---------------------------------------------------------------------------

describe('POST /api/v1/storage-grants — capability checks', () => {
  it('returns 403 when the token has no storage:// capabilities', async () => {
    const token = await signCapabilityToken([
      { resource: 'api://crm/customers', actions: ['read'] },
    ]);
    const res = await buildApp()
      .post('/api/v1/storage-grants')
      .set('Authorization', `Bearer ${token}`)
      .send({ agentId: AGENT_ID });
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('INSUFFICIENT_PERMISSIONS');
  });
});

// ---------------------------------------------------------------------------
// POST /api/v1/storage-grants — happy path
// ---------------------------------------------------------------------------

describe('POST /api/v1/storage-grants — successful minting', () => {
  it('returns grants for a token with storage:// capabilities', async () => {
    const token = await signCapabilityToken([
      { resource: 'storage://azure/testaccount/foo.csv', actions: ['read'] },
    ]);
    const res = await buildApp()
      .post('/api/v1/storage-grants')
      .set('Authorization', `Bearer ${token}`)
      .send({ agentId: AGENT_ID });
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.grants)).toBe(true);
    expect((res.body.grants as StorageGrant[]).length).toBeGreaterThan(0);
    expect((res.body.grants as StorageGrant[])[0]?.provider).toBe('azure-blob');
  });

  it('ignores non-storage:// capabilities in mixed token', async () => {
    const token = await signCapabilityToken([
      { resource: 'api://crm/customers', actions: ['read'] },
      { resource: 'storage://azure/testaccount/report.csv', actions: ['read'] },
    ]);
    const res = await buildApp()
      .post('/api/v1/storage-grants')
      .set('Authorization', `Bearer ${token}`)
      .send({ agentId: AGENT_ID });
    expect(res.status).toBe(200);
    // Only the storage:// capability should produce a grant
    expect((res.body.grants as StorageGrant[]).length).toBe(1);
  });

  it('app constructor throws when neither verificationKey nor jwksUri is provided', () => {
    expect(() =>
      createStorageGrantApp({
        issuerDid: ISSUER_DID,
        audience: AUDIENCE,
        storageGrantService: makeEnabledStorageGrantService(),
      }),
    ).toThrow('either verificationKey or jwksUri must be provided');
  });
});
