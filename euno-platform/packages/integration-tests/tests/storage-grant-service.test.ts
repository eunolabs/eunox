/**
 * Storage Grant Service — integration tests (Task 7, Stage 5).
 *
 * Wires the real `CapabilityIssuerService` (with a genuine RS256 signer)
 * to the `createStorageGrantApp` Express app. Each test issues a capability
 * token via the issuer and presents it to the storage-grant-service,
 * validating the full JWT wire-format contract between the two services.
 *
 * ## Architecture under test
 *
 *   CapabilityIssuerService (in-process)
 *     │  issueCapabilityFromUserContext()
 *     │  → signed RS256 JWT with storage:// capabilities
 *     ▼
 *   createStorageGrantApp (supertest / in-process Express)
 *     │  POST /api/v1/storage-grants
 *     │  → verifies JWT via the same RS256 public key
 *     ▼
 *   StorageGrantService (stubbed Azure Blob minter — no cloud required)
 *     → StorageGrant[]
 *
 * ## Coverage
 *  1.  Issuer-signed token with storage:// capability → 200 + grants
 *  2.  Token without any storage:// capabilities → 403
 *  3.  Token signed by a different key pair → 401 (INVALID_TOKEN)
 *  4.  Token with exp in the past → 401 (EXPIRED_TOKEN)
 *  5.  Token with wrong audience → 401
 *  6.  Mixed token (storage:// + api://) → grants for storage:// only
 *  7.  Multiple storage:// capabilities → multiple grants
 *  8.  GET /health → 200 healthy
 *  9.  GET /.well-known/storage-grant-service → 200 with service metadata
 * 10.  GET /health/ready returns 503 when the service is disabled
 */

import supertest from 'supertest';
import * as jose from 'jose';

import {
  CapabilityTokenPayload,
  IdentityAdapter,
  IdentityAdapterConfig,
  RoleCapabilityPolicy,
  SigningAdapter,
  SigningAdapterConfig,
  UserContext,
  createLogger,
} from '@euno/common';
import { CapabilityIssuerService } from '../../capability-issuer/src/issuer-service';
import { StorageGrantService } from '../../capability-issuer/src/storage-grant/index';
import { AzureStorageGrantMinter } from '../../capability-issuer/src/storage-grant/azure';
import { createStorageGrantApp } from '../../storage-grant-service/src/app';
import type { StorageGrantAppOptions } from '../../storage-grant-service/src/app';

// ── Constants ────────────────────────────────────────────────────────────────

const ISSUER_DID = 'did:web:issuer.storage-grant-it.test';
const AUDIENCE = 'tool-gateway:storage-grant-it';
const SIGNING_ALG = 'RS256';
const AGENT_ID = 'storage-grant-it-agent';

// ── Signer stub ──────────────────────────────────────────────────────────────

class JoseRsaSigner extends SigningAdapter {
  public readonly publicKeyPem: string;

  constructor(
    private readonly privateKey: jose.KeyLike,
    publicKeyPem: string,
    private readonly keyId: string,
  ) {
    super({ type: 'jose-rsa', name: 'jose-rsa', algorithm: SIGNING_ALG } as SigningAdapterConfig);
    this.publicKeyPem = publicKeyPem;
  }

  async sign(payload: CapabilityTokenPayload): Promise<string> {
    return new jose.SignJWT(payload as unknown as jose.JWTPayload)
      .setProtectedHeader({ alg: SIGNING_ALG, kid: this.keyId })
      .sign(this.privateKey);
  }

  async getPublicKey(): Promise<string> {
    return this.publicKeyPem;
  }

  async getKeyId(): Promise<string> {
    return this.keyId;
  }
}

// ── Identity stub ────────────────────────────────────────────────────────────

class StubIdentity extends IdentityAdapter {
  public readonly name = 'stub';

  constructor(private readonly ctx: UserContext) {
    super({ type: 'stub', name: 'stub' } as IdentityAdapterConfig);
  }

  async validateToken(_token: string): Promise<UserContext> {
    return this.ctx;
  }

  async getUserRoles(): Promise<string[]> {
    return this.ctx.roles;
  }
}

// ── Test setup ───────────────────────────────────────────────────────────────

async function createSigner(): Promise<JoseRsaSigner> {
  const { privateKey, publicKey } = await jose.generateKeyPair(SIGNING_ALG, { extractable: true });
  const publicKeyPem = await jose.exportSPKI(publicKey);
  return new JoseRsaSigner(privateKey, publicKeyPem, 'sg-it-key-1');
}

/** Role→capability policy used by the issuer (allows storage:// resources). */
const ISSUER_POLICY: RoleCapabilityPolicy = {
  default: {
    DataScientist: [
      { resource: 'storage://azure/datasets/reports', actions: ['read'] },
    ],
    StorageAdmin: [
      { resource: 'storage://azure/datasets/reports', actions: ['read', 'write'] },
      { resource: 'storage://azure/datasets/models', actions: ['read'] },
    ],
    ApiUser: [
      { resource: 'api://crm/customers', actions: ['read'] },
    ],
  },
};

/** Stubbed AzureStorageGrantMinter — no real Azure credentials required. */
function makeAzureMinter(): AzureStorageGrantMinter {
  return new AzureStorageGrantMinter({
    clientFactory: () => ({
      accountName: 'datasets',
      getUserDelegationKey: async () => ({}),
    }),
    signer: () => ({
      sasToken: 'stub-sas-token',
      url: 'https://datasets.blob.core.windows.net/reports/data.csv?stub-sas-token',
    }),
  });
}

function makeStorageGrantService(): StorageGrantService {
  return new StorageGrantService({
    enabled: true,
    minters: { 'azure-blob': makeAzureMinter() },
  });
}

// ── Harness ──────────────────────────────────────────────────────────────────

interface Harness {
  issuer: CapabilityIssuerService;
  signer: JoseRsaSigner;
  request: ReturnType<typeof supertest>;
}

async function buildHarness(opts: {
  roles?: string[];
  serviceOpts?: Partial<StorageGrantAppOptions>;
} = {}): Promise<Harness> {
  const signer = await createSigner();

  const userCtx: UserContext = {
    userId: 'user-sg-it-1',
    email: 'sg-it@example.com',
    roles: opts.roles ?? ['DataScientist'],
    tenantId: 'tenant-sg-it',
    claims: {},
  };

  const issuer = new CapabilityIssuerService(
    signer,
    new StubIdentity(userCtx),
    ISSUER_DID,
    900,
    createLogger('sg-it-issuer', 'test'),
    {
      policy: ISSUER_POLICY,
      gatewayAudience: AUDIENCE,
    },
  );

  const publicKey = await jose.importSPKI(signer.publicKeyPem, SIGNING_ALG);

  const app = createStorageGrantApp({
    issuerDid: ISSUER_DID,
    audience: AUDIENCE,
    verificationKey: publicKey,
    storageGrantService: makeStorageGrantService(),
    logger: createLogger('sg-it-app', 'test'),
    environment: 'test',
    rateLimitMaxPerWindow: 0, // disable rate limiting in tests
    ...opts.serviceOpts,
  });

  return { issuer, signer, request: supertest(app) };
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('storage-grant-service integration: issuer ↔ service wire format', () => {
  it('1. issues grants for an issuer-signed token with a storage:// capability', async () => {
    const h = await buildHarness();
    const result = await h.issuer.issueCapabilityFromUserContext({
      userContext: {
        userId: 'user-sg-it-1',
        email: 'sg-it@example.com',
        roles: ['DataScientist'],
        tenantId: 'tenant-sg-it',
        claims: {},
      },
      agentId: AGENT_ID,
      requestedCapabilities: [
        { resource: 'storage://azure/datasets/reports', actions: ['read'] },
      ],
    });

    const res = await h.request
      .post('/api/v1/storage-grants')
      .set('Authorization', `Bearer ${result.token}`)
      .send({ agentId: AGENT_ID });

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.grants)).toBe(true);
    expect(res.body.grants.length).toBeGreaterThan(0);
    expect(res.body.grants[0]?.provider).toBe('azure-blob');
  });

  it('2. token without any storage:// capabilities → 403 INSUFFICIENT_PERMISSIONS', async () => {
    const h = await buildHarness({ roles: ['ApiUser'] });
    const result = await h.issuer.issueCapabilityFromUserContext({
      userContext: {
        userId: 'user-sg-it-1',
        email: 'sg-it@example.com',
        roles: ['ApiUser'],
        tenantId: 'tenant-sg-it',
        claims: {},
      },
      agentId: AGENT_ID,
      requestedCapabilities: [
        { resource: 'api://crm/customers', actions: ['read'] },
      ],
    });

    const res = await h.request
      .post('/api/v1/storage-grants')
      .set('Authorization', `Bearer ${result.token}`)
      .send({ agentId: AGENT_ID });

    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('INSUFFICIENT_PERMISSIONS');
  });

  it('3. token signed by a different key pair → 401 INVALID_TOKEN', async () => {
    // Build a rogue signer with a different key pair.
    const rogueSigner = await createSigner();
    const rogueIssuer = new CapabilityIssuerService(
      rogueSigner,
      new StubIdentity({ userId: 'u', email: 'u@e.com', roles: ['DataScientist'], tenantId: 't', claims: {} }),
      ISSUER_DID,
      900,
      createLogger('rogue-sg-issuer', 'test'),
      { policy: ISSUER_POLICY, gatewayAudience: AUDIENCE },
    );

    // Build a separate app trusting a DIFFERENT (good) signer's key.
    const goodSigner = await createSigner();
    const goodPublicKey = await jose.importSPKI(goodSigner.publicKeyPem, SIGNING_ALG);
    const app = createStorageGrantApp({
      issuerDid: ISSUER_DID,
      audience: AUDIENCE,
      verificationKey: goodPublicKey, // trusts the good key
      storageGrantService: makeStorageGrantService(),
      logger: createLogger('sg-it-app', 'test'),
      environment: 'test',
      rateLimitMaxPerWindow: 0,
    });

    // Token signed by rogueSigner — the app rejects it because it trusts goodSigner.
    const rogueResult = await rogueIssuer.issueCapabilityFromUserContext({
      userContext: { userId: 'u', email: 'u@e.com', roles: ['DataScientist'], tenantId: 't', claims: {} },
      agentId: AGENT_ID,
      requestedCapabilities: [
        { resource: 'storage://azure/datasets/reports', actions: ['read'] },
      ],
    });

    const res = await supertest(app)
      .post('/api/v1/storage-grants')
      .set('Authorization', `Bearer ${rogueResult.token}`)
      .send({ agentId: AGENT_ID });

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('INVALID_TOKEN');
  });

  it('4. expired token → 401 EXPIRED_TOKEN', async () => {
    const h = await buildHarness();
    const now = Math.floor(Date.now() / 1000);
    const expiredToken = await h.signer.sign({
      iss: ISSUER_DID,
      sub: AGENT_ID,
      aud: AUDIENCE,
      iat: now - 120,
      exp: now - 60,
      jti: 'expired-sg-it-token',
      schemaVersion: '1.0',
      capabilities: [
        { resource: 'storage://azure/datasets/reports', actions: ['read'] },
      ],
      authorizedBy: { userId: 'user-sg-it-1', roles: ['DataScientist'], tenantId: 'tenant-sg-it' },
    } as unknown as CapabilityTokenPayload);

    const res = await h.request
      .post('/api/v1/storage-grants')
      .set('Authorization', `Bearer ${expiredToken}`)
      .send({ agentId: AGENT_ID });

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('EXPIRED_TOKEN');
  });

  it('5. token with wrong audience → 401', async () => {
    const h = await buildHarness();
    const now = Math.floor(Date.now() / 1000);
    const wrongAudToken = await h.signer.sign({
      iss: ISSUER_DID,
      sub: AGENT_ID,
      aud: 'wrong-service',
      iat: now,
      exp: now + 900,
      jti: 'wrong-aud-sg-token',
      schemaVersion: '1.0',
      capabilities: [
        { resource: 'storage://azure/datasets/reports', actions: ['read'] },
      ],
      authorizedBy: { userId: 'user-sg-it-1', roles: ['DataScientist'], tenantId: 'tenant-sg-it' },
    } as unknown as CapabilityTokenPayload);

    const res = await h.request
      .post('/api/v1/storage-grants')
      .set('Authorization', `Bearer ${wrongAudToken}`)
      .send({ agentId: AGENT_ID });

    expect(res.status).toBe(401);
  });

  it('6. mixed token (storage:// + api://) — api:// capabilities are ignored, storage:// are processed', async () => {
    const combinedPolicy = {
      default: {
        DataScientist: [
          { resource: 'storage://azure/datasets/reports', actions: ['read'] },
          { resource: 'api://analytics/dashboard', actions: ['read'] },
        ],
      },
    };
    const mixedSigner = await createSigner();
    const mixedPublicKey = await jose.importSPKI(mixedSigner.publicKeyPem, SIGNING_ALG);
    const issuer = new CapabilityIssuerService(
      mixedSigner,
      new StubIdentity({ userId: 'u', email: 'u@e.com', roles: ['DataScientist'], tenantId: 't', claims: {} }),
      ISSUER_DID,
      900,
      createLogger('mixed-sg-issuer', 'test'),
      { policy: combinedPolicy, gatewayAudience: AUDIENCE },
    );
    const app = createStorageGrantApp({
      issuerDid: ISSUER_DID,
      audience: AUDIENCE,
      verificationKey: mixedPublicKey,
      storageGrantService: makeStorageGrantService(),
      logger: createLogger('mixed-sg-app', 'test'),
      environment: 'test',
      rateLimitMaxPerWindow: 0,
    });

    const result = await issuer.issueCapabilityFromUserContext({
      userContext: { userId: 'u', email: 'u@e.com', roles: ['DataScientist'], tenantId: 't', claims: {} },
      agentId: AGENT_ID,
      requestedCapabilities: [
        { resource: 'storage://azure/datasets/reports', actions: ['read'] },
        { resource: 'api://analytics/dashboard', actions: ['read'] },
      ],
    });

    const res = await supertest(app)
      .post('/api/v1/storage-grants')
      .set('Authorization', `Bearer ${result.token}`)
      .send({ agentId: AGENT_ID });

    // storage:// capability present → 200
    expect(res.status).toBe(200);
    expect(res.body.grants.length).toBeGreaterThan(0);
    // api:// capability should NOT produce a grant
    const grants = res.body.grants as Array<{ provider: string }>;
    expect(grants.every((g) => g.provider === 'azure-blob')).toBe(true);
  });

  it('7. multiple storage:// capabilities in a single token → grants for each', async () => {
    const h = await buildHarness({ roles: ['StorageAdmin'] });
    const result = await h.issuer.issueCapabilityFromUserContext({
      userContext: {
        userId: 'user-sg-it-1',
        email: 'sg-it@example.com',
        roles: ['StorageAdmin'],
        tenantId: 'tenant-sg-it',
        claims: {},
      },
      agentId: AGENT_ID,
      requestedCapabilities: [
        { resource: 'storage://azure/datasets/reports', actions: ['read'] },
        { resource: 'storage://azure/datasets/models', actions: ['read'] },
      ],
    });

    const res = await h.request
      .post('/api/v1/storage-grants')
      .set('Authorization', `Bearer ${result.token}`)
      .send({ agentId: AGENT_ID });

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.grants)).toBe(true);
    // Both capabilities have matching storage:// URIs → at least two grants
    expect(res.body.grants.length).toBeGreaterThanOrEqual(2);
  });

  it('8. GET /health → 200 healthy', async () => {
    const h = await buildHarness();
    const res = await h.request.get('/health');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: 'healthy', service: 'storage-grant-service' });
  });

  it('9. GET /.well-known/storage-grant-service → 200 with service metadata', async () => {
    const h = await buildHarness();
    const res = await h.request.get('/.well-known/storage-grant-service');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      service: 'storage-grant-service',
      issuerDid: ISSUER_DID,
      audience: AUDIENCE,
      environment: 'test',
    });
    expect(res.body.endpoints?.storageGrants).toBe('/api/v1/storage-grants');
  });

  it('10. GET /health/ready returns 503 when the service is disabled', async () => {
    const h = await buildHarness({
      serviceOpts: {
        storageGrantService: new StorageGrantService({ enabled: false }),
      },
    });
    const res = await h.request.get('/health/ready');
    expect(res.status).toBe(503);
    expect(res.body.status).toBe('not_ready');
  });
});
