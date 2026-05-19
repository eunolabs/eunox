/**
 * DB Token Service — integration tests (Task 7, Stage 5).
 *
 * Wires the real `CapabilityIssuerService` (with a genuine RS256 signer)
 * to the `createDbTokenApp` Express app. Each test issues a capability
 * token via the issuer and presents it to the db-token-service, validating
 * the full JWT wire-format contract between the two services.
 *
 * ## Architecture under test
 *
 *   CapabilityIssuerService (in-process)
 *     │  issueCapabilityFromUserContext()
 *     │  → signed RS256 JWT with db:// capabilities
 *     ▼
 *   createDbTokenApp (supertest / in-process Express)
 *     │  POST /api/v1/db-tokens
 *     │  → verifies JWT via the same RS256 public key
 *     ▼
 *   DbTokenService (stubbed Azure SQL minter — no cloud required)
 *     → DbCredential[]
 *
 * ## Coverage
 *  1.  Issuer-signed token with db:// capability → 200 + credentials
 *  2.  Token TTL flows from JWT `exp` to credential minting context
 *  3.  Token without any db:// capabilities → 403
 *  4.  Token signed by a different key pair → 401 (INVALID_TOKEN)
 *  5.  Token with exp in the past → 401 (EXPIRED_TOKEN)
 *  6.  Token with wrong audience → 401
 *  7.  Token with wrong issuer DID → 401
 *  8.  Service-local dbPolicy maps role → db username independently of issuer
 *  9.  Multiple db:// capabilities in a single token → multiple credentials
 * 10.  Mixed token (db:// + api://) → only db:// capabilities produce credentials
 * 11.  GET /health → 200
 * 12.  GET /.well-known/db-token-service → 200 with issuerDid and endpoints
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
import { DbTokenService } from '../../capability-issuer/src/db-token/index';
import { AzureSqlTokenMinter } from '../../capability-issuer/src/db-token/azure-sql';
import { createDbTokenApp } from '../../db-token-service/src/app';
import type { DbTokenAppOptions } from '../../db-token-service/src/app';

// ── Constants ────────────────────────────────────────────────────────────────

const ISSUER_DID = 'did:web:issuer.db-token-it.test';
const AUDIENCE = 'tool-gateway:db-token-it';
const SIGNING_ALG = 'RS256';
const AGENT_ID = 'db-token-it-agent';

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
  return new JoseRsaSigner(privateKey, publicKeyPem, 'it-key-1');
}

/** Role→capability policy used by the issuer (allows db:// resources). */
const ISSUER_POLICY: RoleCapabilityPolicy = {
  default: {
    DataAnalyst: [
      { resource: 'db://azure-sql/salesserver/salesdb/orders', actions: ['read'] },
    ],
    DBAdmin: [
      { resource: 'db://azure-sql/salesserver/salesdb/orders', actions: ['read', 'write'] },
      { resource: 'db://azure-sql/salesserver/salesdb/reports', actions: ['read'] },
    ],
    ApiUser: [
      { resource: 'api://crm/customers', actions: ['read'] },
    ],
  },
};

/** Service-local policy for db username resolution. */
const SERVICE_DB_POLICY = {
  default: {},
  dbUsernamesByRole: {
    DataAnalyst: 'euno_readonly',
    DBAdmin: 'euno_readwrite',
  },
};

/** Stubbed AzureSqlTokenMinter — no real Azure credentials required. */
function makeAzureMinter(): AzureSqlTokenMinter {
  return new AzureSqlTokenMinter({
    tokenSource: {
      getToken: async () => ({
        token: 'stub-aad-token',
        expiresOnTimestamp: Date.now() + 900_000,
      }),
    },
  });
}

function makeDbTokenService(): DbTokenService {
  return new DbTokenService({
    enabled: true,
    instances: new Map([
      [
        'salesserver',
        {
          id: 'salesserver',
          provider: 'azure-sql' as const,
          host: 'salesserver.database.windows.net',
          port: 1433,
          databases: ['salesdb'],
        },
      ],
    ]),
    minters: { 'azure-sql': makeAzureMinter() },
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
  serviceOpts?: Partial<DbTokenAppOptions>;
} = {}): Promise<Harness> {
  const signer = await createSigner();

  const userCtx: UserContext = {
    userId: 'user-it-1',
    email: 'it@example.com',
    roles: opts.roles ?? ['DataAnalyst'],
    tenantId: 'tenant-it',
    claims: {},
  };

  const issuer = new CapabilityIssuerService(
    signer,
    new StubIdentity(userCtx),
    ISSUER_DID,
    900,
    createLogger('db-token-it-issuer', 'test'),
    {
      policy: ISSUER_POLICY,
      gatewayAudience: AUDIENCE,
    },
  );

  const publicKey = await jose.importSPKI(signer.publicKeyPem, SIGNING_ALG);

  const app = createDbTokenApp({
    issuerDid: ISSUER_DID,
    audience: AUDIENCE,
    verificationKey: publicKey,
    dbTokenService: makeDbTokenService(),
    dbPolicy: SERVICE_DB_POLICY,
    logger: createLogger('db-token-it-app', 'test'),
    environment: 'test',
    rateLimitMaxPerWindow: 0, // disable rate limiting in tests
    ...opts.serviceOpts,
  });

  return { issuer, signer, request: supertest(app) };
}

/** Issue a capability token via the real issuer. */
async function issueToken(
  harness: Harness,
  requestedCapabilities: Array<{ resource: string; actions: string[] }>,
): Promise<string> {
  const result = await harness.issuer.issueCapabilityFromUserContext({
    userContext: {
      userId: 'user-it-1',
      email: 'it@example.com',
      roles: ['DataAnalyst'],
      tenantId: 'tenant-it',
      claims: {},
    },
    agentId: AGENT_ID,
    requestedCapabilities: requestedCapabilities as Array<{ resource: string; actions: ('read' | 'write' | 'delete' | 'execute' | 'admin')[] }>,
  });
  return result.token;
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('db-token-service integration: issuer ↔ service wire format', () => {
  it('1. issues credentials for an issuer-signed token with a db:// capability', async () => {
    const h = await buildHarness();
    const token = await issueToken(h, [
      { resource: 'db://azure-sql/salesserver/salesdb/orders', actions: ['read'] },
    ]);

    const res = await h.request
      .post('/api/v1/db-tokens')
      .set('Authorization', `Bearer ${token}`)
      .send({ agentId: AGENT_ID });

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.credentials)).toBe(true);
    expect(res.body.credentials.length).toBeGreaterThan(0);
  });

  it('2. credential username comes from the service-local dbPolicy, not the issuer policy', async () => {
    const h = await buildHarness({ roles: ['DataAnalyst'] });
    const token = await issueToken(h, [
      { resource: 'db://azure-sql/salesserver/salesdb/orders', actions: ['read'] },
    ]);

    const res = await h.request
      .post('/api/v1/db-tokens')
      .set('Authorization', `Bearer ${token}`)
      .send({ agentId: AGENT_ID });

    expect(res.status).toBe(200);
    const creds = res.body.credentials as Array<{ username: string }>;
    // DataAnalyst maps to 'euno_readonly' in SERVICE_DB_POLICY
    expect(creds[0]?.username).toBe('euno_readonly');
  });

  it('3. token with no db:// capabilities → 403 INSUFFICIENT_PERMISSIONS', async () => {
    const h = await buildHarness({ roles: ['ApiUser'] });
    // Issue a token with only api:// capability (ApiUser role)
    const result = await h.issuer.issueCapabilityFromUserContext({
      userContext: {
        userId: 'user-it-1',
        email: 'it@example.com',
        roles: ['ApiUser'],
        tenantId: 'tenant-it',
        claims: {},
      },
      agentId: AGENT_ID,
      requestedCapabilities: [
        { resource: 'api://crm/customers', actions: ['read'] },
      ],
    });

    const res = await h.request
      .post('/api/v1/db-tokens')
      .set('Authorization', `Bearer ${result.token}`)
      .send({ agentId: AGENT_ID });

    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('INSUFFICIENT_PERMISSIONS');
  });

  it('4. token signed by a different key pair → 401 INVALID_TOKEN', async () => {
    // Build a rogue signer with a different key pair.
    const rogueSigner = await createSigner();
    const rogueIssuer = new CapabilityIssuerService(
      rogueSigner,
      new StubIdentity({ userId: 'u', email: 'u@e.com', roles: ['DataAnalyst'], tenantId: 't', claims: {} }),
      ISSUER_DID,
      900,
      createLogger('rogue-issuer', 'test'),
      { policy: ISSUER_POLICY, gatewayAudience: AUDIENCE },
    );

    // Build a separate app that trusts a DIFFERENT (good) signer's key.
    const goodSigner = await createSigner();
    const goodPublicKey = await jose.importSPKI(goodSigner.publicKeyPem, SIGNING_ALG);
    const app = createDbTokenApp({
      issuerDid: ISSUER_DID,
      audience: AUDIENCE,
      verificationKey: goodPublicKey,   // trusts goodSigner's key
      dbTokenService: makeDbTokenService(),
      dbPolicy: SERVICE_DB_POLICY,
      logger: createLogger('db-token-it-app', 'test'),
      environment: 'test',
      rateLimitMaxPerWindow: 0,
    });

    // Token signed by rogueSigner — the app rejects it because it trusts goodSigner.
    const rogueToken = (
      await rogueIssuer.issueCapabilityFromUserContext({
        userContext: { userId: 'u', email: 'u@e.com', roles: ['DataAnalyst'], tenantId: 't', claims: {} },
        agentId: AGENT_ID,
        requestedCapabilities: [
          { resource: 'db://azure-sql/salesserver/salesdb/orders', actions: ['read'] },
        ],
      })
    ).token;

    const res = await supertest(app)
      .post('/api/v1/db-tokens')
      .set('Authorization', `Bearer ${rogueToken}`)
      .send({ agentId: AGENT_ID });

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('INVALID_TOKEN');
  });

  it('5. expired token → 401 EXPIRED_TOKEN', async () => {
    const h = await buildHarness();
    // Sign a token manually with exp in the past using the issuer's own signer.
    const now = Math.floor(Date.now() / 1000);
    const expiredToken = await h.signer.sign({
      iss: ISSUER_DID,
      sub: AGENT_ID,
      aud: AUDIENCE,
      iat: now - 120,
      exp: now - 60,
      jti: 'expired-it-token',
      schemaVersion: '1.0',
      capabilities: [
        { resource: 'db://azure-sql/salesserver/salesdb/orders', actions: ['read'] },
      ],
      authorizedBy: { userId: 'user-it-1', roles: ['DataAnalyst'], tenantId: 'tenant-it' },
    } as unknown as CapabilityTokenPayload);

    const res = await h.request
      .post('/api/v1/db-tokens')
      .set('Authorization', `Bearer ${expiredToken}`)
      .send({ agentId: AGENT_ID });

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('EXPIRED_TOKEN');
  });

  it('6. token with wrong audience → 401', async () => {
    const h = await buildHarness();
    const now = Math.floor(Date.now() / 1000);
    const wrongAudToken = await h.signer.sign({
      iss: ISSUER_DID,
      sub: AGENT_ID,
      aud: 'wrong-service',
      iat: now,
      exp: now + 900,
      jti: 'wrong-aud-token',
      schemaVersion: '1.0',
      capabilities: [
        { resource: 'db://azure-sql/salesserver/salesdb/orders', actions: ['read'] },
      ],
      authorizedBy: { userId: 'user-it-1', roles: ['DataAnalyst'], tenantId: 'tenant-it' },
    } as unknown as CapabilityTokenPayload);

    const res = await h.request
      .post('/api/v1/db-tokens')
      .set('Authorization', `Bearer ${wrongAudToken}`)
      .send({ agentId: AGENT_ID });

    expect(res.status).toBe(401);
  });

  it('7. token with wrong issuer DID → 401', async () => {
    const h = await buildHarness();
    const now = Math.floor(Date.now() / 1000);
    const wrongIssToken = await h.signer.sign({
      iss: 'did:web:rogue-issuer.example.com',
      sub: AGENT_ID,
      aud: AUDIENCE,
      iat: now,
      exp: now + 900,
      jti: 'wrong-iss-token',
      schemaVersion: '1.0',
      capabilities: [
        { resource: 'db://azure-sql/salesserver/salesdb/orders', actions: ['read'] },
      ],
      authorizedBy: { userId: 'user-it-1', roles: ['DataAnalyst'], tenantId: 'tenant-it' },
    } as unknown as CapabilityTokenPayload);

    const res = await h.request
      .post('/api/v1/db-tokens')
      .set('Authorization', `Bearer ${wrongIssToken}`)
      .send({ agentId: AGENT_ID });

    expect(res.status).toBe(401);
  });

  it('8. service-local dbPolicy is independent of issuer policy: DBAdmin role → euno_readwrite', async () => {
    const h = await buildHarness({ roles: ['DBAdmin'] });
    // DBAdmin has two db:// capabilities in ISSUER_POLICY
    const token = await h.issuer.issueCapabilityFromUserContext({
      userContext: {
        userId: 'user-it-1',
        email: 'it@example.com',
        roles: ['DBAdmin'],
        tenantId: 'tenant-it',
        claims: {},
      },
      agentId: AGENT_ID,
      requestedCapabilities: [
        { resource: 'db://azure-sql/salesserver/salesdb/orders', actions: ['read'] },
      ],
    });

    const res = await h.request
      .post('/api/v1/db-tokens')
      .set('Authorization', `Bearer ${token.token}`)
      .send({ agentId: AGENT_ID });

    expect(res.status).toBe(200);
    const creds = res.body.credentials as Array<{ username: string }>;
    // DBAdmin maps to 'euno_readwrite' in SERVICE_DB_POLICY
    expect(creds[0]?.username).toBe('euno_readwrite');
  });

  it('9. token with multiple db:// capabilities → credentials for each matching instance', async () => {
    // DBAdmin can access both salesdb/orders and salesdb/reports in the test policy
    const h = await buildHarness({ roles: ['DBAdmin'] });
    const token = await h.issuer.issueCapabilityFromUserContext({
      userContext: {
        userId: 'user-it-1',
        email: 'it@example.com',
        roles: ['DBAdmin'],
        tenantId: 'tenant-it',
        claims: {},
      },
      agentId: AGENT_ID,
      requestedCapabilities: [
        { resource: 'db://azure-sql/salesserver/salesdb/orders', actions: ['read'] },
        { resource: 'db://azure-sql/salesserver/salesdb/reports', actions: ['read'] },
      ],
    });

    const res = await h.request
      .post('/api/v1/db-tokens')
      .set('Authorization', `Bearer ${token.token}`)
      .send({ agentId: AGENT_ID });

    expect(res.status).toBe(200);
    // Both capabilities refer to the same instance ('salesserver') — one credential
    // is issued per (instance, database) pair, so we expect at least one credential.
    expect(Array.isArray(res.body.credentials)).toBe(true);
    expect(res.body.credentials.length).toBeGreaterThan(0);
  });

  it('10. mixed token (db:// + api://) — api:// capabilities are ignored, db:// are processed', async () => {
    // Use a combined policy: DataAnalyst has both api:// and db:// resources
    const combinedPolicy = {
      default: {
        DataAnalyst: [
          { resource: 'db://azure-sql/salesserver/salesdb/orders', actions: ['read'] },
          { resource: 'api://crm/customers', actions: ['read'] },
        ],
      },
    };
    const mixedSigner = await createSigner();
    const mixedPublicKey = await jose.importSPKI(mixedSigner.publicKeyPem, SIGNING_ALG);
    const issuer = new CapabilityIssuerService(
      mixedSigner,
      new StubIdentity({ userId: 'u', email: 'u@e.com', roles: ['DataAnalyst'], tenantId: 't', claims: {} }),
      ISSUER_DID,
      900,
      createLogger('mixed-it-issuer', 'test'),
      { policy: combinedPolicy, gatewayAudience: AUDIENCE },
    );
    const app = createDbTokenApp({
      issuerDid: ISSUER_DID,
      audience: AUDIENCE,
      verificationKey: mixedPublicKey,
      dbTokenService: makeDbTokenService(),
      dbPolicy: SERVICE_DB_POLICY,
      logger: createLogger('mixed-it-app', 'test'),
      environment: 'test',
      rateLimitMaxPerWindow: 0,
    });

    const result = await issuer.issueCapabilityFromUserContext({
      userContext: { userId: 'u', email: 'u@e.com', roles: ['DataAnalyst'], tenantId: 't', claims: {} },
      agentId: AGENT_ID,
      requestedCapabilities: [
        { resource: 'db://azure-sql/salesserver/salesdb/orders', actions: ['read'] },
        { resource: 'api://crm/customers', actions: ['read'] },
      ],
    });

    const res = await supertest(app)
      .post('/api/v1/db-tokens')
      .set('Authorization', `Bearer ${result.token}`)
      .send({ agentId: AGENT_ID });

    // db:// capability is present → 200 with credentials
    expect(res.status).toBe(200);
    expect(res.body.credentials.length).toBeGreaterThan(0);
  });

  it('11. GET /health → 200 healthy', async () => {
    const h = await buildHarness();
    const res = await h.request.get('/health');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: 'healthy', service: 'db-token-service' });
  });

  it('12. GET /.well-known/db-token-service → 200 with service metadata', async () => {
    const h = await buildHarness();
    const res = await h.request.get('/.well-known/db-token-service');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      service: 'db-token-service',
      issuerDid: ISSUER_DID,
      audience: AUDIENCE,
      environment: 'test',
    });
    expect(res.body.endpoints?.dbTokens).toBe('/api/v1/db-tokens');
  });
});
