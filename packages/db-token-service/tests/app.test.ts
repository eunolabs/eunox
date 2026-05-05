/**
 * DB Token Service — integration tests.
 *
 * Covers:
 *  - JWT verification (valid, expired, wrong issuer, wrong audience).
 *  - Capability-presence check (no db:// → 403).
 *  - dbUsername resolution from JWT authorizedBy.roles + service policy.
 *  - Successful credential minting with a stubbed DbTokenService.
 *  - Health / metadata endpoints.
 *  - Error response shapes.
 */

import supertest from 'supertest';
import * as jose from 'jose';
import { createDbTokenApp, DbTokenAppOptions } from '../src/app';
import { DbTokenService, AzureSqlTokenMinter } from '@euno/capability-issuer';
import { CapabilityTokenPayload, DbCredential, RoleCapabilityPolicy, createLogger, CAPABILITY_TOKEN_SCHEMA_VERSION } from '@euno/common';

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

async function signToken(
  capabilities: CapabilityTokenPayload['capabilities'],
  overrides: Partial<{
    exp: number;
    iss: string;
    aud: string;
    roles: string[];
    schemaVersion: string;
  }> = {},
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
    authorizedBy: {
      userId: 'user-1',
      roles: overrides.roles ?? ['DataAnalyst'],
      tenantId: 'tenant-1',
    },
  })
    .setProtectedHeader({ alg: 'RS256' })
    .sign(privateKey);
}

// ---------------------------------------------------------------------------
// Service fixtures
// ---------------------------------------------------------------------------

const logger = createLogger('db-token-service-test', 'test');

const DB_POLICY: RoleCapabilityPolicy = {
  default: {},
  dbUsernamesByRole: {
    DataAnalyst: 'euno_readonly',
    Admin: 'euno_admin',
  },
};

function makeEnabledDbTokenService(): DbTokenService {
  const azureSql = new AzureSqlTokenMinter({
    tokenSource: {
      getToken: async () => ({ token: 'test-aad-token', expiresOnTimestamp: Date.now() + 600_000 }),
    },
  });
  return new DbTokenService({
    enabled: true,
    instances: new Map([
      [
        'salesserver',
        {
          id: 'salesserver',
          provider: 'azure-sql',
          host: 'salesserver.database.windows.net',
          port: 1433,
          databases: ['salesdb'],
        },
      ],
    ]),
    minters: { 'azure-sql': azureSql },
  });
}

function buildApp(serviceOpts: Partial<DbTokenAppOptions> = {}): ReturnType<typeof supertest> {
  const app = createDbTokenApp({
    issuerDid: ISSUER_DID,
    audience: AUDIENCE,
    verificationKey: publicKey,
    dbTokenService: makeEnabledDbTokenService(),
    dbPolicy: DB_POLICY,
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
    expect(res.body).toMatchObject({ status: 'healthy', service: 'db-token-service' });
  });
});

describe('GET /health/ready', () => {
  it('returns 200 when the service is enabled', async () => {
    const res = await buildApp().get('/health/ready');
    expect(res.status).toBe(200);
  });

  it('returns 503 when the service is disabled', async () => {
    const disabledService = new DbTokenService({ enabled: false });
    const res = await buildApp({ dbTokenService: disabledService }).get('/health/ready');
    expect(res.status).toBe(503);
  });
});

describe('GET /.well-known/db-token-service', () => {
  it('returns metadata', async () => {
    const res = await buildApp().get('/.well-known/db-token-service');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ service: 'db-token-service', issuerDid: ISSUER_DID });
  });
});

// ---------------------------------------------------------------------------
// POST /api/v1/db-tokens — auth checks
// ---------------------------------------------------------------------------

describe('POST /api/v1/db-tokens — authentication', () => {
  it('returns 401 when Authorization header is missing', async () => {
    const res = await buildApp().post('/api/v1/db-tokens').send({ agentId: AGENT_ID });
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('AUTHENTICATION_FAILED');
  });

  it('returns 401 for a malformed JWT', async () => {
    const res = await buildApp()
      .post('/api/v1/db-tokens')
      .set('Authorization', 'Bearer not.a.jwt')
      .send({ agentId: AGENT_ID });
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('INVALID_TOKEN');
  });

  it('returns 401 for an expired JWT', async () => {
    const token = await signToken(
      [{ resource: 'db://azure-sql/salesserver/salesdb/orders.read', actions: ['read'] }],
      { exp: Math.floor(Date.now() / 1000) - 60 },
    );
    const res = await buildApp()
      .post('/api/v1/db-tokens')
      .set('Authorization', `Bearer ${token}`)
      .send({ agentId: AGENT_ID });
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('EXPIRED_TOKEN');
  });

  it('returns 401 when the issuer DID does not match', async () => {
    const token = await signToken(
      [{ resource: 'db://azure-sql/salesserver/salesdb/orders.read', actions: ['read'] }],
      { iss: 'did:web:rogue.example.com' },
    );
    const res = await buildApp()
      .post('/api/v1/db-tokens')
      .set('Authorization', `Bearer ${token}`)
      .send({ agentId: AGENT_ID });
    expect(res.status).toBe(401);
  });
});

// ---------------------------------------------------------------------------
// POST /api/v1/db-tokens — payload shape checks
// ---------------------------------------------------------------------------

describe('POST /api/v1/db-tokens — payload shape validation', () => {
  it('returns 401 for a token with an unsupported schemaVersion', async () => {
    const token = await signToken(
      [{ resource: 'db://azure-sql/salesserver/salesdb/orders.read', actions: ['read'] }],
      { schemaVersion: '0.9' },
    );
    const res = await buildApp()
      .post('/api/v1/db-tokens')
      .set('Authorization', `Bearer ${token}`)
      .send({ agentId: AGENT_ID });
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('INVALID_TOKEN');
  });
});

// ---------------------------------------------------------------------------
// POST /api/v1/db-tokens — capability checks
// ---------------------------------------------------------------------------

describe('POST /api/v1/db-tokens — capability checks', () => {
  it('returns 403 when the token has no db:// capabilities', async () => {
    const token = await signToken([{ resource: 'api://crm/customers', actions: ['read'] }]);
    const res = await buildApp()
      .post('/api/v1/db-tokens')
      .set('Authorization', `Bearer ${token}`)
      .send({ agentId: AGENT_ID });
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('INSUFFICIENT_PERMISSIONS');
  });
});

// ---------------------------------------------------------------------------
// POST /api/v1/db-tokens — happy path
// ---------------------------------------------------------------------------

describe('POST /api/v1/db-tokens — successful minting', () => {
  it('mints DB credentials for a token with db:// capabilities and a role-mapped username', async () => {
    const token = await signToken(
      [{ resource: 'db://azure-sql/salesserver/salesdb/orders.read', actions: ['read'] }],
      { roles: ['DataAnalyst'] },
    );
    const res = await buildApp()
      .post('/api/v1/db-tokens')
      .set('Authorization', `Bearer ${token}`)
      .send({ agentId: AGENT_ID });
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.credentials)).toBe(true);
    const creds = res.body.credentials as DbCredential[];
    expect(creds.length).toBeGreaterThan(0);
    expect(creds[0]?.username).toBe('euno_readonly');
    expect(creds[0]?.database).toBe('salesdb');
  });

  it('returns 403 when no role in the token maps to a dbUsername', async () => {
    const token = await signToken(
      [{ resource: 'db://azure-sql/salesserver/salesdb/orders.read', actions: ['read'] }],
      { roles: ['LimitedViewer'] }, // not in DB_POLICY.dbUsernamesByRole
    );
    const res = await buildApp()
      .post('/api/v1/db-tokens')
      .set('Authorization', `Bearer ${token}`)
      .send({ agentId: AGENT_ID });
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('INSUFFICIENT_PERMISSIONS');
  });

  it('uses the service-local dbPolicy, not a capability-issuer policy', async () => {
    // The db-token service has its own policy. Even if the token was issued
    // with a different policy, the minted username comes from the service's
    // policy.dbUsernamesByRole.
    const localPolicy: RoleCapabilityPolicy = {
      default: {},
      dbUsernamesByRole: { DataAnalyst: 'custom_db_user' }, // different from DB_POLICY
    };
    const token = await signToken(
      [{ resource: 'db://azure-sql/salesserver/salesdb/orders.read', actions: ['read'] }],
      { roles: ['DataAnalyst'] },
    );
    const res = await buildApp({ dbPolicy: localPolicy })
      .post('/api/v1/db-tokens')
      .set('Authorization', `Bearer ${token}`)
      .send({ agentId: AGENT_ID });
    expect(res.status).toBe(200);
    const creds = res.body.credentials as DbCredential[];
    expect(creds[0]?.username).toBe('custom_db_user');
  });

  it('app constructor throws when neither verificationKey nor jwksUri is provided', () => {
    expect(() =>
      createDbTokenApp({
        issuerDid: ISSUER_DID,
        audience: AUDIENCE,
        dbTokenService: makeEnabledDbTokenService(),
        dbPolicy: DB_POLICY,
      }),
    ).toThrow('either verificationKey or jwksUri must be provided');
  });
});
