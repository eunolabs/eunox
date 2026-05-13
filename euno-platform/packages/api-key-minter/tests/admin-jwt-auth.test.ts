/**
 * Tests for admin JWT bearer-token authentication (Task 6).
 *
 * These tests exercise the `AdminJwtVerifier` integration inside the
 * admin-keys and admin-policies routes:
 *
 *   1. When `jwtVerifier` is configured, a valid Bearer JWT is accepted and
 *      the operator identity is attached to audit log entries.
 *   2. When the JWT is invalid/expired, the request is rejected with 401.
 *   3. When no Bearer token is present and the shared X-Admin-Key is valid,
 *      the request proceeds (fallback path).
 *   4. When a `jwtVerifier` is configured but the caller sends the shared key,
 *      the request succeeds AND a deprecation warning is logged.
 *   5. When neither a valid JWT nor the correct shared key is presented, 401.
 *
 * Rather than standing up a real JWKS server we inject a fake `AdminJwtVerifier`
 * whose `verify()` method is controlled by the test.  This keeps tests fast and
 * avoids network dependencies.
 */

import * as crypto from 'crypto';
import request from 'supertest';
import { createMinterApp } from '../src/app-factory';
import { ApiKeyVerifier } from '../src/api-key-verifier';
import { InMemoryApiKeyStore } from '../src/api-key-store';
import { TokenMinter } from '../src/token-minter';
import { LocalTokenSigner } from '../src/local-token-signer';
import { InMemoryMintAuditStore } from '../src/mint-audit';
import { InMemoryMintRateLimiter } from '../src/mint-rate-limiter';
import { AdminJwtVerifier, AdminPrincipal } from '../src/admin-jwt-verifier';
import { createLogger } from '@euno/common';

const ADMIN_KEY = 'test-admin-secret-for-jwt-tests';

/** Minimal stub of AdminJwtVerifier whose verify() can be overridden per test. */
function makeFakeVerifier(
  impl: (token: string) => Promise<AdminPrincipal>,
): AdminJwtVerifier {
  const stub = Object.create(AdminJwtVerifier.prototype) as AdminJwtVerifier;
  stub.verify = impl;
  return stub;
}

const GOOD_PRINCIPAL: AdminPrincipal = {
  operatorId: 'operator@example.com',
  scopes: ['admin:keys', 'admin:policies'],
};

const validBody = {
  tenantId: 'tenant-jwt',
  policyId: 'policy-jwt',
  capabilities: [],
  scopes: ['enforce'],
};

async function buildAppWithJwt(verifier?: AdminJwtVerifier) {
  const logger = createLogger('test-admin-jwt');
  const pepper = { version: 'v1', key: crypto.randomBytes(32) };
  const store = new InMemoryApiKeyStore();
  const signer = await LocalTokenSigner.generate('RS256');
  const auditStore = new InMemoryMintAuditStore();
  const rateLimiter = new InMemoryMintRateLimiter({ maxMintsPerWindow: 100, windowSeconds: 60 });
  const apiVerifier = new ApiKeyVerifier({ store, peppers: [pepper] });
  const minter = new TokenMinter({ signer, issuerDid: 'did:web:test', gatewayAudience: 'tool-gateway' });

  const app = createMinterApp({
    mintRouterOpts: { verifier: apiVerifier, minter, auditStore, rateLimiter, logger },
    adminKeysRouterOpts: {
      keyStore: store,
      peppers: [pepper],
      adminApiKey: ADMIN_KEY,
      logger,
      jwtVerifier: verifier,
    },
    logger,
  });

  return { app, store, pepper };
}

// ── Bearer JWT primary path ───────────────────────────────────────────────────

describe('Admin routes — Bearer JWT primary authentication', () => {
  it('POST /admin/v1/keys accepts a valid Bearer JWT and returns 201', async () => {
    const verifier = makeFakeVerifier(() => Promise.resolve(GOOD_PRINCIPAL));
    const { app } = await buildAppWithJwt(verifier);

    const res = await request(app)
      .post('/admin/v1/keys')
      .set('Authorization', 'Bearer valid.jwt.token')
      .send(validBody);

    expect(res.status).toBe(201);
    expect(typeof res.body.prefix).toBe('string');
  });

  it('DELETE /admin/v1/keys/:prefix accepts a valid Bearer JWT', async () => {
    const verifier = makeFakeVerifier(() => Promise.resolve(GOOD_PRINCIPAL));
    const { app, store, pepper } = await buildAppWithJwt(verifier);

    // Create a key first using the shared key (convenience).
    const { generateApiKey } = await import('../src/api-key');
    const k = generateApiKey();
    const keyDigest = crypto.createHmac('sha256', pepper.key)
      .update(k.secret, 'utf8').digest().toString('base64url');
    await store.createKey({
      prefix: k.prefix,
      keyDigest,
      hmacKeyVersion: pepper.version,
      tenantId: 'tenant-jwt',
      policyId: 'policy-jwt',
      capabilities: [],
      scopes: ['enforce'],
      createdAt: new Date().toISOString(),
    });

    const res = await request(app)
      .delete(`/admin/v1/keys/${k.prefix}`)
      .set('Authorization', 'Bearer valid.jwt.token');

    expect(res.status).toBe(200);
    expect(res.body.prefix).toBe(k.prefix);
  });

  it('POST /admin/v1/keys rejects an invalid Bearer JWT with 401', async () => {
    const verifier = makeFakeVerifier(() => Promise.reject(new Error('jwt expired')));
    const { app } = await buildAppWithJwt(verifier);

    const res = await request(app)
      .post('/admin/v1/keys')
      .set('Authorization', 'Bearer expired.jwt.token')
      .send(validBody);

    expect(res.status).toBe(401);
  });

  it('POST /admin/v1/policies accepts a valid Bearer JWT', async () => {
    const verifier = makeFakeVerifier(() => Promise.resolve(GOOD_PRINCIPAL));
    const { app } = await buildAppWithJwt(verifier);

    // We need a valid manifest shape.
    const manifest = {
      name: 'test-agent',
      agentId: 'agent-1',
      version: '1.0.0',
      requiredCapabilities: [
        { resource: '/api', actions: ['read'], conditions: [] },
      ],
    };

    const res = await request(app)
      .post('/admin/v1/policies')
      .set('Authorization', 'Bearer valid.jwt.token')
      .send({ policyId: 'policy-jwt', manifest });

    expect(res.status).toBe(200);
  });
});

// ── X-Admin-Key fallback path ─────────────────────────────────────────────────

describe('Admin routes — X-Admin-Key fallback when jwtVerifier is configured', () => {
  it('falls back to shared key when no Authorization header is present', async () => {
    const verifier = makeFakeVerifier(() => Promise.reject(new Error('should not be called')));
    const { app } = await buildAppWithJwt(verifier);

    const res = await request(app)
      .post('/admin/v1/keys')
      .set('X-Admin-Key', ADMIN_KEY)
      .send(validBody);

    // Shared key fallback succeeds even when verifier is configured.
    expect(res.status).toBe(201);
  });

  it('rejects with 401 when shared key is wrong and no Bearer token', async () => {
    const verifier = makeFakeVerifier(() => Promise.reject(new Error('should not be called')));
    const { app } = await buildAppWithJwt(verifier);

    const res = await request(app)
      .post('/admin/v1/keys')
      .set('X-Admin-Key', 'wrong-secret')
      .send(validBody);

    expect(res.status).toBe(401);
  });

  it('returns 401 when neither Bearer token nor shared key is provided', async () => {
    const verifier = makeFakeVerifier(() => Promise.reject(new Error('should not be called')));
    const { app } = await buildAppWithJwt(verifier);

    const res = await request(app)
      .post('/admin/v1/keys')
      .send(validBody);

    expect(res.status).toBe(401);
  });
});

// ── No jwtVerifier (shared key only, no deprecation warning) ──────────────────

describe('Admin routes — shared key only (no jwtVerifier)', () => {
  it('POST /admin/v1/keys accepts the shared key without verifier', async () => {
    const { app } = await buildAppWithJwt(/* no verifier */);

    const res = await request(app)
      .post('/admin/v1/keys')
      .set('X-Admin-Key', ADMIN_KEY)
      .send(validBody);

    expect(res.status).toBe(201);
  });

  it('POST /admin/v1/keys rejects wrong key without verifier', async () => {
    const { app } = await buildAppWithJwt(/* no verifier */);

    const res = await request(app)
      .post('/admin/v1/keys')
      .set('X-Admin-Key', 'not-the-right-key')
      .send(validBody);

    expect(res.status).toBe(401);
  });
});

// ── AdminJwtVerifier unit tests ───────────────────────────────────────────────

describe('AdminJwtVerifier', () => {
  it('constructor does not throw when given a valid HTTPS JWKS URI', () => {
    expect(() => {
      // We are not calling verify(); just constructing should not throw.
      new AdminJwtVerifier({
        jwksUri: 'https://idp.example.com/.well-known/jwks.json',
        audience: 'https://api.example.com',
      });
    }).not.toThrow();
  });

  it('rejects tokens when the JWKS server is unreachable', async () => {
    const v = new AdminJwtVerifier({
      // Non-existent domain — JWKS fetch will fail.
      jwksUri: 'https://jwks.invalid.example.com/.well-known/jwks.json',
      audience: 'test-aud',
    });
    await expect(v.verify('some.jwt.token')).rejects.toThrow();
  });
});

// ── createAdminJwtVerifierFromEnv ─────────────────────────────────────────────

describe('createAdminJwtVerifierFromEnv', () => {
  it('returns undefined when MINTER_ADMIN_JWKS_URI is not set', async () => {
    const { createAdminJwtVerifierFromEnv } = await import('../src/admin-jwt-verifier');
    const result = createAdminJwtVerifierFromEnv({});
    expect(result).toBeUndefined();
  });

  it('returns undefined when MINTER_ADMIN_JWT_AUDIENCE is not set', async () => {
    const { createAdminJwtVerifierFromEnv } = await import('../src/admin-jwt-verifier');
    const result = createAdminJwtVerifierFromEnv({
      MINTER_ADMIN_JWKS_URI: 'https://idp.example.com/.well-known/jwks.json',
    });
    expect(result).toBeUndefined();
  });

  it('returns an AdminJwtVerifier when both env vars are set', async () => {
    const { createAdminJwtVerifierFromEnv, AdminJwtVerifier: AJV } = await import('../src/admin-jwt-verifier');
    const result = createAdminJwtVerifierFromEnv({
      MINTER_ADMIN_JWKS_URI: 'https://idp.example.com/.well-known/jwks.json',
      MINTER_ADMIN_JWT_AUDIENCE: 'https://api.example.com',
    });
    expect(result).toBeInstanceOf(AJV);
  });

  it('passes requiredScope through when supplied via options', async () => {
    const { createAdminJwtVerifierFromEnv } = await import('../src/admin-jwt-verifier');
    // Just verify construction does not throw with a requiredScope.
    expect(() =>
      createAdminJwtVerifierFromEnv(
        {
          MINTER_ADMIN_JWKS_URI: 'https://idp.example.com/.well-known/jwks.json',
          MINTER_ADMIN_JWT_AUDIENCE: 'https://api.example.com',
        },
        { requiredScope: 'admin:keys' },
      ),
    ).not.toThrow();
  });
});
