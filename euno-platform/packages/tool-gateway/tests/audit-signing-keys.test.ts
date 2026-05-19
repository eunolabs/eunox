/**
 * Tests for `GET /api/v1/audit/signing-keys` — Task 6 review fix
 *
 * Tests cover:
 *  1. Route returns 200 with a JWK Set when public key PEM is provided.
 *  2. JWK Set contains the expected keyId and algorithm.
 *  3. Route is absent from createApp when auditSigningPublicKeyPem is not in deps.
 *  4. Route returns Cache-Control: public, max-age=3600.
 *  5. Router uses provided keyId and algorithm.
 */

import request from 'supertest';
import crypto from 'crypto';
import express from 'express';
import { createAuditSigningKeysRouter } from '../src/routes/audit-signing-keys';
import { createApp } from '../src/app-factory';
import { createLogger, createMetricsRegistry, Counter, DefaultKillSwitchManager, ServiceConfig, BUILTIN_ACTION_RESOLVER } from '@euno/common';
import { JWTTokenVerifier } from '../src/verifier';
import { EnforcementEngine } from '../src/enforcement';
import type { GatewayDependencies } from '../src/bootstrap';

// ── Helpers ───────────────────────────────────────────────────────────────────

function generateRsaKeyPair(): { publicKeyPem: string; privateKeyPem: string } {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }) as string,
  };
}

async function buildDeps(overrides: Partial<GatewayDependencies> = {}): Promise<GatewayDependencies> {
  const logger = createLogger('signing-keys-test');
  const killSwitchManager = new DefaultKillSwitchManager(logger);
  const fakeVerifier = { verify: async () => { throw new Error('not used'); } } as unknown as JWTTokenVerifier;
  const enforcementEngine = new EnforcementEngine({
    verifier: fakeVerifier,
    logger,
    killSwitchManager,
    dpop: { required: false },
  });
  const config: ServiceConfig = {
    name: 'tool-gateway',
    port: 0,
    environment: 'test' as ServiceConfig['environment'],
    enableCryptographicAudit: false,
    policyVersion: '0.1.0',
  };
  const metricsRegistry = createMetricsRegistry({
    serviceName: `signing-keys-test-${Date.now()}`,
    collectDefaults: false,
  });
  return {
    config,
    logger,
    verifier: fakeVerifier,
    enforcementEngine,
    killSwitchManager,
    backendServiceUrl: 'http://localhost:65535',
    allowedOrigins: [],
    rateLimitWindowMs: 60_000,
    rateLimitMax: 10_000,
    metricsRegistry,
    decisionsCounter: new Counter({
      name: `euno_gateway_decisions_total_signing_keys_test_${Date.now()}`,
      help: 'test',
      labelNames: ['decision'],
      registers: [metricsRegistry],
    }),
    auditPipelineDrainTimeoutMs: 5_000,
    isReady: () => true,
    actionResolver: BUILTIN_ACTION_RESOLVER,
    adminPort: 0,
    responseRedactionMaxBytes: 1_048_576,
    ...overrides,
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('GET /api/v1/audit/signing-keys', () => {
  it('1. returns 200 with a JWK Set when public key PEM is provided', async () => {
    const { publicKeyPem } = generateRsaKeyPair();
    const logger = createLogger('test');
    const router = createAuditSigningKeysRouter({
      publicKeyPem,
      keyId: 'my-key',
      algorithm: 'RS256',
      logger,
    });
    const app = express();
    app.use(router);

    const res = await request(app).get('/api/v1/audit/signing-keys');

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('keys');
    expect(Array.isArray(res.body.keys)).toBe(true);
    expect(res.body.keys).toHaveLength(1);
  });

  it('2. JWK Set contains the expected keyId, algorithm, and use=sig', async () => {
    const { publicKeyPem } = generateRsaKeyPair();
    const logger = createLogger('test');
    const router = createAuditSigningKeysRouter({
      publicKeyPem,
      keyId: 'evidence-signing-key',
      algorithm: 'RS256',
      logger,
    });
    const app = express();
    app.use(router);

    const res = await request(app).get('/api/v1/audit/signing-keys');

    expect(res.status).toBe(200);
    const key = res.body.keys[0];
    expect(key.kid).toBe('evidence-signing-key');
    expect(key.alg).toBe('RS256');
    expect(key.use).toBe('sig');
    expect(key.kty).toBe('RSA');
  });

  it('3. route is absent from createApp when auditSigningPublicKeyPem is not in deps', async () => {
    const deps = await buildDeps(); // no auditSigningPublicKeyPem
    const app = createApp(deps);

    const res = await request(app).get('/api/v1/audit/signing-keys');

    expect(res.status).toBe(404);
  });

  it('4. returns Cache-Control: public, max-age=3600', async () => {
    const { publicKeyPem } = generateRsaKeyPair();
    const logger = createLogger('test');
    const router = createAuditSigningKeysRouter({
      publicKeyPem,
      keyId: 'k1',
      algorithm: 'RS256',
      logger,
    });
    const app = express();
    app.use(router);

    const res = await request(app).get('/api/v1/audit/signing-keys');

    expect(res.status).toBe(200);
    expect(res.headers['cache-control']).toBe('public, max-age=3600');
  });

  it('5. route is mounted in createApp when auditSigningPublicKeyPem is set', async () => {
    const { publicKeyPem } = generateRsaKeyPair();
    const deps = await buildDeps({
      auditSigningPublicKeyPem: publicKeyPem,
      auditSigningKeyId: 'sw-key',
      auditSigningAlgorithm: 'RS256',
    });
    const app = createApp(deps);

    const res = await request(app).get('/api/v1/audit/signing-keys');

    expect(res.status).toBe(200);
    expect(res.body.keys[0].kid).toBe('sw-key');
    expect(res.body.keys[0].alg).toBe('RS256');
  });
});
