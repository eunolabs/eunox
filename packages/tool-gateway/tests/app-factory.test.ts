/**
 * Tests for the in-process app factory and split health endpoints.
 *
 * R-2 introduces `createApp(deps)` so callers (notably
 * `packages/integration-tests`) can build a gateway in-process without HTTP
 * setup, env reads, or Redis. These tests exercise that contract.
 */

import request from 'supertest';
import {
  CapabilityTokenPayload,
  CapabilityConstraint,
  getCurrentTimestamp,
  getExpirationTimestamp,
  createLogger,
  DefaultKillSwitchManager,
  CAPABILITY_TOKEN_SCHEMA_VERSION,
  ServiceConfig,
} from '@euno/common';
import * as jose from 'jose';

import { createApp } from '../src/app-factory';
import { EnforcementEngine } from '../src/enforcement';
import { JWTTokenVerifier } from '../src/verifier';
import type { GatewayDependencies } from '../src/bootstrap';

async function buildDeps(opts?: {
  isReady?: () => boolean;
}): Promise<{
  deps: GatewayDependencies;
  privateKey: jose.KeyLike;
}> {
  const { publicKey: pubKey, privateKey } = await jose.generateKeyPair('RS256');
  const publicKey = await jose.exportSPKI(pubKey);

  const logger = createLogger('test');
  const killSwitchManager = new DefaultKillSwitchManager(logger);
  const verifier = new JWTTokenVerifier(publicKey);
  const enforcementEngine = new EnforcementEngine({ verifier, logger, killSwitchManager });

  const config: ServiceConfig = {
    name: 'tool-gateway',
    port: 0,
    environment: 'test' as ServiceConfig['environment'],
    enableCryptographicAudit: false,
    policyVersion: '1.0.0',
  };

  const deps: GatewayDependencies = {
    config,
    logger,
    verifier,
    enforcementEngine,
    killSwitchManager,
    backendServiceUrl: 'http://localhost:65535', // never reached in these tests
    allowedOrigins: [],
    rateLimitWindowMs: 60_000,
    rateLimitMax: 10_000,
    isReady: opts?.isReady ?? (() => true),
  };

  return { deps, privateKey };
}

async function signToken(
  privateKey: jose.KeyLike,
  capabilities: CapabilityConstraint[],
  extra?: Partial<CapabilityTokenPayload>,
): Promise<string> {
  const payload: CapabilityTokenPayload = {
    iss: 'did:web:test.com',
    sub: 'test-agent',
    aud: 'tool-gateway',
    iat: getCurrentTimestamp(),
    exp: getExpirationTimestamp(900),
    jti: `test-${Date.now()}-${Math.random()}`,
    schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
    capabilities,
    ...extra,
  };

  return new jose.SignJWT(payload as unknown as jose.JWTPayload)
    .setProtectedHeader({ alg: 'RS256' })
    .sign(privateKey);
}

describe('createApp(deps) — R-2 in-process factory', () => {
  describe('health endpoints', () => {
    it('responds 200 on /health (legacy liveness alias)', async () => {
      const { deps } = await buildDeps();
      const app = createApp(deps);

      const res = await request(app).get('/health');

      expect(res.status).toBe(200);
      expect(res.body.status).toBe('healthy');
      expect(res.body.service).toBe('tool-gateway');
    });

    it('responds 200 on /health/live regardless of readiness', async () => {
      const { deps } = await buildDeps({ isReady: () => false });
      const app = createApp(deps);

      const res = await request(app).get('/health/live');

      expect(res.status).toBe(200);
      expect(res.body.status).toBe('healthy');
    });

    it('responds 200 on /health/ready when isReady() is true', async () => {
      const { deps } = await buildDeps({ isReady: () => true });
      const app = createApp(deps);

      const res = await request(app).get('/health/ready');

      expect(res.status).toBe(200);
      expect(res.body.status).toBe('ready');
    });

    it('responds 503 not_ready on /health/ready before initialisation completes', async () => {
      const { deps } = await buildDeps({ isReady: () => false });
      const app = createApp(deps);

      const res = await request(app).get('/health/ready');

      expect(res.status).toBe(503);
      expect(res.body.status).toBe('not_ready');
    });

    it('flips /health/ready response when readiness toggles', async () => {
      let ready = false;
      const { deps } = await buildDeps({ isReady: () => ready });
      const app = createApp(deps);

      const before = await request(app).get('/health/ready');
      expect(before.status).toBe(503);

      ready = true;
      const after = await request(app).get('/health/ready');
      expect(after.status).toBe(200);
    });
  });

  describe('/api/v1/validate', () => {
    it('returns 401 when no Authorization header is supplied', async () => {
      const { deps } = await buildDeps();
      const app = createApp(deps);

      const res = await request(app)
        .post('/api/v1/validate')
        .send({ action: 'read', resource: 'tool://anything' });

      expect(res.status).toBe(401);
      expect(res.body.error.code).toBeDefined();
    });

    it('returns 400 INVALID_REQUEST when action is missing', async () => {
      const { deps, privateKey } = await buildDeps();
      const app = createApp(deps);
      const token = await signToken(privateKey, [
        { resource: 'tool://read_file', actions: ['read'] },
      ]);

      const res = await request(app)
        .post('/api/v1/validate')
        .set('Authorization', `Bearer ${token}`)
        .send({ resource: 'tool://read_file' });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('INVALID_REQUEST');
    });

    it('returns 400 INVALID_REQUEST when resource is not a string', async () => {
      const { deps, privateKey } = await buildDeps();
      const app = createApp(deps);
      const token = await signToken(privateKey, [
        { resource: 'tool://read_file', actions: ['read'] },
      ]);

      const res = await request(app)
        .post('/api/v1/validate')
        .set('Authorization', `Bearer ${token}`)
        .send({ action: 'read', resource: 123 });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('INVALID_REQUEST');
    });

    it('returns allowed=true for a token whose capability matches', async () => {
      const { deps, privateKey } = await buildDeps();
      const app = createApp(deps);
      const token = await signToken(privateKey, [
        {
          resource: 'tool://read_file',
          actions: ['read'],
        },
      ]);

      const res = await request(app)
        .post('/api/v1/validate')
        .set('Authorization', `Bearer ${token}`)
        .send({ action: 'read', resource: 'tool://read_file' });

      expect(res.status).toBe(200);
      expect(res.body.allowed).toBe(true);
    });

    it('returns allowed=false when the resource does not match', async () => {
      const { deps, privateKey } = await buildDeps();
      const app = createApp(deps);
      const token = await signToken(privateKey, [
        {
          resource: 'tool://read_file',
          actions: ['read'],
        },
      ]);

      const res = await request(app)
        .post('/api/v1/validate')
        .set('Authorization', `Bearer ${token}`)
        .send({ action: 'read', resource: 'tool://write_file' });

      expect(res.status).toBe(200);
      expect(res.body.allowed).toBe(false);
    });
  });

  describe('/api/v1/tools/invoke', () => {
    it('returns 400 when `tool` is missing from the body', async () => {
      const { deps, privateKey } = await buildDeps();
      const app = createApp(deps);
      const token = await signToken(privateKey, [
        { resource: 'tool://read_file', actions: ['read'] },
      ]);

      const res = await request(app)
        .post('/api/v1/tools/invoke')
        .set('Authorization', `Bearer ${token}`)
        .send({ args: {} });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('INVALID_REQUEST');
    });

    it('returns 400 INVALID_REQUEST when `tool` is not a string', async () => {
      const { deps, privateKey } = await buildDeps();
      const app = createApp(deps);
      const token = await signToken(privateKey, [
        { resource: 'tool://read_file', actions: ['read'] },
      ]);

      const res = await request(app)
        .post('/api/v1/tools/invoke')
        .set('Authorization', `Bearer ${token}`)
        .send({ tool: { foo: 'bar' }, args: {} });

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('INVALID_REQUEST');
    });

    it('uses server-side action registry to authorise read_file as `read`', async () => {
      const { deps, privateKey } = await buildDeps();
      const app = createApp(deps);
      const token = await signToken(privateKey, [
        { resource: 'tool://read_file', actions: ['read'] },
      ]);

      const res = await request(app)
        .post('/api/v1/tools/invoke')
        .set('Authorization', `Bearer ${token}`)
        .send({ tool: 'read_file', args: { path: '/etc/hosts' } });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.tool).toBe('read_file');
    });

    it('rejects unknown tools (default action `execute`) when capability lacks execute', async () => {
      const { deps, privateKey } = await buildDeps();
      const app = createApp(deps);
      const token = await signToken(privateKey, [
        { resource: 'tool://anything', actions: ['read'] },
      ]);

      const res = await request(app)
        .post('/api/v1/tools/invoke')
        .set('Authorization', `Bearer ${token}`)
        .send({ tool: 'mystery_tool', args: {} });

      expect(res.status).toBe(403);
    });
  });

  describe('CapabilityError mapping', () => {
    it('maps CapabilityError to {error:{code,message}} on unauthenticated proxy hit', async () => {
      const { deps } = await buildDeps();
      const app = createApp(deps);

      // No Authorization header — the validate middleware throws
      // CapabilityError before the proxy is invoked, so no backend is needed.
      const res = await request(app).get('/proxy/api.example.com/things');

      expect(res.status).toBe(401);
      expect(res.body.error).toBeDefined();
      expect(res.body.error.code).toBeDefined();
      expect(res.body.error.message).toBeDefined();
    });
  });
});
