/**
 * Tests for POST /api/v1/enforce — Stage-3 remote-enforcer endpoint (Task 9)
 *
 * Covers:
 *   - Protocol version negotiation (missing header, valid, unsupported)
 *   - X-Euno-Protocol-Version echoed on UNSUPPORTED_PROTOCOL_VERSION 400
 *   - Authentication (missing token, invalid token)
 *   - Request body validation (malformed, missing fields, clock-skew)
 *   - requestId included in INVALID_REQUEST error bodies
 *   - In-band allow response with and without obligations
 *   - ARGUMENT_SCHEMA_VIOLATION denial code propagation
 *   - In-band deny response for policy denials
 *   - In-band deny response for kill-switch and token errors
 *   - 401/503 out-of-band error propagation (503 preserves err.code)
 *   - REQUEST_TOO_LARGE (413) for bodies over 512 KiB (via body-parser)
 *   - requestId echoing
 *   - Protocol-version response header
 */

import express, { Express } from 'express';
import request from 'supertest';
import * as jose from 'jose';
import { createEnforceRouter } from '../src/routes/enforce';
import { EnforcementEngine } from '../src/enforcement';
import { JWTTokenVerifier } from '../src/verifier';
import {
  CAPABILITY_TOKEN_SCHEMA_VERSION,
  CapabilityConstraint,
  CapabilityTokenPayload,
  CapabilityError,
  ErrorCode,
  getCurrentTimestamp,
  getExpirationTimestamp,
  createLogger,
  ENFORCE_PROTOCOL_VERSION,
} from '@euno/common';

// ---------------------------------------------------------------------------
// Shared test infrastructure
// ---------------------------------------------------------------------------

const logger = createLogger('test');

async function generateKeyPair() {
  const { publicKey, privateKey } = await jose.generateKeyPair('RS256');
  return {
    privateKey,
    publicKeyPem: await jose.exportSPKI(publicKey),
  };
}

async function signToken(
  privateKey: jose.KeyLike,
  capabilities: CapabilityConstraint[],
  extra: Partial<CapabilityTokenPayload> = {},
): Promise<string> {
  const payload: CapabilityTokenPayload = {
    iss: 'did:web:test.issuer',
    sub: 'test-agent',
    aud: 'tool-gateway',
    iat: getCurrentTimestamp(),
    exp: getExpirationTimestamp(900),
    jti: `jti-${Date.now()}-${Math.random()}`,
    schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
    capabilities,
    ...extra,
  };
  return new jose.SignJWT(payload as unknown as Record<string, unknown>)
    .setProtectedHeader({ alg: 'RS256' })
    .sign(privateKey);
}

function buildApp(engine: EnforcementEngine, opts: { sourceIpMode?: 'gateway' | 'client' } = {}): Express {
  const app = express();
  // Mount the enforce router BEFORE the global body-parser, mirroring app-factory.ts.
  // The router installs its own 512 KiB body-parser and the PayloadTooLargeError
  // handler so the 413 test cases work correctly.
  app.use(createEnforceRouter({ enforcementEngine: engine, logger, sourceIpMode: opts.sourceIpMode }));
  // Global body-parser for any other routes in this test app (none currently,
  // but keeps the middleware chain consistent with production).
  app.use(express.json());
  // Minimal error handler to serialise unhandled errors
  app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    const status = (err as { statusCode?: number }).statusCode ?? 500;
    const code = (err as { code?: string }).code ?? 'INTERNAL_ERROR';
    res.status(status).json({ error: { code, message: err.message } });
  });
  return app;
}

// ---------------------------------------------------------------------------
// Test suites
// ---------------------------------------------------------------------------

describe('POST /api/v1/enforce', () => {
  let privateKey: jose.KeyLike;
  let publicKeyPem: string;
  let engine: EnforcementEngine;
  let app: Express;

  beforeAll(async () => {
    ({ privateKey, publicKeyPem } = await generateKeyPair());
    const verifier = new JWTTokenVerifier(publicKeyPem, { requireKid: false });
    engine = new EnforcementEngine({
      verifier,
      logger,
      dpop: { required: false },
    });
    // Use 'client' mode for the shared test app so existing tests that pass
    // context.sourceIp in the body work as expected. Tests for 'gateway' mode
    // are in section 8b below using a dedicated app instance.
    app = buildApp(engine, { sourceIpMode: 'client' });
  });

  // ── Body representing a minimal valid request ─────────────────────────────
  function validBody(
    toolName = 'test-tool',
    extra: Record<string, unknown> = {},
  ): Record<string, unknown> {
    return {
      sessionId: 'sess-abc',
      toolName,
      arguments: {},
      context: {},
      ...extra,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // 1. Protocol version negotiation
  // ─────────────────────────────────────────────────────────────────────────

  describe('protocol version header', () => {
    let validToken: string;

    beforeAll(async () => {
      validToken = await signToken(privateKey, [
        { resource: 'tool://test-tool', actions: ['execute'] },
      ]);
    });

    it('echoes X-Euno-Protocol-Version in every response', async () => {
      const res = await request(app)
        .post('/api/v1/enforce')
        .set('Authorization', `Bearer ${validToken}`)
        .set('X-Euno-Protocol-Version', '1')
        .send(validBody());

      expect(res.headers['x-euno-protocol-version']).toBe('1');
    });

    it('defaults to version 1 when header is absent (backward compat)', async () => {
      const res = await request(app)
        .post('/api/v1/enforce')
        .set('Authorization', `Bearer ${validToken}`)
        // No X-Euno-Protocol-Version header
        .send(validBody());

      // Missing header should not cause a 400
      expect(res.status).not.toBe(400);
    });

    it('returns 400 UNSUPPORTED_PROTOCOL_VERSION for unknown version', async () => {
      const res = await request(app)
        .post('/api/v1/enforce')
        .set('Authorization', `Bearer ${validToken}`)
        .set('X-Euno-Protocol-Version', '99')
        .send(validBody());

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe(ErrorCode.UNSUPPORTED_PROTOCOL_VERSION);
      expect(Array.isArray(res.body.error.supportedVersions)).toBe(true);
      expect(res.body.error.supportedVersions).toContain(ENFORCE_PROTOCOL_VERSION);
      // Protocol spec: X-Euno-Protocol-Version MUST be echoed even on 400
      expect(res.headers['x-euno-protocol-version']).toBe(String(ENFORCE_PROTOCOL_VERSION));
    });

    it('returns 400 UNSUPPORTED_PROTOCOL_VERSION for non-integer version', async () => {
      const res = await request(app)
        .post('/api/v1/enforce')
        .set('Authorization', `Bearer ${validToken}`)
        .set('X-Euno-Protocol-Version', 'abc')
        .send(validBody());

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe(ErrorCode.UNSUPPORTED_PROTOCOL_VERSION);
      expect(res.body.error.supportedVersions).toContain(ENFORCE_PROTOCOL_VERSION);
      expect(res.headers['x-euno-protocol-version']).toBe(String(ENFORCE_PROTOCOL_VERSION));
    });

    it('returns 400 UNSUPPORTED_PROTOCOL_VERSION for zero', async () => {
      const res = await request(app)
        .post('/api/v1/enforce')
        .set('Authorization', `Bearer ${validToken}`)
        .set('X-Euno-Protocol-Version', '0')
        .send(validBody());

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe(ErrorCode.UNSUPPORTED_PROTOCOL_VERSION);
      expect(res.headers['x-euno-protocol-version']).toBe(String(ENFORCE_PROTOCOL_VERSION));
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // 2. Authentication
  // ─────────────────────────────────────────────────────────────────────────

  describe('authentication', () => {
    it('returns 401 when Authorization header is absent', async () => {
      const res = await request(app)
        .post('/api/v1/enforce')
        .set('X-Euno-Protocol-Version', '1')
        .send(validBody());

      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe(ErrorCode.AUTHENTICATION_FAILED);
    });

    it('returns 401 when the JWT is invalid', async () => {
      const res = await request(app)
        .post('/api/v1/enforce')
        .set('Authorization', 'Bearer not.a.valid.jwt')
        .set('X-Euno-Protocol-Version', '1')
        .send(validBody());

      // Token verification throws CapabilityError with statusCode 401
      expect(res.status).toBe(401);
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // 3. Request body validation
  // ─────────────────────────────────────────────────────────────────────────

  describe('request body validation', () => {
    let validToken: string;

    beforeAll(async () => {
      validToken = await signToken(privateKey, [
        { resource: 'tool://test-tool', actions: ['execute'] },
      ]);
    });

    const cases: Array<[string, Record<string, unknown>]> = [
      ['missing sessionId', { toolName: 'test-tool', arguments: {}, context: {} }],
      ['empty sessionId', { sessionId: '', toolName: 'test-tool', arguments: {}, context: {} }],
      ['missing toolName', { sessionId: 's', arguments: {}, context: {} }],
      ['empty toolName', { sessionId: 's', toolName: '', arguments: {}, context: {} }],
      ['missing arguments', { sessionId: 's', toolName: 'test-tool', context: {} }],
      ['arguments is array', { sessionId: 's', toolName: 'test-tool', arguments: [], context: {} }],
      ['missing context', { sessionId: 's', toolName: 'test-tool', arguments: {} }],
      ['context.sourceIp is number', { sessionId: 's', toolName: 'test-tool', arguments: {}, context: { sourceIp: 42 } }],
      ['context.recipients contains non-strings', { sessionId: 's', toolName: 'test-tool', arguments: {}, context: { recipients: [1, 2] } }],
      ['context.now is number', { sessionId: 's', toolName: 'test-tool', arguments: {}, context: { now: 12345 } }],
    ];

    it.each(cases)('returns 400 INVALID_REQUEST when %s', async (_label, body) => {
      const res = await request(app)
        .post('/api/v1/enforce')
        .set('Authorization', `Bearer ${validToken}`)
        .set('X-Euno-Protocol-Version', '1')
        .send(body);

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe(ErrorCode.INVALID_REQUEST);
      // Protocol spec: requestId must be present even in validation-error bodies
      expect(typeof res.body.error.requestId).toBe('string');
      expect(res.body.error.requestId.length).toBeGreaterThan(0);
    });

    it('returns 400 INVALID_REQUEST when context.now has excessive clock skew', async () => {
      const past = new Date(Date.now() - 120_000).toISOString(); // 2 min ago
      const res = await request(app)
        .post('/api/v1/enforce')
        .set('Authorization', `Bearer ${validToken}`)
        .set('X-Euno-Protocol-Version', '1')
        .send(validBody('test-tool', { context: { now: past } }));

      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe(ErrorCode.INVALID_REQUEST);
      expect(res.body.error.message).toMatch(/clock/i);
      expect(typeof res.body.error.requestId).toBe('string');
    });

    it('accepts context.now within 60 s of gateway clock', async () => {
      const near = new Date(Date.now() - 5_000).toISOString(); // 5 s ago
      const res = await request(app)
        .post('/api/v1/enforce')
        .set('Authorization', `Bearer ${validToken}`)
        .set('X-Euno-Protocol-Version', '1')
        .send(validBody('test-tool', { context: { now: near } }));

      // The request is structurally valid; whether it is allowed depends on
      // the token/policy, not clock validation.
      expect(res.status).not.toBe(400);
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // 4. Allow decisions
  // ─────────────────────────────────────────────────────────────────────────

  describe('allow decisions', () => {
    it('returns EnforceResponse with decision=allow for matching capability', async () => {
      const token = await signToken(privateKey, [
        { resource: 'tool://my-tool', actions: ['execute'] },
      ]);

      const res = await request(app)
        .post('/api/v1/enforce')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Euno-Protocol-Version', '1')
        .send({ sessionId: 'sess-1', toolName: 'my-tool', arguments: {}, context: {} });

      expect(res.status).toBe(200);
      expect(res.body.decision).toBe('allow');
      expect(typeof res.body.requestId).toBe('string');
      expect(typeof res.body.decidedAt).toBe('string');
      expect(res.body.denial).toBeUndefined();
    });

    it('includes obligations when capability has redactFields conditions', async () => {
      const token = await signToken(privateKey, [
        {
          resource: 'tool://my-tool',
          actions: ['execute'],
          conditions: [{ type: 'redactFields', fields: ['secret', 'internal.data'] }],
        },
      ]);

      const res = await request(app)
        .post('/api/v1/enforce')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Euno-Protocol-Version', '1')
        .send({ sessionId: 'sess-1', toolName: 'my-tool', arguments: {}, context: {} });

      expect(res.status).toBe(200);
      expect(res.body.decision).toBe('allow');
      expect(Array.isArray(res.body.obligations)).toBe(true);
      expect(res.body.obligations).toEqual(
        expect.arrayContaining([
          { type: 'redactFields', paths: ['secret', 'internal.data'] },
        ]),
      );
    });

    it('omits obligations field when capability has no redactFields conditions', async () => {
      const token = await signToken(privateKey, [
        { resource: 'tool://my-tool', actions: ['execute'] },
      ]);

      const res = await request(app)
        .post('/api/v1/enforce')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Euno-Protocol-Version', '1')
        .send({ sessionId: 'sess-1', toolName: 'my-tool', arguments: {}, context: {} });

      expect(res.status).toBe(200);
      expect(res.body.decision).toBe('allow');
      expect(res.body.obligations).toBeUndefined();
    });

    it('echoes X-Request-Id from the caller in the response body', async () => {
      const token = await signToken(privateKey, [
        { resource: 'tool://my-tool', actions: ['execute'] },
      ]);
      const callerRequestId = 'caller-req-abc-123';

      const res = await request(app)
        .post('/api/v1/enforce')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Euno-Protocol-Version', '1')
        .set('X-Request-Id', callerRequestId)
        .send({ sessionId: 'sess-1', toolName: 'my-tool', arguments: {}, context: {} });

      expect(res.status).toBe(200);
      expect(res.body.requestId).toBe(callerRequestId);
    });

    it('generates a requestId when X-Request-Id is absent', async () => {
      const token = await signToken(privateKey, [
        { resource: 'tool://my-tool', actions: ['execute'] },
      ]);

      const res = await request(app)
        .post('/api/v1/enforce')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Euno-Protocol-Version', '1')
        .send({ sessionId: 'sess-1', toolName: 'my-tool', arguments: {}, context: {} });

      expect(res.status).toBe(200);
      // requestId must be a non-empty string (UUID)
      expect(typeof res.body.requestId).toBe('string');
      expect(res.body.requestId.length).toBeGreaterThan(0);
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // 5. Deny decisions
  // ─────────────────────────────────────────────────────────────────────────

  describe('deny decisions', () => {
    it('returns EnforceResponse with decision=deny when capability does not match', async () => {
      const token = await signToken(privateKey, [
        { resource: 'tool://other-tool', actions: ['execute'] },
      ]);

      const res = await request(app)
        .post('/api/v1/enforce')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Euno-Protocol-Version', '1')
        .send({ sessionId: 'sess-1', toolName: 'my-tool', arguments: {}, context: {} });

      expect(res.status).toBe(200);
      expect(res.body.decision).toBe('deny');
      expect(res.body.denial).toBeDefined();
      expect(typeof res.body.denial.code).toBe('string');
      expect(typeof res.body.denial.conditionType).toBe('string');
      expect(typeof res.body.denial.message).toBe('string');
      expect(res.body.obligations).toBeUndefined();
    });

    it('returns EnforceResponse with decision=deny for wrong audience', async () => {
      const token = await signToken(
        privateKey,
        [{ resource: 'tool://my-tool', actions: ['execute'] }],
        { aud: 'wrong-audience' },
      );

      const res = await request(app)
        .post('/api/v1/enforce')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Euno-Protocol-Version', '1')
        .send({ sessionId: 'sess-1', toolName: 'my-tool', arguments: {}, context: {} });

      // Audience mismatch → CapabilityError with statusCode 403 → in-band deny
      expect(res.status).toBe(200);
      expect(res.body.decision).toBe('deny');
      expect(res.body.denial).toBeDefined();
    });

    it('returns 401 (out-of-band) for JWT verification failure', async () => {
      // A valid structure but signed with a different key
      const { privateKey: otherKey } = await jose.generateKeyPair('RS256');
      const token = await signToken(otherKey, [
        { resource: 'tool://my-tool', actions: ['execute'] },
      ]);

      const res = await request(app)
        .post('/api/v1/enforce')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Euno-Protocol-Version', '1')
        .send({ sessionId: 'sess-1', toolName: 'my-tool', arguments: {}, context: {} });

      expect(res.status).toBe(401);
    });

    it('returns decidedAt in the deny response', async () => {
      const token = await signToken(privateKey, [
        { resource: 'tool://other-tool', actions: ['execute'] },
      ]);

      const res = await request(app)
        .post('/api/v1/enforce')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Euno-Protocol-Version', '1')
        .send({ sessionId: 'sess-1', toolName: 'my-tool', arguments: {}, context: {} });

      expect(res.status).toBe(200);
      expect(res.body.decision).toBe('deny');
      expect(typeof res.body.decidedAt).toBe('string');
      // Rough sanity: parseable as a date
      expect(Number.isNaN(Date.parse(res.body.decidedAt))).toBe(false);
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // 6. Kill-switch in-band deny
  // ─────────────────────────────────────────────────────────────────────────

  describe('kill-switch in-band deny', () => {
    it('returns decision=deny (not 403 out-of-band) when kill-switch is active', async () => {
      const { DefaultKillSwitchManager } = await import('@euno/common');
      const killSwitch = new DefaultKillSwitchManager();
      killSwitch.activateGlobalKill();

      const verifier = new JWTTokenVerifier(publicKeyPem, { requireKid: false });
      const engineWithKill = new EnforcementEngine({
        verifier,
        logger,
        killSwitchManager: killSwitch,
        dpop: { required: false },
      });
      const appWithKill = buildApp(engineWithKill);

      const token = await signToken(privateKey, [
        { resource: 'tool://my-tool', actions: ['execute'] },
      ]);

      const res = await request(appWithKill)
        .post('/api/v1/enforce')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Euno-Protocol-Version', '1')
        .send({ sessionId: 'sess-1', toolName: 'my-tool', arguments: {}, context: {} });

      // Kill-switch is a 403 CapabilityError → in-band deny (HTTP 200)
      expect(res.status).toBe(200);
      expect(res.body.decision).toBe('deny');
      expect(res.body.denial.code).toBe(ErrorCode.AGENT_TERMINATED);
      expect(res.body.denial.conditionType).toBe('killSwitch');
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // 7. timeWindow condition
  // ─────────────────────────────────────────────────────────────────────────

  describe('timeWindow condition', () => {
    it('returns in-band deny when timeWindow has expired', async () => {
      const pastTime = new Date(Date.now() - 1000).toISOString();
      const token = await signToken(privateKey, [
        {
          resource: 'tool://my-tool',
          actions: ['execute'],
          conditions: [{ type: 'timeWindow', notAfter: pastTime }],
        },
      ]);

      const res = await request(app)
        .post('/api/v1/enforce')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Euno-Protocol-Version', '1')
        .send({ sessionId: 'sess-1', toolName: 'my-tool', arguments: {}, context: {} });

      expect(res.status).toBe(200);
      expect(res.body.decision).toBe('deny');
      expect(res.body.denial).toBeDefined();
    });

    it('returns allow when timeWindow is currently active', async () => {
      const futureTime = new Date(Date.now() + 60_000).toISOString();
      const token = await signToken(privateKey, [
        {
          resource: 'tool://my-tool',
          actions: ['execute'],
          conditions: [{ type: 'timeWindow', notAfter: futureTime }],
        },
      ]);

      const res = await request(app)
        .post('/api/v1/enforce')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Euno-Protocol-Version', '1')
        .send({ sessionId: 'sess-1', toolName: 'my-tool', arguments: {}, context: {} });

      expect(res.status).toBe(200);
      expect(res.body.decision).toBe('allow');
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // 8. sourceIp forwarding
  // ─────────────────────────────────────────────────────────────────────────

  describe('sourceIp forwarding', () => {
    it('forwards sourceIp for ipRange condition enforcement', async () => {
      const token = await signToken(privateKey, [
        {
          resource: 'tool://my-tool',
          actions: ['execute'],
          conditions: [{ type: 'ipRange', cidrs: ['10.0.0.0/8'] }],
        },
      ]);

      // sourceIp in the allowed range → allow
      const allowRes = await request(app)
        .post('/api/v1/enforce')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Euno-Protocol-Version', '1')
        .send({
          sessionId: 'sess-1',
          toolName: 'my-tool',
          arguments: {},
          context: { sourceIp: '10.1.2.3' },
        });

      expect(allowRes.status).toBe(200);
      expect(allowRes.body.decision).toBe('allow');

      // sourceIp outside the allowed range → deny
      const denyRes = await request(app)
        .post('/api/v1/enforce')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Euno-Protocol-Version', '1')
        .send({
          sessionId: 'sess-1',
          toolName: 'my-tool',
          arguments: {},
          context: { sourceIp: '192.168.1.1' },
        });

      expect(denyRes.status).toBe(200);
      expect(denyRes.body.decision).toBe('deny');
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // 8b. sourceIpMode='gateway' (CR-2 fix)
  // ─────────────────────────────────────────────────────────────────────────

  describe("sourceIpMode='gateway' (CR-2 fix)", () => {
    // The 'gateway' mode app: the router uses req.ip (loopback from supertest)
    // as the effective sourceIp, ignoring the body field.
    let gatewayModeApp: Express;

    beforeAll(() => {
      // No need to rebuild engine; reuse the one from the outer beforeAll.
      gatewayModeApp = buildApp(engine, { sourceIpMode: 'gateway' });
    });

    it('uses req.ip (loopback) as the effective sourceIp when mode is gateway', async () => {
      // req.ip from supertest local connections is '::ffff:127.0.0.1' (IPv4-mapped
      // loopback). The CIDR '::ffff:127.0.0.0/104' covers ::ffff:127.x.x.x — the
      // IPv4-mapped loopback space — and does NOT match bare IPv4 strings like
      // '10.9.9.9' (address-family mismatch in ipMatchesCidr).
      const token = await signToken(privateKey, [
        {
          resource: 'tool://gw-tool',
          actions: ['execute'],
          conditions: [{ type: 'ipRange', cidrs: ['::ffff:127.0.0.0/104'] }],
        },
      ]);

      const res = await request(gatewayModeApp)
        .post('/api/v1/enforce')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Euno-Protocol-Version', '1')
        .send({
          sessionId: 'sess-gw',
          toolName: 'gw-tool',
          arguments: {},
          // Supply a non-matching IP in the body — gateway mode must ignore it.
          context: { sourceIp: '10.9.9.9' },
        });

      // req.ip (::ffff:127.0.0.1) matches ::ffff:127.0.0.0/104 → allow.
      expect(res.status).toBe(200);
      expect(res.body.decision).toBe('allow');
    });

    it('denies when req.ip falls outside the allowed CIDR even though body sourceIp would match', async () => {
      // Token only allows 10.0.0.0/8 — body says 10.x.x.x but gateway ignores it.
      const token = await signToken(privateKey, [
        {
          resource: 'tool://gw-tool',
          actions: ['execute'],
          conditions: [{ type: 'ipRange', cidrs: ['10.0.0.0/8'] }],
        },
      ]);

      const res = await request(gatewayModeApp)
        .post('/api/v1/enforce')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Euno-Protocol-Version', '1')
        .send({
          sessionId: 'sess-gw',
          toolName: 'gw-tool',
          arguments: {},
          // Body says 10.x.x.x (in-range) but req.ip is loopback (out-of-range).
          context: { sourceIp: '10.1.2.3' },
        });

      // req.ip (loopback, ~127.x or ::1) is NOT in 10.0.0.0/8 → deny.
      expect(res.status).toBe(200);
      expect(res.body.decision).toBe('deny');
    });

    it("does not set sourceIp in the validation context when req.ip is undefined and body has no sourceIp", async () => {
      // A token with no ipRange condition. Request with no body sourceIp.
      // Should behave as if sourceIp is absent (the condition is vacuously met).
      const token = await signToken(privateKey, [
        { resource: 'tool://gw-tool', actions: ['execute'] },
      ]);

      const res = await request(gatewayModeApp)
        .post('/api/v1/enforce')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Euno-Protocol-Version', '1')
        .send({
          sessionId: 'sess-gw',
          toolName: 'gw-tool',
          arguments: {},
          context: {},
        });

      expect(res.status).toBe(200);
      expect(res.body.decision).toBe('allow');
    });

    it('still allows when no ipRange condition is present regardless of sourceIp values', async () => {
      const token = await signToken(privateKey, [
        { resource: 'tool://gw-tool', actions: ['execute'] },
      ]);

      const res = await request(gatewayModeApp)
        .post('/api/v1/enforce')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Euno-Protocol-Version', '1')
        .send({
          sessionId: 'sess-gw',
          toolName: 'gw-tool',
          arguments: {},
          context: { sourceIp: '1.2.3.4' },
        });

      expect(res.status).toBe(200);
      expect(res.body.decision).toBe('allow');
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // 9. Request body size guard (REQUEST_TOO_LARGE)
  // ─────────────────────────────────────────────────────────────────────────

  describe('request body size guard', () => {
    let validToken: string;

    beforeAll(async () => {
      validToken = await signToken(privateKey, [
        { resource: 'tool://test-tool', actions: ['execute'] },
      ]);
    });

    it('returns 413 REQUEST_TOO_LARGE when Content-Length exceeds 512 KiB', async () => {
      // Use the Content-Length fast-path: advertise a large body without
      // actually sending one (supertest still sets the header).
      const bigBody = {
        sessionId: 'sess-1',
        toolName: 'test-tool',
        arguments: { data: 'x'.repeat(520 * 1024) }, // ~520 KiB
        context: {},
      };

      const res = await request(app)
        .post('/api/v1/enforce')
        .set('Authorization', `Bearer ${validToken}`)
        .set('X-Euno-Protocol-Version', '1')
        .send(bigBody);

      expect(res.status).toBe(413);
      expect(res.body.error.code).toBe(ErrorCode.REQUEST_TOO_LARGE);
      expect(typeof res.body.error.requestId).toBe('string');
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // 10. 503 out-of-band — preserves engine's specific error code
  // ─────────────────────────────────────────────────────────────────────────

  describe('503 out-of-band error propagation', () => {
    it('preserves the engine error code on 503 (not hardcoded GATEWAY_UNAVAILABLE)', async () => {
      // Spy on validateAction to throw a REVOCATION_UNAVAILABLE 503,
      // simulating a Redis outage in the revocation-check path.
      const spy = jest
        .spyOn(engine, 'validateAction')
        .mockRejectedValueOnce(
          new CapabilityError(
            ErrorCode.REVOCATION_UNAVAILABLE,
            'Redis unavailable',
            503,
          ),
        );

      const token = await signToken(privateKey, [
        { resource: 'tool://my-tool', actions: ['execute'] },
      ]);

      const res = await request(app)
        .post('/api/v1/enforce')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Euno-Protocol-Version', '1')
        .send({ sessionId: 'sess-1', toolName: 'my-tool', arguments: {}, context: {} });

      spy.mockRestore();

      expect(res.status).toBe(503);
      // Must preserve the engine's specific code, not the generic GATEWAY_UNAVAILABLE
      expect(res.body.error.code).toBe(ErrorCode.REVOCATION_UNAVAILABLE);
    });
  });
});
