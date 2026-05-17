/**
 * Tests for the proxy route middleware stack.
 *
 * Focused on the security-critical X-Target-Host strip-and-rewrite pipeline:
 *   createTargetHostCanonicalizeMiddleware  →  createValidateCapabilityMiddleware
 *
 * The tests exercise `createTargetHostCanonicalizeMiddleware` in isolation and
 * then as part of the full proxy stack (via `createApp`) to verify end-to-end
 * resource canonicalization behaves correctly regardless of what
 * X-Target-Host value a client sends.
 */

import * as http from 'http';
import { AddressInfo } from 'net';
import { Request, Response } from 'express';

import request from 'supertest';
import {
  CapabilityConstraint,
  getCurrentTimestamp,
  getExpirationTimestamp,
  createLogger,
  DefaultKillSwitchManager,
  CAPABILITY_TOKEN_SCHEMA_VERSION,
  ServiceConfig,
  createMetricsRegistry,
  Counter,
  BUILTIN_ACTION_RESOLVER,
} from '@euno/common';
import * as jose from 'jose';

import { createApp } from '../src/app-factory';
import { EnforcementEngine } from '../src/enforcement';
import { JWTTokenVerifier } from '../src/verifier';
import type { GatewayDependencies } from '../src/bootstrap';
import {
  TARGET_HOST_RE,
  createTargetHostCanonicalizeMiddleware,
} from '../src/routes/proxy';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type Logger = ReturnType<typeof createLogger>;

async function buildDeps(backendServiceUrl = 'http://localhost:65535'): Promise<{
  deps: GatewayDependencies;
  privateKey: jose.KeyLike;
}> {
  const { publicKey: pubKey, privateKey } = await jose.generateKeyPair('RS256');
  const publicKey = await jose.exportSPKI(pubKey);

  const logger = createLogger('test');
  const killSwitchManager = new DefaultKillSwitchManager(logger);
  const verifier = new JWTTokenVerifier(publicKey, { requireKid: false });
  const enforcementEngine = new EnforcementEngine({
    verifier,
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
    serviceName: 'tool-gateway-test',
    collectDefaults: false,
  });

  const deps: GatewayDependencies = {
    config,
    logger,
    verifier,
    enforcementEngine,
    killSwitchManager,
    backendServiceUrl,
    allowedOrigins: [],
    rateLimitWindowMs: 60_000,
    rateLimitMax: 10_000,
    metricsRegistry,
    decisionsCounter: new Counter({
      name: 'euno_gateway_decisions_total_proxy_test',
      help: 'test decisions counter',
      labelNames: ['decision'],
      registers: [metricsRegistry],
    }),
    auditPipelineDrainTimeoutMs: 5_000,
    isReady: () => true,
    actionResolver: BUILTIN_ACTION_RESOLVER,
    adminPort: 0,
    responseRedactionMaxBytes: 1048576,
  };

  return { deps, privateKey };
}

async function signToken(
  privateKey: jose.KeyLike,
  capabilities: CapabilityConstraint[],
): Promise<string> {
  return new jose.SignJWT({
    iss: 'did:web:test.com',
    sub: 'test-agent',
    aud: 'tool-gateway',
    iat: getCurrentTimestamp(),
    exp: getExpirationTimestamp(900),
    jti: `test-${Date.now()}-${Math.random()}`,
    schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
    capabilities,
  } as jose.JWTPayload)
    .setProtectedHeader({ alg: 'RS256' })
    .sign(privateKey);
}

/** Minimal fake Express request used to test the middleware in isolation. */
function fakeRequest(path: string, xTargetHost?: string | string[]): Request {
  return {
    path,
    ip: '127.0.0.1',
    headers: xTargetHost !== undefined ? { 'x-target-host': xTargetHost } : {},
  } as unknown as Request;
}

/** Spin up a minimal JSON echo backend on an ephemeral port. */
function startBackend(payload: unknown): Promise<{ url: string; close: () => Promise<void> }> {
  return new Promise((resolve) => {
    const server = http.createServer((_req, res) => {
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify(payload));
    });
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as AddressInfo;
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        close: () => new Promise<void>((r) => server.close(() => r())),
      });
    });
  });
}

// ---------------------------------------------------------------------------
// TARGET_HOST_RE unit tests
// ---------------------------------------------------------------------------

describe('TARGET_HOST_RE', () => {
  const matching = [
    'api.example.com',
    'localhost',
    '192.168.1.1',
    '[::1]',
    '[2001:db8::1]',
    'api.example.com:8080',
    'localhost:3000',
    'host-with-dashes',
    'UPPERCASE.HOST',
  ];

  const nonMatching = [
    '',
    '/path',
    'host/path',
    'host with space',
  ];

  matching.forEach((s) => {
    it(`matches "${s}"`, () => {
      expect(TARGET_HOST_RE.test(s)).toBe(true);
    });
  });

  nonMatching.forEach((s) => {
    it(`does not match "${s}"`, () => {
      expect(TARGET_HOST_RE.test(s)).toBe(false);
    });
  });
});

// ---------------------------------------------------------------------------
// createTargetHostCanonicalizeMiddleware — isolation tests
// ---------------------------------------------------------------------------

describe('createTargetHostCanonicalizeMiddleware', () => {
  let logger: Logger;
  let warnSpy: jest.SpyInstance;

  beforeEach(() => {
    logger = createLogger('test-canonicalize');
    warnSpy = jest.spyOn(logger, 'warn').mockImplementation(() => logger);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('strips an incoming X-Target-Host and rewrites it from the path', () => {
    const middleware = createTargetHostCanonicalizeMiddleware(logger);
    const req = fakeRequest('/api.example.com/users', 'api.example.com');
    const next = jest.fn();

    middleware(req, {} as Response, next);

    expect(req.headers['x-target-host']).toBe('api.example.com');
    expect(next).toHaveBeenCalledTimes(1);
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('emits a warn and overwrites when client-supplied host differs from path segment', () => {
    const middleware = createTargetHostCanonicalizeMiddleware(logger);
    // Path says api.example.com but client sent admin.internal
    const req = fakeRequest('/api.example.com/users', 'admin.internal');
    const next = jest.fn();

    middleware(req, {} as Response, next);

    // Header must be rewritten to the path-derived value, NOT the client value
    expect(req.headers['x-target-host']).toBe('api.example.com');
    expect(warnSpy).toHaveBeenCalledWith(
      'X-Target-Host stripped: client value differed from URL path host',
      expect.objectContaining({
        clientSuppliedHost: 'admin.internal',
        pathDerivedHost: 'api.example.com',
      }),
    );
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('strips a spoofed header and sets the path-derived host when path has no host segment', () => {
    const middleware = createTargetHostCanonicalizeMiddleware(logger);
    // Path first segment 'v1' looks like a host so it is used;
    // the client-supplied value is a different (attacker-chosen) host.
    const req = fakeRequest('/v1/endpoint', 'admin.internal');
    const next = jest.fn();

    middleware(req, {} as Response, next);

    // 'v1' matches TARGET_HOST_RE, so the header is set to 'v1', not 'admin.internal'
    expect(req.headers['x-target-host']).toBe('v1');
    expect(warnSpy).toHaveBeenCalledWith(
      'X-Target-Host stripped: client value differed from URL path host',
      expect.objectContaining({
        clientSuppliedHost: 'admin.internal',
        pathDerivedHost: 'v1',
      }),
    );
  });

  it('removes the header entirely when the path has no host-like first segment', () => {
    const middleware = createTargetHostCanonicalizeMiddleware(logger);
    // Path with no segments at all
    const req = fakeRequest('/', 'admin.internal');
    const next = jest.fn();

    middleware(req, {} as Response, next);

    expect(req.headers['x-target-host']).toBeUndefined();
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('sets the header from the path when no X-Target-Host was supplied', () => {
    const middleware = createTargetHostCanonicalizeMiddleware(logger);
    const req = fakeRequest('/api.example.com/data');
    const next = jest.fn();

    middleware(req, {} as Response, next);

    expect(req.headers['x-target-host']).toBe('api.example.com');
    expect(warnSpy).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('does not throw and uses first element when X-Target-Host is an array (duplicate header)', () => {
    // Node/Express represent duplicate headers as an array.  The previous code
    // cast to `string` and called `.trim()` which would throw a TypeError.
    const middleware = createTargetHostCanonicalizeMiddleware(logger);
    // Duplicate headers: first is the spoofed value, second is a different host.
    const req = fakeRequest('/api.example.com/data', ['evil.host', 'api.example.com']);
    const next = jest.fn();

    // Must not throw — previously this would crash.
    expect(() => middleware(req, {} as Response, next)).not.toThrow();
    expect(next).toHaveBeenCalledTimes(1);
    // The header must be rewritten to the path-derived value.
    expect(req.headers['x-target-host']).toBe('api.example.com');
    // A warn must be emitted because the first array element differed.
    expect(warnSpy).toHaveBeenCalledWith(
      'X-Target-Host stripped: client value differed from URL path host',
      expect.objectContaining({ clientSuppliedHost: 'evil.host' }),
    );
  });

  it('does not emit a warn when client-supplied host matches path host (case-insensitive)', () => {
    const middleware = createTargetHostCanonicalizeMiddleware(logger);
    const req = fakeRequest('/API.EXAMPLE.COM/users', 'api.example.com');
    const next = jest.fn();

    middleware(req, {} as Response, next);

    expect(warnSpy).not.toHaveBeenCalled();
    // Header is set to the path-derived value (preserving original path casing)
    expect((req.headers['x-target-host'] as string).toLowerCase()).toBe('api.example.com');
  });

  it('handles a bracketed IPv6 address in the path', () => {
    const middleware = createTargetHostCanonicalizeMiddleware(logger);
    const req = fakeRequest('/[::1]:8080/api', '[::1]:8080');
    const next = jest.fn();

    middleware(req, {} as Response, next);

    expect(req.headers['x-target-host']).toBe('[::1]:8080');
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('calls next() exactly once in all branches', () => {
    const middleware = createTargetHostCanonicalizeMiddleware(logger);
    const next = jest.fn();

    middleware(fakeRequest('/api.example.com/path'), {} as Response, next);
    middleware(fakeRequest('/'), {} as Response, next);
    middleware(fakeRequest('/api.example.com/path', 'evil.host'), {} as Response, next);

    expect(next).toHaveBeenCalledTimes(3);
  });
});

// ---------------------------------------------------------------------------
// End-to-end security scenarios (full app stack)
// ---------------------------------------------------------------------------

describe('/proxy/* X-Target-Host strip-and-rewrite security scenarios', () => {
  it('enforces using the path-derived resource even when client sends a spoofed X-Target-Host', async () => {
    // Capability grants access to api://api.example.com/**
    // Client sends X-Target-Host: admin.internal (a privileged resource label)
    // The request path is /proxy/api.example.com/data
    // The middleware must strip admin.internal and use api.example.com from the path.
    const backend = await startBackend({ ok: true });
    try {
      const { deps, privateKey } = await buildDeps(backend.url);
      const app = createApp(deps);

      const token = await signToken(privateKey, [
        { resource: 'api://api.example.com/**', actions: ['read'] },
      ]);

      const res = await request(app)
        .get('/proxy/api.example.com/data')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Target-Host', 'admin.internal'); // spoofed — should be ignored

      // Request should succeed: the strip-and-rewrite uses api.example.com
      // from the path, which matches the capability.
      expect(res.status).toBe(200);
    } finally {
      await backend.close();
    }
  });

  it('rejects a request whose path-derived host does not match the capability resource', async () => {
    // Capability grants access to api://admin.internal/**
    // Path is /proxy/api.example.com/data → resource is api://api.example.com/data
    // Even if client sends X-Target-Host: admin.internal it is stripped and
    // rewritten to api.example.com, so the capability check fails.
    const backend = await startBackend({ ok: true });
    try {
      const { deps, privateKey } = await buildDeps(backend.url);
      const app = createApp(deps);

      const token = await signToken(privateKey, [
        { resource: 'api://admin.internal/**', actions: ['read'] },
      ]);

      const res = await request(app)
        .get('/proxy/api.example.com/data')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Target-Host', 'admin.internal'); // spoofed — must be ignored

      // The strip-and-rewrite derives api.example.com from the path;
      // that does NOT match the api://admin.internal/** capability → 403.
      expect(res.status).toBe(403);
    } finally {
      await backend.close();
    }
  });

  it('handles a request with no X-Target-Host header (path-only resource derivation)', async () => {
    const backend = await startBackend({ hello: 'world' });
    try {
      const { deps, privateKey } = await buildDeps(backend.url);
      const app = createApp(deps);

      const token = await signToken(privateKey, [
        { resource: 'api://api.example.com/**', actions: ['read'] },
      ]);

      const res = await request(app)
        .get('/proxy/api.example.com/hello')
        .set('Authorization', `Bearer ${token}`);
      // No X-Target-Host header at all — middleware sets it from path

      expect(res.status).toBe(200);
    } finally {
      await backend.close();
    }
  });

  it('allows a legitimate request whose X-Target-Host matches the path (canonical client)', async () => {
    // A correctly-implemented client sends X-Target-Host: api.example.com
    // and the path also has api.example.com as the first segment.
    // The middleware rewrites the header to the same value — no warn emitted.
    const backend = await startBackend({ data: 'ok' });
    try {
      const { deps, privateKey } = await buildDeps(backend.url);
      const app = createApp(deps);

      const token = await signToken(privateKey, [
        { resource: 'api://api.example.com/**', actions: ['read'] },
      ]);

      const res = await request(app)
        .get('/proxy/api.example.com/data')
        .set('Authorization', `Bearer ${token}`)
        .set('X-Target-Host', 'api.example.com'); // matches path — OK

      expect(res.status).toBe(200);
    } finally {
      await backend.close();
    }
  });
});
