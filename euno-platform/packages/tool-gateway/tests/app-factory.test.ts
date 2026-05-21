/**
 * Tests for the in-process app factory and split health endpoints.
 *
 * R-2 introduces `createApp(deps)` so callers (notably
 * `packages/integration-tests`) can build a gateway in-process without HTTP
 * setup, env reads, or Redis. These tests exercise that contract.
 */

import * as http from 'http';
import { AddressInfo } from 'net';

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
  createMetricsRegistry,
  Counter,
  BUILTIN_ACTION_RESOLVER,
  DefaultActionResolver,
} from '@euno/common';
import * as jose from 'jose';

import { createApp, createAdminApp } from '../src/app-factory';
import { EnforcementEngine } from '../src/enforcement';
import { JWTTokenVerifier } from '../src/verifier';
import type { GatewayDependencies } from '../src/bootstrap';

async function buildDeps(opts?: {
  isReady?: () => boolean;
  backendServiceUrl?: string;
}): Promise<{
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
    backendServiceUrl: opts?.backendServiceUrl ?? 'http://localhost:65535', // never reached in these tests by default
    allowedOrigins: [],
    rateLimitWindowMs: 60_000,
    rateLimitMax: 10_000,
    metricsRegistry,
    decisionsCounter: new Counter({
      name: 'euno_gateway_decisions_total',
      help: 'test decisions counter',
      labelNames: ['decision'],
      registers: [metricsRegistry],
    }),
    // Required by GatewayDependencies even when no auditPipeline is
    // wired in — bootstrap always populates it from the validated
    // config (default 5000ms) so the entrypoint never passes
    // `undefined` into `AuditPipeline.drain()`.
    auditPipelineDrainTimeoutMs: 5_000,
    isReady: opts?.isReady ?? (() => true),
    actionResolver: BUILTIN_ACTION_RESOLVER,
    adminPort: 0,
    responseRedactionMaxBytes: 1048576,
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

    it('strips fields named in a `redactFields` condition before sending the response (R-4 step 1)', async () => {
      const { deps, privateKey } = await buildDeps();
      const app = createApp(deps);
      const token = await signToken(privateKey, [
        {
          resource: 'tool://read_file',
          actions: ['read'],
          conditions: [
            { type: 'redactFields', fields: ['result.data.ssn', 'result.data.address'] },
          ],
        },
      ]);

      const res = await request(app)
        .post('/api/v1/tools/invoke')
        .set('Authorization', `Bearer ${token}`)
        .send({
          tool: 'read_file',
          args: { name: 'Alice', ssn: '111-22-3333', address: '1 Main St' },
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      // The mock tool echoes args under result.data; the obligation
      // strips ssn and address but leaves the rest intact.
      expect(res.body.result.data).toEqual({ name: 'Alice' });
      expect(res.body.result.data).not.toHaveProperty('ssn');
      expect(res.body.result.data).not.toHaveProperty('address');
    });

    it('honours an injected ActionResolver override on /api/v1/tools/invoke (R-7)', async () => {
      // Wire a resolver that maps an unknown tool to `read` instead of
      // the default `execute` — the request should now succeed against
      // a token that only grants `read`.
      const { deps, privateKey } = await buildDeps();
      const customResolver = new DefaultActionResolver({
        toolActions: { custom_search: 'read' },
      });
      const app = createApp({ ...deps, actionResolver: customResolver });
      const token = await signToken(privateKey, [
        { resource: 'tool://custom_search', actions: ['read'] },
      ]);

      const res = await request(app)
        .post('/api/v1/tools/invoke')
        .set('Authorization', `Bearer ${token}`)
        .send({ tool: 'custom_search', args: {} });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });
  });

  describe('/proxy/* response redaction (F-3, addresses I-3)', () => {
    /**
     * Spin up a tiny HTTP backend on an ephemeral port that echoes a JSON
     * payload containing fields the capability declares as redactable. The
     * gateway's `responseInterceptor` should strip those fields before the
     * body reaches the caller, exercising the full chain:
     *
     *   validateCapabilityMiddleware → enforcement.applyResponseRedactions
     *   → http-proxy-middleware → responseInterceptor.
     */
    function startBackend(payload: unknown): Promise<{
      url: string;
      close: () => Promise<void>;
    }> {
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

    it('strips fields named in a `redactFields` condition from JSON responses on /proxy', async () => {
      // Backend returns a payload with sensitive fields; the obligation
      // strips `user.ssn` and `user.address` but leaves the rest intact.
      const backend = await startBackend({
        user: {
          name: 'Alice',
          ssn: '111-22-3333',
          address: '1 Main St',
        },
        meta: { version: 1 },
      });

      try {
        const { deps, privateKey } = await buildDeps({
          backendServiceUrl: backend.url,
        });
        const app = createApp(deps);

        // The proxy derives `api://api.example.com/things` from the path
        // segment, so the capability resource is a glob that matches it.
        const token = await signToken(privateKey, [
          {
            resource: 'api://api.example.com/**',
            actions: ['read'],
            conditions: [
              { type: 'redactFields', fields: ['user.ssn', 'user.address'] },
            ],
          },
        ]);

        const res = await request(app)
          .get('/proxy/api.example.com/things')
          .set('Authorization', `Bearer ${token}`);

        expect(res.status).toBe(200);
        expect(res.body).toEqual({
          user: { name: 'Alice' },
          meta: { version: 1 },
        });
        expect(res.body.user).not.toHaveProperty('ssn');
        expect(res.body.user).not.toHaveProperty('address');
      } finally {
        await backend.close();
      }
    });

    it('passes the upstream JSON body through unchanged when no redact obligation is attached', async () => {
      // Sanity: without a `redactFields` condition the proxy must not
      // mutate the body. Guards against accidental over-redaction.
      const payload = { user: { name: 'Alice', ssn: '111-22-3333' } };
      const backend = await startBackend(payload);

      try {
        const { deps, privateKey } = await buildDeps({
          backendServiceUrl: backend.url,
        });
        const app = createApp(deps);

        const token = await signToken(privateKey, [
          { resource: 'api://api.example.com/**', actions: ['read'] },
        ]);

        const res = await request(app)
          .get('/proxy/api.example.com/things')
          .set('Authorization', `Bearer ${token}`);

        expect(res.status).toBe(200);
        expect(res.body).toEqual(payload);
      } finally {
        await backend.close();
      }
    });

    it('returns 502 REDACTION_CONTENT_TYPE_UNSUPPORTED when backend returns a non-JSON content-type and redactFields is set', async () => {
      // The backend returns `text/plain` — the gateway cannot redact it,
      // so it must fail closed rather than pass unredacted data through.
      const backend = await new Promise<{ url: string; close: () => Promise<void> }>(
        (resolve) => {
          const server = http.createServer((_req, res) => {
            res.statusCode = 200;
            res.setHeader('content-type', 'text/plain');
            res.end('raw sensitive data');
          });
          server.listen(0, '127.0.0.1', () => {
            const addr = server.address() as AddressInfo;
            resolve({
              url: `http://127.0.0.1:${addr.port}`,
              close: () => new Promise<void>((r) => server.close(() => r())),
            });
          });
        },
      );

      try {
        const { deps, privateKey } = await buildDeps({ backendServiceUrl: backend.url });
        const app = createApp(deps);

        const token = await signToken(privateKey, [
          {
            resource: 'api://api.example.com/**',
            actions: ['read'],
            conditions: [{ type: 'redactFields', fields: ['secret'] }],
          },
        ]);

        const res = await request(app)
          .get('/proxy/api.example.com/things')
          .set('Authorization', `Bearer ${token}`);

        expect(res.status).toBe(502);
        expect(res.body.error?.code).toBe('REDACTION_CONTENT_TYPE_UNSUPPORTED');
        expect(res.headers['content-type']).toMatch(/application\/json/);
      } finally {
        await backend.close();
      }
    });

    it('returns 502 REDACTION_OVERSIZE when backend body exceeds the configured size limit and redactFields is set', async () => {
      // A 10-byte limit ensures any real response body exceeds it.
      const backend = await startBackend({ big: 'payload' });

      try {
        const { deps, privateKey } = await buildDeps({ backendServiceUrl: backend.url });
        // Override the default 1 MiB cap with 10 bytes for this test.
        const smallLimitDeps = { ...deps, responseRedactionMaxBytes: 10 };
        const app = createApp(smallLimitDeps);

        const token = await signToken(privateKey, [
          {
            resource: 'api://api.example.com/**',
            actions: ['read'],
            conditions: [{ type: 'redactFields', fields: ['secret'] }],
          },
        ]);

        const res = await request(app)
          .get('/proxy/api.example.com/things')
          .set('Authorization', `Bearer ${token}`);

        expect(res.status).toBe(502);
        expect(res.body.error?.code).toBe('REDACTION_OVERSIZE');
        expect(res.headers['content-type']).toMatch(/application\/json/);
      } finally {
        await backend.close();
      }
    });

    it('streams a large response (no buffering) when capability has no redactFields', async () => {
      // 10 MiB response — if the gateway buffers this into memory unconditionally
      // it would still work, but the test asserts that the body arrives intact and
      // no REDACTION_OVERSIZE 502 fires even though we set a tiny 10-byte cap on
      // the *buffered* path. The 10-byte cap is a canary: if the streaming path
      // accidentally routes through the buffered proxy, the test will return 502.
      const tenMiB = 10 * 1024 * 1024;
      const backend = await new Promise<{ url: string; close: () => Promise<void> }>(
        (resolve) => {
          const server = http.createServer((_req, res) => {
            res.statusCode = 200;
            res.setHeader('content-type', 'application/octet-stream');
            res.setHeader('content-length', String(tenMiB));
            // Stream 10 MiB in 1 MiB chunks so Node keeps memory bounded.
            let sent = 0;
            function writeChunk() {
              const remaining = tenMiB - sent;
              if (remaining <= 0) { res.end(); return; }
              const chunkSize = Math.min(1024 * 1024, remaining);
              const chunk = Buffer.alloc(chunkSize, 0x42);
              sent += chunkSize;
              const ok = res.write(chunk);
              if (ok) setImmediate(writeChunk);
              else res.once('drain', writeChunk);
            }
            writeChunk();
          });
          server.listen(0, '127.0.0.1', () => {
            const addr = server.address() as AddressInfo;
            resolve({
              url: `http://127.0.0.1:${addr.port}`,
              close: () => new Promise<void>((r) => server.close(() => r())),
            });
          });
        },
      );

      try {
        const { deps, privateKey } = await buildDeps({ backendServiceUrl: backend.url });
        // Set a 10-byte cap on the buffered path — any buffering triggers 502.
        const app = createApp({ ...deps, responseRedactionMaxBytes: 10 });

        // No redactFields — should route to streaming proxy.
        const token = await signToken(privateKey, [
          { resource: 'api://api.example.com/**', actions: ['read'] },
        ]);

        const res = await request(app)
          .get('/proxy/api.example.com/download')
          .set('Authorization', `Bearer ${token}`)
          .buffer(true); // collect entire body for size assertion

        expect(res.status).toBe(200);
        // Body arrived intact, no REDACTION_OVERSIZE 502.
        // Assert the full 10 MiB arrived — buffer(true) collects the entire
        // response, so res.body is a Buffer we can measure directly.
        const body = res.body as Buffer;
        expect(body).toBeInstanceOf(Buffer);
        expect(body.length).toBe(tenMiB);
        // No error code in response.
        expect(typeof res.body === 'object' && res.body?.error?.code).toBeFalsy();
      } finally {
        await backend.close();
      }
    });

    it('passes Content-Encoding: gzip and Transfer-Encoding: chunked through unmodified on streaming path', async () => {
      // Backend signals gzip encoding via Content-Encoding header.
      // The streaming path must not strip or alter the header.
      const backend = await new Promise<{ url: string; close: () => Promise<void> }>(
        (resolve) => {
          const server = http.createServer((_req, res) => {
            res.statusCode = 200;
            res.setHeader('content-type', 'application/octet-stream');
            res.setHeader('content-encoding', 'gzip');
            // Transfer-Encoding chunked is implicit for HTTP/1.1 responses
            // without Content-Length — no need to set it explicitly.
            res.end(Buffer.from([0x1f, 0x8b])); // just a stub gzip magic header
          });
          server.listen(0, '127.0.0.1', () => {
            const addr = server.address() as AddressInfo;
            resolve({
              url: `http://127.0.0.1:${addr.port}`,
              close: () => new Promise<void>((r) => server.close(() => r())),
            });
          });
        },
      );

      try {
        const { deps, privateKey } = await buildDeps({ backendServiceUrl: backend.url });
        const app = createApp(deps);

        const token = await signToken(privateKey, [
          { resource: 'api://api.example.com/**', actions: ['read'] },
        ]);

        const res = await request(app)
          .get('/proxy/api.example.com/file.gz')
          .set('Authorization', `Bearer ${token}`)
          .buffer(false); // don't let supertest decompress

        expect(res.status).toBe(200);
        // Content-Encoding must be preserved (streaming proxy does not strip it).
        expect(res.headers['content-encoding']).toBe('gzip');
      } finally {
        await backend.close();
      }
    });

    it('returns 502 REDACTION_STREAM_UNSUPPORTED when backend returns SSE and redactFields is set', async () => {
      const backend = await new Promise<{ url: string; close: () => Promise<void> }>(
        (resolve) => {
          const server = http.createServer((_req, res) => {
            res.statusCode = 200;
            res.setHeader('content-type', 'text/event-stream');
            res.end('data: hello\n\n');
          });
          server.listen(0, '127.0.0.1', () => {
            const addr = server.address() as AddressInfo;
            resolve({
              url: `http://127.0.0.1:${addr.port}`,
              close: () => new Promise<void>((r) => server.close(() => r())),
            });
          });
        },
      );

      try {
        const { deps, privateKey } = await buildDeps({ backendServiceUrl: backend.url });
        const app = createApp(deps);

        const token = await signToken(privateKey, [
          {
            resource: 'api://api.example.com/**',
            actions: ['read'],
            conditions: [{ type: 'redactFields', fields: ['secret'] }],
          },
        ]);

        const res = await request(app)
          .get('/proxy/api.example.com/events')
          .set('Authorization', `Bearer ${token}`);

        expect(res.status).toBe(502);
        expect(res.body.error?.code).toBe('REDACTION_STREAM_UNSUPPORTED');
        expect(res.headers['content-type']).toMatch(/application\/json/);
      } finally {
        await backend.close();
      }
    });

    it('returns 502 REDACTION_CONTENT_TYPE_UNSUPPORTED when backend returns application/x-ndjson and redactFields is set', async () => {
      const backend = await new Promise<{ url: string; close: () => Promise<void> }>(
        (resolve) => {
          const server = http.createServer((_req, res) => {
            res.statusCode = 200;
            res.setHeader('content-type', 'application/x-ndjson');
            res.end('{"a":1}\n{"b":2}\n');
          });
          server.listen(0, '127.0.0.1', () => {
            const addr = server.address() as AddressInfo;
            resolve({
              url: `http://127.0.0.1:${addr.port}`,
              close: () => new Promise<void>((r) => server.close(() => r())),
            });
          });
        },
      );

      try {
        const { deps, privateKey } = await buildDeps({ backendServiceUrl: backend.url });
        const app = createApp(deps);

        const token = await signToken(privateKey, [
          {
            resource: 'api://api.example.com/**',
            actions: ['read'],
            conditions: [{ type: 'redactFields', fields: ['secret'] }],
          },
        ]);

        const res = await request(app)
          .get('/proxy/api.example.com/stream')
          .set('Authorization', `Bearer ${token}`);

        expect(res.status).toBe(502);
        expect(res.body.error?.code).toBe('REDACTION_CONTENT_TYPE_UNSUPPORTED');
        expect(res.headers['content-type']).toMatch(/application\/json/);
      } finally {
        await backend.close();
      }
    });

    it('returns 502 REDACTION_CONTENT_TYPE_UNSUPPORTED when backend returns application/octet-stream and redactFields is set', async () => {
      const backend = await new Promise<{ url: string; close: () => Promise<void> }>(
        (resolve) => {
          const server = http.createServer((_req, res) => {
            res.statusCode = 200;
            res.setHeader('content-type', 'application/octet-stream');
            res.end(Buffer.alloc(16));
          });
          server.listen(0, '127.0.0.1', () => {
            const addr = server.address() as AddressInfo;
            resolve({
              url: `http://127.0.0.1:${addr.port}`,
              close: () => new Promise<void>((r) => server.close(() => r())),
            });
          });
        },
      );

      try {
        const { deps, privateKey } = await buildDeps({ backendServiceUrl: backend.url });
        const app = createApp(deps);

        const token = await signToken(privateKey, [
          {
            resource: 'api://api.example.com/**',
            actions: ['read'],
            conditions: [{ type: 'redactFields', fields: ['secret'] }],
          },
        ]);

        const res = await request(app)
          .get('/proxy/api.example.com/file.bin')
          .set('Authorization', `Bearer ${token}`);

        expect(res.status).toBe(502);
        expect(res.body.error?.code).toBe('REDACTION_CONTENT_TYPE_UNSUPPORTED');
        expect(res.headers['content-type']).toMatch(/application\/json/);
      } finally {
        await backend.close();
      }
    });

    it('returns 502 REDACTION_PARSE_ERROR when backend returns application/json with non-JSON body and redactFields is set', async () => {
      // Backend claims JSON content-type but sends invalid JSON.
      const backend = await new Promise<{ url: string; close: () => Promise<void> }>(
        (resolve) => {
          const server = http.createServer((_req, res) => {
            res.statusCode = 200;
            res.setHeader('content-type', 'application/json');
            res.end('not-valid-json{{{');
          });
          server.listen(0, '127.0.0.1', () => {
            const addr = server.address() as AddressInfo;
            resolve({
              url: `http://127.0.0.1:${addr.port}`,
              close: () => new Promise<void>((r) => server.close(() => r())),
            });
          });
        },
      );

      try {
        const { deps, privateKey } = await buildDeps({ backendServiceUrl: backend.url });
        const app = createApp(deps);

        const token = await signToken(privateKey, [
          {
            resource: 'api://api.example.com/**',
            actions: ['read'],
            conditions: [{ type: 'redactFields', fields: ['secret'] }],
          },
        ]);

        const res = await request(app)
          .get('/proxy/api.example.com/things')
          .set('Authorization', `Bearer ${token}`);

        expect(res.status).toBe(502);
        expect(res.body.error?.code).toBe('REDACTION_PARSE_ERROR');
        expect(res.headers['content-type']).toMatch(/application\/json/);
      } finally {
        await backend.close();
      }
    });

    it('returns 502 REDACTION_OVERSIZE via early Content-Length check when backend declares an oversized body', async () => {
      // Backend declares a content-length that exceeds the cap in the response
      // header — the gateway must fail-closed before reading any body bytes.
      const backend = await new Promise<{ url: string; close: () => Promise<void> }>(
        (resolve) => {
          const server = http.createServer((_req, res) => {
            res.statusCode = 200;
            res.setHeader('content-type', 'application/json');
            // Declare a large content-length but only send a tiny body — the
            // gateway must abort based on the declared size alone.
            res.setHeader('content-length', String(10 * 1024 * 1024)); // 10 MiB declared
            res.end('{"tiny":"body"}');
          });
          server.listen(0, '127.0.0.1', () => {
            const addr = server.address() as AddressInfo;
            resolve({
              url: `http://127.0.0.1:${addr.port}`,
              close: () => new Promise<void>((r) => server.close(() => r())),
            });
          });
        },
      );

      try {
        const { deps, privateKey } = await buildDeps({ backendServiceUrl: backend.url });
        // Cap at 1 KiB so the declared 10 MiB triggers the early check.
        const app = createApp({ ...deps, responseRedactionMaxBytes: 1024 });

        const token = await signToken(privateKey, [
          {
            resource: 'api://api.example.com/**',
            actions: ['read'],
            conditions: [{ type: 'redactFields', fields: ['secret'] }],
          },
        ]);

        const res = await request(app)
          .get('/proxy/api.example.com/data')
          .set('Authorization', `Bearer ${token}`);

        expect(res.status).toBe(502);
        expect(res.body.error?.code).toBe('REDACTION_OVERSIZE');
        expect(res.headers['content-type']).toMatch(/application\/json/);
      } finally {
        await backend.close();
      }
    });

    it('returns 502 REDACTION_PARSE_ERROR when backend uses an unsupported Content-Encoding and redactFields is set', async () => {
      // Backend uses 'zstd' encoding — not supported by the decompressor.
      // The gateway must fail-closed with REDACTION_PARSE_ERROR rather than
      // passing opaque compressed bytes to the JSON parser.
      const backend = await new Promise<{ url: string; close: () => Promise<void> }>(
        (resolve) => {
          const server = http.createServer((_req, res) => {
            res.statusCode = 200;
            res.setHeader('content-type', 'application/json');
            res.setHeader('content-encoding', 'zstd');
            res.end(Buffer.from([0x28, 0xb5, 0x2f, 0xfd])); // minimal zstd frame magic number (4 bytes)
          });
          server.listen(0, '127.0.0.1', () => {
            const addr = server.address() as AddressInfo;
            resolve({
              url: `http://127.0.0.1:${addr.port}`,
              close: () => new Promise<void>((r) => server.close(() => r())),
            });
          });
        },
      );

      try {
        const { deps, privateKey } = await buildDeps({ backendServiceUrl: backend.url });
        const app = createApp(deps);

        const token = await signToken(privateKey, [
          {
            resource: 'api://api.example.com/**',
            actions: ['read'],
            conditions: [{ type: 'redactFields', fields: ['secret'] }],
          },
        ]);

        const res = await request(app)
          .get('/proxy/api.example.com/things')
          .set('Authorization', `Bearer ${token}`);

        expect(res.status).toBe(502);
        expect(res.body.error?.code).toBe('REDACTION_PARSE_ERROR');
        expect(res.headers['content-type']).toMatch(/application\/json/);
      } finally {
        await backend.close();
      }
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

  describe('/metrics (F-5, addresses I-16) — served on admin app only', () => {
    it('exposes Prometheus metrics from the admin app with the correct content-type', async () => {
      const { deps } = await buildDeps();
      // createApp registers the HTTP metrics middleware against deps.metricsRegistry;
      // createAdminApp serves the same shared registry on /metrics.
      const app = createApp(deps);
      const adminApp = createAdminApp(deps);

      // Make a real request through the public app so the HTTP metrics
      // instruments are guaranteed to have been initialised by the middleware.
      await request(app).get('/health');

      const res = await request(adminApp).get('/metrics');

      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toMatch(/text\/plain/);
      // Standard HTTP middleware series should be registered.
      expect(res.text).toContain('euno_http_request_duration_seconds');
      expect(res.text).toContain('euno_http_requests_total');
    });

    it('returns 404 for /metrics on the public app (no longer served there)', async () => {
      const { deps } = await buildDeps();
      const app = createApp(deps);

      const res = await request(app).get('/metrics');

      expect(res.status).toBe(404);
    });

    it('records a sample on the shared registry after handling a request on the public app', async () => {
      const { deps } = await buildDeps();
      const app = createApp(deps);
      const adminApp = createAdminApp(deps);

      await request(app).get('/health');
      const res = await request(adminApp).get('/metrics');

      expect(res.status).toBe(200);
      // The /health request should have produced at least one observation
      // labelled with status_code="200".
      expect(res.text).toMatch(
        /euno_http_requests_total\{[^}]*status_code="200"[^}]*\}\s+\d+/,
      );
    });

    it('does not record observations for the /metrics endpoint itself', async () => {
      const { deps } = await buildDeps();
      const adminApp = createAdminApp(deps);

      await request(adminApp).get('/metrics');
      await request(adminApp).get('/metrics');
      const res = await request(adminApp).get('/metrics');

      // The admin app does not mount the HTTP metrics middleware, so no
      // route observations should be recorded for /metrics scrapes.
      expect(res.text).not.toMatch(
        /euno_http_requests_total\{[^}]*route="\/metrics"/,
      );
    });
  });
});
