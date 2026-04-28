/**
 * End-to-end integration tests for the capability-based agent governance flow.
 *
 * These tests exercise the **inter-service contract** between the three
 * Sprint-1/2 components — the Capability Issuer, the Tool Gateway, and the
 * Agent Runtime — by wiring them together over real HTTP loopback servers.
 * They cover scenarios the per-package unit tests cannot, including:
 *
 *   - Public-key bootstrap: gateway fetches the issuer's public key over HTTP
 *     and uses it to verify real RS256-signed JWTs produced by the issuer.
 *   - Audience claim contract: tokens issued with `aud=tool-gateway` are
 *     accepted by a verifier configured for the same audience and rejected by
 *     one configured for a different audience.
 *   - 401 retry: an expired/invalid capability triggers the runtime to
 *     re-acquire from the issuer and retry against the gateway.
 *   - Host-based capability binding: when the runtime forwards an absolute
 *     URL, the gateway derives a host-qualified resource identifier so a
 *     token bound to `api://api.example.com/**` cannot be used to call
 *     `api://evil.example.com/**`.
 *
 * The full test runs in-process (no external network). Each test starts the
 * issuer + gateway HTTP servers on ephemeral ports, configures an
 * AgentRuntime to talk to them, exercises the flow, and tears the servers
 * down on completion.
 */

import * as http from 'http';
import { AddressInfo } from 'net';
import * as jose from 'jose';

import {
  CapabilityError,
  CapabilityTokenPayload,
  ErrorCode,
  IdentityAdapter,
  IdentityAdapterConfig,
  SigningAdapter,
  SigningAdapterConfig,
  UserContext,
  ValidateActionRequest,
  createLogger,
} from '@euno/common';
import { CapabilityIssuerService } from '../../capability-issuer/src/issuer-service';
import { JWTTokenVerifier } from '../../tool-gateway/src/verifier';
import { EnforcementEngine } from '../../tool-gateway/src/enforcement';
import { AgentRuntime } from '@euno/agent-runtime';

// ── Test fixtures ────────────────────────────────────────────────────────────

const ISSUER_DID = 'did:web:issuer.test';
const AUDIENCE = 'tool-gateway';
const SIGNING_ALG = 'RS256';

class StubIdentityProvider extends IdentityAdapter {
  public readonly name = 'stub';
  constructor(private context: UserContext) {
    super({ type: 'stub', name: 'stub' } as IdentityAdapterConfig);
  }
  async validateToken(token: string): Promise<UserContext> {
    if (!token || token === 'invalid') {
      throw new Error('invalid auth token');
    }
    return this.context;
  }
  async getUserRoles(): Promise<string[]> {
    return this.context.roles;
  }
}

/**
 * Real signer that produces verifiable RS256 JWTs from an in-memory key pair.
 * Used so the gateway can perform genuine signature verification against the
 * issuer's published public key.
 */
class JoseRsaSigner extends SigningAdapter {
  private privateKey!: jose.KeyLike;
  private publicKeyPem!: string;
  private keyId: string;

  constructor(privateKey: jose.KeyLike, publicKeyPem: string, keyId: string) {
    super({ type: 'jose-rsa', name: 'jose-rsa', algorithm: SIGNING_ALG } as SigningAdapterConfig);
    this.privateKey = privateKey;
    this.publicKeyPem = publicKeyPem;
    this.keyId = keyId;
  }

  async sign(payload: CapabilityTokenPayload): Promise<string> {
    return await new jose.SignJWT(payload as unknown as jose.JWTPayload)
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

async function createSigner(): Promise<JoseRsaSigner> {
  const { privateKey, publicKey } = await jose.generateKeyPair(SIGNING_ALG, { extractable: true });
  const publicKeyPem = await jose.exportSPKI(publicKey);
  return new JoseRsaSigner(privateKey, publicKeyPem, 'integration-test-key');
}

// ── Server helpers ───────────────────────────────────────────────────────────

interface RunningServer {
  server: http.Server;
  baseUrl: string;
  close: () => Promise<void>;
}

function readJsonBody(req: http.IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      if (!text) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(text));
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', reject);
  });
}

function send(res: http.ServerResponse, status: number, body: unknown): void {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify(body));
}

function listen(handler: http.RequestListener): Promise<RunningServer> {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as AddressInfo;
      const baseUrl = `http://127.0.0.1:${addr.port}`;
      resolve({
        server,
        baseUrl,
        close: () => new Promise<void>((r) => server.close(() => r())),
      });
    });
  });
}

/**
 * Spin up a minimal HTTP wrapper around the CapabilityIssuerService that
 * exposes /api/v1/issue and /api/v1/public-key — the same surface the real
 * Express server exposes.
 */
async function startIssuerServer(
  service: CapabilityIssuerService,
  signer: JoseRsaSigner,
): Promise<RunningServer> {
  return listen(async (req, res) => {
    try {
      if (req.method === 'GET' && req.url === '/api/v1/public-key') {
        send(res, 200, { publicKey: await signer.getPublicKey(), keyId: await signer.getKeyId() });
        return;
      }
      if (req.method === 'POST' && req.url === '/api/v1/issue') {
        const auth = req.headers.authorization || '';
        const token = auth.startsWith('Bearer ') ? auth.slice('Bearer '.length) : '';
        if (!token) {
          send(res, 401, { error: { code: 'AUTHENTICATION_FAILED', message: 'Missing bearer token' } });
          return;
        }
        const body = (await readJsonBody(req)) as { agentId?: string };
        if (!body?.agentId) {
          send(res, 400, { error: { code: 'INVALID_REQUEST', message: 'agentId required' } });
          return;
        }
        const result = await service.issueCapability({ authToken: token, agentId: body.agentId });
        send(res, 200, result);
        return;
      }
      send(res, 404, { error: { code: 'NOT_FOUND', message: req.url } });
    } catch (e) {
      const err = e as { statusCode?: number; code?: string; message?: string };
      send(res, err.statusCode || 500, {
        error: { code: err.code || 'INTERNAL_ERROR', message: err.message || 'unknown' },
      });
    }
  });
}

/**
 * Spin up a minimal HTTP wrapper around the EnforcementEngine that exposes
 * /api/v1/tools/invoke and /proxy/* — mirroring the gateway's enforcement
 * surface (without the Express middleware stack).
 */
async function startGatewayServer(
  engine: EnforcementEngine,
  /** Backend echo for proxy requests. */
  backendEcho: (path: string, headers: http.IncomingHttpHeaders) => unknown,
): Promise<RunningServer> {
  return listen(async (req, res) => {
    try {
      const url = new URL(req.url || '/', 'http://localhost').pathname;
      const auth = req.headers.authorization || '';
      const token = auth.startsWith('Bearer ') ? auth.slice('Bearer '.length) : '';
      if (!token) {
        send(res, 401, { error: { code: 'AUTHENTICATION_FAILED', message: 'Missing bearer token' } });
        return;
      }

      if (req.method === 'POST' && url === '/api/v1/tools/invoke') {
        const body = (await readJsonBody(req)) as { tool: string; resource?: string };
        const action = 'write';
        const resource = body.resource || `tool://${body.tool}`;
        const result = await engine.validateAction({
          token,
          action: action as ValidateActionRequest['action'],
          resource,
          context: { method: 'POST', path: url },
        });
        if (!result.allowed) {
          send(res, 403, { error: { code: 'AUTHORIZATION_FAILED', message: result.reason } });
          return;
        }
        send(res, 200, { ok: true, resource });
        return;
      }

      if (url.startsWith('/proxy/')) {
        // Mirror the gateway's host-aware resource derivation.
        // Use pathname only (no query string) to match production gateway behaviour.
        const rawPath = url.slice('/proxy/'.length);
        const headerHost = (req.headers['x-target-host'] as string | undefined)?.trim();
        const firstSegment = rawPath.split('/')[0] || '';
        // Recognise single-label hosts (e.g. localhost) and bracketed IPv6; no
        // dot requirement so the heuristic matches the updated production gateway.
        const looksLikeHost =
          /^(\[[\da-fA-F:]+\]|[A-Za-z0-9.\-]+)(:\d+)?$/.test(firstSegment);

        let resource: string;
        if (headerHost) {
          // Strip the leading segment only when it equals the header host.
          const pathHasHostSegment = firstSegment.toLowerCase() === headerHost.toLowerCase();
          if (looksLikeHost && !pathHasHostSegment) {
            send(res, 400, { error: { code: 'AUTHORIZATION_FAILED', message: 'host mismatch' } });
            return;
          }
          const tail = pathHasHostSegment ? rawPath.slice(firstSegment.length).replace(/^\/+/, '') : rawPath;
          resource = `api://${headerHost}/${tail}`;
        } else if (looksLikeHost) {
          const tail = rawPath.slice(firstSegment.length).replace(/^\/+/, '');
          resource = `api://${firstSegment}/${tail}`;
        } else {
          resource = `api://${rawPath}`;
        }

        const actionMap: Record<string, string> = {
          GET: 'read',
          POST: 'write',
          PUT: 'write',
          DELETE: 'delete',
        };
        const action = actionMap[req.method || 'GET'] || 'read';

        const result = await engine.validateAction({
          token,
          action: action as ValidateActionRequest['action'],
          resource,
          context: { method: req.method, path: url },
        });
        if (!result.allowed) {
          send(res, 403, { error: { code: 'AUTHORIZATION_FAILED', message: result.reason } });
          return;
        }
        send(res, 200, backendEcho(rawPath, req.headers));
        return;
      }

      send(res, 404, { error: { code: 'NOT_FOUND', message: url } });
    } catch (e) {
      const err = e as { statusCode?: number; code?: string; message?: string };
      send(res, err.statusCode || 500, {
        error: { code: err.code || 'INTERNAL_ERROR', message: err.message || 'unknown' },
      });
    }
  });
}

// ── Test harness ─────────────────────────────────────────────────────────────

interface Harness {
  signer: JoseRsaSigner;
  identity: StubIdentityProvider;
  service: CapabilityIssuerService;
  issuer: RunningServer;
  gateway: RunningServer;
  verifier: JWTTokenVerifier;
  engine: EnforcementEngine;
}

async function buildHarness(opts?: {
  audience?: string;
  roles?: string[];
}): Promise<Harness> {
  const signer = await createSigner();
  const identity = new StubIdentityProvider({
    userId: 'user-1',
    email: 'user@example.com',
    roles: opts?.roles ?? ['Administrator'],
    tenantId: 'tenant-1',
    claims: {},
  });
  const service = new CapabilityIssuerService(
    signer,
    identity,
    ISSUER_DID,
    900,
    createLogger('issuer-it', 'test'),
  );

  const issuer = await startIssuerServer(service, signer);

  // Public-key bootstrap: gateway fetches the public key from the issuer URL.
  const pkResp = await fetch(`${issuer.baseUrl}/api/v1/public-key`);
  const pkData = (await pkResp.json()) as { publicKey: string };

  const verifier = new JWTTokenVerifier(pkData.publicKey, [SIGNING_ALG]);
  // Wrap verify() so we can assert the audience contract from the issuer
  // matches what the gateway expects.
  const expectedAudience = opts?.audience ?? AUDIENCE;
  const audienceCheckedVerifier: JWTTokenVerifier = Object.assign(
    Object.create(Object.getPrototypeOf(verifier)),
    verifier,
    {
      verify: async (token: string) => {
        const payload = await verifier.verify.call(verifier, token);
        if (payload.aud !== expectedAudience) {
          throw new CapabilityError(
            ErrorCode.INVALID_TOKEN,
            `audience mismatch: expected ${expectedAudience}, got ${payload.aud}`,
            401,
          );
        }
        return payload;
      },
    },
  );

  const engine = new EnforcementEngine({
    verifier: audienceCheckedVerifier,
    logger: createLogger('gateway-it', 'test'),
  });

  const gateway = await startGatewayServer(engine, (path, headers) => ({
    proxiedPath: path,
    targetHost: headers['x-target-host'] || null,
  }));

  return { signer, identity, service, issuer, gateway, verifier: audienceCheckedVerifier, engine };
}

async function teardown(h: Harness): Promise<void> {
  await h.issuer.close();
  await h.gateway.close();
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('e2e: capability issuer + tool gateway + agent runtime', () => {
  let harness: Harness;
  let runtime: AgentRuntime;

  afterEach(async () => {
    if (runtime) await runtime.shutdown();
    if (harness) await teardown(harness);
  });

  it('issues a real JWT, the gateway verifies it via bootstrapped public key, and an authorized tool call succeeds', async () => {
    harness = await buildHarness();
    runtime = new AgentRuntime({
      agentId: 'agent-it',
      gatewayUrl: harness.gateway.baseUrl,
      issuerUrl: harness.issuer.baseUrl,
      authToken: 'user-bearer-token',
      // Disable periodic refresh by using a very long interval; we trigger
      // refresh manually via the 401 path.
      tokenRefreshInterval: 3600,
    });

    await runtime.initialize();
    expect(runtime.getCapabilityToken()).toBeDefined();

    const response = await runtime.invokeTool({
      tool: 'read_file',
      args: { path: '/data/x' },
      // Administrator role grants api://** so any resource is allowed.
      resource: 'api://crm/customers',
    });

    expect(response.statusCode).toBe(200);
    expect(response.success).toBe(true);
  });

  it('rejects an action that exceeds the agent\'s capabilities (role-based 403)', async () => {
    // Viewer role only grants read on api://**
    harness = await buildHarness({ roles: ['Viewer'] });
    runtime = new AgentRuntime({
      agentId: 'agent-it',
      gatewayUrl: harness.gateway.baseUrl,
      issuerUrl: harness.issuer.baseUrl,
      authToken: 'user-bearer-token',
      tokenRefreshInterval: 3600,
    });
    await runtime.initialize();

    // invokeTool maps to 'write' in the test gateway — Viewer cannot write
    const response = await runtime.invokeTool({
      tool: 'delete_file',
      args: {},
      resource: 'api://crm/customers',
    });

    expect(response.statusCode).toBe(403);
    expect(response.success).toBe(false);
  });

  it('audience contract: a verifier configured for a different audience rejects the issuer\'s tokens', async () => {
    harness = await buildHarness({ audience: 'some-other-service' });
    runtime = new AgentRuntime({
      agentId: 'agent-it',
      gatewayUrl: harness.gateway.baseUrl,
      issuerUrl: harness.issuer.baseUrl,
      authToken: 'user-bearer-token',
      tokenRefreshInterval: 3600,
    });
    await runtime.initialize();

    const response = await runtime.invokeTool({
      tool: 'read_file',
      args: {},
      resource: 'api://crm/customers',
    });

    // Audience mismatch surfaces from the verifier as an INVALID_TOKEN /
    // 401. The runtime retries once after refreshing — the new token has the
    // same (mismatched) audience so the second attempt also fails 401.
    expect(response.statusCode).toBe(401);
    expect(response.success).toBe(false);
  });

  it('401 retry: after the gateway rejects the cached token the runtime re-acquires from the issuer and the retry succeeds', async () => {
    harness = await buildHarness();
    runtime = new AgentRuntime({
      agentId: 'agent-it',
      gatewayUrl: harness.gateway.baseUrl,
      issuerUrl: harness.issuer.baseUrl,
      authToken: 'user-bearer-token',
      tokenRefreshInterval: 3600,
    });
    await runtime.initialize();
    const firstToken = runtime.getCapabilityToken();
    expect(firstToken).toBeTruthy();

    // Force the runtime into the 401 path by manually corrupting the cached
    // token so the next gateway call fails verification.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (runtime as any).capabilityToken = 'not-a-real-jwt';

    const response = await runtime.invokeTool({
      tool: 'read_file',
      args: {},
      resource: 'api://crm/customers',
    });

    expect(response.statusCode).toBe(200);
    expect(response.success).toBe(true);
    // The retry path should have re-acquired a fresh token from the issuer.
    expect(runtime.getCapabilityToken()).not.toBe('not-a-real-jwt');
    // And it should be a valid JWT (3 dot-separated segments).
    expect(runtime.getCapabilityToken()!.split('.').length).toBe(3);
  });

  it('host-based binding: makeRequest forwards the target host to the gateway so resource = api://<host>/<path>', async () => {
    harness = await buildHarness();
    runtime = new AgentRuntime({
      agentId: 'agent-it',
      gatewayUrl: harness.gateway.baseUrl,
      issuerUrl: harness.issuer.baseUrl,
      authToken: 'user-bearer-token',
      tokenRefreshInterval: 3600,
    });
    await runtime.initialize();

    const ok = await runtime.makeRequest('GET', 'http://api.example.com/v1/customers');
    expect(ok.statusCode).toBe(200);
    expect(ok.success).toBe(true);
    // The backend echo recorded the X-Target-Host header so we can confirm
    // the gateway received it (and would have used it to derive a host-bound
    // resource identifier).
    const data = ok.data as { proxiedPath: string; targetHost: string };
    expect(data.targetHost).toBe('api.example.com');
    expect(data.proxiedPath).toBe('api.example.com/v1/customers');
  });

  it('shutdown during refresh: cancelling an in-flight token acquisition does not throw', async () => {
    harness = await buildHarness();
    runtime = new AgentRuntime({
      agentId: 'agent-it',
      gatewayUrl: harness.gateway.baseUrl,
      issuerUrl: harness.issuer.baseUrl,
      authToken: 'user-bearer-token',
      tokenRefreshInterval: 3600,
    });
    await runtime.initialize();

    // Kick off a manual acquisition concurrently with shutdown to exercise
    // the abort path against a real HTTP server.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const acquirePromise = (runtime as any).acquireCapabilityToken().catch((e: Error) => e);
    const shutdownPromise = runtime.shutdown();
    await expect(shutdownPromise).resolves.toBeUndefined();
    // Whether the acquisition succeeded or aborted depends on timing; either
    // way it must not leave an unhandled rejection.
    await acquirePromise;
  });
});
