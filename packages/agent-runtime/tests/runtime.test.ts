/**
 * Agent Runtime Tests
 *
 * Uses Jest module mocking to verify request routing, header attachment,
 * token refresh, and 401 retry behaviour without requiring a live server.
 */

import axios from 'axios';
import { AgentRuntime } from '../src/runtime';

// ── axios mock setup ──────────────────────────────────────────────────────────

jest.mock('axios');

const mockedAxios = axios as jest.Mocked<typeof axios>;

// Track instances created by axios.create()
interface FakeInstance {
  post: jest.Mock;
  request: jest.Mock;
  defaults: Record<string, unknown>;
  interceptors: { request: { use: jest.Mock }; response: { use: jest.Mock } };
}

const makeInstance = (): FakeInstance => ({
  post: jest.fn(),
  request: jest.fn(),
  defaults: {},
  interceptors: {
    request: { use: jest.fn() },
    response: { use: jest.fn() },
  },
});

let issuerInstance: FakeInstance;
let gatewayInstance: FakeInstance;

beforeEach(() => {
  jest.clearAllMocks();
  jest.useFakeTimers();

  issuerInstance = makeInstance();
  gatewayInstance = makeInstance();

  // Differentiate instances by baseURL so order of create() calls doesn't matter.
  mockedAxios.create = jest.fn().mockImplementation((cfg?: { baseURL?: string }) => {
    if (cfg?.baseURL?.includes('issuer') || cfg?.baseURL?.includes('3001')) {
      return issuerInstance;
    }
    return gatewayInstance;
  }) as any;
});

afterEach(() => {
  jest.useRealTimers();
});

// Helper to build a runtime with a pre-seeded token so most tests skip real acquisition
function buildRuntime(overrides?: Partial<ConstructorParameters<typeof AgentRuntime>[0]>) {
  return new AgentRuntime({
    agentId: 'test-agent',
    gatewayUrl: 'http://gateway:3002',
    issuerUrl: 'http://issuer:3001',
    authToken: 'bearer-test-token',
    ...overrides as any,
  });
}

// ── initialization ────────────────────────────────────────────────────────────

describe('AgentRuntime – initialization', () => {
  it('creates runtime with valid config', () => {
    const rt = buildRuntime();
    expect(rt).toBeDefined();
  });

  it('acquires a capability token on initialize()', async () => {
    issuerInstance.post.mockResolvedValueOnce({
      status: 200,
      data: { token: 'cap-token-abc' },
    });

    const rt = buildRuntime();
    await rt.initialize();

    expect(issuerInstance.post).toHaveBeenCalledWith(
      '/api/v1/issue',
      { agentId: 'test-agent' },
      expect.objectContaining({
        headers: expect.objectContaining({ Authorization: 'Bearer bearer-test-token' }),
      })
    );
    expect(rt.getCapabilityToken()).toBe('cap-token-abc');
  });

  it('throws CapabilityError (auth) when issuer returns 401', async () => {
    issuerInstance.post.mockResolvedValueOnce({ status: 401, data: {} });

    const rt = buildRuntime();
    await expect(rt.initialize()).rejects.toMatchObject({ statusCode: 401 });
  });

  it('throws CapabilityError (internal) when issuer returns 500', async () => {
    issuerInstance.post.mockResolvedValueOnce({ status: 500, data: {} });

    const rt = buildRuntime();
    await expect(rt.initialize()).rejects.toMatchObject({ statusCode: 500 });
  });

  it('throws CapabilityError (internal) on network error to issuer', async () => {
    issuerInstance.post.mockRejectedValueOnce(new Error('ECONNREFUSED'));

    const rt = buildRuntime();
    await expect(rt.initialize()).rejects.toMatchObject({ statusCode: 500 });
  });
});

// ── tool invocation ───────────────────────────────────────────────────────────

describe('AgentRuntime – tool invocation', () => {
  async function initializedRuntime(): Promise<AgentRuntime> {
    issuerInstance.post.mockResolvedValueOnce({
      status: 200,
      data: { token: 'cap-token-123' },
    });
    const rt = buildRuntime();
    await rt.initialize();
    return rt;
  }

  it('routes tool calls through the gateway URL', async () => {
    const rt = await initializedRuntime();

    gatewayInstance.post.mockResolvedValueOnce({ status: 200, data: { success: true } });

    await rt.invokeTool({ tool: 'read_file', args: { path: '/data/f.txt' } });

    expect(gatewayInstance.post).toHaveBeenCalledWith(
      '/api/v1/tools/invoke',
      expect.objectContaining({ tool: 'read_file', args: { path: '/data/f.txt' } }),
      expect.any(Object)
    );
  });

  it('attaches capability token in Authorization header', async () => {
    const rt = await initializedRuntime();

    gatewayInstance.post.mockResolvedValueOnce({ status: 200, data: {} });

    await rt.invokeTool({ tool: 'read_file', args: {} });

    const callArgs = gatewayInstance.post.mock.calls[0];
    expect(callArgs[2]).toMatchObject({
      headers: expect.objectContaining({ Authorization: 'Bearer cap-token-123' }),
    });
  });

  it('attaches X-Agent-ID header', async () => {
    const rt = await initializedRuntime();

    gatewayInstance.post.mockResolvedValueOnce({ status: 200, data: {} });

    await rt.invokeTool({ tool: 'read_file', args: {} });

    const callArgs = gatewayInstance.post.mock.calls[0];
    expect(callArgs[2]).toMatchObject({
      headers: expect.objectContaining({ 'X-Agent-ID': 'test-agent' }),
    });
  });

  it('retries with refreshed token on 401', async () => {
    const rt = await initializedRuntime();

    // First call → 401; issuer gives new token; second call → 200
    gatewayInstance.post.mockResolvedValueOnce({ status: 401, data: {} });
    issuerInstance.post.mockResolvedValueOnce({
      status: 200,
      data: { token: 'cap-token-refreshed' },
    });
    gatewayInstance.post.mockResolvedValueOnce({ status: 200, data: { ok: true } });

    const result = await rt.invokeTool({ tool: 'read_file', args: {} });

    expect(result.success).toBe(true);
    expect(rt.getCapabilityToken()).toBe('cap-token-refreshed');
    expect(gatewayInstance.post).toHaveBeenCalledTimes(2);
  });

  it('returns success=false for 403 responses', async () => {
    const rt = await initializedRuntime();

    gatewayInstance.post.mockResolvedValueOnce({ status: 403, data: { error: 'Forbidden' } });

    const result = await rt.invokeTool({ tool: 'delete_file', args: {} });

    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(403);
  });
});

// ── makeRequest ───────────────────────────────────────────────────────────────

describe('AgentRuntime – makeRequest', () => {
  async function initializedRuntime(): Promise<AgentRuntime> {
    issuerInstance.post.mockResolvedValueOnce({
      status: 200,
      data: { token: 'cap-token-req' },
    });
    const rt = buildRuntime();
    await rt.initialize();
    return rt;
  }

  it('routes absolute URLs through /proxy/<host><path> and forwards X-Target-Host', async () => {
    const rt = await initializedRuntime();

    gatewayInstance.request.mockResolvedValueOnce({ status: 200, data: {} });

    await rt.makeRequest('GET', 'http://api.example.com/data/items');

    expect(gatewayInstance.request).toHaveBeenCalledWith(
      expect.objectContaining({
        url: '/proxy/api.example.com/data/items',
        headers: expect.objectContaining({
          'X-Target-Host': 'api.example.com',
          'X-Target-Scheme': 'http',
        }),
      })
    );
  });

  it('routes relative paths through /proxy/<path>', async () => {
    const rt = await initializedRuntime();

    gatewayInstance.request.mockResolvedValueOnce({ status: 200, data: {} });

    await rt.makeRequest('POST', '/internal/resource', { key: 'val' });

    expect(gatewayInstance.request).toHaveBeenCalledWith(
      expect.objectContaining({ url: '/proxy/internal/resource' })
    );
  });

  it('attaches capability token to proxy requests', async () => {
    const rt = await initializedRuntime();

    gatewayInstance.request.mockResolvedValueOnce({ status: 200, data: {} });

    await rt.makeRequest('GET', '/some/path');

    const callArgs = gatewayInstance.request.mock.calls[0][0];
    expect(callArgs.headers).toMatchObject({
      Authorization: 'Bearer cap-token-req',
    });
  });
});

// ── cleanup ───────────────────────────────────────────────────────────────────

describe('AgentRuntime – cleanup', () => {
  it('cleans up refresh timer on shutdown', async () => {
    issuerInstance.post.mockResolvedValueOnce({
      status: 200,
      data: { token: 'cap-token-cleanup' },
    });

    const rt = buildRuntime();
    await rt.initialize();
    await rt.shutdown();

    // After shutdown the token is still accessible (not cleared), but the timer is gone
    expect(rt).toBeDefined();
  });

  it('aborts an in-flight token acquisition triggered by shutdown', async () => {
    // Initial acquisition succeeds so initialize() returns.
    issuerInstance.post.mockResolvedValueOnce({
      status: 200,
      data: { token: 'cap-token-initial' },
    });

    const rt = buildRuntime({ tokenRefreshInterval: 1 });
    await rt.initialize();

    // Now arrange a refresh that hangs forever — but rejects when the
    // AbortController fires. AxiosRequestConfig with signal will be passed
    // through; we simulate by inspecting the call args.
    let abortListener: (() => void) | undefined;
    const hangingPromise = new Promise<never>((_resolve, reject) => {
      abortListener = () => reject(new Error('aborted'));
    });
    issuerInstance.post.mockImplementationOnce(((_url: string, _body: unknown, cfg: { signal?: AbortSignal }) => {
      cfg?.signal?.addEventListener('abort', () => abortListener?.());
      return hangingPromise;
    }) as never);

    // Trigger a refresh by advancing fake timers past the refresh interval.
    jest.advanceTimersByTime(1500);

    // Give the refresh callback and its awaited auth/hint resolution steps a
    // chance to reach the issuer call and register the abort listener.
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
    expect(issuerInstance.post).toHaveBeenCalledTimes(2);

    // Shutdown — this should abort the hanging refresh and resolve.
    await rt.shutdown();

    // The acquisition should not have replaced the token.
    expect(rt.getCapabilityToken()).toBe('cap-token-initial');
  });
});

// ── auth-token provider (OBO / federated short-lived tokens) ──────────────────

describe('AgentRuntime – authTokenProvider', () => {
  it('requires either authToken or authTokenProvider', () => {
    expect(() => new AgentRuntime({
      agentId: 'a',
      gatewayUrl: 'http://gw',
      issuerUrl: 'http://iss',
    } as any)).toThrow();
  });

  it('calls the provider on every issuance and forwards its token', async () => {
    const provider = jest.fn()
      .mockResolvedValueOnce('obo-token-1')
      .mockResolvedValueOnce('obo-token-2');

    issuerInstance.post.mockResolvedValueOnce({
      status: 200,
      data: { token: 'cap-1' },
    });

    const rt = new AgentRuntime({
      agentId: 'test-agent',
      gatewayUrl: 'http://gateway:3002',
      issuerUrl: 'http://issuer:3001',
      authTokenProvider: provider,
    });
    await rt.initialize();

    expect(provider).toHaveBeenCalledTimes(1);
    expect(issuerInstance.post.mock.calls[0][2]).toMatchObject({
      headers: { Authorization: 'Bearer obo-token-1' },
    });

    // A 401 with EXPIRED_TOKEN triggers a fresh provider call for the refresh.
    gatewayInstance.post.mockResolvedValueOnce({
      status: 401,
      data: { error: { code: 'EXPIRED_TOKEN', message: 'expired' } },
    });
    issuerInstance.post.mockResolvedValueOnce({ status: 200, data: { token: 'cap-2' } });
    gatewayInstance.post.mockResolvedValueOnce({ status: 200, data: { ok: true } });

    await rt.invokeTool({ tool: 'read_file', args: {} });

    expect(provider).toHaveBeenCalledTimes(2);
    expect(issuerInstance.post.mock.calls[1][2]).toMatchObject({
      headers: { Authorization: 'Bearer obo-token-2' },
    });
  });

  it('provider takes precedence over a static authToken', async () => {
    const provider = jest.fn().mockResolvedValue('from-provider');
    issuerInstance.post.mockResolvedValueOnce({ status: 200, data: { token: 'cap' } });

    const rt = new AgentRuntime({
      agentId: 'test-agent',
      gatewayUrl: 'http://gateway:3002',
      issuerUrl: 'http://issuer:3001',
      authToken: 'static-should-be-ignored',
      authTokenProvider: provider,
    });
    await rt.initialize();

    expect(issuerInstance.post.mock.calls[0][2]).toMatchObject({
      headers: { Authorization: 'Bearer from-provider' },
    });
  });

  it('rejects an empty token returned by the provider', async () => {
    const provider = jest.fn().mockResolvedValue('');
    const rt = new AgentRuntime({
      agentId: 'test-agent',
      gatewayUrl: 'http://gateway:3002',
      issuerUrl: 'http://issuer:3001',
      authTokenProvider: provider,
    });
    await expect(rt.initialize()).rejects.toMatchObject({ statusCode: 401 });
  });
});

// ── issuance hints (manifest / consent forwarding) ───────────────────────────

describe('AgentRuntime – issuanceHints / issuanceHintsProvider', () => {
  it('forwards static requestedCapabilities, manifest and consent on every issuance', async () => {
    issuerInstance.post.mockResolvedValueOnce({
      status: 200,
      data: { token: 'cap-with-hints' },
    });

    const manifest = {
      agentId: 'test-agent',
      name: 'Test',
      version: '1.0.0',
      requiredCapabilities: [{ resource: 'api://crm/**', actions: ['read'] as const }],
    };
    const consent = {
      userId: 'u1',
      agentId: 'test-agent',
      grantedCapabilities: [{ resource: 'api://crm/**', actions: ['read'] as const }],
      grantedAt: 1700000000,
    };
    const requestedCapabilities = [{ resource: 'api://crm/customers', actions: ['read'] as const }];

    const rt = buildRuntime({
      issuanceHints: { requestedCapabilities, manifest, consent } as any,
    });
    await rt.initialize();

    expect(issuerInstance.post).toHaveBeenCalledWith(
      '/api/v1/issue',
      {
        agentId: 'test-agent',
        requestedCapabilities,
        manifest,
        consent,
      },
      expect.any(Object),
    );
  });

  it('omits unspecified hint fields rather than sending undefined', async () => {
    issuerInstance.post.mockResolvedValueOnce({ status: 200, data: { token: 'cap' } });

    const rt = buildRuntime();
    await rt.initialize();

    // Only `agentId` should be in the body — no `requestedCapabilities`, no
    // `manifest`, no `consent` keys at all.
    expect(issuerInstance.post.mock.calls[0][1]).toEqual({ agentId: 'test-agent' });
  });

  it('issuanceHintsProvider takes precedence over static issuanceHints and is called per refresh', async () => {
    const consentA = {
      userId: 'u1', agentId: 'test-agent',
      grantedCapabilities: [{ resource: 'api://crm/**', actions: ['read'] as const }],
      grantedAt: 1700000000, consentId: 'A',
    };
    const consentB = {
      userId: 'u1', agentId: 'test-agent',
      grantedCapabilities: [{ resource: 'api://crm/**', actions: ['read'] as const }],
      grantedAt: 1700000001, consentId: 'B',
    };
    const provider = jest.fn()
      .mockResolvedValueOnce({ consent: consentA })
      .mockResolvedValueOnce({ consent: consentB });

    issuerInstance.post.mockResolvedValueOnce({ status: 200, data: { token: 'cap-1' } });

    const rt = buildRuntime({
      issuanceHints: { consent: { ...consentA, consentId: 'static-should-be-ignored' } } as any,
      issuanceHintsProvider: provider as any,
    });
    await rt.initialize();

    expect(provider).toHaveBeenCalledTimes(1);
    expect(issuerInstance.post.mock.calls[0][1]).toMatchObject({ consent: consentA });

    // Trigger a refresh via 401 EXPIRED_TOKEN — provider must be invoked again.
    gatewayInstance.post.mockResolvedValueOnce({
      status: 401,
      data: { error: { code: 'EXPIRED_TOKEN', message: 'expired' } },
    });
    issuerInstance.post.mockResolvedValueOnce({ status: 200, data: { token: 'cap-2' } });
    gatewayInstance.post.mockResolvedValueOnce({ status: 200, data: { ok: true } });

    await rt.invokeTool({ tool: 'read_file', args: {} });

    expect(provider).toHaveBeenCalledTimes(2);
    expect(issuerInstance.post.mock.calls[1][1]).toMatchObject({ consent: consentB });
  });
});

// ── failure-mode discrimination on 401 / 403 ──────────────────────────────────

describe('AgentRuntime – distinguishes expired / revoked / kill-switched', () => {
  async function initializedRuntime(): Promise<AgentRuntime> {
    issuerInstance.post.mockResolvedValueOnce({
      status: 200,
      data: { token: 'cap-token-init' },
    });
    const rt = buildRuntime();
    await rt.initialize();
    return rt;
  }

  it('refreshes and retries on 401 EXPIRED_TOKEN', async () => {
    const rt = await initializedRuntime();

    gatewayInstance.post.mockResolvedValueOnce({
      status: 401,
      data: { error: { code: 'EXPIRED_TOKEN', message: 'Token has expired' } },
    });
    issuerInstance.post.mockResolvedValueOnce({
      status: 200,
      data: { token: 'cap-token-refreshed' },
    });
    gatewayInstance.post.mockResolvedValueOnce({ status: 200, data: { ok: true } });

    const result = await rt.invokeTool({ tool: 'read_file', args: {} });

    expect(result.success).toBe(true);
    expect(rt.getCapabilityToken()).toBe('cap-token-refreshed');
    expect(gatewayInstance.post).toHaveBeenCalledTimes(2);
  });

  it('does NOT refresh on 401 TOKEN_REVOKED — surfaces the failure instead', async () => {
    const rt = await initializedRuntime();

    gatewayInstance.post.mockResolvedValueOnce({
      status: 401,
      data: { error: { code: 'TOKEN_REVOKED', message: 'Token has been revoked' } },
    });

    const result = await rt.invokeTool({ tool: 'read_file', args: {} });

    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(401);
    expect(result.errorCode).toBe('TOKEN_REVOKED');
    // Crucially, no refresh round-trip to the issuer beyond the initial one.
    expect(issuerInstance.post).toHaveBeenCalledTimes(1);
    expect(gatewayInstance.post).toHaveBeenCalledTimes(1);
    expect(rt.getCapabilityToken()).toBe('cap-token-init');
  });

  it('marks runtime terminated and stops refresh loop on 403 AGENT_TERMINATED', async () => {
    const rt = await initializedRuntime();

    gatewayInstance.post.mockResolvedValueOnce({
      status: 403,
      data: {
        error: { code: 'AGENT_TERMINATED', message: 'Agent or session has been terminated' },
      },
    });

    const result = await rt.invokeTool({ tool: 'read_file', args: {} });

    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(403);
    expect(result.errorCode).toBe('AGENT_TERMINATED');
    expect(rt.isTerminated()).toBe(true);

    // A subsequent call must short-circuit without contacting the issuer or gateway.
    issuerInstance.post.mockClear();
    gatewayInstance.post.mockClear();

    const second = await rt.invokeTool({ tool: 'read_file', args: {} });
    expect(second.success).toBe(false);
    expect(second.errorCode).toBe('AGENT_TERMINATED');
    expect(issuerInstance.post).not.toHaveBeenCalled();
    expect(gatewayInstance.post).not.toHaveBeenCalled();
  });

  it('does not refresh on 401 with an unrelated error code (e.g. INVALID_TOKEN)', async () => {
    const rt = await initializedRuntime();

    gatewayInstance.post.mockResolvedValueOnce({
      status: 401,
      data: { error: { code: 'INVALID_TOKEN', message: 'Token verification failed' } },
    });

    const result = await rt.invokeTool({ tool: 'read_file', args: {} });

    expect(result.success).toBe(false);
    expect(result.errorCode).toBe('INVALID_TOKEN');
    // Initial issuance only — no refresh was attempted.
    expect(issuerInstance.post).toHaveBeenCalledTimes(1);
    expect(gatewayInstance.post).toHaveBeenCalledTimes(1);
  });

  it('still refreshes on a 401 without a structured error code (back-compat)', async () => {
    const rt = await initializedRuntime();

    gatewayInstance.post.mockResolvedValueOnce({ status: 401, data: {} });
    issuerInstance.post.mockResolvedValueOnce({
      status: 200,
      data: { token: 'cap-back-compat' },
    });
    gatewayInstance.post.mockResolvedValueOnce({ status: 200, data: { ok: true } });

    const result = await rt.invokeTool({ tool: 'read_file', args: {} });

    expect(result.success).toBe(true);
    expect(gatewayInstance.post).toHaveBeenCalledTimes(2);
  });

  it('makeRequest also short-circuits when terminated', async () => {
    const rt = await initializedRuntime();

    gatewayInstance.request.mockResolvedValueOnce({
      status: 403,
      data: { error: { code: 'AGENT_TERMINATED', message: 'killed' } },
    });

    const r1 = await rt.makeRequest('GET', '/some/path');
    expect(r1.errorCode).toBe('AGENT_TERMINATED');
    expect(rt.isTerminated()).toBe(true);

    gatewayInstance.request.mockClear();
    const r2 = await rt.makeRequest('GET', '/another');
    expect(r2.errorCode).toBe('AGENT_TERMINATED');
    expect(gatewayInstance.request).not.toHaveBeenCalled();
  });
});

// ── DPoP / sender-constrained tokens (F-2) ──────────────────────────────────

describe('AgentRuntime – DPoP (F-2)', () => {
  // jose.SignJWT relies on a real clock for `iat`; the global
  // `useFakeTimers` in this file's beforeEach would freeze it at
  // epoch 0, which the gateway-side verifier rejects as too-old.
  let dpopFixture: { privateKey: any; publicJwk: any };
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const jose = require('jose') as typeof import('jose');

  beforeAll(async () => {
    const { privateKey, publicKey } = await jose.generateKeyPair('ES256', { extractable: true });
    const publicJwk = await jose.exportJWK(publicKey);
    dpopFixture = { privateKey, publicJwk };
  });

  // Track runtimes so we can shut them down after each test — without
  // this the token-refresh setTimeout keeps the Node event loop alive
  // and Jest hangs on exit (the file-wide fake-timer afterEach
  // doesn't help here because we deliberately use real timers in this
  // describe block).
  const runtimes: AgentRuntime[] = [];
  beforeEach(() => {
    jest.useRealTimers();
    runtimes.length = 0;
  });
  afterEach(async () => {
    for (const rt of runtimes) {
      await rt.shutdown().catch(() => undefined);
    }
    runtimes.length = 0;
    // Restore fake timers so the file-wide `afterEach` (`useRealTimers`)
    // and the next `beforeEach` (`useFakeTimers`) do not see any
    // residual real-timer handles that would keep the Jest worker
    // alive after the suite finishes.
    jest.useFakeTimers();
    jest.clearAllTimers();
  });

  function dpopRuntime(): AgentRuntime {
    const rt = buildRuntime({
      dpop: {
        privateKey: dpopFixture.privateKey,
        publicJwk: dpopFixture.publicJwk,
        algorithm: 'ES256',
      },
    });
    runtimes.push(rt);
    return rt;
  }

  it('sends dpopJkt on issuance so the issuer can stamp cnf.jkt', async () => {
    issuerInstance.post.mockResolvedValueOnce({
      status: 200,
      data: { token: 'cap-token-dpop' },
    });

    const rt = dpopRuntime();
    await rt.initialize();

    const issueBody = issuerInstance.post.mock.calls[0]![1] as Record<string, unknown>;
    expect(issueBody['dpopJkt']).toEqual(expect.any(String));
    // RFC 7638 SHA-256 thumbprints are 43 base64url chars.
    expect(issueBody['dpopJkt'] as string).toMatch(/^[A-Za-z0-9_-]{43}$/);
    // The thumbprint sent must equal the one derived locally from the public JWK.
    expect(issueBody['dpopJkt']).toBe(
      await jose.calculateJwkThumbprint(dpopFixture.publicJwk, 'sha256'),
    );
  });

  it('attaches a DPoP proof header on every tool invocation', async () => {
    issuerInstance.post.mockResolvedValueOnce({ status: 200, data: { token: 'cap-token-dpop' } });
    const rt = dpopRuntime();
    await rt.initialize();
    gatewayInstance.post.mockResolvedValueOnce({ status: 200, data: { ok: true } });

    await rt.invokeTool({ tool: 'read_file', args: {} });

    const headers = gatewayInstance.post.mock.calls[0]![2].headers as Record<string, string>;
    expect(headers).toHaveProperty('DPoP');
    expect(typeof headers['DPoP']).toBe('string');
    // DPoP proofs are JWS Compact: three base64url segments.
    expect(headers['DPoP']!.split('.')).toHaveLength(3);

    // The proof binds to method + URL; decode the payload and check.
    const decoded = jose.decodeJwt(headers['DPoP']!);
    expect(decoded['htm']).toBe('POST');
    expect(decoded['htu']).toBe('http://gateway:3002/api/v1/tools/invoke');
    // Header carries the public JWK so the verifier can match cnf.jkt.
    const protectedHeader = jose.decodeProtectedHeader(headers['DPoP']!);
    expect(protectedHeader.typ).toBe('dpop+jwt');
    expect(protectedHeader.jwk).toBeDefined();
  });

  it('issues a FRESH DPoP proof on the 401 retry (no replay) — PR review #10', async () => {
    // First call 401 → token refresh → second call. The retry MUST
    // sign a new proof with a new `jti`, otherwise the gateway's
    // replay store would refuse it as a duplicate of the original.
    issuerInstance.post.mockResolvedValueOnce({ status: 200, data: { token: 'cap-1' } });
    const rt = dpopRuntime();
    await rt.initialize();

    gatewayInstance.post.mockResolvedValueOnce({ status: 401, data: {} });
    issuerInstance.post.mockResolvedValueOnce({ status: 200, data: { token: 'cap-2' } });
    gatewayInstance.post.mockResolvedValueOnce({ status: 200, data: { ok: true } });

    const result = await rt.invokeTool({ tool: 'read_file', args: {} });
    expect(result.success).toBe(true);
    expect(gatewayInstance.post).toHaveBeenCalledTimes(2);

    const proof1 = (gatewayInstance.post.mock.calls[0]![2].headers as Record<string, string>)['DPoP'];
    const proof2 = (gatewayInstance.post.mock.calls[1]![2].headers as Record<string, string>)['DPoP'];
    expect(proof1).toBeDefined();
    expect(proof2).toBeDefined();
    expect(proof1).not.toBe(proof2);
    const jti1 = jose.decodeJwt(proof1!)['jti'];
    const jti2 = jose.decodeJwt(proof2!)['jti'];
    expect(jti1).toBeDefined();
    expect(jti2).toBeDefined();
    expect(jti1).not.toBe(jti2);
  });

  it('attaches a DPoP proof on /proxy requests too', async () => {
    issuerInstance.post.mockResolvedValueOnce({ status: 200, data: { token: 'cap-token-dpop' } });
    const rt = dpopRuntime();
    await rt.initialize();
    gatewayInstance.request.mockResolvedValueOnce({ status: 200, data: { ok: true } });

    await rt.makeRequest('GET', 'https://api.example.com/data');

    const opts = gatewayInstance.request.mock.calls[0]![0];
    const headers = opts.headers as Record<string, string>;
    expect(headers).toHaveProperty('DPoP');
    const decoded = jose.decodeJwt(headers['DPoP']!);
    expect(decoded['htm']).toBe('GET');
    // Proof URL points at the gateway path the runtime actually dialled.
    expect(typeof decoded['htu']).toBe('string');
    expect(decoded['htu']).toContain('http://gateway:3002');
  });

  it('omits DPoP headers when no dpop config is supplied (back-compat)', async () => {
    issuerInstance.post.mockResolvedValueOnce({ status: 200, data: { token: 'cap-token-plain' } });
    const rt = buildRuntime(); // no dpop
    runtimes.push(rt);
    await rt.initialize();
    gatewayInstance.post.mockResolvedValueOnce({ status: 200, data: { ok: true } });
    await rt.invokeTool({ tool: 'read_file', args: {} });
    const headers = gatewayInstance.post.mock.calls[0]![2].headers as Record<string, string>;
    expect(headers).not.toHaveProperty('DPoP');
    // Issuance body must not include dpopJkt either.
    const body = issuerInstance.post.mock.calls[0]![1] as Record<string, unknown>;
    expect(body['dpopJkt']).toBeUndefined();
  });
});
