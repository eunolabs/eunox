/**
 * Agent Runtime Tests
 *
 * Gateway calls (tool invocations and proxy requests) are intercepted via an
 * InProcessToolTransport injected into the runtime config.  Issuer calls still
 * go through an axios mock (the runtime uses axios exclusively for the issuer
 * token-acquisition path and does not use the transport for those).
 */

import axios from 'axios';
import {
  AgentRuntime,
  InProcessToolTransport,
} from '../src/runtime';
import type {
  ToolTransportInvokeRequest,
  ToolTransportProxyRequest,
  TransportCredentials,
  ToolTransportResponse,
} from '../src/runtime';

// ── axios mock setup (issuer calls only) ──────────────────────────────────────

jest.mock('axios');

const mockedAxios = axios as jest.Mocked<typeof axios>;

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

// Transport mock state — recreated by buildRuntime() on every call.
let toolHandler: jest.Mock<
  Promise<ToolTransportResponse>,
  [ToolTransportInvokeRequest, TransportCredentials]
>;
let proxyHandler: jest.Mock<
  Promise<ToolTransportResponse>,
  [ToolTransportProxyRequest, TransportCredentials]
>;

beforeEach(() => {
  jest.clearAllMocks();
  jest.useFakeTimers();

  issuerInstance = makeInstance();
  mockedAxios.create = jest.fn().mockImplementation(() => issuerInstance) as any;
});

afterEach(() => {
  jest.useRealTimers();
});

// Helper to build a runtime with a fresh InProcessToolTransport and optional
// overrides.  Sets the module-level toolHandler/proxyHandler so individual
// tests can configure responses via mockResolvedValueOnce.
function buildRuntime(overrides?: Partial<ConstructorParameters<typeof AgentRuntime>[0]>) {
  toolHandler = jest.fn<
    Promise<ToolTransportResponse>,
    [ToolTransportInvokeRequest, TransportCredentials]
  >();
  proxyHandler = jest.fn<
    Promise<ToolTransportResponse>,
    [ToolTransportProxyRequest, TransportCredentials]
  >();
  const transport = new InProcessToolTransport(toolHandler, proxyHandler);
  return new AgentRuntime({
    agentId: 'test-agent',
    gatewayUrl: 'http://gateway:3002',
    issuerUrl: 'http://issuer:3001',
    authToken: 'bearer-test-token',
    transport,
    ...(overrides as any),
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

  it('dispatches tool calls through the transport', async () => {
    const rt = await initializedRuntime();

    toolHandler.mockResolvedValueOnce({ success: true, data: { result: 'ok' }, statusCode: 200 });

    await rt.invokeTool({ tool: 'read_file', args: { path: '/data/f.txt' } });

    expect(toolHandler).toHaveBeenCalledWith(
      expect.objectContaining({ tool: 'read_file', args: { path: '/data/f.txt' } }),
      expect.any(Object)
    );
  });

  it('passes capability token in credentials', async () => {
    const rt = await initializedRuntime();

    toolHandler.mockResolvedValueOnce({ success: true, data: {}, statusCode: 200 });

    await rt.invokeTool({ tool: 'read_file', args: {} });

    const creds = toolHandler.mock.calls[0]![1] as TransportCredentials;
    expect(creds.capabilityToken).toBe('cap-token-123');
  });

  it('passes agentId in credentials', async () => {
    const rt = await initializedRuntime();

    toolHandler.mockResolvedValueOnce({ success: true, data: {}, statusCode: 200 });

    await rt.invokeTool({ tool: 'read_file', args: {} });

    const creds = toolHandler.mock.calls[0]![1] as TransportCredentials;
    expect(creds.agentId).toBe('test-agent');
  });

  it('retries with refreshed token on 401', async () => {
    const rt = await initializedRuntime();

    // First call → 401; issuer gives new token; second call → 200
    toolHandler.mockResolvedValueOnce({ success: false, statusCode: 401, errorCode: undefined });
    issuerInstance.post.mockResolvedValueOnce({
      status: 200,
      data: { token: 'cap-token-refreshed' },
    });
    toolHandler.mockResolvedValueOnce({ success: true, data: { ok: true }, statusCode: 200 });

    const result = await rt.invokeTool({ tool: 'read_file', args: {} });

    expect(result.success).toBe(true);
    expect(rt.getCapabilityToken()).toBe('cap-token-refreshed');
    expect(toolHandler).toHaveBeenCalledTimes(2);
  });

  it('returns success=false for 403 responses', async () => {
    const rt = await initializedRuntime();

    toolHandler.mockResolvedValueOnce({ success: false, statusCode: 403, error: 'Forbidden' });

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

  it('passes the URL unchanged to the transport proxyRequest', async () => {
    const rt = await initializedRuntime();

    proxyHandler.mockResolvedValueOnce({ success: true, data: {}, statusCode: 200 });

    await rt.makeRequest('GET', 'http://api.example.com/data/items');

    expect(proxyHandler).toHaveBeenCalledWith(
      expect.objectContaining({
        method: 'GET',
        url: 'http://api.example.com/data/items',
      }),
      expect.any(Object)
    );
  });

  it('passes relative paths to the transport proxyRequest', async () => {
    const rt = await initializedRuntime();

    proxyHandler.mockResolvedValueOnce({ success: true, data: {}, statusCode: 200 });

    await rt.makeRequest('POST', '/internal/resource', { key: 'val' });

    expect(proxyHandler).toHaveBeenCalledWith(
      expect.objectContaining({ method: 'POST', url: '/internal/resource', data: { key: 'val' } }),
      expect.any(Object)
    );
  });

  it('passes capability token to proxy requests', async () => {
    const rt = await initializedRuntime();

    proxyHandler.mockResolvedValueOnce({ success: true, data: {}, statusCode: 200 });

    await rt.makeRequest('GET', '/some/path');

    const creds = proxyHandler.mock.calls[0]![1] as TransportCredentials;
    expect(creds.capabilityToken).toBe('cap-token-req');
  });
});

// ── cleanup ───────────────────────────────────────────────────────────────────

describe('AgentRuntime – cleanup', () => {
  it('cleans up refresh timer on shutdown and zeroes the capability token', async () => {
    issuerInstance.post.mockResolvedValueOnce({
      status: 200,
      data: { token: 'cap-token-cleanup' },
    });

    const rt = buildRuntime();
    await rt.initialize();
    expect(rt.getCapabilityToken()).toBe('cap-token-cleanup');

    await rt.shutdown();

    // After shutdown the token MUST be cleared to prevent it from
    // appearing in post-shutdown heap dumps or crash dumps.
    expect(rt.getCapabilityToken()).toBeUndefined();
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

    // After shutdown the token must be cleared to prevent it from
    // appearing in post-shutdown heap dumps (even if it held a prior value).
    expect(rt.getCapabilityToken()).toBeUndefined();
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
      transport: new InProcessToolTransport(
        jest.fn().mockResolvedValueOnce({
          success: false,
          statusCode: 401,
          errorCode: 'EXPIRED_TOKEN',
        }).mockResolvedValueOnce({
          success: true,
          data: { ok: true },
          statusCode: 200,
        }),
      ),
    });
    await rt.initialize();

    expect(provider).toHaveBeenCalledTimes(1);
    expect(issuerInstance.post.mock.calls[0]![2]).toMatchObject({
      headers: { Authorization: 'Bearer obo-token-1' },
    });

    // A 401 with EXPIRED_TOKEN triggers a fresh provider call for the refresh.
    issuerInstance.post.mockResolvedValueOnce({ status: 200, data: { token: 'cap-2' } });

    await rt.invokeTool({ tool: 'read_file', args: {} });

    expect(provider).toHaveBeenCalledTimes(2);
    expect(issuerInstance.post.mock.calls[1]![2]).toMatchObject({
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
      transport: new InProcessToolTransport(jest.fn()),
    });
    await rt.initialize();

    expect(issuerInstance.post.mock.calls[0]![2]).toMatchObject({
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
      transport: new InProcessToolTransport(jest.fn()),
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
      version: '0.1.0',
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
    expect(issuerInstance.post.mock.calls[0]![1]).toEqual({ agentId: 'test-agent' });
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
    expect(issuerInstance.post.mock.calls[0]![1]).toMatchObject({ consent: consentA });

    // Trigger a refresh via 401 EXPIRED_TOKEN — provider must be invoked again.
    toolHandler.mockResolvedValueOnce({
      success: false,
      statusCode: 401,
      errorCode: 'EXPIRED_TOKEN',
    });
    issuerInstance.post.mockResolvedValueOnce({ status: 200, data: { token: 'cap-2' } });
    toolHandler.mockResolvedValueOnce({ success: true, data: { ok: true }, statusCode: 200 });

    await rt.invokeTool({ tool: 'read_file', args: {} });

    expect(provider).toHaveBeenCalledTimes(2);
    expect(issuerInstance.post.mock.calls[1]![1]).toMatchObject({ consent: consentB });
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

    toolHandler.mockResolvedValueOnce({
      success: false,
      statusCode: 401,
      errorCode: 'EXPIRED_TOKEN',
    });
    issuerInstance.post.mockResolvedValueOnce({
      status: 200,
      data: { token: 'cap-token-refreshed' },
    });
    toolHandler.mockResolvedValueOnce({ success: true, data: { ok: true }, statusCode: 200 });

    const result = await rt.invokeTool({ tool: 'read_file', args: {} });

    expect(result.success).toBe(true);
    expect(rt.getCapabilityToken()).toBe('cap-token-refreshed');
    expect(toolHandler).toHaveBeenCalledTimes(2);
  });

  it('does NOT refresh on 401 TOKEN_REVOKED — surfaces the failure instead', async () => {
    const rt = await initializedRuntime();

    toolHandler.mockResolvedValueOnce({
      success: false,
      statusCode: 401,
      errorCode: 'TOKEN_REVOKED',
    });

    const result = await rt.invokeTool({ tool: 'read_file', args: {} });

    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(401);
    expect(result.errorCode).toBe('TOKEN_REVOKED');
    // Crucially, no refresh round-trip to the issuer beyond the initial one.
    expect(issuerInstance.post).toHaveBeenCalledTimes(1);
    expect(toolHandler).toHaveBeenCalledTimes(1);
    expect(rt.getCapabilityToken()).toBe('cap-token-init');
  });

  it('marks runtime terminated and stops refresh loop on 403 AGENT_TERMINATED', async () => {
    const rt = await initializedRuntime();

    toolHandler.mockResolvedValueOnce({
      success: false,
      statusCode: 403,
      errorCode: 'AGENT_TERMINATED',
    });

    const result = await rt.invokeTool({ tool: 'read_file', args: {} });

    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(403);
    expect(result.errorCode).toBe('AGENT_TERMINATED');
    expect(rt.isTerminated()).toBe(true);

    // A subsequent call must short-circuit without contacting the issuer or transport.
    issuerInstance.post.mockClear();
    toolHandler.mockClear();

    const second = await rt.invokeTool({ tool: 'read_file', args: {} });
    expect(second.success).toBe(false);
    expect(second.errorCode).toBe('AGENT_TERMINATED');
    expect(issuerInstance.post).not.toHaveBeenCalled();
    expect(toolHandler).not.toHaveBeenCalled();
  });

  it('does not refresh on 401 with an unrelated error code (e.g. INVALID_TOKEN)', async () => {
    const rt = await initializedRuntime();

    toolHandler.mockResolvedValueOnce({
      success: false,
      statusCode: 401,
      errorCode: 'INVALID_TOKEN',
    });

    const result = await rt.invokeTool({ tool: 'read_file', args: {} });

    expect(result.success).toBe(false);
    expect(result.errorCode).toBe('INVALID_TOKEN');
    // Initial issuance only — no refresh was attempted.
    expect(issuerInstance.post).toHaveBeenCalledTimes(1);
    expect(toolHandler).toHaveBeenCalledTimes(1);
  });

  it('still refreshes on a 401 without a structured error code (back-compat)', async () => {
    const rt = await initializedRuntime();

    toolHandler.mockResolvedValueOnce({ success: false, statusCode: 401 });
    issuerInstance.post.mockResolvedValueOnce({
      status: 200,
      data: { token: 'cap-back-compat' },
    });
    toolHandler.mockResolvedValueOnce({ success: true, data: { ok: true }, statusCode: 200 });

    const result = await rt.invokeTool({ tool: 'read_file', args: {} });

    expect(result.success).toBe(true);
    expect(toolHandler).toHaveBeenCalledTimes(2);
  });

  it('makeRequest also short-circuits when terminated', async () => {
    const rt = await initializedRuntime();

    proxyHandler.mockResolvedValueOnce({
      success: false,
      statusCode: 403,
      errorCode: 'AGENT_TERMINATED',
    });

    const r1 = await rt.makeRequest('GET', '/some/path');
    expect(r1.errorCode).toBe('AGENT_TERMINATED');
    expect(rt.isTerminated()).toBe(true);

    proxyHandler.mockClear();
    const r2 = await rt.makeRequest('GET', '/another');
    expect(r2.errorCode).toBe('AGENT_TERMINATED');
    expect(proxyHandler).not.toHaveBeenCalled();
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
    expect(issueBody['dpopJkt'] as string).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(issueBody['dpopJkt']).toBe(
      await jose.calculateJwkThumbprint(dpopFixture.publicJwk, 'sha256'),
    );
  });

  it('passes a dpopSigner to the transport on every tool invocation', async () => {
    issuerInstance.post.mockResolvedValueOnce({ status: 200, data: { token: 'cap-token-dpop' } });
    const rt = dpopRuntime();
    await rt.initialize();

    // Capture credentials and call the signer to verify it works.
    let capturedCreds: TransportCredentials | undefined;
    toolHandler.mockImplementationOnce(async (_req, creds) => {
      capturedCreds = creds;
      return { success: true, data: { ok: true }, statusCode: 200 };
    });

    await rt.invokeTool({ tool: 'read_file', args: {} });

    expect(capturedCreds!.dpopSigner).toBeDefined();
    const proof = await capturedCreds!.dpopSigner!('POST', 'http://gateway:3002/api/v1/tools/invoke');
    expect(typeof proof).toBe('string');
    expect(proof.split('.')).toHaveLength(3);

    const decoded = jose.decodeJwt(proof);
    expect(decoded['htm']).toBe('POST');
    expect(decoded['htu']).toBe('http://gateway:3002/api/v1/tools/invoke');
    const protectedHeader = jose.decodeProtectedHeader(proof);
    expect(protectedHeader.typ).toBe('dpop+jwt');
    expect(protectedHeader.jwk).toBeDefined();
  });

  it('provides a fresh dpopSigner on the 401 retry (proof jti must differ)', async () => {
    issuerInstance.post.mockResolvedValueOnce({ status: 200, data: { token: 'cap-1' } });
    const rt = dpopRuntime();
    await rt.initialize();

    const proofs: string[] = [];
    let callCount = 0;
    toolHandler.mockImplementation(async (_req, creds) => {
      callCount++;
      if (creds.dpopSigner) {
        const proof = await creds.dpopSigner('POST', 'http://gateway:3002/api/v1/tools/invoke');
        proofs.push(proof);
      }
      if (callCount === 1) {
        return { success: false, statusCode: 401, errorCode: undefined };
      }
      return { success: true, statusCode: 200, data: { ok: true } };
    });
    issuerInstance.post.mockResolvedValueOnce({ status: 200, data: { token: 'cap-2' } });

    const result = await rt.invokeTool({ tool: 'read_file', args: {} });
    expect(result.success).toBe(true);
    expect(toolHandler).toHaveBeenCalledTimes(2);
    expect(proofs).toHaveLength(2);

    // Each proof must have a different jti (no replay).
    const jti1 = jose.decodeJwt(proofs[0]!)['jti'];
    const jti2 = jose.decodeJwt(proofs[1]!)['jti'];
    expect(jti1).toBeDefined();
    expect(jti2).toBeDefined();
    expect(jti1).not.toBe(jti2);
  });

  it('passes a dpopSigner to the transport on proxy requests', async () => {
    issuerInstance.post.mockResolvedValueOnce({ status: 200, data: { token: 'cap-token-dpop' } });
    const rt = dpopRuntime();
    await rt.initialize();

    let capturedCreds: TransportCredentials | undefined;
    proxyHandler.mockImplementationOnce(async (_req, creds) => {
      capturedCreds = creds;
      return { success: true, data: { ok: true }, statusCode: 200 };
    });

    await rt.makeRequest('GET', 'https://api.example.com/data');

    expect(capturedCreds!.dpopSigner).toBeDefined();
  });

  it('omits dpopSigner when no dpop config is supplied (back-compat)', async () => {
    issuerInstance.post.mockResolvedValueOnce({ status: 200, data: { token: 'cap-token-plain' } });
    const rt = buildRuntime(); // no dpop
    runtimes.push(rt);
    await rt.initialize();

    let capturedCreds: TransportCredentials | undefined;
    toolHandler.mockImplementationOnce(async (_req, creds) => {
      capturedCreds = creds;
      return { success: true, data: { ok: true }, statusCode: 200 };
    });

    await rt.invokeTool({ tool: 'read_file', args: {} });

    expect(capturedCreds!.dpopSigner).toBeUndefined();

    // Issuance body must not include dpopJkt either.
    const body = issuerInstance.post.mock.calls[0]![1] as Record<string, unknown>;
    expect(body['dpopJkt']).toBeUndefined();
  });
});
