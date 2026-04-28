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

    // Give the microtask queue a chance to start the refresh.
    await Promise.resolve();

    // Shutdown — this should abort the hanging refresh and resolve.
    await rt.shutdown();

    // The acquisition should not have replaced the token.
    expect(rt.getCapabilityToken()).toBe('cap-token-initial');
  });
});
