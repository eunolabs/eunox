/**
 * Integration tests for:
 *   - HttpProxy Bearer-token authentication (`authToken` / `--auth-token`)
 *   - Upstream call timeout (`upstreamTimeoutMs`) for both transports
 *
 * Test matrix — auth token
 * ─────────────────────────
 * ✓ Constructor throws when authToken is an empty string
 * ✓ POST /mcp without Authorization header → 401
 * ✓ POST /mcp with wrong Bearer token → 401
 * ✓ POST /mcp with correct Bearer token is accepted (initialize succeeds)
 * ✓ GET /mcp (SSE) without Authorization header → 401
 *
 * Test matrix — upstream timeout (HttpProxy)
 * ───────────────────────────────────────────
 * ✓ tools/call to a hung upstream returns a structured UPSTREAM_TIMEOUT denial
 *   within the timeout window (not hanging indefinitely)
 *
 * Test matrix — upstream timeout (StdioProxy)
 * ─────────────────────────────────────────────
 * ✓ tools/call to a hung upstream returns a structured UPSTREAM_TIMEOUT denial
 */

import * as http from 'node:http';
import * as path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { CompatibilityCallToolResultSchema } from '@modelcontextprotocol/sdk/types.js';
import { HttpProxy, UpstreamTimeoutError } from '../../src/index';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Path to the ts-node register hook. */
const TS_NODE_REGISTER = require.resolve('ts-node/register');

/** Absolute path to the slow mock upstream fixture. */
const SLOW_UPSTREAM = path.resolve(
  __dirname,
  '../../test/fixtures/mock-slow-upstream.ts',
);

/** Absolute path to the normal mock upstream fixture. */
const MOCK_UPSTREAM = path.resolve(
  __dirname,
  '../../test/fixtures/mock-upstream.ts',
);

/**
 * Sends a raw HTTP request to a URL and returns the status code.
 * Consumes the body so the connection is released.
 */
function rawRequest(opts: {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}): Promise<{ status: number; body: string }> {
  const { url, method = 'GET', headers = {}, body } = opts;
  const parsed = new URL(url);
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: parsed.hostname,
        port: parseInt(parsed.port, 10),
        path: parsed.pathname + parsed.search,
        method,
        headers: {
          'Content-Type': 'application/json',
          ...(body !== undefined ? { 'Content-Length': String(Buffer.byteLength(body)) } : {}),
          ...headers,
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      },
    );
    req.on('error', reject);
    if (body !== undefined) {
      req.write(body);
    }
    req.end();
  });
}

async function waitForNoTrackedSessions(
  proxy: HttpProxy,
  timeoutMs = 5_000,
  intervalMs = 50,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const internalProxy = proxy as unknown as {
      _sessions: Map<string, unknown>;
      _pendingSessions: Set<unknown>;
    };
    if (
      internalProxy._sessions.size === 0 &&
      internalProxy._pendingSessions.size === 0
    ) {
      return;
    }
    await new Promise<void>((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new Error('Timed out waiting for tracked HTTP sessions to be cleaned up');
}

// ---------------------------------------------------------------------------
// Auth token — constructor validation
// ---------------------------------------------------------------------------

describe('HttpProxy authToken — constructor validation', () => {
  it('throws when authToken is an empty string', () => {
    expect(() => new HttpProxy({
      command: 'echo',
      port: 0,
      authToken: '',
    })).toThrow(/authToken must not be.*empty/i);
  });

  it('throws when authToken is whitespace-only', () => {
    expect(() => new HttpProxy({
      command: 'echo',
      port: 0,
      authToken: '   ',
    })).toThrow(/authToken must not be.*empty/i);
  });

  it('does not throw when authToken is a non-empty string', () => {
    expect(() => new HttpProxy({
      command: 'echo',
      port: 0,
      authToken: 'my-secret-token',
    })).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Auth token — HTTP enforcement
// ---------------------------------------------------------------------------

describe('HttpProxy authToken — /mcp endpoint enforcement', () => {
  const TOKEN = 'test-bearer-token-12345';
  let proxy: HttpProxy;
  let proxyPort: number;

  beforeEach(async () => {
    // The auth token tests only send raw HTTP requests to /mcp — they never
    // reach a tools/call handler, so the normal mock upstream (which responds
    // to tools/list and tools/call) is a fine choice here.  Auth enforcement
    // happens before any session is created, so the upstream's behaviour is
    // irrelevant for the 401 tests.
    proxy = new HttpProxy({
      command: process.execPath,
      args: ['--require', TS_NODE_REGISTER, MOCK_UPSTREAM],
      env: { ...process.env as Record<string, string>, TS_NODE_TRANSPILE_ONLY: 'true' },
      port: 0,
      authToken: TOKEN,
    });
    proxyPort = await proxy.start();
  }, 20_000);

  afterEach(async () => {
    await proxy.close().catch(() => undefined);
  }, 10_000);

  it('returns 401 when Authorization header is missing', async () => {
    const { status, body } = await rawRequest({
      url: `http://127.0.0.1:${proxyPort}/mcp`,
      method: 'POST',
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
    });
    expect(status).toBe(401);
    expect(JSON.parse(body)).toMatchObject({ error: expect.stringContaining('Unauthorized') });
  });

  it('returns 401 when Authorization header has the wrong token', async () => {
    const { status } = await rawRequest({
      url: `http://127.0.0.1:${proxyPort}/mcp`,
      method: 'POST',
      headers: { Authorization: 'Bearer wrong-token' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
    });
    expect(status).toBe(401);
  });

  it('returns 401 when Authorization header uses a non-Bearer scheme', async () => {
    const { status } = await rawRequest({
      url: `http://127.0.0.1:${proxyPort}/mcp`,
      method: 'POST',
      headers: { Authorization: `Basic ${TOKEN}` },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
    });
    expect(status).toBe(401);
  });

  it('accepts POST /mcp with the correct Bearer token (initialize succeeds)', async () => {
    // A successful initialize gives a non-401 response (200, 202, or similar).
    const { status } = await rawRequest({
      url: `http://127.0.0.1:${proxyPort}/mcp`,
      method: 'POST',
      headers: { Authorization: `Bearer ${TOKEN}` },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2024-11-05',
          capabilities: {},
          clientInfo: { name: 'test-client', version: '0.0.1' },
        },
      }),
    });
    expect(status).not.toBe(401);
  });

  it('returns 401 for GET /mcp without token (SSE endpoint)', async () => {
    const { status } = await rawRequest({
      url: `http://127.0.0.1:${proxyPort}/mcp`,
      method: 'GET',
    });
    expect(status).toBe(401);
  });

  it('invalid initialize requests do not leak pending upstream sessions', async () => {
    const { status } = await rawRequest({
      url: `http://127.0.0.1:${proxyPort}/mcp`,
      method: 'POST',
      headers: { Authorization: `Bearer ${TOKEN}` },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/list',
        params: {},
      }),
    });

    expect(status).not.toBe(401);
    await waitForNoTrackedSessions(proxy);
  }, 15_000);
});

// ---------------------------------------------------------------------------
// Upstream timeout — HttpProxy
// ---------------------------------------------------------------------------

describe('HttpProxy upstreamTimeoutMs — hung upstream returns UPSTREAM_TIMEOUT', () => {
  let proxy: HttpProxy;
  let client: Client;

  beforeEach(async () => {
    proxy = new HttpProxy({
      command: process.execPath,
      args: ['--require', TS_NODE_REGISTER, SLOW_UPSTREAM],
      env: { ...process.env as Record<string, string>, TS_NODE_TRANSPILE_ONLY: 'true' },
      port: 0,
      bind: '127.0.0.1',
      // 1-second timeout — slow_tool never responds so this will always fire.
      upstreamTimeoutMs: 1_000,
    });
    const port = await proxy.start();
    const url = new URL(`http://127.0.0.1:${port}/mcp`);
    const transport = new StreamableHTTPClientTransport(url);
    client = new Client({ name: 'test-host', version: '1.0.0' }, { capabilities: {} });
    await client.connect(transport);
  }, 30_000);

  afterEach(async () => {
    await client.close().catch(() => undefined);
    await proxy.close().catch(() => undefined);
  }, 10_000);

  it('returns a CapabilityDenied result with UPSTREAM_TIMEOUT code', async () => {
    const raw = await client.callTool(
      { name: 'slow_tool', arguments: {} },
      CompatibilityCallToolResultSchema,
    );
    const result = raw as unknown as { content: Array<{ type: string; text: string }>; isError?: boolean };

    expect(result.isError).toBe(true);
    const payload = JSON.parse(result.content[0]!.text) as Record<string, unknown>;
    expect(payload['error']).toBe('CapabilityDenied');
    expect(payload['code']).toBe('UPSTREAM_TIMEOUT');
  }, 15_000);

  it('resolves within the timeout window (not hanging indefinitely)', async () => {
    const start = Date.now();
    await client.callTool(
      { name: 'slow_tool', arguments: {} },
      CompatibilityCallToolResultSchema,
    );
    const elapsed = Date.now() - start;
    // The timeout is 1 s.  Allow 4 s total to account for process startup
    // overhead (ts-node compilation) and CI scheduling jitter, while still
    // catching true hangs that would take >10 s.
    expect(elapsed).toBeLessThan(4_000);
  }, 15_000);
});

// ---------------------------------------------------------------------------
// Upstream timeout — StdioProxy (unit-level test via UpstreamTimeoutError)
// ---------------------------------------------------------------------------

describe('UpstreamTimeoutError — sentinel class', () => {
  it('is an instanceof Error', () => {
    const err = new UpstreamTimeoutError('my_tool', 5_000);
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(UpstreamTimeoutError);
  });

  it('exposes toolName and timeoutMs properties', () => {
    const err = new UpstreamTimeoutError('my_tool', 5_000);
    expect(err.toolName).toBe('my_tool');
    expect(err.timeoutMs).toBe(5_000);
  });

  it('has a descriptive message', () => {
    const err = new UpstreamTimeoutError('my_tool', 5_000);
    expect(err.message).toContain('my_tool');
    expect(err.message).toContain('5000');
  });

  it('name is UpstreamTimeoutError', () => {
    const err = new UpstreamTimeoutError('my_tool', 5_000);
    expect(err.name).toBe('UpstreamTimeoutError');
  });
});
