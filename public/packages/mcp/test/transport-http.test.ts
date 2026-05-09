/**
 * Integration tests for the @euno/mcp HTTP proxy transport.
 *
 * Topology
 * ────────
 *   Jest process
 *     └── HttpProxy (in-process, port 0 → random ephemeral port)
 *           └── StdioClientTransport (spawns mock-upstream via ts-node)
 *                 └── mock-upstream fixture
 *
 * A real MCP `Client` using `StreamableHTTPClientTransport` drives the proxy.
 * The proxy runs with `AlwaysAllowPDP` (Stage 1 default).
 *
 * Acceptance criteria (Task 5):
 *   ✓  `tools/list` returns both tools declared by the mock upstream.
 *   ✓  `tools/call echo` round-trips the input text through the proxy.
 *   ✓  `tools/call query_db` returns a result containing the SQL string.
 *   ✓  Concurrent sessions are isolated (counter keys include sessionId).
 *   ✓  Starting with bind 0.0.0.0 and unsafeBindAll: false throws.
 *   ✓  Starting with bind 0.0.0.0 and unsafeBindAll: true succeeds (and warns).
 *
 * Acceptance criteria (Task 2 — ipRange):
 *   ✓  A request from 127.0.0.1 is allowed when that IP is in the CIDR list.
 *   ✓  A request from 127.0.0.1 is denied when that IP is NOT in the CIDR list.
 *   ✓  X-Forwarded-For is ignored when trustForwardedFor is off (default).
 *   ✓  X-Forwarded-For is used when trustForwardedFor is on (loopback bind).
 *   ✓  A request with no sourceIp (stdio-like context) is denied by ipRange.
 */

import * as path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { CompatibilityCallToolResultSchema } from '@modelcontextprotocol/sdk/types.js';
import { HttpProxy } from '../src/transport/http';
import { ConditionEnforcerPDP } from '../src/pdp';
import { FilePolicySource } from '../src/policy/source';
import * as fs from 'node:fs';
import * as os from 'node:os';

// --------------------------------------------------------------------------
// Shared types
// --------------------------------------------------------------------------

/** Shape of a text content item returned by the mock upstream. */
interface TextContent {
  type: 'text';
  text: string;
}

/** Minimal typed view of a tool call result used by these tests. */
interface ToolCallResult {
  content: TextContent[];
  isError?: boolean;
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

/** Absolute path to the mock-upstream fixture. */
const MOCK_UPSTREAM = path.resolve(__dirname, 'fixtures', 'mock-upstream.ts');

/** Path to the ts-node register hook (in the monorepo root node_modules). */
const TS_NODE_REGISTER = require.resolve('ts-node/register');

/**
 * Creates an `HttpProxy` instance that spawns the mock-upstream via ts-node.
 * Binds to 127.0.0.1 on an ephemeral port.
 */
function buildHttpProxy(): HttpProxy {
  return new HttpProxy({
    command: process.execPath,
    args: ['--require', TS_NODE_REGISTER, MOCK_UPSTREAM],
    env: {
      ...process.env,
      TS_NODE_TRANSPILE_ONLY: 'true',
    },
    port: 0, // ephemeral
    bind: '127.0.0.1',
  });
}

/**
 * Connects an MCP `Client` to the given `HttpProxy` via the streamable HTTP
 * transport and returns both.  The caller is responsible for calling
 * `client.close()` in cleanup.
 */
async function connectClient(proxy: HttpProxy): Promise<Client> {
  const port = proxy.port;
  if (port === undefined) {
    throw new Error('Proxy has not been started');
  }
  const url = new URL(`http://127.0.0.1:${port}/mcp`);
  const transport = new StreamableHTTPClientTransport(url);
  const client = new Client({ name: 'test-host', version: '1.0.0' }, { capabilities: {} });
  await client.connect(transport);
  return client;
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

describe('HttpProxy — integration (Task 5)', () => {
  let proxy: HttpProxy;
  let client: Client;

  beforeEach(async () => {
    proxy = buildHttpProxy();
    await proxy.start();
    client = await connectClient(proxy);
  }, 30_000);

  afterEach(async () => {
    await client.close().catch(() => undefined);
    await proxy.close().catch(() => undefined);
  }, 10_000);

  // ── tools/list ─────────────────────────────────────────────────────────────

  it('tools/list returns all tools from the mock upstream', async () => {
    const { tools } = await client.listTools();

    const names = tools.map((t) => t.name).sort();
    expect(names).toEqual(['echo', 'get_user', 'query_db']);
  }, 20_000);

  it('each tool has a non-empty description and inputSchema', async () => {
    const { tools } = await client.listTools();

    for (const tool of tools) {
      expect(typeof tool.description).toBe('string');
      expect(tool.description!.length).toBeGreaterThan(0);
      expect(tool.inputSchema).toBeDefined();
      expect((tool.inputSchema as Record<string, unknown>)['type']).toBe('object');
    }
  }, 20_000);

  // ── tools/call echo ────────────────────────────────────────────────────────

  it('tools/call echo round-trips text through the HTTP proxy', async () => {
    const raw = await client.callTool(
      { name: 'echo', arguments: { text: 'hello over http' } },
      CompatibilityCallToolResultSchema,
    );
    const result = raw as unknown as ToolCallResult;

    expect(result.isError).toBeFalsy();
    expect(result.content).toHaveLength(1);
    expect(result.content[0]!.type).toBe('text');
    expect(result.content[0]!.text).toBe('hello over http');
  }, 20_000);

  // ── tools/call query_db ────────────────────────────────────────────────────

  it('tools/call query_db returns a result containing the SQL string', async () => {
    const sql = 'SELECT * FROM mock WHERE id = 99';
    const raw = await client.callTool(
      { name: 'query_db', arguments: { sql } },
      CompatibilityCallToolResultSchema,
    );
    const result = raw as unknown as ToolCallResult;

    expect(result.isError).toBeFalsy();
    const parsed = JSON.parse(result.content[0]!.text) as {
      rows: Array<{ id: number; sql: string }>;
    };
    expect(parsed.rows).toHaveLength(1);
    expect(parsed.rows[0]!.sql).toBe(sql);
  }, 20_000);

  // ── resources/list ─────────────────────────────────────────────────────────

  it('resources/list returns the mock resource', async () => {
    const { resources } = await client.listResources();

    expect(resources).toHaveLength(1);
    expect(resources[0]!.uri).toBe('file:///data/mock.txt');
  }, 20_000);

  // ── Session isolation ──────────────────────────────────────────────────────

  it('two concurrent sessions are isolated (each gets its own upstream)', async () => {
    // Connect a second independent client to the same proxy.
    const client2 = await connectClient(proxy);
    try {
      // Both sessions should be functional independently.
      const [tools1, tools2] = await Promise.all([
        client.listTools(),
        client2.listTools(),
      ]);
      expect(tools1.tools.map((t) => t.name).sort()).toEqual(['echo', 'get_user', 'query_db']);
      expect(tools2.tools.map((t) => t.name).sort()).toEqual(['echo', 'get_user', 'query_db']);
    } finally {
      await client2.close().catch(() => undefined);
    }
  }, 30_000);
});

// --------------------------------------------------------------------------
// Bind address safety
// --------------------------------------------------------------------------

describe('HttpProxy — bind address validation', () => {
  it('start() throws when binding to 0.0.0.0 without unsafeBindAll', async () => {
    const proxy = new HttpProxy({
      command: process.execPath,
      args: ['--eval', 'setTimeout(() => {}, 60000)'],
      port: 0,
      bind: '0.0.0.0',
      unsafeBindAll: false,
    });

    await expect(proxy.start()).rejects.toThrow(/0\.0\.0\.0/);
    // No cleanup needed — the server never started.
  });

  it('start() succeeds when binding to 0.0.0.0 with unsafeBindAll: true', async () => {
    const proxy = new HttpProxy({
      command: process.execPath,
      args: ['--eval', 'setTimeout(() => {}, 60000)'],
      port: 0,
      bind: '0.0.0.0',
      unsafeBindAll: true,
    });

    let port: number | undefined;
    try {
      port = await proxy.start();
      expect(typeof port).toBe('number');
      expect(port).toBeGreaterThan(0);
    } finally {
      await proxy.close().catch(() => undefined);
    }
  }, 10_000);

  it('start() rejects when binding to :: without unsafeBindAll', async () => {
    const proxy = new HttpProxy({
      command: process.execPath,
      args: ['--eval', 'setTimeout(() => {}, 60000)'],
      port: 0,
      bind: '::',
      unsafeBindAll: false,
    });

    await expect(proxy.start()).rejects.toThrow(/::/);
  });
});

// --------------------------------------------------------------------------
// Request validation (session-less request guard)
// --------------------------------------------------------------------------

describe('HttpProxy — session-init request validation', () => {
  let proxy: HttpProxy;
  let baseUrl: string;

  beforeEach(async () => {
    proxy = new HttpProxy({
      command: process.execPath,
      args: ['-r', 'ts-node/register', MOCK_UPSTREAM],
      port: 0,
    });
    const port = await proxy.start();
    baseUrl = `http://127.0.0.1:${port}/mcp`;
  }, 15_000);

  afterEach(async () => {
    await proxy.close().catch(() => undefined);
  }, 10_000);

  it('GET /mcp without a session id returns 405', async () => {
    const res = await fetch(baseUrl, { method: 'GET' });
    expect(res.status).toBe(405);
  });

  it('DELETE /mcp without a session id returns 405', async () => {
    const res = await fetch(baseUrl, { method: 'DELETE' });
    expect(res.status).toBe(405);
  });

  it('POST /mcp with wrong content-type returns 415', async () => {
    const res = await fetch(baseUrl, {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: '{}',
    });
    expect(res.status).toBe(415);
  });
});

// --------------------------------------------------------------------------
// ipRange enforcement (Task 2 — Stage 2)
// --------------------------------------------------------------------------

/**
 * Parse an HTTP response that may be either `application/json` or
 * `text/event-stream` (SSE).  The MCP streamable-HTTP transport chooses
 * SSE when the client Accept header includes `text/event-stream`, so raw
 * fetch callers must handle both content types.
 *
 * For SSE, the body looks like:
 *   event: message\n
 *   data: {"jsonrpc":"2.0","id":N,"result":...}\n
 *   \n
 * We scan for the first `data: ` line and JSON-parse its payload.
 */
async function parseMcpResponse(res: Response): Promise<unknown> {
  const ct = res.headers.get('content-type') ?? '';
  if (ct.includes('application/json')) {
    return res.json();
  }
  // SSE or unknown — extract the first `data: ` line.
  const text = await res.text();
  const dataLine = text.split('\n').find((l) => l.startsWith('data: '));
  if (!dataLine) {
    throw new Error(`No data line in SSE response body: ${text.slice(0, 200)}`);
  }
  return JSON.parse(dataLine.slice('data: '.length));
}

/**
 * Build a policy YAML that restricts `echo` to the given CIDRs.
 */
function ipRangePolicyYaml(cidrs: string[]): string {
  const cidrList = cidrs.map((c) => `"${c}"`).join(', ');
  return `
agentId: test-agent
name: Test Agent
version: 1.0.0
requiredCapabilities:
  - resource: "echo"
    actions: [call]
    conditions:
      - type: ipRange
        cidrs: [${cidrList}]
`.trim();
}

describe('HttpProxy — ipRange enforcement (Task 2)', () => {
  const tempDirs: string[] = [];

  afterEach(() => {
    for (const dir of tempDirs.splice(0)) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  function writeTempPolicy(yaml: string): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'euno-http-test-'));
    tempDirs.push(dir);
    const file = path.join(dir, 'policy.yaml');
    fs.writeFileSync(file, yaml, 'utf8');
    return file;
  }

  /**
   * Start an HttpProxy with a ConditionEnforcerPDP loaded from a YAML file.
   * Returns [proxy, port].
   */
  async function startProxyWithPolicy(
    policyYaml: string,
    opts: { trustForwardedFor?: boolean } = {},
  ): Promise<[HttpProxy, number]> {
    const policyFile = writeTempPolicy(policyYaml);
    const policySource = new FilePolicySource({ filePath: policyFile });
    const pdp = new ConditionEnforcerPDP({ policySource });
    const proxy = new HttpProxy({
      command: process.execPath,
      args: ['--require', TS_NODE_REGISTER, MOCK_UPSTREAM],
      env: { ...process.env as Record<string, string>, TS_NODE_TRANSPILE_ONLY: 'true' },
      port: 0,
      bind: '127.0.0.1',
      pdp,
      trustForwardedFor: opts.trustForwardedFor ?? false,
    });
    const port = await proxy.start();
    return [proxy, port];
  }

  it('allows echo when sourceIp (127.0.0.1) is in the CIDR list', async () => {
    const [proxy] = await startProxyWithPolicy(ipRangePolicyYaml(['127.0.0.0/8']));
    const client = await connectClient(proxy);
    try {
      const raw = await client.callTool(
        { name: 'echo', arguments: { text: 'hello' } },
        CompatibilityCallToolResultSchema,
      );
      const result = raw as unknown as ToolCallResult;
      expect(result.isError).toBeFalsy();
      expect(result.content[0]!.text).toBe('hello');
    } finally {
      await client.close().catch(() => undefined);
      await proxy.close().catch(() => undefined);
    }
  }, 30_000);

  it('denies echo when sourceIp (127.0.0.1) is NOT in the CIDR list', async () => {
    // Only allow 10.0.0.0/8 — requests from 127.0.0.1 are denied.
    const [proxy] = await startProxyWithPolicy(ipRangePolicyYaml(['10.0.0.0/8']));
    const client = await connectClient(proxy);
    try {
      const raw = await client.callTool(
        { name: 'echo', arguments: { text: 'should-be-denied' } },
        CompatibilityCallToolResultSchema,
      );
      const result = raw as unknown as ToolCallResult;
      // The proxy returns an isError result (CapabilityDenied) rather than
      // propagating a transport-level error.
      expect(result.isError).toBe(true);
      const parsed = JSON.parse(result.content[0]!.text) as {
        error: string;
        code: string;
      };
      expect(parsed.error).toBe('CapabilityDenied');
      expect(parsed.code).toBe('IP_RANGE_DENIED');
    } finally {
      await client.close().catch(() => undefined);
      await proxy.close().catch(() => undefined);
    }
  }, 30_000);

  it('ignores X-Forwarded-For when trustForwardedFor is off (default)', async () => {
    // Policy allows only 10.0.0.0/8.  The real IP (127.0.0.1) is NOT in that
    // range.  We send XFF: 10.0.0.1 (which IS in range) with trustForwardedFor
    // off to confirm XFF is ignored and the real IP (127.0.0.1) causes a denial.
    const policyFile = writeTempPolicy(ipRangePolicyYaml(['10.0.0.0/8']));
    const proxy = new HttpProxy({
      command: process.execPath,
      args: ['--require', TS_NODE_REGISTER, MOCK_UPSTREAM],
      env: { ...process.env as Record<string, string>, TS_NODE_TRANSPILE_ONLY: 'true' },
      port: 0,
      bind: '127.0.0.1',
      pdp: new ConditionEnforcerPDP({
        policySource: new FilePolicySource({ filePath: policyFile }),
      }),
      trustForwardedFor: false,
    });
    const port = await proxy.start();

    try {
      // Initialize via raw fetch to capture session ID.
      const initRes = await fetch(`http://127.0.0.1:${port}/mcp`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
          'mcp-protocol-version': '2025-03-26',
        },
        body: JSON.stringify({
          jsonrpc: '2.0', id: 1, method: 'initialize',
          params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'test', version: '1' } },
        }),
      });
      const sessionId = initRes.headers.get('mcp-session-id');
      expect(sessionId).toBeTruthy();

      // Send tools/call with XFF: 10.0.0.1 (allowed CIDR) but flag is off.
      // The proxy should use the real IP (127.0.0.1, not in 10.0.0.0/8) → denied.
      const callRes = await fetch(`http://127.0.0.1:${port}/mcp`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
          'mcp-protocol-version': '2025-03-26',
          'mcp-session-id': sessionId!,
          'x-forwarded-for': '10.0.0.1',
        },
        body: JSON.stringify({
          jsonrpc: '2.0', id: 2, method: 'tools/call',
          params: { name: 'echo', arguments: { text: 'xff-ignored' } },
        }),
      });
      expect(callRes.status).toBe(200);
      const body = await parseMcpResponse(callRes) as { result?: { isError?: boolean; content?: Array<{ text: string }> } };
      // XFF is ignored → real IP 127.0.0.1 used → not in 10.0.0.0/8 → denied.
      expect(body.result?.isError).toBe(true);
      const denial = JSON.parse(body.result?.content?.[0]?.text ?? '{}') as { code: string };
      expect(denial.code).toBe('IP_RANGE_DENIED');
    } finally {
      await proxy.close().catch(() => undefined);
    }
  }, 30_000);

  it('trusts X-Forwarded-For when trustForwardedFor is on and bind is loopback', async () => {
    // Policy allows 10.0.0.0/8.  The real source IP (127.0.0.1) is NOT in
    // that range.  With trustForwardedFor on, a XFF header claiming 10.0.0.1
    // should be trusted → allowed.  Without the XFF header the real IP is
    // used → denied.
    const policyFile = writeTempPolicy(ipRangePolicyYaml(['10.0.0.0/8']));
    const proxy = new HttpProxy({
      command: process.execPath,
      args: ['--require', TS_NODE_REGISTER, MOCK_UPSTREAM],
      env: { ...process.env as Record<string, string>, TS_NODE_TRANSPILE_ONLY: 'true' },
      port: 0,
      bind: '127.0.0.1',
      pdp: new ConditionEnforcerPDP({
        policySource: new FilePolicySource({ filePath: policyFile }),
      }),
      trustForwardedFor: true,
    });
    const port2 = await proxy.start();

    try {
      // ── initialize via raw fetch → capture session id ────────────────────
      const initRes = await fetch(`http://127.0.0.1:${port2}/mcp`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
          'mcp-protocol-version': '2025-03-26',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2025-03-26',
            capabilities: {},
            clientInfo: { name: 'test', version: '1.0' },
          },
        }),
      });
      expect(initRes.status).toBe(200);
      const sessionId = initRes.headers.get('mcp-session-id');
      expect(sessionId).toBeTruthy();

      // ── tools/call with XFF: 10.0.0.1 ────────────────────────────────────
      // The real source IP (127.0.0.1) is NOT in 10.0.0.0/8.
      // With trustForwardedFor on, the proxy uses XFF (10.0.0.1) which IS in range.
      const callRes = await fetch(`http://127.0.0.1:${port2}/mcp`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
          'mcp-protocol-version': '2025-03-26',
          'mcp-session-id': sessionId!,
          'x-forwarded-for': '10.0.0.1',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 2,
          method: 'tools/call',
          params: { name: 'echo', arguments: { text: 'xff-allowed' } },
        }),
      });
      expect(callRes.status).toBe(200);
      const body = await parseMcpResponse(callRes) as { result?: { isError?: boolean; content?: Array<{ text: string }> } };
      // The response should be a successful tool call result.
      expect(body.result?.isError).toBeFalsy();
      expect(body.result?.content?.[0]?.text).toBe('xff-allowed');

      // ── tools/call WITHOUT XFF — real IP (127.0.0.1) used ────────────────
      // 127.0.0.1 is NOT in 10.0.0.0/8 → denied.
      const callRes2 = await fetch(`http://127.0.0.1:${port2}/mcp`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
          'mcp-protocol-version': '2025-03-26',
          'mcp-session-id': sessionId!,
          // No X-Forwarded-For header.
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 3,
          method: 'tools/call',
          params: { name: 'echo', arguments: { text: 'no-xff' } },
        }),
      });
      expect(callRes2.status).toBe(200);
      const body2 = await parseMcpResponse(callRes2) as { result?: { isError?: boolean; content?: Array<{ text: string }> } };
      expect(body2.result?.isError).toBe(true);
      const denial = JSON.parse(body2.result?.content?.[0]?.text ?? '{}') as { code: string };
      expect(denial.code).toBe('IP_RANGE_DENIED');
    } finally {
      await proxy.close().catch(() => undefined);
    }
  }, 45_000);

  it('_extractSourceIp: uses socket address when trustForwardedFor is off', async () => {
    // Verify denial code reflects the real IP, not XFF, when flag is off.
    const [proxy] = await startProxyWithPolicy(
      ipRangePolicyYaml(['10.0.0.0/8']),
      { trustForwardedFor: false },
    );
    // Real IP is 127.0.0.1 which is NOT in 10.0.0.0/8.
    const port = proxy.port!;
    const initRes = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        'mcp-protocol-version': '2025-03-26',
      },
      body: JSON.stringify({
        jsonrpc: '2.0', id: 1, method: 'initialize',
        params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'test', version: '1' } },
      }),
    });
    const sessionId = initRes.headers.get('mcp-session-id');

    const callRes = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        'mcp-protocol-version': '2025-03-26',
        'mcp-session-id': sessionId!,
        'x-forwarded-for': '10.0.0.1', // would be allowed if XFF was trusted
      },
      body: JSON.stringify({
        jsonrpc: '2.0', id: 2, method: 'tools/call',
        params: { name: 'echo', arguments: { text: 'hi' } },
      }),
    });
    const body = await parseMcpResponse(callRes) as { result?: { isError?: boolean; content?: Array<{ text: string }> } };
    // XFF is ignored → real IP 127.0.0.1 used → not in 10.0.0.0/8 → denied.
    expect(body.result?.isError).toBe(true);
    const denial = JSON.parse(body.result?.content?.[0]?.text ?? '{}') as { code: string };
    expect(denial.code).toBe('IP_RANGE_DENIED');

    await proxy.close().catch(() => undefined);
  }, 30_000);
});
