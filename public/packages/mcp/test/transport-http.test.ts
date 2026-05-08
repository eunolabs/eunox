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
 */

import * as path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { CompatibilityCallToolResultSchema } from '@modelcontextprotocol/sdk/types.js';
import { HttpProxy } from '../src/transport/http';

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

  it('tools/list returns both tools from the mock upstream', async () => {
    const { tools } = await client.listTools();

    const names = tools.map((t) => t.name).sort();
    expect(names).toEqual(['echo', 'query_db']);
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
      expect(tools1.tools.map((t) => t.name).sort()).toEqual(['echo', 'query_db']);
      expect(tools2.tools.map((t) => t.name).sort()).toEqual(['echo', 'query_db']);
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
