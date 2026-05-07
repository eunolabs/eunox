/**
 * Integration tests for the @euno/mcp stdio proxy transport.
 *
 * Topology
 * ────────
 *   Jest process
 *     └── StdioClientTransport (spawns proxy CLI via ts-node)
 *           └── euno-mcp proxy CLI
 *                 └── StdioClientTransport (spawns mock-upstream via ts-node)
 *                       └── mock-upstream fixture
 *
 * Each test drives a real MCP `Client` connected to the proxy, which in turn
 * connects to the mock-upstream fixture.  The proxy runs with `AlwaysAllowPDP`
 * (Stage 1 default) so all tool calls are permitted.
 *
 * Acceptance criteria (Task 4):
 *   ✓  `tools/list` returns both tools declared by the mock upstream.
 *   ✓  `tools/call echo` round-trips the input text through the proxy.
 *   ✓  `tools/call query_db` returns a result containing the SQL string.
 *   ✓  A tool denied by the PDP returns `isError: true` with a CapabilityDenied body.
 */

import * as path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { CompatibilityCallToolResultSchema } from '@modelcontextprotocol/sdk/types.js';

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

/** Absolute path to the euno-mcp CLI entry point. */
const PROXY_CLI = path.resolve(__dirname, '..', 'src', 'cli.ts');

/** Path to the ts-node register hook (in the monorepo root node_modules). */
const TS_NODE_REGISTER = require.resolve('ts-node/register');

/**
 * Builds a `StdioClientTransport` that spawns the euno-mcp proxy (via ts-node)
 * in front of the mock-upstream fixture (also via ts-node).
 *
 * The proxy CLI is invoked as:
 *   node --require ts-node/register src/cli.ts proxy [extraArgs...] --
 *       node --require ts-node/register test/fixtures/mock-upstream.ts
 */
function buildProxyTransport(
  extraProxyArgs: string[] = [],
  sessionId?: string,
): StdioClientTransport {
  const upstreamCmd = process.execPath;
  const upstreamArgs = [
    '--require',
    TS_NODE_REGISTER,
    MOCK_UPSTREAM,
  ];

  const proxyArgs = [
    '--require',
    TS_NODE_REGISTER,
    PROXY_CLI,
    'proxy',
    ...extraProxyArgs,
    ...(sessionId ? ['--session-id', sessionId] : []),
    '--',
    upstreamCmd,
    ...upstreamArgs,
  ];

  return new StdioClientTransport({
    command: process.execPath,
    args: proxyArgs,
    env: {
      ...process.env,
      TS_NODE_TRANSPILE_ONLY: 'true',
      // Suppress ts-node deprecation output on the proxy's stderr.
      TS_NODE_SKIP_PROJECT: 'false',
    },
  });
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

describe('StdioProxy — integration (Task 4)', () => {
  let client: Client;
  let transport: StdioClientTransport;

  beforeEach(async () => {
    transport = buildProxyTransport();
    client = new Client({ name: 'test-host', version: '1.0.0' }, { capabilities: {} });
    await client.connect(transport);
  }, 30_000);

  afterEach(async () => {
    await client.close().catch(() => undefined);
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

  it('tools/call echo round-trips text through the proxy', async () => {
    const raw = await client.callTool(
      { name: 'echo', arguments: { text: 'hello from test' } },
      CompatibilityCallToolResultSchema,
    );
    const result = raw as unknown as ToolCallResult;

    expect(result.isError).toBeFalsy();
    expect(result.content).toHaveLength(1);
    expect(result.content[0]!.type).toBe('text');
    expect(result.content[0]!.text).toBe('hello from test');
  }, 20_000);

  // ── tools/call query_db ────────────────────────────────────────────────────

  it('tools/call query_db returns a result containing the SQL string', async () => {
    const sql = 'SELECT 1 FROM users WHERE id = 42';
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

  // ── Error propagation ────────────────────────────────────────────────────

  it('calling a nonexistent tool propagates an McpError from the upstream', async () => {
    // When the upstream has no handler for a tool, it returns a JSON-RPC
    // protocol error (-32603).  The proxy forwards this as a transport-level
    // error and the SDK client throws it as an McpError.
    //
    // NOTE: Tool-call *denial* (isError: true + CapabilityDenied body) is a
    // different code path exercised in Phase B tests (Task 8), where a real
    // PDP is wired in.
    await expect(
      client.callTool(
        { name: 'nonexistent_tool', arguments: {} },
        CompatibilityCallToolResultSchema,
      ),
    ).rejects.toThrow(/Unknown tool.*nonexistent_tool/i);
  }, 20_000);

  // ── resources/list ─────────────────────────────────────────────────────────

  it('resources/list returns the mock resource', async () => {
    const { resources } = await client.listResources();

    expect(resources).toHaveLength(1);
    expect(resources[0]!.uri).toBe('file:///data/mock.txt');
  }, 20_000);
});
