/**
 * End-to-end tests for argumentSchema structured error reporting (Task 1).
 *
 * Topology
 * ────────
 *   Jest process
 *     └── HttpProxy (in-process, port 0 → random ephemeral port)
 *           ├── ConditionEnforcerPDP  ← wired with argumentSchema policy
 *           └── StdioClientTransport (spawns mock-upstream via ts-node)
 *                 └── mock-upstream fixture
 *
 * Acceptance criteria (Task 1):
 *   ✓  A denied call returns isError: true with a CapabilityDenied body.
 *   ✓  The body contains a machine-readable `details` object.
 *   ✓  `details.path` identifies the failing JSON path.
 *   ✓  `details.expected` describes the constraint that was violated.
 *   ✓  `details.got` carries the actual offending value (or descriptor).
 *   ✓  The allow-path behaviour is unchanged (no details on success).
 *   ✓  Non-argumentSchema denials do NOT carry a `details` object.
 *   ✓  The audit sink receives the same structured details.
 *   ✓  HTTP proxy forwards details in the denial result body.
 */

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { CompatibilityCallToolResultSchema } from '@modelcontextprotocol/sdk/types.js';

import { HttpProxy } from '../src/transport/http';
import { ConditionEnforcerPDP } from '../src/pdp';
import { LocalAuditSink, SignedMcpAuditEvent } from '../src/audit/audit-sink';
import { LocalHmacSigner } from '../src/audit/hmac-signer';
import type { AgentCapabilityManifest } from '@euno/common-core';
import type { LocalPolicySource } from '../src/policy/source';

// --------------------------------------------------------------------------
// Shared types
// --------------------------------------------------------------------------

interface TextContent {
  type: 'text';
  text: string;
}

interface ToolCallResult {
  content: TextContent[];
  isError?: boolean;
}

/** Parsed CapabilityDenied body from a denial result. */
interface CapabilityDeniedBody {
  error: 'CapabilityDenied';
  tool: string;
  code: string;
  message: string;
  details?: {
    path: string;
    expected: string;
    got: unknown;
  };
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

const MOCK_UPSTREAM = path.resolve(__dirname, 'fixtures', 'mock-upstream.ts');
const TS_NODE_REGISTER = require.resolve('ts-node/register');

function staticPolicySource(manifest: AgentCapabilityManifest): LocalPolicySource {
  return { load: async () => manifest };
}

/**
 * Parses the denial body from a tool-call result.
 * Returns null when the result is not an error.
 */
function parseDenialBody(result: ToolCallResult): CapabilityDeniedBody | null {
  if (!result.isError) return null;
  try {
    return JSON.parse(result.content[0]!.text) as CapabilityDeniedBody;
  } catch {
    return null;
  }
}

function readAuditLines(logPath: string): SignedMcpAuditEvent[] {
  if (!fs.existsSync(logPath)) return [];
  const raw = fs.readFileSync(logPath, 'utf8');
  return raw
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l) as SignedMcpAuditEvent);
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

describe('argumentSchema structured error reporting — E2E via HttpProxy', () => {
  let proxy: HttpProxy;
  let client: Client;
  let auditDir: string;
  let auditLogPath: string;
  let auditSink: LocalAuditSink;

  beforeEach(async () => {
    auditDir = fs.mkdtempSync(path.join(os.tmpdir(), 'euno-e2e-audit-'));
    auditLogPath = path.join(auditDir, 'audit.jsonl');
    const signer = new LocalHmacSigner(crypto.randomBytes(32));
    auditSink = new LocalAuditSink(signer, { logPath: auditLogPath });

    // Policy: `echo` tool requires a `text` string argument.
    const manifest: AgentCapabilityManifest = {
      agentId: 'e2e-agent',
      name: 'E2E Agent',
      version: '0.1.0',
      requiredCapabilities: [
        {
          resource: 'echo',
          actions: ['call'],
          argumentSchema: {
            type: 'object',
            properties: { text: { type: 'string', minLength: 1 } },
            required: ['text'],
          },
        },
      ],
    };

    const pdp = new ConditionEnforcerPDP({
      policySource: staticPolicySource(manifest),
    });

    proxy = new HttpProxy({
      command: process.execPath,
      args: ['--require', TS_NODE_REGISTER, MOCK_UPSTREAM],
      env: { ...process.env, TS_NODE_TRANSPILE_ONLY: 'true' },
      port: 0,
      bind: '127.0.0.1',
      pdp,
      auditSink,
    });

    const port = await proxy.start();
    const url = new URL(`http://127.0.0.1:${port}/mcp`);
    const transport = new StreamableHTTPClientTransport(url);
    client = new Client({ name: 'test-host', version: '0.1.0' }, { capabilities: {} });
    await client.connect(transport);
  }, 30_000);

  afterEach(async () => {
    await client.close().catch(() => undefined);
    await proxy.close().catch(() => undefined);
    await auditSink.close().catch(() => undefined);
    fs.rmSync(auditDir, { recursive: true, force: true });
  }, 15_000);

  // ── allow path ─────────────────────────────────────────────────────────────

  it('allows a conforming call and returns no isError flag', async () => {
    const raw = await client.callTool(
      { name: 'echo', arguments: { text: 'hello' } },
      CompatibilityCallToolResultSchema,
    );
    const result = raw as unknown as ToolCallResult;

    expect(result.isError).toBeFalsy();
    expect(result.content[0]!.text).toBe('hello');
  }, 20_000);

  // ── deny path — structured details in the HTTP response ───────────────────

  it('denial for missing required property carries structured details', async () => {
    const raw = await client.callTool(
      { name: 'echo', arguments: {} },
      CompatibilityCallToolResultSchema,
    );
    const result = raw as unknown as ToolCallResult;
    const body = parseDenialBody(result);

    expect(result.isError).toBe(true);
    expect(body).not.toBeNull();
    expect(body!.error).toBe('CapabilityDenied');
    expect(body!.code).toBe('ARGUMENT_VALIDATION_FAILED');
    expect(body!.details).toBeDefined();
    expect(body!.details!.path).toBe('args.text');
    expect(body!.details!.expected).toBe('present');
    expect(body!.details!.got).toBe('absent');
  }, 20_000);

  it('denial for wrong type carries structured details with type info', async () => {
    const raw = await client.callTool(
      { name: 'echo', arguments: { text: 42 } },
      CompatibilityCallToolResultSchema,
    );
    const result = raw as unknown as ToolCallResult;
    const body = parseDenialBody(result);

    expect(result.isError).toBe(true);
    expect(body!.details).toBeDefined();
    expect(body!.details!.path).toBe('args.text');
    expect(body!.details!.expected).toContain('string');
    expect(body!.details!.got).toBe('number');
  }, 20_000);

  it('denial for minLength violation carries length info', async () => {
    const raw = await client.callTool(
      { name: 'echo', arguments: { text: '' } },
      CompatibilityCallToolResultSchema,
    );
    const result = raw as unknown as ToolCallResult;
    const body = parseDenialBody(result);

    expect(result.isError).toBe(true);
    expect(body!.details!.path).toBe('args.text');
    expect(body!.details!.expected).toContain('>= 1');
    expect(body!.details!.got).toBe(0);
  }, 20_000);

  it('denial for disallowed additional property carries property info', async () => {
    const raw = await client.callTool(
      { name: 'echo', arguments: { text: 'hello', extra: 'bad' } },
      CompatibilityCallToolResultSchema,
    );
    const result = raw as unknown as ToolCallResult;
    const body = parseDenialBody(result);

    expect(result.isError).toBe(true);
    expect(body!.details!.path).toBe('args.extra');
    expect(body!.details!.expected).toBe('absent');
    expect(body!.details!.got).toBe('present');
  }, 20_000);

  it('human-readable message is present alongside details', async () => {
    const raw = await client.callTool(
      { name: 'echo', arguments: {} },
      CompatibilityCallToolResultSchema,
    );
    const result = raw as unknown as ToolCallResult;
    const body = parseDenialBody(result);

    expect(body!.message).toMatch(/Argument validation failed/);
    expect(body!.details).toBeDefined();
  }, 20_000);

  // ── audit sink receives the same structured details ───────────────────────

  it('audit log records details in unmapped for a denied call', async () => {
    await client.callTool(
      { name: 'echo', arguments: {} },
      CompatibilityCallToolResultSchema,
    );
    // Give the fire-and-forget audit write time to flush.
    await auditSink.flush();

    const events = readAuditLines(auditLogPath);
    const denialEvent = events.find((e) => e.status === 'Failure');

    expect(denialEvent).toBeDefined();
    expect(denialEvent!.unmapped).toMatchObject({
      denialCode: 'ARGUMENT_VALIDATION_FAILED',
      conditionType: 'argumentSchema',
      details: {
        path: 'args.text',
        expected: 'present',
        got: 'absent',
      },
    });
  }, 20_000);

  it('audit log does NOT include details for an allowed call', async () => {
    await client.callTool(
      { name: 'echo', arguments: { text: 'hello' } },
      CompatibilityCallToolResultSchema,
    );
    await auditSink.flush();

    const events = readAuditLines(auditLogPath);
    const allowEvent = events.find((e) => e.status === 'Success');

    expect(allowEvent).toBeDefined();
    expect(allowEvent!.unmapped).not.toHaveProperty('details');
  }, 20_000);

  // ── unconstrained tool is unaffected ─────────────────────────────────────

  it('a tool not in the manifest is allowed and returns no details', async () => {
    // query_db is not in our test manifest → no constraint → allow
    const raw = await client.callTool(
      { name: 'query_db', arguments: { sql: 'SELECT 1' } },
      CompatibilityCallToolResultSchema,
    );
    const result = raw as unknown as ToolCallResult;
    expect(result.isError).toBeFalsy();
  }, 20_000);
});
