/**
 * End-to-end test: `redactFields` strips sensitive fields from the upstream
 * response before forwarding it to the MCP client.
 *
 * Task 4 — Acceptance criteria
 * ─────────────────────────────
 * This test encodes the Stage-2 Task 4 claim:
 *   "fields listed in redactFields are removed from the upstream tool-call
 *    result before the proxy returns it to the MCP host"
 *
 * Topology
 * ────────
 *   Jest process
 *     └── StdioClientTransport (spawns proxy CLI via ts-node)
 *           └── euno-mcp proxy CLI
 *                 ├── ConditionEnforcerPDP (redactFields: [ssn, credit])
 *                 ├── LocalAuditSink → <tmpdir>/audit.jsonl
 *                 └── StdioClientTransport (spawns mock-upstream-recorder)
 *                       └── mock-upstream-recorder fixture
 *                             └── records calls to <tmpdir>/calls.jsonl
 *
 * Scenarios
 * ─────────
 * A. `get_user` with redactFields=[ssn, credit]:
 *    - Upstream returns `{id, name, ssn, credit}`.
 *    - Proxy returns `{id, name}` (ssn and credit stripped).
 *    - `isError` is NOT set (redactFields never denies).
 *    - Audit record: status=Success, unmapped.obligationsApplied=['redactFields'].
 *
 * B. Non-JSON text response (echo) is not altered:
 *    - Upstream returns a plain text string.
 *    - Proxy returns the string unchanged.
 *
 * C. Fields absent from the upstream response do not cause errors:
 *    - Manifest lists a field ('nonce') that does not appear in the response.
 *    - Proxy returns the original response unchanged (no crash, no error).
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { CompatibilityCallToolResultSchema } from '@modelcontextprotocol/sdk/types.js';
import type { SignedMcpAuditEvent } from '../src/audit/audit-sink';

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

interface TextContent {
  type: 'text';
  text: string;
}

interface ToolCallResult {
  content: TextContent[];
  isError?: boolean;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const TEST_SESSION_ID = 'e2e-redact-test-session';
const TS_NODE_REGISTER = require.resolve('ts-node/register');
const MOCK_UPSTREAM_RECORDER = path.resolve(
  __dirname,
  'fixtures',
  'mock-upstream-recorder.ts',
);
const PROXY_CLI = path.resolve(__dirname, '..', 'src', 'cli.ts');

/** Policy that restricts `get_user` with redactFields: [ssn, credit]. */
const REDACT_POLICY_YAML = `
name: e2e-redact-agent
agentId: e2e-redact-agent-001
version: "0.1.0"
requiredCapabilities:
  - resource: get_user
    actions:
      - call
    conditions:
      - type: redactFields
        fields: [ssn, credit]
`.trim();

/** Policy that lists a field absent from the upstream response. */
const REDACT_ABSENT_POLICY_YAML = `
name: e2e-redact-absent-agent
agentId: e2e-redact-absent-001
version: "0.1.0"
requiredCapabilities:
  - resource: echo
    actions:
      - call
    conditions:
      - type: redactFields
        fields: [nonce]
`.trim();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

function makeTempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'euno-e2e-redact-'));
  tempDirs.push(dir);
  return dir;
}

function buildRecordingProxyTransport(opts: {
  policyPath: string;
  auditLogPath: string;
  recorderFilePath: string;
  sessionId?: string;
}): StdioClientTransport {
  const sessionId = opts.sessionId ?? TEST_SESSION_ID;

  return new StdioClientTransport({
    command: process.execPath,
    args: [
      '--require', TS_NODE_REGISTER,
      PROXY_CLI,
      'proxy',
      '--policy', opts.policyPath,
      '--audit-log', opts.auditLogPath,
      '--session-id', sessionId,
      '--shutdown-timeout', '2000',
      '--',
      process.execPath,
      '--require', TS_NODE_REGISTER,
      MOCK_UPSTREAM_RECORDER,
      opts.recorderFilePath,
    ],
    env: {
      ...process.env,
      TS_NODE_TRANSPILE_ONLY: 'true',
      EUNO_TELEMETRY_DISABLED: '1',
    },
  });
}

async function waitForAuditRecords(
  auditLogPath: string,
  timeoutMs = 5_000,
  intervalMs = 100,
): Promise<SignedMcpAuditEvent[]> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const content = fs.readFileSync(auditLogPath, 'utf8').trim();
      if (content.length > 0) {
        return content
          .split('\n')
          .filter((l) => l.trim().length > 0)
          .map((l) => JSON.parse(l) as SignedMcpAuditEvent);
      }
    } catch {
      // File not yet created — keep polling.
    }
    await new Promise<void>((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new Error(
    `Timed out waiting for audit record in '${auditLogPath}' after ${timeoutMs}ms`,
  );
}

// ---------------------------------------------------------------------------
// Scenario A — redactFields strips ssn and credit from get_user response
// ---------------------------------------------------------------------------

describe('E2E: redactFields strips sensitive fields from the upstream response (Task 4)', () => {
  let client: Client;
  let transport: StdioClientTransport;
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = makeTempDir();

    const policyPath = path.join(tmpDir, 'policy.yaml');
    fs.writeFileSync(policyPath, REDACT_POLICY_YAML, 'utf8');

    transport = buildRecordingProxyTransport({
      policyPath,
      auditLogPath: path.join(tmpDir, 'audit.jsonl'),
      recorderFilePath: path.join(tmpDir, 'calls.jsonl'),
    });
    client = new Client({ name: 'e2e-redact-host', version: '0.1.0' }, { capabilities: {} });
    await client.connect(transport);
  }, 30_000);

  afterEach(async () => {
    await client.close().catch(() => undefined);
  }, 10_000);

  it('strips ssn and credit from the upstream JSON response', async () => {
    const raw = await client.callTool(
      { name: 'get_user', arguments: { id: '42' } },
      CompatibilityCallToolResultSchema,
    );
    const result = raw as unknown as ToolCallResult;

    // The call must succeed (redactFields never denies).
    expect(result.isError).toBeFalsy();
    expect(result.content).toHaveLength(1);
    expect(result.content[0]!.type).toBe('text');

    const body = JSON.parse(result.content[0]!.text) as Record<string, unknown>;

    // Sensitive fields must be absent.
    expect(Object.prototype.hasOwnProperty.call(body, 'ssn')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(body, 'credit')).toBe(false);

    // Non-sensitive fields must be present and correct.
    expect(body['id']).toBe('42');
    expect(body['name']).toBe('Alice');
  }, 20_000);

  it('upstream is still called (redactFields is a response-path obligation, not a deny)', async () => {
    const recorderFilePath = path.join(tmpDir, 'calls.jsonl');

    await client.callTool(
      { name: 'get_user', arguments: { id: '1' } },
      CompatibilityCallToolResultSchema,
    );

    // Give the synchronous recorder a brief moment to flush.
    await new Promise<void>((resolve) => setTimeout(resolve, 200));
    const raw = fs.readFileSync(recorderFilePath, 'utf8').trim();
    const entries = raw
      .split('\n')
      .filter(Boolean)
      .map((l) => JSON.parse(l) as { name: string; args: Record<string, unknown> });
    const getUserEntries = entries.filter((e) => e.name === 'get_user');

    // The upstream must have been called exactly once.
    expect(getUserEntries).toHaveLength(1);
  }, 20_000);

  it('audit record has status=Success and obligationsApplied=[redactFields]', async () => {
    const auditLogPath = path.join(tmpDir, 'audit.jsonl');

    await client.callTool(
      { name: 'get_user', arguments: { id: '7' } },
      CompatibilityCallToolResultSchema,
    );

    const records = await waitForAuditRecords(auditLogPath);
    expect(records).toHaveLength(1);
    const rec = records[0]!;

    // Allow path.
    expect(rec.status).toBe('Success');
    expect(rec.status_id).toBe(1);
    expect(rec.api?.operation).toBe('get_user');

    // Obligation recorded in unmapped.
    expect(rec.unmapped?.['obligationsApplied']).toEqual(['redactFields']);

    // No denial fields present.
    expect(rec.unmapped?.['denialCode']).toBeUndefined();
    expect(rec.unmapped?.['conditionType']).toBeUndefined();
  }, 20_000);
});

// ---------------------------------------------------------------------------
// Scenario B — non-JSON text is not altered
// ---------------------------------------------------------------------------

describe('E2E: redactFields does not alter non-JSON text responses (Task 4)', () => {
  let client: Client;
  let transport: StdioClientTransport;
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = makeTempDir();

    // Policy with redactFields on the echo tool (whose response is plain text).
    const policyPath = path.join(tmpDir, 'policy.yaml');
    fs.writeFileSync(policyPath, REDACT_ABSENT_POLICY_YAML, 'utf8');

    transport = buildRecordingProxyTransport({
      policyPath,
      auditLogPath: path.join(tmpDir, 'audit.jsonl'),
      recorderFilePath: path.join(tmpDir, 'calls.jsonl'),
    });
    client = new Client({ name: 'e2e-non-json-host', version: '0.1.0' }, { capabilities: {} });
    await client.connect(transport);
  }, 30_000);

  afterEach(async () => {
    await client.close().catch(() => undefined);
  }, 10_000);

  it('plain text response is forwarded unchanged when field is absent', async () => {
    const text = 'hello from test';
    const raw = await client.callTool(
      { name: 'echo', arguments: { text } },
      CompatibilityCallToolResultSchema,
    );
    const result = raw as unknown as ToolCallResult;

    expect(result.isError).toBeFalsy();
    expect(result.content).toHaveLength(1);
    // The echo response is not JSON — the proxy must not alter it.
    expect(result.content[0]!.text).toBe(text);
  }, 20_000);
});
