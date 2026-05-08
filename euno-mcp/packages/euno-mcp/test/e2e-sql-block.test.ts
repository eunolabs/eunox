/**
 * End-to-end test: destructive SQL is blocked before upstream is called.
 *
 * Task 11 — Acceptance criteria
 * ──────────────────────────────
 * This test encodes the README's headline claim:
 *   "the agent called the tool with these arguments — upstream never called"
 * as an executable regression guard.  The test MUST fail if any future change
 * forwards a denied `tools/call` to the upstream MCP server.
 *
 * Topology
 * ────────
 *   Jest process
 *     └── StdioClientTransport (spawns proxy CLI via ts-node)
 *           └── euno-mcp proxy CLI
 *                 ├── ConditionEnforcerPDP (allowedOperations: [SELECT])
 *                 ├── LocalAuditSink → <tmpdir>/audit.jsonl
 *                 └── StdioClientTransport (spawns mock-upstream-recorder)
 *                       └── mock-upstream-recorder fixture
 *                             └── recorder path via process.argv[2] → <tmpdir>/calls.jsonl
 *
 * Scenario: DROP TABLE is denied
 * ────────────────────────────────
 * 1. Load a policy that restricts `query_db` to SELECT operations only.
 * 2. Send `tools/call query_db { query: "DROP TABLE users" }`.
 * 3. Assert (A): client receives `isError: true` with a `CapabilityDenied` body
 *               carrying code `OPERATION_NOT_ALLOWED`.
 * 4. Assert (B): the recorder file has zero entries — the upstream was never
 *               reached.
 * 5. Assert (C): the audit JSONL contains exactly one record with
 *               `status: "Failure"`, `unmapped.denialCode: "OPERATION_NOT_ALLOWED"`,
 *               and the correct session ID and tool name.
 *
 * Scenario: SELECT passes through
 * ─────────────────────────────────
 * 1. Same policy — `query_db` restricted to SELECT.
 * 2. Send `tools/call query_db { query: "SELECT * FROM users" }`.
 * 3. Assert: call succeeds and the recorder file has exactly one entry, proving
 *            the upstream was reached for permitted operations.
 *
 * References
 * ──────────
 * - docs/stage1executionplan.md: Task 11
 * - docs/mvp.md §"Enforcement guarantee" lines 404-412
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

/** Shape of a text content item in an MCP tool-call result. */
interface TextContent {
  type: 'text';
  text: string;
}

/** Minimal typed view of a tool-call result used by these tests. */
interface ToolCallResult {
  content: TextContent[];
  isError?: boolean;
}

/** Shape of a CapabilityDenied payload embedded in a denial result's text. */
interface CapabilityDeniedPayload {
  error: string;
  tool: string;
  code: string;
  message: string;
}

/** Shape of one line in the recorder JSONL file. */
interface RecorderEntry {
  name: string;
  args: Record<string, unknown>;
  ts: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Fixed session ID injected via `--session-id` so assertions are deterministic. */
const TEST_SESSION_ID = 'e2e-sql-block-test-session';

/**
 * Brief settle time (ms) given to the upstream fixture's synchronous
 * `fs.appendFileSync` call to flush through the OS page cache and become
 * visible to the test process's `fs.readFileSync`.  This is only needed for
 * the positive-control scenario where the upstream writes before returning
 * the response — the test reads immediately after `callTool()` resolves, so
 * a small tick is required.
 */
const FILE_IO_SETTLE_MS = 200;

/** Policy YAML that restricts `query_db` to SELECT operations only. */
const SELECT_ONLY_POLICY_YAML = `
name: e2e-block-agent
agentId: e2e-block-agent-001
version: "1.0.0"
requiredCapabilities:
  - resource: query_db
    actions:
      - call
    conditions:
      - type: allowedOperations
        operations:
          - SELECT
`.trim();

/** Path to the ts-node register hook. */
const TS_NODE_REGISTER = require.resolve('ts-node/register');

/** Path to the recording mock-upstream fixture. */
const MOCK_UPSTREAM_RECORDER = path.resolve(
  __dirname,
  'fixtures',
  'mock-upstream-recorder.ts',
);

/** Path to the euno-mcp CLI entry point. */
const PROXY_CLI = path.resolve(__dirname, '..', 'src', 'cli.ts');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Temporary directories created during each test — removed in afterEach. */
const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

/**
 * Create a fresh temporary directory for test artefacts (policy file, audit
 * log, recorder file).  Registered for cleanup in `afterEach`.
 */
function makeTempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'euno-e2e-sql-'));
  tempDirs.push(dir);
  return dir;
}

/**
 * Build a `StdioClientTransport` that spawns the euno-mcp proxy CLI (via
 * ts-node) in front of the `mock-upstream-recorder` fixture.
 *
 * The proxy is configured with:
 *   - `--policy <policyPath>`   — the policy file to enforce
 *   - `--audit-log <auditPath>` — OCSF JSONL destination
 *   - `--session-id <id>`       — fixed session ID for deterministic assertions
 */
function buildRecordingProxyTransport(opts: {
  policyPath: string;
  auditLogPath: string;
  recorderFilePath: string;
  sessionId?: string;
}): StdioClientTransport {
  const sessionId = opts.sessionId ?? TEST_SESSION_ID;

  const upstreamArgs = [
    '--require',
    TS_NODE_REGISTER,
    MOCK_UPSTREAM_RECORDER,
    opts.recorderFilePath, // passed as process.argv[2] — avoids POSIX env-var filtering
  ];

  const proxyArgs = [
    '--require',
    TS_NODE_REGISTER,
    PROXY_CLI,
    'proxy',
    '--policy',
    opts.policyPath,
    '--audit-log',
    opts.auditLogPath,
    '--session-id',
    sessionId,
    '--shutdown-timeout',
    '2000',
    '--',
    process.execPath,
    ...upstreamArgs,
  ];

  return new StdioClientTransport({
    command: process.execPath,
    args: proxyArgs,
    env: {
      ...process.env,
      TS_NODE_TRANSPILE_ONLY: 'true',
      // Suppress telemetry during tests.
      EUNO_TELEMETRY_DISABLED: '1',
    },
  });
}

/**
 * Poll for the audit log file to contain at least one non-empty line, then
 * return all records in the file.
 *
 * The audit sink writes records fire-and-forget (after returning the
 * enforcement decision to the client) so there is a brief window between
 * when the client receives the denial response and when the line is flushed
 * to disk.  This helper retries every `intervalMs` for up to `timeoutMs`.
 *
 * @throws if no record appears within the timeout.
 */
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
      // File doesn't exist yet — keep polling.
    }
    await new Promise<void>((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new Error(
    `Timed out waiting for audit record in '${auditLogPath}' after ${timeoutMs}ms`,
  );
}

/**
 * Read the recorder JSONL file and return all logged entries.
 * Returns an empty array if the file does not exist.
 */
function readRecorderEntries(recorderFilePath: string): RecorderEntry[] {
  try {
    const content = fs.readFileSync(recorderFilePath, 'utf8').trim();
    if (!content) return [];
    return content
      .split('\n')
      .filter((l) => l.trim().length > 0)
      .map((l) => JSON.parse(l) as RecorderEntry);
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('E2E: destructive SQL is blocked before upstream is called (Task 11)', () => {
  let client: Client;
  let transport: StdioClientTransport;
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = makeTempDir();

    // Write the SELECT-only policy file.
    const policyPath = path.join(tmpDir, 'policy.yaml');
    fs.writeFileSync(policyPath, SELECT_ONLY_POLICY_YAML, 'utf8');

    const auditLogPath = path.join(tmpDir, 'audit.jsonl');
    const recorderFilePath = path.join(tmpDir, 'calls.jsonl');

    transport = buildRecordingProxyTransport({
      policyPath,
      auditLogPath,
      recorderFilePath,
      sessionId: TEST_SESSION_ID,
    });

    client = new Client(
      { name: 'e2e-test-host', version: '1.0.0' },
      { capabilities: {} },
    );
    await client.connect(transport);
  }, 30_000);

  afterEach(async () => {
    await client.close().catch(() => undefined);
  }, 10_000);

  // ── A. Client receives CapabilityDenied ─────────────────────────────────────

  it('client receives isError: true with CapabilityDenied for DROP TABLE', async () => {
    const raw = await client.callTool(
      { name: 'query_db', arguments: { query: 'DROP TABLE users' } },
      CompatibilityCallToolResultSchema,
    );
    const result = raw as unknown as ToolCallResult;

    // The proxy must return a tool-call result (not a transport error) so the
    // host can present a human-readable denial.
    expect(result.isError).toBe(true);
    expect(result.content).toHaveLength(1);
    expect(result.content[0]!.type).toBe('text');

    const payload = JSON.parse(result.content[0]!.text) as CapabilityDeniedPayload;
    expect(payload.error).toBe('CapabilityDenied');
    expect(payload.tool).toBe('query_db');
    expect(payload.code).toBe('OPERATION_NOT_ALLOWED');
    expect(typeof payload.message).toBe('string');
    expect(payload.message.length).toBeGreaterThan(0);
  }, 20_000);

  // ── B. Upstream was never called ────────────────────────────────────────────

  it('upstream recorder shows zero query_db invocations for a denied DROP', async () => {
    const recorderFilePath = path.join(tmpDir, 'calls.jsonl');

    await client.callTool(
      { name: 'query_db', arguments: { query: 'DROP TABLE users' } },
      CompatibilityCallToolResultSchema,
    );

    // The proxy must make its enforcement decision and return the denial to the
    // client without ever contacting the upstream.  The recorder file is
    // written synchronously at the START of every tools/call handler the
    // upstream receives — so an empty file proves the upstream was never called.
    const entries = readRecorderEntries(recorderFilePath);
    const queryDbEntries = entries.filter((e) => e.name === 'query_db');

    expect(queryDbEntries).toHaveLength(0);
  }, 20_000);

  // ── C. OCSF deny record on disk ─────────────────────────────────────────────

  it('one OCSF deny record is written with the correct denial code', async () => {
    const auditLogPath = path.join(tmpDir, 'audit.jsonl');

    await client.callTool(
      { name: 'query_db', arguments: { query: 'DROP TABLE users' } },
      CompatibilityCallToolResultSchema,
    );

    // The audit write is fire-and-forget — poll until the record appears.
    const records = await waitForAuditRecords(auditLogPath);

    expect(records).toHaveLength(1);
    const rec = records[0]!;

    // OCSF API Activity class
    expect(rec.class_uid).toBe(6003);

    // Failure status
    expect(rec.status_id).toBe(2);
    expect(rec.status).toBe('Failure');

    // Tool name in api.operation
    expect(rec.api?.operation).toBe('query_db');

    // Session ID in actor.session.uid
    expect(rec.actor?.session?.uid).toBe(TEST_SESSION_ID);

    // Denial code in unmapped
    expect(rec.unmapped?.['denialCode']).toBe('OPERATION_NOT_ALLOWED');
    expect(rec.unmapped?.['conditionType']).toBe('allowedOperations');

    // HMAC enrichment present (tamper-evidence)
    expect(Array.isArray(rec.enrichments)).toBe(true);
    const hmacEnrichment = rec.enrichments?.find(
      (e) => e.name === 'hmac-signature',
    );
    expect(hmacEnrichment).toBeDefined();
    expect(typeof hmacEnrichment?.value).toBe('string');
    expect(hmacEnrichment?.value.length).toBeGreaterThan(0);
  }, 20_000);

  // ── Combined: single-invocation scenario covering all three criteria ─────────

  it(
    'single DROP call: denied to client, upstream not reached, audit deny record written',
    async () => {
      const auditLogPath = path.join(tmpDir, 'audit.jsonl');
      const recorderFilePath = path.join(tmpDir, 'calls.jsonl');

      const raw = await client.callTool(
        { name: 'query_db', arguments: { query: 'DROP TABLE users' } },
        CompatibilityCallToolResultSchema,
      );
      const result = raw as unknown as ToolCallResult;

      // A. Client receives a structured denial.
      expect(result.isError).toBe(true);
      const payload = JSON.parse(result.content[0]!.text) as CapabilityDeniedPayload;
      expect(payload.error).toBe('CapabilityDenied');
      expect(payload.code).toBe('OPERATION_NOT_ALLOWED');

      // B. Upstream was never called.
      expect(readRecorderEntries(recorderFilePath)).toHaveLength(0);

      // C. Audit log contains one deny record.
      const records = await waitForAuditRecords(auditLogPath);
      expect(records).toHaveLength(1);
      expect(records[0]!.status).toBe('Failure');
      expect(records[0]!.unmapped?.['denialCode']).toBe('OPERATION_NOT_ALLOWED');
    },
    25_000,
  );
});

// ---------------------------------------------------------------------------
// Positive control: SELECT passes through to the upstream
// ---------------------------------------------------------------------------

describe('E2E: permitted SQL reaches the upstream (positive control)', () => {
  let client: Client;
  let transport: StdioClientTransport;
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = makeTempDir();

    const policyPath = path.join(tmpDir, 'policy.yaml');
    fs.writeFileSync(policyPath, SELECT_ONLY_POLICY_YAML, 'utf8');

    transport = buildRecordingProxyTransport({
      policyPath,
      auditLogPath: path.join(tmpDir, 'audit.jsonl'),
      recorderFilePath: path.join(tmpDir, 'calls.jsonl'),
      sessionId: TEST_SESSION_ID,
    });

    client = new Client(
      { name: 'e2e-positive-host', version: '1.0.0' },
      { capabilities: {} },
    );
    await client.connect(transport);
  }, 30_000);

  afterEach(async () => {
    await client.close().catch(() => undefined);
  }, 10_000);

  it('SELECT query is allowed and reaches the upstream', async () => {
    const recorderFilePath = path.join(tmpDir, 'calls.jsonl');
    const auditLogPath = path.join(tmpDir, 'audit.jsonl');

    const raw = await client.callTool(
      { name: 'query_db', arguments: { query: 'SELECT * FROM users' } },
      CompatibilityCallToolResultSchema,
    );
    const result = raw as unknown as ToolCallResult;

    // No denial for a permitted operation.
    expect(result.isError).toBeFalsy();
    expect(result.content).toHaveLength(1);

    // The upstream received the call — recorder has exactly one entry.
    // Give the recorder a brief moment since the call was synchronous on the
    // upstream side, but wait a tick in case file I/O lags.
    await new Promise<void>((resolve) => setTimeout(resolve, FILE_IO_SETTLE_MS));
    const entries = readRecorderEntries(recorderFilePath);
    const queryDbEntries = entries.filter((e) => e.name === 'query_db');
    expect(queryDbEntries).toHaveLength(1);
    expect(queryDbEntries[0]?.args?.['query']).toBe('SELECT * FROM users');

    // Audit log contains one allow record (status: Success).
    const records = await waitForAuditRecords(auditLogPath);
    expect(records).toHaveLength(1);
    expect(records[0]!.status).toBe('Success');
    expect(records[0]!.status_id).toBe(1);
  }, 25_000);
});
