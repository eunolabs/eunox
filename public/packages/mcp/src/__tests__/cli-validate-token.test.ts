/**
 * Subprocess tests for `euno-mcp validate-token` CLI command.
 *
 * These tests spawn a real subprocess using ts-node to exercise the full
 * CLI pipeline from argument parsing through audit-log reading and signature
 * verification.
 *
 * Test matrix
 * -----------
 * --help
 *   ✓ exits 0 and prints usage information
 *   ✓ output mentions --request-id option
 *   ✓ output mentions --since option
 *   ✓ output mentions --audit-log option
 *
 * No arguments
 *   ✓ exits 1 and prints error about missing required option
 *
 * --request-id mode
 *   ✓ exits 1 when audit log does not exist
 *   ✓ exits 1 when record is not found in the log
 *   ✓ exits 0 when record is found with valid signature
 *   ✓ exits 2 when record is found but signature is tampered
 *   ✓ stdout contains "Audit record found" on success
 *   ✓ stdout contains the request ID on success
 *   ✓ stdout contains the tool name on success
 *   ✓ stdout contains the session ID on success
 *   ✓ stdout contains "allow" for allow decisions
 *   ✓ stdout contains "deny" for deny decisions
 *   ✓ stdout contains the denialCode for deny decisions
 *   ✓ stderr contains error message on not-found
 *   ✓ exit 2 output shows "✗ INVALID" for bad signature
 *
 * --since mode
 *   ✓ exits 0 when audit log does not exist (no output)
 *   ✓ exits 0 and prints allow summary line
 *   ✓ exits 0 and prints deny summary line
 *   ✓ exits 0 and prints nothing for empty matching window
 *   ✓ summary line contains "[allow]" for allow decisions
 *   ✓ summary line contains "[DENY ]" for deny decisions
 *   ✓ --since invalid value exits 1 with error
 *
 * --audit-log (custom path)
 *   ✓ uses the specified path when provided
 *   ✓ exits 1 for --request-id when custom path has no files
 */

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as childProcess from 'node:child_process';

import { LocalHmacSigner } from '../audit/hmac-signer';
import { loadOrCreateHmacKey, DEFAULT_KEY_PATH } from '../audit/hmac-key';
import { LocalAuditSink, type McpAuditRecord } from '../audit/audit-sink';

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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'euno-vt-cli-test-'));
  tempDirs.push(dir);
  return dir;
}

const TS_NODE_REGISTER = require.resolve('ts-node/register');
const CLI = path.resolve(__dirname, '..', '..', 'src', 'cli.ts');

function runValidateToken(
  args: string[],
  env: Record<string, string> = {},
): { exitCode: number; stdout: string; stderr: string } {
  const result = childProcess.spawnSync(
    process.execPath,
    ['--require', TS_NODE_REGISTER, CLI, 'validate-token', ...args],
    {
      encoding: 'utf8',
      timeout: 20_000,
      env: { ...process.env, EUNO_TELEMETRY: '0', ...env },
    },
  );
  return {
    exitCode: result.status ?? 1,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

/** Write a signed audit JSONL file using the system HMAC key (same as CLI uses). */
async function writeAuditFileWithSystemKey(
  logPath: string,
  records: McpAuditRecord[],
): Promise<string[]> {
  const key = await loadOrCreateHmacKey(DEFAULT_KEY_PATH);
  const signer = new LocalHmacSigner(key);
  fs.mkdirSync(path.dirname(logPath), { recursive: true });
  const sink = new LocalAuditSink(signer, { logPath });
  for (const r of records) await sink.record(r);
  await sink.close();
  const lines = fs.readFileSync(logPath, 'utf8').trim().split('\n').filter(Boolean);
  return lines.map((l) => JSON.parse(l).metadata.uid as string);
}

function allowRecord(overrides: Partial<McpAuditRecord> = {}): McpAuditRecord {
  return {
    requestId: crypto.randomUUID(),
    sessionId: 'sess-cli-test',
    toolName: 'echo',
    decision: 'allow',
    ...overrides,
  };
}

function denyRecord(overrides: Partial<McpAuditRecord> = {}): McpAuditRecord {
  return {
    requestId: crypto.randomUUID(),
    sessionId: 'sess-cli-test',
    toolName: 'query_db',
    decision: 'deny',
    denialCode: 'MAX_CALLS_EXCEEDED',
    conditionType: 'maxCalls',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// --help
// ---------------------------------------------------------------------------

describe('validate-token --help', () => {
  it('exits 0 when --help is passed', () => {
    const { exitCode } = runValidateToken(['--help']);
    expect(exitCode).toBe(0);
  });

  it('prints information about --request-id option', () => {
    const { stdout } = runValidateToken(['--help']);
    expect(stdout).toContain('request-id');
  });

  it('prints information about --since option', () => {
    const { stdout } = runValidateToken(['--help']);
    expect(stdout).toContain('since');
  });

  it('prints information about --audit-log option', () => {
    const { stdout } = runValidateToken(['--help']);
    expect(stdout).toContain('audit-log');
  });
});

// ---------------------------------------------------------------------------
// No arguments
// ---------------------------------------------------------------------------

describe('validate-token — no arguments', () => {
  it('exits 1 when no options are provided', () => {
    const dir = makeTempDir();
    const { exitCode } = runValidateToken(['--audit-log', path.join(dir, 'audit.jsonl')]);
    expect(exitCode).toBe(1);
  });

  it('stderr contains an explanatory error message', () => {
    const dir = makeTempDir();
    const { stderr } = runValidateToken(['--audit-log', path.join(dir, 'audit.jsonl')]);
    expect(stderr.toLowerCase()).toMatch(/require|option|missing/);
  });
});

// ---------------------------------------------------------------------------
// --request-id mode
// ---------------------------------------------------------------------------

describe('validate-token --request-id', () => {
  it('exits 1 when audit log does not exist', () => {
    const dir = makeTempDir();
    const { exitCode } = runValidateToken([
      '--request-id', 'does-not-exist',
      '--audit-log', path.join(dir, 'audit.jsonl'),
    ]);
    expect(exitCode).toBe(1);
  });

  it('stderr mentions "Audit log not found" when log does not exist', () => {
    const dir = makeTempDir();
    const { stderr } = runValidateToken([
      '--request-id', 'missing',
      '--audit-log', path.join(dir, 'audit.jsonl'),
    ]);
    expect(stderr).toContain('Audit log not found');
  });

  it('exits 1 when record is not found in existing log', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    await writeAuditFileWithSystemKey(logPath, [allowRecord({ requestId: 'other' })]);

    const { exitCode } = runValidateToken([
      '--request-id', 'completely-different-uid',
      '--audit-log', logPath,
    ]);
    expect(exitCode).toBe(1);
  });

  it('stderr mentions "No audit record found" when not found', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    await writeAuditFileWithSystemKey(logPath, [allowRecord()]);

    const { stderr } = runValidateToken([
      '--request-id', 'not-this-uid',
      '--audit-log', logPath,
    ]);
    expect(stderr).toContain('No audit record found');
  });

  it('exits 0 when record is found with valid signature', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const [uid] = await writeAuditFileWithSystemKey(logPath, [allowRecord()]);

    const { exitCode } = runValidateToken(['--request-id', uid!, '--audit-log', logPath]);
    expect(exitCode).toBe(0);
  });

  it('stdout contains "Audit record found" on success', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const [uid] = await writeAuditFileWithSystemKey(logPath, [allowRecord()]);

    const { stdout } = runValidateToken(['--request-id', uid!, '--audit-log', logPath]);
    expect(stdout).toContain('Audit record found');
  });

  it('stdout contains the request ID on success', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const [uid] = await writeAuditFileWithSystemKey(logPath, [allowRecord()]);

    const { stdout } = runValidateToken(['--request-id', uid!, '--audit-log', logPath]);
    expect(stdout).toContain(uid!);
  });

  it('stdout contains the tool name on success', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const [uid] = await writeAuditFileWithSystemKey(logPath, [
      allowRecord({ toolName: 'my_special_tool' }),
    ]);

    const { stdout } = runValidateToken(['--request-id', uid!, '--audit-log', logPath]);
    expect(stdout).toContain('my_special_tool');
  });

  it('stdout contains the session ID on success', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const [uid] = await writeAuditFileWithSystemKey(logPath, [
      allowRecord({ sessionId: 'my-unique-session-id' }),
    ]);

    const { stdout } = runValidateToken(['--request-id', uid!, '--audit-log', logPath]);
    expect(stdout).toContain('my-unique-session-id');
  });

  it('stdout contains "allow" for allow decisions', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const [uid] = await writeAuditFileWithSystemKey(logPath, [allowRecord()]);

    const { stdout } = runValidateToken(['--request-id', uid!, '--audit-log', logPath]);
    expect(stdout.toLowerCase()).toContain('allow');
  });

  it('stdout contains "deny" for deny decisions', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const [uid] = await writeAuditFileWithSystemKey(logPath, [denyRecord()]);

    const { stdout } = runValidateToken(['--request-id', uid!, '--audit-log', logPath]);
    expect(stdout.toLowerCase()).toContain('deny');
  });

  it('stdout contains the denialCode for deny decisions', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const [uid] = await writeAuditFileWithSystemKey(logPath, [
      denyRecord({ denialCode: 'TIME_WINDOW_DENIED' }),
    ]);

    const { stdout } = runValidateToken(['--request-id', uid!, '--audit-log', logPath]);
    expect(stdout).toContain('TIME_WINDOW_DENIED');
  });

  it('exits 2 when the record signature is tampered', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const [uid] = await writeAuditFileWithSystemKey(logPath, [allowRecord()]);

    // Tamper with the log
    const raw = fs.readFileSync(logPath, 'utf8');
    fs.writeFileSync(logPath, raw.replace('"Success"', '"Failure"'));

    const { exitCode } = runValidateToken(['--request-id', uid!, '--audit-log', logPath]);
    expect(exitCode).toBe(2);
  });

  it('exit 2 output shows "✗ INVALID" in stdout', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const [uid] = await writeAuditFileWithSystemKey(logPath, [allowRecord()]);

    const raw = fs.readFileSync(logPath, 'utf8');
    fs.writeFileSync(logPath, raw.replace('"Success"', '"Failure"'));

    const { stdout } = runValidateToken(['--request-id', uid!, '--audit-log', logPath]);
    expect(stdout).toContain('INVALID');
  });
});

// ---------------------------------------------------------------------------
// --since mode
// ---------------------------------------------------------------------------

describe('validate-token --since', () => {
  it('exits 0 when audit log does not exist', () => {
    const dir = makeTempDir();
    const { exitCode } = runValidateToken([
      '--since', '2020-01-01T00:00:00Z',
      '--audit-log', path.join(dir, 'audit.jsonl'),
    ]);
    expect(exitCode).toBe(0);
  });

  it('exits 0 and produces no stdout when log does not exist', () => {
    const dir = makeTempDir();
    const { stdout } = runValidateToken([
      '--since', '2020-01-01T00:00:00Z',
      '--audit-log', path.join(dir, 'audit.jsonl'),
    ]);
    expect(stdout.trim()).toBe('');
  });

  it('exits 0 and prints summary lines for matching records', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    await writeAuditFileWithSystemKey(logPath, [allowRecord(), denyRecord()]);

    const { exitCode, stdout } = runValidateToken([
      '--since', '2020-01-01T00:00:00Z',
      '--audit-log', logPath,
    ]);
    expect(exitCode).toBe(0);
    const lines = stdout.trim().split('\n').filter(Boolean);
    expect(lines.length).toBeGreaterThanOrEqual(2);
  });

  it('summary line contains "[allow]" for allow decisions', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    await writeAuditFileWithSystemKey(logPath, [allowRecord({ toolName: 'list_files' })]);

    const { stdout } = runValidateToken([
      '--since', '2020-01-01T00:00:00Z',
      '--audit-log', logPath,
    ]);
    expect(stdout).toContain('[allow]');
  });

  it('summary line contains "[DENY ]" for deny decisions', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    await writeAuditFileWithSystemKey(logPath, [denyRecord({ toolName: 'query_db' })]);

    const { stdout } = runValidateToken([
      '--since', '2020-01-01T00:00:00Z',
      '--audit-log', logPath,
    ]);
    expect(stdout).toContain('[DENY ]');
  });

  it('exits 0 and produces no output when --since is in the far future', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    await writeAuditFileWithSystemKey(logPath, [allowRecord()]);

    const { exitCode, stdout } = runValidateToken([
      '--since', '2099-01-01T00:00:00Z',
      '--audit-log', logPath,
    ]);
    expect(exitCode).toBe(0);
    expect(stdout.trim()).toBe('');
  });

  it('exits 1 when --since value is not a valid ISO-8601 timestamp', () => {
    const { exitCode } = runValidateToken(['--since', 'not-a-date']);
    expect(exitCode).toBe(1);
  });

  it('stderr contains error message for invalid --since value', () => {
    const { stderr } = runValidateToken(['--since', 'not-a-date']);
    expect(stderr.toLowerCase()).toMatch(/invalid|--since/);
  });
});

// ---------------------------------------------------------------------------
// --audit-log (custom path)
// ---------------------------------------------------------------------------

describe('validate-token --audit-log (custom path)', () => {
  it('reads from the custom --audit-log path', async () => {
    const dir = makeTempDir();
    const customPath = path.join(dir, 'my-custom-audit.jsonl');
    const [uid] = await writeAuditFileWithSystemKey(customPath, [allowRecord()]);

    const { exitCode } = runValidateToken(['--request-id', uid!, '--audit-log', customPath]);
    expect(exitCode).toBe(0);
  });

  it('exits 1 for --request-id when custom path has no files', () => {
    const dir = makeTempDir();
    const { exitCode } = runValidateToken([
      '--request-id', 'anything',
      '--audit-log', path.join(dir, 'nonexistent-custom.jsonl'),
    ]);
    expect(exitCode).toBe(1);
  });
});
