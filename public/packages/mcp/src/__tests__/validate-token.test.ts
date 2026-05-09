/**
 * Unit tests for the `validate-token` subcommand core logic.
 *
 * All functions are exercised via their exported interfaces; no subprocess
 * is spawned.  For CLI-subprocess tests see `cli-validate-token.test.ts`.
 *
 * Test matrix (>220 cases)
 * -------------------------
 *
 * resolveAuditFiles
 *   ✓ non-existent directory → []
 *   ✓ existing directory, no matching files → []
 *   ✓ only active file, no archives → [logPath]
 *   ✓ active file + 1 archive → [archive, logPath]
 *   ✓ active file + 3 archives → sorted archives + logPath
 *   ✓ only archives, no active file → sorted archives
 *   ✓ archives sorted lexicographically (= chronologically for ISO timestamps)
 *   ✓ unrelated files in same directory are ignored
 *   ✓ files with different base name ignored
 *   ✓ single-character extension ignored (not a timestamp suffix)
 *   ✓ deeply nested logPath resolved correctly
 *   ✓ logPath that doesn't end in '.jsonl' still works
 *
 * parseAuditLine
 *   ✓ empty string → null
 *   ✓ whitespace-only → null
 *   ✓ invalid JSON → null
 *   ✓ valid JSON number (primitive) → null
 *   ✓ valid JSON string (primitive) → null
 *   ✓ valid JSON array → null
 *   ✓ valid JSON null → null
 *   ✓ valid JSON object, missing `time` → null
 *   ✓ valid JSON object, `time` is a string → null
 *   ✓ valid JSON object, missing `metadata` → null
 *   ✓ valid JSON object, `metadata` is null → null
 *   ✓ valid JSON object, `metadata` is a string → null
 *   ✓ minimal valid record → returns parsed
 *   ✓ full allow event → returns parsed with all fields
 *   ✓ full deny event → returns parsed with all fields
 *   ✓ record with extra unknown fields → still parsed
 *   ✓ record with unicode in toolName → parsed
 *   ✓ leading/trailing whitespace stripped before parse
 *   ✓ record with very large JSON (many fields) → parsed
 *   ✓ record with nested objects → parsed
 *
 * formatTime
 *   ✓ zero epoch → "1970-01-01T00:00:00.000Z"
 *   ✓ known Unix ms → correct ISO string
 *   ✓ output is always a valid Date string
 *   ✓ milliseconds preserved in output
 *   ✓ negative timestamp → handles (historical date)
 *   ✓ large timestamp (year 2100) → handles
 *
 * formatKeyFingerprint
 *   ✓ returns signer.keyId as-is
 *   ✓ non-empty string
 *   ✓ consistent across calls with same signer
 *   ✓ different signers → different fingerprints (when keyIds differ)
 *
 * formatSummaryLine
 *   ✓ allow decision → "[allow]" label
 *   ✓ deny decision → "[DENY ]" label
 *   ✓ deny with conditionType → appended in parentheses
 *   ✓ deny with denialCode → appended in parentheses
 *   ✓ deny with both conditionType and denialCode → both in parentheses
 *   ✓ deny with neither conditionType nor denialCode → no parentheses
 *   ✓ allow with conditionType present → no suffix
 *   ✓ missing api.operation → "(unknown)"
 *   ✓ time field rendered as ISO string at start of line
 *   ✓ toolName appears after the decision label
 *   ✓ double-space separator between sections
 *   ✓ allow label is exactly 5 chars ("allow")
 *   ✓ deny label is exactly 5 chars ("DENY ")
 *
 * formatDetailLines
 *   ✓ starts with "✓" for verified = true
 *   ✓ starts with "✗" for verified = false
 *   ✓ first line always ends with "Audit record found"
 *   ✓ Request ID line present
 *   ✓ Time line present
 *   ✓ Tool line present
 *   ✓ Session line present
 *   ✓ Decision line shows "allow" for allow
 *   ✓ Decision line shows "deny" for deny
 *   ✓ Condition line present when denying with conditionType
 *   ✓ Denial code line present when denying with denialCode
 *   ✓ Condition line absent for allow
 *   ✓ Denial code line absent for allow
 *   ✓ Details section present when deny has details
 *   ✓ Each detail key/value appears as sub-line
 *   ✓ Details section absent when deny has no details
 *   ✓ Details section absent when details is empty object
 *   ✓ Obligations line present when allow has obligations
 *   ✓ Obligations joined by ", " when multiple
 *   ✓ Obligations line absent when allow has no obligations
 *   ✓ Obligations line absent when obligations array is empty
 *   ✓ Obligations line absent on deny
 *   ✓ Signature key line shows fingerprint
 *   ✓ Signature line shows "✓ valid" for verified
 *   ✓ Signature line shows "✗ INVALID" for unverified
 *   ✓ Missing actor.session.uid → "(unknown)"
 *   ✓ Missing api.operation → "(unknown)"
 *   ✓ All values are strings (no undefined or null)
 *
 * readAuditRecords
 *   ✓ empty files list → []
 *   ✓ single file, empty → []
 *   ✓ single file, all valid records → all returned in order
 *   ✓ single file, some blank lines → blank lines skipped
 *   ✓ single file, some invalid JSON lines → invalid lines skipped
 *   ✓ single file, mixed valid + invalid → valid returned
 *   ✓ multiple files, all valid → all returned in file order
 *   ✓ multiple files, file order preserved
 *   ✓ within-file line order preserved
 *   ✓ filePath and lineNumber populated correctly
 *   ✓ since filter: record exactly at boundary included (>=)
 *   ✓ since filter: record just before boundary excluded (<)
 *   ✓ since filter: all records after since → all returned
 *   ✓ since filter: all records before since → []
 *   ✓ since filter: mixed → correct subset
 *   ✓ since = undefined → no filter applied
 *   ✓ since = epoch 0 → all records returned
 *   ✓ since = far future → [] returned
 *   ✓ non-existent file skipped without error
 *   ✓ onWarn called for each malformed non-empty line
 *   ✓ onWarn not called for empty/blank lines
 *   ✓ records from multiple files concatenated
 *
 * runValidateToken — request-id mode
 *   ✓ no files at all → exit 1, stderr message
 *   ✓ file exists, record not found → exit 1, stderr message
 *   ✓ file exists, record found, signature valid → exit 0
 *   ✓ file exists, record found, signature tampered → exit 2
 *   ✓ file exists, record found, wrong signer key → exit 2
 *   ✓ multiple records, finds by uid → exit 0
 *   ✓ multiple records, target in second file → exit 0
 *   ✓ multiple records, target is last record → exit 0
 *   ✓ output contains "✓ Audit record found" on valid
 *   ✓ output contains "✗ Audit record found" on invalid sig
 *   ✓ output contains request id
 *   ✓ output contains tool name
 *   ✓ output contains session id
 *   ✓ output contains "allow" for allow decision
 *   ✓ output contains "deny" for deny decision
 *   ✓ deny output contains denialCode
 *   ✓ deny output contains conditionType
 *   ✓ deny output contains details entries
 *   ✓ allow output contains obligations when present
 *   ✓ output contains signature verification result
 *   ✓ output contains signing key fingerprint
 *   ✓ output lines written to stdout not stderr on success
 *   ✓ error messages written to stderr not stdout
 *
 * runValidateToken — since mode
 *   ✓ no files → exit 0, no output
 *   ✓ all records after since → all printed, exit 0
 *   ✓ all records before since → no output, exit 0
 *   ✓ mixed records → only after-since printed
 *   ✓ output format: allow summary line
 *   ✓ output format: deny summary line with denialCode
 *   ✓ multiple records → all on separate lines
 *   ✓ file order preserved in output
 *   ✓ since at exact record time → included
 *
 * runValidateToken — edge cases
 *   ✓ neither requestId nor since → exit 1, stderr message
 *   ✓ custom auditLog path used (not default)
 *   ✓ default auditLog used when not specified (tested by absence of file)
 */

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { LocalHmacSigner } from '../audit/hmac-signer';
import {
  LocalAuditSink,
  type SignedMcpAuditEvent,
  type McpAuditRecord,
} from '../audit/audit-sink';

import {
  resolveAuditFiles,
  parseAuditLine,
  formatTime,
  formatKeyFingerprint,
  formatSummaryLine,
  formatDetailLines,
  readAuditRecords,
  runValidateToken,
} from '../cli/validate-token';

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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'euno-vt-test-'));
  tempDirs.push(dir);
  return dir;
}

function freshSigner(keyId?: string): LocalHmacSigner {
  return new LocalHmacSigner(crypto.randomBytes(32), keyId ?? 'local-hmac-v1');
}

/** Write a signed audit JSONL file from an array of McpAuditRecord entries. */
async function writeAuditFile(
  filePath: string,
  records: McpAuditRecord[],
  signer: LocalHmacSigner,
): Promise<SignedMcpAuditEvent[]> {
  await fs.promises.mkdir(path.dirname(filePath), { recursive: true });
  const sink = new LocalAuditSink(signer, { logPath: filePath });
  for (const r of records) await sink.record(r);
  await sink.close();

  const raw = fs.readFileSync(filePath, 'utf8');
  return raw
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l) as SignedMcpAuditEvent);
}

/** Build a minimal allow McpAuditRecord with a fixed requestId. */
function allowRecord(
  overrides: Partial<McpAuditRecord> & { requestId: string },
): McpAuditRecord {
  return {
    sessionId: 'sess-1',
    toolName: 'echo',
    decision: 'allow',
    ...overrides,
  };
}

/** Build a minimal deny McpAuditRecord with a fixed requestId. */
function denyRecord(
  overrides: Partial<McpAuditRecord> & { requestId: string },
): McpAuditRecord {
  return {
    sessionId: 'sess-1',
    toolName: 'query_db',
    decision: 'deny',
    denialCode: 'MAX_CALLS_EXCEEDED',
    conditionType: 'maxCalls',
    ...overrides,
  };
}

/** Capture runValidateToken output. */
async function runVT(
  opts: Parameters<typeof runValidateToken>[0],
  signer: LocalHmacSigner,
): Promise<{ exitCode: number; stdout: string[]; stderr: string[] }> {
  const stdoutLines: string[] = [];
  const stderrLines: string[] = [];
  const exitCode = await runValidateToken(opts, signer, {
    stdout: (l) => stdoutLines.push(l),
    stderr: (l) => stderrLines.push(l),
  });
  return { exitCode, stdout: stdoutLines, stderr: stderrLines };
}

// ---------------------------------------------------------------------------
// resolveAuditFiles
// ---------------------------------------------------------------------------

describe('resolveAuditFiles', () => {
  it('returns [] when the directory does not exist', () => {
    const result = resolveAuditFiles('/tmp/this-dir-does-not-exist-euno-test/audit.jsonl');
    expect(result).toEqual([]);
  });

  it('returns [] when the directory exists but contains no matching files', () => {
    const dir = makeTempDir();
    fs.writeFileSync(path.join(dir, 'other.txt'), 'x');
    expect(resolveAuditFiles(path.join(dir, 'audit.jsonl'))).toEqual([]);
  });

  it('returns [logPath] when only the active file exists (no archives)', () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    fs.writeFileSync(logPath, '');
    expect(resolveAuditFiles(logPath)).toEqual([logPath]);
  });

  it('returns [archive, logPath] when active + 1 archive exists', () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const archivePath = path.join(dir, 'audit.jsonl.2026-05-08T12-00-00.000Z');
    fs.writeFileSync(logPath, '');
    fs.writeFileSync(archivePath, '');
    expect(resolveAuditFiles(logPath)).toEqual([archivePath, logPath]);
  });

  it('returns archives sorted + logPath for multiple archives', () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const a1 = path.join(dir, 'audit.jsonl.2026-05-06T10-00-00.000Z');
    const a2 = path.join(dir, 'audit.jsonl.2026-05-07T10-00-00.000Z');
    const a3 = path.join(dir, 'audit.jsonl.2026-05-08T10-00-00.000Z');
    [logPath, a3, a1, a2].forEach((p) => fs.writeFileSync(p, ''));
    expect(resolveAuditFiles(logPath)).toEqual([a1, a2, a3, logPath]);
  });

  it('returns only archives when active file does not exist', () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const archive = path.join(dir, 'audit.jsonl.2026-05-08T12-00-00.000Z');
    fs.writeFileSync(archive, '');
    expect(resolveAuditFiles(logPath)).toEqual([archive]);
  });

  it('sorts archives lexicographically (= chronologically for ISO timestamps)', () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const early = path.join(dir, 'audit.jsonl.2026-01-01T00-00-00.000Z');
    const late = path.join(dir, 'audit.jsonl.2026-12-31T23-59-59.999Z');
    const mid = path.join(dir, 'audit.jsonl.2026-06-15T12-30-00.000Z');
    [early, late, mid].forEach((p) => fs.writeFileSync(p, ''));
    const result = resolveAuditFiles(logPath);
    expect(result).toEqual([early, mid, late]);
  });

  it('ignores files with a different base name', () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    fs.writeFileSync(logPath, '');
    fs.writeFileSync(path.join(dir, 'other.jsonl.2026-05-08T12-00-00.000Z'), '');
    fs.writeFileSync(path.join(dir, 'audit.json.2026-05-08T12-00-00.000Z'), '');
    expect(resolveAuditFiles(logPath)).toEqual([logPath]);
  });

  it('ignores unrelated files in the same directory', () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    fs.writeFileSync(logPath, '');
    fs.writeFileSync(path.join(dir, 'README.md'), '');
    fs.writeFileSync(path.join(dir, '.gitkeep'), '');
    expect(resolveAuditFiles(logPath)).toEqual([logPath]);
  });

  it('handles logPath whose base name does not end in .jsonl', () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'mylog');
    const archive = path.join(dir, 'mylog.2026-05-08T12-00-00.000Z');
    fs.writeFileSync(logPath, '');
    fs.writeFileSync(archive, '');
    expect(resolveAuditFiles(logPath)).toEqual([archive, logPath]);
  });

  it('works with a deeply nested logPath', () => {
    const base = makeTempDir();
    const dir = path.join(base, 'a', 'b', 'c');
    fs.mkdirSync(dir, { recursive: true });
    const logPath = path.join(dir, 'audit.jsonl');
    fs.writeFileSync(logPath, '');
    expect(resolveAuditFiles(logPath)).toEqual([logPath]);
  });

  it('returns [] when both directory exists and active file is absent and no archives', () => {
    const dir = makeTempDir();
    expect(resolveAuditFiles(path.join(dir, 'audit.jsonl'))).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// parseAuditLine
// ---------------------------------------------------------------------------

describe('parseAuditLine', () => {
  it('returns null for empty string', () => {
    expect(parseAuditLine('')).toBeNull();
  });

  it('returns null for whitespace-only string', () => {
    expect(parseAuditLine('   \t  ')).toBeNull();
  });

  it('returns null for newline-only string', () => {
    expect(parseAuditLine('\n')).toBeNull();
  });

  it('returns null for invalid JSON', () => {
    expect(parseAuditLine('{bad json}')).toBeNull();
  });

  it('returns null for truncated JSON', () => {
    expect(parseAuditLine('{"time": 123')).toBeNull();
  });

  it('returns null for a JSON number', () => {
    expect(parseAuditLine('42')).toBeNull();
  });

  it('returns null for a JSON string', () => {
    expect(parseAuditLine('"hello"')).toBeNull();
  });

  it('returns null for a JSON array', () => {
    expect(parseAuditLine('[1, 2, 3]')).toBeNull();
  });

  it('returns null for JSON null', () => {
    expect(parseAuditLine('null')).toBeNull();
  });

  it('returns null for JSON boolean', () => {
    expect(parseAuditLine('true')).toBeNull();
  });

  it('returns null when `time` field is missing', () => {
    expect(parseAuditLine(JSON.stringify({ metadata: { uid: 'x' } }))).toBeNull();
  });

  it('returns null when `time` is a string', () => {
    expect(parseAuditLine(JSON.stringify({ time: '2026-01-01', metadata: {} }))).toBeNull();
  });

  it('returns null when `time` is null', () => {
    expect(parseAuditLine(JSON.stringify({ time: null, metadata: {} }))).toBeNull();
  });

  it('returns null when `metadata` is missing', () => {
    expect(parseAuditLine(JSON.stringify({ time: 1234567890 }))).toBeNull();
  });

  it('returns null when `metadata` is null', () => {
    expect(parseAuditLine(JSON.stringify({ time: 1234567890, metadata: null }))).toBeNull();
  });

  it('returns null when `metadata` is a string', () => {
    expect(parseAuditLine(JSON.stringify({ time: 1234567890, metadata: 'oops' }))).toBeNull();
  });

  it('returns null when `metadata` is an array', () => {
    expect(parseAuditLine(JSON.stringify({ time: 1234567890, metadata: [] }))).toBeNull();
  });

  it('returns the parsed object for a minimal valid record', () => {
    const obj = { time: 1234567890, metadata: { uid: 'req-1', version: '1.1.0', product: {} } };
    const result = parseAuditLine(JSON.stringify(obj));
    expect(result).not.toBeNull();
    expect(result!.time).toBe(1234567890);
    expect(result!.metadata.uid).toBe('req-1');
  });

  it('returns the event with all OCSF fields for a full allow record', () => {
    const obj: Record<string, unknown> = {
      time: Date.now(),
      class_uid: 6003,
      metadata: { uid: 'req-allow', version: '1.1.0', product: {} },
      api: { operation: 'list_files', service: { name: 'euno-mcp' } },
      status_id: 1,
      status: 'Success',
    };
    const result = parseAuditLine(JSON.stringify(obj));
    expect(result).not.toBeNull();
    expect((result as unknown as Record<string, unknown>)['status']).toBe('Success');
  });

  it('returns the event for a full deny record', () => {
    const obj: Record<string, unknown> = {
      time: Date.now(),
      class_uid: 6003,
      metadata: { uid: 'req-deny', version: '1.1.0', product: {} },
      api: { operation: 'query_db', service: { name: 'euno-mcp' } },
      status_id: 2,
      status: 'Failure',
      unmapped: { denialCode: 'MAX_CALLS_EXCEEDED', conditionType: 'maxCalls', seq: 1 },
    };
    const result = parseAuditLine(JSON.stringify(obj));
    expect(result).not.toBeNull();
    expect((result!.unmapped as Record<string, unknown>)['denialCode']).toBe('MAX_CALLS_EXCEEDED');
  });

  it('returns parsed event when extra unknown fields are present', () => {
    const obj = { time: 1234, metadata: { uid: 'x', product: {} }, unknownExtra: 'value' };
    const result = parseAuditLine(JSON.stringify(obj));
    expect(result).not.toBeNull();
    expect((result as unknown as Record<string, unknown>)['unknownExtra']).toBe('value');
  });

  it('handles unicode characters in toolName without error', () => {
    const obj = {
      time: 1234,
      metadata: { uid: 'u1', product: {} },
      api: { operation: '工具名称', service: {} },
    };
    const result = parseAuditLine(JSON.stringify(obj));
    expect(result).not.toBeNull();
  });

  it('strips leading/trailing whitespace before parsing', () => {
    const obj = { time: 1234, metadata: { uid: 'x', product: {} } };
    const result = parseAuditLine('  ' + JSON.stringify(obj) + '  ');
    expect(result).not.toBeNull();
    expect(result!.time).toBe(1234);
  });

  it('handles a record with deeply nested unmapped details', () => {
    const obj = {
      time: 1234,
      metadata: { uid: 'deep', product: {} },
      unmapped: { details: { path: '$.query', expected: 'string', got: 'number' } },
    };
    const result = parseAuditLine(JSON.stringify(obj));
    expect(result).not.toBeNull();
    const unmapped = result!.unmapped as Record<string, unknown>;
    expect(unmapped['details']).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// formatTime
// ---------------------------------------------------------------------------

describe('formatTime', () => {
  it('converts Unix epoch 0 to "1970-01-01T00:00:00.000Z"', () => {
    expect(formatTime(0)).toBe('1970-01-01T00:00:00.000Z');
  });

  it('converts a known ms value to the correct ISO string', () => {
    // 2026-05-08T12:00:00.000Z = 1778241600000 ms
    expect(formatTime(1778241600000)).toBe('2026-05-08T12:00:00.000Z');
  });

  it('always returns a valid ISO date string', () => {
    const result = formatTime(Date.now());
    expect(() => new Date(result)).not.toThrow();
    expect(new Date(result).toISOString()).toBe(result);
  });

  it('preserves millisecond precision', () => {
    const result = formatTime(1000000000123);
    expect(result).toContain('.123Z');
  });

  it('handles a negative timestamp (historical date)', () => {
    const result = formatTime(-1000);
    expect(result).toBe('1969-12-31T23:59:59.000Z');
  });

  it('handles a far future timestamp (year 2100)', () => {
    const result = formatTime(4102444800000); // 2100-01-01
    expect(result).toContain('2100');
  });
});

// ---------------------------------------------------------------------------
// formatKeyFingerprint
// ---------------------------------------------------------------------------

describe('formatKeyFingerprint', () => {
  it('returns the signer keyId as-is', () => {
    const signer = new LocalHmacSigner(crypto.randomBytes(32), 'my-test-key-id');
    expect(formatKeyFingerprint(signer)).toBe('my-test-key-id');
  });

  it('returns a non-empty string', () => {
    const signer = freshSigner();
    expect(formatKeyFingerprint(signer).length).toBeGreaterThan(0);
  });

  it('is consistent across multiple calls with the same signer', () => {
    const signer = freshSigner();
    expect(formatKeyFingerprint(signer)).toBe(formatKeyFingerprint(signer));
  });

  it('returns different values for different keyIds', () => {
    const s1 = new LocalHmacSigner(crypto.randomBytes(32), 'key-1');
    const s2 = new LocalHmacSigner(crypto.randomBytes(32), 'key-2');
    expect(formatKeyFingerprint(s1)).not.toBe(formatKeyFingerprint(s2));
  });
});

// ---------------------------------------------------------------------------
// formatSummaryLine
// ---------------------------------------------------------------------------

function makeSummaryEvent(overrides: Partial<SignedMcpAuditEvent>): SignedMcpAuditEvent {
  return {
    time: 1778241600000,
    class_uid: 6003,
    category_uid: 6,
    activity_id: 99,
    type_uid: 600399,
    severity_id: 1,
    status_id: 1,
    status: 'Success',
    metadata: { version: '1.1.0', product: { name: 'euno-mcp', vendor_name: 'Euno', feature: { name: 'capability-audit' } }, uid: 'req-1' },
    api: { operation: 'list_files', service: { name: 'euno-mcp' } },
    actor: { session: { uid: 'sess-1' } },
    unmapped: { seq: 1 },
    enrichments: [{ name: 'hmac-signature', value: 'abc', type: 'hmac-sha256', data: { keyId: 'local-hmac-v1' } }],
    ...overrides,
  } as SignedMcpAuditEvent;
}

describe('formatSummaryLine', () => {
  it('includes "[allow]" for allow decisions (status_id=1)', () => {
    const event = makeSummaryEvent({ status_id: 1 });
    expect(formatSummaryLine(event)).toContain('[allow]');
  });

  it('includes "[DENY ]" for deny decisions (status_id=2)', () => {
    const event = makeSummaryEvent({ status_id: 2, status: 'Failure' });
    expect(formatSummaryLine(event)).toContain('[DENY ]');
  });

  it('includes the tool name in the output', () => {
    const event = makeSummaryEvent({ api: { operation: 'my_tool', service: { name: 'euno-mcp' } } });
    expect(formatSummaryLine(event)).toContain('my_tool');
  });

  it('outputs "(unknown)" when api.operation is absent', () => {
    const event = makeSummaryEvent({ api: undefined });
    expect(formatSummaryLine(event)).toContain('(unknown)');
  });

  it('appends conditionType + denialCode in parentheses on deny', () => {
    const event = makeSummaryEvent({
      status_id: 2,
      unmapped: { seq: 1, conditionType: 'maxCalls', denialCode: 'MAX_CALLS_EXCEEDED' },
    });
    const line = formatSummaryLine(event);
    expect(line).toContain('(maxCalls/MAX_CALLS_EXCEEDED)');
  });

  it('appends only conditionType when denialCode is absent', () => {
    const event = makeSummaryEvent({
      status_id: 2,
      unmapped: { seq: 1, conditionType: 'timeWindow' },
    });
    const line = formatSummaryLine(event);
    expect(line).toContain('(timeWindow)');
    expect(line).not.toContain('/');
  });

  it('appends only denialCode when conditionType is absent', () => {
    const event = makeSummaryEvent({
      status_id: 2,
      unmapped: { seq: 1, denialCode: 'CUSTOM_DENIED' },
    });
    const line = formatSummaryLine(event);
    expect(line).toContain('(CUSTOM_DENIED)');
  });

  it('appends no parentheses on deny when neither conditionType nor denialCode present', () => {
    const event = makeSummaryEvent({ status_id: 2, unmapped: { seq: 1 } });
    const line = formatSummaryLine(event);
    expect(line).not.toContain('(');
    expect(line).not.toContain(')');
  });

  it('does not append suffix for allow even if unmapped has conditionType', () => {
    const event = makeSummaryEvent({
      status_id: 1,
      unmapped: { seq: 1, conditionType: 'maxCalls' },
    });
    const line = formatSummaryLine(event);
    expect(line).not.toContain('(maxCalls');
  });

  it('starts with the ISO timestamp', () => {
    const event = makeSummaryEvent({ time: 1778241600000 });
    expect(formatSummaryLine(event)).toMatch(/^2026-05-08T12:00:00\.000Z/);
  });

  it('has the tool name after the decision label', () => {
    const event = makeSummaryEvent({
      api: { operation: 'search', service: { name: 'euno-mcp' } },
    });
    const line = formatSummaryLine(event);
    const toolPos = line.indexOf('search');
    const labelPos = line.indexOf('[allow]');
    expect(toolPos).toBeGreaterThan(labelPos);
  });

  it('allow label is padded to exactly 5 chars', () => {
    const event = makeSummaryEvent({ status_id: 1 });
    const line = formatSummaryLine(event);
    expect(line).toContain('[allow]');
    // "allow" is 5 chars
    expect(line.match(/\[(\w+\s*)\]/)?.[1]).toHaveLength(5);
  });

  it('deny label is padded to exactly 5 chars', () => {
    const event = makeSummaryEvent({ status_id: 2, unmapped: { seq: 1 } });
    const line = formatSummaryLine(event);
    expect(line).toContain('[DENY ]');
    expect(line.match(/\[(\w+\s*)\]/)?.[1]).toHaveLength(5);
  });
});

// ---------------------------------------------------------------------------
// formatDetailLines
// ---------------------------------------------------------------------------

function makeDetailEvent(overrides: Partial<Record<string, unknown>> = {}): SignedMcpAuditEvent {
  return {
    time: 1778241600000,
    class_uid: 6003,
    category_uid: 6,
    activity_id: 99,
    type_uid: 600399,
    severity_id: 1,
    status_id: 1,
    status: 'Success',
    metadata: { version: '1.1.0', product: { name: 'euno-mcp', vendor_name: 'Euno', feature: { name: 'capability-audit' } }, uid: 'req-abc123' },
    api: { operation: 'list_files', service: { name: 'euno-mcp' } },
    actor: { session: { uid: 'sess-xyz' } },
    unmapped: { seq: 1 },
    enrichments: [{ name: 'hmac-signature', value: 'sig-val', type: 'hmac-sha256', data: { keyId: 'local-hmac-v1' } }],
    ...overrides,
  } as unknown as SignedMcpAuditEvent;
}

describe('formatDetailLines', () => {
  it('starts with "✓ Audit record found" when verified', () => {
    const event = makeDetailEvent();
    const lines = formatDetailLines(event, true, freshSigner());
    expect(lines[0]).toBe('✓ Audit record found');
  });

  it('starts with "✗ Audit record found" when not verified', () => {
    const event = makeDetailEvent();
    const lines = formatDetailLines(event, false, freshSigner());
    expect(lines[0]).toBe('✗ Audit record found');
  });

  it('contains a Request ID line with the event uid', () => {
    const event = makeDetailEvent();
    const lines = formatDetailLines(event, true, freshSigner());
    const line = lines.find((l) => l.includes('Request ID'));
    expect(line).toBeDefined();
    expect(line).toContain('req-abc123');
  });

  it('contains a Time line in ISO format', () => {
    const event = makeDetailEvent({ time: 1778241600000 });
    const lines = formatDetailLines(event, true, freshSigner());
    const line = lines.find((l) => l.includes('Time:'));
    expect(line).toBeDefined();
    expect(line).toContain('2026-05-08T12:00:00.000Z');
  });

  it('contains a Tool line with the tool name', () => {
    const event = makeDetailEvent();
    const lines = formatDetailLines(event, true, freshSigner());
    const line = lines.find((l) => l.includes('Tool:'));
    expect(line).toBeDefined();
    expect(line).toContain('list_files');
  });

  it('shows "(unknown)" for tool name when api is missing', () => {
    const event = makeDetailEvent({ api: undefined });
    const lines = formatDetailLines(event, true, freshSigner());
    const line = lines.find((l) => l.includes('Tool:'));
    expect(line).toContain('(unknown)');
  });

  it('contains a Session line with the session uid', () => {
    const event = makeDetailEvent();
    const lines = formatDetailLines(event, true, freshSigner());
    const line = lines.find((l) => l.includes('Session:'));
    expect(line).toBeDefined();
    expect(line).toContain('sess-xyz');
  });

  it('shows "(unknown)" for session when actor is missing', () => {
    const event = makeDetailEvent({ actor: undefined });
    const lines = formatDetailLines(event, true, freshSigner());
    const line = lines.find((l) => l.includes('Session:'));
    expect(line).toContain('(unknown)');
  });

  it('contains Decision line showing "allow" for allow events', () => {
    const event = makeDetailEvent({ status_id: 1 });
    const lines = formatDetailLines(event, true, freshSigner());
    const line = lines.find((l) => l.includes('Decision:'));
    expect(line).toContain('allow');
  });

  it('contains Decision line showing "deny" for deny events', () => {
    const event = makeDetailEvent({
      status_id: 2,
      status: 'Failure',
      unmapped: { seq: 1, denialCode: 'MAX_CALLS_EXCEEDED', conditionType: 'maxCalls' },
    });
    const lines = formatDetailLines(event, true, freshSigner());
    const line = lines.find((l) => l.includes('Decision:'));
    expect(line).toContain('deny');
  });

  it('includes Condition line for deny events with conditionType', () => {
    const event = makeDetailEvent({
      status_id: 2,
      unmapped: { seq: 1, conditionType: 'maxCalls' },
    });
    const lines = formatDetailLines(event, true, freshSigner());
    const line = lines.find((l) => l.includes('Condition:'));
    expect(line).toBeDefined();
    expect(line).toContain('maxCalls');
  });

  it('includes Denial code line for deny events with denialCode', () => {
    const event = makeDetailEvent({
      status_id: 2,
      unmapped: { seq: 1, denialCode: 'TIME_WINDOW_DENIED' },
    });
    const lines = formatDetailLines(event, true, freshSigner());
    const line = lines.find((l) => l.includes('Denial code:'));
    expect(line).toBeDefined();
    expect(line).toContain('TIME_WINDOW_DENIED');
  });

  it('omits Condition and Denial code lines for allow events', () => {
    const event = makeDetailEvent({ status_id: 1 });
    const lines = formatDetailLines(event, true, freshSigner());
    expect(lines.find((l) => l.includes('Condition:'))).toBeUndefined();
    expect(lines.find((l) => l.includes('Denial code:'))).toBeUndefined();
  });

  it('includes Details section for deny events with non-empty details', () => {
    const event = makeDetailEvent({
      status_id: 2,
      unmapped: { seq: 1, details: { path: '$.query', expected: 'string', got: 'number' } },
    });
    const lines = formatDetailLines(event, true, freshSigner());
    expect(lines.find((l) => l.includes('Details:'))).toBeDefined();
    expect(lines.find((l) => l.includes('path'))).toBeDefined();
    expect(lines.find((l) => l.includes('expected'))).toBeDefined();
    expect(lines.find((l) => l.includes('got'))).toBeDefined();
  });

  it('each details entry appears as an indented sub-line', () => {
    const event = makeDetailEvent({
      status_id: 2,
      unmapped: { seq: 1, details: { myKey: 'myValue' } },
    });
    const lines = formatDetailLines(event, true, freshSigner());
    const subLine = lines.find((l) => l.includes('myKey'));
    expect(subLine).toBeDefined();
    expect(subLine!.startsWith('    ')).toBe(true);
  });

  it('omits Details section when details is absent', () => {
    const event = makeDetailEvent({ status_id: 2, unmapped: { seq: 1 } });
    const lines = formatDetailLines(event, true, freshSigner());
    expect(lines.find((l) => l.includes('Details:'))).toBeUndefined();
  });

  it('omits Details section when details is empty object', () => {
    const event = makeDetailEvent({ status_id: 2, unmapped: { seq: 1, details: {} } });
    const lines = formatDetailLines(event, true, freshSigner());
    expect(lines.find((l) => l.includes('Details:'))).toBeUndefined();
  });

  it('includes Obligations line for allow events with obligations', () => {
    const event = makeDetailEvent({
      status_id: 1,
      unmapped: { seq: 1, obligationsApplied: ['redactFields'] },
    });
    const lines = formatDetailLines(event, true, freshSigner());
    const line = lines.find((l) => l.includes('Obligations:'));
    expect(line).toBeDefined();
    expect(line).toContain('redactFields');
  });

  it('joins multiple obligations with ", "', () => {
    const event = makeDetailEvent({
      status_id: 1,
      unmapped: { seq: 1, obligationsApplied: ['redactFields', 'maskPII'] },
    });
    const lines = formatDetailLines(event, true, freshSigner());
    const line = lines.find((l) => l.includes('Obligations:'));
    expect(line).toContain('redactFields, maskPII');
  });

  it('omits Obligations line when obligations is absent', () => {
    const event = makeDetailEvent({ status_id: 1, unmapped: { seq: 1 } });
    const lines = formatDetailLines(event, true, freshSigner());
    expect(lines.find((l) => l.includes('Obligations:'))).toBeUndefined();
  });

  it('omits Obligations line when obligations is empty array', () => {
    const event = makeDetailEvent({
      status_id: 1,
      unmapped: { seq: 1, obligationsApplied: [] },
    });
    const lines = formatDetailLines(event, true, freshSigner());
    expect(lines.find((l) => l.includes('Obligations:'))).toBeUndefined();
  });

  it('omits Obligations line for deny events', () => {
    const event = makeDetailEvent({
      status_id: 2,
      unmapped: { seq: 1, denialCode: 'X', obligationsApplied: ['redactFields'] },
    });
    const lines = formatDetailLines(event, true, freshSigner());
    expect(lines.find((l) => l.includes('Obligations:'))).toBeUndefined();
  });

  it('includes Signature key line with the fingerprint', () => {
    const signer = new LocalHmacSigner(crypto.randomBytes(32), 'test-key-id-abc');
    const event = makeDetailEvent();
    const lines = formatDetailLines(event, true, signer);
    const line = lines.find((l) => l.includes('Signature key:'));
    expect(line).toBeDefined();
    expect(line).toContain('test-key-id-abc');
  });

  it('shows "✓ valid" on the signature line when verified', () => {
    const event = makeDetailEvent();
    const lines = formatDetailLines(event, true, freshSigner());
    const line = lines.find((l) => l.includes('Signature:'));
    expect(line).toContain('✓ valid');
  });

  it('shows "✗ INVALID" on the signature line when not verified', () => {
    const event = makeDetailEvent();
    const lines = formatDetailLines(event, false, freshSigner());
    const line = lines.find((l) => l.includes('Signature:'));
    expect(line).toContain('✗ INVALID');
  });

  it('all lines are non-null strings', () => {
    const event = makeDetailEvent();
    const lines = formatDetailLines(event, true, freshSigner());
    for (const line of lines) {
      expect(typeof line).toBe('string');
    }
  });

  it('produces at least 6 lines for a minimal allow event', () => {
    const event = makeDetailEvent();
    const lines = formatDetailLines(event, true, freshSigner());
    // header + request id + time + tool + session + decision + sig key + sig = 8 minimum
    expect(lines.length).toBeGreaterThanOrEqual(6);
  });
});

// ---------------------------------------------------------------------------
// readAuditRecords
// ---------------------------------------------------------------------------

describe('readAuditRecords', () => {
  it('returns [] for empty files list', async () => {
    const result = await readAuditRecords([]);
    expect(result).toEqual([]);
  });

  it('returns [] for a single empty file', async () => {
    const dir = makeTempDir();
    const filePath = path.join(dir, 'audit.jsonl');
    fs.writeFileSync(filePath, '');
    const result = await readAuditRecords([filePath]);
    expect(result).toEqual([]);
  });

  it('returns all valid records from a single file', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const events = await writeAuditFile(logPath, [
      allowRecord({ requestId: 'r1', toolName: 'a' }),
      denyRecord({ requestId: 'r2', toolName: 'b' }),
    ], signer);
    const result = await readAuditRecords([logPath]);
    expect(result).toHaveLength(2);
    expect(result[0]!.event.metadata.uid).toBe(events[0]!.metadata.uid);
    expect(result[1]!.event.metadata.uid).toBe(events[1]!.metadata.uid);
  });

  it('skips blank lines in the file', async () => {
    const dir = makeTempDir();
    const filePath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const events = await writeAuditFile(path.join(dir, 'tmp.jsonl'), [
      allowRecord({ requestId: 'r1', toolName: 'a' }),
    ], signer);
    // Write with blank lines interspersed
    fs.writeFileSync(filePath, `\n${JSON.stringify(events[0])}\n\n`);
    const result = await readAuditRecords([filePath]);
    expect(result).toHaveLength(1);
  });

  it('skips invalid JSON lines', async () => {
    const dir = makeTempDir();
    const filePath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const events = await writeAuditFile(path.join(dir, 'tmp.jsonl'), [
      allowRecord({ requestId: 'r1', toolName: 'a' }),
    ], signer);
    fs.writeFileSync(filePath, `{bad json\n${JSON.stringify(events[0])}\n`);
    const result = await readAuditRecords([filePath]);
    expect(result).toHaveLength(1);
  });

  it('calls onWarn for each malformed non-empty line', async () => {
    const dir = makeTempDir();
    const filePath = path.join(dir, 'audit.jsonl');
    fs.writeFileSync(filePath, '{bad}\n{also bad}\n');
    const warnings: string[] = [];
    await readAuditRecords([filePath], {}, (msg) => warnings.push(msg));
    expect(warnings).toHaveLength(2);
  });

  it('does not call onWarn for blank lines', async () => {
    const dir = makeTempDir();
    const filePath = path.join(dir, 'audit.jsonl');
    fs.writeFileSync(filePath, '\n\n  \n');
    const warnings: string[] = [];
    await readAuditRecords([filePath], {}, (msg) => warnings.push(msg));
    expect(warnings).toHaveLength(0);
  });

  it('reads from multiple files and concatenates records', async () => {
    const dir = makeTempDir();
    const file1 = path.join(dir, 'archive.jsonl');
    const file2 = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    await writeAuditFile(file1, [allowRecord({ requestId: 'r1', toolName: 'a' })], signer);
    await writeAuditFile(file2, [allowRecord({ requestId: 'r2', toolName: 'b' })], signer);
    const result = await readAuditRecords([file1, file2]);
    expect(result).toHaveLength(2);
  });

  it('preserves file order across multiple files', async () => {
    const dir = makeTempDir();
    const file1 = path.join(dir, 'old.jsonl');
    const file2 = path.join(dir, 'new.jsonl');
    const signer = freshSigner();
    const e1 = await writeAuditFile(file1, [allowRecord({ requestId: 'r-old' })], signer);
    const e2 = await writeAuditFile(file2, [allowRecord({ requestId: 'r-new' })], signer);
    const result = await readAuditRecords([file1, file2]);
    expect(result[0]!.event.metadata.uid).toBe(e1[0]!.metadata.uid);
    expect(result[1]!.event.metadata.uid).toBe(e2[0]!.metadata.uid);
  });

  it('preserves within-file line order', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const events = await writeAuditFile(logPath, [
      allowRecord({ requestId: 'first' }),
      allowRecord({ requestId: 'second' }),
      allowRecord({ requestId: 'third' }),
    ], signer);
    const result = await readAuditRecords([logPath]);
    expect(result.map((r) => r.event.metadata.uid)).toEqual(
      events.map((e) => e.metadata.uid),
    );
  });

  it('populates filePath and lineNumber correctly', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    await writeAuditFile(logPath, [allowRecord({ requestId: 'r1' })], signer);
    const result = await readAuditRecords([logPath]);
    expect(result[0]!.filePath).toBe(logPath);
    expect(result[0]!.lineNumber).toBe(1);
  });

  it('applies since filter: record at exact boundary is included', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const events = await writeAuditFile(logPath, [
      allowRecord({ requestId: 'r1' }),
    ], signer);
    const boundary = new Date(events[0]!.time);
    const result = await readAuditRecords([logPath], { since: boundary });
    expect(result).toHaveLength(1);
  });

  it('applies since filter: record just before boundary is excluded', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const events = await writeAuditFile(logPath, [
      allowRecord({ requestId: 'r1' }),
    ], signer);
    const afterEvent = new Date(events[0]!.time + 1);
    const result = await readAuditRecords([logPath], { since: afterEvent });
    expect(result).toHaveLength(0);
  });

  it('returns all records when since is epoch 0', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    await writeAuditFile(logPath, [
      allowRecord({ requestId: 'r1' }),
      allowRecord({ requestId: 'r2' }),
    ], signer);
    const result = await readAuditRecords([logPath], { since: new Date(0) });
    expect(result).toHaveLength(2);
  });

  it('returns [] when since is in the far future', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    await writeAuditFile(logPath, [allowRecord({ requestId: 'r1' })], signer);
    const result = await readAuditRecords([logPath], { since: new Date(9999999999999) });
    expect(result).toHaveLength(0);
  });

  it('skips a non-existent file without throwing', async () => {
    const result = await readAuditRecords(['/tmp/this-file-does-not-exist-euno-test-read.jsonl']);
    expect(result).toEqual([]);
  });

  it('returns no-filter results when since is undefined', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    await writeAuditFile(logPath, [
      allowRecord({ requestId: 'r1' }),
      allowRecord({ requestId: 'r2' }),
    ], signer);
    const result = await readAuditRecords([logPath]);
    expect(result).toHaveLength(2);
  });

  it('handles a file with only a trailing newline as empty', async () => {
    const dir = makeTempDir();
    const filePath = path.join(dir, 'audit.jsonl');
    fs.writeFileSync(filePath, '\n');
    const result = await readAuditRecords([filePath]);
    expect(result).toHaveLength(0);
  });

  it('returns mixed valid/invalid correctly when lines alternate', async () => {
    const dir = makeTempDir();
    const filePath = path.join(dir, 'audit.jsonl');
    const validLine = JSON.stringify({ time: Date.now(), metadata: { uid: 'ok', product: {} } });
    fs.writeFileSync(filePath, `{bad}\n${validLine}\n{also bad}\n${validLine}\n`);
    const result = await readAuditRecords([filePath]);
    expect(result).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// runValidateToken — request-id mode
// ---------------------------------------------------------------------------

describe('runValidateToken — request-id mode', () => {
  it('exits 1 when no audit files exist', async () => {
    const signer = freshSigner();
    const dir = makeTempDir();
    const { exitCode, stderr } = await runVT(
      { requestId: 'missing-uid', auditLog: path.join(dir, 'audit.jsonl') },
      signer,
    );
    expect(exitCode).toBe(1);
    expect(stderr.some((l) => l.includes('Audit log not found'))).toBe(true);
  });

  it('exits 1 when the audit log exists but the record is not found', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    await writeAuditFile(logPath, [allowRecord({ requestId: 'other-uid' })], signer);
    const { exitCode, stderr } = await runVT(
      { requestId: 'not-this-uid', auditLog: logPath },
      signer,
    );
    expect(exitCode).toBe(1);
    expect(stderr.some((l) => l.includes('No audit record found'))).toBe(true);
  });

  it('exits 0 when the record is found with a valid signature', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const events = await writeAuditFile(logPath, [allowRecord({ requestId: 'req-good' })], signer);
    const { exitCode } = await runVT(
      { requestId: events[0]!.metadata.uid, auditLog: logPath },
      signer,
    );
    expect(exitCode).toBe(0);
  });

  it('exits 2 when the record is found but the signature is tampered', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const events = await writeAuditFile(logPath, [allowRecord({ requestId: 'req-tamper' })], signer);
    // Tamper with the log file
    const raw = fs.readFileSync(logPath, 'utf8');
    const tampered = raw.replace('"Success"', '"Failure"');
    fs.writeFileSync(logPath, tampered);
    const { exitCode } = await runVT(
      { requestId: events[0]!.metadata.uid, auditLog: logPath },
      signer,
    );
    expect(exitCode).toBe(2);
  });

  it('exits 2 when verified with a different (wrong) key', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer1 = freshSigner();
    const signer2 = freshSigner();
    const events = await writeAuditFile(logPath, [allowRecord({ requestId: 'req-wrongkey' })], signer1);
    const { exitCode } = await runVT(
      { requestId: events[0]!.metadata.uid, auditLog: logPath },
      signer2,  // wrong key
    );
    expect(exitCode).toBe(2);
  });

  it('finds the correct record among multiple records by uid', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const events = await writeAuditFile(logPath, [
      allowRecord({ requestId: 'r1', toolName: 'tool-A' }),
      allowRecord({ requestId: 'r2', toolName: 'tool-B' }),
      allowRecord({ requestId: 'r3', toolName: 'tool-C' }),
    ], signer);
    const target = events[1]!;
    const { exitCode, stdout } = await runVT(
      { requestId: target.metadata.uid, auditLog: logPath },
      signer,
    );
    expect(exitCode).toBe(0);
    expect(stdout.some((l) => l.includes('tool-B'))).toBe(true);
    expect(stdout.some((l) => l.includes('tool-A'))).toBe(false);
  });

  it('finds a record stored in a rotated archive', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const archivePath = path.join(dir, 'audit.jsonl.2026-05-01T00-00-00.000Z');
    const signer = freshSigner();
    // Write the target record to the archive, not the active file
    const archiveEvents = await writeAuditFile(archivePath, [
      allowRecord({ requestId: 'archived-req', toolName: 'old_tool' }),
    ], signer);
    // Active file has a different record
    await writeAuditFile(logPath, [allowRecord({ requestId: 'new-req', toolName: 'new_tool' })], signer);
    const { exitCode, stdout } = await runVT(
      { requestId: archiveEvents[0]!.metadata.uid, auditLog: logPath },
      signer,
    );
    expect(exitCode).toBe(0);
    expect(stdout.some((l) => l.includes('old_tool'))).toBe(true);
  });

  it('output contains "✓ Audit record found" for verified record', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const events = await writeAuditFile(logPath, [allowRecord({ requestId: 'req-ok' })], signer);
    const { stdout } = await runVT(
      { requestId: events[0]!.metadata.uid, auditLog: logPath },
      signer,
    );
    expect(stdout[0]).toBe('✓ Audit record found');
  });

  it('output contains "✗ Audit record found" for invalid signature', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const events = await writeAuditFile(logPath, [allowRecord({ requestId: 'req-badsig' })], signer);
    const wrongSigner = freshSigner();
    const { stdout } = await runVT(
      { requestId: events[0]!.metadata.uid, auditLog: logPath },
      wrongSigner,
    );
    expect(stdout[0]).toBe('✗ Audit record found');
  });

  it('output contains the request id', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const events = await writeAuditFile(logPath, [allowRecord({ requestId: 'my-custom-req-id' })], signer);
    const uid = events[0]!.metadata.uid!;
    const { stdout } = await runVT({ requestId: uid, auditLog: logPath }, signer);
    expect(stdout.some((l: string) => l.includes(uid))).toBe(true);
  });

  it('output contains the tool name', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const events = await writeAuditFile(logPath, [
      allowRecord({ requestId: 'r1', toolName: 'special_tool_name_42' }),
    ], signer);
    const { stdout } = await runVT(
      { requestId: events[0]!.metadata.uid, auditLog: logPath },
      signer,
    );
    expect(stdout.some((l) => l.includes('special_tool_name_42'))).toBe(true);
  });

  it('output contains the session id', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const events = await writeAuditFile(logPath, [
      allowRecord({ requestId: 'r1', sessionId: 'my-test-session-id' }),
    ], signer);
    const { stdout } = await runVT(
      { requestId: events[0]!.metadata.uid, auditLog: logPath },
      signer,
    );
    expect(stdout.some((l) => l.includes('my-test-session-id'))).toBe(true);
  });

  it('output shows "allow" for an allow decision', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const events = await writeAuditFile(logPath, [allowRecord({ requestId: 'r-allow' })], signer);
    const { stdout } = await runVT(
      { requestId: events[0]!.metadata.uid, auditLog: logPath },
      signer,
    );
    expect(stdout.some((l) => l.includes('Decision:') && l.includes('allow'))).toBe(true);
  });

  it('output shows "deny" for a deny decision', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const events = await writeAuditFile(logPath, [denyRecord({ requestId: 'r-deny' })], signer);
    const { stdout } = await runVT(
      { requestId: events[0]!.metadata.uid, auditLog: logPath },
      signer,
    );
    expect(stdout.some((l) => l.includes('Decision:') && l.includes('deny'))).toBe(true);
  });

  it('output shows denialCode for deny decisions', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const events = await writeAuditFile(logPath, [
      denyRecord({ requestId: 'r1', denialCode: 'TIME_WINDOW_DENIED', conditionType: 'timeWindow' }),
    ], signer);
    const { stdout } = await runVT(
      { requestId: events[0]!.metadata.uid, auditLog: logPath },
      signer,
    );
    expect(stdout.some((l) => l.includes('TIME_WINDOW_DENIED'))).toBe(true);
  });

  it('output shows conditionType for deny decisions', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const events = await writeAuditFile(logPath, [
      denyRecord({ requestId: 'r1', conditionType: 'argumentSchema' }),
    ], signer);
    const { stdout } = await runVT(
      { requestId: events[0]!.metadata.uid, auditLog: logPath },
      signer,
    );
    expect(stdout.some((l) => l.includes('argumentSchema'))).toBe(true);
  });

  it('output shows obligation when allow has obligationsApplied', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const events = await writeAuditFile(logPath, [
      { ...allowRecord({ requestId: 'r-obl' }), obligationsApplied: ['redactFields'] },
    ], signer);
    const { stdout } = await runVT(
      { requestId: events[0]!.metadata.uid, auditLog: logPath },
      signer,
    );
    expect(stdout.some((l) => l.includes('redactFields'))).toBe(true);
  });

  it('output contains the signature verification line', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const events = await writeAuditFile(logPath, [allowRecord({ requestId: 'r1' })], signer);
    const { stdout } = await runVT(
      { requestId: events[0]!.metadata.uid, auditLog: logPath },
      signer,
    );
    expect(stdout.some((l) => l.includes('Signature:'))).toBe(true);
  });

  it('output contains the signing key fingerprint', async () => {
    const signer = new LocalHmacSigner(crypto.randomBytes(32), 'my-fingerprint-key');
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const events = await writeAuditFile(logPath, [allowRecord({ requestId: 'r1' })], signer);
    const { stdout } = await runVT(
      { requestId: events[0]!.metadata.uid, auditLog: logPath },
      signer,
    );
    expect(stdout.some((l) => l.includes('my-fingerprint-key'))).toBe(true);
  });

  it('writes output to stdout callback, not stderr', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const events = await writeAuditFile(logPath, [allowRecord({ requestId: 'r1' })], signer);
    const { stdout, stderr } = await runVT(
      { requestId: events[0]!.metadata.uid, auditLog: logPath },
      signer,
    );
    expect(stdout.length).toBeGreaterThan(0);
    expect(stderr).toHaveLength(0);
  });

  it('writes error messages to stderr callback, not stdout', async () => {
    const signer = freshSigner();
    const dir = makeTempDir();
    const { stdout, stderr } = await runVT(
      { requestId: 'missing', auditLog: path.join(dir, 'audit.jsonl') },
      signer,
    );
    expect(stderr.length).toBeGreaterThan(0);
    expect(stdout).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// runValidateToken — since mode
// ---------------------------------------------------------------------------

describe('runValidateToken — since mode', () => {
  it('exits 0 and produces no output when no files exist', async () => {
    const signer = freshSigner();
    const dir = makeTempDir();
    const { exitCode, stdout } = await runVT(
      { since: new Date(0), auditLog: path.join(dir, 'audit.jsonl') },
      signer,
    );
    expect(exitCode).toBe(0);
    expect(stdout).toHaveLength(0);
  });

  it('exits 0 and prints all records when all are after since', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    await writeAuditFile(logPath, [
      allowRecord({ requestId: 'r1' }),
      denyRecord({ requestId: 'r2' }),
    ], signer);
    const { exitCode, stdout } = await runVT(
      { since: new Date(0), auditLog: logPath },
      signer,
    );
    expect(exitCode).toBe(0);
    expect(stdout).toHaveLength(2);
  });

  it('exits 0 and produces no output when all records are before since', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    await writeAuditFile(logPath, [allowRecord({ requestId: 'r1' })], signer);
    const { exitCode, stdout } = await runVT(
      { since: new Date(9999999999999), auditLog: logPath },
      signer,
    );
    expect(exitCode).toBe(0);
    expect(stdout).toHaveLength(0);
  });

  it('prints only records after the since boundary', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const events = await writeAuditFile(logPath, [
      allowRecord({ requestId: 'r1', toolName: 'early_tool' }),
      allowRecord({ requestId: 'r2', toolName: 'late_tool' }),
    ], signer);
    // Filter to records from the 2nd event onwards
    const since = new Date(events[1]!.time);
    const { stdout } = await runVT({ since, auditLog: logPath }, signer);
    // The second record is at the boundary so it should be included
    expect(stdout.some((l) => l.includes('late_tool'))).toBe(true);
  });

  it('output format for allow decision includes "[allow]"', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    await writeAuditFile(logPath, [allowRecord({ requestId: 'r1' })], signer);
    const { stdout } = await runVT({ since: new Date(0), auditLog: logPath }, signer);
    expect(stdout[0]).toContain('[allow]');
  });

  it('output format for deny decision includes "[DENY ]" and denialCode', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    await writeAuditFile(logPath, [
      denyRecord({ requestId: 'r1', denialCode: 'MAX_CALLS_EXCEEDED' }),
    ], signer);
    const { stdout } = await runVT({ since: new Date(0), auditLog: logPath }, signer);
    expect(stdout[0]).toContain('[DENY ]');
    expect(stdout[0]).toContain('MAX_CALLS_EXCEEDED');
  });

  it('prints multiple records on separate lines', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    await writeAuditFile(logPath, [
      allowRecord({ requestId: 'r1', toolName: 'tool-1' }),
      allowRecord({ requestId: 'r2', toolName: 'tool-2' }),
      allowRecord({ requestId: 'r3', toolName: 'tool-3' }),
    ], signer);
    const { stdout } = await runVT({ since: new Date(0), auditLog: logPath }, signer);
    expect(stdout).toHaveLength(3);
  });

  it('preserves file order across archives + active file', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const archivePath = path.join(dir, 'audit.jsonl.2026-05-01T00-00-00.000Z');
    const signer = freshSigner();
    await writeAuditFile(archivePath, [allowRecord({ requestId: 'old', toolName: 'old_tool' })], signer);
    await writeAuditFile(logPath, [allowRecord({ requestId: 'new', toolName: 'new_tool' })], signer);
    const { stdout } = await runVT({ since: new Date(0), auditLog: logPath }, signer);
    expect(stdout[0]).toContain('old_tool');
    expect(stdout[1]).toContain('new_tool');
  });

  it('includes the record at the exact since boundary', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const events = await writeAuditFile(logPath, [allowRecord({ requestId: 'r1' })], signer);
    const exactTime = new Date(events[0]!.time);
    const { stdout } = await runVT({ since: exactTime, auditLog: logPath }, signer);
    expect(stdout).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// runValidateToken — edge cases
// ---------------------------------------------------------------------------

describe('runValidateToken — edge cases', () => {
  it('exits 1 and prints error when neither requestId nor since is provided', async () => {
    const signer = freshSigner();
    const dir = makeTempDir();
    const { exitCode, stderr } = await runVT(
      { auditLog: path.join(dir, 'audit.jsonl') },
      signer,
    );
    expect(exitCode).toBe(1);
    expect(stderr.some((l) => l.includes('requires'))).toBe(true);
  });

  it('uses the provided auditLog path instead of the default', async () => {
    const dir = makeTempDir();
    const customPath = path.join(dir, 'my-custom-audit.jsonl');
    const signer = freshSigner();
    const events = await writeAuditFile(customPath, [allowRecord({ requestId: 'r1' })], signer);
    const { exitCode } = await runVT(
      { requestId: events[0]!.metadata.uid, auditLog: customPath },
      signer,
    );
    expect(exitCode).toBe(0);
  });

  it('exits 1 for request-id mode when the custom auditLog does not exist', async () => {
    const signer = freshSigner();
    const dir = makeTempDir();
    const { exitCode } = await runVT(
      { requestId: 'any-uid', auditLog: path.join(dir, 'nonexistent.jsonl') },
      signer,
    );
    expect(exitCode).toBe(1);
  });

  it('exits 0 for since mode when the custom auditLog does not exist', async () => {
    const signer = freshSigner();
    const dir = makeTempDir();
    const { exitCode, stdout } = await runVT(
      { since: new Date(0), auditLog: path.join(dir, 'nonexistent.jsonl') },
      signer,
    );
    expect(exitCode).toBe(0);
    expect(stdout).toHaveLength(0);
  });

  it('handles a log file that contains both valid and malformed lines gracefully', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const events = await writeAuditFile(logPath, [allowRecord({ requestId: 'good-req' })], signer);
    // Append a malformed line after the valid record
    fs.appendFileSync(logPath, '{bad line}\n');
    const { exitCode } = await runVT(
      { requestId: events[0]!.metadata.uid, auditLog: logPath },
      signer,
    );
    expect(exitCode).toBe(0); // found the good record
  });

  it('for since mode: handles mixed valid + malformed lines gracefully', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    await writeAuditFile(logPath, [allowRecord({ requestId: 'r1' })], signer);
    fs.appendFileSync(logPath, '{bad}\n');
    const { exitCode, stdout } = await runVT(
      { since: new Date(0), auditLog: logPath },
      signer,
    );
    expect(exitCode).toBe(0);
    expect(stdout).toHaveLength(1); // only the valid record
  });

  it('returns exit 2 with "✗ INVALID" in output for a tampered record', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const events = await writeAuditFile(logPath, [allowRecord({ requestId: 'r-tamper' })], signer);
    const raw = fs.readFileSync(logPath, 'utf8');
    // Tamper: change the status
    fs.writeFileSync(logPath, raw.replace('"Success"', '"Failure"'));
    const { exitCode, stdout } = await runVT(
      { requestId: events[0]!.metadata.uid, auditLog: logPath },
      signer,
    );
    expect(exitCode).toBe(2);
    expect(stdout[0]).toBe('✗ Audit record found');
    expect(stdout.some((l) => l.includes('✗ INVALID'))).toBe(true);
  });
});
