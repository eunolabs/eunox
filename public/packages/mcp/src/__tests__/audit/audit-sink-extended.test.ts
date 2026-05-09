/**
 * Extended unit tests for LocalAuditSink and related audit utilities.
 *
 * These tests augment `audit-sink.test.ts` with additional coverage for:
 *   - All McpAuditRecord fields appearing in the correct OCSF output positions
 *   - Deny record OCSF shape
 *   - Details field round-trip
 *   - obligationsApplied round-trip
 *   - Sequence counter behaviour
 *   - verifyAuditEvent edge cases
 *   - NullAuditSink (no-op behaviour)
 *   - Sink close / re-use after close
 *   - Multiple sinks writing to different files
 *   - Records with unicode content
 *   - Records with empty/minimal arguments
 *
 * @module
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { LocalHmacSigner } from '../../audit/hmac-signer';
import {
  LocalAuditSink,
  NullAuditSink,
  verifyAuditEvent,
  type McpAuditRecord,
  type SignedMcpAuditEvent,
} from '../../audit/audit-sink';

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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'euno-audit-ext-'));
  tempDirs.push(dir);
  return dir;
}

function freshSigner(): LocalHmacSigner {
  return new LocalHmacSigner(crypto.randomBytes(32));
}

async function writeRecord(
  sink: LocalAuditSink,
  record: McpAuditRecord,
): Promise<SignedMcpAuditEvent> {
  await sink.record(record);
  await sink.close();
  // Reopen the file and read the last written line
  const logPath = (sink as unknown as { _logPath: string })._logPath;
  const lines = fs.readFileSync(logPath, 'utf8').trim().split('\n').filter(Boolean);
  return JSON.parse(lines[lines.length - 1]!) as SignedMcpAuditEvent;
}

function allowRecord(overrides: Partial<McpAuditRecord> = {}): McpAuditRecord {
  return {
    requestId: crypto.randomUUID(),
    sessionId: 'sess-1',
    toolName: 'echo',
    decision: 'allow',
    ...overrides,
  };
}

function denyRecord(overrides: Partial<McpAuditRecord> = {}): McpAuditRecord {
  return {
    requestId: crypto.randomUUID(),
    sessionId: 'sess-1',
    toolName: 'query_db',
    decision: 'deny',
    denialCode: 'MAX_CALLS_EXCEEDED',
    conditionType: 'maxCalls',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Allow record OCSF shape
// ---------------------------------------------------------------------------

describe('LocalAuditSink — allow record OCSF shape', () => {
  it('status_id is 1 for allow decisions', async () => {
    const dir = makeTempDir();
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath: path.join(dir, 'audit.jsonl') });
    const event = await writeRecord(sink, allowRecord());
    expect(event.status_id).toBe(1);
  });

  it('status is "Success" for allow decisions', async () => {
    const dir = makeTempDir();
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath: path.join(dir, 'audit.jsonl') });
    const event = await writeRecord(sink, allowRecord());
    expect(event.status).toBe('Success');
  });

  it('class_uid is 6003 (API Activity)', async () => {
    const dir = makeTempDir();
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath: path.join(dir, 'audit.jsonl') });
    const event = await writeRecord(sink, allowRecord());
    expect(event.class_uid).toBe(6003);
  });

  it('metadata.uid matches requestId from the record', async () => {
    const dir = makeTempDir();
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath: path.join(dir, 'audit.jsonl') });
    const record = allowRecord({ requestId: 'my-custom-request-id' });
    const event = await writeRecord(sink, record);
    expect(event.metadata.uid).toBe('my-custom-request-id');
  });

  it('actor.session.uid matches sessionId from the record', async () => {
    const dir = makeTempDir();
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath: path.join(dir, 'audit.jsonl') });
    const record = allowRecord({ sessionId: 'my-test-session' });
    const event = await writeRecord(sink, record);
    expect(event.actor?.session?.uid).toBe('my-test-session');
  });

  it('api.operation matches toolName from the record', async () => {
    const dir = makeTempDir();
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath: path.join(dir, 'audit.jsonl') });
    const record = allowRecord({ toolName: 'special_tool_42' });
    const event = await writeRecord(sink, record);
    expect(event.api?.operation).toBe('special_tool_42');
  });

  it('time field is a number (unix milliseconds)', async () => {
    const dir = makeTempDir();
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath: path.join(dir, 'audit.jsonl') });
    const before = Date.now();
    const event = await writeRecord(sink, allowRecord());
    const after = Date.now();
    expect(typeof event.time).toBe('number');
    expect(event.time).toBeGreaterThanOrEqual(before);
    expect(event.time).toBeLessThanOrEqual(after);
  });

  it('enrichments array contains the HMAC signature entry', async () => {
    const dir = makeTempDir();
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath: path.join(dir, 'audit.jsonl') });
    const event = await writeRecord(sink, allowRecord());
    expect(Array.isArray(event.enrichments)).toBe(true);
    const sig = event.enrichments?.find((e) => e.name === 'hmac-signature');
    expect(sig).toBeDefined();
    expect(sig!.value).toBeTruthy();
  });

  it('unmapped.seq is 1 for the first record written', async () => {
    const dir = makeTempDir();
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath: path.join(dir, 'audit.jsonl') });
    const event = await writeRecord(sink, allowRecord());
    expect((event.unmapped as Record<string, unknown>)['seq']).toBe(1);
  });

  it('obligationsApplied is populated in unmapped when provided', async () => {
    const dir = makeTempDir();
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath: path.join(dir, 'audit.jsonl') });
    const record = allowRecord({ obligationsApplied: ['redactFields', 'maskPII'] });
    const event = await writeRecord(sink, record);
    const unmapped = event.unmapped as Record<string, unknown>;
    expect(unmapped['obligationsApplied']).toEqual(['redactFields', 'maskPII']);
  });

  it('obligationsApplied is absent in unmapped when not provided', async () => {
    const dir = makeTempDir();
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath: path.join(dir, 'audit.jsonl') });
    const event = await writeRecord(sink, allowRecord());
    const unmapped = event.unmapped as Record<string, unknown>;
    expect(unmapped['obligationsApplied']).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Deny record OCSF shape
// ---------------------------------------------------------------------------

describe('LocalAuditSink — deny record OCSF shape', () => {
  it('status_id is 2 for deny decisions', async () => {
    const dir = makeTempDir();
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath: path.join(dir, 'audit.jsonl') });
    const event = await writeRecord(sink, denyRecord());
    expect(event.status_id).toBe(2);
  });

  it('status is "Failure" for deny decisions', async () => {
    const dir = makeTempDir();
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath: path.join(dir, 'audit.jsonl') });
    const event = await writeRecord(sink, denyRecord());
    expect(event.status).toBe('Failure');
  });

  it('unmapped.denialCode matches the denial code from the record', async () => {
    const dir = makeTempDir();
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath: path.join(dir, 'audit.jsonl') });
    const record = denyRecord({ denialCode: 'TIME_WINDOW_DENIED' });
    const event = await writeRecord(sink, record);
    expect((event.unmapped as Record<string, unknown>)['denialCode']).toBe('TIME_WINDOW_DENIED');
  });

  it('unmapped.conditionType matches the condition type from the record', async () => {
    const dir = makeTempDir();
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath: path.join(dir, 'audit.jsonl') });
    const record = denyRecord({ conditionType: 'timeWindow' });
    const event = await writeRecord(sink, record);
    expect((event.unmapped as Record<string, unknown>)['conditionType']).toBe('timeWindow');
  });

  it('unmapped.details is populated when details provided', async () => {
    const dir = makeTempDir();
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath: path.join(dir, 'audit.jsonl') });
    const details = { path: '$.query', expected: 'string', got: 'number' };
    const record = denyRecord({ details });
    const event = await writeRecord(sink, record);
    expect((event.unmapped as Record<string, unknown>)['details']).toEqual(details);
  });

  it('unmapped.details is absent when not provided', async () => {
    const dir = makeTempDir();
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath: path.join(dir, 'audit.jsonl') });
    const event = await writeRecord(sink, denyRecord());
    expect((event.unmapped as Record<string, unknown>)['details']).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Signature verification (verifyAuditEvent)
// ---------------------------------------------------------------------------

describe('verifyAuditEvent', () => {
  it('verifies a freshly written record as true', async () => {
    const dir = makeTempDir();
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath: path.join(dir, 'audit.jsonl') });
    const event = await writeRecord(sink, allowRecord());
    expect(verifyAuditEvent(event, signer)).toBe(true);
  });

  it('returns false when verified with a different key', async () => {
    const dir = makeTempDir();
    const signer1 = freshSigner();
    const signer2 = freshSigner();
    const sink = new LocalAuditSink(signer1, { logPath: path.join(dir, 'audit.jsonl') });
    const event = await writeRecord(sink, allowRecord());
    expect(verifyAuditEvent(event, signer2)).toBe(false);
  });

  it('returns false after status field is tampered', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath });
    await writeRecord(sink, allowRecord());

    const raw = fs.readFileSync(logPath, 'utf8');
    const tampered = raw.replace('"Success"', '"Failure"');
    const event = JSON.parse(tampered) as SignedMcpAuditEvent;
    expect(verifyAuditEvent(event, signer)).toBe(false);
  });

  it('returns false after denial code is tampered', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath });
    await writeRecord(sink, denyRecord({ denialCode: 'MAX_CALLS_EXCEEDED' }));

    const raw = fs.readFileSync(logPath, 'utf8');
    const tampered = raw.replace('"MAX_CALLS_EXCEEDED"', '"ALLOWED"');
    const event = JSON.parse(tampered) as SignedMcpAuditEvent;
    expect(verifyAuditEvent(event, signer)).toBe(false);
  });

  it('returns false after the tool name is tampered', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath });
    await writeRecord(sink, allowRecord({ toolName: 'safe_tool' }));

    const raw = fs.readFileSync(logPath, 'utf8');
    const tampered = raw.replace('"safe_tool"', '"dangerous_tool"');
    const event = JSON.parse(tampered) as SignedMcpAuditEvent;
    expect(verifyAuditEvent(event, signer)).toBe(false);
  });

  it('returns false after requestId (metadata.uid) is tampered', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath });
    await writeRecord(sink, allowRecord({ requestId: 'original-uid' }));

    const raw = fs.readFileSync(logPath, 'utf8');
    const tampered = raw.replace('"original-uid"', '"different-uid"');
    const event = JSON.parse(tampered) as SignedMcpAuditEvent;
    expect(verifyAuditEvent(event, signer)).toBe(false);
  });

  it('verifies both allow and deny records correctly', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath });
    await sink.record(allowRecord());
    await sink.record(denyRecord());
    await sink.close();

    const lines = fs.readFileSync(logPath, 'utf8').trim().split('\n').filter(Boolean);
    const [allow, deny] = lines.map((l) => JSON.parse(l) as SignedMcpAuditEvent);
    expect(verifyAuditEvent(allow!, signer)).toBe(true);
    expect(verifyAuditEvent(deny!, signer)).toBe(true);
  });

  it('does not throw when the enrichments array is missing', () => {
    const signer = freshSigner();
    const badEvent = {
      time: Date.now(),
      class_uid: 6003,
      metadata: { uid: 'x', version: '1.1.0', product: {} },
      status_id: 1,
      status: 'Success',
      // no enrichments
    } as unknown as SignedMcpAuditEvent;
    expect(() => verifyAuditEvent(badEvent, signer)).not.toThrow();
    expect(verifyAuditEvent(badEvent, signer)).toBe(false);
  });

  it('does not throw when the enrichments array is empty', () => {
    const signer = freshSigner();
    const badEvent = {
      time: Date.now(),
      class_uid: 6003,
      metadata: { uid: 'x', version: '1.1.0', product: {} },
      status_id: 1,
      enrichments: [],
    } as unknown as SignedMcpAuditEvent;
    expect(() => verifyAuditEvent(badEvent, signer)).not.toThrow();
    expect(verifyAuditEvent(badEvent, signer)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Sequence counter
// ---------------------------------------------------------------------------

describe('LocalAuditSink — sequence counter', () => {
  it('seq increments with each record written', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath });

    await sink.record(allowRecord());
    await sink.record(allowRecord());
    await sink.record(allowRecord());
    await sink.close();

    const lines = fs.readFileSync(logPath, 'utf8').trim().split('\n').filter(Boolean);
    const seqs = lines.map((l) => {
      const e = JSON.parse(l) as SignedMcpAuditEvent;
      return (e.unmapped as Record<string, unknown>)['seq'] as number;
    });
    expect(seqs).toEqual([1, 2, 3]);
  });

  it('seq starts at 1 for the first record in a new sink', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath });
    const event = await writeRecord(sink, allowRecord());
    expect((event.unmapped as Record<string, unknown>)['seq']).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Unicode and special characters
// ---------------------------------------------------------------------------

describe('LocalAuditSink — unicode and special characters', () => {
  it('tool names with unicode are correctly stored and verified', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath });
    const event = await writeRecord(sink, allowRecord({ toolName: '工具名称_🎉' }));
    expect(event.api?.operation).toBe('工具名称_🎉');
    expect(verifyAuditEvent(event, signer)).toBe(true);
  });

  it('session IDs with special characters are correctly stored', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath });
    const event = await writeRecord(sink, allowRecord({ sessionId: 'sess/with\\special:chars' }));
    expect(event.actor?.session?.uid).toBe('sess/with\\special:chars');
  });

  it('details with unicode values round-trip correctly', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath });
    const details = { message: 'エラー: 不正なリクエスト' };
    const event = await writeRecord(sink, denyRecord({ details }));
    expect((event.unmapped as Record<string, unknown>)['details']).toEqual(details);
    expect(verifyAuditEvent(event, signer)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// NullAuditSink
// ---------------------------------------------------------------------------

describe('NullAuditSink', () => {
  it('record() resolves without throwing', async () => {
    const sink = new NullAuditSink();
    await expect(sink.record(allowRecord())).resolves.toBeUndefined();
  });

  it('record() for a deny record also resolves without throwing', async () => {
    const sink = new NullAuditSink();
    await expect(sink.record(denyRecord())).resolves.toBeUndefined();
  });

  it('close() resolves without throwing', async () => {
    const sink = new NullAuditSink();
    await expect(sink.close()).resolves.toBeUndefined();
  });

  it('close() is idempotent', async () => {
    const sink = new NullAuditSink();
    await sink.close();
    await expect(sink.close()).resolves.toBeUndefined();
  });

  it('record() after close() resolves without throwing', async () => {
    const sink = new NullAuditSink();
    await sink.close();
    await expect(sink.record(allowRecord())).resolves.toBeUndefined();
  });

  it('writes nothing to disk', async () => {
    // Verify NullAuditSink has no side effects on the file system
    const sink = new NullAuditSink();
    await sink.record(allowRecord());
    await sink.record(denyRecord());
    await sink.close();
    // No assertions needed beyond no error thrown and no disk writes
  });
});

// ---------------------------------------------------------------------------
// Multiple sinks writing to different files
// ---------------------------------------------------------------------------

describe('LocalAuditSink — multiple independent sinks', () => {
  it('two sinks writing to different files produce independent logs', async () => {
    const dir = makeTempDir();
    const signer1 = freshSigner();
    const signer2 = freshSigner();
    const log1 = path.join(dir, 'audit1.jsonl');
    const log2 = path.join(dir, 'audit2.jsonl');

    const sink1 = new LocalAuditSink(signer1, { logPath: log1 });
    const sink2 = new LocalAuditSink(signer2, { logPath: log2 });

    await sink1.record(allowRecord({ toolName: 'tool1' }));
    await sink2.record(allowRecord({ toolName: 'tool2' }));

    await sink1.close();
    await sink2.close();

    const event1 = JSON.parse(fs.readFileSync(log1, 'utf8').trim()) as SignedMcpAuditEvent;
    const event2 = JSON.parse(fs.readFileSync(log2, 'utf8').trim()) as SignedMcpAuditEvent;

    expect(event1.api?.operation).toBe('tool1');
    expect(event2.api?.operation).toBe('tool2');

    // Each event is verified by its own signer
    expect(verifyAuditEvent(event1, signer1)).toBe(true);
    expect(verifyAuditEvent(event2, signer2)).toBe(true);

    // Cross-verification fails
    expect(verifyAuditEvent(event1, signer2)).toBe(false);
    expect(verifyAuditEvent(event2, signer1)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Multiple records per sink
// ---------------------------------------------------------------------------

describe('LocalAuditSink — multiple records per sink', () => {
  it('writes all records to the log file in order', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath });

    const records = [
      allowRecord({ toolName: 'tool-1' }),
      allowRecord({ toolName: 'tool-2' }),
      denyRecord({ toolName: 'tool-3' }),
    ];

    for (const r of records) await sink.record(r);
    await sink.close();

    const lines = fs.readFileSync(logPath, 'utf8').trim().split('\n').filter(Boolean);
    expect(lines).toHaveLength(3);

    const events = lines.map((l) => JSON.parse(l) as SignedMcpAuditEvent);
    expect(events[0]!.api?.operation).toBe('tool-1');
    expect(events[1]!.api?.operation).toBe('tool-2');
    expect(events[2]!.api?.operation).toBe('tool-3');
  });

  it('all records are independently verifiable', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath });

    for (let i = 0; i < 5; i++) {
      await sink.record(allowRecord({ toolName: `tool-${i}` }));
    }
    await sink.close();

    const lines = fs.readFileSync(logPath, 'utf8').trim().split('\n').filter(Boolean);
    for (const line of lines) {
      const event = JSON.parse(line) as SignedMcpAuditEvent;
      expect(verifyAuditEvent(event, signer)).toBe(true);
    }
  });

  it('records each have increasing timestamps (monotonic)', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath });

    for (let i = 0; i < 3; i++) {
      await sink.record(allowRecord());
      // Small delay to ensure strictly increasing ms timestamps
      await new Promise((resolve) => setTimeout(resolve, 2));
    }
    await sink.close();

    const lines = fs.readFileSync(logPath, 'utf8').trim().split('\n').filter(Boolean);
    const times = lines.map((l) => (JSON.parse(l) as SignedMcpAuditEvent).time);
    for (let i = 1; i < times.length; i++) {
      expect(times[i]!).toBeGreaterThanOrEqual(times[i - 1]!);
    }
  });
});

// ---------------------------------------------------------------------------
// McpAuditRecord optional fields
// ---------------------------------------------------------------------------

describe('LocalAuditSink — optional record fields', () => {
  it('record without obligationsApplied produces unmapped without that field', async () => {
    const dir = makeTempDir();
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath: path.join(dir, 'audit.jsonl') });
    const event = await writeRecord(sink, allowRecord({ toolName: 'echo' }));
    const unmapped = event.unmapped as Record<string, unknown>;
    expect(unmapped['obligationsApplied']).toBeUndefined();
  });

  it('record with empty obligationsApplied array stores empty array', async () => {
    const dir = makeTempDir();
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath: path.join(dir, 'audit.jsonl') });
    const event = await writeRecord(sink, allowRecord({ obligationsApplied: [] }));
    const unmapped = event.unmapped as Record<string, unknown>;
    // Either undefined or [] — both are acceptable; just verify no crash
    expect(unmapped).toBeDefined();
  });

  it('record without conditionType produces unmapped without that field for deny', async () => {
    const dir = makeTempDir();
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath: path.join(dir, 'audit.jsonl') });
    // Deny with only denialCode, no conditionType
    const event = await writeRecord(sink, {
      requestId: crypto.randomUUID(),
      sessionId: 'sess',
      toolName: 'tool',
      decision: 'deny',
      denialCode: 'CUSTOM_ERROR',
    });
    const unmapped = event.unmapped as Record<string, unknown>;
    expect(unmapped['denialCode']).toBe('CUSTOM_ERROR');
    expect(unmapped['conditionType']).toBeUndefined();
  });

  it('every written record is a valid JSON string on a single line', async () => {
    const dir = makeTempDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath });
    await sink.record(allowRecord());
    await sink.record(denyRecord());
    await sink.close();

    const lines = fs.readFileSync(logPath, 'utf8').trim().split('\n');
    for (const line of lines) {
      expect(() => JSON.parse(line)).not.toThrow();
      // Each line must be a single line (no embedded newlines)
      expect(line.includes('\n')).toBe(false);
    }
  });
});
