/**
 * Tests for LocalAuditSink and verifyAuditEvent.
 *
 * Coverage:
 *   - OCSF record shape (schema match against common-core types)
 *   - HMAC round-trip via verifyAuditEvent
 *   - All McpAuditRecord fields appear in the correct OCSF locations
 *   - Monotonic seq counter increments correctly
 *   - File rotation when size limit is reached
 *   - Concurrent writes do not interleave records
 *   - NullAuditSink is a safe no-op
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import type { OcsfApiActivityEvent } from '@euno/common-core';

import { LocalHmacSigner } from '../../audit/hmac-signer';
import {
  LocalAuditSink,
  NullAuditSink,
  SignedMcpAuditEvent,
  verifyAuditEvent,
  McpAuditRecord,
} from '../../audit/audit-sink';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'euno-audit-test-'));
}

function freshSigner(): LocalHmacSigner {
  return new LocalHmacSigner(crypto.randomBytes(32));
}

function readLines(logPath: string): SignedMcpAuditEvent[] {
  const raw = fs.readFileSync(logPath, 'utf8');
  return raw
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l) as SignedMcpAuditEvent);
}

// ---------------------------------------------------------------------------
// Helper: create a sink backed by a temp directory
// ---------------------------------------------------------------------------

function makeSink(
  dir: string,
  opts: { rotateSizeBytes?: number; signer?: LocalHmacSigner } = {},
): { sink: LocalAuditSink; logPath: string; signer: LocalHmacSigner } {
  const logPath = path.join(dir, 'audit.jsonl');
  const signer = opts.signer ?? freshSigner();
  const sink = new LocalAuditSink(signer, {
    logPath,
    rotateSizeBytes: opts.rotateSizeBytes,
  });
  return { sink, logPath, signer };
}

// ---------------------------------------------------------------------------
// NullAuditSink
// ---------------------------------------------------------------------------

describe('NullAuditSink', () => {
  it('is a safe no-op for all methods', async () => {
    const sink = new NullAuditSink();
    await expect(sink.record({ sessionId: 's1', toolName: 'echo', decision: 'allow' })).resolves.toBeUndefined();
    await expect(sink.flush()).resolves.toBeUndefined();
    await expect(sink.close()).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// OCSF record shape
// ---------------------------------------------------------------------------

describe('LocalAuditSink — OCSF record shape', () => {
  let dir: string;

  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  describe('allow decision', () => {
    let event: SignedMcpAuditEvent;

    beforeEach(async () => {
      const { sink, logPath } = makeSink(dir);
      await sink.record({
        sessionId: 'sess-abc',
        toolName: 'list_files',
        resource: '/tmp',
        decision: 'allow',
        requestId: 'req-123',
      });
      await sink.close();
      event = readLines(logPath)[0]!;
    });

    // ── OCSF base fields ────────────────────────────────────────────────────
    it('sets class_uid=6003 (API Activity)', () => {
      expect(event.class_uid).toBe(6003);
    });

    it('sets category_uid=6 (Application Activity)', () => {
      expect(event.category_uid).toBe(6);
    });

    it('sets activity_id=99 (Other)', () => {
      expect(event.activity_id).toBe(99);
    });

    it('sets type_uid = class_uid * 100 + activity_id', () => {
      expect(event.type_uid).toBe(6003 * 100 + 99);
    });

    it('sets severity_id=1 (Informational) for allow', () => {
      expect(event.severity_id).toBe(1);
    });

    it('sets status_id=1 (Success) for allow', () => {
      expect(event.status_id).toBe(1);
    });

    it('sets status="Success" for allow', () => {
      expect(event.status).toBe('Success');
    });

    it('sets time as a positive unix-ms integer', () => {
      expect(typeof event.time).toBe('number');
      expect(event.time).toBeGreaterThan(0);
    });

    // ── metadata ──────────────────────────────────────────────────────────
    it('sets metadata.version to "1.1.0"', () => {
      expect(event.metadata.version).toBe('1.1.0');
    });

    it('sets metadata.product.name to "euno-mcp"', () => {
      expect(event.metadata.product.name).toBe('euno-mcp');
    });

    it('sets metadata.product.vendor_name to "Euno"', () => {
      expect(event.metadata.product.vendor_name).toBe('Euno');
    });

    it('uses requestId as metadata.uid when provided', () => {
      expect(event.metadata.uid).toBe('req-123');
    });

    it('generates a UUID as metadata.uid when requestId is absent', async () => {
      const freshDir = tmpDir();
      try {
        const { sink, logPath } = makeSink(freshDir);
        await sink.record({ sessionId: 's', toolName: 'echo', decision: 'allow' });
        await sink.close();
        const ev = readLines(logPath)[0]!;
        expect(typeof ev.metadata.uid).toBe('string');
        expect(ev.metadata.uid).toMatch(
          /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
        );
      } finally {
        fs.rmSync(freshDir, { recursive: true, force: true });
      }
    });

    // ── api ────────────────────────────────────────────────────────────────
    it('sets api.operation to toolName', () => {
      expect(event.api?.operation).toBe('list_files');
    });

    it('sets api.service.name to "euno-mcp"', () => {
      expect(event.api?.service?.name).toBe('euno-mcp');
    });

    // ── actor ──────────────────────────────────────────────────────────────
    it('sets actor.session.uid to sessionId', () => {
      expect(event.actor?.session?.uid).toBe('sess-abc');
    });

    // ── resources ─────────────────────────────────────────────────────────
    it('includes resource in resources array when provided', () => {
      expect(event.resources).toHaveLength(1);
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      expect(event.resources![0]!.uid).toBe('/tmp');
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      expect(event.resources![0]!.type).toBe('mcp-tool-resource');
    });

    it('omits resources array when no resource is provided', async () => {
      const freshDir = tmpDir();
      try {
        const { sink, logPath } = makeSink(freshDir);
        await sink.record({ sessionId: 's', toolName: 'echo', decision: 'allow' });
        await sink.close();
        const ev = readLines(logPath)[0]!;
        expect(ev.resources).toBeUndefined();
      } finally {
        fs.rmSync(freshDir, { recursive: true, force: true });
      }
    });

    // ── unmapped ──────────────────────────────────────────────────────────
    it('includes seq=1 in unmapped for first record', () => {
      expect(event.unmapped?.['seq']).toBe(1);
    });

    it('does not include denial fields in unmapped for allow', () => {
      expect(event.unmapped?.['denialCode']).toBeUndefined();
      expect(event.unmapped?.['conditionType']).toBeUndefined();
    });
  });

  describe('deny decision', () => {
    let event: SignedMcpAuditEvent;

    beforeEach(async () => {
      const { sink, logPath } = makeSink(dir);
      await sink.record({
        sessionId: 'sess-xyz',
        toolName: 'query_db',
        resource: 'postgres://localhost/app',
        decision: 'deny',
        denialCode: 'MAX_CALLS_EXCEEDED',
        conditionType: 'maxCalls',
      });
      await sink.close();
      event = readLines(logPath)[0]!;
    });

    it('sets severity_id=3 (Medium) for deny', () => {
      expect(event.severity_id).toBe(3);
    });

    it('sets status_id=2 (Failure) for deny', () => {
      expect(event.status_id).toBe(2);
    });

    it('sets status="Failure" for deny', () => {
      expect(event.status).toBe('Failure');
    });

    it('includes denialCode in unmapped', () => {
      expect(event.unmapped?.['denialCode']).toBe('MAX_CALLS_EXCEEDED');
    });

    it('includes conditionType in unmapped', () => {
      expect(event.unmapped?.['conditionType']).toBe('maxCalls');
    });
  });
});

// ---------------------------------------------------------------------------
// HMAC signature
// ---------------------------------------------------------------------------

describe('LocalAuditSink — HMAC signature', () => {
  let dir: string;

  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it('attaches exactly one hmac-signature enrichment', async () => {
    const { sink, logPath } = makeSink(dir);
    await sink.record({ sessionId: 's', toolName: 'echo', decision: 'allow' });
    await sink.close();
    const event = readLines(logPath)[0]!;
    expect(event.enrichments).toHaveLength(1);
    expect(event.enrichments[0]!.name).toBe('hmac-signature');
    expect(event.enrichments[0]!.type).toBe('hmac-sha256');
    expect(typeof event.enrichments[0]!.value).toBe('string');
  });

  it('embeds keyId in enrichment data', async () => {
    const { sink, logPath, signer } = makeSink(dir);
    await sink.record({ sessionId: 's', toolName: 'echo', decision: 'allow' });
    await sink.close();
    const event = readLines(logPath)[0]!;
    expect(event.enrichments[0]!.data?.['keyId']).toBe(signer.keyId);
  });

  it('verifyAuditEvent returns true for a well-formed record', async () => {
    const signer = freshSigner();
    const { sink, logPath } = makeSink(dir, { signer });
    await sink.record({ sessionId: 's', toolName: 'echo', decision: 'allow' });
    await sink.close();
    const event = readLines(logPath)[0]!;
    expect(verifyAuditEvent(event, signer)).toBe(true);
  });

  it('verifyAuditEvent returns false after the record is tampered with', async () => {
    const signer = freshSigner();
    const { sink, logPath } = makeSink(dir, { signer });
    await sink.record({ sessionId: 's', toolName: 'echo', decision: 'allow' });
    await sink.close();

    // Read the line, mutate it, verify should fail.
    const line = fs.readFileSync(logPath, 'utf8').trim();
    const event = JSON.parse(line) as SignedMcpAuditEvent;
    // Tamper with the status field (which is covered by the HMAC).
    (event as unknown as Record<string, unknown>)['status'] = 'Failure';
    expect(verifyAuditEvent(event, signer)).toBe(false);
  });

  it('verifyAuditEvent returns false with the wrong signer key', async () => {
    const signer1 = freshSigner();
    const signer2 = freshSigner();
    const { sink, logPath } = makeSink(dir, { signer: signer1 });
    await sink.record({ sessionId: 's', toolName: 'echo', decision: 'allow' });
    await sink.close();
    const event = readLines(logPath)[0]!;
    expect(verifyAuditEvent(event, signer2)).toBe(false);
  });

  it('verifyAuditEvent returns false when enrichments are missing', async () => {
    const signer = freshSigner();
    const { sink, logPath } = makeSink(dir, { signer });
    await sink.record({ sessionId: 's', toolName: 'echo', decision: 'allow' });
    await sink.close();
    const event = readLines(logPath)[0]!;
    // Remove enrichments.
    const stripped = { ...event, enrichments: [] } as unknown as SignedMcpAuditEvent;
    expect(verifyAuditEvent(stripped, signer)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Monotonic counter
// ---------------------------------------------------------------------------

describe('LocalAuditSink — monotonic seq counter', () => {
  let dir: string;

  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it('increments seq across multiple records', async () => {
    const { sink, logPath } = makeSink(dir);
    const records: McpAuditRecord[] = [
      { sessionId: 's', toolName: 'a', decision: 'allow' },
      { sessionId: 's', toolName: 'b', decision: 'deny', denialCode: 'ERR' },
      { sessionId: 's', toolName: 'c', decision: 'allow' },
    ];
    for (const r of records) await sink.record(r);
    await sink.close();

    const events = readLines(logPath);
    expect(events).toHaveLength(3);
    expect(events[0]!.unmapped?.['seq']).toBe(1);
    expect(events[1]!.unmapped?.['seq']).toBe(2);
    expect(events[2]!.unmapped?.['seq']).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// File rotation
// ---------------------------------------------------------------------------

describe('LocalAuditSink — file rotation', () => {
  let dir: string;

  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it('rotates the file when the size limit is reached', async () => {
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    // Use a tiny rotate threshold so even one record triggers rotation.
    const sink = new LocalAuditSink(signer, { logPath, rotateSizeBytes: 1 });

    // Write enough records to guarantee at least one rotation.
    for (let i = 0; i < 5; i++) {
      await sink.record({ sessionId: 's', toolName: `tool${i}`, decision: 'allow' });
    }
    await sink.close();

    // There should be at least one rotated file in the directory.
    const files = fs.readdirSync(dir);
    const rotated = files.filter((f) => f.startsWith('audit.jsonl.') && f !== 'audit.jsonl');
    expect(rotated.length).toBeGreaterThanOrEqual(1);
  });

  it('continues writing to a new file after rotation', async () => {
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    // Set threshold to 1 byte so every write triggers a rotation.
    const sink = new LocalAuditSink(signer, { logPath, rotateSizeBytes: 1 });

    await sink.record({ sessionId: 's', toolName: 'first', decision: 'allow' });
    await sink.record({ sessionId: 's', toolName: 'second', decision: 'allow' });
    await sink.close();

    // The active file must exist and be readable.
    expect(fs.existsSync(logPath)).toBe(true);
    const activeLines = fs.readFileSync(logPath, 'utf8').trim().split('\n').filter(Boolean);
    expect(activeLines.length).toBeGreaterThanOrEqual(1);
  });

  it('uses an ISO-8601 timestamp in the rotated filename', async () => {
    const logPath = path.join(dir, 'audit.jsonl');
    const signer = freshSigner();
    const sink = new LocalAuditSink(signer, { logPath, rotateSizeBytes: 1 });

    await sink.record({ sessionId: 's', toolName: 'a', decision: 'allow' });
    await sink.record({ sessionId: 's', toolName: 'b', decision: 'allow' });
    await sink.close();

    const files = fs.readdirSync(dir);
    const rotated = files.filter((f) => f.startsWith('audit.jsonl.') && f !== 'audit.jsonl');
    expect(rotated.length).toBeGreaterThanOrEqual(1);
    // Filename contains a date-like segment (YYYY-MM-DD).
    for (const f of rotated) {
      expect(f).toMatch(/\d{4}-\d{2}-\d{2}/);
    }
  });
});

// ---------------------------------------------------------------------------
// Concurrent writes
// ---------------------------------------------------------------------------

describe('LocalAuditSink — concurrent writes', () => {
  let dir: string;

  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it('serialises concurrent record() calls — no interleaved lines', async () => {
    const { sink, logPath, signer } = makeSink(dir);
    const N = 20;
    await Promise.all(
      Array.from({ length: N }, (_, i) =>
        sink.record({ sessionId: 's', toolName: `tool${i}`, decision: 'allow' }),
      ),
    );
    await sink.close();

    const events = readLines(logPath);
    // All records written, all parseable, all verifiable.
    expect(events).toHaveLength(N);
    for (const ev of events) {
      expect(verifyAuditEvent(ev, signer)).toBe(true);
    }
    // seq values should be 1..N (order may vary due to concurrency, but values unique).
    const seqs = events.map((e) => e.unmapped?.['seq'] as number);
    expect(new Set(seqs).size).toBe(N);
    const sorted = [...seqs].sort((a, b) => a - b);
    expect(sorted[0]).toBe(1);
    expect(sorted[N - 1]).toBe(N);
  });
});

// ---------------------------------------------------------------------------
// Schema parity with OcsfApiActivityEvent (common-core type)
// ---------------------------------------------------------------------------

describe('LocalAuditSink — OcsfApiActivityEvent schema parity', () => {
  let dir: string;

  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it('produces a record that satisfies the OcsfApiActivityEvent shape', async () => {
    const { sink, logPath } = makeSink(dir);
    await sink.record({ sessionId: 's', toolName: 'run', decision: 'allow' });
    await sink.close();

    const event = readLines(logPath)[0]!;

    // Type check: assign to OcsfApiActivityEvent — if this compiles, the
    // shape is compatible.  We also assert all required fields at runtime.
    const typed: OcsfApiActivityEvent = event as OcsfApiActivityEvent;

    expect(typeof typed.class_uid).toBe('number');
    expect(typeof typed.category_uid).toBe('number');
    expect(typeof typed.activity_id).toBe('number');
    expect(typeof typed.type_uid).toBe('number');
    expect(typeof typed.severity_id).toBe('number');
    expect(typeof typed.time).toBe('number');
    expect(typed.metadata).toBeTruthy();
    expect(typed.metadata.version).toBeTruthy();
    expect(typed.metadata.product).toBeTruthy();
  });

  it('produces a record with identical shape when written twice (schema stability)', async () => {
    const signer = freshSigner();
    const { sink, logPath } = makeSink(dir, { signer });
    await sink.record({ sessionId: 's', toolName: 'run', decision: 'allow' });
    await sink.record({ sessionId: 's', toolName: 'run', decision: 'allow' });
    await sink.close();

    const events = readLines(logPath);
    const e1 = events[0]!;
    const e2 = events[1]!;
    // Same structural keys (order-insensitive).
    expect(Object.keys(e1).sort()).toEqual(Object.keys(e2).sort());
  });
});

// ---------------------------------------------------------------------------
// Post-close behaviour
// ---------------------------------------------------------------------------

describe('LocalAuditSink — post-close behaviour', () => {
  let dir: string;

  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it('silently ignores record() calls after close()', async () => {
    const { sink, logPath } = makeSink(dir);
    await sink.record({ sessionId: 's', toolName: 'a', decision: 'allow' });
    await sink.close();
    // This should not throw or write.
    await sink.record({ sessionId: 's', toolName: 'b', decision: 'allow' });

    const events = readLines(logPath);
    expect(events).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Queue resilience — prior failure does not drop subsequent records
// ---------------------------------------------------------------------------

describe('LocalAuditSink — queue resilience', () => {
  it('continues recording after an internal write failure', async () => {
    const signer = freshSigner();
    const resilDir = fs.mkdtempSync(path.join(os.tmpdir(), 'euno-resilience-'));
    const logPath = path.join(resilDir, 'audit.jsonl');

    try {
      const sink = new LocalAuditSink(signer, { logPath });

      // First write succeeds.
      await sink.record({ sessionId: 's', toolName: 'first', decision: 'allow' });

      // Second write: make the directory read-only so appendFile fails.
      if (process.platform !== 'win32' && !(process.getuid && process.getuid() === 0)) {
        fs.chmodSync(resilDir, 0o555);
        await sink.record({ sessionId: 's', toolName: 'failing', decision: 'allow' });
        // Restore.
        fs.chmodSync(resilDir, 0o755);
      }

      // Third write must succeed (queue must still be alive after the failure).
      await sink.record({ sessionId: 's', toolName: 'third', decision: 'allow' });
      await sink.close();

      const events = readLines(logPath);
      // First and third records must be present (second may have been dropped).
      expect(events.some((e) => e.api?.operation === 'first')).toBe(true);
      expect(events.some((e) => e.api?.operation === 'third')).toBe(true);
    } finally {
      try { fs.chmodSync(resilDir, 0o755); } catch { /* ignore */ }
      fs.rmSync(resilDir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// Rotation — non-ENOENT errors preserve size accuracy
// ---------------------------------------------------------------------------

describe('LocalAuditSink — rotation error handling', () => {
  it('resets size to 0 on ENOENT (file not yet created)', async () => {
    const rotDir = fs.mkdtempSync(path.join(os.tmpdir(), 'euno-rot-'));
    try {
      const logPath = path.join(rotDir, 'audit.jsonl');
      const signer = freshSigner();
      // Set threshold to 1 so rotation is attempted on first write.
      const sink = new LocalAuditSink(signer, { logPath, rotateSizeBytes: 1 });
      await sink.record({ sessionId: 's', toolName: 'a', decision: 'allow' });
      await sink.close();
      // Must have written something (rotation ENOENT → size reset → fresh write).
      expect(fs.existsSync(logPath)).toBe(true);
    } finally {
      fs.rmSync(rotDir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// details field — argumentSchema structured error reporting (Task 1)
// ---------------------------------------------------------------------------

describe('LocalAuditSink — details field in unmapped', () => {
  let dir: string;

  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it('writes details into unmapped when provided on a deny record', async () => {
    const { sink, logPath, signer } = makeSink(dir);
    await sink.record({
      sessionId: 'sess-details',
      toolName: 'query_db',
      decision: 'deny',
      denialCode: 'ARGUMENT_VALIDATION_FAILED',
      conditionType: 'argumentSchema',
      details: { path: 'args.sql', expected: 'type:string', got: 'number' },
    });
    await sink.close();

    const [event] = readLines(logPath);
    expect(event!.unmapped).toMatchObject({
      denialCode: 'ARGUMENT_VALIDATION_FAILED',
      conditionType: 'argumentSchema',
      details: { path: 'args.sql', expected: 'type:string', got: 'number' },
    });
    expect(verifyAuditEvent(event!, signer)).toBe(true);
  });

  it('omits details from unmapped when not provided', async () => {
    const { sink, logPath } = makeSink(dir);
    await sink.record({
      sessionId: 'sess-no-details',
      toolName: 'echo',
      decision: 'deny',
      denialCode: 'MAX_CALLS_EXCEEDED',
      conditionType: 'maxCalls',
    });
    await sink.close();

    const [event] = readLines(logPath);
    expect(event!.unmapped).not.toHaveProperty('details');
  });

  it('does not include details on allow records even if supplied', async () => {
    const { sink, logPath } = makeSink(dir);
    await sink.record({
      sessionId: 'sess-allow',
      toolName: 'echo',
      decision: 'allow',
      // details should be ignored for allow decisions
      details: { path: 'args', expected: 'string', got: 'number' },
    });
    await sink.close();

    const [event] = readLines(logPath);
    expect(event!.unmapped).not.toHaveProperty('details');
    expect(event!.unmapped).not.toHaveProperty('denialCode');
  });

  it('HMAC covers the details in unmapped (tampered details fails verify)', async () => {
    const { sink, logPath, signer } = makeSink(dir);
    await sink.record({
      sessionId: 'sess-hmac',
      toolName: 'query_db',
      decision: 'deny',
      denialCode: 'ARGUMENT_VALIDATION_FAILED',
      conditionType: 'argumentSchema',
      details: { path: 'args.x', expected: 'string', got: 'number' },
    });
    await sink.close();

    const [event] = readLines(logPath);
    // Verify original is valid.
    expect(verifyAuditEvent(event!, signer)).toBe(true);

    // Tamper with details and verify that it now fails.
    const tampered = JSON.parse(JSON.stringify(event)) as SignedMcpAuditEvent;
    (tampered.unmapped as Record<string, unknown>)['details'] = { path: 'TAMPERED' };
    expect(verifyAuditEvent(tampered, signer)).toBe(false);
  });

  it('preserves arbitrary nested details structure', async () => {
    const { sink, logPath, signer } = makeSink(dir);
    const nestedDetails = {
      path: 'args.body.items[0].id',
      expected: 'type:string',
      got: 42,
      extra: { nested: true },
    };
    await sink.record({
      sessionId: 'sess-nested',
      toolName: 'create_order',
      decision: 'deny',
      denialCode: 'ARGUMENT_VALIDATION_FAILED',
      conditionType: 'argumentSchema',
      details: nestedDetails,
    });
    await sink.close();

    const [event] = readLines(logPath);
    expect(event!.unmapped['details']).toEqual(nestedDetails);
    expect(verifyAuditEvent(event!, signer)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// obligationsApplied field — redactFields response-path obligation (Task 4)
// ---------------------------------------------------------------------------

describe('LocalAuditSink — obligationsApplied field in unmapped', () => {
  let dir: string;

  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it('writes obligationsApplied into unmapped for an allow record when provided', async () => {
    const { sink, logPath, signer } = makeSink(dir);
    await sink.record({
      sessionId: 'sess-oblig',
      toolName: 'get_user',
      decision: 'allow',
      obligationsApplied: ['redactFields'],
    });
    await sink.close();

    const [event] = readLines(logPath);
    expect(event!.unmapped).toMatchObject({ obligationsApplied: ['redactFields'] });
    expect(verifyAuditEvent(event!, signer)).toBe(true);
  });

  it('omits obligationsApplied from unmapped when not provided', async () => {
    const { sink, logPath } = makeSink(dir);
    await sink.record({ sessionId: 'sess-no-oblig', toolName: 'echo', decision: 'allow' });
    await sink.close();

    const [event] = readLines(logPath);
    expect(event!.unmapped).not.toHaveProperty('obligationsApplied');
  });

  it('omits obligationsApplied on deny records even if supplied', async () => {
    // The sink only records obligationsApplied on allow decisions.
    const { sink, logPath } = makeSink(dir);
    await sink.record({
      sessionId: 'sess-deny',
      toolName: 'echo',
      decision: 'deny',
      denialCode: 'MAX_CALLS_EXCEEDED',
      conditionType: 'maxCalls',
      obligationsApplied: ['redactFields'],
    });
    await sink.close();

    const [event] = readLines(logPath);
    expect(event!.unmapped).not.toHaveProperty('obligationsApplied');
    expect(event!.unmapped).toHaveProperty('denialCode');
  });

  it('obligationsApplied is covered by HMAC (tampering fails verify)', async () => {
    const { sink, logPath, signer } = makeSink(dir);
    await sink.record({
      sessionId: 'sess-tamper',
      toolName: 'get_user',
      decision: 'allow',
      obligationsApplied: ['redactFields'],
    });
    await sink.close();

    const [event] = readLines(logPath);
    expect(verifyAuditEvent(event!, signer)).toBe(true);

    // Tamper: change the obligationsApplied list.
    const tampered = JSON.parse(JSON.stringify(event)) as SignedMcpAuditEvent;
    (tampered.unmapped as Record<string, unknown>)['obligationsApplied'] = ['TAMPERED'];
    expect(verifyAuditEvent(tampered, signer)).toBe(false);
  });

  it('supports multiple obligation names in the array', async () => {
    const { sink, logPath, signer } = makeSink(dir);
    await sink.record({
      sessionId: 'sess-multi',
      toolName: 'export',
      decision: 'allow',
      obligationsApplied: ['redactFields', 'customObligation'],
    });
    await sink.close();

    const [event] = readLines(logPath);
    expect(event!.unmapped['obligationsApplied']).toEqual(['redactFields', 'customObligation']);
    expect(verifyAuditEvent(event!, signer)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// annotateValues field — remote annotate obligation (Task 2 Stage 3)
// ---------------------------------------------------------------------------

describe('LocalAuditSink — annotateValues field in unmapped', () => {
  let dir: string;

  beforeEach(() => { dir = tmpDir(); });
  afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

  it('writes annotateValues into unmapped for an allow record when provided', async () => {
    const { sink, logPath, signer } = makeSink(dir);
    await sink.record({
      sessionId: 'sess-ann',
      toolName: 'get_user',
      decision: 'allow',
      annotateValues: { classification: 'internal', owner: 'team-a' },
    });
    await sink.close();

    const [event] = readLines(logPath);
    expect(event!.unmapped).toMatchObject({
      annotateValues: { classification: 'internal', owner: 'team-a' },
    });
    expect(verifyAuditEvent(event!, signer)).toBe(true);
  });

  it('omits annotateValues from unmapped when not provided', async () => {
    const { sink, logPath } = makeSink(dir);
    await sink.record({ sessionId: 'sess-no-ann', toolName: 'echo', decision: 'allow' });
    await sink.close();

    const [event] = readLines(logPath);
    expect(event!.unmapped).not.toHaveProperty('annotateValues');
  });

  it('omits annotateValues on deny records even if supplied', async () => {
    const { sink, logPath } = makeSink(dir);
    await sink.record({
      sessionId: 'sess-deny-ann',
      toolName: 'echo',
      decision: 'deny',
      denialCode: 'MAX_CALLS_EXCEEDED',
      conditionType: 'maxCalls',
      annotateValues: { classification: 'internal' },
    });
    await sink.close();

    const [event] = readLines(logPath);
    expect(event!.unmapped).not.toHaveProperty('annotateValues');
    expect(event!.unmapped).toHaveProperty('denialCode');
  });

  it('writes both obligationsApplied and annotateValues when both are present', async () => {
    const { sink, logPath, signer } = makeSink(dir);
    await sink.record({
      sessionId: 'sess-both',
      toolName: 'export',
      decision: 'allow',
      obligationsApplied: ['redactFields'],
      annotateValues: { sensitivity: 'high' },
    });
    await sink.close();

    const [event] = readLines(logPath);
    expect(event!.unmapped).toMatchObject({
      obligationsApplied: ['redactFields'],
      annotateValues: { sensitivity: 'high' },
    });
    expect(verifyAuditEvent(event!, signer)).toBe(true);
  });

  it('annotateValues is covered by HMAC (tampering fails verify)', async () => {
    const { sink, logPath, signer } = makeSink(dir);
    await sink.record({
      sessionId: 'sess-tamper-ann',
      toolName: 'get_user',
      decision: 'allow',
      annotateValues: { classification: 'internal' },
    });
    await sink.close();

    const [event] = readLines(logPath);
    expect(verifyAuditEvent(event!, signer)).toBe(true);

    const tampered = JSON.parse(JSON.stringify(event)) as SignedMcpAuditEvent;
    (tampered.unmapped as Record<string, unknown>)['annotateValues'] = { classification: 'TAMPERED' };
    expect(verifyAuditEvent(tampered, signer)).toBe(false);
  });
});
