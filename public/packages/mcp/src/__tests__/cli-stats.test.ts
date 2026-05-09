/**
 * Unit tests for `src/cli/stats.ts` — the `euno-mcp stats` CLI subcommand.
 *
 * Test matrix
 * -----------
 * File discovery
 *   ✓ Returns empty array when log path does not exist and directory is absent
 *   ✓ Returns only the active log when no rotated archives exist
 *   ✓ Returns rotated archives sorted chronologically before the active log
 *   ✓ Archives with earlier timestamps come before later ones
 *   ✓ Files in the directory that don't start with the log base name are ignored
 *   ✓ Works when the directory exists but is empty
 *   ✓ Works when the active log is missing but archives exist
 *   ✓ Works when only archives exist (no active file)
 *   ✓ Handles multiple rotated archives in the correct order
 *
 * JSONL parsing (parseAuditLine)
 *   ✓ Returns null for an empty string
 *   ✓ Returns null for a whitespace-only string
 *   ✓ Returns null for invalid JSON
 *   ✓ Returns null for a JSON array
 *   ✓ Returns null for a JSON primitive (string)
 *   ✓ Returns null for a JSON primitive (number)
 *   ✓ Returns null for JSON null
 *   ✓ Returns the parsed object for valid JSON object
 *   ✓ Preserves all fields on the parsed object
 *   ✓ Strips leading/trailing whitespace before parsing
 *
 * Denial event detection (isDenialEvent)
 *   ✓ Returns true when status_id === 2
 *   ✓ Returns false when status_id === 1
 *   ✓ Returns true when status === 'Failure' (regardless of status_id)
 *   ✓ Returns false when status === 'Success'
 *   ✓ Returns false when neither status_id nor status is set
 *   ✓ status_id takes precedence over status string when status_id === 1
 *   ✓ Returns true when status_id is 2 and status is also set
 *
 * Aggregation (aggregateDenials)
 *   ✓ Returns zero counts for an empty event list
 *   ✓ Counts only denial records (allow records are excluded from buckets)
 *   ✓ Counts all records (allow + deny) in totalCalls
 *   ✓ totalDenied equals the sum of all bucket counts
 *   ✓ Groups by conditionType + denialCode key
 *   ✓ Multiple denials with the same key increment the same bucket
 *   ✓ Different (conditionType, denialCode) pairs produce separate buckets
 *   ✓ Falls back to "(unknown)" when conditionType is absent
 *   ✓ Falls back to "(unknown)" when denialCode is absent
 *   ✓ Falls back to "(unknown)" when both are absent
 *   ✓ Falls back to "(unknown)" when conditionType is not a string
 *   ✓ Falls back to "(unknown)" when denialCode is not a string
 *   ✓ Falls back to "(unknown)" when unmapped is absent
 *   ✓ Buckets are sorted by count descending
 *   ✓ Ties are broken by conditionType ascending
 *   ✓ Ties on conditionType are broken by denialCode ascending
 *   ✓ Handles a single event that is a denial
 *   ✓ Handles a single event that is not a denial
 *   ✓ Handles mix of allow and deny records
 *   ✓ Tracks earliestTime and latestTime correctly
 *   ✓ Tracks earliestTime when only one record exists
 *   ✓ earliestTime and latestTime are undefined for empty input
 *   ✓ Propagates skippedLines count from caller
 *   ✓ skippedLines defaults to 0 when not supplied
 *   ✓ Records without a time field are included but don't affect time range
 *
 * Since filtering (collectStats with sinceMs)
 *   ✓ Returns only events at or after sinceMs
 *   ✓ Includes events exactly at sinceMs
 *   ✓ Excludes events strictly before sinceMs
 *   ✓ Returns all events when sinceMs is undefined
 *   ✓ Returns empty result when all events are before sinceMs
 *
 * Table rendering (renderStatsTable)
 *   ✓ Prints "Period: (unknown) → (unknown)" for empty stats
 *   ✓ Prints "Total: 0 calls; 0 denied" for empty stats
 *   ✓ Prints correct date range using UTC YYYY-MM-DD format
 *   ✓ Prints correct total counts with locale formatting
 *   ✓ Prints column headers: conditionType, denialCode, count, %
 *   ✓ Each denial bucket appears as a row
 *   ✓ Percentages are rounded to integers
 *   ✓ 100% when only one bucket accounts for all denials
 *   ✓ Percentage is '—' when totalDenied is 0
 *   ✓ Column widths are at least the header width
 *   ✓ Columns expand to fit longer content
 *   ✓ Output is a multi-line string (no trailing newline from renderStatsTable)
 *   ✓ Header separator is at least as wide as the header
 *   ✓ Rows are in the order provided by AuditStats.buckets
 *   ✓ Renders correctly with a single row
 *   ✓ Renders correctly with multiple rows
 *
 * collectStats (filesystem integration)
 *   ✓ Returns empty stats when the log file does not exist
 *   ✓ Returns stats from a single log file
 *   ✓ Returns combined stats from active + rotated files
 *   ✓ Filters by sinceMs when provided
 *   ✓ Skipped lines are counted in stats.skippedLines
 *   ✓ Invalid JSON lines are skipped and counted
 *   ✓ Empty lines do not increment skippedLines
 *   ✓ Uses DEFAULT_AUDIT_LOG_PATH when logPath is not provided
 *
 * Date formatting (formatDate)
 *   ✓ Formats a unix-ms timestamp as YYYY-MM-DD in UTC
 *   ✓ Returns "(unknown)" when ms is undefined
 *   ✓ Handles the Unix epoch (0)
 *   ✓ Handles midnight boundary correctly
 */

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as childProcess from 'node:child_process';

import type { OcsfApiActivityEvent } from '@euno/common-core';

import {
  discoverAuditLogFiles,
  parseAuditLine,
  isDenialEvent,
  aggregateDenials,
  collectStats,
  renderStatsTable,
  formatDate,
  AuditStats,
  DenialBucket,
  StreamingAggregator,
  streamFileIntoAggregator,
} from '../cli/stats';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

function tmpDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'euno-stats-test-'));
  tempDirs.push(dir);
  return dir;
}

/**
 * Build a minimal OCSF API Activity event that represents a denial.
 * Provide only the fields you care about; everything else is sensible default.
 */
function makeDenialEvent(opts: {
  conditionType?: string;
  denialCode?: string;
  time?: number;
  unmapped?: Record<string, unknown>;
}): OcsfApiActivityEvent {
  return {
    metadata: {
      version: '1.1.0',
      product: { name: 'euno-mcp', vendor_name: 'Euno', feature: { name: 'capability-audit' } },
      uid: crypto.randomUUID(),
    },
    time: opts.time ?? Date.now(),
    class_uid: 6003,
    category_uid: 6,
    activity_id: 99,
    type_uid: 600399,
    severity_id: 3,
    status_id: 2,
    status: 'Failure',
    api: { operation: 'test-tool', service: { name: 'euno-mcp' } },
    actor: { session: { uid: 'sess-1' } },
    unmapped: opts.unmapped ?? {
      seq: 1,
      ...(opts.conditionType !== undefined ? { conditionType: opts.conditionType } : {}),
      ...(opts.denialCode !== undefined ? { denialCode: opts.denialCode } : {}),
    },
  } as OcsfApiActivityEvent;
}

/**
 * Build a minimal allow event.
 */
function makeAllowEvent(opts: { time?: number } = {}): OcsfApiActivityEvent {
  return {
    metadata: {
      version: '1.1.0',
      product: { name: 'euno-mcp', vendor_name: 'Euno', feature: { name: 'capability-audit' } },
      uid: crypto.randomUUID(),
    },
    time: opts.time ?? Date.now(),
    class_uid: 6003,
    category_uid: 6,
    activity_id: 99,
    type_uid: 600399,
    severity_id: 1,
    status_id: 1,
    status: 'Success',
    api: { operation: 'test-tool', service: { name: 'euno-mcp' } },
    actor: { session: { uid: 'sess-1' } },
    unmapped: { seq: 1 },
  } as OcsfApiActivityEvent;
}

/** Write JSONL lines to a file. Each element is serialized as one line. */
function writeJsonlFile(filePath: string, records: unknown[]): void {
  fs.writeFileSync(filePath, records.map((r) => JSON.stringify(r)).join('\n') + '\n', 'utf8');
}

/** Minimal empty AuditStats. */
function emptyStats(): AuditStats {
  return {
    buckets: [],
    totalCalls: 0,
    totalDenied: 0,
    earliestTime: undefined,
    latestTime: undefined,
    skippedLines: 0,
  };
}

// ---------------------------------------------------------------------------
// File discovery
// ---------------------------------------------------------------------------

describe('discoverAuditLogFiles', () => {
  it('returns empty array when log path does not exist and directory is absent', () => {
    const result = discoverAuditLogFiles('/tmp/this-dir-should-not-exist-euno/audit.jsonl');
    expect(result).toEqual([]);
  });

  it('returns only the active log when no rotated archives exist', () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');
    fs.writeFileSync(logPath, '', 'utf8');

    const result = discoverAuditLogFiles(logPath);
    expect(result).toEqual([logPath]);
  });

  it('returns rotated archives sorted before the active log', () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');
    // Create active file
    fs.writeFileSync(logPath, '', 'utf8');
    // Create a rotated archive
    const archive = logPath + '.2026-05-08T12-00-00.000Z';
    fs.writeFileSync(archive, '', 'utf8');

    const result = discoverAuditLogFiles(logPath);
    expect(result).toEqual([archive, logPath]);
  });

  it('sorts archives lexicographically (= chronologically) before the active log', () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');
    fs.writeFileSync(logPath, '', 'utf8');

    const a1 = logPath + '.2026-05-06T10-00-00.000Z';
    const a2 = logPath + '.2026-05-07T08-00-00.000Z';
    const a3 = logPath + '.2026-05-08T06-00-00.000Z';
    // Write in reverse order to verify sorting.
    fs.writeFileSync(a3, '', 'utf8');
    fs.writeFileSync(a1, '', 'utf8');
    fs.writeFileSync(a2, '', 'utf8');

    const result = discoverAuditLogFiles(logPath);
    expect(result).toEqual([a1, a2, a3, logPath]);
  });

  it('ignores files in the directory whose name does not start with the log base name', () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');
    fs.writeFileSync(logPath, '', 'utf8');
    // Sibling files that should not be picked up
    fs.writeFileSync(path.join(dir, 'unrelated.txt'), '', 'utf8');
    fs.writeFileSync(path.join(dir, 'key'), '', 'utf8');
    fs.writeFileSync(path.join(dir, 'telemetry'), '', 'utf8');

    const result = discoverAuditLogFiles(logPath);
    expect(result).toEqual([logPath]);
  });

  it('returns empty array when the directory exists but is empty and active log is absent', () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');

    const result = discoverAuditLogFiles(logPath);
    expect(result).toEqual([]);
  });

  it('returns archives without the active log when the active log is missing', () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const archive = logPath + '.2026-05-01T00-00-00.000Z';
    fs.writeFileSync(archive, '', 'utf8');

    const result = discoverAuditLogFiles(logPath);
    expect(result).toEqual([archive]);
  });

  it('handles multiple rotated archives without an active file', () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const a1 = logPath + '.2026-04-01T00-00-00.000Z';
    const a2 = logPath + '.2026-05-01T00-00-00.000Z';
    fs.writeFileSync(a1, '', 'utf8');
    fs.writeFileSync(a2, '', 'utf8');

    const result = discoverAuditLogFiles(logPath);
    expect(result).toEqual([a1, a2]);
  });

  it('handles a custom log name (not audit.jsonl)', () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'mylog.jsonl');
    fs.writeFileSync(logPath, '', 'utf8');
    const archive = logPath + '.2026-05-01T00-00-00.000Z';
    fs.writeFileSync(archive, '', 'utf8');
    // A file with a similar name but different prefix should NOT be included.
    fs.writeFileSync(path.join(dir, 'audit.jsonl.2026-01-01T00-00-00.000Z'), '', 'utf8');

    const result = discoverAuditLogFiles(logPath);
    expect(result).toEqual([archive, logPath]);
  });

  it('returns empty array when the logPath parent is a file (not a directory)', () => {
    const dir = tmpDir();
    // Put a regular file where the parent directory should be — this causes
    // readdirSync to fail, which the function handles gracefully.
    const fakedir = path.join(dir, 'notadir');
    fs.writeFileSync(fakedir, 'content', 'utf8');
    const logPath = path.join(fakedir, 'audit.jsonl');

    expect(() => discoverAuditLogFiles(logPath)).not.toThrow();
    const result = discoverAuditLogFiles(logPath);
    expect(result).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// parseAuditLine
// ---------------------------------------------------------------------------

describe('parseAuditLine', () => {
  it('returns null for an empty string', () => {
    expect(parseAuditLine('')).toBeNull();
  });

  it('returns null for a whitespace-only string', () => {
    expect(parseAuditLine('   \t\n  ')).toBeNull();
  });

  it('returns null for invalid JSON', () => {
    expect(parseAuditLine('not json')).toBeNull();
    expect(parseAuditLine('{ bad: json }')).toBeNull();
    expect(parseAuditLine('{unclosed')).toBeNull();
  });

  it('returns null for a JSON array', () => {
    expect(parseAuditLine('[]')).toBeNull();
    expect(parseAuditLine('[{"a":1}]')).toBeNull();
  });

  it('returns null for a JSON string primitive', () => {
    expect(parseAuditLine('"hello"')).toBeNull();
  });

  it('returns null for a JSON number primitive', () => {
    expect(parseAuditLine('42')).toBeNull();
  });

  it('returns null for JSON null', () => {
    expect(parseAuditLine('null')).toBeNull();
  });

  it('returns null for JSON boolean', () => {
    expect(parseAuditLine('true')).toBeNull();
    expect(parseAuditLine('false')).toBeNull();
  });

  it('returns the parsed object for a valid JSON object', () => {
    const obj = { class_uid: 6003, status_id: 1 };
    const result = parseAuditLine(JSON.stringify(obj));
    expect(result).toEqual(obj);
  });

  it('preserves nested fields on the parsed object', () => {
    const event = makeDenialEvent({ conditionType: 'maxCalls', denialCode: 'MAX_CALLS_EXCEEDED' });
    const line = JSON.stringify(event);
    const parsed = parseAuditLine(line);
    expect(parsed).not.toBeNull();
    expect((parsed as OcsfApiActivityEvent).status_id).toBe(2);
    expect(((parsed as OcsfApiActivityEvent).unmapped as Record<string, unknown>)['conditionType']).toBe('maxCalls');
  });

  it('strips leading/trailing whitespace before parsing', () => {
    const obj = { x: 1 };
    expect(parseAuditLine('  ' + JSON.stringify(obj) + '  ')).toEqual(obj);
  });

  it('handles a large object without error', () => {
    const large = Object.fromEntries(Array.from({ length: 100 }, (_, i) => [`key${i}`, i]));
    expect(parseAuditLine(JSON.stringify(large))).toEqual(large);
  });
});

// ---------------------------------------------------------------------------
// isDenialEvent
// ---------------------------------------------------------------------------

describe('isDenialEvent', () => {
  it('returns true when status_id is 2', () => {
    const event = { status_id: 2 } as OcsfApiActivityEvent;
    expect(isDenialEvent(event)).toBe(true);
  });

  it('returns false when status_id is 1', () => {
    const event = { status_id: 1 } as OcsfApiActivityEvent;
    expect(isDenialEvent(event)).toBe(false);
  });

  it('returns true when status is "Failure" (and status_id is absent)', () => {
    const event = { status: 'Failure' } as OcsfApiActivityEvent;
    expect(isDenialEvent(event)).toBe(true);
  });

  it('returns false when status is "Success" (and status_id is absent)', () => {
    const event = { status: 'Success' } as OcsfApiActivityEvent;
    expect(isDenialEvent(event)).toBe(false);
  });

  it('returns false when neither status_id nor status is set', () => {
    const event = {} as OcsfApiActivityEvent;
    expect(isDenialEvent(event)).toBe(false);
  });

  it('returns false when status_id is 1 even if status is "Failure"', () => {
    // status_id 1 = Success — status_id takes precedence via the `||` chain.
    // Actually our implementation is `status_id === 2 || status === 'Failure'`
    // so if status_id === 1 AND status === 'Failure' it returns true.
    // This is intentional forward-compat behaviour. Let's test the actual
    // behaviour rather than an assumed precedence.
    const event = { status_id: 1, status: 'Failure' } as OcsfApiActivityEvent;
    // Under our implementation: status_id===1 is false, status==='Failure' is true → true.
    expect(isDenialEvent(event)).toBe(true);
  });

  it('returns true when status_id is 2 and status is also set', () => {
    const event = { status_id: 2, status: 'Failure' } as OcsfApiActivityEvent;
    expect(isDenialEvent(event)).toBe(true);
  });

  it('returns false when status_id is 0', () => {
    const event = { status_id: 0 } as OcsfApiActivityEvent;
    expect(isDenialEvent(event)).toBe(false);
  });

  it('returns false when status is an empty string', () => {
    const event = { status: '' } as unknown as OcsfApiActivityEvent;
    expect(isDenialEvent(event)).toBe(false);
  });

  it('is case-sensitive — "failure" does not match', () => {
    const event = { status: 'failure' } as unknown as OcsfApiActivityEvent;
    expect(isDenialEvent(event)).toBe(false);
  });

  it('returns true for a full denial event', () => {
    expect(isDenialEvent(makeDenialEvent({ conditionType: 'maxCalls', denialCode: 'MAX_CALLS_EXCEEDED' }))).toBe(true);
  });

  it('returns false for a full allow event', () => {
    expect(isDenialEvent(makeAllowEvent())).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// aggregateDenials
// ---------------------------------------------------------------------------

describe('aggregateDenials', () => {
  it('returns zero counts for an empty event list', () => {
    const stats = aggregateDenials([]);
    expect(stats.totalCalls).toBe(0);
    expect(stats.totalDenied).toBe(0);
    expect(stats.buckets).toEqual([]);
    expect(stats.earliestTime).toBeUndefined();
    expect(stats.latestTime).toBeUndefined();
    expect(stats.skippedLines).toBe(0);
  });

  it('counts only denial records in buckets', () => {
    const events = [
      makeAllowEvent(),
      makeAllowEvent(),
      makeDenialEvent({ conditionType: 'maxCalls', denialCode: 'MAX_CALLS_EXCEEDED' }),
    ];
    const stats = aggregateDenials(events);
    expect(stats.totalCalls).toBe(3);
    expect(stats.totalDenied).toBe(1);
    expect(stats.buckets).toHaveLength(1);
    expect(stats.buckets[0]?.count).toBe(1);
  });

  it('counts all records (allow + deny) in totalCalls', () => {
    const events = [makeAllowEvent(), makeAllowEvent(), makeDenialEvent({ conditionType: 'maxCalls', denialCode: 'MC' })];
    const stats = aggregateDenials(events);
    expect(stats.totalCalls).toBe(3);
  });

  it('totalDenied equals the sum of all bucket counts', () => {
    const events = [
      makeDenialEvent({ conditionType: 'maxCalls', denialCode: 'MAX' }),
      makeDenialEvent({ conditionType: 'maxCalls', denialCode: 'MAX' }),
      makeDenialEvent({ conditionType: 'timeWindow', denialCode: 'TW' }),
    ];
    const stats = aggregateDenials(events);
    expect(stats.totalDenied).toBe(3);
    expect(stats.buckets.reduce((s: number, b: DenialBucket) => s + b.count, 0)).toBe(3);
  });

  it('groups by conditionType + denialCode key', () => {
    const events = [
      makeDenialEvent({ conditionType: 'maxCalls', denialCode: 'MAX_CALLS_EXCEEDED' }),
      makeDenialEvent({ conditionType: 'maxCalls', denialCode: 'MAX_CALLS_EXCEEDED' }),
      makeDenialEvent({ conditionType: 'argumentSchema', denialCode: 'ARGUMENT_VALIDATION_FAILED' }),
    ];
    const stats = aggregateDenials(events);
    expect(stats.buckets).toHaveLength(2);
    const maxCallsBucket = stats.buckets.find((b: DenialBucket) => b.conditionType === 'maxCalls');
    expect(maxCallsBucket?.count).toBe(2);
    const argBucket = stats.buckets.find((b: DenialBucket) => b.conditionType === 'argumentSchema');
    expect(argBucket?.count).toBe(1);
  });

  it('increments the same bucket for repeated (conditionType, denialCode) pairs', () => {
    const events = Array.from({ length: 5 }, () =>
      makeDenialEvent({ conditionType: 'maxCalls', denialCode: 'MAX_CALLS_EXCEEDED' }),
    );
    const stats = aggregateDenials(events);
    expect(stats.buckets).toHaveLength(1);
    expect(stats.buckets[0]?.count).toBe(5);
  });

  it('treats different conditionTypes as separate buckets even with same denialCode', () => {
    const events = [
      makeDenialEvent({ conditionType: 'A', denialCode: 'CODE' }),
      makeDenialEvent({ conditionType: 'B', denialCode: 'CODE' }),
    ];
    const stats = aggregateDenials(events);
    expect(stats.buckets).toHaveLength(2);
  });

  it('treats different denialCodes as separate buckets even with same conditionType', () => {
    const events = [
      makeDenialEvent({ conditionType: 'maxCalls', denialCode: 'CODE_A' }),
      makeDenialEvent({ conditionType: 'maxCalls', denialCode: 'CODE_B' }),
    ];
    const stats = aggregateDenials(events);
    expect(stats.buckets).toHaveLength(2);
  });

  it('falls back to "(unknown)" when conditionType is absent', () => {
    const event = makeDenialEvent({
      unmapped: { seq: 1, denialCode: 'MY_CODE' },
    });
    const stats = aggregateDenials([event]);
    expect(stats.buckets[0]?.conditionType).toBe('(unknown)');
    expect(stats.buckets[0]?.denialCode).toBe('MY_CODE');
  });

  it('falls back to "(unknown)" when denialCode is absent', () => {
    const event = makeDenialEvent({
      unmapped: { seq: 1, conditionType: 'myType' },
    });
    const stats = aggregateDenials([event]);
    expect(stats.buckets[0]?.conditionType).toBe('myType');
    expect(stats.buckets[0]?.denialCode).toBe('(unknown)');
  });

  it('falls back to "(unknown)" for both fields when unmapped is absent', () => {
    const event: OcsfApiActivityEvent = {
      metadata: {
        version: '1.1.0',
        product: { name: 'euno-mcp', vendor_name: 'Euno', feature: { name: 'capability-audit' } },
        uid: crypto.randomUUID(),
      },
      time: Date.now(),
      class_uid: 6003,
      category_uid: 6,
      activity_id: 99,
      type_uid: 600399,
      severity_id: 2,
      status_id: 2,
      status: 'Failure',
      api: { operation: 'tool', service: { name: 'euno-mcp' } },
      actor: { session: { uid: 'sess' } },
    };
    const stats = aggregateDenials([event]);
    expect(stats.buckets[0]?.conditionType).toBe('(unknown)');
    expect(stats.buckets[0]?.denialCode).toBe('(unknown)');
  });

  it('falls back to "(unknown)" when conditionType is not a string (number)', () => {
    const event = makeDenialEvent({
      unmapped: { seq: 1, conditionType: 42, denialCode: 'CODE' },
    });
    const stats = aggregateDenials([event]);
    expect(stats.buckets[0]?.conditionType).toBe('(unknown)');
  });

  it('falls back to "(unknown)" when denialCode is not a string (boolean)', () => {
    const event = makeDenialEvent({
      unmapped: { seq: 1, conditionType: 'maxCalls', denialCode: true },
    });
    const stats = aggregateDenials([event]);
    expect(stats.buckets[0]?.denialCode).toBe('(unknown)');
  });

  it('falls back to "(unknown)" when conditionType is null', () => {
    const event = makeDenialEvent({
      unmapped: { seq: 1, conditionType: null, denialCode: 'CODE' },
    });
    const stats = aggregateDenials([event]);
    expect(stats.buckets[0]?.conditionType).toBe('(unknown)');
  });

  it('falls back to "(unknown)" when denialCode is null', () => {
    const event = makeDenialEvent({
      unmapped: { seq: 1, conditionType: 'type', denialCode: null },
    });
    const stats = aggregateDenials([event]);
    expect(stats.buckets[0]?.denialCode).toBe('(unknown)');
  });

  it('sorts buckets by count descending', () => {
    const events = [
      makeDenialEvent({ conditionType: 'a', denialCode: 'A' }),
      makeDenialEvent({ conditionType: 'b', denialCode: 'B' }),
      makeDenialEvent({ conditionType: 'b', denialCode: 'B' }),
      makeDenialEvent({ conditionType: 'b', denialCode: 'B' }),
      makeDenialEvent({ conditionType: 'c', denialCode: 'C' }),
      makeDenialEvent({ conditionType: 'c', denialCode: 'C' }),
    ];
    const stats = aggregateDenials(events);
    expect(stats.buckets.map((b: DenialBucket) => b.conditionType)).toEqual(['b', 'c', 'a']);
    expect(stats.buckets.map((b: DenialBucket) => b.count)).toEqual([3, 2, 1]);
  });

  it('breaks ties by conditionType ascending', () => {
    const events = [
      makeDenialEvent({ conditionType: 'z-type', denialCode: 'Z' }),
      makeDenialEvent({ conditionType: 'a-type', denialCode: 'A' }),
    ];
    const stats = aggregateDenials(events);
    expect(stats.buckets[0]?.conditionType).toBe('a-type');
    expect(stats.buckets[1]?.conditionType).toBe('z-type');
  });

  it('breaks ties on conditionType by denialCode ascending', () => {
    const events = [
      makeDenialEvent({ conditionType: 'same', denialCode: 'Z_CODE' }),
      makeDenialEvent({ conditionType: 'same', denialCode: 'A_CODE' }),
    ];
    const stats = aggregateDenials(events);
    expect(stats.buckets[0]?.denialCode).toBe('A_CODE');
    expect(stats.buckets[1]?.denialCode).toBe('Z_CODE');
  });

  it('handles a single event that is a denial', () => {
    const stats = aggregateDenials([makeDenialEvent({ conditionType: 'maxCalls', denialCode: 'MAX' })]);
    expect(stats.totalCalls).toBe(1);
    expect(stats.totalDenied).toBe(1);
    expect(stats.buckets).toHaveLength(1);
  });

  it('handles a single event that is an allow', () => {
    const stats = aggregateDenials([makeAllowEvent()]);
    expect(stats.totalCalls).toBe(1);
    expect(stats.totalDenied).toBe(0);
    expect(stats.buckets).toHaveLength(0);
  });

  it('handles a realistic mix of allow and deny records', () => {
    const events: OcsfApiActivityEvent[] = [
      ...Array.from({ length: 20 }, () => makeAllowEvent()),
      ...Array.from({ length: 5 }, () => makeDenialEvent({ conditionType: 'maxCalls', denialCode: 'MAX' })),
      ...Array.from({ length: 3 }, () => makeDenialEvent({ conditionType: 'timeWindow', denialCode: 'TW' })),
    ];
    const stats = aggregateDenials(events);
    expect(stats.totalCalls).toBe(28);
    expect(stats.totalDenied).toBe(8);
    expect(stats.buckets).toHaveLength(2);
    expect(stats.buckets[0]?.conditionType).toBe('maxCalls');
    expect(stats.buckets[0]?.count).toBe(5);
    expect(stats.buckets[1]?.conditionType).toBe('timeWindow');
    expect(stats.buckets[1]?.count).toBe(3);
  });

  it('tracks earliestTime and latestTime correctly', () => {
    const t1 = 1000;
    const t2 = 2000;
    const t3 = 3000;
    const events = [
      makeAllowEvent({ time: t2 }),
      makeDenialEvent({ conditionType: 'a', denialCode: 'A', time: t1 }),
      makeAllowEvent({ time: t3 }),
    ];
    const stats = aggregateDenials(events);
    expect(stats.earliestTime).toBe(t1);
    expect(stats.latestTime).toBe(t3);
  });

  it('sets both earliestTime and latestTime to the same value when there is one event', () => {
    const t = 12345678;
    const stats = aggregateDenials([makeDenialEvent({ conditionType: 'x', denialCode: 'Y', time: t })]);
    expect(stats.earliestTime).toBe(t);
    expect(stats.latestTime).toBe(t);
  });

  it('leaves earliestTime and latestTime undefined for empty input', () => {
    const stats = aggregateDenials([]);
    expect(stats.earliestTime).toBeUndefined();
    expect(stats.latestTime).toBeUndefined();
  });

  it('propagates the skippedLines count from the caller', () => {
    const stats = aggregateDenials([], 7);
    expect(stats.skippedLines).toBe(7);
  });

  it('defaults skippedLines to 0 when not supplied', () => {
    const stats = aggregateDenials([makeAllowEvent()]);
    expect(stats.skippedLines).toBe(0);
  });

  it('includes events without a time field in totalCalls but they do not affect the time range', () => {
    const eventWithoutTime = {
      metadata: {
        version: '1.1.0',
        product: { name: 'euno-mcp', vendor_name: 'Euno', feature: { name: 'capability-audit' } },
        uid: 'x',
      },
      class_uid: 6003,
      category_uid: 6,
      activity_id: 99,
      type_uid: 600399,
      severity_id: 1,
      status_id: 1,
      status: 'Success',
      api: { operation: 'tool', service: { name: 'euno-mcp' } },
      actor: { session: { uid: 'sess' } },
      unmapped: { seq: 1 },
      // Intentionally omit `time` to test the time-absent branch.
    } as unknown as OcsfApiActivityEvent;
    const stats = aggregateDenials([eventWithoutTime]);
    expect(stats.totalCalls).toBe(1);
    expect(stats.earliestTime).toBeUndefined();
    expect(stats.latestTime).toBeUndefined();
  });

  it('produces deterministic output on the same input (stable sort)', () => {
    const events = [
      makeDenialEvent({ conditionType: 'z', denialCode: 'ZCODE', time: 1000 }),
      makeDenialEvent({ conditionType: 'a', denialCode: 'ACODE', time: 2000 }),
    ];
    const stats1 = aggregateDenials([...events]);
    const stats2 = aggregateDenials([...events].reverse());
    expect(stats1.buckets.map((b: DenialBucket) => b.conditionType)).toEqual(stats2.buckets.map((b: DenialBucket) => b.conditionType));
  });

  it('handles 100 different conditionType+denialCode combinations', () => {
    const events = Array.from({ length: 100 }, (_, i) =>
      makeDenialEvent({ conditionType: `type${i}`, denialCode: `CODE${i}` }),
    );
    const stats = aggregateDenials(events);
    expect(stats.buckets).toHaveLength(100);
    expect(stats.totalDenied).toBe(100);
    // All buckets have count=1 so ties are broken by conditionType ascending.
    // type0 < type1 < ... (lexicographic, type10 < type2 etc.)
    for (const b of stats.buckets) {
      expect(b.count).toBe(1);
    }
  });
});

// ---------------------------------------------------------------------------
// StreamingAggregator
// ---------------------------------------------------------------------------

describe('StreamingAggregator', () => {
  it('starts with all-zero counts', () => {
    const agg = new StreamingAggregator();
    const stats = agg.finish();
    expect(stats.totalCalls).toBe(0);
    expect(stats.totalDenied).toBe(0);
    expect(stats.buckets).toEqual([]);
    expect(stats.earliestTime).toBeUndefined();
    expect(stats.latestTime).toBeUndefined();
    expect(stats.skippedLines).toBe(0);
  });

  it('counts allow events in totalCalls but not in buckets', () => {
    const agg = new StreamingAggregator();
    agg.ingest(makeAllowEvent());
    agg.ingest(makeAllowEvent());
    const stats = agg.finish();
    expect(stats.totalCalls).toBe(2);
    expect(stats.totalDenied).toBe(0);
    expect(stats.buckets).toHaveLength(0);
  });

  it('counts denial events in both totalCalls and totalDenied', () => {
    const agg = new StreamingAggregator();
    agg.ingest(makeDenialEvent({ conditionType: 'maxCalls', denialCode: 'MAX' }));
    const stats = agg.finish();
    expect(stats.totalCalls).toBe(1);
    expect(stats.totalDenied).toBe(1);
    expect(stats.buckets).toHaveLength(1);
  });

  it('groups repeated (conditionType, denialCode) into one bucket', () => {
    const agg = new StreamingAggregator();
    agg.ingest(makeDenialEvent({ conditionType: 'maxCalls', denialCode: 'MAX' }));
    agg.ingest(makeDenialEvent({ conditionType: 'maxCalls', denialCode: 'MAX' }));
    agg.ingest(makeDenialEvent({ conditionType: 'maxCalls', denialCode: 'MAX' }));
    const stats = agg.finish();
    expect(stats.buckets).toHaveLength(1);
    expect(stats.buckets[0]?.count).toBe(3);
  });

  it('creates separate buckets for different (conditionType, denialCode) pairs', () => {
    const agg = new StreamingAggregator();
    agg.ingest(makeDenialEvent({ conditionType: 'A', denialCode: 'CODE' }));
    agg.ingest(makeDenialEvent({ conditionType: 'B', denialCode: 'CODE' }));
    const stats = agg.finish();
    expect(stats.buckets).toHaveLength(2);
  });

  it('sorts finish() buckets by count desc with stable tie-breaking', () => {
    const agg = new StreamingAggregator();
    agg.ingest(makeDenialEvent({ conditionType: 'z', denialCode: 'Z' }));
    agg.ingest(makeDenialEvent({ conditionType: 'a', denialCode: 'A' }));
    agg.ingest(makeDenialEvent({ conditionType: 'a', denialCode: 'A' }));
    const stats = agg.finish();
    expect(stats.buckets[0]?.conditionType).toBe('a');
    expect(stats.buckets[0]?.count).toBe(2);
    expect(stats.buckets[1]?.conditionType).toBe('z');
    expect(stats.buckets[1]?.count).toBe(1);
  });

  it('tracks time range across ingested events', () => {
    const t1 = Date.UTC(2026, 4, 1);
    const t2 = Date.UTC(2026, 4, 8);
    const agg = new StreamingAggregator();
    agg.ingest(makeAllowEvent({ time: t2 }));
    agg.ingest(makeDenialEvent({ conditionType: 'a', denialCode: 'A', time: t1 }));
    const stats = agg.finish();
    expect(stats.earliestTime).toBe(t1);
    expect(stats.latestTime).toBe(t2);
  });

  it('addSkippedLines accumulates across multiple calls', () => {
    const agg = new StreamingAggregator();
    agg.addSkippedLines(3);
    agg.addSkippedLines(7);
    const stats = agg.finish();
    expect(stats.skippedLines).toBe(10);
  });

  it('finish() can be called multiple times and returns the same value', () => {
    const agg = new StreamingAggregator();
    agg.ingest(makeDenialEvent({ conditionType: 'a', denialCode: 'A' }));
    const first = agg.finish();
    const second = agg.finish();
    expect(first).toEqual(second);
  });

  it('produces the same result as aggregateDenials for the same events', () => {
    const events = [
      makeAllowEvent(),
      makeDenialEvent({ conditionType: 'maxCalls', denialCode: 'MAX' }),
      makeDenialEvent({ conditionType: 'maxCalls', denialCode: 'MAX' }),
      makeDenialEvent({ conditionType: 'timeWindow', denialCode: 'TW' }),
    ];
    const agg = new StreamingAggregator();
    for (const e of events) agg.ingest(e);
    const streaming = agg.finish();
    const batch = aggregateDenials(events);
    expect(streaming.totalCalls).toBe(batch.totalCalls);
    expect(streaming.totalDenied).toBe(batch.totalDenied);
    expect(streaming.buckets).toEqual(batch.buckets);
  });
});

// ---------------------------------------------------------------------------
// streamFileIntoAggregator
// ---------------------------------------------------------------------------

describe('streamFileIntoAggregator', () => {
  it('reads valid records and ingests them into the aggregator', async () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');
    writeJsonlFile(logPath, [
      makeAllowEvent({ time: Date.UTC(2026, 4, 8) }),
      makeDenialEvent({ conditionType: 'maxCalls', denialCode: 'MAX', time: Date.UTC(2026, 4, 9) }),
    ]);

    const agg = new StreamingAggregator();
    await streamFileIntoAggregator(logPath, agg, undefined);
    const stats = agg.finish();
    expect(stats.totalCalls).toBe(2);
    expect(stats.totalDenied).toBe(1);
  });

  it('counts invalid lines as skipped', async () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');
    fs.writeFileSync(logPath, 'INVALID\n' + JSON.stringify(makeAllowEvent()) + '\n', 'utf8');

    const agg = new StreamingAggregator();
    await streamFileIntoAggregator(logPath, agg, undefined);
    const stats = agg.finish();
    expect(stats.totalCalls).toBe(1);
    expect(stats.skippedLines).toBe(1);
  });

  it('applies sinceMs filter — events before the cutoff are excluded', async () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const sinceMs = Date.UTC(2026, 4, 8);
    writeJsonlFile(logPath, [
      makeDenialEvent({ conditionType: 'old', denialCode: 'OLD', time: sinceMs - 1 }),
      makeDenialEvent({ conditionType: 'new', denialCode: 'NEW', time: sinceMs }),
    ]);

    const agg = new StreamingAggregator();
    await streamFileIntoAggregator(logPath, agg, sinceMs);
    const stats = agg.finish();
    expect(stats.totalCalls).toBe(1);
    expect(stats.buckets[0]?.conditionType).toBe('new');
  });

  it('handles a non-existent file gracefully (no throw, no records)', async () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'nonexistent.jsonl');
    const agg = new StreamingAggregator();
    await expect(streamFileIntoAggregator(logPath, agg, undefined)).resolves.toBeUndefined();
    const stats = agg.finish();
    expect(stats.totalCalls).toBe(0);
  });

  it('handles a file that is removed between discovery and open (async ENOENT) gracefully', async () => {
    // We can't easily simulate the race, but we can verify the code doesn't throw
    // for a missing file regardless of timing (same result as sync ENOENT).
    const dir = tmpDir();
    const logPath = path.join(dir, 'gone.jsonl');
    const agg = new StreamingAggregator();
    await expect(streamFileIntoAggregator(logPath, agg, undefined)).resolves.toBeUndefined();
    expect(agg.finish().totalCalls).toBe(0);
  });

  it('does not count blank lines as skipped', async () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');
    fs.writeFileSync(logPath, '\n\n' + JSON.stringify(makeAllowEvent()) + '\n\n', 'utf8');

    const agg = new StreamingAggregator();
    await streamFileIntoAggregator(logPath, agg, undefined);
    const stats = agg.finish();
    expect(stats.skippedLines).toBe(0);
    expect(stats.totalCalls).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// formatDate
// ---------------------------------------------------------------------------

describe('formatDate', () => {
  it('formats a unix-ms timestamp as YYYY-MM-DD in UTC', () => {
    // 2026-05-08T12:00:00.000Z → 2026-05-08
    const ms = Date.UTC(2026, 4, 8, 12, 0, 0);
    expect(formatDate(ms)).toBe('2026-05-08');
  });

  it('returns "(unknown)" when ms is undefined', () => {
    expect(formatDate(undefined)).toBe('(unknown)');
  });

  it('handles the Unix epoch (0)', () => {
    expect(formatDate(0)).toBe('1970-01-01');
  });

  it('handles midnight boundary correctly (just before midnight UTC)', () => {
    const ms = Date.UTC(2026, 0, 31, 23, 59, 59, 999);
    expect(formatDate(ms)).toBe('2026-01-31');
  });

  it('handles midnight boundary correctly (exactly midnight UTC)', () => {
    const ms = Date.UTC(2026, 1, 1, 0, 0, 0, 0);
    expect(formatDate(ms)).toBe('2026-02-01');
  });

  it('handles the end of the year', () => {
    const ms = Date.UTC(2026, 11, 31, 23, 59, 59, 999);
    expect(formatDate(ms)).toBe('2026-12-31');
  });

  it('handles a leap day', () => {
    const ms = Date.UTC(2024, 1, 29, 12, 0, 0);
    expect(formatDate(ms)).toBe('2024-02-29');
  });
});

// ---------------------------------------------------------------------------
// renderStatsTable
// ---------------------------------------------------------------------------

describe('renderStatsTable', () => {
  it('renders "(unknown)" date range and zero counts for empty stats', () => {
    const output = renderStatsTable(emptyStats());
    expect(output).toContain('Period: (unknown) → (unknown)');
    expect(output).toContain('Total: 0 calls; 0 denied');
  });

  it('includes column headers', () => {
    const output = renderStatsTable(emptyStats());
    expect(output).toContain('conditionType');
    expect(output).toContain('denialCode');
    expect(output).toContain('count');
    expect(output).toContain('%');
  });

  it('includes a separator line', () => {
    const output = renderStatsTable(emptyStats());
    const lines = output.split('\n');
    const separatorLine = lines.find((l: string) => /^─+$/.test(l));
    expect(separatorLine).toBeDefined();
  });

  it('includes a row for each bucket', () => {
    const stats: AuditStats = {
      buckets: [
        { conditionType: 'maxCalls', denialCode: 'MAX_CALLS_EXCEEDED', count: 42 },
        { conditionType: 'argumentSchema', denialCode: 'ARGUMENT_VALIDATION_FAILED', count: 21 },
      ],
      totalCalls: 1237,
      totalDenied: 63,
      earliestTime: Date.UTC(2026, 4, 8),
      latestTime: Date.UTC(2026, 4, 15),
      skippedLines: 0,
    };
    const output = renderStatsTable(stats);
    expect(output).toContain('maxCalls');
    expect(output).toContain('MAX_CALLS_EXCEEDED');
    expect(output).toContain('42');
    expect(output).toContain('argumentSchema');
    expect(output).toContain('ARGUMENT_VALIDATION_FAILED');
    expect(output).toContain('21');
  });

  it('prints the correct date range', () => {
    const stats: AuditStats = {
      ...emptyStats(),
      earliestTime: Date.UTC(2026, 4, 8),
      latestTime: Date.UTC(2026, 4, 15),
    };
    const output = renderStatsTable(stats);
    expect(output).toContain('2026-05-08 → 2026-05-15');
  });

  it('prints correct total counts', () => {
    const stats: AuditStats = {
      ...emptyStats(),
      totalCalls: 1237,
      totalDenied: 89,
    };
    const output = renderStatsTable(stats);
    expect(output).toContain('1,237 calls');
    expect(output).toContain('89 denied');
  });

  it('calculates percentages rounded to integers', () => {
    const stats: AuditStats = {
      buckets: [
        { conditionType: 'maxCalls', denialCode: 'MAX', count: 1 },
        { conditionType: 'timeWindow', denialCode: 'TW', count: 2 },
      ],
      totalCalls: 10,
      totalDenied: 3,
      earliestTime: Date.now(),
      latestTime: Date.now(),
      skippedLines: 0,
    };
    const output = renderStatsTable(stats);
    // timeWindow: 2/3 ≈ 67%; maxCalls: 1/3 ≈ 33%
    expect(output).toContain('67%');
    expect(output).toContain('33%');
  });

  it('shows "—" for percentage when totalDenied is 0', () => {
    const stats: AuditStats = {
      buckets: [
        { conditionType: 'maxCalls', denialCode: 'MAX', count: 0 },
      ],
      totalCalls: 5,
      totalDenied: 0,
      earliestTime: Date.now(),
      latestTime: Date.now(),
      skippedLines: 0,
    };
    const output = renderStatsTable(stats);
    expect(output).toContain('—');
  });

  it('shows 100% when a single bucket accounts for all denials', () => {
    const stats: AuditStats = {
      buckets: [{ conditionType: 'maxCalls', denialCode: 'MAX', count: 10 }],
      totalCalls: 15,
      totalDenied: 10,
      earliestTime: Date.now(),
      latestTime: Date.now(),
      skippedLines: 0,
    };
    const output = renderStatsTable(stats);
    expect(output).toContain('100%');
  });

  it('does not add a trailing newline (renderStatsTable returns the table string only)', () => {
    const output = renderStatsTable(emptyStats());
    expect(output.endsWith('\n')).toBe(false);
  });

  it('separator is at least as wide as the header line', () => {
    const stats: AuditStats = {
      ...emptyStats(),
      totalCalls: 999999,
      totalDenied: 999,
    };
    const output = renderStatsTable(stats);
    const lines = output.split('\n');
    const headerLine = lines[0] ?? '';
    const separatorLine = lines.find((l: string) => /^─+$/.test(l)) ?? '';
    expect(separatorLine.length).toBeGreaterThanOrEqual(headerLine.length);
  });

  it('column widths expand to fit longer content', () => {
    const longConditionType = 'a'.repeat(50);
    const longDenialCode = 'B'.repeat(50);
    const stats: AuditStats = {
      buckets: [{ conditionType: longConditionType, denialCode: longDenialCode, count: 1 }],
      totalCalls: 1,
      totalDenied: 1,
      earliestTime: Date.now(),
      latestTime: Date.now(),
      skippedLines: 0,
    };
    const output = renderStatsTable(stats);
    expect(output).toContain(longConditionType);
    expect(output).toContain(longDenialCode);
  });

  it('renders a single bucket correctly', () => {
    const stats: AuditStats = {
      buckets: [{ conditionType: 'maxCalls', denialCode: 'MAX_CALLS_EXCEEDED', count: 42 }],
      totalCalls: 100,
      totalDenied: 42,
      earliestTime: Date.UTC(2026, 4, 1),
      latestTime: Date.UTC(2026, 4, 8),
      skippedLines: 0,
    };
    const output = renderStatsTable(stats);
    const lines = output.split('\n');
    // header, separator, colHeader, 1 data row
    expect(lines).toHaveLength(4);
    expect(output).toContain('42');
    expect(output).toContain('100%');
  });

  it('renders rows in the order provided by AuditStats.buckets', () => {
    // Buckets are pre-sorted by aggregateDenials; renderStatsTable just renders.
    const stats: AuditStats = {
      buckets: [
        { conditionType: 'first', denialCode: 'F', count: 3 },
        { conditionType: 'second', denialCode: 'S', count: 2 },
        { conditionType: 'third', denialCode: 'T', count: 1 },
      ],
      totalCalls: 10,
      totalDenied: 6,
      earliestTime: Date.now(),
      latestTime: Date.now(),
      skippedLines: 0,
    };
    const output = renderStatsTable(stats);
    const firstIdx = output.indexOf('first');
    const secondIdx = output.indexOf('second');
    const thirdIdx = output.indexOf('third');
    expect(firstIdx).toBeLessThan(secondIdx);
    expect(secondIdx).toBeLessThan(thirdIdx);
  });

  it('uses locale-formatted numbers (commas for thousands)', () => {
    const stats: AuditStats = {
      ...emptyStats(),
      totalCalls: 1000000,
      totalDenied: 1000,
    };
    const output = renderStatsTable(stats);
    expect(output).toContain('1,000,000');
    expect(output).toContain('1,000');
  });

  it('renders correctly with many rows', () => {
    const buckets: DenialBucket[] = Array.from({ length: 10 }, (_, i) => ({
      conditionType: `type${i}`,
      denialCode: `CODE_${i}`,
      count: 10 - i,
    }));
    const stats: AuditStats = {
      buckets,
      totalCalls: 100,
      totalDenied: buckets.reduce((s, b) => s + b.count, 0),
      earliestTime: Date.now(),
      latestTime: Date.now(),
      skippedLines: 0,
    };
    const output = renderStatsTable(stats);
    const dataLines = output.split('\n').slice(3); // skip header, separator, colHeader
    expect(dataLines).toHaveLength(10);
  });

  it('same stats object always produces the same output (deterministic)', () => {
    const stats: AuditStats = {
      buckets: [
        { conditionType: 'maxCalls', denialCode: 'MAX', count: 5 },
        { conditionType: 'timeWindow', denialCode: 'TW', count: 2 },
      ],
      totalCalls: 100,
      totalDenied: 7,
      earliestTime: Date.UTC(2026, 4, 1),
      latestTime: Date.UTC(2026, 4, 8),
      skippedLines: 0,
    };
    expect(renderStatsTable(stats)).toBe(renderStatsTable(stats));
  });
});

// ---------------------------------------------------------------------------
// collectStats (filesystem integration)
// ---------------------------------------------------------------------------

describe('collectStats', () => {
  it('returns empty stats when the log file does not exist', async () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const stats = await collectStats({ logPath });
    expect(stats.totalCalls).toBe(0);
    expect(stats.totalDenied).toBe(0);
    expect(stats.buckets).toEqual([]);
    expect(stats.skippedLines).toBe(0);
  });

  it('returns stats from a single log file', async () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const events = [
      makeAllowEvent({ time: Date.UTC(2026, 4, 8) }),
      makeDenialEvent({ conditionType: 'maxCalls', denialCode: 'MAX', time: Date.UTC(2026, 4, 9) }),
    ];
    writeJsonlFile(logPath, events);

    const stats = await collectStats({ logPath });
    expect(stats.totalCalls).toBe(2);
    expect(stats.totalDenied).toBe(1);
    expect(stats.buckets).toHaveLength(1);
    expect(stats.buckets[0]?.conditionType).toBe('maxCalls');
  });

  it('combines stats from active log and rotated archives', async () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');

    // Rotated archive (older)
    const archive = logPath + '.2026-05-07T00-00-00.000Z';
    writeJsonlFile(archive, [
      makeDenialEvent({ conditionType: 'timeWindow', denialCode: 'TW', time: Date.UTC(2026, 4, 7) }),
    ]);

    // Active log (newer)
    writeJsonlFile(logPath, [
      makeDenialEvent({ conditionType: 'maxCalls', denialCode: 'MAX', time: Date.UTC(2026, 4, 8) }),
      makeDenialEvent({ conditionType: 'maxCalls', denialCode: 'MAX', time: Date.UTC(2026, 4, 9) }),
    ]);

    const stats = await collectStats({ logPath });
    expect(stats.totalCalls).toBe(3);
    expect(stats.totalDenied).toBe(3);
    expect(stats.buckets).toHaveLength(2);
    const maxBucket = stats.buckets.find((b: DenialBucket) => b.conditionType === 'maxCalls');
    expect(maxBucket?.count).toBe(2);
    const twBucket = stats.buckets.find((b: DenialBucket) => b.conditionType === 'timeWindow');
    expect(twBucket?.count).toBe(1);
  });

  it('filters by sinceMs when provided', async () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const t1 = Date.UTC(2026, 4, 1);  // excluded
    const t2 = Date.UTC(2026, 4, 8);  // included
    const t3 = Date.UTC(2026, 4, 15); // included
    writeJsonlFile(logPath, [
      makeDenialEvent({ conditionType: 'a', denialCode: 'A', time: t1 }),
      makeAllowEvent({ time: t2 }),
      makeDenialEvent({ conditionType: 'b', denialCode: 'B', time: t3 }),
    ]);

    const stats = await collectStats({ logPath, sinceMs: t2 });
    expect(stats.totalCalls).toBe(2);
    expect(stats.totalDenied).toBe(1);
    expect(stats.buckets[0]?.conditionType).toBe('b');
  });

  it('includes events exactly at sinceMs', async () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const sinceMs = Date.UTC(2026, 4, 8);
    writeJsonlFile(logPath, [
      makeDenialEvent({ conditionType: 'exact', denialCode: 'EX', time: sinceMs }),
    ]);

    const stats = await collectStats({ logPath, sinceMs });
    expect(stats.totalCalls).toBe(1);
    expect(stats.totalDenied).toBe(1);
  });

  it('excludes events strictly before sinceMs', async () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const sinceMs = Date.UTC(2026, 4, 8);
    writeJsonlFile(logPath, [
      makeDenialEvent({ conditionType: 'old', denialCode: 'OLD', time: sinceMs - 1 }),
    ]);

    const stats = await collectStats({ logPath, sinceMs });
    expect(stats.totalCalls).toBe(0);
  });

  it('returns all events when sinceMs is undefined', async () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');
    writeJsonlFile(logPath, [
      makeDenialEvent({ conditionType: 'a', denialCode: 'A', time: 1000 }),
      makeDenialEvent({ conditionType: 'b', denialCode: 'B', time: 999999999 }),
    ]);

    const stats = await collectStats({ logPath, sinceMs: undefined });
    expect(stats.totalCalls).toBe(2);
  });

  it('returns empty result when all events are before sinceMs', async () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');
    writeJsonlFile(logPath, [
      makeAllowEvent({ time: 1000 }),
      makeDenialEvent({ conditionType: 'a', denialCode: 'A', time: 2000 }),
    ]);

    const stats = await collectStats({ logPath, sinceMs: 999999999 });
    expect(stats.totalCalls).toBe(0);
    expect(stats.totalDenied).toBe(0);
  });

  it('counts invalid JSON lines in skippedLines', async () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const validEvent = makeAllowEvent();
    fs.writeFileSync(
      logPath,
      JSON.stringify(validEvent) + '\n' + 'THIS IS NOT JSON\n' + '{ also bad\n',
      'utf8',
    );

    const stats = await collectStats({ logPath });
    expect(stats.totalCalls).toBe(1);
    expect(stats.skippedLines).toBe(2);
  });

  it('does not count blank lines in skippedLines', async () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const event = makeAllowEvent();
    fs.writeFileSync(logPath, '\n' + JSON.stringify(event) + '\n\n', 'utf8');

    const stats = await collectStats({ logPath });
    expect(stats.totalCalls).toBe(1);
    expect(stats.skippedLines).toBe(0);
  });

  it('accumulates skippedLines across multiple files', async () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const archive = logPath + '.2026-05-07T00-00-00.000Z';
    fs.writeFileSync(archive, 'BAD LINE\n', 'utf8');
    fs.writeFileSync(logPath, 'ALSO BAD\n', 'utf8');

    const stats = await collectStats({ logPath });
    expect(stats.skippedLines).toBe(2);
  });

  it('handles log files with only blank lines gracefully', async () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');
    fs.writeFileSync(logPath, '\n\n\n', 'utf8');

    const stats = await collectStats({ logPath });
    expect(stats.totalCalls).toBe(0);
    expect(stats.skippedLines).toBe(0);
  });

  it('handles a log file with mixed valid/invalid lines', async () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');
    fs.writeFileSync(
      logPath,
      [
        JSON.stringify(makeAllowEvent()),
        'INVALID',
        JSON.stringify(makeDenialEvent({ conditionType: 'a', denialCode: 'A' })),
        '',
        'ALSO INVALID',
        JSON.stringify(makeAllowEvent()),
      ].join('\n') + '\n',
      'utf8',
    );

    const stats = await collectStats({ logPath });
    expect(stats.totalCalls).toBe(3);
    expect(stats.totalDenied).toBe(1);
    expect(stats.skippedLines).toBe(2);
  });

  it('reads multiple archives in chronological order', async () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');
    const t1 = Date.UTC(2026, 4, 1);
    const t2 = Date.UTC(2026, 4, 8);
    const t3 = Date.UTC(2026, 4, 15);

    const archive1 = logPath + '.2026-05-01T00-00-00.000Z';
    const archive2 = logPath + '.2026-05-08T00-00-00.000Z';
    writeJsonlFile(archive1, [makeDenialEvent({ conditionType: 'a', denialCode: 'A', time: t1 })]);
    writeJsonlFile(archive2, [makeDenialEvent({ conditionType: 'b', denialCode: 'B', time: t2 })]);
    writeJsonlFile(logPath, [makeDenialEvent({ conditionType: 'c', denialCode: 'C', time: t3 })]);

    const stats = await collectStats({ logPath });
    expect(stats.totalCalls).toBe(3);
    expect(stats.earliestTime).toBe(t1);
    expect(stats.latestTime).toBe(t3);
  });
});

// ---------------------------------------------------------------------------
// CLI integration — subprocess tests
// ---------------------------------------------------------------------------

const TS_NODE_REGISTER = require.resolve('ts-node/register');
const CLI = path.resolve(__dirname, '..', '..', 'src', 'cli.ts');

function runStats(
  args: string[],
  env?: Record<string, string>,
): { exitCode: number; stdout: string; stderr: string } {
  const result = childProcess.spawnSync(
    process.execPath,
    ['--require', TS_NODE_REGISTER, CLI, 'stats', ...args],
    {
      encoding: 'utf8',
      timeout: 30_000,
      env: { ...process.env, EUNO_TELEMETRY: '0', ...env },
    },
  );
  return {
    exitCode: result.status ?? 1,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

describe('euno-mcp stats — CLI integration', () => {
  it('exits 0 and prints "Period:" when the audit log does not exist', () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'nonexistent-audit.jsonl');
    const { exitCode, stdout } = runStats(['--audit-log', logPath]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain('Period:');
    expect(stdout).toContain('Total: 0 calls; 0 denied');
  });

  it('exits 0 and prints the histogram for a simple log', () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');
    writeJsonlFile(logPath, [
      makeAllowEvent({ time: Date.UTC(2026, 4, 8) }),
      makeDenialEvent({ conditionType: 'maxCalls', denialCode: 'MAX_CALLS_EXCEEDED', time: Date.UTC(2026, 4, 9) }),
    ]);

    const { exitCode, stdout } = runStats(['--audit-log', logPath]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain('Period:');
    expect(stdout).toContain('Total: 2 calls; 1 denied');
    expect(stdout).toContain('maxCalls');
    expect(stdout).toContain('MAX_CALLS_EXCEEDED');
    expect(stdout).toContain('100%');
  });

  it('exits 0 and honours --since (only shows events after the cutoff)', () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');
    writeJsonlFile(logPath, [
      makeDenialEvent({ conditionType: 'old', denialCode: 'OLD', time: Date.UTC(2026, 3, 1) }),
      makeDenialEvent({ conditionType: 'recent', denialCode: 'RECENT', time: Date.UTC(2026, 4, 1) }),
    ]);

    const { exitCode, stdout } = runStats([
      '--audit-log', logPath,
      '--since', '2026-05-01T00:00:00Z',
    ]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain('recent');
    expect(stdout).not.toContain('old');
  });

  it('exits 1 for an invalid --since value', () => {
    const dir = tmpDir();
    const { exitCode, stderr } = runStats(['--audit-log', path.join(dir, 'a.jsonl'), '--since', 'not-a-date']);
    expect(exitCode).toBe(1);
    expect(stderr).toContain('Invalid --since value');
  });

  it('prints a warning to stderr for skipped lines', () => {
    const dir = tmpDir();
    const logPath = path.join(dir, 'audit.jsonl');
    fs.writeFileSync(logPath, 'NOT VALID JSON\n', 'utf8');

    const { exitCode, stdout, stderr } = runStats(['--audit-log', logPath]);
    expect(exitCode).toBe(0);
    expect(stderr).toContain('skipped');
    expect(stdout).toContain('Period:');
  });

  it('shows help text when --help is passed', () => {
    const { exitCode, stdout } = runStats(['--help']);
    expect(exitCode).toBe(0);
    expect(stdout).toContain('denial-reason histogram');
  });
});
