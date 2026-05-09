/**
 * Implementation of the `euno-mcp stats` subcommand.
 *
 * Reads the JSONL audit log (active file plus all rotated archives in the same
 * directory), aggregates denial events by `conditionType` + `denialCode`, and
 * prints an ASCII histogram to stdout.
 *
 * ### Output format
 *
 * ```
 * Period: 2026-05-08 → 2026-05-15  (Total: 1,237 calls; 89 denied)
 * ─────────────────────────────────────────────────────────────────
 *  conditionType        denialCode                  count    %
 *  maxCalls             MAX_CALLS_EXCEEDED            42  47%
 *  argumentSchema       ARGUMENT_VALIDATION_FAILED    21  24%
 *  …
 * ```
 *
 * ### Rotation
 *
 * The sink renames `<path>` to `<path>.<ISO-timestamp>` (colons replaced with
 * hyphens) when the file reaches the rotation threshold.  This module
 * discovers all files matching `<basename>.*` in the log directory and reads
 * them in ascending timestamp order so the period header reflects the true
 * span.
 *
 * @module
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as readline from 'node:readline';

import type { OcsfApiActivityEvent } from '@euno/common-core';

import { DEFAULT_AUDIT_LOG_PATH } from '../audit/audit-sink';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** One aggregated bucket in the denial histogram. */
export interface DenialBucket {
  /** The `CapabilityCondition.type` that triggered the denial, e.g. `"maxCalls"`. */
  conditionType: string;
  /** The machine-readable denial code, e.g. `"MAX_CALLS_EXCEEDED"`. */
  denialCode: string;
  /** Number of denials in this bucket. */
  count: number;
}

/** Summary statistics returned from {@link aggregateDenials}. */
export interface AuditStats {
  /** All denial buckets, sorted by count descending (stable: ties broken by conditionType, then denialCode). */
  buckets: DenialBucket[];
  /** Total number of successfully-parsed records (allow + deny). */
  totalCalls: number;
  /** Total number of denial records (sum of all bucket counts). */
  totalDenied: number;
  /** Unix-ms timestamp of the earliest record in the window, or undefined if empty. */
  earliestTime: number | undefined;
  /** Unix-ms timestamp of the latest record in the window, or undefined if empty. */
  latestTime: number | undefined;
  /** Number of lines skipped due to parse errors. */
  skippedLines: number;
}

/** Options for {@link collectStats}. */
export interface CollectStatsOptions {
  /**
   * Path to the active audit log file.
   * @default DEFAULT_AUDIT_LOG_PATH (`~/.euno/audit.jsonl`)
   */
  logPath?: string;
  /**
   * Only include records with `time >= since` (unix-ms).
   * When undefined all records are included.
   */
  sinceMs?: number;
}

// ---------------------------------------------------------------------------
// File discovery
// ---------------------------------------------------------------------------

/**
 * Discover all audit log files (active + rotated archives) for the given log
 * path.
 *
 * Rotated files are named `<logPath>.<ISO-timestamp>` (e.g.,
 * `audit.jsonl.2026-05-08T12-00-00.000Z`).  This function lists the log
 * directory for files whose name starts with the base name of `logPath`
 * followed by a dot, then sorts them by name (which is lexicographically
 * equal to chronological order because of the ISO-8601 timestamp suffix), and
 * appends the active log file last.
 *
 * Files that do not exist are silently omitted so callers never need to
 * distinguish between "no logs yet" and "log file was just rotated away".
 *
 * @param logPath  Absolute path to the active audit log file.
 * @returns        Ordered list of existing files to read (oldest first).
 */
export function discoverAuditLogFiles(logPath: string): string[] {
  const dir = path.dirname(logPath);
  const base = path.basename(logPath);

  // Collect rotated archives.
  let rotated: string[] = [];
  try {
    const entries = fs.readdirSync(dir);
    rotated = entries
      .filter((name) => name.startsWith(base + '.'))
      .sort() // ISO suffix → lexicographic ≡ chronological
      .map((name) => path.join(dir, name));
  } catch {
    // Directory doesn't exist yet — no archives.
  }

  // Filter to only existing files (archives only; we check the active file below).
  const existing = rotated.filter((p) => {
    try {
      fs.statSync(p);
      return true;
    } catch {
      return false;
    }
  });

  // Add the active log file if it exists.
  try {
    fs.statSync(logPath);
    existing.push(logPath);
  } catch {
    // Active log doesn't exist yet — no problem.
  }

  return existing;
}

// ---------------------------------------------------------------------------
// JSONL parsing
// ---------------------------------------------------------------------------

/**
 * Attempt to parse one JSONL line as an OCSF API Activity event.
 *
 * Returns the parsed object when successful, or `null` when the line is empty,
 * not valid JSON, or the parsed value is not an object.
 */
export function parseAuditLine(line: string): OcsfApiActivityEvent | null {
  const trimmed = line.trim();
  if (!trimmed) return null;
  try {
    const parsed: unknown = JSON.parse(trimmed);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return null;
    }
    return parsed as OcsfApiActivityEvent;
  } catch {
    return null;
  }
}

/**
 * Return `true` when the OCSF event represents a denial decision.
 *
 * A record is a denial when `status_id === 2` (Failure).  We also accept
 * `status === 'Failure'` as a fallback for forward-compatibility.
 */
export function isDenialEvent(event: OcsfApiActivityEvent): boolean {
  return event.status_id === 2 || event.status === 'Failure';
}

// ---------------------------------------------------------------------------
// Streaming aggregation
// ---------------------------------------------------------------------------

/**
 * Incremental accumulator used by {@link collectStats} to aggregate audit
 * records in a streaming fashion without loading all events into memory.
 *
 * The same logical computation as {@link aggregateDenials} is performed, but
 * one record at a time — memory usage grows only with the number of distinct
 * `(conditionType, denialCode)` pairs, not with the number of log records.
 */
export class StreamingAggregator {
  private readonly _bucketMap = new Map<string, DenialBucket>();
  private _totalCalls = 0;
  private _totalDenied = 0;
  private _earliestTime: number | undefined;
  private _latestTime: number | undefined;
  private _skippedLines = 0;

  /** Process one successfully-parsed OCSF event. */
  ingest(event: OcsfApiActivityEvent): void {
    this._totalCalls++;

    if (typeof event.time === 'number') {
      if (this._earliestTime === undefined || event.time < this._earliestTime) {
        this._earliestTime = event.time;
      }
      if (this._latestTime === undefined || event.time > this._latestTime) {
        this._latestTime = event.time;
      }
    }

    if (!isDenialEvent(event)) return;

    this._totalDenied++;

    const unmapped = (event.unmapped ?? {}) as Record<string, unknown>;
    const conditionType =
      typeof unmapped['conditionType'] === 'string'
        ? unmapped['conditionType']
        : '(unknown)';
    const denialCode =
      typeof unmapped['denialCode'] === 'string'
        ? unmapped['denialCode']
        : '(unknown)';

    const key = `${conditionType}\x00${denialCode}`;
    const existing = this._bucketMap.get(key);
    if (existing) {
      existing.count++;
    } else {
      this._bucketMap.set(key, { conditionType, denialCode, count: 1 });
    }
  }

  /** Record lines that could not be parsed. */
  addSkippedLines(n: number): void {
    this._skippedLines += n;
  }

  /** Return the final {@link AuditStats} with buckets sorted by count desc. */
  finish(): AuditStats {
    const buckets = Array.from(this._bucketMap.values()).sort((a, b) => {
      if (b.count !== a.count) return b.count - a.count;
      if (a.conditionType !== b.conditionType) {
        return a.conditionType.localeCompare(b.conditionType);
      }
      return a.denialCode.localeCompare(b.denialCode);
    });

    return {
      buckets,
      totalCalls: this._totalCalls,
      totalDenied: this._totalDenied,
      earliestTime: this._earliestTime,
      latestTime: this._latestTime,
      skippedLines: this._skippedLines,
    };
  }
}

// ---------------------------------------------------------------------------
// File reading (streaming, bounded memory)
// ---------------------------------------------------------------------------

/**
 * Stream all lines from a single audit log file into `aggregator`, skipping
 * lines that cannot be parsed and recording them via
 * `aggregator.addSkippedLines()`.
 *
 * Handles the case where `fs.createReadStream()` emits an asynchronous
 * `'error'` event (e.g. ENOENT after the file was removed between discovery
 * and open, or a permission error) by treating it as a read failure: the
 * readline interface is closed, all lines read so far are still counted, and
 * the error is silently discarded so a single inaccessible file never aborts
 * the entire stats run.
 *
 * @param filePath   Absolute path to the JSONL file to read.
 * @param aggregator Target accumulator.
 * @param sinceMs    If set, events whose `time` is earlier than this value
 *                   are skipped (but are NOT counted as skipped lines).
 */
export async function streamFileIntoAggregator(
  filePath: string,
  aggregator: StreamingAggregator,
  sinceMs: number | undefined,
): Promise<void> {
  // Wrap the readline iteration in a Promise so that an asynchronous stream
  // error can be surfaced through the for-await loop without leaking the
  // readline interface.
  await new Promise<void>((resolve) => {
    let stream: fs.ReadStream;
    try {
      stream = fs.createReadStream(filePath, { encoding: 'utf8' });
    } catch {
      // Synchronous error (extremely rare — createReadStream is usually lazy).
      resolve();
      return;
    }

    const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

    // Surface asynchronous stream errors through the readline interface so
    // the for-await loop terminates cleanly.
    stream.on('error', () => {
      rl.close();
    });

    // Process lines one at a time — no accumulation in an events array.
    const processLines = async (): Promise<void> => {
      let skipped = 0;
      for await (const line of rl) {
        const event = parseAuditLine(line);
        if (event === null) {
          if (line.trim()) skipped++;
          continue;
        }
        if (
          sinceMs !== undefined &&
          typeof event.time === 'number' &&
          event.time < sinceMs
        ) {
          continue;
        }
        aggregator.ingest(event);
      }
      aggregator.addSkippedLines(skipped);
    };

    processLines().then(resolve, resolve);
  });
}

// ---------------------------------------------------------------------------
// Aggregation (batch helper — kept for unit tests)
// ---------------------------------------------------------------------------

/**
 * Aggregate a list of OCSF events into denial histograms.
 *
 * Exported separately from {@link collectStats} so unit tests can feed
 * synthetic events without touching the filesystem.  Production code uses
 * {@link collectStats} which streams records through a
 * {@link StreamingAggregator} to keep memory bounded.
 *
 * @param events       Pre-parsed OCSF events (allow + deny mixed).
 * @param skippedLines Number of lines that could not be parsed (for the summary).
 */
export function aggregateDenials(
  events: OcsfApiActivityEvent[],
  skippedLines = 0,
): AuditStats {
  const agg = new StreamingAggregator();
  agg.addSkippedLines(skippedLines);
  for (const event of events) {
    agg.ingest(event);
  }
  return agg.finish();
}

/**
 * Collect denial statistics from all audit log files at `logPath`.
 *
 * Records are processed in a streaming fashion (one line at a time) so memory
 * usage is bounded by the number of distinct `(conditionType, denialCode)`
 * pairs rather than the total number of log entries.
 *
 * @param opts  Options controlling which files and records to include.
 * @returns     Aggregated {@link AuditStats}.
 */
export async function collectStats(opts: CollectStatsOptions = {}): Promise<AuditStats> {
  const logPath = opts.logPath ?? DEFAULT_AUDIT_LOG_PATH;
  const files = discoverAuditLogFiles(logPath);

  const aggregator = new StreamingAggregator();
  for (const file of files) {
    await streamFileIntoAggregator(file, aggregator, opts.sinceMs);
  }

  return aggregator.finish();
}

// ---------------------------------------------------------------------------
// Table rendering
// ---------------------------------------------------------------------------

/**
 * Format a unix-ms timestamp as `YYYY-MM-DD` in UTC.
 * Returns `'(unknown)'` when the value is undefined.
 */
export function formatDate(ms: number | undefined): string {
  if (ms === undefined) return '(unknown)';
  return new Date(ms).toISOString().slice(0, 10);
}

/** Right-pad a string to `width` characters. */
function rpad(s: string, width: number): string {
  return s.length >= width ? s : s + ' '.repeat(width - s.length);
}

/** Left-pad a string to `width` characters. */
function lpad(s: string, width: number): string {
  return s.length >= width ? s : ' '.repeat(width - s.length) + s;
}

/**
 * Render the denial histogram as an ASCII table string (without a trailing
 * newline).
 *
 * The table is deterministic: given the same {@link AuditStats} it always
 * produces the same output.
 *
 * @param stats  Pre-computed statistics from {@link aggregateDenials}.
 * @returns      Multi-line string suitable for `process.stdout.write(… + '\n')`.
 */
export function renderStatsTable(stats: AuditStats): string {
  const { buckets, totalCalls, totalDenied, earliestTime, latestTime } = stats;

  const periodFrom = formatDate(earliestTime);
  const periodTo = formatDate(latestTime);
  const totalCallsFmt = totalCalls.toLocaleString('en-US');
  const totalDeniedFmt = totalDenied.toLocaleString('en-US');

  const header =
    `Period: ${periodFrom} → ${periodTo}` +
    `  (Total: ${totalCallsFmt} calls; ${totalDeniedFmt} denied)`;

  // Calculate column widths.
  const COL_CONDITION = Math.max(
    'conditionType'.length,
    ...buckets.map((b) => b.conditionType.length),
  );
  const COL_CODE = Math.max(
    'denialCode'.length,
    ...buckets.map((b) => b.denialCode.length),
  );
  const COL_COUNT = Math.max(
    'count'.length,
    ...buckets.map((b) => b.count.toLocaleString('en-US').length),
  );
  // % column is always at least 4 chars wide ("100%").
  const COL_PCT = Math.max(4, '%'.length);

  // Width of the full table (leading space + columns + separators).
  const tableWidth =
    1 + COL_CONDITION + 2 + COL_CODE + 2 + COL_COUNT + 2 + COL_PCT;
  const separator = '─'.repeat(Math.max(header.length, tableWidth));

  const colHeader =
    ' ' +
    rpad('conditionType', COL_CONDITION) +
    '  ' +
    rpad('denialCode', COL_CODE) +
    '  ' +
    lpad('count', COL_COUNT) +
    '  ' +
    '%';

  const rows = buckets.map((b) => {
    const pct =
      totalDenied > 0
        ? Math.round((b.count / totalDenied) * 100) + '%'
        : '—';
    return (
      ' ' +
      rpad(b.conditionType, COL_CONDITION) +
      '  ' +
      rpad(b.denialCode, COL_CODE) +
      '  ' +
      lpad(b.count.toLocaleString('en-US'), COL_COUNT) +
      '  ' +
      pct
    );
  });

  return [header, separator, colHeader, ...rows].join('\n');
}

// ---------------------------------------------------------------------------
// Commander command builder
// ---------------------------------------------------------------------------

import { Command } from 'commander';
import { createTelemetry } from '../telemetry';

/**
 * Build the `stats` Commander sub-command.
 *
 * Separated from cli.ts so it can be imported and tested independently.
 */
export function buildStatsCommand(): Command {
  return new Command('stats')
    .description(
      'Print a denial-reason histogram from the local audit log.\n' +
        'Reads the active log file and all rotated archives under the same directory.',
    )
    .option(
      '--since <ISO8601>',
      'Only include records at or after this timestamp (ISO 8601, e.g. 2026-05-01T00:00:00Z)',
    )
    .option(
      '--audit-log <path>',
      'Path to the audit JSONL file (default: ~/.euno/audit.jsonl)',
    )
    .addHelpText(
      'after',
      `
Examples:
  # Show all-time denial histogram
  euno-mcp stats

  # Limit to the last week
  euno-mcp stats --since 2026-05-01T00:00:00Z

  # Use a custom audit log path
  euno-mcp stats --audit-log ~/.euno/audit-archive.jsonl
`,
    )
    .action(async (options) => {
      const telemetry = await createTelemetry({ subcommand: 'stats' });

      // Parse --since.
      let sinceMs: number | undefined;
      if (options.since !== undefined) {
        const parsed = Date.parse(options.since as string);
        if (Number.isNaN(parsed)) {
          process.stderr.write(
            `[euno-mcp] Invalid --since value "${options.since as string}": ` +
              `must be an ISO 8601 timestamp (e.g. 2026-05-01T00:00:00Z).\n`,
          );
          await telemetry.flush();
          process.exit(1);
        }
        sinceMs = parsed;
      }

      const logPath: string | undefined = options.auditLog as string | undefined;

      let stats: AuditStats;
      try {
        stats = await collectStats({ logPath, sinceMs });
      } catch (err) {
        process.stderr.write(
          `[euno-mcp] Failed to read audit log: ${err instanceof Error ? err.message : String(err)}\n`,
        );
        await telemetry.flush();
        process.exit(1);
      }

      if (stats.skippedLines > 0) {
        process.stderr.write(
          `[euno-mcp] Warning: ${stats.skippedLines.toLocaleString('en-US')} ` +
            `line${stats.skippedLines === 1 ? '' : 's'} skipped (could not parse).\n`,
        );
      }

      process.stdout.write(renderStatsTable(stats) + '\n');
      await telemetry.flush();
    });
}
