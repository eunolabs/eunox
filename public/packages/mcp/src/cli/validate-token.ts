/**
 * Core implementation of the `euno-mcp validate-token` subcommand.
 *
 * This module exports all logic as pure, testable functions so the CLI
 * entry point in `cli.ts` stays thin and the full decision-explain
 * behaviour can be covered by unit tests without spawning subprocesses.
 *
 * ### Modes
 *
 * **`--request-id <uid>`** — finds the matching audit record by
 * `metadata.uid` across the active log and any rotated archives, verifies
 * the HMAC signature, and prints a human-readable decision summary.
 * Exit codes: 0 = found + verified; 1 = not found; 2 = found + invalid
 * signature.
 *
 * **`--since <ISO8601>`** — prints a one-line-per-decision summary of all
 * records at or after the given timestamp. Always exits 0.
 *
 * ### Rotation convention
 *
 * Rotated archives are named `<basePath>.<ISO-timestamp-colons-replaced>`,
 * e.g. `audit.jsonl.2026-05-08T12-34-56.789Z`.  The same convention is
 * used by {@link LocalAuditSink._rotate}.  This module reads all matching
 * archives in ascending name order (oldest first) then the active file.
 *
 * @module
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as readline from 'node:readline';

import { verifyAuditEvent, DEFAULT_AUDIT_LOG_PATH } from '../audit/audit-sink';
import type { SignedMcpAuditEvent } from '../audit/audit-sink';
import type { LocalHmacSigner } from '../audit/hmac-signer';

export { DEFAULT_AUDIT_LOG_PATH };

// ---------------------------------------------------------------------------
// Audit file discovery
// ---------------------------------------------------------------------------

/**
 * Return all audit log file paths for a given base path, in chronological
 * order (oldest rotated archive first, active file last).
 *
 * A rotated archive is any file in the same directory whose name starts with
 * `<basename>.` (a dot-suffix after the base name).  Archives are sorted
 * lexicographically, which is equivalent to chronological order because the
 * rotation timestamp uses a filesystem-safe ISO-8601 format
 * (`2026-05-08T12-34-56.789Z`).
 *
 * Returns an empty array when the directory does not exist or cannot be read.
 */
export function resolveAuditFiles(logPath: string): string[] {
  const dir = path.dirname(logPath);
  const base = path.basename(logPath);

  let entries: string[];
  try {
    entries = fs.readdirSync(dir);
  } catch {
    return [];
  }

  // Rotation timestamp format: YYYY-MM-DDTHH-MM-SS.mmmZ
  // Produced by LocalAuditSink._rotate(): new Date().toISOString().replace(/:/g, '-')
  // e.g. "2026-05-08T12-34-56.789Z"
  const ROTATION_SUFFIX_RE = /^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.\d{3}Z$/;

  // Collect rotated archives (e.g. `audit.jsonl.2026-05-08T12-34-56.789Z`) sorted oldest first.
  // Files with unrecognised suffixes (e.g. .bak, .tmp) are intentionally excluded.
  const rotated = entries
    .filter((name) => {
      if (!name.startsWith(base + '.')) return false;
      const suffix = name.slice(base.length + 1);
      return ROTATION_SUFFIX_RE.test(suffix);
    })
    .sort();

  const result = rotated.map((name) => path.join(dir, name));

  // Append the active file last so records are in chronological order.
  if (entries.includes(base)) {
    result.push(logPath);
  }

  return result;
}

// ---------------------------------------------------------------------------
// JSONL line parsing
// ---------------------------------------------------------------------------

/**
 * Parse a single JSONL line from an audit log file.
 *
 * Returns the parsed {@link SignedMcpAuditEvent} or `null` when the line is
 * empty, whitespace-only, invalid JSON, or does not match the minimal
 * expected shape (an object with a numeric `time` field and an object
 * `metadata` field).
 */
export function parseAuditLine(line: string): SignedMcpAuditEvent | null {
  const trimmed = line.trim();
  if (!trimmed) return null;

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return null;
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return null;
  }

  const rec = parsed as Record<string, unknown>;

  // Minimal shape: must have a numeric `time` and an object `metadata`.
  if (typeof rec['time'] !== 'number') return null;
  if (typeof rec['metadata'] !== 'object' || rec['metadata'] === null || Array.isArray(rec['metadata'])) return null;

  return parsed as SignedMcpAuditEvent;
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

/**
 * Format a Unix-millisecond timestamp as an ISO-8601 string in UTC.
 *
 * @example formatTime(0) → "1970-01-01T00:00:00.000Z"
 */
export function formatTime(timeMs: number): string {
  return new Date(timeMs).toISOString();
}

/**
 * Format a signing-key fingerprint for display.
 *
 * Returns `<algorithm>:<keyId>` (e.g. `hmac-sha256:local-hmac-v1`) so users
 * can distinguish key IDs across different algorithms or after key rotation.
 * The raw key material is never included.
 */
export function formatKeyFingerprint(signer: LocalHmacSigner): string {
  return `${signer.algorithm}:${signer.keyId}`;
}

/**
 * Render a one-line summary of a single audit record for `--since` mode.
 *
 * Format:
 * ```
 * 2026-05-08T12:34:56.789Z  [allow]  list_files
 * 2026-05-08T12:34:57.123Z  [DENY ]  query_db  (maxCalls/MAX_CALLS_EXCEEDED)
 * ```
 */
export function formatSummaryLine(event: SignedMcpAuditEvent): string {
  const isAllow = event.status_id === 1;
  // Pad to 5 chars so allow/deny columns line up.
  const decision = isAllow ? 'allow' : 'DENY ';
  const toolName = event.api?.operation ?? '(unknown)';
  const unmapped = event.unmapped as Record<string, unknown> | undefined;
  const conditionType = unmapped?.['conditionType'] as string | undefined;
  const denialCode = unmapped?.['denialCode'] as string | undefined;

  let suffix = '';
  if (!isAllow) {
    const parts: string[] = [];
    if (conditionType) parts.push(conditionType);
    if (denialCode) parts.push(denialCode);
    if (parts.length > 0) suffix = `  (${parts.join('/')})`;
  }

  return `${formatTime(event.time)}  [${decision}]  ${toolName}${suffix}`;
}

/**
 * Render a multi-line detail view of a single audit record for
 * `--request-id` mode.
 *
 * The first line is `✓ Audit record found` (verified) or
 * `✗ Audit record found` (signature invalid).  Subsequent lines are
 * indented key-value pairs showing the decision context.
 */
export function formatDetailLines(
  event: SignedMcpAuditEvent,
  verified: boolean,
  signer: LocalHmacSigner,
): string[] {
  const isAllow = event.status_id === 1;
  const unmapped = event.unmapped as Record<string, unknown> | undefined;
  const conditionType = unmapped?.['conditionType'] as string | undefined;
  const denialCode = unmapped?.['denialCode'] as string | undefined;
  const details = unmapped?.['details'] as Record<string, unknown> | undefined;
  const obligationsApplied = unmapped?.['obligationsApplied'] as string[] | undefined;

  const prefix = verified ? '✓' : '✗';
  const lines: string[] = [];

  lines.push(`${prefix} Audit record found`);
  lines.push(`  Request ID:    ${event.metadata.uid}`);
  lines.push(`  Time:          ${formatTime(event.time)}`);
  lines.push(`  Tool:          ${event.api?.operation ?? '(unknown)'}`);
  lines.push(`  Session:       ${event.actor?.session?.uid ?? '(unknown)'}`);
  lines.push(`  Decision:      ${isAllow ? 'allow' : 'deny'}`);

  if (!isAllow) {
    if (conditionType) lines.push(`  Condition:     ${conditionType}`);
    if (denialCode) lines.push(`  Denial code:   ${denialCode}`);
    if (details && Object.keys(details).length > 0) {
      lines.push(`  Details:`);
      for (const [k, v] of Object.entries(details)) {
        lines.push(`    ${k}: ${JSON.stringify(v)}`);
      }
    }
  } else if (obligationsApplied && obligationsApplied.length > 0) {
    lines.push(`  Obligations:   ${obligationsApplied.join(', ')}`);
  }

  lines.push(`  Signature key: ${formatKeyFingerprint(signer)}`);
  lines.push(`  Signature:     ${verified ? '✓ valid' : '✗ INVALID'}`);

  return lines;
}

// ---------------------------------------------------------------------------
// Audit record reader
// ---------------------------------------------------------------------------

/** Options for {@link readAuditRecords}. */
export interface AuditReadOptions {
  /**
   * When provided, only records with `time >= since.getTime()` are returned.
   */
  since?: Date;
}

/** A successfully parsed audit record with its source location. */
export interface ParsedRecord {
  event: SignedMcpAuditEvent;
  filePath: string;
  lineNumber: number;
}

/**
 * Read all valid audit records from an ordered list of JSONL files.
 *
 * Files are read in the provided order (pass {@link resolveAuditFiles} output
 * for chronological order).  Within each file, records are returned in line
 * order.  Lines that are empty, whitespace-only, or fail to parse are silently
 * skipped; a stderr warning is emitted for each skipped non-empty line.
 *
 * If a file listed in `files` cannot be opened (e.g. it was rotated away
 * between the directory listing and this read), it is silently skipped.
 *
 * @param files   Ordered list of JSONL file paths.
 * @param opts    Optional filter options.
 * @param onWarn  Optional callback for non-fatal parse warnings (one call per
 *                bad line).  Defaults to `process.stderr.write`.
 */
export async function readAuditRecords(
  files: string[],
  opts: AuditReadOptions = {},
  onWarn?: (msg: string) => void,
): Promise<ParsedRecord[]> {
  const results: ParsedRecord[] = [];
  const sinceMs = opts.since?.getTime();
  const warn = onWarn ?? ((msg: string) => process.stderr.write(msg + '\n'));

  for (const filePath of files) {
    let lineNumber = 0;
    try {
      const fileStream = fs.createReadStream(filePath, { encoding: 'utf8' });
      const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });

      for await (const line of rl) {
        lineNumber++;
        if (!line.trim()) continue;

        const event = parseAuditLine(line);
        if (!event) {
          warn(
            `[euno-mcp] validate-token: skipping malformed line ${lineNumber} in ${filePath}`,
          );
          continue;
        }

        if (sinceMs !== undefined && event.time < sinceMs) continue;

        results.push({ event, filePath, lineNumber });
      }
    } catch {
      // File disappeared between directory listing and read — skip.
      continue;
    }
  }

  return results;
}

// ---------------------------------------------------------------------------
// Main command entry point
// ---------------------------------------------------------------------------

/** Options for {@link runValidateToken}. */
export interface ValidateTokenOptions {
  /**
   * Find and verify the audit record whose `metadata.uid` equals this value.
   * Mutually exclusive with `since`.
   */
  requestId?: string;
  /**
   * List all records whose `time` is at or after this date.
   * Mutually exclusive with `requestId`.
   */
  since?: Date;
  /**
   * Path to the OCSF audit JSONL file.
   * Defaults to {@link DEFAULT_AUDIT_LOG_PATH} (`~/.euno/audit.jsonl`).
   */
  auditLog?: string;
}

/**
 * Run the `validate-token` command.
 *
 * All output is routed through the `out` callbacks so callers can capture
 * stdout/stderr in tests without monkey-patching globals.
 *
 * @returns Exit code:
 *   - `0` — record found + signature verified (request-id mode), or
 *           since-mode completed successfully.
 *   - `1` — record not found, no files, or neither option provided.
 *   - `2` — record found but signature verification failed.
 */
export async function runValidateToken(
  opts: ValidateTokenOptions,
  signer: LocalHmacSigner,
  out: {
    /** Called for each line of normal output (default: process.stdout). */
    stdout?: (line: string) => void;
    /** Called for each line of error output (default: process.stderr). */
    stderr?: (line: string) => void;
  } = {},
): Promise<number> {
  const writeLine = out.stdout ?? ((line: string) => process.stdout.write(line + '\n'));
  const writeErr = out.stderr ?? ((line: string) => process.stderr.write(line + '\n'));
  const logPath = opts.auditLog ?? DEFAULT_AUDIT_LOG_PATH;

  // ── Mutual exclusivity check ──────────────────────────────────────────────
  if (opts.requestId !== undefined && opts.since !== undefined) {
    writeErr('[euno-mcp] validate-token: --request-id and --since are mutually exclusive; provide only one.');
    return 1;
  }

  // ── --request-id mode ────────────────────────────────────────────────────
  if (opts.requestId !== undefined) {
    const files = resolveAuditFiles(logPath);

    if (files.length === 0) {
      writeErr(`[euno-mcp] Audit log not found: ${logPath}`);
      return 1;
    }

    const records = await readAuditRecords(files, {}, writeErr);
    const match = records.find((r) => r.event.metadata.uid === opts.requestId);

    if (!match) {
      writeErr(`[euno-mcp] No audit record found for request ID: ${opts.requestId}`);
      return 1;
    }

    const verified = verifyAuditEvent(match.event, signer);
    const lines = formatDetailLines(match.event, verified, signer);
    for (const line of lines) {
      writeLine(line);
    }

    return verified ? 0 : 2;
  }

  // ── --since mode ─────────────────────────────────────────────────────────
  if (opts.since !== undefined) {
    const files = resolveAuditFiles(logPath);
    const records =
      files.length > 0
        ? await readAuditRecords(files, { since: opts.since }, writeErr)
        : [];

    for (const { event } of records) {
      writeLine(formatSummaryLine(event));
    }

    return 0;
  }

  // ── Neither option provided ───────────────────────────────────────────────
  writeErr('[euno-mcp] validate-token requires --request-id <uid> or --since <ISO8601>');
  return 1;
}
