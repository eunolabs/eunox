/**
 * Local JSONL audit sink for @euno/mcp.
 *
 * Every enforcement decision (allow _or_ deny) is durably recorded in a
 * JSONL file whose shape is byte-for-byte identical to the OCSF API Activity
 * records the Stage 3 gateway writes — only the signing mechanism differs
 * (local HMAC-SHA-256 here vs KMS-backed asymmetric signing in Stage 3).
 *
 * ### Record anatomy
 *
 * Each line is an {@link OcsfApiActivityEvent} extended with an HMAC
 * enrichment:
 *
 * ```json
 * {
 *   "metadata": { "version": "1.1.0", "product": { "name": "euno-mcp", … }, "uid": "<uuid>" },
 *   "time": <unix-ms>,
 *   "class_uid": 6003,
 *   "category_uid": 6,
 *   "activity_id": 99,
 *   "type_uid": 600399,
 *   "severity_id": 1,
 *   "status_id": 1,
 *   "status": "Success",
 *   "api": { "operation": "<toolName>", "service": { "name": "euno-mcp" } },
 *   "actor": { "session": { "uid": "<sessionId>" } },
 *   "resources": [{ "uid": "<resource>", "type": "mcp-tool-resource" }],
 *   "unmapped": { "denialCode": "…", "conditionType": "…", "seq": 1 },
 *   "enrichments": [{
 *     "name": "hmac-signature",
 *     "value": "<base64-hmac>",
 *     "type": "hmac-sha256",
 *     "data": { "keyId": "local-hmac-v1" }
 *   }]
 * }
 * ```
 *
 * The HMAC covers the canonical JSON of the record _without_ the
 * `enrichments` array (so the tag is computed over a deterministic payload).
 * The `seq` in `unmapped` is a per-sink monotonic counter that allows
 * detecting dropped records.
 *
 * ### Rotation
 *
 * When the active log file reaches `rotateSizeBytes` (default 100 MiB) the
 * sink renames it to `<path>.<ISO-8601-timestamp>` and starts a fresh file.
 * All writes are serialised through an internal async queue so concurrent
 * callers never interleave partial lines.
 *
 * @module
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

import { canonicalize } from '@euno/common-core';
import type { OcsfApiActivityEvent } from '@euno/common-core';

import { LocalHmacSigner } from './hmac-signer';
import { loadOrCreateHmacKey } from './hmac-key';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * Input record describing one MCP tool-call enforcement decision.
 *
 * The sink builds the full OCSF record and HMAC tag from these fields; callers
 * do not need to know the OCSF schema.
 */
export interface McpAuditRecord {
  /** MCP session identifier (process lifetime for stdio, per-initialize for HTTP). */
  sessionId: string;
  /** Name of the MCP tool that was called. */
  toolName: string;
  /** Resource targeted by the tool call, when applicable. */
  resource?: string;
  /** Enforcement outcome. */
  decision: 'allow' | 'deny';
  /**
   * Machine-readable denial code, e.g. `MAX_CALLS_EXCEEDED`.
   * Only set when `decision` is `'deny'`.
   */
  denialCode?: string;
  /**
   * The `CapabilityCondition.type` that caused the denial, e.g. `'maxCalls'`.
   * Only set when `decision` is `'deny'` and a condition triggered it.
   */
  conditionType?: string;
  /**
   * Structured details about the denial cause.  Currently populated for
   * `argumentSchema` denials and carries the machine-readable fields from
   * `ArgumentValidationError` (`path`, `expected`, `got`).  Stored in the
   * `unmapped` block of the OCSF record alongside `denialCode` and
   * `conditionType`.
   *
   * Only set when `decision` is `'deny'` and structured information is
   * available.
   */
  details?: Record<string, unknown>;
  /**
   * Optional request identifier for correlation with upstream logs.
   * Stored in `metadata.uid` when provided; a UUID is generated otherwise.
   */
  requestId?: string;
}

/**
 * A signed OCSF API Activity event with a guaranteed HMAC enrichment.
 *
 * This is what gets written to the JSONL file. The type alias makes test
 * assertions self-documenting without requiring callers to know the full OCSF
 * schema.
 */
export type SignedMcpAuditEvent = OcsfApiActivityEvent & {
  /** Guaranteed to contain exactly one `hmac-signature` enrichment. */
  enrichments: NonNullable<OcsfApiActivityEvent['enrichments']>;
  /**
   * Guaranteed to contain `seq` (monotonic counter) plus any denial-specific
   * fields.
   */
  unmapped: NonNullable<OcsfApiActivityEvent['unmapped']>;
};

/**
 * Sink contract for MCP audit records.
 *
 * Implementations MUST:
 *   - Never throw from `record()` — a transient write failure should be logged
 *     and swallowed so enforcement decisions are not affected by audit I/O.
 *   - Serialise writes so concurrent calls do not produce partial lines.
 *   - Flush and close cleanly on `close()`.
 */
export interface McpAuditSink {
  /** Record an enforcement decision. MUST NOT throw. */
  record(entry: McpAuditRecord): Promise<void>;
  /** Flush any buffered writes to disk. MUST NOT throw. */
  flush(): Promise<void>;
  /** Stop accepting new records and flush. MUST NOT throw. */
  close(): Promise<void>;
}

/** No-op sink — used before the real sink is configured. */
export class NullAuditSink implements McpAuditSink {
  async record(_entry: McpAuditRecord): Promise<void> { /* no-op */ }
  async flush(): Promise<void> { /* no-op */ }
  async close(): Promise<void> { /* no-op */ }
}

// ---------------------------------------------------------------------------
// LocalAuditSink implementation
// ---------------------------------------------------------------------------

/** Default log path: `~/.euno/audit.jsonl`. */
export const DEFAULT_AUDIT_LOG_PATH = path.join(os.homedir(), '.euno', 'audit.jsonl');

/** Default rotation threshold: 100 MiB. */
export const DEFAULT_ROTATE_BYTES = 100 * 1024 * 1024;

/** OCSF product descriptor embedded in every record's `metadata`. */
const AUDIT_PRODUCT = {
  name: 'euno-mcp',
  vendor_name: 'Euno',
  feature: { name: 'capability-audit' },
} as const;

/** OCSF schema version. Must match the constant in common/src/ocsf.ts. */
const OCSF_SCHEMA_VERSION = '1.1.0';

export interface LocalAuditSinkOptions {
  /**
   * Path to the JSONL log file.
   * @default `~/.euno/audit.jsonl`
   */
  logPath?: string;
  /**
   * Maximum file size (bytes) before rotation.
   * @default 100 MiB
   */
  rotateSizeBytes?: number;
  /**
   * Pre-constructed signer. When absent a signer is built from `keyPath`.
   * Pass this in tests to avoid touching the filesystem.
   */
  signer?: LocalHmacSigner;
  /**
   * Path to the HMAC key file. Only used when `signer` is absent.
   * @default `~/.euno/key`
   */
  keyPath?: string;
}

/**
 * Append-only JSONL audit sink that signs each record with a local
 * HMAC-SHA-256 key.
 *
 * Construct via the async factory {@link createLocalAuditSink} so the key is
 * loaded before the first write.
 */
export class LocalAuditSink implements McpAuditSink {
  private readonly _logPath: string;
  private readonly _rotateSizeBytes: number;
  private readonly _signer: LocalHmacSigner;

  /** Monotonic per-instance record counter (1-based). */
  private _seq = 0;
  /** Estimated current file size (refreshed on open). */
  private _currentSize = 0;
  /** Serial write queue — ensures lines are never interleaved. */
  private _queue: Promise<void> = Promise.resolve();
  private _closed = false;

  constructor(signer: LocalHmacSigner, opts: LocalAuditSinkOptions = {}) {
    this._signer = signer;
    this._logPath = opts.logPath ?? DEFAULT_AUDIT_LOG_PATH;
    this._rotateSizeBytes = opts.rotateSizeBytes ?? DEFAULT_ROTATE_BYTES;
  }

  // ── McpAuditSink implementation ─────────────────────────────────────────

  async record(entry: McpAuditRecord): Promise<void> {
    if (this._closed) return;
    // Serialise writes and ensure a prior failure never silently drops the
    // current entry — catch any rejection from the previous step before
    // chaining the new write.
    this._queue = this._queue
      .catch(() => { /* prior failure already logged in _writeRecord */ })
      .then(() => this._writeRecord(entry));
    await this._queue;
  }

  async flush(): Promise<void> {
    await this._queue;
  }

  async close(): Promise<void> {
    this._closed = true;
    await this._queue;
  }

  // ── Internal helpers ─────────────────────────────────────────────────────

  private async _writeRecord(entry: McpAuditRecord): Promise<void> {
    try {
      const line = this._buildLine(entry);
      await this._appendLine(line);
    } catch (err) {
      // Audit failures must NEVER propagate to the enforcement path.
      process.stderr.write(
        `[euno-mcp] Audit write failed: ${err instanceof Error ? err.message : String(err)}\n`,
      );
    }
  }

  /**
   * Build the signed JSONL line for one enforcement decision.
   *
   * Steps:
   *   1. Assemble the unsigned OCSF API Activity event.
   *   2. Canonicalize it.
   *   3. Compute HMAC over the canonical form.
   *   4. Attach the HMAC as an enrichment.
   *   5. Serialise to JSON.
   */
  private _buildLine(entry: McpAuditRecord): string {
    const seq = ++this._seq;
    const uid = entry.requestId ?? crypto.randomUUID();
    const now = Date.now();

    const isAllow = entry.decision === 'allow';

    // Build unmapped blob — always includes seq; denial fields only when denying.
    const unmapped: Record<string, unknown> = { seq };
    if (!isAllow) {
      if (entry.denialCode) unmapped['denialCode'] = entry.denialCode;
      if (entry.conditionType) unmapped['conditionType'] = entry.conditionType;
      if (entry.details) unmapped['details'] = entry.details;
    }

    // Build the unsigned OCSF event body (no enrichments yet).
    const unsignedEvent: Omit<OcsfApiActivityEvent, 'enrichments'> & {
      enrichments?: undefined;
    } = {
      metadata: {
        version: OCSF_SCHEMA_VERSION,
        product: { ...AUDIT_PRODUCT },
        uid,
      },
      time: now,
      class_uid: 6003,
      category_uid: 6,
      // MCP tool calls don't map to CRUD verbs — use 99 (Other).
      activity_id: 99,
      type_uid: 6003 * 100 + 99,
      severity_id: isAllow ? 1 : 3, // 1=Informational, 3=Medium
      status_id: isAllow ? 1 : 2,   // 1=Success, 2=Failure
      status: isAllow ? 'Success' : 'Failure',
      api: {
        operation: entry.toolName,
        service: { name: 'euno-mcp' },
      },
      actor: {
        session: { uid: entry.sessionId },
      },
      ...(entry.resource
        ? { resources: [{ uid: entry.resource, type: 'mcp-tool-resource' }] }
        : {}),
      unmapped,
    };

    // Compute HMAC over the canonical form of the unsigned event.
    const canonical = canonicalize(unsignedEvent);
    const hmacTag = this._signer.sign(canonical);

    // Attach the HMAC enrichment.
    // The cast is safe: we always supply `unmapped` and `enrichments` above.
    const signedEvent = {
      ...unsignedEvent,
      unmapped,
      enrichments: [
        {
          name: 'hmac-signature',
          value: hmacTag,
          type: this._signer.algorithm,
          data: { keyId: this._signer.keyId },
        },
      ],
    } as SignedMcpAuditEvent;

    return JSON.stringify(signedEvent);
  }

  /**
   * Append `line` (without trailing newline) to the log file, rotating if
   * the file would exceed the size limit.
   */
  private async _appendLine(line: string): Promise<void> {
    const lineBytes = Buffer.byteLength(line + '\n', 'utf8');

    // Lazy-init: stat the file on the first write to get the real current size.
    if (this._seq === 1) {
      try {
        const stat = await fs.promises.stat(this._logPath);
        this._currentSize = stat.size;
      } catch {
        // File doesn't exist yet — size is 0.
        this._currentSize = 0;
      }
    }

    // Rotate if needed.
    if (this._currentSize + lineBytes > this._rotateSizeBytes) {
      await this._rotate();
    }

    // Ensure the parent directory exists.
    await fs.promises.mkdir(path.dirname(this._logPath), { recursive: true });

    await fs.promises.appendFile(this._logPath, line + '\n', 'utf8');
    this._currentSize += lineBytes;
  }

  /**
   * Rename the current log to `<logPath>.<ISO-timestamp>` and reset the size
   * counter so the next write goes to a fresh file.
   *
   * The timestamp uses a filesystem-safe format: colons replaced with hyphens.
   *
   * ENOENT is treated as a no-op (nothing to rotate). Any other error is
   * logged to stderr and the current size is refreshed via `stat()` so rotation
   * logic remains accurate and the log does not grow unboundedly.
   */
  private async _rotate(): Promise<void> {
    try {
      const ts = new Date().toISOString().replace(/:/g, '-');
      const rotatedPath = `${this._logPath}.${ts}`;
      await fs.promises.rename(this._logPath, rotatedPath);
      this._currentSize = 0;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'ENOENT') {
        // File doesn't exist — nothing to rotate; start fresh.
        this._currentSize = 0;
      } else {
        // Unexpected error (permissions, read-only filesystem, etc.).
        // Log the problem but do not let it stop the audit pipeline. Refresh
        // _currentSize via stat so we don't under-count and silently stop
        // rotating, which would cause unbounded log growth.
        process.stderr.write(
          `[euno-mcp] Audit log rotation failed: ` +
            `${(err as Error).message ?? String(err)}. Continuing.\n`,
        );
        try {
          const stat = await fs.promises.stat(this._logPath);
          this._currentSize = stat.size;
        } catch {
          // stat also failed — we have no reliable size; keep the previous
          // value so we try to rotate again on the next write.
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Async factory: load (or create) the HMAC key and return a ready-to-use
 * {@link LocalAuditSink}.
 *
 * Prefer this over constructing `LocalAuditSink` directly in production code.
 *
 * @example
 * ```ts
 * const sink = await createLocalAuditSink();
 * // or
 * const sink = await createLocalAuditSink({ logPath: '/var/log/euno/audit.jsonl' });
 * ```
 */
export async function createLocalAuditSink(
  opts: LocalAuditSinkOptions = {},
): Promise<LocalAuditSink> {
  const signer =
    opts.signer ?? new LocalHmacSigner(await loadOrCreateHmacKey(opts.keyPath));
  return new LocalAuditSink(signer, opts);
}

// ---------------------------------------------------------------------------
// Verification helper
// ---------------------------------------------------------------------------

/**
 * Verify the HMAC tag on a signed MCP audit event.
 *
 * Recomputes `HMAC(key, canonicalize(event_without_enrichments))` and
 * compares it to the tag in `enrichments[0].value`.
 *
 * Returns `false` (never throws) when the event is invalid, unrecognised, or
 * the tag does not match.
 *
 * @param event   Signed event as parsed from the JSONL file.
 * @param signer  The signer whose key was used to produce the tag.
 */
export function verifyAuditEvent(
  event: SignedMcpAuditEvent,
  signer: LocalHmacSigner,
): boolean {
  try {
    const hmacEnrichment = event.enrichments?.find(
      (e) => e.name === 'hmac-signature',
    );
    if (!hmacEnrichment) return false;

    // Reconstruct the unsigned event (strip enrichments, as they were absent
    // when the canonical form was computed).
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { enrichments, ...unsignedEvent } = event;
    const canonical = canonicalize(unsignedEvent);
    return signer.verify(canonical, hmacEnrichment.value);
  } catch {
    return false;
  }
}
