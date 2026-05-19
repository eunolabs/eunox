/**
 * `GET /api/v1/audit/export` route — Task 6 (Stage 5)
 * ---------------------------------------------------------------------------
 * SOC2 audit-trail export endpoint.  Returns pages of `SignedAuditEvidence`
 * records from the gateway ledger, suitable for offline compliance review.
 *
 * ### Security model
 *
 * Every request MUST carry a valid `X-Admin-API-Key` header (timing-safe
 * comparison against `GATEWAY_ADMIN_API_KEY`).  This is the same check used
 * by every other admin endpoint and the chain-proof route.
 *
 * ### Compliance scope filter
 *
 * The `?scope=` parameter maps OCSF `class_uid` values to SOC2 trust-service
 * criteria (documented in `docs/security/soc2-mapping.md`):
 *
 * | `scope`     | OCSF class         | `class_uid` | SOC2 criteria   |
 * |-------------|--------------------|-------------|-----------------|
 * | `soc2-cc6`  | Authorization      | 3003        | CC6 — Logical and Physical Access Controls |
 * | `soc2-cc7`  | API Activity       | 6003        | CC7 — System Operations |
 * | `all`       | Both               | 3003 + 6003 | All             |
 *
 * Gateway enforcement decisions are always API Activity events (class_uid
 * 6003 / CC7).  Authorization events (class_uid 3003 / CC6) are emitted by
 * the capability issuer and are not stored in the gateway's own ledger.
 * Therefore `scope=soc2-cc6` correctly returns an empty records array from
 * this endpoint — the CC6 evidence lives in the issuer's audit trail.
 *
 * ### Cursor
 *
 * The cursor is a base64-encoded JSON object `{ lastRowId, expiresAt }`.
 * `lastRowId` is the sequence number of the last record on the previous page
 * (used as a continuation cursor for the underlying `AuditQueryStore`).
 * `expiresAt` is a Unix timestamp (ms) set to 24 hours after the cursor was
 * issued; clients that present a cursor older than 24 h receive a 400 error.
 *
 * ### Response shape
 *
 * ```json
 * {
 *   "cursor":          "<opaque-base64> | null",
 *   "hasMore":         true | false,
 *   "records":         [ /* SignedAuditEvidence[] *\/ ],
 *   "verificationUri": "/.well-known/jwks.json"
 * }
 * ```
 *
 * `cursor` is `null` on the last page.
 */

import crypto from 'crypto';
import { Request, Response, NextFunction, Router } from 'express';
import { createLogger, SignedAuditEvidence, AuditQueryStore } from '@euno/common';

type Logger = ReturnType<typeof createLogger>;

// ── Constants ─────────────────────────────────────────────────────────────────

/** Maximum number of records returned in a single page. */
const MAX_PAGE_SIZE = 1_000;

/** Default number of records per page. */
const DEFAULT_PAGE_SIZE = 100;

/** Cursor TTL: 24 hours in milliseconds. */
const CURSOR_TTL_MS = 24 * 60 * 60 * 1_000;

/**
 * OCSF class_uid values that map to each scope.
 *
 * - 3003 = Authorization (issuer events — CC6 logical access controls)
 * - 6003 = API Activity   (gateway enforcement — CC7 system operations)
 *
 * Gateway ledger records are always class_uid 6003.  `soc2-cc6` correctly
 * returns empty because CC6 (Authorization) events are stored in the
 * capability issuer's audit trail, not the gateway's ledger.
 */
const SCOPE_CLASS_UIDS: Record<ExportScope, number[]> = {
  'soc2-cc6': [3003],
  'soc2-cc7': [6003],
  all: [3003, 6003],
};

/** Gateway enforcement records are always API Activity (class_uid 6003). */
const GATEWAY_RECORD_CLASS_UID = 6003;

// ── Types ─────────────────────────────────────────────────────────────────────

/** Allowed values for the `scope` query parameter. */
export type ExportScope = 'soc2-cc6' | 'soc2-cc7' | 'all';

const VALID_SCOPES: readonly ExportScope[] = ['soc2-cc6', 'soc2-cc7', 'all'];

/**
 * Internal representation of an export cursor.
 *
 * Serialised as base64(JSON.stringify(ExportCursorPayload)).
 */
interface ExportCursorPayload {
  /** Sequence number of the last record on the previous page. */
  lastRowId: string;
  /** Unix timestamp (ms) after which this cursor must be rejected. */
  expiresAt: number;
  /**
   * ISO-8601 lower bound preserved from the original `?since=` query
   * parameter.  Passed to `queryEntries` on every continuation page so the
   * time window stays consistent across pages.  Absent when no lower bound
   * was specified on the first page.
   */
  fromTs?: string;
  /**
   * ISO-8601 upper bound preserved from the original `?until=` query
   * parameter.  Passed to `queryEntries` on every continuation page so the
   * time window stays consistent across pages.  Absent when no upper bound
   * was specified on the first page.
   */
  toTs?: string;
}

// ── Options ───────────────────────────────────────────────────────────────────

export interface AuditExportRouterOptions {
  /** The audit query store — same store served by `/api/v1/audit/records`. */
  queryStore: AuditQueryStore;
  /** Raw admin API key (from `GATEWAY_ADMIN_API_KEY`).  When absent the route is open (dev/test). */
  adminApiKey?: string;
  logger: Logger;
  /**
   * Path of the gateway's evidence-signing JWKS endpoint, used as the
   * `verificationUri` in export responses.  Set when the active signer is a
   * software signer (e.g. `/api/v1/audit/signing-keys`).  When absent
   * `verificationUri` is `null` in the response — operators should retrieve
   * the public key from the KMS control plane.
   */
  auditSigningKeysUri?: string;
}

// ── Cursor helpers ────────────────────────────────────────────────────────────

/**
 * Encode a cursor payload as an opaque base64 string.
 */
export function encodeCursor(payload: ExportCursorPayload): string {
  return Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
}

/**
 * Decode and validate a cursor string.
 *
 * Returns `{ ok: true, payload }` on success, or `{ ok: false, reason }` when
 * the cursor is malformed or expired.
 */
export function decodeCursor(
  raw: string,
  nowMs = Date.now(),
): { ok: true; payload: ExportCursorPayload } | { ok: false; reason: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(raw, 'base64').toString('utf8'));
  } catch {
    return { ok: false, reason: 'cursor is not valid base64 JSON' };
  }

  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    typeof (parsed as Record<string, unknown>).lastRowId !== 'string' ||
    typeof (parsed as Record<string, unknown>).expiresAt !== 'number'
  ) {
    return { ok: false, reason: 'cursor has unexpected structure' };
  }

  const p = parsed as Record<string, unknown>;
  // Validate the optional time-bound fields when present.
  if (p['fromTs'] !== undefined && typeof p['fromTs'] !== 'string') {
    return { ok: false, reason: 'cursor has unexpected structure' };
  }
  if (p['toTs'] !== undefined && typeof p['toTs'] !== 'string') {
    return { ok: false, reason: 'cursor has unexpected structure' };
  }

  const payload = parsed as ExportCursorPayload;
  if (payload.expiresAt < nowMs) {
    return { ok: false, reason: 'cursor has expired' };
  }

  return { ok: true, payload };
}

// ── ISO-8601 date param helper ────────────────────────────────────────────────

/**
 * Parse an ISO-8601 date string query parameter.
 *
 * Returns `{ ok: true, isoString }` on success, or `{ ok: false, message }`
 * when the value is not a valid date.
 */
function parseISODateParam(
  raw: string,
  paramName: string,
): { ok: true; isoString: string } | { ok: false; message: string } {
  const ms = Date.parse(raw);
  if (isNaN(ms)) {
    return {
      ok: false,
      message: `\`${paramName}\` must be a valid ISO-8601 date/time string`,
    };
  }
  return { ok: true, isoString: new Date(ms).toISOString() };
}

// ── Route ─────────────────────────────────────────────────────────────────────

/**
 * Create an Express router that serves `GET /api/v1/audit/export`.
 */
export function createAuditExportRouter(opts: AuditExportRouterOptions): Router {
  const { queryStore, adminApiKey, logger } = opts;
  const verificationUri: string | null = opts.auditSigningKeysUri ?? null;
  const router = Router();

  router.get('/api/v1/audit/export', async (req: Request, res: Response, next: NextFunction) => {
    try {
      // ── Authentication ─────────────────────────────────────────────────
      if (adminApiKey) {
        const rawHeader = req.headers['x-admin-api-key'];
        const providedKey = Array.isArray(rawHeader) ? rawHeader[0] : rawHeader;
        const isValid = (() => {
          if (typeof providedKey !== 'string') return false;
          const a = Buffer.from(providedKey, 'utf8');
          const b = Buffer.from(adminApiKey, 'utf8');
          if (a.byteLength !== b.byteLength) return false;
          return crypto.timingSafeEqual(a, b);
        })();

        if (!isValid) {
          logger.warn('Unauthorized audit-export access attempt', {
            ip: req.ip,
            path: req.path,
          });
          res.status(401).json({
            error: { code: 'UNAUTHORIZED', message: 'Valid admin API key required' },
          });
          return;
        }
      }

      // ── Query parameter parsing ────────────────────────────────────────
      const q = req.query as Record<string, unknown>;

      // scope
      const rawScope = typeof q['scope'] === 'string' ? q['scope'] : 'all';
      if (!VALID_SCOPES.includes(rawScope as ExportScope)) {
        res.status(400).json({
          error: {
            code: 'INVALID_REQUEST',
            message: `\`scope\` must be one of: ${VALID_SCOPES.join(', ')}`,
          },
        });
        return;
      }
      const scope = rawScope as ExportScope;

      // pageSize
      const rawPageSize = typeof q['pageSize'] === 'string' ? q['pageSize'] : undefined;
      let pageSize = DEFAULT_PAGE_SIZE;
      if (rawPageSize !== undefined) {
        if (!/^\d+$/.test(rawPageSize.trim())) {
          res.status(400).json({
            error: { code: 'INVALID_REQUEST', message: '`pageSize` must be a positive integer' },
          });
          return;
        }
        const parsed = parseInt(rawPageSize, 10);
        if (!Number.isFinite(parsed) || parsed < 1) {
          res.status(400).json({
            error: { code: 'INVALID_REQUEST', message: '`pageSize` must be a positive integer' },
          });
          return;
        }
        pageSize = Math.min(parsed, MAX_PAGE_SIZE);
      }

      // cursor
      const rawCursor = typeof q['cursor'] === 'string' && q['cursor'].length > 0
        ? q['cursor']
        : undefined;

      let innerCursor: string | undefined;
      let cursorFromTs: string | undefined;
      let cursorToTs: string | undefined;

      if (rawCursor !== undefined) {
        const decoded = decodeCursor(rawCursor);
        if (!decoded.ok) {
          res.status(400).json({
            error: { code: 'INVALID_REQUEST', message: `Invalid cursor: ${decoded.reason}` },
          });
          return;
        }
        innerCursor = decoded.payload.lastRowId;
        // Restore the original time bounds that were encoded in the cursor so
        // subsequent pages stay within the window the caller requested on the
        // first page.
        cursorFromTs = decoded.payload.fromTs;
        cursorToTs = decoded.payload.toTs;
      }

      // since / until — only parsed from query params on the first page
      // (no cursor). Subsequent pages inherit the bounds from the cursor so
      // the time window is consistent across pages regardless of what query
      // params the client sends.
      const rawSince = typeof q['since'] === 'string' && q['since'].length > 0
        ? q['since']
        : undefined;
      const rawUntil = typeof q['until'] === 'string' && q['until'].length > 0
        ? q['until']
        : undefined;

      let fromTs: string | undefined;
      let toTs: string | undefined;

      if (rawCursor === undefined) {
        // First page: parse time bounds from query parameters.
        if (rawSince !== undefined) {
          const result = parseISODateParam(rawSince, 'since');
          if (!result.ok) {
            res.status(400).json({ error: { code: 'INVALID_REQUEST', message: result.message } });
            return;
          }
          fromTs = result.isoString;
        }

        if (rawUntil !== undefined) {
          const result = parseISODateParam(rawUntil, 'until');
          if (!result.ok) {
            res.status(400).json({ error: { code: 'INVALID_REQUEST', message: result.message } });
            return;
          }
          toTs = result.isoString;
        }

        if (fromTs !== undefined && toTs !== undefined && fromTs > toTs) {
          res.status(400).json({
            error: { code: 'INVALID_REQUEST', message: '`since` must not be after `until`' },
          });
          return;
        }
      } else {
        // Continuation page: restore the time bounds from the cursor, ignoring
        // any `since`/`until` query params the client may have provided.
        fromTs = cursorFromTs;
        toTs = cursorToTs;
      }

      // ── Scope filtering ────────────────────────────────────────────────
      // All gateway enforcement records are OCSF API Activity (class_uid 6003).
      // `soc2-cc6` requests Authorization events (class_uid 3003) which are
      // not stored in the gateway ledger — return empty immediately.
      const scopeClassUids = SCOPE_CLASS_UIDS[scope];
      const gatewayRecordsIncluded = scopeClassUids.includes(GATEWAY_RECORD_CLASS_UID);

      if (!gatewayRecordsIncluded) {
        // No gateway records match the requested scope; short-circuit.
        res.json({
          cursor: null,
          hasMore: false,
          records: [],
          verificationUri,
        });
        return;
      }

      // ── Query ──────────────────────────────────────────────────────────
      const page = await queryStore.queryEntries(
        {
          ...(fromTs !== undefined ? { fromTs } : {}),
          ...(toTs !== undefined ? { toTs } : {}),
        },
        {
          limit: pageSize,
          direction: 'asc',
          ...(innerCursor !== undefined ? { cursor: innerCursor } : {}),
        },
      );

      // Build next cursor when there are more records.  Encode the original
      // time bounds so continuation pages stay within the caller's window.
      const records: SignedAuditEvidence[] = page.entries.map((e) => e.signedEvidence);
      const hasMore = page.nextCursor !== undefined && page.nextCursor !== null;

      let nextCursor: string | null = null;
      if (hasMore && page.nextCursor) {
        nextCursor = encodeCursor({
          lastRowId: page.nextCursor,
          expiresAt: Date.now() + CURSOR_TTL_MS,
          ...(fromTs !== undefined ? { fromTs } : {}),
          ...(toTs !== undefined ? { toTs } : {}),
        });
      }

      logger.info('Audit export query', {
        scope,
        pageSize,
        hasCursor: rawCursor !== undefined,
        fromTs,
        toTs,
        resultCount: records.length,
        hasMore,
      });

      res.json({
        cursor: nextCursor,
        hasMore,
        records,
        verificationUri,
      });
    } catch (err) {
      next(err);
    }
  });

  return router;
}
