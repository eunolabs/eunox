/**
 * `GET /api/v1/audit/records` route — Task 7 (Stage 3)
 * ---------------------------------------------------------------------------
 * Provides a paginated, filterable read-only view of the immutable audit
 * ledger. The endpoint returns `SignedAuditEvidence` records from the
 * configured ledger backend.
 *
 * ### Security model
 *
 * Every request MUST carry a valid capability token. Results are
 * automatically scoped to the **tenant** extracted from the token's
 * `authorizedBy.tenantId` claim so tenants can only see their own records.
 * Requests from tokens that do not carry `tenantId` are rejected with 403
 * to prevent accidental cross-tenant data leakage.
 *
 * ### Pagination
 *
 * Cursor-based pagination via `nextCursor`. Clients pass the opaque
 * cursor returned in the previous response as `cursor` in the next
 * request. The cursor is backend-specific (for Postgres it encodes a `seq`
 * value) and MUST be treated as opaque by callers.
 *
 * ### Query parameters
 *
 * | Name            | Type                      | Description                                    |
 * |-----------------|---------------------------|------------------------------------------------|
 * | `agentId`       | string                    | Filter by agent sub.                           |
 * | `jti`           | string                    | Filter by capability token JTI.                |
 * | `decision`      | `allow` \| `deny`         | Filter by decision outcome.                    |
 * | `conditionType` | string                    | Filter by the failing condition type.          |
 * | `denialCode`    | string                    | Filter by denial code.                         |
 * | `fromTs`        | ISO 8601 string           | Inclusive lower timestamp bound.               |
 * | `toTs`          | ISO 8601 string           | Inclusive upper timestamp bound.               |
 * | `limit`         | integer (1-100, def 50)   | Maximum records per page.                      |
 * | `cursor`        | string                    | Opaque pagination cursor from previous page.   |
 * | `direction`     | `asc` \| `desc`           | Sort direction (default `asc`).                |
 */

import { Request, Response, NextFunction, Router } from 'express';
import {
  CapabilityError,
  ErrorCode,
  parseBearerToken,
  createLogger,
  LedgerBackend,
  TokenVerifier,
  AuditQueryFilter,
  AuditQueryPagination,
} from '@euno/common';

type Logger = ReturnType<typeof createLogger>;

const MAX_LIMIT = 100;
const DEFAULT_LIMIT = 50;

export interface AuditRouterOptions {
  ledgerBackend: LedgerBackend;
  verifier: TokenVerifier;
  logger: Logger;
}

/**
 * Parse a query-string parameter as a strictly positive integer.
 * Returns `undefined` when the parameter is absent, not an integer string
 * (including trailing text like "3abc" or decimals like "10.5"), or ≤ 0.
 */
function parseIntParam(value: unknown): number | undefined {
  if (typeof value !== 'string' || value.trim().length === 0) return undefined;
  // Reject anything that isn't a pure decimal integer string.
  if (!/^\d+$/.test(value.trim())) return undefined;
  const n = parseInt(value, 10);
  return Number.isInteger(n) && n > 0 ? n : undefined;
}

/**
 * Validate that a value is one of a fixed set of allowed strings.
 */
function parseEnum<T extends string>(value: unknown, allowed: readonly T[]): T | undefined {
  if (typeof value !== 'string') return undefined;
  return (allowed as readonly string[]).includes(value) ? (value as T) : undefined;
}

/**
 * Create an Express router that serves `GET /api/v1/audit/records`.
 *
 * The router authenticates the caller using `verifier.verify()`, extracts
 * `tenantId` from the token, and forwards a tenant-scoped query to the
 * ledger backend.
 */
export function createAuditRouter(opts: AuditRouterOptions): Router {
  const { ledgerBackend, verifier, logger } = opts;
  const router = Router();

  router.get('/api/v1/audit/records', async (req: Request, res: Response, next: NextFunction) => {
    try {
      // ── Authentication ─────────────────────────────────────────────────
      const rawToken = parseBearerToken(req.headers.authorization);
      if (!rawToken) {
        throw new CapabilityError(
          ErrorCode.AUTHENTICATION_FAILED,
          'Authorization header with Bearer token is required',
          401,
        );
      }

      let tenantId: string | undefined;
      try {
        const payload = await verifier.verify(rawToken);
        tenantId = payload.authorizedBy?.tenantId;
      } catch (err) {
        if (err instanceof CapabilityError) throw err;
        throw new CapabilityError(
          ErrorCode.AUTHENTICATION_FAILED,
          'Token verification failed',
          401,
        );
      }

      // Require tenantId scoping: tokens without a tenantId claim must not
      // be allowed to see all records (cross-tenant leakage risk).
      if (!tenantId) {
        throw new CapabilityError(
          ErrorCode.INSUFFICIENT_PERMISSIONS,
          'Capability token must carry an authorizedBy.tenantId claim to query audit records',
          403,
        );
      }

      // ── Query parameter parsing ────────────────────────────────────────
      const q = req.query as Record<string, unknown>;

      const rawLimit = parseIntParam(q['limit']);
      const limit = rawLimit !== undefined ? Math.min(rawLimit, MAX_LIMIT) : DEFAULT_LIMIT;

      const direction = parseEnum(q['direction'], ['asc', 'desc'] as const) ?? 'asc';

      const cursor = typeof q['cursor'] === 'string' && q['cursor'].length > 0
        ? q['cursor']
        : undefined;

      const decision = parseEnum(q['decision'], ['allow', 'deny'] as const);

      // Timestamp validation: must parse as a valid date if provided.
      // We normalize to a canonical UTC ISO 8601 string so that backends
      // receive a consistent format regardless of how the caller expressed
      // the timestamp (e.g. "2025-6-1" or "+06:00" offset forms).
      const rawFromTs = typeof q['fromTs'] === 'string' && q['fromTs'].length > 0
        ? q['fromTs']
        : undefined;
      const rawToTs = typeof q['toTs'] === 'string' && q['toTs'].length > 0
        ? q['toTs']
        : undefined;

      if (rawFromTs !== undefined && isNaN(Date.parse(rawFromTs))) {
        throw new CapabilityError(
          ErrorCode.INVALID_REQUEST,
          'fromTs must be a valid ISO 8601 date/time string',
          400,
        );
      }
      if (rawToTs !== undefined && isNaN(Date.parse(rawToTs))) {
        throw new CapabilityError(
          ErrorCode.INVALID_REQUEST,
          'toTs must be a valid ISO 8601 date/time string',
          400,
        );
      }

      // Normalize to canonical UTC ISO string so all backends receive a
      // uniform format and string/timestamp comparisons are predictable.
      const fromTs = rawFromTs !== undefined ? new Date(rawFromTs).toISOString() : undefined;
      const toTs = rawToTs !== undefined ? new Date(rawToTs).toISOString() : undefined;

      const agentId = typeof q['agentId'] === 'string' && q['agentId'].length > 0
        ? q['agentId']
        : undefined;
      const jti = typeof q['jti'] === 'string' && q['jti'].length > 0
        ? q['jti']
        : undefined;
      const conditionType = typeof q['conditionType'] === 'string' && q['conditionType'].length > 0
        ? q['conditionType']
        : undefined;
      const denialCode = typeof q['denialCode'] === 'string' && q['denialCode'].length > 0
        ? q['denialCode']
        : undefined;

      // ── Ledger query ───────────────────────────────────────────────────
      const filter: AuditQueryFilter = {
        // Always scope to the caller's tenant.
        tenantId,
        ...(agentId !== undefined ? { agentId } : {}),
        ...(jti !== undefined ? { jti } : {}),
        ...(decision !== undefined ? { decision } : {}),
        ...(conditionType !== undefined ? { conditionType } : {}),
        ...(denialCode !== undefined ? { denialCode } : {}),
        ...(fromTs !== undefined ? { fromTs } : {}),
        ...(toTs !== undefined ? { toTs } : {}),
      };

      const pagination: AuditQueryPagination = {
        limit,
        direction,
        ...(cursor !== undefined ? { cursor } : {}),
      };

      logger.info('Audit records query', {
        tenantId,
        filter: { agentId, jti, decision, conditionType, denialCode, fromTs, toTs },
        pagination: { limit, direction, hasCursor: cursor !== undefined },
      });

      const page = await ledgerBackend.queryEntries(filter, pagination);

      // Strip `rowHmac` (raw DB bytes) from the response — callers do not
      // need the per-row HMAC to verify the chain (they use the `signature`
      // field on the `signedEvidence` payload). Exposing raw HMAC bytes
      // would leak the internal HMAC key derivation surface unnecessarily.
      const records = page.entries.map((entry) => entry.signedEvidence);

      res.json({
        records,
        nextCursor: page.nextCursor ?? null,
        total: page.total ?? null,
      });
    } catch (err) {
      next(err);
    }
  });

  return router;
}
