/**
 * `GET /api/v1/audit/chain-proof` route — Task 5 (Stage 5)
 * ---------------------------------------------------------------------------
 * Serves in-memory `SignedCrossChainCommitment` records produced by the
 * `CrossChainAnchor` running in the gateway process.  Commitments are
 * accumulated in a bounded ring buffer (`CrossChainCommitmentStore`) and
 * filtered by an optional `since` / `until` ISO-8601 time window.
 *
 * ### Response shape
 *
 * ```json
 * {
 *   "commits": [ /* SignedCrossChainCommitment[] *\/ ],
 *   "chainHead": "<hex>|null"
 * }
 * ```
 *
 * `chainHead` is the `canonicalSha256` of the most recent commitment in the
 * store (across all replicas, not just the filtered window).  Callers can
 * compare successive responses to detect gaps — a changed `chainHead` with
 * no matching commit in `commits` means they missed a cycle.  `null` when no
 * commitment has been emitted yet.
 *
 * ### Security model
 *
 * Every request MUST carry a valid `X-Admin-API-Key` header (timing-safe
 * comparison against `GATEWAY_ADMIN_API_KEY`).  This is the same check used
 * by every other admin endpoint.
 *
 * ### Offline verification
 *
 * Callers can verify any `SignedCrossChainCommitment` offline:
 *
 * 1. Fetch the gateway JWKS from `/.well-known/jwks.json`.
 * 2. Import the public key matching `commit.keyId`.
 * 3. Recompute `canonicalSha256(commit)` (over the `CrossChainCommitment`
 *    fields only — `signature`, `keyId`, and `algorithm` are excluded from
 *    the canonical form).
 * 4. Verify the `commit.signature` against the digest using `commit.algorithm`.
 */

import crypto from 'crypto';
import { Request, Response, NextFunction, Router } from 'express';
import { createLogger, SignedCrossChainCommitment, canonicalSha256 } from '@euno/common';

type Logger = ReturnType<typeof createLogger>;

// ── CrossChainCommitmentStore ─────────────────────────────────────────────────

/**
 * Maximum number of `SignedCrossChainCommitment` records held in the
 * ring buffer.  Oldest records are evicted when the buffer is full.
 *
 * At one commitment per minute (the default interval) this retains roughly
 * 7 days of history.  Operators who need longer in-process retention should
 * lower `AUDIT_LEDGER_CROSS_CHAIN_INTERVAL_MS` or read records from S3
 * Object-Lock directly.
 */
const DEFAULT_MAX_STORE_SIZE = 10_000;

/**
 * Bounded in-memory ring buffer of `SignedCrossChainCommitment` records.
 *
 * Thread-safe because Node.js is single-threaded — no locking required.
 */
export class CrossChainCommitmentStore {
  private readonly commits: SignedCrossChainCommitment[] = [];
  private readonly maxSize: number;

  constructor(maxSize = DEFAULT_MAX_STORE_SIZE) {
    if (maxSize < 1) throw new RangeError('maxSize must be ≥ 1');
    this.maxSize = maxSize;
  }

  /**
   * Append a new commitment.  When the buffer is full the oldest record is
   * dropped to keep memory bounded.
   */
  add(commitment: SignedCrossChainCommitment): void {
    if (this.commits.length >= this.maxSize) {
      this.commits.shift();
    }
    this.commits.push(commitment);
  }

  /**
   * Return all commitments whose `ts` field falls within the optional
   * `[since, until]` window (both bounds inclusive).  Pass `undefined` for
   * either bound to leave that side open.
   */
  query(since?: Date, until?: Date): SignedCrossChainCommitment[] {
    return this.commits.filter((c) => {
      const ts = new Date(c.ts).getTime();
      if (since !== undefined && ts < since.getTime()) return false;
      if (until !== undefined && ts > until.getTime()) return false;
      return true;
    });
  }

  /**
   * The `canonicalSha256` of the most recently appended commitment, or
   * `null` when the store is empty.
   */
  chainHead(): string | null {
    if (this.commits.length === 0) return null;
    return canonicalSha256(this.commits[this.commits.length - 1]);
  }

  /** Total number of commitments currently in the store. */
  size(): number {
    return this.commits.length;
  }
}

// ── Route ─────────────────────────────────────────────────────────────────────

export interface ChainProofRouterOptions {
  /** Store populated by the CrossChainAnchor's `onCommitment` callback. */
  commitmentStore: CrossChainCommitmentStore;
  /** Raw admin API key (from `GATEWAY_ADMIN_API_KEY`). When absent the route is open (dev/test). */
  adminApiKey?: string;
  logger: Logger;
}

/**
 * Create an Express router that serves `GET /api/v1/audit/chain-proof`.
 *
 * The route is mounted on the **public app** (not the separate admin app) so
 * it is reachable on the standard gateway port.  It is protected by the same
 * timing-safe `X-Admin-API-Key` check as all admin routes.
 */
export function createChainProofRouter(opts: ChainProofRouterOptions): Router {
  const { commitmentStore, adminApiKey, logger } = opts;
  const router = Router();

  router.get('/api/v1/audit/chain-proof', (req: Request, res: Response, next: NextFunction) => {
    try {
      // ── Authentication ─────────────────────────────────────────────────
      if (adminApiKey) {
        const rawHeader = req.headers['x-admin-api-key'];
        const providedKey = Array.isArray(rawHeader) ? rawHeader[0] : rawHeader;
        const isValid =
          typeof providedKey === 'string' &&
          providedKey.length === adminApiKey.length &&
          crypto.timingSafeEqual(Buffer.from(providedKey), Buffer.from(adminApiKey));

        if (!isValid) {
          logger.warn('Unauthorized chain-proof access attempt', {
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

      const rawSince = typeof q['since'] === 'string' && q['since'].length > 0
        ? q['since']
        : undefined;
      const rawUntil = typeof q['until'] === 'string' && q['until'].length > 0
        ? q['until']
        : undefined;

      let since: Date | undefined;
      let until: Date | undefined;

      if (rawSince !== undefined) {
        const ms = Date.parse(rawSince);
        if (isNaN(ms)) {
          res.status(400).json({
            error: { code: 'INVALID_REQUEST', message: '`since` must be a valid ISO-8601 date/time string' },
          });
          return;
        }
        since = new Date(ms);
      }

      if (rawUntil !== undefined) {
        const ms = Date.parse(rawUntil);
        if (isNaN(ms)) {
          res.status(400).json({
            error: { code: 'INVALID_REQUEST', message: '`until` must be a valid ISO-8601 date/time string' },
          });
          return;
        }
        until = new Date(ms);
      }

      if (since !== undefined && until !== undefined && since > until) {
        res.status(400).json({
          error: { code: 'INVALID_REQUEST', message: '`since` must not be after `until`' },
        });
        return;
      }

      // ── Query store ────────────────────────────────────────────────────
      const commits = commitmentStore.query(since, until);
      const chainHead = commitmentStore.chainHead();

      logger.info('Chain-proof query', {
        since: rawSince,
        until: rawUntil,
        resultCount: commits.length,
        chainHead: chainHead?.substring(0, 16),
      });

      res.json({ commits, chainHead });
    } catch (err) {
      next(err);
    }
  });

  return router;
}
