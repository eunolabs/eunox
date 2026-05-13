/**
 * POST /mint
 * ---------------------------------------------------------------------------
 * Verifies an API key and mints a short-lived capability JWT (≤5 min).
 * Rate-limited per tenant.
 *
 * Authentication: Bearer sk-<prefix8>.<secret48>
 * Body: { agentId: string, sessionId: string }
 * Response: { capabilityToken: string, expiresAt: number }
 */
import { Request, Response, NextFunction, Router } from 'express';
import {
  CapabilityError,
  ErrorCode,
  parseBearerToken,
  createLogger,
} from '@euno/common';
import { ApiKeyVerifier } from '../api-key-verifier';
import { TokenMinter } from '../token-minter';
import { MintAuditStore } from '../mint-audit';
import { MintRateLimiter } from '../mint-rate-limiter';
import { minterMetrics } from '../metrics';
import { KmsSigningError } from '../kms-signing-error';
import { AnomalyDetector } from '../anomaly-detector';
import type { RedisAnomalyDetector } from '../redis-anomaly-detector';

type Logger = ReturnType<typeof createLogger>;

export interface MintRouterOptions {
  verifier: ApiKeyVerifier;
  minter: TokenMinter;
  auditStore: MintAuditStore;
  rateLimiter: MintRateLimiter;
  logger: Logger;
  /**
   * Optional anomaly detector.  When provided, `recordMint` is called after
   * every mint attempt and the fired rule names are logged for observability.
   *
   * Accepts both the in-memory {@link AnomalyDetector} (synchronous
   * `recordMint`) and the Redis-backed {@link RedisAnomalyDetector}
   * (asynchronous `recordMint`).
   */
  anomalyDetector?: AnomalyDetector | RedisAnomalyDetector;
}

function parseMintRequestBody(body: unknown): { agentId: string; sessionId: string } {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'Request body must be a JSON object', 400);
  }
  const b = body as Record<string, unknown>;
  if (typeof b['agentId'] !== 'string' || b['agentId'].length === 0) {
    throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'agentId is required and must be a non-empty string', 400);
  }
  if (typeof b['sessionId'] !== 'string' || b['sessionId'].length === 0) {
    throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'sessionId is required and must be a non-empty string', 400);
  }
  return { agentId: b['agentId'], sessionId: b['sessionId'] };
}

/** Sentinel error class that marks an audit-write failure on the mint path. */
class MintAuditError extends CapabilityError {
  constructor(message: string) {
    super(ErrorCode.GATEWAY_UNAVAILABLE, message, 503);
    Object.defineProperty(this, 'name', { value: 'MintAuditError' });
  }
}

export function createMintRouter(opts: MintRouterOptions): Router {
  const router = Router();

  // Rate limiting is applied at the application level via opts.rateLimiter per tenant.
  router.post('/mint', async (req: Request, res: Response, next: NextFunction) => {
    // Start latency timer (label resolved after auth, defaults to 'unknown' if auth fails)
    let tenantId: string | undefined;
    const endLatency = minterMetrics.mintLatencySeconds.startTimer();
    // Guard against double-recording when an error path already stopped the timer inline.
    let metricsRecorded = false;
    // Hoisted outside try so the catch block can feed pre-auth failures to the
    // anomaly detector using the key prefix (Task 23).
    let rawKeyOrNull: string | null = null;

    try {
      // 1. Extract and verify API key
      const authHeader = req.headers.authorization;
      rawKeyOrNull = parseBearerToken(authHeader);
      if (!rawKeyOrNull) {
        minterMetrics.mintTotal.inc({ tenant: 'unknown', result: 'authentication_failed' });
        endLatency({ tenant: 'unknown' });
        metricsRecorded = true;
        throw new CapabilityError(ErrorCode.AUTHENTICATION_FAILED, 'Bearer token required', 401);
      }
      const verified = await opts.verifier.verify(rawKeyOrNull);
      tenantId = verified.tenantId;

      // 2. Check rate limit per tenant
      const rateResult = await opts.rateLimiter.check(tenantId);
      if (!rateResult.allowed) {
        minterMetrics.mintTotal.inc({ tenant: tenantId, result: 'rate_limited' });
        endLatency({ tenant: tenantId });
        metricsRecorded = true;
        throw new CapabilityError(
          ErrorCode.RATE_LIMIT_EXCEEDED,
          'Mint rate limit exceeded for this tenant',
          429,
          { 'Retry-After': String(rateResult.retryAfterSeconds ?? 60) },
        );
      }

      // 3. Parse and validate request body
      const { agentId, sessionId } = parseMintRequestBody(req.body);

      // 4. Mint short-lived JWT
      const result = await opts.minter.mintToken({
        tenantId,
        agentId,
        sessionId,
        capabilities: verified.capabilities,
        apiKeyPrefix: verified.prefix,
        scopes: verified.scopes,
        policyId: verified.policyId,
      });

      // 5. Write mint audit record — acknowledged persistence (Task 3).
      //    The audit write must complete before we return success so that
      //    every minted token has a corresponding, durable audit entry.
      //    If the audit store is unavailable the request fails with 503;
      //    the euno_minter_audit_failure_total counter tracks these events.
      try {
        await opts.auditStore.record({
          keyPrefix: verified.prefix,
          tenantId,
          agentId,
          sessionId,
          jti: result.jti,
          policyId: verified.policyId,
          issuedAt: new Date().toISOString(),
          expiresAt: result.expiresAt,
          kid: result.kid,
          result: 'minted',
        });
      } catch (auditErr: unknown) {
        // Return the rate-limit slot so audit-failure retries don't burn the
        // tenant's quota.  Non-fatal if the decrement itself fails.
        await opts.rateLimiter.decrement(tenantId).catch(() => { /* non-fatal */ });
        minterMetrics.mintAuditFailureTotal.inc({ stage: 'write' });
        opts.logger.error('Failed to write mint audit record — mint aborted', {
          error: auditErr instanceof Error ? auditErr.message : 'unknown',
        });
        throw new MintAuditError(
          'Audit store unavailable — mint request rejected to preserve audit integrity',
        );
      }

      // 6. Record metrics
      minterMetrics.mintTotal.inc({ tenant: tenantId, result: 'minted' });
      endLatency({ tenant: tenantId });

      // 7. Fire-and-forget anomaly detection — intentionally non-blocking so
      //    Redis round-trips (when RedisAnomalyDetector is used) do not add
      //    latency to the mint response. Errors are swallowed here; the
      //    Prometheus counter is the source of truth for anomaly rate.
      if (opts.anomalyDetector) {
        void Promise.resolve(opts.anomalyDetector.recordMint(tenantId, true))
          .then(firedRules => {
            if (firedRules.length > 0) {
              opts.logger.warn('Mint anomaly detected', { tenantId, rules: firedRules });
            }
          })
          .catch((err: unknown) => {
            opts.logger.debug('Anomaly detection error (non-fatal)', {
              error: err instanceof Error ? err.message : String(err),
            });
          });
      }

      opts.logger.info('Capability token minted', {
        tenantId,
        agentId,
        jti: result.jti,
        expiresAt: result.expiresAt,
      });

      res.status(200).json({
        capabilityToken: result.capabilityToken,
        expiresAt: result.expiresAt,
      });
    } catch (error) {
      if (!metricsRecorded) {
        // If tenantId was never resolved, verify() threw before auth completed.
        const failureTenant = tenantId ?? 'unknown';
        const resultLabel = tenantId === undefined
          ? 'authentication_failed'
          : classifyErrorResult(error);
        if (resultLabel !== null) {
          minterMetrics.mintTotal.inc({ tenant: failureTenant, result: resultLabel });
          endLatency({ tenant: failureTenant });
        }
      }

      // Fire-and-forget anomaly detection for failure events.
      if (tenantId !== undefined && opts.anomalyDetector) {
        // Post-auth failure: record against the resolved tenant ID.
        void Promise.resolve(opts.anomalyDetector.recordMint(tenantId, false))
          .then(firedRules => {
            if (firedRules.length > 0) {
              opts.logger.warn('Mint anomaly detected on failure', { tenantId, rules: firedRules });
            }
          })
          .catch((err: unknown) => {
            opts.logger.debug('Anomaly detection error (non-fatal)', {
              error: err instanceof Error ? err.message : String(err),
            });
          });
      } else if (tenantId === undefined && rawKeyOrNull && opts.anomalyDetector) {
        // Pre-auth failure (key present but verification failed): record against
        // the key prefix so failed-verify bursts on a single key are detected
        // even when the key is unknown/revoked and we never resolved a tenantId.
        const keyPrefix = extractKeyPrefix(rawKeyOrNull);
        void Promise.resolve(opts.anomalyDetector.recordMint(keyPrefix, false))
          .then(firedRules => {
            if (firedRules.length > 0) {
              opts.logger.warn('Mint anomaly detected on pre-auth failure', { keyPrefix, rules: firedRules });
            }
          })
          .catch((err: unknown) => {
            opts.logger.debug('Anomaly detection error (non-fatal)', {
              error: err instanceof Error ? err.message : String(err),
            });
          });
      }

      // Translate KmsSigningError to a retryable 503 so clients can distinguish
      // transient HSM outages from internal bugs, and to match the alert-rule
      // documentation (KMS unavailability returns 503).  Metrics were already
      // classified above using the original KmsSigningError, so the label
      // accuracy is unaffected by this translation.
      const effectiveError =
        error instanceof KmsSigningError
          ? new CapabilityError(
              ErrorCode.GATEWAY_UNAVAILABLE,
              'Signing service temporarily unavailable',
              503,
            )
          : error;
      next(effectiveError);
    }
  });

  return router;
}

/**
 * Map a caught error to a Prometheus `result` label, or `null` if the metric
 * was already recorded inline (see the early-exit paths in the route handler
 * above — `authentication_failed` and `rate_limited` are recorded before the
 * error is thrown so that the latency timer can be stopped at the right point).
 *
 * When `tenantId` was never resolved (verify() threw), the caller uses
 * `'authentication_failed'` directly rather than calling this function.
 *
 * Error codes already recorded inline (return null):
 * - `AUTHENTICATION_FAILED` — recorded when Bearer token is missing
 * - `RATE_LIMIT_EXCEEDED`   — recorded when tenant rate limit is hit
 */
function classifyErrorResult(error: unknown): string | null {
  if (error instanceof KmsSigningError) {
    // KMS errors are recorded by MeteredTokenSigner on kmsErrorTotal;
    // here we only need the mintTotal result label.
    return 'kms_error';
  }
  if (error instanceof MintAuditError) {
    // Audit failures have their own counter (mintAuditFailureTotal) but also
    // appear in mintTotal so dashboards can measure total success/failure rates.
    return 'audit_failure';
  }
  if (error instanceof CapabilityError) {
    switch (error.code) {
      case ErrorCode.INVALID_REQUEST: return 'invalid_request';
      case ErrorCode.AUTHENTICATION_FAILED: return null; // already recorded above
      case ErrorCode.RATE_LIMIT_EXCEEDED: return null;   // already recorded above
      default: return 'internal_error';
    }
  }
  return 'internal_error';
}

/**
 * Extract the prefix portion of a raw API key for use as an anomaly-detection
 * key when the full tenant ID cannot be resolved (e.g. the key is unknown or
 * revoked and `verify()` threw before populating `tenantId`).
 *
 * API keys are formatted as `sk-<prefix8>.<secret48>`. The prefix is the
 * `sk-XXXXXXXX` segment before the first `.`. This gives enough identity to
 * detect repeated invalid-key attempts without leaking the full secret.
 *
 * If the key does not contain a `.` the entire raw key is returned as-is.
 */
function extractKeyPrefix(rawKey: string): string {
  const dotIndex = rawKey.indexOf('.');
  return dotIndex >= 0 ? rawKey.slice(0, dotIndex) : rawKey;
}
