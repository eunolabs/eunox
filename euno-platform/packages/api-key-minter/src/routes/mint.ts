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

type Logger = ReturnType<typeof createLogger>;

export interface MintRouterOptions {
  verifier: ApiKeyVerifier;
  minter: TokenMinter;
  auditStore: MintAuditStore;
  rateLimiter: MintRateLimiter;
  logger: Logger;
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

export function createMintRouter(opts: MintRouterOptions): Router {
  const router = Router();

  // Rate limiting is applied at the application level via opts.rateLimiter per tenant.
  router.post('/mint', async (req: Request, res: Response, next: NextFunction) => {
    // Start latency timer (label resolved after auth, defaults to 'unknown' if auth fails)
    let tenantId: string | undefined;
    const endLatency = minterMetrics.mintLatencySeconds.startTimer();

    try {
      // 1. Extract and verify API key
      const authHeader = req.headers.authorization;
      const rawKeyOrNull = parseBearerToken(authHeader);
      if (!rawKeyOrNull) {
        minterMetrics.mintTotal.inc({ tenant: 'unknown', result: 'authentication_failed' });
        endLatency({ tenant: 'unknown' });
        throw new CapabilityError(ErrorCode.AUTHENTICATION_FAILED, 'Bearer token required', 401);
      }
      const verified = await opts.verifier.verify(rawKeyOrNull);
      tenantId = verified.tenantId;

      // 2. Check rate limit per tenant
      const rateResult = await opts.rateLimiter.check(tenantId);
      if (!rateResult.allowed) {
        minterMetrics.mintTotal.inc({ tenant: tenantId, result: 'rate_limited' });
        endLatency({ tenant: tenantId });
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

      // 5. Write mint audit record (fire-and-forget)
      void opts.auditStore.record({
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
      }).catch((err: unknown) => {
        opts.logger.error('Failed to write mint audit record', {
          error: err instanceof Error ? err.message : 'unknown',
        });
      });

      // 6. Record metrics
      minterMetrics.mintTotal.inc({ tenant: tenantId, result: 'minted' });
      endLatency({ tenant: tenantId });

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
      // Record failure metric if we haven't already (e.g., for body parse errors)
      if (tenantId !== undefined) {
        const resultLabel = classifyErrorResult(error);
        if (resultLabel !== null) {
          minterMetrics.mintTotal.inc({ tenant: tenantId, result: resultLabel });
          endLatency({ tenant: tenantId });
        }
      }
      next(error);
    }
  });

  return router;
}

/**
 * Map a caught error to a Prometheus `result` label, or `null` if the metric
 * was already recorded (e.g. rate_limited / authentication_failed paths above).
 */
function classifyErrorResult(error: unknown): string | null {
  if (error instanceof CapabilityError) {
    switch (error.code as string) {
      case ErrorCode.INVALID_REQUEST: return 'invalid_request';
      case ErrorCode.AUTHENTICATION_FAILED: return null; // already recorded
      case ErrorCode.RATE_LIMIT_EXCEEDED: return null;   // already recorded
      default: return 'internal_error';
    }
  }
  return 'internal_error';
}
