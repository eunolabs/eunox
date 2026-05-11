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

  router.post('/mint', async (req: Request, res: Response, next: NextFunction) => {
    try {
      // 1. Extract and verify API key
      const authHeader = req.headers.authorization;
      const rawKeyOrNull = parseBearerToken(authHeader);
      if (!rawKeyOrNull) {
        throw new CapabilityError(ErrorCode.AUTHENTICATION_FAILED, 'Bearer token required', 401);
      }
      const verified = await opts.verifier.verify(rawKeyOrNull);

      // 2. Check rate limit per tenant
      const rateResult = await opts.rateLimiter.check(verified.tenantId);
      if (!rateResult.allowed) {
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
        tenantId: verified.tenantId,
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
        tenantId: verified.tenantId,
        agentId,
        sessionId,
        jti: result.jti,
        policyId: verified.policyId,
        issuedAt: new Date().toISOString(),
        expiresAt: result.expiresAt,
      }).catch((err: unknown) => {
        opts.logger.error('Failed to write mint audit record', {
          error: err instanceof Error ? err.message : 'unknown',
        });
      });

      opts.logger.info('Capability token minted', {
        tenantId: verified.tenantId,
        agentId,
        jti: result.jti,
        expiresAt: result.expiresAt,
      });

      res.status(200).json({
        capabilityToken: result.capabilityToken,
        expiresAt: result.expiresAt,
      });
    } catch (error) {
      next(error);
    }
  });

  return router;
}
