/**
 * GET /api/v1/ping
 * ---------------------------------------------------------------------------
 * Lightweight API-key validation endpoint.
 *
 * Accepts a Bearer `sk-<prefix8>.<secret48>` token in the `Authorization`
 * header and returns the key's metadata without minting a JWT.  Intended
 * for the `euno-mcp upgrade-to-hosted` CLI command so it can verify a
 * user-supplied API key before writing it into a config file.
 *
 * Response (200):
 *   { valid: true, tenantId, policyId, scopes, label? }
 *
 * The endpoint never returns `valid: false` — invalid keys receive HTTP 401
 * so the semantics of the `valid` field are always "yes this key works here".
 *
 * Authentication: Bearer <api-key>
 * No request body required.
 */

import { Request, Response, NextFunction, Router } from 'express';
import { CapabilityError, ErrorCode, parseBearerToken, createLogger } from '@euno/common';
import { ApiKeyVerifier } from '../api-key-verifier';

type Logger = ReturnType<typeof createLogger>;

export interface PingRouterOptions {
  verifier: ApiKeyVerifier;
  logger: Logger;
}

export function createPingRouter(opts: PingRouterOptions): Router {
  const router = Router();

  router.get('/api/v1/ping', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const rawKey = parseBearerToken(req.headers.authorization);
      if (!rawKey) {
        next(new CapabilityError(ErrorCode.AUTHENTICATION_FAILED, 'Bearer token required', 401));
        return;
      }

      const verified = await opts.verifier.verify(rawKey);

      res.json({
        valid: true,
        tenantId: verified.tenantId,
        policyId: verified.policyId,
        scopes: verified.scopes,
      });
    } catch (err) {
      next(err);
    }
  });

  return router;
}
