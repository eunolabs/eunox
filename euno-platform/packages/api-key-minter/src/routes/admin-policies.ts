/**
 * Admin policy-management routes for the api-key-minter service.
 * ---------------------------------------------------------------------------
 *
 * Authentication (two paths, tried in order):
 *   1. PRIMARY — `Authorization: Bearer <jwt>` verified against the JWKS
 *      endpoint configured by `jwtVerifier`.  Operator identity is extracted
 *      from the JWT `sub` claim and written to `res.locals.operatorId`.
 *   2. FALLBACK — `X-Admin-Key: <secret>` shared-secret (explicitly temporary;
 *      logs a deprecation warning each time it is used).
 *
 * Routes (all require admin authentication):
 *
 *   POST /admin/v1/policies
 *     Store or replace the `AgentCapabilityManifest` for a named policy and
 *     propagate the updated `capabilities` array to every non-revoked API key
 *     whose `policyId` matches.  Used by `euno-mcp upgrade-to-hosted` to
 *     round-trip a local policy file to the hosted policy store in one call.
 *
 * Request body:
 *   {
 *     policyId: string,          // matches api_keys.policy_id
 *     manifest: {                // AgentCapabilityManifest (JSON)
 *       name: string,
 *       agentId: string,
 *       version: string,
 *       requiredCapabilities: CapabilityConstraint[],
 *       optionalCapabilities?: CapabilityConstraint[],
 *     }
 *   }
 *
 * Response (200):
 *   { policyId, updatedKeys: number, capabilityCount: number }
 */

import * as crypto from 'crypto';
import { Request, Response, NextFunction, Router } from 'express';
import { CapabilityError, ErrorCode, createLogger, validateManifest } from '@euno/common';
import { ApiKeyStore } from '../api-key-store';
import { AdminJwtVerifier } from '../admin-jwt-verifier';

type Logger = ReturnType<typeof createLogger>;

export interface AdminPoliciesRouterOptions {
  keyStore: ApiKeyStore;
  adminApiKey: string;
  logger: Logger;
  /**
   * Optional JWKS-backed JWT verifier for operator tokens.
   * When provided, `Authorization: Bearer <jwt>` is accepted as the primary
   * authentication path.  The shared `X-Admin-Key` remains as an explicit
   * temporary fallback but emits a deprecation warning on each use.
   */
  jwtVerifier?: AdminJwtVerifier;
}

function requireAdminAuth(
  adminApiKey: string,
  logger: Logger,
  jwtVerifier?: AdminJwtVerifier,
): (req: Request, res: Response, next: NextFunction) => void {
  // Normalise both the expected and provided keys to a fixed-length SHA-256
  // digest so that crypto.timingSafeEqual (which requires equal-length buffers)
  // can be used without leaking length information.
  const expectedHash = crypto
    .createHash('sha256')
    .update(Buffer.from(adminApiKey, 'utf8'))
    .digest();

  return (req: Request, res: Response, next: NextFunction): void => {
    const fail = (): void => {
      next(
        new CapabilityError(
          ErrorCode.AUTHENTICATION_FAILED,
          'Admin authentication required',
          401,
        ),
      );
    };

    // ── Primary path: Bearer JWT ──────────────────────────────────────────
    if (jwtVerifier) {
      const authHeader = req.headers['authorization'];
      if (typeof authHeader === 'string' && authHeader.toLowerCase().startsWith('bearer ')) {
        const token = authHeader.slice('bearer '.length).trim();
        jwtVerifier.verify(token).then((principal) => {
          res.locals['operatorId'] = principal.operatorId;
          next();
        }).catch(() => {
          fail();
        });
        return;
      }
    }

    // ── Fallback path: X-Admin-Key shared secret ──────────────────────────
    const provided = req.headers['x-admin-key'];
    const providedBuf =
      typeof provided === 'string' ? Buffer.from(provided, 'utf8') : Buffer.alloc(0);
    const providedHash = crypto.createHash('sha256').update(providedBuf).digest();

    if (!crypto.timingSafeEqual(providedHash, expectedHash)) {
      fail();
      return;
    }

    if (jwtVerifier) {
      logger.warn(
        'Admin request authenticated via deprecated X-Admin-Key shared secret. ' +
        'Migrate to operator JWT tokens (MINTER_ADMIN_JWKS_URI / MINTER_ADMIN_JWT_AUDIENCE).',
        { path: req.path },
      );
    }
    next();
  };
}

export function createAdminPoliciesRouter(opts: AdminPoliciesRouterOptions): Router {
  const router = Router();
  const auth = requireAdminAuth(opts.adminApiKey, opts.logger, opts.jwtVerifier);

  /**
   * POST /admin/v1/policies
   *
   * Validate the supplied AgentCapabilityManifest, extract its capabilities,
   * and update every non-revoked API key whose policyId matches.
   */
  router.post(
    '/admin/v1/policies',
    auth,
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const body = req.body as Record<string, unknown>;

        if (typeof body['policyId'] !== 'string' || body['policyId'].length === 0) {
          throw new CapabilityError(ErrorCode.INVALID_REQUEST, 'policyId (string) is required', 400);
        }
        const policyId = body['policyId'] as string;

        if (
          typeof body['manifest'] !== 'object' ||
          body['manifest'] === null ||
          Array.isArray(body['manifest'])
        ) {
          throw new CapabilityError(
            ErrorCode.INVALID_REQUEST,
            'manifest must be a JSON object',
            400,
          );
        }

        // Validate the manifest against the full schema.  validateManifest
        // throws ManifestValidationError (extends Error) on any structural
        // or semantic violation.
        let manifest;
        try {
          manifest = validateManifest(body['manifest']);
        } catch (err) {
          throw new CapabilityError(
            ErrorCode.INVALID_REQUEST,
            `manifest validation failed: ${err instanceof Error ? err.message : String(err)}`,
            400,
          );
        }

        // Flatten required + optional capabilities into a single array.
        const capabilities = [
          ...manifest.requiredCapabilities,
          ...(manifest.optionalCapabilities ?? []),
        ];

        const updatedKeys = await opts.keyStore.updateCapabilitiesByPolicyId(
          policyId,
          capabilities,
        );

        opts.logger.info('Policy capabilities updated via admin API', {
          policyId,
          updatedKeys,
          capabilityCount: capabilities.length,
          operator: (res.locals['operatorId'] as string | undefined) ?? 'shared-key',
        });

        res.json({
          policyId,
          updatedKeys,
          capabilityCount: capabilities.length,
        });
      } catch (err) {
        next(err);
      }
    },
  );

  return router;
}
