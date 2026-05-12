/**
 * Admin policy-management routes for the api-key-minter service.
 * ---------------------------------------------------------------------------
 *
 * Routes (all require admin authentication via X-Admin-Key header):
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

type Logger = ReturnType<typeof createLogger>;

export interface AdminPoliciesRouterOptions {
  keyStore: ApiKeyStore;
  adminApiKey: string;
  logger: Logger;
}

function requireAdminAuth(
  adminApiKey: string,
): (req: Request, res: Response, next: NextFunction) => void {
  // Normalise both the expected and provided keys to a fixed-length SHA-256
  // digest so that crypto.timingSafeEqual (which requires equal-length buffers)
  // can be used without leaking length information.  SHA-256 (not HMAC) is
  // sufficient here: the admin API key is a high-entropy random bearer
  // credential, not a user password; a KDF would add latency without benefit.
  const expectedHash = crypto
    .createHash('sha256')
    .update(Buffer.from(adminApiKey, 'utf8'))
    .digest();

  return (req: Request, _res: Response, next: NextFunction): void => {
    const provided = req.headers['x-admin-key'];
    const providedBuf =
      typeof provided === 'string' ? Buffer.from(provided, 'utf8') : Buffer.alloc(0);
    const providedHash = crypto.createHash('sha256').update(providedBuf).digest();

    if (!crypto.timingSafeEqual(providedHash, expectedHash)) {
      next(
        new CapabilityError(
          ErrorCode.AUTHENTICATION_FAILED,
          'Admin authentication required',
          401,
        ),
      );
      return;
    }
    next();
  };
}

export function createAdminPoliciesRouter(opts: AdminPoliciesRouterOptions): Router {
  const router = Router();
  const auth = requireAdminAuth(opts.adminApiKey);

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
