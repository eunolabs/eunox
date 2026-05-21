/**
 * Revocation admin route group.
 *
 * Handles:
 *   POST /admin/revoke
 *   POST /admin/revocation/epoch
 */

import * as crypto from 'crypto';
import { Router, Request, Response } from 'express';
import { AdminRouterContext } from './context';

/**
 * Mount all revocation routes onto `router`.
 *
 * Called from `createAdminRouter` after the authentication middleware has been
 * applied, so every handler here can assume the caller is authenticated.
 */
export function mountRevocationRoutes(router: Router, ctx: AdminRouterContext): void {
  const {
    logger,
    auditLogger,
    tokenVerifier,
    epochStore,
    resolveOperator,
    emitAdminOcsfEvent,
    replayIfIdempotent,
    cacheIdempotentResponse,
    assertTenantScope,
  } = ctx;

  /**
   * POST /admin/revoke
   * Revoke a capability token by its JTI (JWT ID).
   * Body: { tokenId: string, expiresAt?: number }
   *
   * When the gateway is tenant-scoped, `tenantId` must be present in the body.
   */
  router.post('/revoke', async (req: Request, res: Response): Promise<void> => {
    if (await replayIfIdempotent(req, res)) return;
    if (assertTenantScope(req, res)) return;
    try {
      if (!tokenVerifier) {
        res.status(501).json({
          error: {
            code: 'NOT_IMPLEMENTED',
            message: 'Token revocation not available - verifier not configured',
          },
        });
        return;
      }

      const { tokenId, expiresAt } = req.body;
      if (!tokenId || typeof tokenId !== 'string') {
        res.status(400).json({
          error: {
            code: 'INVALID_REQUEST',
            message: 'tokenId (string) is required',
          },
        });
        return;
      }

      if (expiresAt !== undefined && (typeof expiresAt !== 'number' || !Number.isFinite(expiresAt))) {
        res.status(400).json({
          error: {
            code: 'INVALID_REQUEST',
            message: 'expiresAt must be a finite number (Unix timestamp in seconds)',
          },
        });
        return;
      }

      const now = Math.floor(Date.now() / 1000);
      const effectiveExpiresAt = expiresAt ?? now + 86400;

      await tokenVerifier.revokeToken(tokenId, effectiveExpiresAt);
      const operator = resolveOperator(req);
      const uid = crypto.randomUUID();
      auditLogger.warn('token_revoked', {
        eventType: 'token_revoked',
        tokenId,
        expiresAt: effectiveExpiresAt,
        operator: operator ?? 'unknown',
        auditEventId: uid,
      });
      emitAdminOcsfEvent({
        uid,
        activityId: 2, // Revoke Privileges
        severityId: 4, // High
        operator,
        targets: [{ uid: tokenId, type: 'capability-token' }],
        message: `Capability token "${tokenId}" revoked`,
        status: 'Success',
        unmapped: { expiresAt: effectiveExpiresAt },
      });
      logger.warn('Token revoked via admin API', { tokenId, expiresAt: effectiveExpiresAt });
      const body = {
        message: `Token ${tokenId} has been revoked`,
        tokenId,
        expiresAt: effectiveExpiresAt,
      };
      await cacheIdempotentResponse(req, 200, body);
      res.json(body);
    } catch (error) {
      logger.error('Failed to revoke token', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Failed to revoke token',
        },
      });
    }
  });

  /**
   * POST /admin/revocation/epoch
   *
   * Set (or replace) the per-issuer revocation epoch.  Every token from the
   * given issuer whose `iat` claim is strictly before `issuedBefore` will be
   * rejected by the gateway on the next verification attempt — without
   * requiring the caller to enumerate individual JTIs.
   *
   * This is the incident-response "single-knob cut-off": if a signing key is
   * believed compromised, set `issuedBefore` to the unix-seconds timestamp of
   * the suspected breach.  All tokens minted from that point back are
   * immediately blocked.
   *
   * Body: `{ issuer: string, issuedBefore: number }`
   *   - `issuer`      — The `iss` claim value of the tokens to block
   *                     (DID or plain string, must match exactly).
   *   - `issuedBefore` — Unix timestamp (seconds).  Tokens with
   *                      `iat < issuedBefore` are rejected.
   *
   * When the gateway is tenant-scoped, `tenantId` must be present in the body.
   */
  router.post('/revocation/epoch', async (req: Request, res: Response): Promise<void> => {
    if (await replayIfIdempotent(req, res)) return;
    if (assertTenantScope(req, res)) return;
    try {
      if (!epochStore) {
        res.status(501).json({
          error: {
            code: 'NOT_IMPLEMENTED',
            message: 'Epoch revocation not available — epoch store not configured',
          },
        });
        return;
      }

      const { issuer, issuedBefore } = req.body;
      if (!issuer || typeof issuer !== 'string') {
        res.status(400).json({
          error: {
            code: 'INVALID_REQUEST',
            message: 'issuer (string) is required',
          },
        });
        return;
      }

      if (
        issuedBefore === undefined ||
        typeof issuedBefore !== 'number' ||
        !Number.isFinite(issuedBefore)
      ) {
        res.status(400).json({
          error: {
            code: 'INVALID_REQUEST',
            message: 'issuedBefore must be a finite number (Unix timestamp in seconds)',
          },
        });
        return;
      }

      await epochStore.setEpoch(issuer, issuedBefore);
      const operator = resolveOperator(req);
      const uid = crypto.randomUUID();
      auditLogger.warn('revocation_epoch_set', {
        eventType: 'revocation_epoch_set',
        issuer,
        issuedBefore,
        operator: operator ?? 'unknown',
        auditEventId: uid,
      });
      emitAdminOcsfEvent({
        uid,
        activityId: 2, // Revoke Privileges
        severityId: 4, // High
        operator,
        targets: [{ uid: issuer, type: 'token-issuer' }],
        message: `Revocation epoch set for issuer "${issuer}": tokens issued before ${issuedBefore} are now rejected`,
        status: 'Success',
        unmapped: { issuedBefore },
      });
      logger.warn('Revocation epoch set via admin API', { issuer, issuedBefore });
      const body = {
        message: `Revocation epoch set for issuer ${issuer}: tokens issued before ${issuedBefore} are now rejected`,
        issuer,
        issuedBefore,
      };
      await cacheIdempotentResponse(req, 200, body);
      res.json(body);
    } catch (error) {
      logger.error('Failed to set revocation epoch', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Failed to set revocation epoch',
        },
      });
    }
  });
}
