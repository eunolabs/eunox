/**
 * Admin API for Tool Gateway
 * Provides administrative endpoints for kill-switch management and monitoring
 */

import * as crypto from 'crypto';
import { Router, Request, Response, NextFunction } from 'express';
import { KillSwitchManager, Logger } from '@euno/common';
import { JWTTokenVerifier } from './verifier';
import { RevocationEpochStore } from './revocation-store';
import { PartnerIssuerResolver } from './partner-issuer-resolver';

export interface AdminApiOptions {
  killSwitchManager: KillSwitchManager;
  logger: Logger;
  adminApiKey?: string;
  tokenVerifier?: JWTTokenVerifier;
  /**
   * Optional per-issuer epoch store.  When supplied the admin router exposes
   * `POST /admin/revocation/epoch` so incident responders can set a cut-off
   * timestamp that invalidates every token from a given issuer issued before
   * that point — without enumerating individual JTIs.
   */
  epochStore?: RevocationEpochStore;
  /**
   * Optional partner-issuer resolver. When supplied the admin router
   * exposes a `POST /admin/partner-did/refresh/:encodedDid` endpoint
   * that drops all cached (positive and negative) entries for a DID
   * so the next token from that partner forces a fresh resolution.
   * Useful for incident response when a partner rotates its signing
   * key out-of-band or when a transient resolver outage has pinned a
   * stale negative-cache entry.
   */
  partnerResolver?: PartnerIssuerResolver;
}

/**
 * Create admin API router with authentication
 */
export function createAdminRouter(options: AdminApiOptions): Router {
  const router = Router();
  const { killSwitchManager, logger, adminApiKey, tokenVerifier, epochStore, partnerResolver } = options;

  // Authentication middleware for admin endpoints
  const authenticateAdmin = (req: Request, res: Response, next: NextFunction): void => {
    if (adminApiKey) {
      // Normalise to a single string – Express allows headers to be string[]
      const rawHeader = req.headers['x-admin-api-key'];
      const providedKey = Array.isArray(rawHeader) ? rawHeader[0] : rawHeader;

      // Use timing-safe comparison to prevent key-leakage via timing attacks
      const isValid =
        typeof providedKey === 'string' &&
        providedKey.length === adminApiKey.length &&
        crypto.timingSafeEqual(Buffer.from(providedKey), Buffer.from(adminApiKey));

      if (!isValid) {
        logger.warn('Unauthorized admin API access attempt', {
          ip: req.ip,
          path: req.path,
        });
        res.status(401).json({
          error: {
            code: 'UNAUTHORIZED',
            message: 'Valid admin API key required',
          },
        });
        return;
      }
    }
    next();
  };

  // Apply authentication to all admin routes
  router.use(authenticateAdmin);

  /**
   * GET /admin/kill-switch/status
   * Get the current status of all kill switches
   */
  router.get('/kill-switch/status', (_req: Request, res: Response) => {
    try {
      const status = killSwitchManager.getStatus();
      res.json(status);
    } catch (error) {
      logger.error('Failed to get kill-switch status', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Failed to get kill-switch status',
        },
      });
    }
  });

  /**
   * POST /admin/kill-switch/global/activate
   * Activate the global kill switch (blocks all agents)
   */
  router.post('/kill-switch/global/activate', (_req: Request, res: Response) => {
    try {
      killSwitchManager.activateGlobalKill();
      logger.warn('Global kill switch activated via admin API');
      res.json({ message: 'Global kill switch activated' });
    } catch (error) {
      logger.error('Failed to activate global kill switch', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Failed to activate global kill switch',
        },
      });
    }
  });

  /**
   * POST /admin/kill-switch/global/deactivate
   * Deactivate the global kill switch
   */
  router.post('/kill-switch/global/deactivate', (_req: Request, res: Response) => {
    try {
      killSwitchManager.deactivateGlobalKill();
      logger.info('Global kill switch deactivated via admin API');
      res.json({ message: 'Global kill switch deactivated' });
    } catch (error) {
      logger.error('Failed to deactivate global kill switch', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Failed to deactivate global kill switch',
        },
      });
    }
  });

  /**
   * POST /admin/kill-switch/session/:sessionId/kill
   * Kill a specific session
   */
  router.post('/kill-switch/session/:sessionId/kill', (req: Request, res: Response): void => {
    try {
      const { sessionId } = req.params;
      if (!sessionId) {
        res.status(400).json({
          error: {
            code: 'INVALID_REQUEST',
            message: 'sessionId parameter is required',
          },
        });
        return;
      }

      killSwitchManager.killSession(sessionId);
      logger.warn('Session killed via admin API', { sessionId });
      res.json({ message: `Session ${sessionId} has been killed` });
    } catch (error) {
      logger.error('Failed to kill session', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Failed to kill session',
        },
      });
    }
  });

  /**
   * POST /admin/kill-switch/agent/:agentId/kill
   * Kill a specific agent
   */
  router.post('/kill-switch/agent/:agentId/kill', (req: Request, res: Response): void => {
    try {
      const { agentId } = req.params;
      if (!agentId) {
        res.status(400).json({
          error: {
            code: 'INVALID_REQUEST',
            message: 'agentId parameter is required',
          },
        });
        return;
      }

      killSwitchManager.killAgent(agentId);
      logger.warn('Agent killed via admin API', { agentId });
      res.json({ message: `Agent ${agentId} has been killed` });
    } catch (error) {
      logger.error('Failed to kill agent', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Failed to kill agent',
        },
      });
    }
  });

  /**
   * POST /admin/kill-switch/session/:sessionId/revive
   * Revive a killed session
   */
  router.post('/kill-switch/session/:sessionId/revive', (req: Request, res: Response): void => {
    try {
      const { sessionId } = req.params;
      if (!sessionId) {
        res.status(400).json({
          error: {
            code: 'INVALID_REQUEST',
            message: 'sessionId parameter is required',
          },
        });
        return;
      }

      killSwitchManager.reviveSession(sessionId);
      logger.info('Session revived via admin API', { sessionId });
      res.json({ message: `Session ${sessionId} has been revived` });
    } catch (error) {
      logger.error('Failed to revive session', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Failed to revive session',
        },
      });
    }
  });

  /**
   * POST /admin/kill-switch/agent/:agentId/revive
   * Revive a killed agent
   */
  router.post('/kill-switch/agent/:agentId/revive', (req: Request, res: Response): void => {
    try {
      const { agentId } = req.params;
      if (!agentId) {
        res.status(400).json({
          error: {
            code: 'INVALID_REQUEST',
            message: 'agentId parameter is required',
          },
        });
        return;
      }

      killSwitchManager.reviveAgent(agentId);
      logger.info('Agent revived via admin API', { agentId });
      res.json({ message: `Agent ${agentId} has been revived` });
    } catch (error) {
      logger.error('Failed to revive agent', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Failed to revive agent',
        },
      });
    }
  });

  /**
   * POST /admin/kill-switch/reset
   * Reset all kill switches (use with caution)
   */
  router.post('/kill-switch/reset', (_req: Request, res: Response) => {
    try {
      killSwitchManager.resetAll();
      logger.warn('All kill switches reset via admin API');
      res.json({ message: 'All kill switches have been reset' });
    } catch (error) {
      logger.error('Failed to reset kill switches', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Failed to reset kill switches',
        },
      });
    }
  });

  /**
   * POST /admin/revoke
   * Revoke a capability token by its JTI (JWT ID)
   * Body: { tokenId: string, expiresAt?: number }
   */
  router.post('/revoke', async (req: Request, res: Response): Promise<void> => {
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
      logger.warn('Token revoked via admin API', { tokenId, expiresAt: effectiveExpiresAt });
      res.json({
        message: `Token ${tokenId} has been revoked`,
        tokenId,
        expiresAt: effectiveExpiresAt,
      });
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
   */
  router.post('/revocation/epoch', async (req: Request, res: Response): Promise<void> => {
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
      logger.warn('Revocation epoch set via admin API', { issuer, issuedBefore });
      res.json({
        message: `Revocation epoch set for issuer ${issuer}: tokens issued before ${issuedBefore} are now rejected`,
        issuer,
        issuedBefore,
      });
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

  /**
   * POST /admin/partner-did/refresh/:encodedDid
   *
   * Drops all cached (positive and negative) DID-document entries for
   * the given partner DID so the next token from that partner triggers
   * a fresh resolution. Useful for:
   *  - Incident response when a partner has rotated its signing key
   *    out-of-band and the cache is serving the stale key.
   *  - Clearing a negative-cache entry after a transient resolver
   *    outage has been resolved.
   *
   * The DID must be URL-encoded in the path (e.g.
   * `did%3Aweb%3Apartner.example.com`).
   *
   * Returns 404 when the resolver is not configured (no
   * TRUSTED_PARTNER_DIDS) — a safe no-op signal.
   */
  router.post('/partner-did/refresh/:encodedDid', (req: Request, res: Response): void => {
    try {
      const encodedDid = req.params['encodedDid'];
      if (!encodedDid) {
        res.status(400).json({
          error: { code: 'INVALID_REQUEST', message: 'encodedDid path parameter is required' },
        });
        return;
      }

      let did: string;
      try {
        did = decodeURIComponent(encodedDid);
      } catch {
        res.status(400).json({
          error: { code: 'INVALID_REQUEST', message: 'encodedDid is not a valid URI-encoded string' },
        });
        return;
      }

      if (!partnerResolver) {
        res.status(404).json({
          error: {
            code: 'NOT_CONFIGURED',
            message: 'Partner-issuer resolver is not configured on this gateway (TRUSTED_PARTNER_DIDS is unset)',
          },
        });
        return;
      }

      if (!partnerResolver.trusts(did)) {
        res.status(404).json({
          error: {
            code: 'UNKNOWN_DID',
            message: `DID is not in the trusted partner set: ${did}`,
          },
        });
        return;
      }

      partnerResolver.invalidateAll(did);
      logger.info('Partner DID cache refreshed via admin API', {
        eventType: 'partner_did_cache_admin_refresh',
        did,
      });
      res.json({ message: `Cache for partner DID ${did} has been cleared`, did });
    } catch (error) {
      logger.error('Failed to refresh partner DID cache', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({
        error: { code: 'INTERNAL_ERROR', message: 'Failed to refresh partner DID cache' },
      });
    }
  });

  return router;
}
