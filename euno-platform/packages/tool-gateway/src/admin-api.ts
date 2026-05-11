/**
 * Admin API for Tool Gateway
 * Provides administrative endpoints for kill-switch management and monitoring
 */

import * as crypto from 'crypto';
import { Router, Request, Response, NextFunction } from 'express';
import { KillSwitchManager, Logger, createAuditLogger } from '@euno/common';
import { JWTTokenVerifier } from './verifier';
import { RevocationEpochStore } from './revocation-store';
import { PartnerIssuerResolver } from './partner-issuer-resolver';
import {
  PartnerDidRegistry,
  TwoEyesViolationError,
  PartnerDidStatus,
  PinAttestation,
  createPinAttestation,
  jcsSha256,
} from './partner-did-registry';

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
  /**
   * Optional partner-DID registry. When supplied, the admin router exposes
   * the two-eyes proposal/approval/revoke/list/refresh endpoints under
   * `/admin/partner-dids/*`.
   */
  partnerRegistry?: PartnerDidRegistry;
  /**
   * When supplied, the approval endpoint automatically fetches the DID document
   * for proposals that lack a `pinnedDocSha256`, computes the hash, and stores
   * it on the entry.  This removes the manual SHA-256 computation step from
   * the operator's workflow and ensures the hash was derived from the live
   * document at approval time — not from a proposer-supplied value.
   *
   * Pass `resolveDID` from `@euno/capability-issuer/adapters` here.
   * When omitted, auto-fetch is disabled (pin must be supplied in the proposal).
   */
  resolveDidDocument?: (did: string) => Promise<unknown>;
  /**
   * HMAC-SHA-256 secret used to sign pin attestations at approval time.
   * When set, the approval endpoint wraps the computed or proposer-supplied
   * `pinnedDocSha256` in a {@link PinAttestation} that binds the hash to
   * the approving operator and activation timestamp.  The resolver then
   * verifies this signature before trusting the hash — tampered registry
   * entries (e.g. Redis store compromise) cannot forge a valid attestation.
   *
   * Plumbed from `PARTNER_DID_PIN_SECRET`.  When omitted attestations are not
   * created and the resolver skips HMAC verification (hash-only check).
   */
  pinAttestationSecret?: string;
  /**
   * When true, proposals without `pinnedDocSha256` are rejected with HTTP 400.
   * Plumbed from `PARTNER_DID_REQUIRE_PIN`.
   */
  requirePin?: boolean;
  /**
   * Forward-compat hook: derive the operator identity for a request.
   * Defaults to reading `X-Admin-Operator` from the (already-authenticated)
   * request headers.  Override to inject OIDC/mTLS-derived identities in
   * future without touching the registry code.
   */
  resolveOperator?: (req: Request) => string | undefined;
}

/**
 * Create admin API router with authentication
 */
export function createAdminRouter(options: AdminApiOptions): Router {
  const router = Router();
  const {
    killSwitchManager,
    logger,
    adminApiKey,
    tokenVerifier,
    epochStore,
    partnerResolver,
    partnerRegistry,
    requirePin = false,
    resolveDidDocument,
    pinAttestationSecret,
    resolveOperator: resolveOperatorFn,
  } = options;

  const auditLogger = createAuditLogger('tool-gateway');

  // Default operator resolver: read X-Admin-Operator from the authenticated channel.
  const resolveOperator = resolveOperatorFn ?? ((req: Request): string | undefined => {
    const raw = req.headers['x-admin-operator'];
    return (Array.isArray(raw) ? raw[0] : raw) ?? undefined;
  });

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
  router.post('/kill-switch/global/activate', (req: Request, res: Response) => {
    try {
      killSwitchManager.activateGlobalKill();
      const operator = resolveOperator(req);
      auditLogger.warn('kill_switch_global_activated', {
        eventType: 'kill_switch_global_activated',
        operator: operator ?? 'unknown',
        severity: 'CRITICAL',
      });
      logger.warn('Global kill switch activated via admin API', { operator });
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
  router.post('/kill-switch/global/deactivate', (req: Request, res: Response) => {
    try {
      killSwitchManager.deactivateGlobalKill();
      const operator = resolveOperator(req);
      auditLogger.info('kill_switch_global_deactivated', {
        eventType: 'kill_switch_global_deactivated',
        operator: operator ?? 'unknown',
      });
      logger.info('Global kill switch deactivated via admin API', { operator });
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
      auditLogger.warn('kill_switch_session_killed', {
        eventType: 'kill_switch_session_killed',
        sessionId,
        operator: resolveOperator(req) ?? 'unknown',
      });
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
      auditLogger.warn('kill_switch_agent_killed', {
        eventType: 'kill_switch_agent_killed',
        agentId,
        operator: resolveOperator(req) ?? 'unknown',
      });
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
      auditLogger.info('kill_switch_session_revived', {
        eventType: 'kill_switch_session_revived',
        sessionId,
        operator: resolveOperator(req) ?? 'unknown',
      });
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
      auditLogger.info('kill_switch_agent_revived', {
        eventType: 'kill_switch_agent_revived',
        agentId,
        operator: resolveOperator(req) ?? 'unknown',
      });
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
  router.post('/kill-switch/reset', (req: Request, res: Response) => {
    try {
      killSwitchManager.resetAll();
      auditLogger.warn('kill_switch_reset_all', {
        eventType: 'kill_switch_reset_all',
        operator: resolveOperator(req) ?? 'unknown',
      });
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
   * POST /admin/partner-did/refresh/:encodedDid (legacy alias kept for back-compat)
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

  // ── Partner-DID registry endpoints ──────────────────────────────────────
  //
  // These endpoints require the X-Admin-Operator header (inside the
  // already-authenticated X-Admin-Api-Key channel) so that each operator
  // action has a distinct identity in the audit trail.  The header is
  // treated as an opaque label — it is NOT a separate authentication
  // boundary; security relies on X-Admin-Api-Key as today.

  /** Middleware that requires X-Admin-Operator (for proposal/approval/revoke). */
  const requireOperator = (req: Request, res: Response, next: NextFunction): void => {
    const operatorId = resolveOperator(req);
    if (!operatorId || operatorId.trim().length === 0) {
      res.status(400).json({
        error: {
          code: 'MISSING_OPERATOR',
          message: 'X-Admin-Operator header is required for this endpoint',
        },
      });
      return;
    }
    next();
  };

  /**
   * GET /admin/partner-dids
   * List registry entries, optionally filtered by ?status=proposed|active|revoked
   */
  router.get('/partner-dids', async (_req: Request, res: Response): Promise<void> => {
    if (!partnerRegistry) {
      res.status(404).json({ error: { code: 'NOT_CONFIGURED', message: 'Partner-DID registry is not configured' } });
      return;
    }
    try {
      const statusParam = (_req.query.status as string | undefined)?.trim();
      const filter = (['proposed', 'active', 'revoked'].includes(statusParam ?? ''))
        ? statusParam as PartnerDidStatus
        : undefined;
      const entries = await partnerRegistry.list(filter);
      res.json({ entries });
    } catch (error) {
      logger.error('Failed to list partner DIDs', { error: error instanceof Error ? error.message : 'Unknown' });
      res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Failed to list partner DIDs' } });
    }
  });

  /**
   * POST /admin/partner-dids/proposals
   * Create a new entry in `proposed` state.
   * Body: { did, pinnedDocSha256?, pinnedVerificationKeys?, secondaryResolver?, notBefore?, notAfter?, notes? }
   */
  router.post('/partner-dids/proposals', requireOperator, async (req: Request, res: Response): Promise<void> => {
    if (!partnerRegistry) {
      res.status(404).json({ error: { code: 'NOT_CONFIGURED', message: 'Partner-DID registry is not configured' } });
      return;
    }
    const operator = resolveOperator(req)!;
    const { did, pinnedDocSha256, pinnedVerificationKeys, secondaryResolver, notBefore, notAfter, notes } = req.body;
    if (!did || typeof did !== 'string') {
      res.status(400).json({ error: { code: 'INVALID_REQUEST', message: 'did (string) is required' } });
      return;
    }
    // Enforce pin discipline when PARTNER_DID_REQUIRE_PIN is set.
    if (requirePin && typeof pinnedDocSha256 !== 'string') {
      res.status(400).json({
        error: {
          code: 'PIN_REQUIRED',
          message:
            'PARTNER_DID_REQUIRE_PIN is enabled: pinnedDocSha256 is required for all proposals. ' +
            'Compute it with: SHA-256(JCS(DID document)) encoded as lowercase hex.',
        },
      });
      return;
    }
    try {
      const entry = await partnerRegistry.propose({
        did,
        proposer: operator,
        ...(pinnedDocSha256 ? { pinnedDocSha256 } : {}),
        ...(pinnedVerificationKeys ? { pinnedVerificationKeys } : {}),
        ...(secondaryResolver ? { secondaryResolver } : {}),
        ...(notBefore !== undefined ? { notBefore } : {}),
        ...(notAfter !== undefined ? { notAfter } : {}),
        ...(notes ? { notes } : {}),
      });
      auditLogger.info('partner_did_proposed', {
        eventType: 'partner_did_proposed',
        did,
        proposer: operator,
      });
      logger.info('Partner DID proposed via admin API', { did, operator });
      res.status(201).json({ entry });
    } catch (error) {
      const msg = error instanceof Error ? error.message : 'Unknown error';
      if (msg.includes('already exists')) {
        res.status(409).json({ error: { code: 'CONFLICT', message: msg } });
        return;
      }
      logger.error('Failed to propose partner DID', { error: msg });
      res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Failed to propose partner DID' } });
    }
  });

  /**
   * POST /admin/partner-dids/proposals/:did/approve
   * Approve a proposed entry (two-eyes: approver must differ from proposer).
   */
  router.post('/partner-dids/proposals/:did/approve', requireOperator, async (req: Request, res: Response): Promise<void> => {
    if (!partnerRegistry) {
      res.status(404).json({ error: { code: 'NOT_CONFIGURED', message: 'Partner-DID registry is not configured' } });
      return;
    }
    const operator = resolveOperator(req)!;
    const did = decodeURIComponent(req.params['did'] ?? '');
    if (!did) {
      res.status(400).json({ error: { code: 'INVALID_REQUEST', message: 'DID path parameter is required' } });
      return;
    }
    try {
      // ── Auto-fetch DID document and sign pin attestation ─────────────────────
      //
      // When resolveDidDocument is wired (PARTNER_DID_AUTO_FETCH_PIN=true in
      // bootstrap), we fetch the live DID document at approval time so:
      //   (a) the pin is computed from the real document, not an operator-typed
      //       SHA-256 that could be wrong or spoofed, and
      //   (b) approval fails fast if the DID endpoint is unreachable or
      //       returns garbage — the approver knows immediately rather than
      //       discovering a broken trust root the first time a token arrives.
      //
      // pinOverrides is merged into the entry as part of the atomic approve()
      // call, keeping the state transition consistent.
      let pinOverrides: Partial<Pick<import('./partner-did-registry').PartnerDidEntry,
        'pinnedDocSha256' | 'pinnedVerificationKeys' | 'pinAttestation'>> | undefined;

      if (resolveDidDocument) {
        // Peek at the current entry to know whether a pin was already supplied.
        const proposed = await partnerRegistry.get(did);
        if (!proposed) {
          res.status(404).json({ error: { code: 'NOT_FOUND', message: `Partner DID not found: ${did}` } });
          return;
        }

        let effectivePinnedDocSha256 = proposed.pinnedDocSha256;

        if (!effectivePinnedDocSha256) {
          // Auto-compute: fetch the live DID document and hash it.
          let didDoc: unknown;
          try {
            didDoc = await resolveDidDocument(did);
          } catch (fetchErr) {
            const detail = fetchErr instanceof Error ? fetchErr.message : String(fetchErr);
            logger.error('Auto-fetch of DID document failed during approval', { did, error: detail });
            res.status(502).json({
              error: {
                code: 'DID_FETCH_FAILED',
                message: `Could not fetch DID document for ${did} during approval: ${detail}`,
              },
            });
            return;
          }
          effectivePinnedDocSha256 = jcsSha256(didDoc);
          logger.info('Auto-computed DID document pin at approval', {
            eventType: 'partner_did_pin_auto_computed',
            did,
            approver: operator,
            pinnedDocSha256: effectivePinnedDocSha256,
          });
        }

        // Sign the pin attestation when a secret is configured.
        pinOverrides = { pinnedDocSha256: effectivePinnedDocSha256 };
        if (pinAttestationSecret) {
          // activatedAt is set inside approve(); use Date.now() here for the
          // attestation — the registry will also stamp activatedAt to ~this time.
          const activatedAt = Date.now();
          const attestation: PinAttestation = createPinAttestation(
            {
              did,
              pinnedDocSha256: effectivePinnedDocSha256,
              approver: operator,
              activatedAt,
            },
            pinAttestationSecret,
          );
          pinOverrides.pinAttestation = attestation;
          logger.info('Pin attestation created at approval', {
            eventType: 'partner_did_pin_attestation_created',
            did,
            approver: operator,
          });
        }
      } else if (pinAttestationSecret) {
        // resolveDidDocument not wired, but we have a secret. Sign over the
        // proposer-supplied pin (if any) so the hash at least has provenance.
        const proposed = await partnerRegistry.get(did);
        if (proposed?.pinnedDocSha256) {
          const activatedAt = Date.now();
          pinOverrides = {
            pinAttestation: createPinAttestation(
              {
                did,
                pinnedDocSha256: proposed.pinnedDocSha256,
                approver: operator,
                activatedAt,
              },
              pinAttestationSecret,
            ),
          };
          logger.info('Pin attestation signed over proposer-supplied hash', {
            eventType: 'partner_did_pin_attestation_created',
            did,
            approver: operator,
          });
        }
      }
      // ── End auto-fetch / attestation ─────────────────────────────────────────

      const entry = await partnerRegistry.approve(did, operator, pinOverrides);
      auditLogger.info('partner_did_approved', {
        eventType: 'partner_did_approved',
        did,
        approver: operator,
        pinnedDocSha256: entry.pinnedDocSha256 ?? null,
        hasAttestation: !!entry.pinAttestation,
      });
      // Invalidate resolver cache so the new trust takes effect immediately.
      if (partnerResolver) partnerResolver.invalidateAll(did);
      logger.info('Partner DID approved via admin API', { did, operator });
      res.json({ entry });
    } catch (error) {
      if (error instanceof TwoEyesViolationError) {
        auditLogger.warn('partner_did_two_eyes_violation', {
          eventType: 'partner_did_two_eyes_violation',
          did,
          operator,
        });
        res.status(403).json({ error: { code: 'TWO_EYES_VIOLATION', message: error.message } });
        return;
      }
      const msg = error instanceof Error ? error.message : 'Unknown error';
      if (msg.includes('not found')) {
        res.status(404).json({ error: { code: 'NOT_FOUND', message: msg } });
        return;
      }
      if (msg.includes('cannot be approved')) {
        res.status(409).json({ error: { code: 'CONFLICT', message: msg } });
        return;
      }
      logger.error('Failed to approve partner DID', { error: msg });
      res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Failed to approve partner DID' } });
    }
  });

  /**
   * DELETE /admin/partner-dids/:did
   * Revoke a partner DID (single-operator — incident response is fast).
   * Body: { reason? }
   */
  router.delete('/partner-dids/:did', requireOperator, async (req: Request, res: Response): Promise<void> => {
    if (!partnerRegistry) {
      res.status(404).json({ error: { code: 'NOT_CONFIGURED', message: 'Partner-DID registry is not configured' } });
      return;
    }
    const operator = resolveOperator(req)!;
    const did = decodeURIComponent(req.params['did'] ?? '');
    if (!did) {
      res.status(400).json({ error: { code: 'INVALID_REQUEST', message: 'DID path parameter is required' } });
      return;
    }
    try {
      const entry = await partnerRegistry.revoke(did, operator);
      auditLogger.warn('partner_did_revoked', {
        eventType: 'partner_did_revoked',
        did,
        revokedBy: operator,
        reason: req.body?.reason,
      });
      // Invalidate resolver cache so tokens from this DID are immediately rejected.
      if (partnerResolver) partnerResolver.invalidateAll(did);
      logger.warn('Partner DID revoked via admin API', { did, operator });
      res.json({ entry });
    } catch (error) {
      const msg = error instanceof Error ? error.message : 'Unknown error';
      if (msg.includes('not found')) {
        res.status(404).json({ error: { code: 'NOT_FOUND', message: msg } });
        return;
      }
      logger.error('Failed to revoke partner DID', { error: msg });
      res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Failed to revoke partner DID' } });
    }
  });

  /**
   * POST /admin/partner-dids/:did/refresh
   * Invalidate the resolver cache for a DID and re-validate against the pin.
   * Also available as the legacy /admin/partner-did/refresh/:encodedDid alias.
   * Requires X-Admin-Operator for audit trail consistency with other mutations.
   */
  router.post('/partner-dids/:did/refresh', requireOperator, async (req: Request, res: Response): Promise<void> => {
    const did = decodeURIComponent(req.params['did'] ?? '');
    if (!did) {
      res.status(400).json({ error: { code: 'INVALID_REQUEST', message: 'DID path parameter is required' } });
      return;
    }
    if (!partnerResolver && !partnerRegistry) {
      res.status(404).json({ error: { code: 'NOT_CONFIGURED', message: 'Partner-DID resolver/registry is not configured' } });
      return;
    }
    // Check trust (from either the resolver's legacy set or the registry).
    const isTrusted = partnerResolver
      ? (await partnerResolver.trustsAsync(did))
      : (partnerRegistry ? await partnerRegistry.trusts(did) : false);
    if (!isTrusted) {
      res.status(404).json({ error: { code: 'UNKNOWN_DID', message: `DID is not trusted: ${did}` } });
      return;
    }
    if (partnerResolver) partnerResolver.invalidateAll(did);
    const operator = resolveOperator(req);
    auditLogger.info('partner_did_refreshed', {
      eventType: 'partner_did_refreshed',
      did,
      operator: operator ?? 'unknown',
    });
    logger.info('Partner DID cache refreshed via admin API', { eventType: 'partner_did_cache_admin_refresh', did });
    res.json({ message: `Cache for partner DID ${did} has been cleared`, did });
  });

  return router;
}
