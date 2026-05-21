/**
 * Partner-DID admin route group.
 *
 * Handles:
 *   POST   /admin/partner-did/refresh/:encodedDid  (legacy alias)
 *   GET    /admin/partner-dids
 *   POST   /admin/partner-dids/proposals
 *   POST   /admin/partner-dids/proposals/:did/approve
 *   DELETE /admin/partner-dids/:did
 *   POST   /admin/partner-dids/:did/refresh
 */

import { Router, Request, Response, NextFunction } from 'express';
import {
  PartnerDidStatus,
  PARTNER_DID_STATUSES,
  TwoEyesViolationError,
  PinAttestation,
  createPinAttestation,
  jcsSha256,
  PartnerDidEntry,
} from '../partner-did-registry';
import { AdminRouterContext } from './context';

/**
 * Mount all partner-DID routes onto `router`.
 *
 * Called from `createAdminRouter` after the authentication middleware has been
 * applied, so every handler here can assume the caller is authenticated.
 */
export function mountPartnerDidRoutes(router: Router, ctx: AdminRouterContext): void {
  const {
    logger,
    auditLogger,
    partnerResolver,
    partnerRegistry,
    requirePin,
    resolveDidDocument,
    pinAttestationSecret,
    resolveOperator,
  } = ctx;

  // ── Middleware ─────────────────────────────────────────────────────────────
  // Partner-DID mutations require an X-Admin-Operator header inside the
  // already-authenticated X-Admin-Api-Key channel, so that each operator action
  // has a distinct identity in the audit trail.  The header is treated as an
  // opaque label — it is NOT a separate authentication boundary; security relies
  // on X-Admin-Api-Key as before.
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

  // ── Legacy cache-invalidation alias ───────────────────────────────────────
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

  // ── Registry endpoints ─────────────────────────────────────────────────────

  /**
   * GET /admin/partner-dids
   * List registry entries, optionally filtered by ?status=proposed|active|revoked
   *
   * Uses `PARTNER_DID_STATUSES` for the guard.
   */
  router.get('/partner-dids', async (_req: Request, res: Response): Promise<void> => {
    if (!partnerRegistry) {
      res.status(404).json({ error: { code: 'NOT_CONFIGURED', message: 'Partner-DID registry is not configured' } });
      return;
    }
    try {
      const statusParam = (_req.query.status as string | undefined)?.trim();
      const filter = (statusParam !== undefined && (PARTNER_DID_STATUSES as readonly string[]).includes(statusParam))
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
    let did: string;
    try {
      did = decodeURIComponent(req.params['did'] ?? '');
    } catch {
      res.status(400).json({ error: { code: 'INVALID_REQUEST', message: 'did is not a valid URI-encoded string' } });
      return;
    }
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
      let pinOverrides: Partial<Pick<PartnerDidEntry,
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
    let did: string;
    try {
      did = decodeURIComponent(req.params['did'] ?? '');
    } catch {
      res.status(400).json({ error: { code: 'INVALID_REQUEST', message: 'did is not a valid URI-encoded string' } });
      return;
    }
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
    let did: string;
    try {
      did = decodeURIComponent(req.params['did'] ?? '');
    } catch {
      res.status(400).json({ error: { code: 'INVALID_REQUEST', message: 'did is not a valid URI-encoded string' } });
      return;
    }
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
}
