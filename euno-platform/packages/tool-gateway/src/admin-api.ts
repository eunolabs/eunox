/**
 * Admin API for Tool Gateway
 * Provides administrative endpoints for kill-switch management and monitoring
 */

import * as crypto from 'crypto';
import { Router, Request, Response, NextFunction } from 'express';
import {
  KillSwitchManager,
  Logger,
  createAuditLogger,
  OcsfAuditTransport,
  OcsfAuthorizationEvent,
} from '@euno/common';
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

// =============================================================================
// Idempotency store
// =============================================================================

interface IdempotencyEntry {
  /** The HTTP status code of the original response. */
  status: number;
  /** The JSON body of the original response. */
  body: unknown;
  /** Endpoint that handled the original request (method + normalised path). */
  endpoint: string;
  /** Expiry in milliseconds since epoch. */
  expiresAt: number;
}

/**
 * In-memory idempotency store for admin API mutations.
 *
 * Keyed by the value of the caller-supplied `Idempotency-Key` header.
 * Entries expire after `ttlMs` (default 24 h) and are pruned lazily on
 * insert when the map grows beyond `maxSize`.
 *
 * This implementation is local-process only.  In a multi-replica deployment
 * the same idempotency key sent to two different replicas will be processed
 * twice.  For Stage 3 this is acceptable — the admin surface already lives
 * on a separate port targeted by a ClusterIP Service, so a single replica
 * typically handles all admin traffic.  A Redis-backed implementation can
 * replace this class without changing the callers.
 */
export class AdminIdempotencyStore {
  private readonly store = new Map<string, IdempotencyEntry>();
  private readonly ttlMs: number;
  private readonly maxSize: number;

  constructor(opts: { ttlMs?: number; maxSize?: number } = {}) {
    this.ttlMs = opts.ttlMs ?? 24 * 60 * 60 * 1000; // 24 h
    this.maxSize = opts.maxSize ?? 10_000;
  }

  /** Return a cached entry if one exists and has not expired; undefined otherwise. */
  get(key: string): IdempotencyEntry | undefined {
    const entry = this.store.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return undefined;
    }
    return entry;
  }

  /** Store a completed response keyed by the idempotency key. */
  set(key: string, endpoint: string, status: number, body: unknown): IdempotencyEntry {
    // Prune expired entries when the store is full to bound memory use.
    if (this.store.size >= this.maxSize) {
      const now = Date.now();
      for (const [k, v] of this.store) {
        if (now > v.expiresAt) this.store.delete(k);
      }
    }
    const entry: IdempotencyEntry = {
      status,
      body,
      endpoint,
      expiresAt: Date.now() + this.ttlMs,
    };
    this.store.set(key, entry);
    return entry;
  }
}

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
  /**
   * Tenant identifier that scopes this admin router instance.
   *
   * When set, every mutating endpoint (kill-switch, revocation, epoch) MUST
   * receive a matching `tenantId` field in the JSON request body.  A request
   * whose `tenantId` differs from this value is rejected with HTTP 403
   * `TENANT_MISMATCH` so a credential issued for tenant A cannot affect
   * resources belonging to tenant B.
   *
   * Global kill-switch operations additionally require
   * `acknowledgesCrossTenantImpact: true` in the body because they block all
   * traffic on the gateway instance irrespective of tenant, and an explicit
   * acknowledgment forces the operator to be deliberate about that blast radius.
   *
   * Plumbed from `ADMIN_TENANT_ID`.  When omitted, no tenant scoping is
   * applied (single-tenant / development deployments).
   */
  tenantId?: string;
  /**
   * OCSF audit transport for admin-action events.
   *
   * When supplied, every mutating admin action emits an OCSF Authorization
   * event (class_uid 3003) to this transport in addition to the existing
   * Winston audit-chain log entries.  This makes admin actions ingestible by
   * any SIEM that speaks OCSF without requiring a Euno-specific parser.
   *
   * The transport must not throw — failures are swallowed per the
   * {@link OcsfAuditTransport} contract.  Passed from
   * `GatewayDependencies.ocsfTransport` by `createAdminApp`.
   */
  ocsfTransport?: OcsfAuditTransport;
  /**
   * Idempotency store shared across all mutating endpoints.
   *
   * When supplied, responses for requests that carry an `Idempotency-Key`
   * header are cached in this store.  Subsequent requests with the same key
   * targeting the same endpoint return the cached response without re-executing
   * the underlying operation.  The same key used against a *different* endpoint
   * is rejected with HTTP 422.
   *
   * Callers that do not pass a store still benefit from the store created
   * internally per-router-instance; pass an explicit store only when you need
   * to share idempotency state across multiple router instances (uncommon).
   */
  idempotencyStore?: AdminIdempotencyStore;
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
    tenantId: configuredTenantId,
    ocsfTransport,
  } = options;

  // Idempotency store: use caller-supplied or create a fresh in-memory one.
  const idempotencyStore = options.idempotencyStore ?? new AdminIdempotencyStore();

  const auditLogger = createAuditLogger('tool-gateway');

  // ── OCSF event builder ──────────────────────────────────────────────────
  // Emits a structured OCSF Authorization event (class_uid 3003) to the
  // configured transport so SIEMs can ingest admin actions without a
  // Euno-specific parser.  The function is a no-op when no transport is set
  // so code paths that call it never need to null-check the transport.
  function emitAdminOcsfEvent(opts: {
    uid: string;
    /** 1=Assign Privileges, 2=Revoke Privileges, 99=Other */
    activityId: 1 | 2 | 99;
    /** OCSF severity ordinal: 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical */
    severityId: number;
    operator?: string;
    /** Zero or more resources acted upon. */
    targets?: Array<{ uid: string; type: string }>;
    message: string;
    status: 'Success' | 'Failure';
    unmapped?: Record<string, unknown>;
  }): void {
    if (!ocsfTransport) return;
    const event: OcsfAuthorizationEvent = {
      class_uid: 3003,
      category_uid: 3,
      activity_id: opts.activityId,
      type_uid: 3003 * 100 + opts.activityId,
      time: Date.now(),
      severity_id: opts.severityId,
      status_id: opts.status === 'Success' ? 1 : 2,
      status: opts.status,
      message: opts.message,
      metadata: {
        version: '1.1.0',
        product: {
          name: 'euno-tool-gateway',
          vendor_name: 'Euno',
          feature: { name: 'admin-api' },
        },
        uid: opts.uid,
      },
      ...(opts.operator ? { actor: { user: { uid: opts.operator } } } : {}),
      ...(opts.targets && opts.targets.length > 0 ? { resources: opts.targets } : {}),
      ...(opts.unmapped || configuredTenantId
        ? {
            unmapped: {
              ...(configuredTenantId ? { tenantId: configuredTenantId } : {}),
              ...(opts.unmapped ?? {}),
            },
          }
        : {}),
    };
    // Fire-and-forget: transport errors must not fail the request.
    ocsfTransport.send(event).catch(() => undefined);
  }

  // ── Idempotency helpers ──────────────────────────────────────────────────
  /**
   * Extract the Idempotency-Key header value, normalised to a string or
   * undefined.  Multiple values (rare but allowed by RFC 7240) use the first.
   */
  function getIdempotencyKey(req: Request): string | undefined {
    const raw = req.headers['idempotency-key'];
    const key = Array.isArray(raw) ? raw[0] : raw;
    return typeof key === 'string' && key.length > 0 ? key : undefined;
  }

  /**
   * Canonical endpoint label used for idempotency-key scoping.
   * Format: `METHOD /path/template` (e.g. `POST /kill-switch/global/activate`).
   */
  function endpointLabel(req: Request): string {
    return `${req.method} ${req.path}`;
  }

  /**
   * Check whether a completed idempotency entry exists for this request.
   * When one is found, reply with the cached response and return `true`
   * (caller should `return` immediately).  Returns `false` otherwise.
   *
   * If the same key was used for a *different* endpoint, reply with 422 and
   * return `true`.
   */
  function replayIfIdempotent(req: Request, res: Response): boolean {
    const key = getIdempotencyKey(req);
    if (!key) return false;
    const cached = idempotencyStore.get(key);
    if (!cached) return false;
    const current = endpointLabel(req);
    if (cached.endpoint !== current) {
      res.status(422).json({
        error: {
          code: 'IDEMPOTENCY_KEY_REUSE',
          message:
            `Idempotency-Key "${key}" was previously used for "${cached.endpoint}" ` +
            `and cannot be reused for "${current}".`,
        },
      });
      return true;
    }
    res.status(cached.status).json(cached.body);
    return true;
  }

  /**
   * Cache the response for a successful idempotency-key request so future
   * retries can be replayed without re-executing the operation.
   */
  function cacheIdempotentResponse(req: Request, status: number, body: unknown): void {
    const key = getIdempotencyKey(req);
    if (!key) return;
    idempotencyStore.set(key, endpointLabel(req), status, body);
  }

  // ── Tenant-scope guard ──────────────────────────────────────────────────
  /**
   * Validate that the request's `tenantId` body field matches the configured
   * tenant when tenant scoping is enabled.
   *
   * Returns `true` if the request has already been answered (validation
   * failed — caller MUST `return` immediately).  Returns `false` if the
   * scope check passed or is not applicable.
   *
   * @param requiresAcknowledgement - When true (global kill-switch), also
   *   require `acknowledgesCrossTenantImpact: true` in the body because the
   *   operation affects all tenants on this gateway instance.
   */
  function assertTenantScope(req: Request, res: Response, requiresAcknowledgement = false): boolean {
    if (!configuredTenantId) return false; // Tenant scoping not configured.

    const provided = req.body?.tenantId;
    if (typeof provided !== 'string' || !provided.trim()) {
      res.status(400).json({
        error: {
          code: 'TENANT_ID_REQUIRED',
          message:
            'tenantId is required in the request body for tenant-scoped operations. ' +
            'Set tenantId to the tenant this gateway instance is scoped to.',
        },
      });
      return true;
    }

    if (provided !== configuredTenantId) {
      logger.warn('Cross-tenant admin operation rejected', {
        providedTenantId: provided,
        configuredTenantId,
        path: req.path,
        operator: resolveOperator(req),
      });
      const uid = crypto.randomUUID();
      emitAdminOcsfEvent({
        uid,
        activityId: 2,
        severityId: 4,
        operator: resolveOperator(req),
        message: `Cross-tenant admin operation rejected: provided tenantId "${provided}" does not match configured tenantId.`,
        status: 'Failure',
        unmapped: { rejectedTenantId: provided, path: req.path },
      });
      res.status(403).json({
        error: {
          code: 'TENANT_MISMATCH',
          message:
            `The provided tenantId "${provided}" does not match this gateway's configured tenant. ` +
            'Admin operations on this endpoint can only target the scoped tenant.',
        },
      });
      return true;
    }

    if (requiresAcknowledgement && req.body?.acknowledgesCrossTenantImpact !== true) {
      res.status(400).json({
        error: {
          code: 'CROSS_TENANT_ACKNOWLEDGEMENT_REQUIRED',
          message:
            'This operation affects all tenants on the gateway instance. ' +
            'Add "acknowledgesCrossTenantImpact": true to the request body to confirm you ' +
            'understand the full blast radius before proceeding.',
        },
      });
      return true;
    }

    return false; // All checks passed.
  }

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
   * Activate the global kill switch (blocks all agents on this gateway instance).
   *
   * ⚠️  When the gateway is tenant-scoped (`ADMIN_TENANT_ID` is set) this
   * operation STILL blocks all tenants because the kill switch is gateway-wide.
   * Callers must acknowledge this explicitly by including
   * `"acknowledgesCrossTenantImpact": true` in the request body.
   */
  router.post('/kill-switch/global/activate', (req: Request, res: Response) => {
    if (replayIfIdempotent(req, res)) return;
    // Global kill is inherently cross-tenant; require acknowledgement when scoped.
    if (assertTenantScope(req, res, /* requiresAcknowledgement */ true)) return;
    try {
      killSwitchManager.activateGlobalKill();
      const operator = resolveOperator(req);
      const uid = crypto.randomUUID();
      auditLogger.warn('kill_switch_global_activated', {
        eventType: 'kill_switch_global_activated',
        operator: operator ?? 'unknown',
        severity: 'CRITICAL',
        auditEventId: uid,
      });
      emitAdminOcsfEvent({
        uid,
        activityId: 2, // Revoke Privileges
        severityId: 5, // Critical
        operator,
        message: 'Global kill switch activated — all agent traffic blocked',
        status: 'Success',
        unmapped: { scope: 'global' },
      });
      logger.warn('Global kill switch activated via admin API', { operator });
      const body = { message: 'Global kill switch activated' };
      cacheIdempotentResponse(req, 200, body);
      res.json(body);
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
   * Deactivate the global kill switch.
   *
   * Same cross-tenant caveat as activate: when tenant-scoped, the acknowledgement
   * field is required because deactivation restores traffic for ALL tenants.
   */
  router.post('/kill-switch/global/deactivate', (req: Request, res: Response) => {
    if (replayIfIdempotent(req, res)) return;
    if (assertTenantScope(req, res, /* requiresAcknowledgement */ true)) return;
    try {
      killSwitchManager.deactivateGlobalKill();
      const operator = resolveOperator(req);
      const uid = crypto.randomUUID();
      auditLogger.info('kill_switch_global_deactivated', {
        eventType: 'kill_switch_global_deactivated',
        operator: operator ?? 'unknown',
        auditEventId: uid,
      });
      emitAdminOcsfEvent({
        uid,
        activityId: 1, // Assign Privileges (restoring access)
        severityId: 2, // Low
        operator,
        message: 'Global kill switch deactivated — agent traffic restored',
        status: 'Success',
        unmapped: { scope: 'global' },
      });
      logger.info('Global kill switch deactivated via admin API', { operator });
      const body = { message: 'Global kill switch deactivated' };
      cacheIdempotentResponse(req, 200, body);
      res.json(body);
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
   * Kill a specific session.
   *
   * When the gateway is tenant-scoped, the request body MUST include a
   * `tenantId` field matching the configured tenant — this prevents an
   * operator credential for tenant A from killing a session that belongs
   * to tenant B.
   */
  router.post('/kill-switch/session/:sessionId/kill', (req: Request, res: Response): void => {
    if (replayIfIdempotent(req, res)) return;
    if (assertTenantScope(req, res)) return;
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
      const operator = resolveOperator(req);
      const uid = crypto.randomUUID();
      auditLogger.warn('kill_switch_session_killed', {
        eventType: 'kill_switch_session_killed',
        sessionId,
        operator: operator ?? 'unknown',
        auditEventId: uid,
      });
      emitAdminOcsfEvent({
        uid,
        activityId: 2, // Revoke Privileges
        severityId: 4, // High
        operator,
        targets: [{ uid: sessionId, type: 'session' }],
        message: `Session "${sessionId}" killed`,
        status: 'Success',
      });
      logger.warn('Session killed via admin API', { sessionId });
      const body = { message: `Session ${sessionId} has been killed` };
      cacheIdempotentResponse(req, 200, body);
      res.json(body);
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
   * Kill a specific agent.
   *
   * When the gateway is tenant-scoped, the request body MUST include a
   * matching `tenantId` field.
   */
  router.post('/kill-switch/agent/:agentId/kill', (req: Request, res: Response): void => {
    if (replayIfIdempotent(req, res)) return;
    if (assertTenantScope(req, res)) return;
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
      const operator = resolveOperator(req);
      const uid = crypto.randomUUID();
      auditLogger.warn('kill_switch_agent_killed', {
        eventType: 'kill_switch_agent_killed',
        agentId,
        operator: operator ?? 'unknown',
        auditEventId: uid,
      });
      emitAdminOcsfEvent({
        uid,
        activityId: 2, // Revoke Privileges
        severityId: 4, // High
        operator,
        targets: [{ uid: agentId, type: 'agent' }],
        message: `Agent "${agentId}" killed`,
        status: 'Success',
      });
      logger.warn('Agent killed via admin API', { agentId });
      const body = { message: `Agent ${agentId} has been killed` };
      cacheIdempotentResponse(req, 200, body);
      res.json(body);
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
   * Revive a killed session.
   */
  router.post('/kill-switch/session/:sessionId/revive', (req: Request, res: Response): void => {
    if (replayIfIdempotent(req, res)) return;
    if (assertTenantScope(req, res)) return;
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
      const operator = resolveOperator(req);
      const uid = crypto.randomUUID();
      auditLogger.info('kill_switch_session_revived', {
        eventType: 'kill_switch_session_revived',
        sessionId,
        operator: operator ?? 'unknown',
        auditEventId: uid,
      });
      emitAdminOcsfEvent({
        uid,
        activityId: 1, // Assign Privileges (restoring access)
        severityId: 2, // Low
        operator,
        targets: [{ uid: sessionId, type: 'session' }],
        message: `Session "${sessionId}" revived`,
        status: 'Success',
      });
      logger.info('Session revived via admin API', { sessionId });
      const body = { message: `Session ${sessionId} has been revived` };
      cacheIdempotentResponse(req, 200, body);
      res.json(body);
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
   * Revive a killed agent.
   */
  router.post('/kill-switch/agent/:agentId/revive', (req: Request, res: Response): void => {
    if (replayIfIdempotent(req, res)) return;
    if (assertTenantScope(req, res)) return;
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
      const operator = resolveOperator(req);
      const uid = crypto.randomUUID();
      auditLogger.info('kill_switch_agent_revived', {
        eventType: 'kill_switch_agent_revived',
        agentId,
        operator: operator ?? 'unknown',
        auditEventId: uid,
      });
      emitAdminOcsfEvent({
        uid,
        activityId: 1, // Assign Privileges (restoring access)
        severityId: 2, // Low
        operator,
        targets: [{ uid: agentId, type: 'agent' }],
        message: `Agent "${agentId}" revived`,
        status: 'Success',
      });
      logger.info('Agent revived via admin API', { agentId });
      const body = { message: `Agent ${agentId} has been revived` };
      cacheIdempotentResponse(req, 200, body);
      res.json(body);
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
   * Reset all kill switches (use with caution).
   *
   * When the gateway is tenant-scoped, this operation resets kills for the
   * configured tenant scope.  Requires the cross-tenant acknowledgement because
   * the underlying manager state is shared across tenants.
   */
  router.post('/kill-switch/reset', (req: Request, res: Response) => {
    if (replayIfIdempotent(req, res)) return;
    if (assertTenantScope(req, res, /* requiresAcknowledgement */ true)) return;
    try {
      killSwitchManager.resetAll();
      const operator = resolveOperator(req);
      const uid = crypto.randomUUID();
      auditLogger.warn('kill_switch_reset_all', {
        eventType: 'kill_switch_reset_all',
        operator: operator ?? 'unknown',
        auditEventId: uid,
      });
      emitAdminOcsfEvent({
        uid,
        activityId: 99, // Other
        severityId: 5, // Critical
        operator,
        message: 'All kill switches reset — all previously blocked sessions/agents are unblocked',
        status: 'Success',
        unmapped: { scope: 'all' },
      });
      logger.warn('All kill switches reset via admin API');
      const body = { message: 'All kill switches have been reset' };
      cacheIdempotentResponse(req, 200, body);
      res.json(body);
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
   * Revoke a capability token by its JTI (JWT ID).
   * Body: { tokenId: string, expiresAt?: number }
   *
   * When the gateway is tenant-scoped, `tenantId` must be present in the body.
   */
  router.post('/revoke', async (req: Request, res: Response): Promise<void> => {
    if (replayIfIdempotent(req, res)) return;
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
      cacheIdempotentResponse(req, 200, body);
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
    if (replayIfIdempotent(req, res)) return;
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
      cacheIdempotentResponse(req, 200, body);
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
