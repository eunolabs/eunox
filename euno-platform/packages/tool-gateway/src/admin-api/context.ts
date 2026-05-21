/**
 * Shared context object threaded through every admin sub-router.
 *
 * Bundles all the raw dependencies (managers, stores, logger) that the
 * route groups need, together with pre-bound helper functions derived from
 * those dependencies.  `createAdminRouter` builds this object once and passes
 * it to each `mount*Routes` call so the helper closures are not copy-pasted
 * across files.
 */

import { Request, Response } from 'express';
import {
  KillSwitchManager,
  Logger,
  OcsfAuditTransport,
  OcsfAuthorizationEvent,
  UsageMeter,
} from '@euno/common';
import { JWTTokenVerifier } from '../verifier';
import { RevocationEpochStore } from '../revocation-store';
import { PartnerIssuerResolver } from '../partner-issuer-resolver';
import { PartnerDidRegistry } from '../partner-did-registry';
import { IAdminIdempotencyStore } from './idempotency';

// Re-export for convenience so sub-modules only import from context.
export type { IAdminIdempotencyStore };

// ---------------------------------------------------------------------------
// OCSF helper options
// ---------------------------------------------------------------------------

/** Options bag for the `emitAdminOcsfEvent` helper. */
export interface OcsfEventOptions {
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
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

/**
 * All dependencies and pre-bound helpers available inside every admin sub-router.
 *
 * Sub-routers receive this via their `mount*Routes(router, ctx)` parameter
 * rather than closing over isolated copies of each helper, keeping each
 * sub-router file self-contained and testable.
 */
export interface AdminRouterContext {
  // ── Raw dependencies ───────────────────────────────────────────────────
  killSwitchManager: KillSwitchManager;
  logger: Logger;
  /** Audit-chain logger (separate from the request logger). */
  auditLogger: ReturnType<typeof import('@euno/common').createAuditLogger>;
  tokenVerifier?: JWTTokenVerifier;
  epochStore?: RevocationEpochStore;
  partnerResolver?: PartnerIssuerResolver;
  partnerRegistry?: PartnerDidRegistry;
  requirePin: boolean;
  resolveDidDocument?: (did: string) => Promise<unknown>;
  pinAttestationSecret?: string;
  configuredTenantId?: string;
  ocsfTransport?: OcsfAuditTransport;
  usageMeter?: UsageMeter;
  auditRetentionDays?: number;
  killSwitchFailOpenOnWrite: boolean;
  idempotencyStore: IAdminIdempotencyStore;

  // ── Pre-bound helpers ──────────────────────────────────────────────────

  /**
   * Derive the operator identity string from an authenticated request.
   * Reads the `X-Admin-Operator` header by default; injectable for JWT/mTLS.
   */
  resolveOperator(req: Request): string | undefined;

  /**
   * Fire-and-forget: emit an OCSF Authorization event (class_uid 3003) to
   * the configured transport.  No-op when no transport is set.
   */
  emitAdminOcsfEvent(opts: OcsfEventOptions): void;

  /**
   * Check the idempotency store for a cached response for this request.
   * When one is found, reply with the cached response and return `true`
   * (caller should `return` immediately).  Returns `false` otherwise.
   * Replies 422 when the same key was previously used for a different endpoint.
   */
  replayIfIdempotent(req: Request, res: Response): Promise<boolean>;

  /**
   * Persist the response for future idempotent replays.
   * No-op when no `Idempotency-Key` header is present.
   */
  cacheIdempotentResponse(req: Request, status: number, body: unknown): Promise<void>;

  /**
   * Validate that the request's `tenantId` body field matches the configured
   * tenant when tenant scoping is enabled.
   *
   * Returns `true` if the request has already been answered (validation
   * failed — caller MUST `return` immediately).  Returns `false` if the
   * scope check passed or is not applicable.
   */
  assertTenantScope(req: Request, res: Response, requiresAcknowledgement?: boolean): boolean;

  /**
   * Build the appropriate success status + body for a kill-switch mutation,
   * reflecting whether `killSwitchFailOpenOnWrite` is set.
   */
  killSwitchSuccessResponse(message: string): { status: number; body: Record<string, unknown> };

  /**
   * Derive the billing tenant identifier to attribute a kill-switch
   * invocation against, falling back to `'_unscoped'` when unset.
   */
  killSwitchTenantId(req: Request): string;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Build the `AdminRouterContext` from a fully-resolved options object and
 * pre-constructed shared state (audit-logger, idempotency store, HMAC keys).
 *
 * This is the only place where the helper closures are constructed; each
 * sub-router receives the finished context and never re-implements the logic.
 */
export function buildAdminRouterContext(opts: {
  killSwitchManager: KillSwitchManager;
  logger: Logger;
  auditLogger: ReturnType<typeof import('@euno/common').createAuditLogger>;
  tokenVerifier?: JWTTokenVerifier;
  epochStore?: RevocationEpochStore;
  partnerResolver?: PartnerIssuerResolver;
  partnerRegistry?: PartnerDidRegistry;
  requirePin: boolean;
  resolveDidDocument?: (did: string) => Promise<unknown>;
  pinAttestationSecret?: string;
  resolveOperatorFn?: (req: Request) => string | undefined;
  configuredTenantId?: string;
  ocsfTransport?: OcsfAuditTransport;
  usageMeter?: UsageMeter;
  auditRetentionDays?: number;
  killSwitchFailOpenOnWrite: boolean;
  idempotencyStore: IAdminIdempotencyStore;
}): AdminRouterContext {
  const {
    killSwitchManager,
    logger,
    auditLogger,
    tokenVerifier,
    epochStore,
    partnerResolver,
    partnerRegistry,
    requirePin,
    resolveDidDocument,
    pinAttestationSecret,
    resolveOperatorFn,
    configuredTenantId,
    ocsfTransport,
    usageMeter,
    auditRetentionDays,
    killSwitchFailOpenOnWrite,
    idempotencyStore,
  } = opts;

  // ── resolveOperator ──────────────────────────────────────────────────────
  const resolveOperator = resolveOperatorFn ?? ((req: Request): string | undefined => {
    const raw = req.headers['x-admin-operator'];
    return (Array.isArray(raw) ? raw[0] : raw) ?? undefined;
  });

  // ── emitAdminOcsfEvent ───────────────────────────────────────────────────
  function emitAdminOcsfEvent(eopts: OcsfEventOptions): void {
    if (!ocsfTransport) return;
    const event: OcsfAuthorizationEvent = {
      class_uid: 3003,
      category_uid: 3,
      activity_id: eopts.activityId,
      type_uid: 3003 * 100 + eopts.activityId,
      time: Date.now(),
      severity_id: eopts.severityId,
      status_id: eopts.status === 'Success' ? 1 : 2,
      status: eopts.status,
      message: eopts.message,
      metadata: {
        version: '1.1.0',
        product: {
          name: 'euno-tool-gateway',
          vendor_name: 'Euno',
          feature: { name: 'admin-api' },
        },
        uid: eopts.uid,
      },
      ...(eopts.operator ? { actor: { user: { uid: eopts.operator } } } : {}),
      ...(eopts.targets && eopts.targets.length > 0 ? { resources: eopts.targets } : {}),
      ...(eopts.unmapped || configuredTenantId
        ? {
            unmapped: {
              ...(configuredTenantId ? { tenantId: configuredTenantId } : {}),
              ...(eopts.unmapped ?? {}),
            },
          }
        : {}),
    };
    ocsfTransport.send(event).catch(() => undefined);
  }

  // ── Idempotency helpers ──────────────────────────────────────────────────
  function getIdempotencyKey(req: Request): string | undefined {
    const raw = req.headers['idempotency-key'];
    const key = Array.isArray(raw) ? raw[0] : raw;
    return typeof key === 'string' && key.length > 0 ? key : undefined;
  }

  function endpointLabel(req: Request): string {
    return `${req.method} ${req.path}`;
  }

  async function replayIfIdempotent(req: Request, res: Response): Promise<boolean> {
    const key = getIdempotencyKey(req);
    if (!key) return false;
    const cached = await Promise.resolve(idempotencyStore.get(key));
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

  async function cacheIdempotentResponse(req: Request, status: number, body: unknown): Promise<void> {
    const key = getIdempotencyKey(req);
    if (!key) return;
    await Promise.resolve(idempotencyStore.set(key, endpointLabel(req), status, body));
  }

  // ── Tenant-scope guard ───────────────────────────────────────────────────
  function assertTenantScope(req: Request, res: Response, requiresAcknowledgement = false): boolean {
    if (!configuredTenantId) return false;

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

    return false;
  }

  // ── Kill-switch helpers ──────────────────────────────────────────────────
  function killSwitchSuccessResponse(message: string): { status: number; body: Record<string, unknown> } {
    if (killSwitchFailOpenOnWrite) {
      return {
        status: 207,
        body: {
          message,
          fleetPropagationPending: true,
          warning:
            'Kill applied to this replica only. Fleet-wide propagation is ' +
            'pending Redis recovery (KILL_SWITCH_FAIL_OPEN_ON_WRITE=true). ' +
            'Verify Redis connectivity and re-issue the kill once it is restored.',
        },
      };
    }
    return { status: 200, body: { message } };
  }

  function killSwitchTenantId(req: Request): string {
    const bodyTenantId =
      typeof req.body?.tenantId === 'string' ? req.body.tenantId.trim() : '';
    return (
      configuredTenantId ??
      (bodyTenantId.length > 0 ? bodyTenantId : undefined) ??
      '_unscoped'
    );
  }

  return {
    killSwitchManager,
    logger,
    auditLogger,
    tokenVerifier,
    epochStore,
    partnerResolver,
    partnerRegistry,
    requirePin,
    resolveDidDocument,
    pinAttestationSecret,
    configuredTenantId,
    ocsfTransport,
    usageMeter,
    auditRetentionDays,
    killSwitchFailOpenOnWrite,
    idempotencyStore,
    resolveOperator,
    emitAdminOcsfEvent,
    replayIfIdempotent,
    cacheIdempotentResponse,
    assertTenantScope,
    killSwitchSuccessResponse,
    killSwitchTenantId,
  };
}

// Node built-ins used by the helpers above.
import * as crypto from 'crypto';
