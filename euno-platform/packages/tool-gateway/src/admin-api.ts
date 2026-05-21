/**
 * Admin API for Tool Gateway — thin assembler.
 *
 * This file owns:
 *   • All public type/class exports (backward-compat surface)
 *   • `AdminApiOptions` interface
 *   • `createAdminRouter` — builds the shared context and mounts each route
 *     group from the dedicated sub-modules
 *
 * Route implementations live in:
 *   ./admin-api/kill-switch.ts
 *   ./admin-api/revocation.ts
 *   ./admin-api/partner-dids.ts
 *   ./routes/usage.ts
 */

import * as crypto from 'crypto';
import { Router, Request, Response, NextFunction } from 'express';
import {
  KillSwitchManager,
  Logger,
  createAuditLogger,
  OcsfAuditTransport,
  UsageMeter,
} from '@euno/common';
import { JWTTokenVerifier } from './verifier';
import { RevocationEpochStore } from './revocation-store';
import { PartnerIssuerResolver } from './partner-issuer-resolver';
import { PartnerDidRegistry } from './partner-did-registry';
import { mountUsageRoutes } from './routes/usage';
import { buildAdminRouterContext } from './admin-api/context';
import { mountKillSwitchRoutes } from './admin-api/kill-switch';
import { mountRevocationRoutes } from './admin-api/revocation';
import { mountPartnerDidRoutes } from './admin-api/partner-dids';

// =============================================================================
// Re-export idempotency types (public API — callers import from 'admin-api')
// =============================================================================
export {
  IdempotencyEntry,
  IAdminIdempotencyStore,
  RedisIdempotencyClient,
  AdminIdempotencyStore,
  RedisAdminIdempotencyStore,
  createAdminIdempotencyStore,
} from './admin-api/idempotency';

// Import for internal use (instantiating the default store when none supplied).
import { AdminIdempotencyStore as InMemoryIdempotencyStore, IAdminIdempotencyStore } from './admin-api/idempotency';

// =============================================================================
// AdminApiOptions
// =============================================================================

/**
 * Options for {@link createAdminRouter}.
 */
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
   * `pinnedDocSha256` in a PinAttestation that binds the hash to the
   * approving operator and activation timestamp.
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
   * When set, the kill-switch, token-revocation, and revocation-epoch mutating
   * endpoints MUST receive a matching `tenantId` field in the JSON request body.
   * A request whose `tenantId` differs from this value is rejected with HTTP 403
   * `TENANT_MISMATCH` so a credential issued for tenant A cannot affect resources
   * belonging to tenant B.
   *
   * Partner DID endpoints (`/partner-did/*`, `/partner-dids/*`) are not
   * tenant-scoped because DID registrations are inherently gateway-wide and do
   * not carry per-tenant ownership semantics.
   *
   * Global kill-switch operations additionally require
   * `acknowledgesCrossTenantImpact: true` in the body because they block all
   * traffic on the gateway instance irrespective of tenant.
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
   * Winston audit-chain log entries.
   */
  ocsfTransport?: OcsfAuditTransport;
  /**
   * Idempotency store shared across all mutating endpoints.
   *
   * When supplied, responses for requests that carry an `Idempotency-Key`
   * header are cached in this store.  Callers that do not pass a store still
   * benefit from the in-memory store created internally per-router-instance.
   */
  idempotencyStore?: IAdminIdempotencyStore;
  /**
   * When `true`, the kill-switch manager is configured with
   * `failOpenOnWrite=true` (i.e. `KILL_SWITCH_FAIL_OPEN_ON_WRITE=true`).
   *
   * In fail-open mode, a Redis write failure silently updates only the local
   * cache while other replicas remain unaffected.  Mutating kill-switch
   * endpoints return `207 Multi-Status` with a `fleetPropagationPending: true`
   * flag in the body to alert the operator.
   */
  killSwitchFailOpenOnWrite?: boolean;
  /**
   * Billing usage meter (Task 17).
   *
   * When supplied, the admin router exposes `GET /usage` and `POST /usage/reset`,
   * and records a kill-switch invocation on every activating kill-switch call.
   */
  usageMeter?: UsageMeter;
  /**
   * Configured audit-log retention window in days.
   *
   * Surfaced alongside usage counters in `GET /admin/usage` so billing
   * operators can confirm the tenant's tier without consulting environment
   * docs.
   */
  auditRetentionDays?: number;
}

// =============================================================================
// Factory
// =============================================================================

/**
 * Create admin API router with authentication and all route groups.
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
    usageMeter,
    auditRetentionDays,
    killSwitchFailOpenOnWrite = false,
  } = options;

  // Idempotency store: use caller-supplied or create a fresh in-memory one.
  const idempotencyStore = options.idempotencyStore ?? new InMemoryIdempotencyStore();

  const auditLogger = createAuditLogger('tool-gateway');

  // ── Authentication middleware ──────────────────────────────────────────────
  //
  // Pre-compute a per-router-instance HMAC key and the expected digest of the
  // admin API key so that per-request comparisons are always between two
  // fixed-length HMAC-SHA256 digests.  This eliminates the length-oracle that
  // results from an early-exit `length ===` check before `timingSafeEqual`.
  //
  // NOTE: adminApiKey is expected to be a high-entropy random bearer
  // credential (operator-generated), NOT a user-chosen password.
  // codeql[js/insufficient-password-hash] - token comparison, not password storage
  let adminKeyHmacKey: Buffer | undefined;
  let expectedAdminKeyHash: Buffer | undefined;
  if (adminApiKey) {
    adminKeyHmacKey = crypto.randomBytes(32);
    expectedAdminKeyHash = crypto
      .createHmac('sha256', adminKeyHmacKey)
      .update(Buffer.from(adminApiKey, 'utf8'))
      .digest();
  }

  const authenticateAdmin = (req: Request, res: Response, next: NextFunction): void => {
    if (!adminApiKey || !adminKeyHmacKey || !expectedAdminKeyHash) {
      res.status(503).json({
        error: {
          code: 'ADMIN_AUTH_NOT_CONFIGURED',
          message:
            'Admin API not configured — set ADMIN_API_KEY to enable admin endpoints.',
        },
      });
      return;
    }

    const rawHeader = req.headers['x-admin-api-key'];
    const providedKey = Array.isArray(rawHeader) ? rawHeader[0] : rawHeader;

    // codeql[js/insufficient-password-hash] - token comparison, not password storage
    const providedHash = crypto
      .createHmac('sha256', adminKeyHmacKey)
      .update(Buffer.from(typeof providedKey === 'string' ? providedKey : '', 'utf8'))
      .digest();

    if (!crypto.timingSafeEqual(providedHash, expectedAdminKeyHash)) {
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

    next();
  };

  router.use(authenticateAdmin);

  // ── Build shared context ───────────────────────────────────────────────────
  const ctx = buildAdminRouterContext({
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
  });

  // ── Mount route groups ─────────────────────────────────────────────────────
  mountKillSwitchRoutes(router, ctx);
  mountRevocationRoutes(router, ctx);
  mountPartnerDidRoutes(router, ctx);

  // ── Billing usage routes (Task 17) ─────────────────────────────────────────
  // Mounted only when a usageMeter is configured. In self-host dev deployments
  // without metering, the routes are simply absent (404) rather than 501 —
  // operators who don't configure a meter don't need the endpoints.
  if (usageMeter) {
    mountUsageRoutes(router, { usageMeter, auditRetentionDays });
  }

  return router;
}
