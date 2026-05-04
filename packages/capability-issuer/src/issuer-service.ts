/**
 * Capability Issuer Service — orchestrator.
 *
 * Thin coordinator: it owns the externally injected dependencies
 * ({@link TokenSigner}, {@link IdentityProvider}, optional credential
 * pipelines, optional posture emitter) and the issuer configuration,
 * but delegates all the actual issuance / attenuation / renewal
 * mechanics to the cohesive modules under `./issuance/`.
 *
 * See `docs/IMPROVEMENTS_AND_REFACTORING.md` § R-1.
 */

import {
  AuditLogEntry,
  CapabilityConstraint,
  CapabilityError,
  CapabilityTokenPayload,
  DEFAULT_ROLE_CAPABILITY_MAP,
  DbCredential,
  ErrorCode,
  IdentityProvider,
  IssuanceRateLimitSubject,
  IssuanceRateLimiter,
  IssueCapabilityRequest,
  IssueCapabilityResponse,
  JwkSet,
  Logger,
  PostureEmitterLike,
  RateLimitDecision,
  RoleCapabilityPolicy,
  StorageGrant,
  TokenSigner,
  UserConsent,
  UserContext,
  createAuditLogger,
  generateId,
  getCurrentTimestamp,
  getExpirationTimestamp,
  mapRolesToCapabilitiesForPolicy,
  matchesResource,
} from '@euno/common';
import * as crypto from 'crypto';
import { DbTokenService } from './db-token';
import { StorageGrantService } from './storage-grant';
import {
  buildAttenuatedPayload,
  buildIssuancePayload,
  buildRenewedPayload,
  computePimCappedExpiry,
  emitPostureRecord,
  enforceConditionalAccess,
  enforcePimRequiredRoles,
  filterRolesContributingToCapabilities,
  mapVerifyError,
  requestedCapabilitiesIncludeSensitive,
  signPayload,
  validateAgainstManifest,
  validateCapabilitySubset,
  validateConditionsForCapabilities,
  validateConsent,
  verifyParentToken,
} from './issuance';

// Re-export PostureEmitterLike from this module for backwards
// compatibility — it now lives in `@euno/common` (per R-1's
// "Promote `PostureEmitterLike` into `@euno/common`" item) but
// older callers and tests import it from this file.
export type { PostureEmitterLike } from '@euno/common';

/**
 * Infer a JWS algorithm from exported JWK key material when the signer
 * does not expose `getAlgorithm()`.
 *
 * Returns `undefined` when the algorithm cannot be determined with confidence
 * (e.g. RSA keys, which support several algorithm families) so that callers
 * can omit `alg` rather than advertising an incorrect value.
 */
function inferAlgFromJwk(jwkData: Record<string, unknown>): string | undefined {
  const kty = String(jwkData['kty'] ?? '');
  const crv = typeof jwkData['crv'] === 'string' ? jwkData['crv'] : undefined;

  switch (kty) {
    case 'EC':
      // Elliptic-curve: algorithm is unambiguous from the curve name.
      switch (crv) {
        case 'P-256': return 'ES256';
        case 'P-384': return 'ES384';
        case 'P-521': return 'ES512';
        default: return undefined;
      }
    case 'OKP':
      // Octet-key-pair (Ed25519 / Ed448) always uses EdDSA.
      return 'EdDSA';
    case 'RSA':
      // RSA is used with multiple algorithm families (RS256/384/512,
      // PS256/384/512) — the key material alone is insufficient to choose.
      return undefined;
    default:
      return undefined;
  }
}

export interface CapabilityIssuerServiceOptions {
  /**
   * When true, every call to {@link CapabilityIssuerService.issueCapability}
   * MUST include a valid {@link UserConsent} record. Defaults to false to
   * preserve back-compat for deployments that have not yet wired a consent
   * UI; new deployments should enable this in production.
   */
  requireConsent?: boolean;
  /**
   * Optional externalised role → capability policy. When omitted the
   * service falls back to the in-code Sprint-1 default mapping. Supplying
   * a policy here is the recommended way to make the issuer's
   * authorization decisions data-driven (loaded from a file, config
   * service, or per-tenant override map) rather than hard-coded.
   */
  policy?: RoleCapabilityPolicy;
  /**
   * Optional storage-grant service. When supplied and enabled, the
   * issuer mints short-lived cloud storage credentials alongside the
   * VC for every capability whose resource matches the canonical
   * `storage://{cloud}/{bucket}/...` form. See
   * `docs/sprint-3-4-gaps/07-storage-grants.md`.
   */
  storageGrantService?: StorageGrantService;
  /**
   * Optional DB-token service. When supplied and enabled, the issuer
   * mints short-lived IAM-bound database credentials alongside the VC
   * for every capability whose resource matches the canonical
   * `db://{cloud}/{instance}/...` form. See
   * `docs/sprint-3-4-gaps/08-db-token-issuance.md`.
   */
  dbTokenService?: DbTokenService;
  /**
   * Operator-declared list of role display names that MUST be currently
   * active via Privileged Identity Management (or equivalent JIT
   * elevation). Issuance is denied when any of these roles appears in
   * the user's resolved roles but is not in `pim-active` state in
   * `userContext.roleSources`. When `userContext.roleSources` is
   * absent (provider does not implement PIM), this list is ignored —
   * deployments that need enforcement should configure a provider that
   * populates `roleSources` (today, Azure AD with `pim` set).
   *
   * See `docs/sprint-3-4-gaps/04-pim-activation.md`.
   */
  pimRequiredRoles?: string[];
  /**
   * When true, capability TTL is capped at the smallest remaining
   * `pim-active` window across all roles in
   * `userContext.roleSources`. Defaults to true. Has no effect when
   * the user has no `pim-active` roles.
   */
  capTtlToPimActivation?: boolean;
  /**
   * Optional AI posture-management emitter. When supplied, the
   * issuer fires a fire-and-forget {@link PostureEmitterLike.emitObserved}
   * after every successful issuance so cloud posture-management
   * surfaces (Defender CSPM / Security Hub / SCC) keep an accurate
   * inventory of the agent estate. Failures never affect issuance.
   * See `docs/sprint-3-4-gaps/09-ai-posture-inventory.md`.
   */
  postureEmitter?: PostureEmitterLike;
  /**
   * Logical region tag for this issuer instance (F-7). When set,
   * stamped on:
   *  - the `region` claim of issued capability tokens (preserved
   *    across attenuation and renewal),
   *  - posture inventory records (replaces the legacy
   *    {@link postureRegion} option),
   *  - audit log entries via `AuditLogEntry.region`,
   *  - request span attributes (`euno.region`) — set by the HTTP
   *    layer, not this service.
   *
   * Falls back to `process.env.EUNO_DEPLOYMENT_REGION` (legacy) and
   * finally undefined (the `region` claim is then omitted on tokens
   * for back-compat with single-region deployments).
   */
  region?: string;
  /**
   * @deprecated Use {@link region}. Retained for back-compat with
   * sprint 3-4 posture-emitter wiring; ignored when {@link region} is
   * also set.
   */
  postureRegion?: string;
  /**
   * Optional per-(tenant, user, agent) issuance rate limiter (F-1,
   * addresses I-1 from `docs/IMPROVEMENTS_AND_REFACTORING.md`). When
   * supplied, every successful authentication on
   * {@link CapabilityIssuerService.issueCapability} consumes one
   * token from the bucket; exhaustion denies with
   * {@link ErrorCode.RATE_LIMIT_EXCEEDED} (HTTP 429) BEFORE any
   * signing or side-credential mint runs, so a compromised account
   * cannot exhaust KMS budget either.
   *
   * The limiter is keyed on `(tenantId, userId, agentId)` — tenant
   * first so the limit is **tenant-aware**, the load-bearing
   * prerequisite called out by §6.1 #3 of
   * `docs/IMPROVEMENTS_AND_REFACTORING.md` for F-7 (multi-region
   * active/active issuer).
   *
   * Optional for back-compat: the existing per-IP express rate
   * limiter on `/api/v1/issue` continues to run regardless.
   */
  issuanceRateLimiter?: IssuanceRateLimiter;
  /**
   * Optional callback fired whenever {@link issuanceRateLimiter}
   * denies an issuance. Used by the HTTP entrypoint to increment a
   * Prometheus counter. Failures inside the callback are logged and
   * swallowed so observability never affects the request decision.
   */
  onIssuanceRateLimited?: (
    subject: IssuanceRateLimitSubject,
    reason: 'exceeded' | 'limiter_unavailable',
  ) => void;
}

export class CapabilityIssuerService {
  private signer: TokenSigner;
  private identityProvider: IdentityProvider;
  private issuerDid: string;
  private defaultTTL: number;
  private logger: Logger;
  private auditLogger: Logger;
  private requireConsent: boolean;
  private policy: RoleCapabilityPolicy;
  private storageGrantService?: StorageGrantService;
  private dbTokenService?: DbTokenService;
  private pimRequiredRoles: string[];
  private capTtlToPimActivation: boolean;
  private postureEmitter?: PostureEmitterLike;
  /**
   * Effective region tag (F-7). Empty string means "not configured" —
   * audit/posture default to `'unknown'`, the token `region` claim is
   * omitted entirely, and gateways behave exactly as before. See the
   * `region` field on {@link CapabilityIssuerServiceOptions}.
   */
  private region: string;
  /**
   * Region label used by posture emission. Always non-empty (defaults
   * to `'unknown'` so the inventory feed is never sparse). Distinct
   * from {@link region} only because the token `region` claim must be
   * omitted when not configured (back-compat) but posture records have
   * always required a value.
   */
  private postureRegion: string;
  private issuanceRateLimiter?: IssuanceRateLimiter;
  private onIssuanceRateLimited?: (
    subject: IssuanceRateLimitSubject,
    reason: 'exceeded' | 'limiter_unavailable',
  ) => void;

  constructor(
    signer: TokenSigner,
    identityProvider: IdentityProvider,
    issuerDid: string,
    defaultTTL: number = 900, // 15 minutes default
    logger: Logger,
    options: CapabilityIssuerServiceOptions = {},
  ) {
    this.signer = signer;
    this.identityProvider = identityProvider;
    this.issuerDid = issuerDid;
    this.defaultTTL = defaultTTL;
    this.logger = logger;
    // F-7: `region` is the canonical setting; `postureRegion` is the
    // legacy fallback so existing wiring keeps working unchanged.
    // `EUNO_DEPLOYMENT_REGION` is the very-legacy fallback (sprint
    // 3-4 posture-only). Resolved BEFORE the audit logger so every
    // audit record this service emits — including the synchronous
    // deny entries from `enforceIssuanceRateLimit` — is stamped with
    // `region`.
    this.region = options.region ?? options.postureRegion ?? process.env.EUNO_DEPLOYMENT_REGION ?? '';
    this.postureRegion = this.region.length > 0 ? this.region : 'unknown';
    this.auditLogger = createAuditLogger('capability-issuer', { region: this.region });
    this.requireConsent = options.requireConsent === true;
    this.policy = options.policy ?? { default: DEFAULT_ROLE_CAPABILITY_MAP };
    if (options.storageGrantService) this.storageGrantService = options.storageGrantService;
    if (options.dbTokenService) this.dbTokenService = options.dbTokenService;
    this.pimRequiredRoles = options.pimRequiredRoles ?? [];
    this.capTtlToPimActivation = options.capTtlToPimActivation !== false;
    if (options.postureEmitter) this.postureEmitter = options.postureEmitter;
    if (options.issuanceRateLimiter) this.issuanceRateLimiter = options.issuanceRateLimiter;
    if (options.onIssuanceRateLimited) this.onIssuanceRateLimited = options.onIssuanceRateLimited;
  }

  /**
   * Logical region tag for this issuer instance (F-7). Returns the
   * empty string when no region is configured. Exposed read-only so
   * the HTTP layer can surface it on the `/.well-known/capability-issuer`
   * metadata endpoint and on tracing spans without having to re-read
   * the env var.
   */
  getRegion(): string {
    return this.region;
  }

  /**
   * Issue a capability token. Coordinates the issuance pipeline:
   * authenticate → role-derive → enforce manifest/consent/CA/conditions
   * → cap TTL to PIM → build payload → sign → mint side-credentials →
   * audit → emit posture.
   */
  async issueCapability(request: IssueCapabilityRequest): Promise<IssueCapabilityResponse> {
    try {
      // Step 1: Validate the user's authentication token.
      this.logger.info('Validating user authentication token', { agentId: request.agentId });
      const userContext = await this.identityProvider.validateToken(request.authToken);

      // Step 1a: Per-(tenant, user, agent) issuance rate limit (F-1,
      // addresses I-1). Runs *after* authentication so the limit is
      // keyed on the resolved subject rather than transport metadata,
      // and *before* any signing or side-credential mint so a
      // compromised account cannot exhaust KMS budget. Skipped when
      // no limiter was configured (back-compat).
      await this.enforceIssuanceRateLimit({
        tenantId: userContext.tenantId,
        userId: userContext.userId,
        agentId: request.agentId,
      });

      // Step 1b: Enforce PIM-required roles.
      enforcePimRequiredRoles(
        userContext,
        request.agentId,
        this.pimRequiredRoles,
        this.auditLogger,
      );

      // Step 2: Determine capabilities based on user roles.
      this.logger.info('Determining capabilities based on user roles', {
        userId: userContext.userId,
        roles: userContext.roles,
        agentId: request.agentId,
      });

      let capabilities = mapRolesToCapabilitiesForPolicy(
        userContext.roles,
        this.policy,
        userContext.tenantId,
      );

      // Step 3: If specific capabilities were requested, validate them.
      if (request.requestedCapabilities) {
        this.assertRequestedWithinRoleScope(capabilities, request.requestedCapabilities);

        // Step 3b: enforce per-agent manifest constraint at issuance time.
        if (request.manifest) {
          validateAgainstManifest(
            request.manifest,
            request.agentId,
            request.requestedCapabilities,
          );
        }

        // Step 3c: enforce explicit user consent. Sensitive actions or
        // strict mode require it; even when not required, supplied
        // consent is still validated so a stale record is rejected.
        const requiresConsent =
          this.requireConsent ||
          requestedCapabilitiesIncludeSensitive(request.requestedCapabilities);

        if (requiresConsent || request.consent) {
          validateConsent(
            request.consent,
            userContext.userId,
            request.agentId,
            request.requestedCapabilities,
          );
        }

        capabilities = request.requestedCapabilities;
      } else if (this.requireConsent) {
        throw new CapabilityError(
          ErrorCode.INVALID_REQUEST,
          'Explicit user consent (requestedCapabilities + consent) is required by this issuer',
          400,
        );
      }

      // Step 3d: Conditional Access enforcement.
      enforceConditionalAccess(
        userContext,
        capabilities,
        request.agentId,
        this.auditLogger,
      );

      // Step 3e: Validate every typed condition before signing.
      validateConditionsForCapabilities(capabilities);

      // Step 4: Compute the payload validity window.
      const now = getCurrentTimestamp();
      let expiresAt = getExpirationTimestamp(this.defaultTTL);

      // Step 4b: Cap TTL to the smallest remaining `pim-active` window
      // across only the roles that contributed to the capability set.
      const contributingRoleSources = filterRolesContributingToCapabilities(
        userContext,
        capabilities,
        this.policy,
      );
      const pimCappedExpiry = computePimCappedExpiry(
        contributingRoleSources,
        this.capTtlToPimActivation,
        expiresAt,
      );
      if (pimCappedExpiry !== undefined) {
        if (pimCappedExpiry <= now) {
          this.denyExpiredPimActivation(request.agentId, userContext.userId, now, pimCappedExpiry);
        }
        if (pimCappedExpiry < expiresAt) {
          this.logger.info('Capping capability TTL to remaining PIM activation window', {
            agentId: request.agentId,
            userId: userContext.userId,
            requestedExp: expiresAt,
            cappedExp: pimCappedExpiry,
          });
          expiresAt = pimCappedExpiry;
        }
      }

      // Step 5: Build and sign the token.
      const tokenId = generateId();
      const payload = buildIssuancePayload({
        issuerDid: this.issuerDid,
        agentId: request.agentId,
        iat: now,
        exp: expiresAt,
        jti: tokenId,
        capabilities,
        userContext,
        // F-7: stamp the originating region so audit consumers can
        // attribute the token after a regional failover. Falls back to
        // `undefined` (claim omitted) when no region is configured.
        region: this.region.length > 0 ? this.region : undefined,
      });

      this.logger.info('Signing capability token', { tokenId, agentId: request.agentId });
      const token = await signPayload(this.signer, payload);

      // Step 5b: Mint short-lived cloud-storage and DB credentials.
      const { storageGrants, dbCredentials } = await this.mintSideCredentials(
        request,
        userContext,
        capabilities,
        expiresAt - now,
      );

      // Step 6: Audit log the issuance.
      await this.logIssuance(
        userContext.userId,
        request.agentId,
        tokenId,
        capabilities,
        request.consent,
        storageGrants,
        dbCredentials,
      );

      // Step 6b: Push an inventory record (fire-and-forget).
      emitPostureRecord(this.postureEmitter, this.logger, {
        agentId: request.agentId,
        manifest: request.manifest,
        capabilities,
        region: this.postureRegion,
      });

      this.logger.info('Capability token issued successfully', {
        tokenId,
        agentId: request.agentId,
        userId: userContext.userId,
        expiresAt,
      });

      const response: IssueCapabilityResponse = {
        token,
        expiresAt,
        tokenId,
        capabilities,
      };
      if (storageGrants && storageGrants.length > 0) response.storageGrants = storageGrants;
      if (dbCredentials && dbCredentials.length > 0) response.dbCredentials = dbCredentials;
      return response;
    } catch (error) {
      this.logger.error('Failed to issue capability token', {
        agentId: request.agentId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });

      if (error instanceof CapabilityError) {
        throw error;
      }

      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        `Failed to issue capability: ${error instanceof Error ? error.message : 'Unknown error'}`,
        500,
      );
    }
  }

  /**
   * Validate that every requested capability is a subset of what the
   * user's roles allow. Resource matching uses the same wildcard-aware
   * `matchesResource` semantics as the gateway enforcement engine, so
   * role mappings that grant wildcard resources correctly authorize
   * requests for concrete resources beneath them.
   */
  private assertRequestedWithinRoleScope(
    roleDerived: CapabilityConstraint[],
    requested: CapabilityConstraint[],
  ): void {
    for (const req of requested) {
      const matchingCaps = roleDerived.filter((cap) =>
        matchesResource(req.resource, cap.resource),
      );
      if (matchingCaps.length === 0) {
        throw new CapabilityError(
          ErrorCode.INSUFFICIENT_PERMISSIONS,
          `User does not have permission for resource: ${req.resource}`,
          403,
        );
      }

      const allowedActions = new Set<string>();
      for (const cap of matchingCaps) {
        for (const action of cap.actions) {
          allowedActions.add(action);
        }
      }

      for (const action of req.actions) {
        if (!allowedActions.has(action)) {
          throw new CapabilityError(
            ErrorCode.INSUFFICIENT_PERMISSIONS,
            `User does not have permission for action '${action}' on resource: ${req.resource}`,
            403,
          );
        }
      }
    }
  }

  /**
   * Audit and throw when a contributing PIM activation has already
   * expired (or is within the safety margin). Minting a capability
   * with `exp` ≤ `iat` would produce an immediately-unusable token,
   * so deny instead so the caller can re-activate.
   */
  private denyExpiredPimActivation(
    agentId: string,
    userId: string,
    now: number,
    cappedExp: number,
  ): never {
    const auditEntry: AuditLogEntry = {
      id: generateId(),
      timestamp: new Date().toISOString(),
      eventType: 'issuance',
      agentId,
      userId,
      decision: 'deny',
      metadata: {
        reason: 'pim_activation_expired',
        cappedExp,
        now,
      },
    };
    this.auditLogger.warn(
      'Capability issuance denied: contributing PIM activation has expired',
      auditEntry,
    );
    throw new CapabilityError(
      ErrorCode.AUTHORIZATION_FAILED,
      'Contributing PIM activation has expired; re-activate and retry',
      403,
    );
  }

  /**
   * Apply the configured per-(tenant, user, agent) issuance rate
   * limit (F-1, addresses I-1). When no limiter is wired this is a
   * no-op (back-compat). On exhaustion logs an audit-deny entry,
   * fires the optional metric callback, and throws
   * {@link CapabilityError} with {@link ErrorCode.RATE_LIMIT_EXCEEDED}
   * (HTTP 429) — caller-side `next(error)` then surfaces the standard
   * error envelope.
   */
  private async enforceIssuanceRateLimit(subject: IssuanceRateLimitSubject): Promise<void> {
    if (!this.issuanceRateLimiter) return;
    let decision: RateLimitDecision;
    try {
      decision = await this.issuanceRateLimiter.consume(subject);
    } catch (error) {
      // The limiter implementation already chose its failure mode
      // (see RedisIssuanceRateLimiter.failClosedOnError). When it
      // chose to propagate, treat the error as fail-closed here too:
      // the issuer cannot mint without a working limiter when one is
      // wired, otherwise the limit is bypassed silently.
      this.logger.error(
        'Issuance rate limiter threw; failing closed (denying issuance)',
        {
          tenantId: subject.tenantId,
          userId: subject.userId,
          agentId: subject.agentId,
          error: error instanceof Error ? error.message : 'Unknown error',
        },
      );
      this.notifyRateLimited(subject, 'limiter_unavailable');
      const auditEntry: AuditLogEntry = {
        id: generateId(),
        timestamp: new Date().toISOString(),
        eventType: 'issuance',
        agentId: subject.agentId,
        userId: subject.userId,
        decision: 'deny',
        metadata: {
          reason: 'issuance_rate_limiter_unavailable',
          tenantId: subject.tenantId ?? null,
        },
      };
      this.auditLogger.warn(
        'Capability issuance denied: issuance rate limiter unavailable',
        auditEntry,
      );
      throw new CapabilityError(
        ErrorCode.RATE_LIMIT_EXCEEDED,
        'Issuance rate limiter is unavailable; please retry shortly',
        429,
        // `Retry-After` mirrors the limiter's configured window: a
        // stampeding herd that retries inside the same window will
        // hit the same outage immediately, so the bound is the
        // earliest reasonable retry horizon. Reading `windowSeconds`
        // from the limiter (rather than the issuer's local config)
        // keeps the value correct when operators change the window
        // without restarting the issuer.
        { 'Retry-After': String(this.issuanceRateLimiter.windowSeconds) },
      );
    }
    if (decision.allowed) return;

    this.notifyRateLimited(subject, 'exceeded');
    const auditEntry: AuditLogEntry = {
      id: generateId(),
      timestamp: new Date().toISOString(),
      eventType: 'issuance',
      agentId: subject.agentId,
      userId: subject.userId,
      decision: 'deny',
      metadata: {
        reason: 'issuance_rate_limit_exceeded',
        tenantId: subject.tenantId ?? null,
        limit: decision.limit,
        windowSeconds: decision.windowSeconds,
        retryAfterSeconds: decision.retryAfterSeconds,
      },
    };
    this.auditLogger.warn(
      'Capability issuance denied: per-subject issuance rate limit exceeded',
      auditEntry,
    );
    throw new CapabilityError(
      ErrorCode.RATE_LIMIT_EXCEEDED,
      `Issuance rate limit exceeded for this user/agent. Retry after ${decision.retryAfterSeconds}s.`,
      429,
      // RFC 9110 §10.2.3: `Retry-After` is the standard way to tell a
      // client to back off. Always populated for F-1 denials so the
      // SDK / agent runtime does not retry-storm.
      { 'Retry-After': String(decision.retryAfterSeconds) },
    );
  }

  private notifyRateLimited(
    subject: IssuanceRateLimitSubject,
    reason: 'exceeded' | 'limiter_unavailable',
  ): void {
    if (!this.onIssuanceRateLimited) return;
    try {
      this.onIssuanceRateLimited(subject, reason);
    } catch (error) {
      this.logger.warn('onIssuanceRateLimited callback threw', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  /**
   * Mint short-lived storage and DB credentials when their respective
   * services are configured and enabled. A mint failure aborts the
   * entire issuance — partial grants give the agent a misleading view
   * of what it can access (see design § 6 of both
   * `07-storage-grants.md` and `08-db-token-issuance.md`).
   */
  private async mintSideCredentials(
    request: IssueCapabilityRequest,
    userContext: UserContext,
    capabilities: CapabilityConstraint[],
    capabilityTtlSeconds: number,
  ): Promise<{ storageGrants?: StorageGrant[]; dbCredentials?: DbCredential[] }> {
    let storageGrants: StorageGrant[] | undefined;
    let dbCredentials: DbCredential[] | undefined;
    if (this.storageGrantService?.isEnabled()) {
      storageGrants = await this.storageGrantService.mintForCapabilities(capabilities, {
        agentId: request.agentId,
        authorizedBy: userContext.userId,
        capabilityTtlSeconds,
      });
    }
    if (this.dbTokenService?.isEnabled()) {
      dbCredentials = await this.dbTokenService.mintForCapabilities(capabilities, {
        agentId: request.agentId,
        authorizedBy: userContext.userId,
        capabilityTtlSeconds,
        userRoles: userContext.roles,
        policy: this.policy,
      });
    }
    return { storageGrants, dbCredentials };
  }

  /**
   * Log capability issuance for audit trail.
   *
   * Storage grants and DB credentials are summarized at the metadata
   * level (provider / resource / actions / expiresAt) — the credential
   * payload itself (SAS tokens, presigned URLs, AAD JWTs, RDS auth
   * tokens, OAuth access tokens) is **never** written to the audit log.
   * See `docs/sprint-3-4-gaps/07-storage-grants.md` § Risks.
   */
  private async logIssuance(
    userId: string,
    agentId: string,
    tokenId: string,
    capabilities: Array<{ resource: string; actions: string[] }>,
    consent?: UserConsent,
    storageGrants?: StorageGrant[],
    dbCredentials?: DbCredential[],
  ): Promise<void> {
    const auditEntry: AuditLogEntry = {
      id: generateId(),
      timestamp: new Date().toISOString(),
      eventType: 'issuance',
      agentId,
      userId,
      capabilityId: tokenId,
      decision: 'allow',
      metadata: {
        capabilities: capabilities.map((c) => ({
          resource: c.resource,
          actions: c.actions,
        })),
        ...(consent
          ? {
              consent: {
                consentId: consent.consentId,
                grantedAt: consent.grantedAt,
                expiresAt: consent.expiresAt,
              },
            }
          : {}),
        ...(storageGrants && storageGrants.length > 0
          ? {
              storageGrants: storageGrants.map((g) => ({
                provider: g.provider,
                resource: g.resource,
                actions: g.actions,
                expiresAt: g.expiresAt,
              })),
            }
          : {}),
        ...(dbCredentials && dbCredentials.length > 0
          ? {
              dbCredentials: dbCredentials.map((c) => ({
                provider: c.provider,
                resource: c.resource,
                actions: c.actions,
                expiresAt: c.expiresAt,
                host: c.host,
                port: c.port,
                database: c.database,
                username: c.username,
              })),
            }
          : {}),
      },
    };

    this.auditLogger.info('Capability token issued', auditEntry);
  }

  /**
   * Attenuate (reduce scope of) an existing capability token. The
   * child token will have equal or fewer privileges than the parent.
   */
  async attenuateCapability(
    parentToken: string,
    requestedCapabilities: CapabilityConstraint[],
    ttl?: number,
  ): Promise<IssueCapabilityResponse> {
    try {
      this.logger.info('Attenuating capability token');

      const parentPayload = await verifyParentToken(
        this.signer,
        parentToken,
        { issuer: this.issuerDid, audience: 'tool-gateway' },
        'Invalid parent capability token format',
      );

      // Step 2: Validate parent token is not expired.
      const now = getCurrentTimestamp();
      if (parentPayload.exp < now) {
        throw new CapabilityError(
          ErrorCode.EXPIRED_TOKEN,
          'Parent capability token has expired',
          401,
        );
      }

      // Step 2a: Apply F-1 rate limit to attenuation. An attacker
      // holding a single parent token can otherwise mint unlimited
      // children with different capability subsets to evade per-token
      // revocation; the limit must therefore cover this path. Keyed on
      // the same (tenantId, userId, agentId) tuple as fresh issuance
      // so a compromised account hits a single shared budget across
      // issue/attenuate/renew.
      await this.enforceIssuanceRateLimit({
        tenantId: parentPayload.authorizedBy?.tenantId,
        userId: parentPayload.authorizedBy?.userId ?? 'unknown',
        agentId: parentPayload.sub,
      });

      // Step 3: Validate requested capabilities are a subset of parent's.
      validateCapabilitySubset(parentPayload.capabilities, requestedCapabilities);

      // Step 3b: Validate the typed conditions on the attenuated set.
      // The child may carry a *narrower* condition set (e.g. a tighter
      // `maxCalls`) that must itself be well-formed.
      validateConditionsForCapabilities(requestedCapabilities);

      // Step 4: Calculate expiration (cannot exceed parent's expiration).
      const requestedTTL = ttl || this.defaultTTL;
      const expiresAt = Math.min(now + requestedTTL, parentPayload.exp);

      // Step 5: Build and sign the child token.
      const tokenId = generateId();
      const childPayload = buildAttenuatedPayload({
        issuerDid: this.issuerDid,
        parent: parentPayload,
        iat: now,
        exp: expiresAt,
        jti: tokenId,
        capabilities: requestedCapabilities,
      });

      this.logger.info('Signing attenuated capability token', {
        tokenId,
        parentTokenId: parentPayload.jti,
        agentId: parentPayload.sub,
      });
      const token = await signPayload(this.signer, childPayload);

      // Step 6: Audit log the attenuation.
      await this.logAttenuation(
        parentPayload.sub,
        tokenId,
        parentPayload.jti,
        requestedCapabilities,
      );

      this.logger.info('Capability token attenuated successfully', {
        tokenId,
        parentTokenId: parentPayload.jti,
        agentId: parentPayload.sub,
      });

      return {
        token,
        expiresAt,
        tokenId,
        capabilities: requestedCapabilities,
      };
    } catch (error) {
      this.logger.error('Failed to attenuate capability token', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });

      try {
        mapVerifyError(
          error,
          'Parent capability token has expired',
          'Invalid parent capability token',
        );
      } catch (mapped) {
        if (mapped instanceof CapabilityError) throw mapped;
      }

      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        `Failed to attenuate capability: ${error instanceof Error ? error.message : 'Unknown error'}`,
        500,
      );
    }
  }

  /**
   * Log capability attenuation for audit trail.
   */
  private async logAttenuation(
    agentId: string,
    tokenId: string,
    parentTokenId: string,
    capabilities: CapabilityConstraint[],
  ): Promise<void> {
    const auditEntry: AuditLogEntry = {
      id: generateId(),
      timestamp: new Date().toISOString(),
      eventType: 'issuance', // Using issuance for now, could add 'attenuation' type
      agentId,
      capabilityId: tokenId,
      decision: 'allow',
      metadata: {
        parentCapabilityId: parentTokenId,
        capabilities: capabilities.map((c) => ({
          resource: c.resource,
          actions: c.actions,
        })),
      },
    };

    this.auditLogger.info('Capability token attenuated', auditEntry);
  }

  /**
   * Renew an existing capability token with a fresh expiration. Token
   * keeps the same capabilities but gets a new TTL.
   */
  async renewCapability(
    currentToken: string,
    ttl?: number,
  ): Promise<IssueCapabilityResponse> {
    try {
      this.logger.info('Renewing capability token');

      const currentPayload = await verifyParentToken(
        this.signer,
        currentToken,
        { issuer: this.issuerDid, audience: 'tool-gateway' },
        'Invalid capability token format',
      );

      // Step 1a: Apply F-1 rate limit to renewal too. Without this an
      // attacker holding any non-expired token can keep its lineage
      // alive forever by renewing in a tight loop, defeating short
      // TTLs entirely. Same shared (tenantId, userId, agentId) bucket
      // as fresh issuance and attenuation so the budget is meaningful
      // regardless of which mint path is being abused.
      await this.enforceIssuanceRateLimit({
        tenantId: currentPayload.authorizedBy?.tenantId,
        userId: currentPayload.authorizedBy?.userId ?? 'unknown',
        agentId: currentPayload.sub,
      });

      // Step 2: Build the renewed token.
      const now = getCurrentTimestamp();
      const expiresAt = getExpirationTimestamp(ttl || this.defaultTTL);
      const tokenId = generateId();
      const renewedPayload: CapabilityTokenPayload = buildRenewedPayload({
        issuerDid: this.issuerDid,
        current: currentPayload,
        iat: now,
        exp: expiresAt,
        jti: tokenId,
      });

      // Step 3: Sign the renewed token.
      this.logger.info('Signing renewed capability token', {
        tokenId,
        previousTokenId: currentPayload.jti,
        agentId: currentPayload.sub,
      });
      const token = await signPayload(this.signer, renewedPayload);

      // Step 4: Audit log the renewal.
      await this.logRenewal(
        currentPayload.sub,
        tokenId,
        currentPayload.jti,
        currentPayload.capabilities,
      );

      this.logger.info('Capability token renewed successfully', {
        tokenId,
        previousTokenId: currentPayload.jti,
        agentId: currentPayload.sub,
      });

      return {
        token,
        expiresAt,
        tokenId,
        capabilities: currentPayload.capabilities,
      };
    } catch (error) {
      this.logger.error('Failed to renew capability token', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });

      try {
        mapVerifyError(
          error,
          'Capability token has expired; re-authentication is required',
          'Invalid capability token',
        );
      } catch (mapped) {
        if (mapped instanceof CapabilityError) throw mapped;
      }

      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        `Failed to renew capability: ${error instanceof Error ? error.message : 'Unknown error'}`,
        500,
      );
    }
  }

  /**
   * Log capability renewal for audit trail.
   */
  private async logRenewal(
    agentId: string,
    tokenId: string,
    previousTokenId: string,
    capabilities: CapabilityConstraint[],
  ): Promise<void> {
    const auditEntry: AuditLogEntry = {
      id: generateId(),
      timestamp: new Date().toISOString(),
      eventType: 'renewal',
      agentId,
      capabilityId: tokenId,
      decision: 'allow',
      metadata: {
        previousCapabilityId: previousTokenId,
        capabilities: capabilities.map((c) => ({
          resource: c.resource,
          actions: c.actions,
        })),
      },
    };

    this.auditLogger.info('Capability token renewed', auditEntry);
  }

  /**
   * Get public key for token verification.
   */
  async getPublicKey(): Promise<string> {
    return this.signer.getPublicKey();
  }

  /**
   * Get the JWKS (JSON Web Key Set) for this issuer.
   *
   * Derives the JWK from the active signer's public key (SPKI).  The
   * `kid` field in the returned JWK matches the `kid` placed in every
   * JWT protected header by this signer — callers can therefore use it
   * to verify tokens by key ID without a synchronized restart.
   *
   * **Single-key limitation**: this method publishes only the *active*
   * signer's key.  It does **not** publish old and new keys simultaneously.
   * During a signer rotation, tokens minted by the previous signer will be
   * rejected by gateways once they refresh their JWKS cache.  To achieve
   * zero-downtime rotation, wait for outstanding tokens signed with the
   * old key to expire before switching the signer (see the production
   * deployment checklist).  Future work: inject a "previous-key" buffer so
   * overlapping keys can be published during the rotation window.
   */
  async getJwks(): Promise<JwkSet> {
    const spki = await this.signer.getPublicKey();
    const kid = await this.signer.getKeyId();

    // Export the SPKI public key as a JWK using Node.js crypto so that we
    // don't need to pass the algorithm when importing (no chicken-and-egg).
    let jwkData: Record<string, unknown>;
    try {
      const keyObject = crypto.createPublicKey(spki);
      jwkData = keyObject.export({ format: 'jwk' }) as Record<string, unknown>;
    } catch {
      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        'Failed to export public key as JWK',
        500,
      );
    }

    // Determine algorithm: prefer the signer's own getAlgorithm() when
    // available (all SigningAdapter subclasses implement it), then try to
    // infer from the exported JWK key material, and omit `alg` only when
    // the algorithm genuinely cannot be determined (prevents advertising an
    // incorrect `alg` which would cause interoperability failures).
    const signerAlg: string | undefined =
      typeof this.signer.getAlgorithm === 'function'
        ? this.signer.getAlgorithm()
        : inferAlgFromJwk(jwkData);

    const keyEntry: Record<string, unknown> = {
      kty: String(jwkData['kty'] ?? 'RSA'),
      ...jwkData,
      kid,
      use: 'sig',
    };
    if (signerAlg) {
      keyEntry['alg'] = signerAlg;
    }

    return {
      keys: [keyEntry as import('@euno/common').JwkKey],
    };
  }

  /**
   * Thin protected wrapper preserved for tests that reach into the
   * pre-R-1 internal API. Delegates to the standalone
   * {@link validateCapabilitySubset} in `./issuance/attenuation`.
   * Marked `protected` (rather than `private`) so subclasses — and
   * the test-only type-cast that historically reached into this
   * method — keep working without TypeScript's `noUnusedLocals`
   * flagging it as dead code.
   */
  protected validateCapabilitySubset(
    parentCapabilities: CapabilityConstraint[],
    requestedCapabilities: CapabilityConstraint[],
  ): void {
    validateCapabilitySubset(parentCapabilities, requestedCapabilities);
  }
}
