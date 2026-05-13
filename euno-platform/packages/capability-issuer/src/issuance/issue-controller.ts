/**
 * IssueController — thin handler for fresh capability issuance.
 *
 * Owns the endpoint-specific logic for the POST /api/v1/issue flow:
 *
 *   authenticate → PIM check → role resolution → manifest/consent validation
 *   → Conditional Access → conditions validation → cap TTL to PIM window
 *   → build payload → delegate to MintingPipeline → emit posture
 *
 * All shared machinery (signing, rate limiting, side-credentials, proofs)
 * is delegated to the injected {@link MintingPipeline}.
 *
 * See `docs/IMPROVEMENTS_AND_REFACTORING.md` § R-3.
 */

import {
  ActionResolver,
  AuditLogEntry,
  BUILTIN_ACTION_RESOLVER,
  CapabilityConstraint,
  CapabilityError,
  DbCredential,
  ErrorCode,
  IdentityProvider,
  IssueCapabilityRequest,
  IssueCapabilityResponse,
  Logger,
  PostureEmitterLike,
  RoleCapabilityPolicy,
  StorageGrant,
  UserConsent,
  generateId,
  getCurrentTimestamp,
  getExpirationTimestamp,
  mapRolesToCapabilitiesForPolicy,
  matchesResource,
} from '@euno/common';
import { MintingPipeline } from './minting-pipeline';
import {
  buildIssuanceContext,
  buildIssuancePayload,
  computePimCappedExpiry,
  emitPostureRecord,
  enforceConditionalAccess,
  enforcePimRequiredRoles,
  filterRolesContributingToCapabilities,
  requestedCapabilitiesIncludeSensitive,
  validateAgainstManifest,
  validateConditionsForCapabilities,
  validateConsent,
} from './index';

/**
 * Per-request enforcement context supplied by the HTTP layer.
 *
 * Separates transport-level metadata (source IP) from the wire-format
 * request body so the wire types stay clean.  The `clientIp` is fed
 * into the multi-dimensional issuance rate-limit key
 * (`tenantId|userId|agentId|jti|ip`) so that IP rotation cannot be
 * used to bypass per-identity budgets.
 */
export interface IssuerEnforcementContext {
  /**
   * Source IP of the HTTP request (`req.ip` in the Express handler).
   * Included in the issuance rate-limit key as the `ip` dimension.
   */
  clientIp?: string;
}

export interface IssueControllerOptions {
  /**
   * Identity provider used to authenticate the user's auth token.
   */
  identityProvider: IdentityProvider;
  /**
   * When true, every call to {@link IssueController.handle} MUST include
   * a valid {@link UserConsent} record. Defaults to false.
   */
  requireConsent?: boolean;
  /**
   * Optional externalized role → capability policy.
   */
  policy?: RoleCapabilityPolicy;
  /**
   * Operator-declared list of role display names that MUST be currently
   * active via Privileged Identity Management (or equivalent JIT elevation).
   */
  pimRequiredRoles?: string[];
  /**
   * When true, capability TTL is capped at the smallest remaining
   * `pim-active` window across all roles that contributed to the capability
   * set. Defaults to true.
   */
  capTtlToPimActivation?: boolean;
  /**
   * Optional AI posture-management emitter. Fire-and-forget after every
   * successful issuance.
   */
  postureEmitter?: PostureEmitterLike;
  /**
   * Logical region tag for posture inventory records. Falls back to
   * `'unknown'` so the feed is never sparse.
   */
  postureRegion?: string;
  /**
   * Region value to stamp on the JWT `region` claim (F-7).
   * Empty string (`''`) means "not configured" and the claim is omitted
   * — preserving back-compat for single-region deployments.
   * Defaults to `''` (omit).
   *
   * Kept separate from {@link postureRegion} so that an operator who
   * explicitly names their region `'unknown'` still has the claim emitted
   * on the token while posture telemetry continues to use `'unknown'` as
   * its sparse-feed sentinel.
   */
  tokenRegion?: string;
  /**
   * Pluggable {@link ActionResolver} for Conditional Access tier mapping.
   * Defaults to {@link BUILTIN_ACTION_RESOLVER}.
   */
  actionResolver?: ActionResolver;
  /**
   * Default TTL in seconds for issued tokens. Defaults to 900.
   */
  defaultTtl?: number;
  /**
   * Audit logger for structured issuance records.
   */
  auditLogger: Logger;
  /**
   * Operational logger for info/warn/error lines.
   */
  logger: Logger;
}

/**
 * IssueController — thin handler for the fresh-issuance endpoint.
 *
 * Delegates all shared machinery to the injected {@link MintingPipeline}.
 */
export class IssueController {
  private readonly pipeline: MintingPipeline;
  private readonly identityProvider: IdentityProvider;
  private readonly requireConsent: boolean;
  private readonly pimRequiredRoles: string[];
  private readonly capTtlToPimActivation: boolean;
  private readonly postureEmitter?: PostureEmitterLike;
  private readonly postureRegion: string;
  /** Raw region value; empty string means "not configured" → omit JWT claim. */
  private readonly tokenRegion: string;
  private readonly actionResolver: ActionResolver;
  private readonly defaultTtl: number;
  private readonly auditLogger: Logger;
  private readonly logger: Logger;

  constructor(pipeline: MintingPipeline, opts: IssueControllerOptions) {
    this.pipeline = pipeline;
    this.identityProvider = opts.identityProvider;
    this.requireConsent = opts.requireConsent === true;
    this.pimRequiredRoles = opts.pimRequiredRoles ?? [];
    this.capTtlToPimActivation = opts.capTtlToPimActivation !== false;
    this.postureEmitter = opts.postureEmitter;
    this.postureRegion = opts.postureRegion ?? 'unknown';
    this.tokenRegion = opts.tokenRegion ?? '';
    this.actionResolver = opts.actionResolver ?? BUILTIN_ACTION_RESOLVER;
    this.defaultTtl = opts.defaultTtl ?? 900;
    this.auditLogger = opts.auditLogger;
    this.logger = opts.logger;
  }

  // ── Hot-reload ────────────────────────────────────────────────────────────

  /**
   * Hot-reload the active role → capability policy.
   *
   * @deprecated The policy is now owned by the injected {@link MintingPipeline}
   * and `handle()` reads `pipeline.policySnapshot` atomically at the start of
   * each call.  This method is a no-op kept for API compatibility only; it will
   * be removed in a future release once all callers have been updated to drive
   * policy updates exclusively through {@link MintingPipeline.updatePolicy}.
   */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  updatePolicy(_policy: RoleCapabilityPolicy): void {
    // No-op: the pipeline's policySnapshot is the single source of truth.
    // MintingPipeline.updatePolicy() is called first by
    // CapabilityIssuerService.updatePolicy(), so the snapshot is already
    // up-to-date by the time this method is invoked.
  }

  /**
   * Issue a capability token. Coordinates the issuance pipeline:
   * authenticate → role-derive → enforce manifest/consent/CA/conditions
   * → cap TTL to PIM → build payload → sign → mint side-credentials →
   * audit → emit posture.
   */
  async handle(
    request: IssueCapabilityRequest,
    enforcement?: IssuerEnforcementContext,
  ): Promise<IssueCapabilityResponse> {
    try {
      // Capture the policy snapshot atomically before any `await`.  A
      // SIGHUP hot-reload replaces the MintingPipeline's `_policyState`
      // object in a single reference assignment; by reading it once here
      // we guarantee that `activePolicy` and `activePolicyHash` are always
      // a consistent (policy, hash) pair for the entire lifetime of this
      // request, even if an update fires mid-flight.
      const { policy: activePolicy, hash: activePolicyHash } = this.pipeline.policySnapshot;

      // Step 1: Validate the user's authentication token.
      this.logger.info('Validating user authentication token', { agentId: request.agentId });
      const userContext = await this.identityProvider.validateToken(request.authToken);

      // Step 1a: Per-(tenantId, userId, agentId, jti, ip) issuance rate limit (F-1).
      // Runs *after* authentication so the limit is keyed on the resolved
      // subject rather than transport metadata, and *before* any signing so
      // a compromised account cannot exhaust KMS budget. Fresh issuance uses
      // the '_no_jti' sentinel (applied by buildIssuanceRateLimitKey when
      // jti is absent); the ip dimension adds transport-level scoping.
      await this.pipeline.enforceRateLimit({
        tenantId: userContext.tenantId,
        userId: userContext.userId,
        agentId: request.agentId,
        ip: enforcement?.clientIp,
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
        activePolicy,
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

        // Step 3c: enforce explicit user consent.
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
        this.actionResolver,
      );

      // Step 3e: Validate every typed condition before signing.
      validateConditionsForCapabilities(capabilities);

      // Step 4: Compute the payload validity window.
      const now = getCurrentTimestamp();
      let expiresAt = getExpirationTimestamp(this.defaultTtl);

      // Step 4b: Cap TTL to the smallest remaining `pim-active` window
      // across only the roles that contributed to the capability set.
      const contributingRoleSources = filterRolesContributingToCapabilities(
        userContext,
        capabilities,
        activePolicy,
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
      const dpopJkt = await this.pipeline.resolveDpopJkt(request);
      const regionClaim = this.getRegionClaim();
      const payload = buildIssuancePayload({
        issuerDid: this.pipeline.issuerDid,
        agentId: request.agentId,
        iat: now,
        exp: expiresAt,
        jti: tokenId,
        capabilities,
        userContext,
        audience: this.pipeline.gatewayAudience,
        ...(regionClaim !== undefined ? { region: regionClaim } : {}),
        ...(dpopJkt ? { dpopJkt } : {}),
      });

      this.logger.info('Signing capability token', { tokenId, agentId: request.agentId });
      await this.pipeline.attachProofs(payload);
      payload.policyHash = activePolicyHash;
      const issuanceContext = buildIssuanceContext({
        policyHash: activePolicyHash,
        manifest: request.manifest,
        subject: request.agentId,
        audience: this.pipeline.gatewayAudience,
      });
      const token = await this.pipeline.signToken(payload, issuanceContext);

      // Step 5b: Mint side credentials AFTER JWT signing (KMS call is done).
      const { storageGrants, dbCredentials } = await this.pipeline.mintSideCredentials(
        token,
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

      // Step 6b: Push an inventory record. Awaited so the enqueue is
      // confirmed durable (SQLite WAL write) before the HTTP response
      // is sent — per emitPostureRecord's contract. Errors are caught
      // inside emitPostureRecord and never propagate here.
      await emitPostureRecord(this.postureEmitter, this.logger, {
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

  // ── Private helpers ───────────────────────────────────────────────────────

  /**
   * Returns the `region` claim value to stamp on the payload, or
   * `undefined` to omit it (back-compat for single-region deployments).
   *
   * Uses {@link tokenRegion} (empty-string sentinel for "not configured")
   * rather than {@link postureRegion} so that an operator who explicitly
   * names their region `'unknown'` still has the claim emitted on the
   * token.
   */
  private getRegionClaim(): string | undefined {
    return this.tokenRegion.length > 0 ? this.tokenRegion : undefined;
  }

  /**
   * Validate that every requested capability is a subset of what the
   * user's roles allow. Resource matching uses wildcard-aware
   * `matchesResource` semantics.
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
   * Audit and throw when a contributing PIM activation has expired.
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
   * Log capability issuance for audit trail.
   *
   * Credential payloads (SAS tokens, presigned URLs, RDS auth tokens)
   * are never written — only metadata (provider / resource / actions /
   * expiresAt) is recorded.
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
                grantId: g.grantId,
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
                grantId: c.grantId,
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
}
