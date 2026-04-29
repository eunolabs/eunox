/**
 * Capability Issuer Service
 * Implements the /issue endpoint for capability token issuance
 */

import {
  CapabilityTokenPayload,
  CapabilityConstraint,
  IssueCapabilityRequest,
  IssueCapabilityResponse,
  TokenSigner,
  IdentityProvider,
  CapabilityError,
  ErrorCode,
  generateId,
  getCurrentTimestamp,
  getExpirationTimestamp,
  matchesResource,
  Logger,
  createAuditLogger,
  AuditLogEntry,
  SIGNING_ALGORITHMS,
  mapRolesToCapabilitiesForPolicy,
  RoleCapabilityPolicy,
  DEFAULT_ROLE_CAPABILITY_MAP,
  UserConsent,
  AgentCapabilityManifest,
  validateConditions,
  ConditionValidationError,
  CAPABILITY_TOKEN_SCHEMA_VERSION,
  StorageGrant,
  DbCredential,
} from '@euno/common';
import * as jose from 'jose';
import { StorageGrantService } from './storage-grant';
import { DbTokenService } from './db-token';

/** Actions which always require an explicit, validated user consent record. */
const SENSITIVE_ACTIONS: ReadonlySet<string> = new Set(['write', 'delete', 'admin']);

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

  /** Algorithms permitted for capability token signatures. Sourced from the
   *  shared {@link SIGNING_ALGORITHMS} tuple so this allow-list cannot drift
   *  from the {@link SigningAlgorithm} type. */
  private static readonly ALLOWED_ALGORITHMS = SIGNING_ALGORITHMS;

  /**
   * W3C Verifiable Credentials Data Model `@context`.  Per
   * `docs/execution-plan.md` Sprint 4 (Team CP, "Verifiable Credential
   * Issuance"), capability tokens carry a W3C VC envelope so that
   * verifiers built around standard VC libraries (e.g. `@digitalbazaar/vc`,
   * Microsoft Entra Verified ID) can consume them without bespoke code.
   *
   * The base context (`https://www.w3.org/2018/credentials/v1`) is
   * required by the spec; the second URI namespaces our
   * `CapabilityCredential` type and its `capabilities` /
   * `parentCapabilityId` fields so they are unambiguous when the token
   * is presented to a third party.
   */
  private static readonly VC_CONTEXT: readonly string[] = [
    'https://www.w3.org/2018/credentials/v1',
    'https://schemas.euno.dev/capability-credential/v1',
  ];

  /** W3C VC `type` array used by every capability token. */
  private static readonly VC_TYPE: readonly string[] = [
    'VerifiableCredential',
    'CapabilityCredential',
  ];

  /**
   * Build the W3C Verifiable Credential envelope embedded in a
   * capability token.  The envelope mirrors the JWT claims so that a
   * verifier inspecting only the `vc` object (e.g. a `@digitalbazaar/vc`
   * presentation pipeline) sees the same authoritative subject,
   * issuer, validity window, and capability constraints as a verifier
   * inspecting only the JWT claims.  Both views MUST stay in sync —
   * any change to the JWT claim set on issuance / attenuation /
   * renewal must be reflected here.
   *
   * The `id` field is the JWT id (`jti`) prefixed with `urn:uuid:` so
   * the resulting credential identifier is a valid URI per the VC
   * Data Model § 4.2.
   */
  private buildVerifiableCredential(
    payload: Omit<CapabilityTokenPayload, 'vc'>
  ): NonNullable<CapabilityTokenPayload['vc']> {
    const credentialSubject: Record<string, unknown> = {
      id: payload.sub,
      capabilities: payload.capabilities,
    };
    if (payload.parentCapabilityId !== undefined) {
      credentialSubject.parentCapabilityId = payload.parentCapabilityId;
    }
    if (payload.authorizedBy !== undefined) {
      credentialSubject.authorizedBy = payload.authorizedBy;
    }
    return {
      '@context': [...CapabilityIssuerService.VC_CONTEXT],
      // W3C VC Data Model § 4.2: `id` MUST be a single URI.  Use the
      // RFC-4122 `urn:uuid:` namespace so a VC-only verifier sees the
      // same authoritative credential id as a JWT-only verifier reading
      // `jti`.  Keeping `jti` itself as a bare UUID preserves
      // compatibility with verifiers that index revocations by the raw
      // JWT id.
      id: `urn:uuid:${payload.jti}`,
      type: [...CapabilityIssuerService.VC_TYPE],
      credentialSubject,
    };
  }

  constructor(
    signer: TokenSigner,
    identityProvider: IdentityProvider,
    issuerDid: string,
    defaultTTL: number = 900, // 15 minutes default
    logger: Logger,
    options: CapabilityIssuerServiceOptions = {}
  ) {
    this.signer = signer;
    this.identityProvider = identityProvider;
    this.issuerDid = issuerDid;
    this.defaultTTL = defaultTTL;
    this.logger = logger;
    this.auditLogger = createAuditLogger('capability-issuer');
    this.requireConsent = options.requireConsent === true;
    this.policy = options.policy ?? { default: DEFAULT_ROLE_CAPABILITY_MAP };
    if (options.storageGrantService) this.storageGrantService = options.storageGrantService;
    if (options.dbTokenService) this.dbTokenService = options.dbTokenService;
  }

  /**
   * Issue a capability token
   */
  async issueCapability(request: IssueCapabilityRequest): Promise<IssueCapabilityResponse> {
    try {
      // Step 1: Validate the user's authentication token
      this.logger.info('Validating user authentication token', { agentId: request.agentId });
      const userContext = await this.identityProvider.validateToken(request.authToken);

      // Step 2: Determine capabilities based on user roles
      this.logger.info('Determining capabilities based on user roles', {
        userId: userContext.userId,
        roles: userContext.roles,
        agentId: request.agentId,
      });

      let capabilities;
      // Map roles to capabilities using the externalised policy (with
      // optional per-tenant overrides). Every built-in identity provider
      // (Azure AD, AWS Cognito / IAM Identity Center, GCP Cloud Identity /
      // Identity Platform) populates `userContext.roles` from its native
      // group/role claim, and `userContext.tenantId` from the tenant claim
      // (Azure `tid`, Cognito `cognito:groups`-derived tenant, GCP project
      // ID), so the same policy applies uniformly across clouds while still
      // honouring per-tenant overrides when configured.
      capabilities = mapRolesToCapabilitiesForPolicy(
        userContext.roles,
        this.policy,
        userContext.tenantId,
      );

      // Step 3: If specific capabilities were requested, validate they're allowed
      if (request.requestedCapabilities) {
        // Validate that requested capabilities are a subset of what the user's
        // roles allow. Resource matching uses the same wildcard-aware
        // `matchesResource` semantics as the gateway enforcement engine, so
        // role mappings that grant wildcard resources (e.g. `api://**`,
        // `storage://sales-data/**`) correctly authorize requests for
        // concrete resources beneath them.
        for (const requested of request.requestedCapabilities) {
          const matchingCaps = capabilities.filter((cap) =>
            // matchesResource(concreteResource, wildcardPattern) — the first
            // arg is the concrete resource being requested, the second is the
            // (potentially wildcarded) pattern from the role mapping.
            matchesResource(requested.resource, cap.resource),
          );
          if (matchingCaps.length === 0) {
            throw new CapabilityError(
              ErrorCode.INSUFFICIENT_PERMISSIONS,
              `User does not have permission for resource: ${requested.resource}`,
              403,
            );
          }

          const allowedActions = new Set<string>();
          for (const cap of matchingCaps) {
            for (const action of cap.actions) {
              allowedActions.add(action);
            }
          }

          for (const action of requested.actions) {
            if (!allowedActions.has(action)) {
              throw new CapabilityError(
                ErrorCode.INSUFFICIENT_PERMISSIONS,
                `User does not have permission for action '${action}' on resource: ${requested.resource}`,
                403,
              );
            }
          }
        }

        // Step 3b: enforce per-agent manifest constraint at issuance time.
        // The manifest is the developer-declared upper bound of what an agent
        // is permitted to ever request — even if the user's roles would allow
        // more, the issuer must not exceed it.
        if (request.manifest) {
          this.validateAgainstManifest(
            request.manifest,
            request.agentId,
            request.requestedCapabilities,
          );
        }

        // Step 3c: enforce explicit user consent. Requested capabilities that
        // include sensitive actions (write/delete/admin) require a consent
        // record regardless of `requireConsent`; in `requireConsent` mode the
        // check is mandatory for *every* issuance.
        const requiresConsent =
          this.requireConsent ||
          request.requestedCapabilities.some((cap) =>
            cap.actions.some((action) => SENSITIVE_ACTIONS.has(action)),
          );

        if (requiresConsent) {
          this.validateConsent(
            request.consent,
            userContext.userId,
            request.agentId,
            request.requestedCapabilities,
          );
        } else if (request.consent) {
          // Even when not required, validate any supplied consent so a stale
          // or mismatched record is rejected rather than silently accepted.
          this.validateConsent(
            request.consent,
            userContext.userId,
            request.agentId,
            request.requestedCapabilities,
          );
        }

        capabilities = request.requestedCapabilities;
      } else if (this.requireConsent) {
        // Strict mode: even role-derived issuance must be explicitly consented to.
        throw new CapabilityError(
          ErrorCode.INVALID_REQUEST,
          'Explicit user consent (requestedCapabilities + consent) is required by this issuer',
          400,
        );
      }

      // Step 3d: Validate every condition on every capability before
      // signing. This closes the loop on the typed-condition contract:
      // an unrecognized or malformed condition (typo, wrong value
      // type, unknown discriminator) is rejected at mint time rather
      // than silently round-tripping into a token where the gateway
      // would deny it after issuance — or worse, ignore it entirely.
      this.validateConditionsForCapabilities(capabilities);

      // Step 4: Create the capability token payload
      const now = getCurrentTimestamp();
      const expiresAt = getExpirationTimestamp(this.defaultTTL);
      const tokenId = generateId();

      const payload: CapabilityTokenPayload = {
        iss: this.issuerDid,
        sub: request.agentId,
        aud: 'tool-gateway', // Target audience is the Tool Gateway
        iat: now,
        exp: expiresAt,
        jti: tokenId,
        schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
        capabilities,
        authorizedBy: {
          userId: userContext.userId,
          roles: userContext.roles,
          tenantId: userContext.tenantId,
        },
      };
      // Embed the W3C Verifiable Credential envelope so verifiers built
      // around standard VC libraries can consume the same token (Sprint
      // 4 exit criterion: "Credentials conform to open standards and
      // can be verified using only the DID Document and standard
      // JWT/VC libraries, without proprietary code").
      payload.vc = this.buildVerifiableCredential(payload);

      // Step 5: Sign the token
      this.logger.info('Signing capability token', { tokenId, agentId: request.agentId });
      const token = await this.signer.sign(payload);

      // Step 5b: Mint short-lived cloud-storage and DB credentials for any
      // capability whose resource matches the canonical storage:// or db://
      // form. These pipelines are no-ops when their feature flags are off,
      // preserving the behavior of every existing deployment. A mint
      // failure aborts the entire issuance — partial grants give the
      // agent a misleading view of what it can access (see design § 6 of
      // both 07-storage-grants.md and 08-db-token-issuance.md).
      let storageGrants: StorageGrant[] | undefined;
      let dbCredentials: DbCredential[] | undefined;
      if (this.storageGrantService?.isEnabled()) {
        storageGrants = await this.storageGrantService.mintForCapabilities(capabilities, {
          agentId: request.agentId,
          authorizedBy: userContext.userId,
          capabilityTtlSeconds: expiresAt - now,
        });
      }
      if (this.dbTokenService?.isEnabled()) {
        dbCredentials = await this.dbTokenService.mintForCapabilities(capabilities, {
          agentId: request.agentId,
          authorizedBy: userContext.userId,
          capabilityTtlSeconds: expiresAt - now,
          userRoles: userContext.roles,
          policy: this.policy,
        });
      }

      // Step 6: Audit log the issuance
      await this.logIssuance(
        userContext.userId,
        request.agentId,
        tokenId,
        capabilities,
        request.consent,
        storageGrants,
        dbCredentials,
      );

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
        500
      );
    }
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
      timestamp: new Date(),
      eventType: 'issuance',
      agentId,
      userId,
      capabilityId: tokenId,
      decision: 'allow',
      metadata: {
        capabilities: capabilities.map(c => ({
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
   * Validate that every requested capability falls within the agent's
   * declared manifest (the union of `requiredCapabilities` and
   * `optionalCapabilities`).
   *
   * The manifest is the developer-published upper bound on what an agent may
   * ever ask for. Even if the user's roles permit a broader scope, the
   * issuer must refuse to mint a token that exceeds the manifest, otherwise
   * a compromised agent could request capabilities its declaration never
   * advertised.
   */
  private validateAgainstManifest(
    manifest: AgentCapabilityManifest,
    agentId: string,
    requested: CapabilityConstraint[],
  ): void {
    if (manifest.agentId && manifest.agentId !== agentId) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        `Manifest agentId '${manifest.agentId}' does not match request agentId '${agentId}'`,
        400,
      );
    }

    const allowed: CapabilityConstraint[] = [
      ...(manifest.requiredCapabilities ?? []),
      ...(manifest.optionalCapabilities ?? []),
    ];

    if (allowed.length === 0) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        'Agent manifest declares no capabilities; cannot issue a token against it',
        400,
      );
    }

    for (const req of requested) {
      const matching = allowed.filter((cap) =>
        matchesResource(req.resource, cap.resource),
      );
      if (matching.length === 0) {
        throw new CapabilityError(
          ErrorCode.INSUFFICIENT_PERMISSIONS,
          `Requested resource '${req.resource}' is outside the agent manifest`,
          403,
        );
      }

      const allowedActions = new Set<string>();
      for (const cap of matching) {
        for (const action of cap.actions) {
          allowedActions.add(action);
        }
      }

      for (const action of req.actions) {
        if (!allowedActions.has(action)) {
          throw new CapabilityError(
            ErrorCode.INSUFFICIENT_PERMISSIONS,
            `Action '${action}' on '${req.resource}' is not declared in the agent manifest`,
            403,
          );
        }
      }
    }
  }

  /**
   * Validate an explicit user consent record against the requested capabilities.
   *
   * Consent must be:
   *   - present (when required),
   *   - bound to the same `userId` as the authenticated user,
   *   - bound to the same `agentId` as the request,
   *   - not expired,
   *   - covering every requested capability (resource + every requested action).
   */
  private validateConsent(
    consent: UserConsent | undefined,
    userId: string,
    agentId: string,
    requested: CapabilityConstraint[],
  ): void {
    if (!consent) {
      throw new CapabilityError(
        ErrorCode.INSUFFICIENT_PERMISSIONS,
        'Explicit user consent is required for the requested capabilities',
        403,
      );
    }

    if (consent.userId !== userId) {
      throw new CapabilityError(
        ErrorCode.INSUFFICIENT_PERMISSIONS,
        'User consent does not match the authenticated user',
        403,
      );
    }

    if (consent.agentId !== agentId) {
      throw new CapabilityError(
        ErrorCode.INSUFFICIENT_PERMISSIONS,
        'User consent was not granted to this agent',
        403,
      );
    }

    // Validate `grantedAt` is a finite unix-seconds number that isn't in the
    // future.  Without this check a missing/invalid `grantedAt` would be
    // silently accepted from the untyped HTTP body and then written into the
    // audit log as-is, undermining its evidentiary value.
    const now = getCurrentTimestamp();
    if (typeof consent.grantedAt !== 'number' || !Number.isFinite(consent.grantedAt)) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        'User consent grantedAt must be a finite unix-seconds number',
        400,
      );
    }
    // Allow a small skew window for clock drift between the consent UI and
    // the issuer (60 seconds), but reject obviously fabricated future dates.
    if (consent.grantedAt > now + 60) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        'User consent grantedAt is in the future',
        400,
      );
    }

    // `expiresAt` is optional, but when present it must be a finite number.
    // Reject non-undefined non-number values so callers can't bypass the
    // expiry check by sending e.g. a string or boolean.
    if (consent.expiresAt !== undefined) {
      if (typeof consent.expiresAt !== 'number' || !Number.isFinite(consent.expiresAt)) {
        throw new CapabilityError(
          ErrorCode.INVALID_REQUEST,
          'User consent expiresAt must be a finite unix-seconds number when provided',
          400,
        );
      }
      if (consent.expiresAt <= now) {
        throw new CapabilityError(
          ErrorCode.INSUFFICIENT_PERMISSIONS,
          'User consent has expired',
          403,
        );
      }
    }

    if (!Array.isArray(consent.grantedCapabilities) || consent.grantedCapabilities.length === 0) {
      throw new CapabilityError(
        ErrorCode.INSUFFICIENT_PERMISSIONS,
        'User consent does not list any granted capabilities',
        403,
      );
    }

    for (const req of requested) {
      const matching = consent.grantedCapabilities.filter((cap) =>
        matchesResource(req.resource, cap.resource),
      );
      if (matching.length === 0) {
        throw new CapabilityError(
          ErrorCode.INSUFFICIENT_PERMISSIONS,
          `User did not consent to resource: ${req.resource}`,
          403,
        );
      }

      const grantedActions = new Set<string>();
      for (const cap of matching) {
        for (const action of cap.actions) {
          grantedActions.add(action);
        }
      }

      for (const action of req.actions) {
        if (!grantedActions.has(action)) {
          throw new CapabilityError(
            ErrorCode.INSUFFICIENT_PERMISSIONS,
            `User did not consent to action '${action}' on resource: ${req.resource}`,
            403,
          );
        }
      }
    }
  }

  /**
   * Attenuate (reduce scope of) an existing capability token
   * The child token will have equal or fewer privileges than the parent
   */
  async attenuateCapability(
    parentToken: string,
    requestedCapabilities: CapabilityConstraint[],
    ttl?: number
  ): Promise<IssueCapabilityResponse> {
    try {
      // Step 1: Verify and decode the parent token using jose
      this.logger.info('Attenuating capability token');

      // Decode the token header first (fails fast for malformed tokens)
      let algorithm: string;
      try {
        const header = jose.decodeProtectedHeader(parentToken);
        algorithm = header.alg ?? 'RS256';
      } catch {
        throw new CapabilityError(
          ErrorCode.INVALID_TOKEN,
          'Invalid parent capability token format',
          401
        );
      }

      // Validate algorithm against allow-list to prevent algorithm confusion attacks
      if (!CapabilityIssuerService.ALLOWED_ALGORITHMS.includes(algorithm as any)) {
        throw new CapabilityError(
          ErrorCode.INVALID_TOKEN,
          `Token uses disallowed algorithm: ${algorithm}`,
          401
        );
      }

      const publicKey = await this.signer.getPublicKey();
      const publicKeyObj = await jose.importSPKI(publicKey, algorithm);

      const { payload } = await jose.jwtVerify(parentToken, publicKeyObj, {
        issuer: this.issuerDid,
        audience: 'tool-gateway',
        algorithms: [algorithm],
      });

      const parentPayload = payload as unknown as CapabilityTokenPayload;

      // Step 2: Validate parent token is not expired
      const now = getCurrentTimestamp();
      if (parentPayload.exp < now) {
        throw new CapabilityError(
          ErrorCode.EXPIRED_TOKEN,
          'Parent capability token has expired',
          401
        );
      }

      // Step 3: Validate requested capabilities are a subset of parent capabilities
      this.validateCapabilitySubset(parentPayload.capabilities, requestedCapabilities);

      // Step 3b: Validate the typed conditions on the attenuated set.
      // Even though the parent's conditions were validated when the
      // parent was minted, the child may carry a *narrower* condition
      // set (e.g. a tighter `maxCalls`) that must itself be well-formed.
      this.validateConditionsForCapabilities(requestedCapabilities);

      // Step 4: Calculate expiration (cannot exceed parent's expiration)
      const requestedTTL = ttl || this.defaultTTL;
      const maxExpiration = parentPayload.exp;
      const requestedExpiration = now + requestedTTL;
      const expiresAt = Math.min(requestedExpiration, maxExpiration);

      // Step 5: Create child token payload
      const tokenId = generateId();
      const childPayload: CapabilityTokenPayload = {
        iss: this.issuerDid,
        sub: parentPayload.sub, // Same agent
        aud: parentPayload.aud,
        iat: now,
        exp: expiresAt,
        jti: tokenId,
        schemaVersion: parentPayload.schemaVersion,
        capabilities: requestedCapabilities,
        parentCapabilityId: parentPayload.jti, // Link to parent
        authorizedBy: parentPayload.authorizedBy,
      };
      // Re-build the VC envelope from the *attenuated* claim set so the
      // VC view of the token reflects the narrowed capabilities, not
      // the parent's broader set.
      childPayload.vc = this.buildVerifiableCredential(childPayload);

      // Step 6: Sign the child token
      this.logger.info('Signing attenuated capability token', {
        tokenId,
        parentTokenId: parentPayload.jti,
        agentId: parentPayload.sub,
      });
      const token = await this.signer.sign(childPayload);

      // Step 7: Audit log the attenuation
      await this.logAttenuation(
        parentPayload.sub,
        tokenId,
        parentPayload.jti,
        requestedCapabilities
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

      if (error instanceof CapabilityError) {
        throw error;
      }

      // Map jose JWT errors to appropriate capability errors
      if (error instanceof Error && (error as any).code === 'ERR_JWT_EXPIRED') {
        throw new CapabilityError(
          ErrorCode.EXPIRED_TOKEN,
          'Parent capability token has expired',
          401
        );
      }

      if (error instanceof Error && (
        (error as any).code === 'ERR_JWS_INVALID' ||
        (error as any).code === 'ERR_JWT_CLAIM_VALIDATION_FAILED' ||
        (error as any).code === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED'
      )) {
        throw new CapabilityError(
          ErrorCode.INVALID_TOKEN,
          `Invalid parent capability token: ${error.message}`,
          401
        );
      }

      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        `Failed to attenuate capability: ${error instanceof Error ? error.message : 'Unknown error'}`,
        500
      );
    }
  }

  /**
   * Validate every typed condition on every capability in the list,
   * raising a structured `CapabilityError(INVALID_REQUEST)` on the first
   * failure. Replaces the old fail-open posture where unknown or
   * malformed conditions were silently signed into tokens.
   */
  private validateConditionsForCapabilities(capabilities: CapabilityConstraint[]): void {
    for (let i = 0; i < capabilities.length; i++) {
      const cap = capabilities[i]!;
      if (!cap.conditions) continue;
      try {
        validateConditions(cap.conditions);
      } catch (err) {
        const detail =
          err instanceof ConditionValidationError || err instanceof Error
            ? err.message
            : String(err);
        throw new CapabilityError(
          ErrorCode.INVALID_REQUEST,
          `Invalid condition on capability[${i}] (resource '${cap.resource}'): ${detail}`,
          400,
        );
      }
    }
  }

  /**
   * Validate that requested capabilities are a subset of allowed capabilities
   * Throws CapabilityError if validation fails
   */
  private validateCapabilitySubset(
    parentCapabilities: CapabilityConstraint[],
    requestedCapabilities: CapabilityConstraint[]
  ): void {
    // Validate each requested capability against parent capabilities,
    // supporting wildcard patterns (e.g. storage://datasets/**) via matchesResource()
    for (const requested of requestedCapabilities) {
      // Find all parent capabilities whose pattern matches the requested resource
      const matchingParents = parentCapabilities.filter(cap =>
        matchesResource(requested.resource, cap.resource)
      );

      if (matchingParents.length === 0) {
        throw new CapabilityError(
          ErrorCode.INSUFFICIENT_PERMISSIONS,
          `Cannot attenuate: resource '${requested.resource}' not in parent capability`,
          403
        );
      }

      // Union all allowed actions from matching parent capabilities
      const allowedActions = new Set<string>();
      for (const cap of matchingParents) {
        for (const action of cap.actions) {
          allowedActions.add(action);
        }
      }

      for (const action of requested.actions) {
        if (!allowedActions.has(action)) {
          throw new CapabilityError(
            ErrorCode.INSUFFICIENT_PERMISSIONS,
            `Cannot attenuate: action '${action}' on resource '${requested.resource}' not in parent capability`,
            403
          );
        }
      }

      // Attenuation must not LOOSEN argument-level constraints declared on
      // the parent. If any matching parent capability has an
      // `argumentSchema`, the child must carry the same schema (deep
      // equal). The child is allowed to introduce a new schema only when
      // no matching parent has one (introducing a constraint is a
      // tightening, which is always sound).
      const parentsWithSchema = matchingParents.filter(p => p.argumentSchema);
      if (parentsWithSchema.length > 0) {
        const requestedSchemaSerialized = stableStringify(requested.argumentSchema);
        const matchesAnyParent = parentsWithSchema.some(
          p => stableStringify(p.argumentSchema) === requestedSchemaSerialized
        );
        if (!matchesAnyParent) {
          throw new CapabilityError(
            ErrorCode.INSUFFICIENT_PERMISSIONS,
            `Cannot attenuate: argumentSchema on resource '${requested.resource}' must match the parent capability's argumentSchema`,
            403
          );
        }
      }
    }
  }

  /**
   * Log capability attenuation for audit trail
   */
  private async logAttenuation(
    agentId: string,
    tokenId: string,
    parentTokenId: string,
    capabilities: CapabilityConstraint[]
  ): Promise<void> {
    const auditEntry: AuditLogEntry = {
      id: generateId(),
      timestamp: new Date(),
      eventType: 'issuance', // Using issuance for now, could add 'attenuation' type
      agentId,
      capabilityId: tokenId,
      decision: 'allow',
      metadata: {
        parentCapabilityId: parentTokenId,
        capabilities: capabilities.map(c => ({
          resource: c.resource,
          actions: c.actions,
        })),
      },
    };

    this.auditLogger.info('Capability token attenuated', auditEntry);
  }

  /**
   * Renew an existing capability token with a fresh expiration
   * Token keeps same capabilities but gets new TTL
   */
  async renewCapability(
    currentToken: string,
    ttl?: number
  ): Promise<IssueCapabilityResponse> {
    try {
      // Step 1: Verify and decode the current token
      this.logger.info('Renewing capability token');

      // Decode the token header first (fails fast for malformed tokens)
      let algorithm: string;
      try {
        const header = jose.decodeProtectedHeader(currentToken);
        algorithm = header.alg ?? 'RS256';
      } catch {
        throw new CapabilityError(
          ErrorCode.INVALID_TOKEN,
          'Invalid capability token format',
          401
        );
      }

      // Validate algorithm against allow-list to prevent algorithm confusion attacks
      if (!CapabilityIssuerService.ALLOWED_ALGORITHMS.includes(algorithm as any)) {
        throw new CapabilityError(
          ErrorCode.INVALID_TOKEN,
          `Token uses disallowed algorithm: ${algorithm}`,
          401
        );
      }

      const publicKey = await this.signer.getPublicKey();
      const publicKeyObj = await jose.importSPKI(publicKey, algorithm);

      const { payload } = await jose.jwtVerify(currentToken, publicKeyObj, {
        issuer: this.issuerDid,
        audience: 'tool-gateway',
        algorithms: [algorithm],
      });

      const currentPayload = payload as unknown as CapabilityTokenPayload;

      // Step 2: Create renewed token with same capabilities but fresh expiration
      const now = getCurrentTimestamp();
      const expiresAt = getExpirationTimestamp(ttl || this.defaultTTL);
      const tokenId = generateId();

      const renewedPayload: CapabilityTokenPayload = {
        iss: this.issuerDid,
        sub: currentPayload.sub, // Same agent
        aud: currentPayload.aud,
        iat: now,
        exp: expiresAt,
        jti: tokenId,
        schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
        capabilities: currentPayload.capabilities, // Same capabilities
        parentCapabilityId: currentPayload.jti, // Link to previous token for audit trail
        authorizedBy: currentPayload.authorizedBy,
      };
      // Re-build the VC envelope so its `id` (urn:uuid:<jti>) and
      // `parentCapabilityId` reference the new token, not the previous
      // one.
      renewedPayload.vc = this.buildVerifiableCredential(renewedPayload);

      // Step 3: Sign the renewed token
      this.logger.info('Signing renewed capability token', {
        tokenId,
        previousTokenId: currentPayload.jti,
        agentId: currentPayload.sub,
      });
      const token = await this.signer.sign(renewedPayload);

      // Step 4: Audit log the renewal
      await this.logRenewal(
        currentPayload.sub,
        tokenId,
        currentPayload.jti,
        currentPayload.capabilities
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

      if (error instanceof CapabilityError) {
        throw error;
      }

      // Map jose JWT errors to appropriate capability errors
      if (error instanceof Error && (error as any).code === 'ERR_JWT_EXPIRED') {
        throw new CapabilityError(
          ErrorCode.EXPIRED_TOKEN,
          'Capability token has expired; re-authentication is required',
          401
        );
      }

      if (error instanceof Error && (
        (error as any).code === 'ERR_JWS_INVALID' ||
        (error as any).code === 'ERR_JWT_CLAIM_VALIDATION_FAILED' ||
        (error as any).code === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED'
      )) {
        throw new CapabilityError(
          ErrorCode.INVALID_TOKEN,
          `Invalid capability token: ${error.message}`,
          401
        );
      }

      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        `Failed to renew capability: ${error instanceof Error ? error.message : 'Unknown error'}`,
        500
      );
    }
  }

  /**
   * Log capability renewal for audit trail
   */
  private async logRenewal(
    agentId: string,
    tokenId: string,
    previousTokenId: string,
    capabilities: CapabilityConstraint[]
  ): Promise<void> {
    const auditEntry: AuditLogEntry = {
      id: generateId(),
      timestamp: new Date(),
      eventType: 'renewal',
      agentId,
      capabilityId: tokenId,
      decision: 'allow',
      metadata: {
        previousCapabilityId: previousTokenId,
        capabilities: capabilities.map(c => ({
          resource: c.resource,
          actions: c.actions,
        })),
      },
    };

    this.auditLogger.info('Capability token renewed', auditEntry);
  }

  /**
   * Get public key for token verification
   */
  async getPublicKey(): Promise<string> {
    return await this.signer.getPublicKey();
  }
}

/**
 * Deterministic JSON serialiser used to compare `argumentSchema` objects
 * across capability boundaries. Object keys are sorted recursively so that
 * the comparison is independent of property order.
 */
function stableStringify(value: unknown): string {
  if (value === undefined) {
    return 'undefined';
  }
  return JSON.stringify(value, (_key, v) => {
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      const sorted: Record<string, unknown> = {};
      for (const k of Object.keys(v).sort()) {
        sorted[k] = (v as Record<string, unknown>)[k];
      }
      return sorted;
    }
    return v;
  });
}
