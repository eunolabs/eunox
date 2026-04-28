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
  mapRolesToCapabilities,
} from '@euno/common';
import * as jose from 'jose';

export class CapabilityIssuerService {
  private signer: TokenSigner;
  private identityProvider: IdentityProvider;
  private issuerDid: string;
  private defaultTTL: number;
  private logger: Logger;
  private auditLogger: Logger;

  /** Algorithms permitted for capability token signatures. */
  private static readonly ALLOWED_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'ES256K', 'EdDSA'] as const;

  constructor(
    signer: TokenSigner,
    identityProvider: IdentityProvider,
    issuerDid: string,
    defaultTTL: number = 900, // 15 minutes default
    logger: Logger
  ) {
    this.signer = signer;
    this.identityProvider = identityProvider;
    this.issuerDid = issuerDid;
    this.defaultTTL = defaultTTL;
    this.logger = logger;
    this.auditLogger = createAuditLogger('capability-issuer');
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
      // Map roles to capabilities using the shared, provider-agnostic mapper.
      // Every built-in identity provider (Azure AD, AWS Cognito / IAM
      // Identity Center, GCP Cloud Identity / Identity Platform) populates
      // `userContext.roles` from its native group/role claim, so the same
      // Sprint-1 mapping applies uniformly across clouds.
      capabilities = mapRolesToCapabilities(userContext.roles);

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
        capabilities = request.requestedCapabilities;
      }

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
        capabilities,
        authorizedBy: {
          userId: userContext.userId,
          roles: userContext.roles,
          tenantId: userContext.tenantId,
        },
      };

      // Step 5: Sign the token
      this.logger.info('Signing capability token', { tokenId, agentId: request.agentId });
      const token = await this.signer.sign(payload);

      // Step 6: Audit log the issuance
      await this.logIssuance(userContext.userId, request.agentId, tokenId, capabilities);

      this.logger.info('Capability token issued successfully', {
        tokenId,
        agentId: request.agentId,
        userId: userContext.userId,
        expiresAt,
      });

      return {
        token,
        expiresAt,
        tokenId,
        capabilities,
      };
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
   * Log capability issuance for audit trail
   */
  private async logIssuance(
    userId: string,
    agentId: string,
    tokenId: string,
    capabilities: Array<{ resource: string; actions: string[] }>
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
      },
    };

    this.auditLogger.info('Capability token issued', auditEntry);
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
        capabilities: requestedCapabilities,
        parentCapabilityId: parentPayload.jti, // Link to parent
        authorizedBy: parentPayload.authorizedBy,
      };

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
        capabilities: currentPayload.capabilities, // Same capabilities
        parentCapabilityId: currentPayload.jti, // Link to previous token for audit trail
        authorizedBy: currentPayload.authorizedBy,
      };

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
