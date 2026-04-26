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
  Logger,
  createAuditLogger,
  AuditLogEntry,
} from '@euno/common';
import { AzureADIdentityProvider } from './identity-provider';
import * as jose from 'jose';

export class CapabilityIssuerService {
  private signer: TokenSigner;
  private identityProvider: IdentityProvider;
  private issuerDid: string;
  private defaultTTL: number;
  private logger: Logger;
  private auditLogger: Logger;

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
      if (this.identityProvider instanceof AzureADIdentityProvider) {
        capabilities = AzureADIdentityProvider.mapRolesToCapabilities(userContext.roles);
      } else {
        // Generic fallback
        capabilities = request.requestedCapabilities || [];
      }

      // Step 3: If specific capabilities were requested, validate they're allowed
      if (request.requestedCapabilities) {
        // Validate that requested capabilities are a subset of what the user's roles allow
        const allowedCapabilitiesByResource = new Map<string, Set<string>>();
        for (const capability of capabilities) {
          const allowedActions = allowedCapabilitiesByResource.get(capability.resource) || new Set<string>();
          for (const action of capability.actions) {
            allowedActions.add(action);
          }
          allowedCapabilitiesByResource.set(capability.resource, allowedActions);
        }

        for (const requested of request.requestedCapabilities) {
          const allowedActions = allowedCapabilitiesByResource.get(requested.resource);
          if (!allowedActions) {
            throw new CapabilityError(
              ErrorCode.INSUFFICIENT_PERMISSIONS,
              `User does not have permission for resource: ${requested.resource}`,
              403
            );
          }

          for (const action of requested.actions) {
            if (!allowedActions.has(action)) {
              throw new CapabilityError(
                ErrorCode.INSUFFICIENT_PERMISSIONS,
                `User does not have permission for action '${action}' on resource: ${requested.resource}`,
                403
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
      const publicKey = await this.signer.getPublicKey();
      const publicKeyObj = await jose.importSPKI(publicKey, 'RS256');

      const { payload } = await jose.jwtVerify(parentToken, publicKeyObj, {
        issuer: this.issuerDid,
        audience: 'tool-gateway',
      });

      const parentPayload = payload as unknown as CapabilityTokenPayload;

      // Step 2: Validate parent token is not expired
      const now = getCurrentTimestamp();
      if (parentPayload.exp < now) {
        throw new CapabilityError(
          ErrorCode.TOKEN_EXPIRED,
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
    // Build a map of parent resources to their allowed actions
    const parentResourceMap = new Map<string, Set<string>>();
    for (const cap of parentCapabilities) {
      const actions = parentResourceMap.get(cap.resource) || new Set<string>();
      for (const action of cap.actions) {
        actions.add(action);
      }
      parentResourceMap.set(cap.resource, actions);
    }

    // Validate each requested capability
    for (const requested of requestedCapabilities) {
      const parentActions = parentResourceMap.get(requested.resource);

      if (!parentActions) {
        throw new CapabilityError(
          ErrorCode.INSUFFICIENT_PERMISSIONS,
          `Cannot attenuate: resource '${requested.resource}' not in parent capability`,
          403
        );
      }

      for (const action of requested.actions) {
        if (!parentActions.has(action)) {
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
   * Get public key for token verification
   */
  async getPublicKey(): Promise<string> {
    return await this.signer.getPublicKey();
  }
}
