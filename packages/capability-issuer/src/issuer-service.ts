/**
 * Capability Issuer Service
 * Implements the /issue endpoint for capability token issuance
 */

import {
  CapabilityTokenPayload,
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
   * Get public key for token verification
   */
  async getPublicKey(): Promise<string> {
    return await this.signer.getPublicKey();
  }
}
