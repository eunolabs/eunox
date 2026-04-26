/**
 * Azure AD Identity Provider
 * Implements pluggable identity provider interface for Azure Active Directory
 */

import { Client } from '@microsoft/microsoft-graph-client';
import { ClientSecretCredential } from '@azure/identity';
import * as jose from 'jose';
import {
  IdentityAdapter,
  IdentityAdapterConfig,
  UserContext,
  AzureADConfig,
  CapabilityError,
  ErrorCode,
  Action,
  CapabilityConstraint,
} from '@euno/common';

/**
 * Azure AD specific configuration extending the base adapter config
 */
export interface AzureADAdapterConfig extends IdentityAdapterConfig {
  type: 'azure-ad';
  azureAD: AzureADConfig;
}

export class AzureADIdentityProvider extends IdentityAdapter {
  public readonly name = 'azure-ad';
  private azureConfig: AzureADConfig;
  private graphClient?: Client;

  constructor(config: AzureADAdapterConfig) {
    super(config);
    this.azureConfig = config.azureAD;
  }

  /**
   * Validate an OIDC token from Azure AD and extract user context
   */
  async validateToken(token: string): Promise<UserContext> {
    try {
      // Get JWKS for token verification
      const authority = this.azureConfig.authority || `https://login.microsoftonline.com/${this.azureConfig.tenantId}`;
      const jwksUri = `${authority}/discovery/v2.0/keys`;

      // Create JWKS instance
      const JWKS = jose.createRemoteJWKSet(new URL(jwksUri));

      // Verify the token
      const { payload } = await jose.jwtVerify(token, JWKS, {
        issuer: `${authority}/v2.0`,
        audience: this.azureConfig.clientId,
      });

      // Extract user context from token claims
      const userContext: UserContext = {
        userId: payload.oid as string || payload.sub as string,
        email: payload.email as string || payload.upn as string,
        roles: (payload.roles as string[]) || [],
        tenantId: payload.tid as string,
        claims: payload as Record<string, unknown>,
      };

      return userContext;
    } catch (error) {
      throw new CapabilityError(
        ErrorCode.AUTHENTICATION_FAILED,
        `Failed to validate Azure AD token: ${error instanceof Error ? error.message : 'Unknown error'}`,
        401
      );
    }
  }

  /**
   * Get user roles from Azure AD via Microsoft Graph API
   */
  async getUserRoles(userId: string): Promise<string[]> {
    try {
      const graphClient = await this.getGraphClient();

      // Get user's directory roles
      const roles = await graphClient
        .api(`/users/${userId}/memberOf`)
        .select('displayName')
        .get();

      return roles.value.map((role: any) => role.displayName);
    } catch (error) {
      throw new CapabilityError(
        ErrorCode.AUTHORIZATION_FAILED,
        `Failed to get user roles: ${error instanceof Error ? error.message : 'Unknown error'}`,
        500
      );
    }
  }

  /**
   * Check if user has a specific permission
   */
  async hasPermission(userId: string, permission: string): Promise<boolean> {
    const roles = await this.getUserRoles(userId);
    return roles.includes(permission);
  }

  /**
   * Get or create Graph API client
   */
  private async getGraphClient(): Promise<Client> {
    if (this.graphClient) {
      return this.graphClient;
    }

    if (!this.azureConfig.clientSecret) {
      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        'Client secret required for Graph API access',
        500
      );
    }

    const credential = new ClientSecretCredential(
      this.azureConfig.tenantId,
      this.azureConfig.clientId,
      this.azureConfig.clientSecret
    );

    // Get access token for Microsoft Graph
    const tokenResponse = await credential.getToken('https://graph.microsoft.com/.default');

    this.graphClient = Client.init({
      authProvider: (done) => {
        done(null, tokenResponse.token);
      },
    });

    return this.graphClient;
  }

  /**
   * Map Azure AD roles to capability constraints
   * This implements the policy-driven issuance logic
   */
  static mapRolesToCapabilities(roles: string[]): CapabilityConstraint[] {
    const capabilities: CapabilityConstraint[] = [];

    // Define role to capability mappings
    const roleMapping: Record<string, CapabilityConstraint[]> = {
      'SalesManager': [
        { resource: 'api://crm/customers', actions: ['read' as Action, 'write' as Action] },
        { resource: 'api://crm/reports', actions: ['read' as Action] },
        { resource: 'storage://sales-data/**', actions: ['read' as Action, 'write' as Action] },
      ],
      'Viewer': [
        { resource: 'api://crm/customers', actions: ['read' as Action] },
        { resource: 'api://crm/reports', actions: ['read' as Action] },
        { resource: 'storage://sales-data/**', actions: ['read' as Action] },
      ],
      'DataScientist': [
        { resource: 'api://analytics/**', actions: ['read' as Action, 'write' as Action] },
        { resource: 'storage://datasets/**', actions: ['read' as Action] },
        { resource: 'api://ml-models/**', actions: ['read' as Action, 'execute' as Action] },
      ],
      'Administrator': [
        { resource: 'api://**', actions: ['read' as Action, 'write' as Action, 'admin' as Action] },
        { resource: 'storage://**', actions: ['read' as Action, 'write' as Action, 'delete' as Action] },
      ],
    };

    // Collect all capabilities for user's roles
    for (const role of roles) {
      const roleCaps = roleMapping[role];
      if (roleCaps) {
        capabilities.push(...roleCaps);
      }
    }

    return capabilities;
  }
}
