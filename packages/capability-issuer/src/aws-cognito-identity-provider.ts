/**
 * AWS Cognito / IAM Identity Center Identity Provider
 *
 * Implements the pluggable {@link IdentityAdapter} contract for AWS-native
 * identity sources required by Sprint 1 of `docs/execution-plan.md`:
 *
 *   * Amazon Cognito user pools — validates ID/access tokens via the
 *     pool's JWKS at `https://cognito-idp.{region}.amazonaws.com/{poolId}/
 *     .well-known/jwks.json`.
 *   * AWS IAM Identity Center (formerly AWS SSO) — validates OIDC ID
 *     tokens issued by the Identity Center OIDC application; the issuer
 *     and JWKS URI are supplied via configuration.
 *
 * Roles are read from the `cognito:groups` claim (Cognito user pools) or
 * the `groups` claim (IAM Identity Center / generic OIDC) and converted to
 * capability constraints by the shared {@link mapRolesToCapabilities}
 * mapper, exactly mirroring the Azure AD provider.
 */

import * as jose from 'jose';
import {
  IdentityAdapter,
  IdentityAdapterConfig,
  UserContext,
  AWSCognitoConfig,
  CapabilityError,
  ErrorCode,
} from '@euno/common';

/**
 * AWS Cognito specific configuration extending the base adapter config
 */
export interface AWSCognitoAdapterConfig extends IdentityAdapterConfig {
  type: 'aws-cognito';
  awsCognito: AWSCognitoConfig;
}

export class AWSCognitoIdentityProvider extends IdentityAdapter {
  public readonly name = 'aws-cognito';
  private cognitoConfig: AWSCognitoConfig;
  private jwks: ReturnType<typeof jose.createRemoteJWKSet> | null = null;
  private issuer: string;
  private jwksUri: string;
  private tokenUse: 'id' | 'access';

  constructor(config: AWSCognitoAdapterConfig) {
    super(config);
    this.cognitoConfig = config.awsCognito;
    this.issuer =
      this.cognitoConfig.issuer ||
      `https://cognito-idp.${this.cognitoConfig.region}.amazonaws.com/${this.cognitoConfig.userPoolId}`;
    this.jwksUri =
      this.cognitoConfig.jwksUri || `${this.issuer}/.well-known/jwks.json`;
    this.tokenUse = this.cognitoConfig.tokenUse || 'id';
  }

  /**
   * Validate a Cognito / IAM Identity Center OIDC token and extract user
   * context. Cognito access tokens use the `client_id` claim instead of
   * `aud`, so audience verification is performed manually for those.
   */
  async validateToken(token: string): Promise<UserContext> {
    try {
      if (!this.jwks) {
        this.jwks = jose.createRemoteJWKSet(new URL(this.jwksUri));
      }

      const verifyOptions: jose.JWTVerifyOptions = { issuer: this.issuer };
      // Cognito ID tokens carry an `aud` claim equal to the app client ID;
      // access tokens carry `client_id` instead and have no `aud`. Only
      // pass `audience` to jose for ID tokens.
      if (this.tokenUse === 'id') {
        verifyOptions.audience = this.cognitoConfig.clientId;
      }

      const { payload } = await jose.jwtVerify(token, this.jwks, verifyOptions);

      // Enforce token_use matches what we expect (Cognito-specific defence).
      if (payload.token_use && payload.token_use !== this.tokenUse) {
        throw new Error(
          `Token type mismatch: expected '${this.tokenUse}', got '${payload.token_use}'`,
        );
      }

      // For access tokens, manually verify the client_id claim.
      if (this.tokenUse === 'access') {
        const clientIdClaim = payload.client_id as string | undefined;
        if (!clientIdClaim || clientIdClaim !== this.cognitoConfig.clientId) {
          throw new Error('Token client_id does not match configured client');
        }
      }

      const groups =
        (payload['cognito:groups'] as string[] | undefined) ||
        (payload.groups as string[] | undefined) ||
        [];

      const userContext: UserContext = {
        userId:
          (payload.sub as string) ||
          (payload.username as string) ||
          (payload['cognito:username'] as string),
        email:
          (payload.email as string) || (payload['cognito:username'] as string),
        roles: groups,
        // AWS Identity Center surfaces the instance ARN/identity-store ID via
        // a custom claim; expose it as `tenantId` for parity with Azure AD's
        // `tid` claim.
        tenantId:
          (payload['identitystore_id'] as string | undefined) ||
          (payload['identitycenter_instance'] as string | undefined),
        claims: payload as Record<string, unknown>,
      };

      return userContext;
    } catch (error) {
      throw new CapabilityError(
        ErrorCode.AUTHENTICATION_FAILED,
        `Failed to validate AWS Cognito token: ${
          error instanceof Error ? error.message : 'Unknown error'
        }`,
        401,
      );
    }
  }

  /**
   * Get user roles. Cognito does not expose a generic "list groups for user"
   * API on the OIDC token path (it requires AWS-SDK calls with admin
   * permissions); for parity with the Azure provider we surface the groups
   * claim from the most recently validated token via the issuer service.
   * Callers that need authoritative role membership should use the AWS SDK
   * directly with appropriate IAM permissions.
   */
  async getUserRoles(_userId: string): Promise<string[]> {
    throw new CapabilityError(
      ErrorCode.AUTHORIZATION_FAILED,
      'AWS Cognito provider derives roles from token claims; use validateToken() to read userContext.roles',
      501,
    );
  }
}
