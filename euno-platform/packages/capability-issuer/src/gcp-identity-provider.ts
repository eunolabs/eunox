/**
 * Google Cloud Identity Provider
 *
 * Implements the pluggable {@link IdentityAdapter} contract for GCP-native
 * identity sources required by Sprint 1 of `docs/execution-plan.md`:
 *
 *   * Google Cloud Identity / Google accounts — OIDC ID tokens issued by
 *     `https://accounts.google.com`, validated against
 *     `https://www.googleapis.com/oauth2/v3/certs`.
 *   * Identity Platform (Firebase Auth) — tokens issued by
 *     `https://securetoken.google.com/{projectId}`, validated against the
 *     `securetoken@system.gserviceaccount.com` JWKS endpoint.
 *   * Workforce Identity Federation / Workload Identity Federation — pool
 *     issuer and JWKS URI are supplied via configuration.
 *
 * Roles are read from the configured `rolesClaim` (default `groups`) and
 * mapped to capability constraints by the shared
 * {@link mapRolesToCapabilities} mapper, matching the Azure AD provider.
 */

import * as jose from 'jose';
import {
  IdentityAdapter,
  IdentityAdapterConfig,
  UserContext,
  GCPIdentityConfig,
  CapabilityError,
  ErrorCode,
} from '@euno/common';

/**
 * GCP identity specific configuration extending the base adapter config
 */
export interface GCPIdentityAdapterConfig extends IdentityAdapterConfig {
  type: 'gcp-identity';
  gcpIdentity: GCPIdentityConfig;
}

const DEFAULT_GOOGLE_ISSUER = 'https://accounts.google.com';
const DEFAULT_GOOGLE_JWKS = 'https://www.googleapis.com/oauth2/v3/certs';
const IDENTITY_PLATFORM_JWKS =
  'https://www.googleapis.com/service_accounts/v1/metadata/x509/securetoken@system.gserviceaccount.com';

export class GCPIdentityProvider extends IdentityAdapter {
  public readonly name = 'gcp-identity';
  private gcpConfig: GCPIdentityConfig;
  private jwks: ReturnType<typeof jose.createRemoteJWKSet> | null = null;
  private issuer: string;
  private jwksUri: string;
  private rolesClaim: string;

  constructor(config: GCPIdentityAdapterConfig) {
    super(config);
    this.gcpConfig = config.gcpIdentity;

    if (this.gcpConfig.issuer) {
      this.issuer = this.gcpConfig.issuer;
    } else if (this.gcpConfig.projectId) {
      // Identity Platform / Firebase Auth issuer
      this.issuer = `https://securetoken.google.com/${this.gcpConfig.projectId}`;
    } else {
      this.issuer = DEFAULT_GOOGLE_ISSUER;
    }

    if (this.gcpConfig.jwksUri) {
      this.jwksUri = this.gcpConfig.jwksUri;
    } else if (this.issuer.startsWith('https://securetoken.google.com/')) {
      this.jwksUri = IDENTITY_PLATFORM_JWKS;
    } else {
      this.jwksUri = DEFAULT_GOOGLE_JWKS;
    }

    this.rolesClaim = this.gcpConfig.rolesClaim || 'groups';
  }

  /**
   * Validate a Google-issued OIDC token and extract user context.
   */
  async validateToken(token: string): Promise<UserContext> {
    try {
      if (!this.jwks) {
        this.jwks = jose.createRemoteJWKSet(new URL(this.jwksUri));
      }

      const { payload } = await jose.jwtVerify(token, this.jwks, {
        issuer: this.issuer,
        audience: this.gcpConfig.audience,
      });

      // Explicitly validate that a non-empty string subject claim is
      // present. Without this the `as string` cast below would silently
      // produce an `undefined` userId at runtime when both `sub` and
      // `user_id` are missing.
      const subjectClaim =
        typeof payload.sub === 'string' && payload.sub.length > 0
          ? payload.sub
          : typeof payload.user_id === 'string' && payload.user_id.length > 0
            ? payload.user_id
            : undefined;

      if (!subjectClaim) {
        throw new CapabilityError(
          ErrorCode.AUTHENTICATION_FAILED,
          'Failed to validate GCP identity token: missing subject claim',
          401,
        );
      }

      const rawRoles = payload[this.rolesClaim];
      const roles: string[] = Array.isArray(rawRoles)
        ? rawRoles.filter((r): r is string => typeof r === 'string')
        : [];

      const userContext: UserContext = {
        userId: subjectClaim,
        email: (payload.email as string) || undefined,
        roles,
        // Identity Platform tokens carry the Firebase project ID in `aud`,
        // and Cloud Identity / Workspace tokens carry the Google Workspace
        // domain in `hd` (hosted domain). Either is a reasonable tenant
        // identifier for parity with Azure AD's `tid`.
        tenantId:
          (payload.hd as string | undefined) ||
          this.gcpConfig.projectId ||
          undefined,
        claims: payload as Record<string, unknown>,
      };

      return userContext;
    } catch (error) {
      // Re-throw existing CapabilityErrors (e.g. the missing-subject error
      // raised above) without wrapping so their original status codes and
      // messages survive.
      if (error instanceof CapabilityError) {
        throw error;
      }
      throw new CapabilityError(
        ErrorCode.AUTHENTICATION_FAILED,
        `Failed to validate GCP identity token: ${
          error instanceof Error ? error.message : 'Unknown error'
        }`,
        401,
      );
    }
  }

  /**
   * Get user roles. Google does not expose a generic "list groups for user"
   * API on the OIDC token path; authoritative role membership requires the
   * Cloud Identity Groups API (`cloudidentity.googleapis.com`) with a
   * service account that has the `groups.readonly` scope. For Sprint 1
   * parity we read groups from token claims via {@link validateToken}.
   */
  async getUserRoles(_userId: string): Promise<string[]> {
    throw new CapabilityError(
      ErrorCode.AUTHORIZATION_FAILED,
      'GCP identity provider derives roles from token claims; use validateToken() to read userContext.roles',
      501,
    );
  }
}
