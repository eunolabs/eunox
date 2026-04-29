/**
 * Runtime types for `@euno/common`.
 *
 * Types in this module describe **in-process behaviour**: pluggable service
 * interfaces (`EvidenceSigner`, `IdentityProvider`, `TokenSigner`,
 * `TokenVerifier`, `KillSwitchManager`, `PostureEmitterLike`), the
 * authenticated user/session context flowing through the issuer
 * (`UserContext`, `ResolvedRole`, `CaEvaluation`), the canonical inventory
 * record emitted to posture surfaces (`AgentInventoryRecord`), and the
 * service / cloud-provider configuration shapes consumed by bootstrap.
 *
 * They are intentionally separated from the wire-shape types in
 * {@link "./wire"} so that downstream consumers that only need to *speak*
 * the protocol can depend on `@euno/common/wire` without importing any
 * server-side interfaces. The legacy `./types` entry re-exports everything
 * from here for back-compat — see R-8 in
 * `docs/IMPROVEMENTS_AND_REFACTORING.md`.
 */

import type {
  AuditEvidence,
  SignedAuditEvidence,
  CapabilityConstraint,
  CapabilityTokenPayload,
} from './wire';

/**
 * Canonical inventory record for AI posture-management surfaces
 * (Azure Defender CSPM, AWS Security Hub, GCP Security Command Center).
 *
 * Per `docs/sprint-3-4-gaps/09-ai-posture-inventory.md`, the five
 * required fields (`agentId`, `owningTeam`, `capabilityManifestHash`,
 * `runtime`, `region`) are emitted to all three surfaces under the
 * **same** field names so a single dashboard view is possible without
 * per-cloud aliasing. Plugins MUST NOT rename these keys when mapping
 * the record into per-surface payloads.
 */
export interface AgentInventoryRecord {
  /** Schema version of the record envelope. */
  schemaVersion: '1.0';
  /** Agent identifier. Matches `CapabilityToken.sub`. */
  agentId: string;
  /** Owning team / business unit, taken from `manifest.metadata.owner`. */
  owningTeam: string;
  /**
   * SHA-256 (hex) of the canonical-JSON form of the agent's
   * {@link AgentCapabilityManifest}. Computed via the shared
   * `canonicalSha256` helper so it matches the manifest hash
   * recorded in the audit log.
   */
  capabilityManifestHash: string;
  /** Runtime descriptor — e.g. `node:20`, `python:3.12`, `aks:1.29`. */
  runtime: string;
  /** Cloud region the agent runs in — e.g. `eastus2`, `us-east-1`. */
  region: string;
  /**
   * Cloud account / tenant / project the issuer pod runs in.
   * Optional, but recommended for multi-account deployments.
   */
  cloudAccount?: string;
  /** Pointer (URI) to the manifest in storage, when one exists. */
  manifestUri?: string;
  /**
   * Capability constraints granted to the agent. Optional — opt in
   * via `POSTURE_EMITTER_INCLUDE_CAPABILITIES=true` because some
   * surfaces have payload-size limits.
   */
  capabilities?: CapabilityConstraint[];
  /** ISO-8601 timestamp when this agent was first observed. */
  firstSeen: string;
  /** ISO-8601 timestamp when this agent was last observed. */
  lastSeen: string;
  /** ISO-8601 timestamp when the record was revoked (soft delete). */
  revokedAt?: string;
}

/**
 * Minimal structural interface the capability issuer (and any other
 * producer of {@link AgentInventoryRecord}s) needs from a posture-emitter.
 *
 * The full implementation lives in `@euno/posture-emitter`; declaring the
 * contract here keeps producers free of a hard dependency on that package
 * and makes the integration point explicit. See
 * `docs/sprint-3-4-gaps/09-ai-posture-inventory.md` § 5.
 */
export interface PostureEmitterLike {
  /** Returns true when the emitter is configured and active. Producers
   *  MUST short-circuit when this is false to avoid building inventory
   *  records that will be dropped. */
  isEnabled(): boolean;
  /** Fire-and-forget observation of an agent. Implementations SHOULD
   *  not throw; producers treat rejected promises as best-effort
   *  failures and never fail the originating operation. */
  emitObserved(record: AgentInventoryRecord): Promise<void>;
  /** Optional revocation hook. Producers call this when an agent is
   *  decommissioned so posture surfaces can soft-delete the record. */
  emitRevoked?(agentId: string, revokedAt: string): Promise<void>;
}

/**
 * Evidence signer interface for cryptographic audit trails
 */
export interface EvidenceSigner {
  /**
   * Sign audit evidence to create tamper-evident records
   */
  signEvidence(evidence: AuditEvidence): Promise<SignedAuditEvidence>;

  /**
   * Verify a signed evidence record
   */
  verifyEvidence(signedEvidence: SignedAuditEvidence): Promise<boolean>;
}

/**
 * Identity provider interface for pluggable authentication
 */
export interface IdentityProvider {
  /** Provider name (e.g., "azure-ad", "okta", "cognito") */
  name: string;

  /**
   * Validate an authentication token and extract user context
   */
  validateToken(token: string): Promise<UserContext>;

  /**
   * Get user roles and permissions
   */
  getUserRoles(userId: string): Promise<string[]>;

  /**
   * Check if user has specific permission
   */
  hasPermission(userId: string, permission: string): Promise<boolean>;
}

/**
 * Capability action tier used by Conditional Access policy enforcement.
 *
 * The tier set intentionally matches the most sensitive actions named by
 * `SENSITIVE_ACTIONS` in the issuer service plus `read`. CA configuration
 * may declare separate `acrs` requirements per tier (see
 * {@link AzureADConfig.conditionalAccess.requiredAcrsByTier}); the issuer
 * compares each requested capability's actions against this set when
 * evaluating whether {@link CaEvaluation.satisfiedTiers} permits issuance.
 */
export type CaActionTier = 'read' | 'write' | 'delete' | 'admin';

/**
 * Result of evaluating Conditional Access (CA) signals during token
 * validation. Populated by identity providers that participate in CA
 * enforcement (today, Azure AD); other providers leave it undefined and
 * the issuer treats the request as if no CA policy applies.
 *
 * The provider records *what was checked* (`requiredAcrsByTier`) and
 * *which tiers were satisfied* (`satisfiedTiers`); the issuer service is
 * responsible for comparing the requested capability's action set against
 * `satisfiedTiers` and denying the issuance with
 * `CONDITIONAL_ACCESS_REQUIRED` when a required tier is missing. See
 * `docs/sprint-3-4-gaps/03-conditional-access.md`.
 */
export interface CaEvaluation {
  /**
   * The set of capability action tiers that were satisfied by this token.
   *
   * A tier is included when every `acrs` value declared for that tier in
   * the provider's `requiredAcrsByTier` configuration was present in the
   * token's `acrs` claim, plus any additional provider-specific checks for
   * that tier passed.
   *
   * For example, the current Azure AD evaluation only applies
   * `maxSignInAgeSeconds` to the `admin` and `delete` tiers; `read` and
   * `write` may remain satisfied even when the sign-in is older. Optional
   * user/session risk or freshness checks are provider-specific and may be
   * omitted entirely.
   *
   * Providers without CA configuration MUST populate this with all four
   * tiers so unconfigured deployments behave exactly as before.
   */
  satisfiedTiers: CaActionTier[];
  /**
   * The acrs values that the provider's configuration required, keyed by
   * tier. Recorded so the audit log can surface exactly what policy was
   * checked when an issuance is denied.
   */
  requiredAcrsByTier?: Partial<Record<CaActionTier, string[]>>;
  /**
   * The acrs values present in the validated token. Recorded for audit.
   * Empty array when the token had no `acrs`/`acr` claim.
   */
  presentedAcrs: string[];
}

/**
 * Source of a directory role surfaced by an identity provider that
 * supports just-in-time elevation (today, Azure AD via Privileged
 * Identity Management). See `docs/sprint-3-4-gaps/04-pim-activation.md`.
 *
 *   * `permanent` — assigned directly or via a group; the user holds the
 *     role indefinitely.
 *   * `pim-active` — currently activated PIM assignment, valid until
 *     `endDateTime` (ISO-8601). The issuer caps any granted capability's
 *     TTL to the remaining window when {@link AzureADConfig.pim.capTtlToActivation}
 *     is true.
 *   * `pim-eligible-not-active` — the user is eligible for the role but
 *     has not activated it. Roles in this state are stripped before
 *     capability mapping when {@link AzureADConfig.pim.enforceActivation}
 *     is true.
 */
export type RoleSource =
  | { kind: 'permanent' }
  | { kind: 'pim-active'; assignmentId: string; endDateTime: string }
  | { kind: 'pim-eligible-not-active' };

/**
 * A role with metadata about how the user came to hold it. Identity
 * providers that distinguish elevation state (Azure AD with PIM) populate
 * {@link UserContext.roleSources}; providers that don't may omit it and
 * the issuer treats every role as `permanent` for back-compat.
 */
export interface ResolvedRole {
  /** Display name of the role (matches entries in `UserContext.roles`). */
  name: string;
  /** How the user holds this role — see {@link RoleSource}. */
  source: RoleSource;
}

/**
 * User context extracted from authentication
 */
export interface UserContext {
  /** User unique identifier */
  userId: string;
  /** User email or principal name */
  email?: string;
  /** User's roles */
  roles: string[];
  /** Tenant or organization ID */
  tenantId?: string;
  /** Additional claims from the identity provider */
  claims?: Record<string, unknown>;
  /**
   * Optional Conditional Access evaluation result. When populated, the
   * issuer compares each requested capability's action tier against
   * {@link CaEvaluation.satisfiedTiers} and denies with
   * `CONDITIONAL_ACCESS_REQUIRED` when a required tier is missing.
   * Providers that do not implement CA leave this undefined and the
   * issuer skips the check (back-compat).
   */
  caEvaluation?: CaEvaluation;
  /**
   * Optional per-role source metadata. When populated, the issuer
   * strips `pim-eligible-not-active` roles before mapping (when
   * configured) and caps capability TTL to the smallest remaining
   * `pim-active` window. Providers that do not implement PIM leave this
   * undefined; every role is then treated as `permanent`.
   */
  roleSources?: ResolvedRole[];
}

/**
 * Token signing service interface
 */
export interface TokenSigner {
  /**
   * Sign a capability token payload
   */
  sign(payload: CapabilityTokenPayload): Promise<string>;

  /**
   * Get the public key for verification
   */
  getPublicKey(): Promise<string>;

  /**
   * Get the key ID used for signing
   */
  getKeyId(): Promise<string>;

  /**
   * Get the signing algorithm (e.g. 'RS256', 'ES256').
   * Optional: implementations backed by `SigningAdapter` always provide this;
   * custom implementations may omit it, in which case callers fall back to
   * inferring the algorithm from the key type.
   */
  getAlgorithm?(): string;
}

/**
 * Token verification service interface
 */
export interface TokenVerifier {
  /**
   * Verify and decode a capability token
   */
  verify(token: string): Promise<CapabilityTokenPayload>;

  /**
   * Check if a token is revoked
   */
  isRevoked(tokenId: string): Promise<boolean>;
}

/**
 * Configuration for Azure Key Vault integration
 */
export interface AzureKeyVaultConfig {
  /** Key Vault URL (e.g., https://my-vault.vault.azure.net/) */
  vaultUrl: string;
  /** Key name in the vault */
  keyName: string;
  /** Key version (optional, uses latest if not specified) */
  keyVersion?: string;
  /** Credential type to use */
  credentialType?: 'default' | 'managed-identity' | 'client-secret';
  /** Client ID for service principal authentication */
  clientId?: string;
  /** Client secret for service principal authentication */
  clientSecret?: string;
  /** Tenant ID for Azure AD */
  tenantId?: string;
}

/**
 * Configuration for AWS KMS integration
 */
export interface AWSKMSConfig {
  /** AWS region (e.g., us-east-1) */
  region: string;
  /** KMS key ID or ARN */
  keyId: string;
  /** AWS access key ID (optional, uses default credentials if not provided) */
  accessKeyId?: string;
  /** AWS secret access key (optional, uses default credentials if not provided) */
  secretAccessKey?: string;
  /** AWS session token (optional, for temporary credentials) */
  sessionToken?: string;
}

/**
 * Configuration for GCP Cloud KMS integration
 */
export interface GCPCloudKMSConfig {
  /** GCP project ID */
  projectId: string;
  /** Cloud KMS location (e.g., us-central1, global) */
  locationId: string;
  /** Key ring name */
  keyRingId: string;
  /** Crypto key name */
  cryptoKeyId: string;
  /** Crypto key version (optional, uses primary version if not specified) */
  cryptoKeyVersion?: string;
  /** Path to service account key file (optional, uses default credentials if not provided) */
  keyFilePath?: string;
}

/**
 * Configuration for Azure AD integration
 */
export interface AzureADConfig {
  /** Azure AD tenant ID */
  tenantId: string;
  /** Application (client) ID */
  clientId: string;
  /** Client secret (for confidential clients) */
  clientSecret?: string;
  /** Authority URL (defaults to https://login.microsoftonline.com/{tenantId}) */
  authority?: string;
  /** Scopes to request */
  scopes?: string[];
  /**
   * Conditional Access policy enforcement configuration.
   *
   * When omitted, the provider populates `caEvaluation.satisfiedTiers`
   * with all four tiers and the issuer behaves exactly as before
   * (back-compat). When supplied, `validateToken()` requires every
   * `acrs` value listed for a tier to be present in the token's `acrs`
   * claim before that tier is included in `satisfiedTiers`. The issuer
   * service then denies issuance with `CONDITIONAL_ACCESS_REQUIRED`
   * when a requested capability's action tier is not satisfied.
   *
   * See `docs/sprint-3-4-gaps/03-conditional-access.md`.
   */
  conditionalAccess?: {
    /**
     * Per-tier required `acrs` references. A tier is considered
     * satisfied iff every listed value is present in the token's
     * `acrs` claim. Omitted tiers are unconditionally satisfied.
     */
    requiredAcrsByTier?: Partial<Record<CaActionTier, string[]>>;
    /**
     * When true, after claim-based checks pass, call Microsoft Graph
     * to confirm the user/session has not been flagged as risky.
     * Defaults to false. Requires `IdentityRiskyUser.Read.All`.
     */
    requireFreshGraphCheck?: boolean;
    /**
     * Maximum age (seconds) of the underlying sign-in (`auth_time`
     * claim) beyond which the `admin` and `delete` tiers are rejected
     * regardless of `acrs`. Defaults to 3600 (1 hour).
     */
    maxSignInAgeSeconds?: number;
  };
  /**
   * Privileged Identity Management (PIM) activation enforcement.
   *
   * When omitted, every role returned by Graph is treated as permanent
   * (back-compat with deployments that do not use PIM). When supplied,
   * `getUserRoles()` queries `roleAssignmentScheduleInstances` and
   * `roleEligibilityScheduleInstances` and returns
   * {@link ResolvedRole}s alongside the bare role names so the issuer
   * can strip eligible-but-not-active roles and cap capability TTL to
   * the remaining activation window.
   *
   * See `docs/sprint-3-4-gaps/04-pim-activation.md`.
   */
  pim?: {
    /**
     * When true, roles in `pim-eligible-not-active` state are stripped
     * before being mapped to capabilities. Defaults to true when this
     * block is present.
     */
    enforceActivation?: boolean;
    /**
     * Operator-declared list of role display names that MUST be
     * PIM-activated (defense in depth: deny even if the role somehow
     * appears as permanent). Example:
     * `["Global Administrator", "Privileged Role Administrator"]`.
     */
    pimRequiredRoles?: string[];
    /**
     * When true, capability TTL is capped at the smallest remaining
     * `pim-active` window across all roles that contributed to the
     * granted capabilities (with a 30-second clock-skew safety margin).
     * Defaults to true.
     */
    capTtlToActivation?: boolean;
  };
}

/**
 * Configuration for Amazon Cognito / AWS IAM Identity Center integration.
 *
 * Used to validate OIDC ID/access tokens issued by an Amazon Cognito user pool
 * (or, equivalently, by an AWS IAM Identity Center OIDC application). The
 * provider validates the token's signature against the user-pool JWKS and
 * extracts standard OIDC claims plus AWS-specific group claims
 * (`cognito:groups`).
 *
 * Two configuration shapes are supported:
 *   * **Cognito user pool:** supply `region` + `userPoolId` (+ `clientId`).
 *     The default issuer URL is derived as
 *     `https://cognito-idp.{region}.amazonaws.com/{userPoolId}`.
 *   * **AWS IAM Identity Center (or any other OIDC source):** supply
 *     `issuer` (and optionally `jwksUri`) + `clientId`. `region` and
 *     `userPoolId` are not required when an explicit `issuer` is provided.
 *
 * At least one of (`region` + `userPoolId`) or `issuer` MUST be supplied;
 * the {@link AWSCognitoIdentityProvider} constructor enforces this at
 * runtime.
 */
export interface AWSCognitoConfig {
  /**
   * AWS region the user pool is hosted in (e.g., us-east-1). Required when
   * configuring a Cognito user pool; omit (along with `userPoolId`) when
   * configuring IAM Identity Center via an explicit `issuer`.
   */
  region?: string;
  /**
   * Cognito user pool ID (e.g., us-east-1_aBcDeFgHi). Required when
   * configuring a Cognito user pool; omit (along with `region`) when
   * configuring IAM Identity Center via an explicit `issuer`.
   */
  userPoolId?: string;
  /** App client ID — used as the expected `aud` (or `client_id`) claim */
  clientId: string;
  /**
   * Optional issuer URL override. Defaults to
   * `https://cognito-idp.{region}.amazonaws.com/{userPoolId}` for Cognito user
   * pools. Set this when integrating with IAM Identity Center, which uses a
   * different issuer URL of the form
   * `https://identitycenter.amazonaws.com/ssoins-{instanceId}`.
   */
  issuer?: string;
  /**
   * Optional explicit JWKS URI. Defaults to `{issuer}/.well-known/jwks.json`
   * for both Cognito and IAM Identity Center.
   */
  jwksUri?: string;
  /** Token type to expect (`id` or `access`). Defaults to `id`. */
  tokenUse?: 'id' | 'access';
}

/**
 * Configuration for Google Cloud identity integration.
 *
 * Used to validate Google-issued OIDC ID tokens from Cloud Identity, Identity
 * Platform, Workforce Identity Federation, or Workload Identity Federation.
 * All of these issue tokens signed by Google's published JWKS at
 * `https://www.googleapis.com/oauth2/v3/certs` (or, for federated tokens, an
 * issuer-specific JWKS URL). The provider validates signature, issuer, and
 * audience claims, then maps Google identity claims into the common
 * `UserContext`.
 */
export interface GCPIdentityConfig {
  /**
   * Expected `aud` claim. For OIDC clients this is the OAuth 2.0 client ID;
   * for Workload/Workforce Identity Federation this is the configured
   * audience URL.
   */
  audience: string;
  /**
   * Expected `iss` claim. Defaults to `https://accounts.google.com`. Override
   * for Identity Platform tenants
   * (`https://securetoken.google.com/{projectId}`), Workforce Identity
   * Federation pools, or Workload Identity Federation pools.
   */
  issuer?: string;
  /**
   * Optional JWKS URI override. Defaults to
   * `https://www.googleapis.com/oauth2/v3/certs` for Google account tokens.
   * Identity Platform projects expose JWKS at
   * `https://www.googleapis.com/service_accounts/v1/metadata/x509/securetoken@system.gserviceaccount.com`,
   * and federated providers expose a per-pool JWKS URL — set this field
   * accordingly.
   */
  jwksUri?: string;
  /**
   * GCP project ID. Required only when using Identity Platform tenants so the
   * provider can derive the default issuer URL.
   */
  projectId?: string;
  /**
   * Custom claim name to read role/group memberships from. Defaults to
   * `groups` (the conventional Cloud Identity / Workforce IF claim). Set to
   * `roles` or any custom claim name when integrating with Identity Platform
   * custom claims.
   */
  rolesClaim?: string;
}

/**
 * Service configuration
 */
export interface ServiceConfig {
  /** Service name */
  name: string;
  /** Service port */
  port: number;
  /** Environment (development, staging, production) */
  environment: 'development' | 'staging' | 'production';
  /** Signing provider type */
  signingProvider?: 'azure-keyvault' | 'aws-kms' | 'gcp-cloudkms';
  /** Azure Key Vault configuration */
  keyVault?: AzureKeyVaultConfig;
  /** AWS KMS configuration */
  awsKMS?: AWSKMSConfig;
  /** GCP Cloud KMS configuration */
  gcpCloudKMS?: GCPCloudKMSConfig;
  /** Identity provider type */
  identityProvider?: 'azure-ad' | 'aws-cognito' | 'gcp-identity' | 'did';
  /** Azure AD configuration */
  azureAD?: AzureADConfig;
  /** AWS Cognito / IAM Identity Center configuration */
  awsCognito?: AWSCognitoConfig;
  /** Google Cloud identity configuration */
  gcpIdentity?: GCPIdentityConfig;
  /** Issuer identifier (DID or domain URL) */
  issuerDid?: string;
  /** Default token TTL in seconds */
  defaultTokenTTL?: number;
  /** Enable detailed logging */
  enableDetailedLogging?: boolean;
  /** Enable cryptographic audit evidence */
  enableCryptographicAudit?: boolean;
  /**
   * Decisions whose audit evidence is cryptographically signed (I-8).
   *
   * When omitted, the legacy `enableCryptographicAudit` boolean is the
   * single source of truth: `true` ⇒ both `allow` and `deny` are signed,
   * `false` ⇒ neither. When provided, this set is authoritative and
   * the legacy boolean is ignored. An empty set disables signing.
   *
   * Lets operators express "sign critical events but not every event"
   * (e.g. `['deny']` to keep an evidentiary record of refusals without
   * paying the per-allow signing cost).
   */
  signedAuditDecisions?: Array<'allow' | 'deny'>;
  /** Policy version for audit evidence */
  policyVersion?: string;
}

/**
 * Kill-switch configuration
 */
export interface KillSwitchConfig {
  /** Global kill switch - if true, all agent requests are rejected */
  globalKillSwitch: boolean;
  /** Set of session IDs that have been killed */
  killedSessions: Set<string>;
  /** Set of agent IDs that have been killed */
  killedAgents: Set<string>;
}

/**
 * Kill-switch manager interface
 */
export interface KillSwitchManager {
  /** Check if the global kill switch is active */
  isGlobalKillActive(): boolean;

  /** Activate the global kill switch */
  activateGlobalKill(): void;

  /** Deactivate the global kill switch */
  deactivateGlobalKill(): void;

  /** Kill a specific session */
  killSession(sessionId: string): void;

  /** Kill a specific agent */
  killAgent(agentId: string): void;

  /** Check if a session is killed */
  isSessionKilled(sessionId: string): boolean;

  /** Check if an agent is killed */
  isAgentKilled(agentId: string): boolean;

  /** Check if a request should be blocked (session, agent, or global) */
  shouldBlock(sessionId?: string, agentId?: string): boolean;

  /** Revive a killed session */
  reviveSession(sessionId: string): void;

  /** Revive a killed agent */
  reviveAgent(agentId: string): void;

  /** Get the current state of all kill switches */
  getStatus(): {
    globalKill: boolean;
    killedSessionCount: number;
    killedAgentCount: number;
  };

  /** Reset all kill switches */
  resetAll(): void;

  /**
   * Optional teardown for implementations that hold external resources
   * (network connections, timers, etc.).  In-process implementations
   * may omit this entirely.  Idempotent.
   */
  close?(): Promise<void>;
}

