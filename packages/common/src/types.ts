/**
 * Core types and interfaces for capability-based agent governance
 */

/**
 * Decentralized Identifier (DID) string
 * Examples: did:web:example.com, did:ion:abc123, did:key:xyz
 */
export type DID = string;

/**
 * Resource identifier for capability constraints
 */
export type ResourceId = string;

/**
 * Action types that can be performed on resources
 */
export type Action = 'read' | 'write' | 'execute' | 'delete' | 'admin';

/**
 * Capability constraint defining what actions are allowed on which resources
 */
export interface CapabilityConstraint {
  /** Resource identifier (e.g., "api://service-name/endpoint", "storage://container/blob") */
  resource: ResourceId;
  /** List of allowed actions */
  actions: Action[];
  /** Optional additional constraints (e.g., rate limits, data filters) */
  conditions?: Record<string, unknown>;
}

/**
 * Capability token payload following JWT and W3C VC patterns
 */
export interface CapabilityTokenPayload {
  /** Issuer DID or domain (JWT 'iss' claim) */
  iss: string;
  /** Subject - agent DID or identifier (JWT 'sub' claim) */
  sub: string;
  /** Audience - intended recipient service (JWT 'aud' claim) */
  aud: string;
  /** Issued at timestamp (JWT 'iat' claim) */
  iat: number;
  /** Expiration timestamp (JWT 'exp' claim) */
  exp: number;
  /** JWT ID - unique token identifier (JWT 'jti' claim) */
  jti: string;
  /** Capability constraints defining allowed actions */
  capabilities: CapabilityConstraint[];
  /** Optional: parent capability token ID for delegation chains */
  parentCapabilityId?: string;
  /** Optional: user context who authorized this capability */
  authorizedBy?: {
    userId: string;
    roles: string[];
    tenantId?: string;
  };
  /** Optional: W3C VC specific fields */
  vc?: {
    '@context': string[];
    type: string[];
    credentialSubject: Record<string, unknown>;
  };
}

/**
 * Agent capability manifest - declarative specification of agent capabilities
 */
export interface AgentCapabilityManifest {
  /** Agent identifier */
  agentId: string;
  /** Human-readable agent name */
  name: string;
  /** Agent version */
  version: string;
  /** Required capabilities for this agent */
  requiredCapabilities: CapabilityConstraint[];
  /** Optional capabilities that enhance functionality */
  optionalCapabilities?: CapabilityConstraint[];
  /** Metadata about the agent */
  metadata?: {
    description?: string;
    owner?: string;
    tags?: string[];
  };
}

/**
 * Audit log entry for capability operations
 */
export interface AuditLogEntry {
  /** Unique log entry ID */
  id: string;
  /** Timestamp of the event */
  timestamp: Date;
  /** Event type */
  eventType: 'issuance' | 'validation' | 'denial' | 'revocation' | 'renewal';
  /** Agent or session identifier */
  agentId: string;
  /** User who initiated or authorized the action */
  userId?: string;
  /** Capability token ID involved */
  capabilityId?: string;
  /** Action that was attempted or performed */
  action?: string;
  /** Resource that was accessed or targeted */
  resource?: string;
  /** Decision outcome (allow/deny) */
  decision: 'allow' | 'deny';
  /** Reason for the decision */
  reason?: string;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Cryptographic audit evidence for privileged operations
 * Following the pattern from Azure security reference:
 * "Logs help you debug. Evidence helps you prove"
 */
export interface AuditEvidence {
  /** Unique evidence ID */
  id: string;
  /** Session identifier */
  sessionId: string;
  /** User who initiated the action */
  userId: string;
  /** Hash of the prompt/input that triggered the action */
  promptHash: string;
  /** Hash of any documents or context provided */
  documentsHash?: string;
  /** Tool or action being executed */
  tool: string;
  /** Hash of the tool arguments */
  argsHash: string;
  /** Cryptographic nonce for uniqueness */
  nonce: string;
  /** Timestamp in ISO format */
  ts: string;
  /** Policy version that authorized this action */
  policyVersion: string;
  /** Agent identifier */
  agentId: string;
  /** Resource being accessed */
  resource: string;
  /** Action being performed */
  action: string;
  /** Capability token ID used */
  capabilityId: string;
  /** Decision outcome */
  decision: 'allow' | 'deny';
}

/**
 * Signed audit evidence with cryptographic signature
 */
export interface SignedAuditEvidence extends AuditEvidence {
  /** Digital signature of the evidence */
  signature: string;
  /** Key ID used for signing */
  keyId: string;
  /** Signing algorithm */
  algorithm: string;
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
 * Capability issuance request
 */
export interface IssueCapabilityRequest {
  /** User authentication token (OIDC token from Azure AD) */
  authToken: string;
  /** Agent identifier requesting capabilities */
  agentId: string;
  /** Optional: specific capabilities requested (will be validated against user roles) */
  requestedCapabilities?: CapabilityConstraint[];
  /** Optional: capability manifest for the agent */
  manifest?: AgentCapabilityManifest;
}

/**
 * Capability issuance response
 */
export interface IssueCapabilityResponse {
  /** Signed capability token (JWT) */
  token: string;
  /** Token expiration timestamp */
  expiresAt: number;
  /** Token unique identifier */
  tokenId: string;
  /** Capabilities granted */
  capabilities: CapabilityConstraint[];
}

/**
 * Action validation request
 */
export interface ValidateActionRequest {
  /** Capability token */
  token: string;
  /** Action being attempted */
  action: Action;
  /** Resource being accessed */
  resource: ResourceId;
  /** Optional: additional context for validation */
  context?: Record<string, unknown>;
}

/**
 * Action validation response
 */
export interface ValidateActionResponse {
  /** Whether the action is allowed */
  allowed: boolean;
  /** Reason for the decision */
  reason?: string;
  /** Matched capability constraint if allowed */
  matchedCapability?: CapabilityConstraint;
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
}

/**
 * Configuration for Amazon Cognito / AWS IAM Identity Center integration.
 *
 * Used to validate OIDC ID/access tokens issued by an Amazon Cognito user pool
 * (or, equivalently, by an AWS IAM Identity Center OIDC application). The
 * provider validates the token's signature against the user-pool JWKS and
 * extracts standard OIDC claims plus AWS-specific group claims
 * (`cognito:groups`).
 */
export interface AWSCognitoConfig {
  /** AWS region the user pool is hosted in (e.g., us-east-1) */
  region: string;
  /** Cognito user pool ID (e.g., us-east-1_aBcDeFgHi) */
  userPoolId: string;
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
}
