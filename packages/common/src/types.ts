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
 * Service configuration
 */
export interface ServiceConfig {
  /** Service name */
  name: string;
  /** Service port */
  port: number;
  /** Environment (development, staging, production) */
  environment: 'development' | 'staging' | 'production';
  /** Azure Key Vault configuration */
  keyVault?: AzureKeyVaultConfig;
  /** Azure AD configuration */
  azureAD?: AzureADConfig;
  /** Issuer identifier (DID or domain URL) */
  issuerDid?: string;
  /** Default token TTL in seconds */
  defaultTokenTTL?: number;
  /** Enable detailed logging */
  enableDetailedLogging?: boolean;
}
