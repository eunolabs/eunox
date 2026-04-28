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
 * Action types that can be performed on resources.
 *
 * Originally a fixed five-value union. Widened to `string` so capability
 * tokens can express resource-specific verbs (e.g. `db:select`,
 * `s3:putObject`, `kafka:publish`) when callers want finer-grained
 * authorization than the legacy categories provide. The original five
 * values remain available as named constants in {@link LEGACY_ACTIONS}
 * and continue to be the recognized values produced by the default
 * role mapping.
 *
 * Use {@link isLegacyAction} to test whether an action string belongs
 * to the legacy set.
 */
export type Action = string;

/**
 * The original five-action set, preserved as a named tuple so existing
 * role mappings and tests can continue to refer to them by symbol.
 */
export const LEGACY_ACTIONS = ['read', 'write', 'execute', 'delete', 'admin'] as const;

/** Element type of {@link LEGACY_ACTIONS}. */
export type LegacyAction = (typeof LEGACY_ACTIONS)[number];

/** True when `action` is one of the five legacy generic verbs. */
export function isLegacyAction(action: string): action is LegacyAction {
  return (LEGACY_ACTIONS as readonly string[]).includes(action);
}

/**
 * Current capability token schema version. Issuers populate the
 * `schemaVersion` field with this value; gateways validate it at enforcement
 * time and reject unknown versions (fail-closed on schema evolution).
 *
 * Version history:
 *  - "1.0": Initial typed-condition schema (April 2026).
 */
export const CAPABILITY_TOKEN_SCHEMA_VERSION = '1.0' as const;

/**
 * Set of schema versions this implementation can process. Tokens carrying
 * other versions are rejected at verification time (fail-closed).
 */
export const SUPPORTED_SCHEMA_VERSIONS: ReadonlySet<string> = new Set([
  CAPABILITY_TOKEN_SCHEMA_VERSION,
]);

/**
 * Discriminated union of capability conditions enforceable by the
 * tool-gateway and validated at mint time by the capability issuer.
 *
 * Conditions narrow what an otherwise-permitted (action, resource) match
 * is allowed to do. The `type` discriminator selects the handler in the
 * shared {@link ConditionRegistry}. Unknown types are rejected at both
 * issuance and enforcement (deny-by-default), so a typo cannot silently
 * round-trip through signing into an unconstrained token.
 *
 * The 8 built-in types correspond to the constraint families called out
 * in `docs/capability-model.md`. Extension via {@link CustomCondition}
 * is supported but requires a registered handler — there is no
 * "unrecognized = allow" path.
 */
export type CapabilityCondition =
  | TimeWindowCondition
  | IpRangeCondition
  | AllowedOperationsCondition
  | AllowedExtensionsCondition
  | AllowedTablesCondition
  | MaxCallsCondition
  | RecipientDomainCondition
  | RedactFieldsCondition
  | CustomCondition;

/**
 * Restrict use of the capability to a specific time window. Both
 * boundaries are optional (an open-ended window in either direction is
 * permitted) but at least one must be provided. Timestamps are RFC 3339
 * / ISO 8601 strings interpreted as absolute UTC instants.
 */
export interface TimeWindowCondition {
  type: 'timeWindow';
  /** Earliest ISO 8601 timestamp at which the capability is valid. */
  notBefore?: string;
  /** Latest ISO 8601 timestamp at which the capability is valid. */
  notAfter?: string;
}

/** Restrict the source IP of the request to one of the listed CIDRs. */
export interface IpRangeCondition {
  type: 'ipRange';
  /** Non-empty list of CIDR ranges (IPv4 or IPv6). */
  cidrs: string[];
}

/**
 * For generic actions (e.g. `execute`), narrow the operation actually
 * allowed (e.g. `SELECT` but not `INSERT`). Matched case-insensitively
 * against the operation string the gateway pulls from request context.
 */
export interface AllowedOperationsCondition {
  type: 'allowedOperations';
  /** Non-empty allowlist of operation names. */
  operations: string[];
}

/**
 * Restrict file paths to the named extensions. Comparison is
 * case-insensitive and the extension may include or omit the leading dot.
 */
export interface AllowedExtensionsCondition {
  type: 'allowedExtensions';
  /** Non-empty list of file extensions, e.g. `['.txt', 'json']`. */
  extensions: string[];
}

/**
 * Restrict database access to specific tables, optionally further
 * narrowing the columns each table may expose.
 */
export interface AllowedTablesCondition {
  type: 'allowedTables';
  /** Non-empty list of permitted table names. */
  tables: string[];
  /**
   * Optional per-table column allowlist. Tables present in `tables` but
   * absent from `columns` impose no per-column restriction. A column
   * value of `'*'` is shorthand for "all columns of this table".
   */
  columns?: Record<string, string[]>;
}

/**
 * Cap the number of calls authorized by this capability inside a
 * sliding window. Enforced via the `CallCounterStore` plugged into the
 * gateway (in-memory by default, Redis-backed in production).
 */
export interface MaxCallsCondition {
  type: 'maxCalls';
  /** Maximum number of permitted calls in the window (>= 1). */
  count: number;
  /** Length of the sliding window in seconds (>= 1). */
  windowSeconds: number;
}

/**
 * Restrict outbound message recipients (typically email) to the listed
 * domains. Domain comparison is case-insensitive; `recipient` is parsed
 * as a `local@domain` address.
 */
export interface RecipientDomainCondition {
  type: 'recipientDomain';
  /** Non-empty list of permitted recipient domains. */
  domains: string[];
}

/**
 * Declare that the named fields must be redacted from the response
 * before it leaves the gateway. The condition is satisfied at
 * enforcement time (the gateway records the obligation in the audit log
 * for downstream redaction); validation here confirms the field list is
 * well-formed.
 */
export interface RedactFieldsCondition {
  type: 'redactFields';
  /** Non-empty list of dotted field paths to redact. */
  fields: string[];
}

/**
 * Escape hatch for vendor-specific conditions. The named handler MUST
 * be registered in the {@link ConditionRegistry}; unknown `name`s are
 * denied at both issuance and enforcement.
 */
export interface CustomCondition {
  type: 'custom';
  name: string;
  config: unknown;
}

/**
 * Allowlist-based schema describing the shape of arguments a tool/proxy call
 * may carry under a given capability.
 *
 * Intentionally a small, well-defined subset of JSON Schema:
 *  - `additionalProperties` defaults to **false** for objects (strict allowlist)
 *  - all string/number/array constraints are bounds-only — no regex denylists
 *  - schemas are evaluated by {@link validateArguments} inside the tool
 *    gateway's enforcement engine, so capabilities can constrain *what* a tool
 *    is invoked with, not just whether it can be invoked.
 *
 * Set `strict: true` to enable maximum-strictness mode:
 *  - ALL object values must explicitly list every allowed property in `properties`
 *    (object-shape constraints are no longer required to "declare" the shape first)
 *  - `strict` is propagated automatically to all nested property schemas and
 *    `items` schemas so the whole schema tree is evaluated with the same stance
 *
 * NOTE: This is NOT a substitute for parameterized queries / safe APIs in the
 * downstream backend. It enforces *agent-visible* contracts (what an agent
 * may send), so an attacker-controlled prompt cannot smuggle arbitrary fields
 * through a capability that only authorizes a narrow operation.
 */
export interface ArgumentSchema {
  /** JSON-Schema-style type. Multiple types allowed via array. */
  type?:
    | 'object'
    | 'string'
    | 'number'
    | 'integer'
    | 'boolean'
    | 'array'
    | 'null'
    | Array<'object' | 'string' | 'number' | 'integer' | 'boolean' | 'array' | 'null'>;
  /** For object types: per-property schemas. */
  properties?: Record<string, ArgumentSchema>;
  /** For object types: required property names. */
  required?: string[];
  /**
   * For object types: whether properties not listed in `properties` are
   * permitted. Defaults to `false` so capabilities are an explicit allowlist.
   */
  additionalProperties?: boolean;
  /** Restrict to a specific set of literal values. */
  enum?: ReadonlyArray<unknown>;
  /** For string types: ECMAScript regex source the value must fully match. */
  pattern?: string;
  /** For string types: minimum length. */
  minLength?: number;
  /** For string types: maximum length. */
  maxLength?: number;
  /** For numeric types: minimum value (inclusive). */
  minimum?: number;
  /** For numeric types: maximum value (inclusive). */
  maximum?: number;
  /** For array types: schema for each element. */
  items?: ArgumentSchema;
  /** For array types: maximum number of items. */
  maxItems?: number;
  /** For array types: minimum number of items. */
  minItems?: number;
  /** Optional human-readable description of the constraint (for audit). */
  description?: string;
  /**
   * Enable strict validation mode. When `true`:
   *  - Every object value is treated as if it declares its shape, so
   *    `additionalProperties: false` is enforced on ALL plain-object values
   *    regardless of whether `properties`, `required`, or `additionalProperties`
   *    are explicitly present in the schema.
   *  - Strict mode is propagated automatically to all nested `properties` schemas
   *    and to the `items` schema for array types, so the entire schema tree is
   *    validated with the same strictness.
   *
   * Defaults to `false` to preserve backward-compatibility. New capabilities
   * that want the strongest argument-allowlisting guarantees should set this
   * to `true`.
   */
  strict?: boolean;
}

/**
 * Capability constraint defining what actions are allowed on which resources
 */
export interface CapabilityConstraint {
  /** Resource identifier (e.g., "api://service-name/endpoint", "storage://container/blob") */
  resource: ResourceId;
  /** List of allowed actions */
  actions: Action[];
  /**
   * Optional allowlist schema describing the arguments / request body that
   * may accompany a call under this capability. When present, the tool
   * gateway's enforcement engine will validate the actual arguments against
   * this schema in addition to the (action, resource) check, and reject any
   * call whose arguments do not conform.
   */
  argumentSchema?: ArgumentSchema;
  /**
   * Optional list of additional constraints (rate limits, time
   * windows, data filters, ...) that further narrow what this
   * capability authorizes. Conditions are typed via the
   * {@link CapabilityCondition} discriminated union and enforced by
   * the shared {@link ConditionRegistry}: every entry MUST evaluate
   * to "allow" for the request to be permitted, and unknown types
   * are denied by default.
   */
  conditions?: CapabilityCondition[];
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
  /**
   * Schema version of this capability token. Enables forward/backward
   * compatibility during schema evolution. Current version is "1.0".
   *
   * - "1.0": Current schema with typed conditions
   * - Future versions: May introduce new fields or change semantics
   *
   * This field is required. Gateways MUST reject tokens with missing,
   * malformed, or unrecognized schema versions (fail-closed). The `kid`
   * (key ID) in the JWT header provides an orthogonal "rotate all tokens
   * signed with key X" mechanism.
   */
  schemaVersion: string;
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
    /**
     * Credential identifier (W3C VC Data Model § 4.2 — single URI).
     * Set by the issuer to `urn:uuid:<jti>` so a VC-only verifier sees
     * the same authoritative credential id as a JWT-only verifier.
     */
    id?: string;
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
  /**
   * Optional: explicit user consent record authorizing the issuance. When
   * present the issuer validates that the consent was granted by the same
   * user that owns the {@link authToken}, was granted to the same {@link agentId}
   * being requested, has not expired, and covers every requested capability.
   *
   * Issuer deployments can require this for every issuance via the
   * `requireConsent` constructor option (env: `REQUIRE_USER_CONSENT=true`),
   * and it is always required when the requested capabilities include
   * sensitive actions (`write`, `delete`, `admin`).
   */
  consent?: UserConsent;
}

/**
 * Explicit, auditable user-consent record produced by the consent UI.
 *
 * Adding consent at issuance time prevents an agent from silently obtaining
 * capabilities that fall within the user's roles but were never explicitly
 * approved for that agent.
 */
export interface UserConsent {
  /** Subject of the user authentication token (must match `authToken`'s userId). */
  userId: string;
  /** Agent the user consented to grant capabilities to (must match `agentId`). */
  agentId: string;
  /**
   * The capabilities the user explicitly approved. Resource patterns may be
   * wildcards (e.g. `storage://sales-data/**`); the issuer uses
   * `matchesResource()` to check that each requested capability is covered.
   */
  grantedCapabilities: CapabilityConstraint[];
  /** Unix-seconds timestamp when the user granted consent. */
  grantedAt: number;
  /** Optional unix-seconds expiry for the consent record itself. */
  expiresAt?: number;
  /** Optional consent identifier for audit cross-reference (e.g. consent UI receipt id). */
  consentId?: string;
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
  /**
   * Optional short-lived cloud storage credentials minted alongside the VC
   * for any capability whose resource matches the canonical
   * `storage://{cloud}/{bucket}/{key-or-prefix}` form.
   *
   * Each entry is scoped to exactly one capability's `resource` and is a
   * **subset** of that capability's actions. The credential's lifetime is
   * `min(capabilityTtl, configured storage-grant max TTL)` and the cloud's
   * own control plane enforces the scope independently of our gateway
   * (defense in depth). Field is undefined when no storage capabilities
   * are present or when the storage-grant pipeline is disabled.
   *
   * See `docs/sprint-3-4-gaps/07-storage-grants.md`.
   */
  storageGrants?: StorageGrant[];
  /**
   * Optional short-lived database credentials minted alongside the VC for
   * any capability whose resource matches the canonical
   * `db://{cloud}/{instance}/{database}/{schema-or-table}.{action}` form.
   *
   * The credential carries an IAM-bound bearer token (Azure AD JWT for
   * Azure SQL, RDS IAM auth token for AWS, OAuth2 token for Cloud SQL)
   * plus connection hints. The database's IAM, not our gateway, enforces
   * scope. Field is undefined when no database capabilities are present
   * or when the DB-token pipeline is disabled.
   *
   * See `docs/sprint-3-4-gaps/08-db-token-issuance.md`.
   */
  dbCredentials?: DbCredential[];
}

/** Cloud storage providers that can mint short-lived data-plane credentials. */
export type StorageProvider = 'azure-blob' | 's3' | 'gcs';

/**
 * A short-lived, narrowly-scoped cloud storage credential issued alongside
 * a capability VC. The shape is a discriminated union over the cloud
 * provider — exactly one of the provider-specific credential objects is
 * populated. Single-object capabilities use the signed-URL variants
 * (`s3Presigned`, `gcsSigned`); wildcard / prefix capabilities use the
 * downscoped session variants (`s3Session`, `gcsDownscoped`); Azure uses
 * `azureSas` for both since SAS tokens scope to either a blob or a
 * container.
 */
export interface StorageGrant {
  /** Which cloud's storage service this credential targets. */
  provider: StorageProvider;
  /** The capability resource this grant is scoped to (echoes the capability). */
  resource: ResourceId;
  /** Subset of the capability's actions this grant authorizes. */
  actions: Action[];
  /** ISO-8601 expiry of the cloud credential itself (≤ capability exp). */
  expiresAt: string;
  /** Azure Blob SAS (user-delegation SAS preferred). */
  azureSas?: { url: string; sasToken: string };
  /** S3 single-object presigned URLs (one per permitted method). */
  s3Presigned?: { method: 'GET' | 'PUT' | 'DELETE'; url: string; headers?: Record<string, string> }[];
  /** S3 prefix-scoped session credentials (STS AssumeRole + scope-down policy). */
  s3Session?: {
    accessKeyId: string;
    secretAccessKey: string;
    sessionToken: string;
    region: string;
    bucket: string;
    prefix?: string;
  };
  /** GCS single-object signed URLs (one per permitted method). */
  gcsSigned?: { method: 'GET' | 'PUT' | 'DELETE'; url: string }[];
  /** GCS prefix-scoped downscoped credentials (Credential Access Boundaries). */
  gcsDownscoped?: {
    accessToken: string;
    bucket: string;
    prefix?: string;
    availabilityCondition?: string;
  };
}

/** Cloud-managed database services with IAM-based short-lived auth. */
export type DbProvider = 'azure-sql' | 'rds-iam' | 'cloudsql-iam';

/**
 * A short-lived database access credential bound to an IAM-mapped DB
 * principal. The bearer token is consumed by the database itself (Azure
 * SQL via AAD, RDS via IAM auth, Cloud SQL via OAuth) — our gateway is
 * not in the data path.
 *
 * The `username` field is the **IAM-mapped DB principal** resolved from
 * issuer-side role-mapping config. It is NEVER taken from agent input;
 * see `docs/sprint-3-4-gaps/08-db-token-issuance.md` § Risks.
 */
export interface DbCredential {
  provider: DbProvider;
  resource: ResourceId;
  actions: Action[];
  /** ISO-8601 expiry reported by the cloud SDK (never recomputed locally). */
  expiresAt: string;
  /** Database server hostname (from operator-side instance config). */
  host: string;
  /** Database server port (from operator-side instance config). */
  port: number;
  /** Database name (from the parsed resource URI). */
  database: string;
  /** IAM-mapped DB principal (resolved from role mapping; never from agent input). */
  username: string;
  /** Bearer token: AAD JWT (Azure SQL), IAM auth token (RDS), OAuth2 token (Cloud SQL). */
  token: string;
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
