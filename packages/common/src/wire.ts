/**
 * Wire types for `@euno/common`.
 *
 * Types in this module describe the **on-the-wire contract**: JWT payloads,
 * HTTP request/response envelopes, audit-log records and persisted
 * credential payloads. They are pure data shapes, contain no behaviour, and
 * are safe for any consumer (including non-Node clients via type generation)
 * to depend on without pulling in the runtime services that produce them.
 *
 * This module is the canonical home for the types previously co-located
 * with runtime interfaces in `./types.ts`. The legacy `./types` entry
 * still re-exports everything from here for back-compat — see R-8 in
 * `docs/IMPROVEMENTS_AND_REFACTORING.md`.
 *
 * Counterpart: {@link "./runtime"} for in-process interfaces and configs.
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
  | PolicyCondition
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
 * Delegate the authorization decision to a pluggable policy backend
 * (R-4 step 2 / F-10). The `backend` discriminator selects a backend
 * registered via {@link registerPolicyBackend}; backends receive
 * `config` (a backend-specific configuration object, validated at mint
 * time) and `input` (a payload merged with the per-request
 * {@link ConditionContext} at enforcement time). Unknown backend names
 * are rejected at both issuance and enforcement (deny-by-default).
 *
 * The discriminator stays on `type` — the existing discriminated union
 * is the load-bearing contract; adding a separate `kind:` field would
 * be redundant and would silently break readers that already key off
 * `type`.
 */
export interface PolicyCondition {
  type: 'policy';
  /** Name of the registered policy backend (e.g. `'opa-http'`). */
  backend: string;
  /** Backend-specific configuration validated at mint time. */
  config?: unknown;
  /**
   * Backend-specific input payload merged into whatever per-request
   * input the backend builds from the {@link ConditionContext}. Useful
   * for static facts the issuer wants the policy to see (e.g. tenant
   * id, classification level).
   */
  input?: unknown;
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
  /**
   * Optional logical region tag for the issuer instance that minted
   * this token (F-7, multi-region active/active). Surfaced so a
   * downstream gateway / audit consumer can attribute each token to
   * its originating region — important for reconstructing behaviour
   * across a regional failover. Tokens MUST remain accepted by every
   * region's gateway regardless of the value of `region` (no
   * region-pinning enforcement at the gateway by default; operators
   * who want region affinity should layer it on top).
   */
  region?: string;
  /**
   * Optional confirmation claim binding this token to a specific key
   * the holder MUST prove possession of on every use (RFC 7800 / RFC
   * 9449). When present with a `jkt` member, the token is
   * sender-constrained: the gateway requires every request to carry a
   * DPoP proof signed by the key whose JWK SHA-256 thumbprint matches
   * `cnf.jkt`, so that a leaked / replayed bearer token alone is not
   * sufficient for the attacker to call protected endpoints. F-2 in
   * `docs/IMPROVEMENTS_AND_REFACTORING.md`.
   *
   * Tokens minted without `cnf` are rejected by default
   * (`DPOP_REQUIRED` defaults to `true`). Set `DPOP_REQUIRED=false`
   * on the gateway only for back-compat deployments where issuers
   * have not yet been rolled out with DPoP support.
   */
  cnf?: {
    /**
     * Base64url-encoded SHA-256 JWK thumbprint (RFC 7638) of the
     * holder's public key. Computed by the issuer from the
     * `dpopJwk` / `dpopJkt` supplied at issuance time.
     */
    jkt: string;
  };
  /**
   * Optional issuance proofs (multi-issuer trust hardening — addresses the
   * "single-issuer trust root" critical risk).  Carries:
   *
   *   - `cosig[]` — independent co-signatures over the canonical
   *     {@link IssuanceReceipt} derived from this token. A second, separately
   *     keyed authority (an offline policy authority, a different KMS account,
   *     a separately deployed pod identity) signs the receipt so that the
   *     gateway will reject a token whose primary issuer signature is valid
   *     but whose required co-signatures are missing or do not verify.  This
   *     means an attacker who pivots from the issuer pod to KMS `signDigest`
   *     permission still cannot mint usable tokens — they would also need
   *     the cosigner's private key, which is held by a different principal.
   *
   *   - `sct[]` — Signed Certificate Timestamp-style witness records from
   *     one or more transparency logs (analogous to RFC 6962 / Certificate
   *     Transparency for X.509). Each SCT proves that the receipt was
   *     submitted to (and signed by) an external append-only log, giving
   *     the gateway an out-of-band witness independent of the issuer's
   *     signing key. Auditors can reconcile the log against the issuer's
   *     own audit trail to detect silent issuance fraud.
   *
   * Tokens minted without `proofs` continue to verify when the gateway has
   * no proof requirements configured (back-compat). Strict deployments set
   * `REQUIRE_COSIGNATURE_COUNT > 0` and/or `REQUIRE_TRANSPARENCY_LOG_PROOF=true`
   * on the gateway to require these proofs at verification time.
   */
  proofs?: IssuanceProofs;
}

/**
 * Canonical "issuance receipt" — the deterministic, signature-input
 * representation of a capability token used by both the cosignature and
 * transparency-log paths.  Mirrors the load-bearing JWT claims of the
 * primary token (`iss`, `sub`, `aud`, `iat`, `exp`, `jti`) plus a
 * deterministic hash of the granted capability set so that a cosigner /
 * log entry binds to the *exact* set of capabilities the issuer is
 * vouching for.  Any tampering with the capability list invalidates the
 * `capabilitiesHash` and therefore both the cosignature and the SCT.
 *
 * This shape is intentionally free of `vc` / `cnf` / `region` / `proofs`
 * so the canonical bytes are stable across schema evolution: a future
 * version of this codebase that adds optional claims must not invalidate
 * historical cosignatures or SCTs.
 */
export interface IssuanceReceipt {
  /** `iss` claim — issuer DID / domain. */
  iss: string;
  /** `sub` claim — subject (agent) identifier. */
  sub: string;
  /** `aud` claim — gateway audience this token is bound to. */
  aud: string;
  /** `iat` claim — issued-at (unix seconds). */
  iat: number;
  /** `exp` claim — expiry (unix seconds). */
  exp: number;
  /** `jti` claim — unique token id. */
  jti: string;
  /**
   * Base64url-encoded SHA-256 of the canonical JSON serialization of
   * the granted {@link CapabilityConstraint}[] array.
   */
  capabilitiesHash: string;
  /**
   * Optional `cnf.jkt` — DPoP key thumbprint binding the token to a
   * specific holder key (RFC 7800 / RFC 9449). Included in the receipt
   * when the source payload carries `cnf.jkt` so cosignatures and SCTs
   * commit to the holder-binding too. This prevents a "thumbprint
   * substitution" attack where an attacker holding only the primary
   * issuer key takes a legitimately proofed token, rewrites `cnf.jkt`
   * to their own DPoP key, re-signs the JWT, and continues to satisfy
   * the gateway's cosignature / SCT checks.
   *
   * Omitted (rather than set to `null`/`undefined`) for tokens without
   * `cnf` so the canonical JSON of legacy receipts is unchanged
   * — back-compat: deployments that have not enabled DPoP keep
   * producing the previous receipt bytes.
   */
  cnfJkt?: string;
}

/**
 * A single cosignature on an {@link IssuanceReceipt}.  The `sig` is a
 * detached JWS-style signature — base64url-encoded raw signature bytes
 * over the canonical receipt input bytes (see
 * `canonicalReceiptSigningInput` in `@euno/common`).  We do not embed
 * a JWS protected header on the wire because the cosigner's `kid` /
 * `alg` are explicit fields; the verifier reconstructs the input from
 * the token and the receipt deterministically.
 */
export interface Cosignature {
  /** Cosigner key id — looked up against the gateway's cosigner JWKS. */
  kid: string;
  /** JWS signature algorithm (e.g. `EdDSA`, `ES256`). */
  alg: string;
  /** base64url-encoded raw signature bytes over the canonical receipt input. */
  sig: string;
}

/**
 * A Signed Certificate Timestamp-like witness record from a transparency
 * log.  Independent of the issuer's signing key: an attacker who controls
 * the issuer's KMS still cannot forge an SCT without the log's signing
 * key.  Auditors can reconcile the log's append-only entry list against
 * the issuer's audit trail to detect silent issuance fraud.
 */
export interface Sct {
  /** Stable identifier of the transparency log (e.g. `"euno-prod-log-1"`). */
  logId: string;
  /** Signing-key id (matches a key in the log's published JWKS). */
  kid: string;
  /** JWS signature algorithm. */
  alg: string;
  /** Unix milliseconds at which the log appended this entry. */
  timestamp: number;
  /** Optional log entry index (for inclusion-proof retrieval by an auditor). */
  entryIndex?: number;
  /**
   * base64url-encoded raw signature bytes over
   * `canonicalSctSigningInput(logId, timestamp, receiptHash)`.
   */
  sig: string;
}

/**
 * Container claim attached to a {@link CapabilityTokenPayload} when
 * cosignature and/or transparency-log witnessing is configured on the
 * issuer.  Each member is independently optional so an operator can
 * roll the two defenses out incrementally.
 */
export interface IssuanceProofs {
  /** Co-signatures on the issuance receipt. */
  cosig?: Cosignature[];
  /** Signed Certificate Timestamps from one or more transparency logs. */
  sct?: Sct[];
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
    /**
     * Free-form runtime descriptor (e.g. `node:20`, `python:3.12`,
     * `aks:1.29`). Surfaced to AI posture-management inventory feeds
     * so operators can see where each agent runs. Optional — when
     * absent the posture emitter records `'unknown'`.
     * See `docs/sprint-3-4-gaps/09-ai-posture-inventory.md`.
     */
    runtime?: string;
  };
}

/**
 * Audit log entry for capability operations
 */
export interface AuditLogEntry {
  /** Unique log entry ID */
  id: string;
  /** Timestamp of the event (ISO 8601 string) */
  timestamp: string;
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
  /**
   * Optional logical region tag for the issuer/gateway instance that
   * produced this entry (F-7, multi-region active/active). When set,
   * audit pipelines downstream can attribute each event to its
   * originating region — important for reconstructing what happened
   * during a regional failover. Plumbed by the issuer from the
   * `ISSUER_REGION` env var; gateways MAY plumb the same way from
   * their own region tag.
   */
  region?: string;
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
  /**
   * Optional: base64url-encoded SHA-256 JWK thumbprint (RFC 7638) of
   * the agent's DPoP public key. When supplied, the issuer stamps the
   * resulting capability token with `cnf.jkt = <thumbprint>` so the
   * token is sender-constrained per RFC 9449 (F-2): the gateway then
   * requires every request to carry a DPoP proof signed by the
   * matching private key. Either supply `dpopJkt` or `dpopJwk` (the
   * issuer prefers `dpopJkt` because it does not require recomputing
   * the thumbprint).
   */
  dpopJkt?: string;
  /**
   * Optional: agent's DPoP public JWK. The issuer computes its
   * canonical SHA-256 thumbprint (RFC 7638) and binds the token via
   * `cnf.jkt`. Equivalent in effect to {@link dpopJkt}; provided so
   * agent runtimes can hand the issuer the public key without
   * computing thumbprints client-side. Ignored when `dpopJkt` is set.
   */
  dpopJwk?: Record<string, unknown>;
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
 * a capability VC. Modeled as a discriminated union over the cloud
 * provider so the compiler enforces "exactly one provider-specific
 * credential is populated":
 *
 *  - `provider: 'azure-blob'` → `azureSas` is required (single
 *    user-delegation SAS works for both blob- and container-scoped grants).
 *  - `provider: 's3'` → either `s3Presigned` (single-object grants) **or**
 *    `s3Session` (prefix grants) is populated, never both.
 *  - `provider: 'gcs'` → either `gcsSigned` (single-object) **or**
 *    `gcsDownscoped` (prefix) is populated, never both.
 */
export type StorageGrant =
  | StorageGrantAzureBlob
  | StorageGrantS3Presigned
  | StorageGrantS3Session
  | StorageGrantGcsSigned
  | StorageGrantGcsDownscoped;

/** Common fields shared by every {@link StorageGrant} variant. */
interface StorageGrantBase {
  /** The capability resource this grant is scoped to (echoes the capability). */
  resource: ResourceId;
  /** Subset of the capability's actions this grant authorizes. */
  actions: Action[];
  /** ISO-8601 expiry of the cloud credential itself (≤ capability exp). */
  expiresAt: string;
}

export interface StorageGrantAzureBlob extends StorageGrantBase {
  provider: 'azure-blob';
  /** Azure Blob SAS (user-delegation SAS preferred). */
  azureSas: { url: string; sasToken: string };
  s3Presigned?: never;
  s3Session?: never;
  gcsSigned?: never;
  gcsDownscoped?: never;
}

export interface StorageGrantS3Presigned extends StorageGrantBase {
  provider: 's3';
  /** S3 single-object presigned URLs (one per permitted method). */
  s3Presigned: { method: 'GET' | 'PUT' | 'DELETE'; url: string; headers?: Record<string, string> }[];
  azureSas?: never;
  s3Session?: never;
  gcsSigned?: never;
  gcsDownscoped?: never;
}

export interface StorageGrantS3Session extends StorageGrantBase {
  provider: 's3';
  /** S3 prefix-scoped session credentials (STS AssumeRole + scope-down policy). */
  s3Session: {
    accessKeyId: string;
    secretAccessKey: string;
    sessionToken: string;
    region: string;
    bucket: string;
    prefix?: string;
  };
  azureSas?: never;
  s3Presigned?: never;
  gcsSigned?: never;
  gcsDownscoped?: never;
}

export interface StorageGrantGcsSigned extends StorageGrantBase {
  provider: 'gcs';
  /** GCS single-object signed URLs (one per permitted method). */
  gcsSigned: { method: 'GET' | 'PUT' | 'DELETE'; url: string }[];
  azureSas?: never;
  s3Presigned?: never;
  s3Session?: never;
  gcsDownscoped?: never;
}

export interface StorageGrantGcsDownscoped extends StorageGrantBase {
  provider: 'gcs';
  /** GCS prefix-scoped downscoped credentials (Credential Access Boundaries). */
  gcsDownscoped: {
    accessToken: string;
    bucket: string;
    prefix?: string;
    availabilityCondition?: string;
  };
  azureSas?: never;
  s3Presigned?: never;
  s3Session?: never;
  gcsSigned?: never;
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
  /**
   * ISO-8601 expiry of the credential. Reported by the cloud SDK when
   * available (Azure SQL AAD tokens echo their expiry in the JWT and
   * via `expiresOnTimestamp`); otherwise computed locally from the
   * provider-documented lifetime (RDS IAM tokens are always 15 min;
   * Cloud SQL OAuth uses the response's `expires_in`, capped by the
   * operator-configured `DB_TOKEN_MAX_TTL_SECONDS`).
   */
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
  /**
   * Optional DPoP proof binding the request to the holder of the
   * key referenced by the access token's `cnf.jkt` (RFC 9449 / F-2).
   *
   * When the verified token carries `cnf.jkt`, the gateway requires
   * this field; the proof's `htm`/`htu` MUST agree with
   * {@link dpop.httpMethod} / {@link dpop.httpUrl} and the embedded
   * JWK's SHA-256 thumbprint MUST equal the token's `cnf.jkt`. When
   * the token has no `cnf` claim, this field is ignored (back-compat).
   *
   * Routes wire this from the `DPoP` request header (`proof`) and the
   * full request URL the proof was supposed to bind to.
   */
  dpop?: {
    /** Compact-JWS DPoP proof from the `DPoP` header. */
    proof: string;
    /** HTTP method of the originating request, e.g. `'POST'`. */
    httpMethod: string;
    /** Full target URL the proof binds to (query/fragment stripped by verifier). */
    httpUrl: string;
  };
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

