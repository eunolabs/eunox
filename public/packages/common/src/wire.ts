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
   * SHA-256 hex digest of the capability-relevant portions of the
   * role-capability policy that authorized this token.
   *
   * Stamped at fresh issuance so attenuation and renewal can restore
   * the original policy boundary from the token rather than using the
   * issuer's current loaded policy.  This ensures that a policy rollout
   * on a running issuer pod does not change which KMS grant or Key Vault
   * key is used to sign derived tokens — the hash follows the token
   * lineage, not the current server state.
   *
   * The digest covers only the `default` and `tenants` fields of
   * {@link RoleCapabilityPolicy} (i.e. the capability-granting parts),
   * not ancillary fields such as `dbUsernamesByRole`, so changes to
   * credential-minting config that do not alter capability grants do
   * not invalidate existing KMS grants or key mappings.
   *
   * Populated by {@link computeCapabilityPolicyHash} in the issuer.
   * Gateway verifiers MUST NOT require this field (it was absent in
   * pre-signing-intent tokens) — it is present only when the issuer
   * was deployed with signing-intent support.
   */
  policyHash?: string;
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
  /**
   * Tenant identifier from the capability token's `authorizedBy.tenantId`
   * claim. Populated at enforcement time when the claim is present. Used by
   * the audit query API to scope results to the requesting tenant.
   */
  tenantId?: string;
  /**
   * The condition type that caused a `deny` decision (e.g. `'timeWindow'`,
   * `'ipRange'`, `'maxCalls'`, `'policy'`, `'custom'`). Only set on denial
   * records that originate from typed-condition evaluation. Not included in
   * the canonical evidence string so as not to break existing signatures.
   */
  conditionType?: string;
  /**
   * A short machine-readable code describing why this action was denied.
   * Maps to the gateway's `DenialCode` values:
   *   - `'NO_MATCHING_CAPABILITY'`   — no capability matched (action, resource).
   *   - `'ARGUMENT_SCHEMA_REQUIRED'` — strict mode, missing argumentSchema.
   *   - `'ARGUMENT_VALIDATION'`      — argument validation failed.
   *   - `'QUOTA_EXCEEDED'`           — gateway invocation quota exceeded.
   *   - `'CONDITION_FAILED'`         — typed-condition evaluation denied.
   * Only set on `deny` records. Not included in the canonical evidence string
   * to preserve backward compatibility with existing signatures.
   */
  denialCode?: string;
}

/**
 * Sentinel hash used as `previousHash` for the very first record in a chain
 * and as `previousBatchHash` for the first batch. Sixty-four hex zeros (the
 * SHA-256 digest of the empty string is a well-known constant, but an all-
 * zeros sentinel is more readable and unambiguous as a genesis marker).
 */
export const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

/**
 * Signed audit evidence with cryptographic signature and hash-chain linkage.
 *
 * Every `SignedAuditEvidence` produced by {@link AuditEvidenceSigner} carries
 * two additional fields that bind it into a tamper-evident chain:
 *
 *   - `previousHash` — the SHA-256 (hex) digest of the canonical form of the
 *     preceding `SignedAuditEvidence` in this signer's chain. Set to
 *     {@link GENESIS_HASH} for the first record. Tampering with any earlier
 *     record invalidates the hash of its successor, unravelling the whole
 *     chain from that point forward.
 *
 *   - `seq` — a monotonically increasing (1-based) sequence number assigned
 *     by the signer. Gaps in `seq` indicate dropped records; duplicate `seq`
 *     values indicate attempted record injection.
 *
 * Both fields are included in the canonical form that is signed, so they
 * cannot be modified without invalidating the signature.
 */
export interface SignedAuditEvidence extends AuditEvidence {
  /** Digital signature of the evidence */
  signature: string;
  /** Key ID used for signing */
  keyId: string;
  /** Signing algorithm */
  algorithm: string;
  /**
   * SHA-256 hex digest of the canonical form of the previous
   * `SignedAuditEvidence` in this signer's chain. {@link GENESIS_HASH} for
   * the first record.
   */
  previousHash: string;
  /**
   * Monotonically increasing (1-based) sequence number within this signer's
   * chain. The signer assigns this; producers must not set it.
   */
  seq: number;
}

/**
 * Unsigned Merkle batch commitment produced after each pipeline batch.
 *
 * A batch commitment is a cryptographic summary of all the `SignedAuditEvidence`
 * records processed in one pipeline drain cycle. Its fields form a second
 * chain (batch → batch) that is independent of the per-record chain:
 *
 *   - `merkleRoot` proves that the exact set of records with leaf hashes
 *     `leafHashes[0..recordCount-1]` was committed. Any substitution,
 *     addition, or removal of records changes the root.
 *
 *   - `previousBatchHash` links successive commitments so an attacker
 *     cannot silently discard whole batches without breaking the chain.
 *
 * The commitment is signed by {@link AuditEvidenceSigner.signBatch} to
 * produce a {@link SignedBatchCommitment} that can be published to an
 * external anchor (object store, transparency log, SIEM).
 */
export interface AuditBatchCommitment {
  /** Unique identifier for this batch. */
  batchId: string;
  /** Replica/pod identifier — set from `AUDIT_REPLICA_ID` or hostname. */
  replicaId: string;
  /** Monotonically increasing (1-based) batch sequence number for this replica. */
  batchSeq: number;
  /**
   * SHA-256 hex of the canonical form of the previous {@link SignedBatchCommitment}.
   * {@link GENESIS_HASH} for the first batch on this replica.
   */
  previousBatchHash: string;
  /**
   * Merkle root of the leaf hashes `canonicalSha256(SignedAuditEvidence)` for
   * every record in this batch.
   */
  merkleRoot: string;
  /** Number of records committed in this batch. */
  recordCount: number;
  /** `seq` of the first record in this batch. */
  firstSeq: number;
  /** `seq` of the last record in this batch. */
  lastSeq: number;
  /** ISO-8601 timestamp when the commitment was computed. */
  ts: string;
}

/**
 * Cryptographically signed batch commitment.  The signature covers the
 * canonical JSON form of all {@link AuditBatchCommitment} fields so the
 * commitment cannot be modified without detection.
 */
export interface SignedBatchCommitment extends AuditBatchCommitment {
  /** Digital signature over the canonical form of the commitment fields. */
  signature: string;
  /** Key ID used for signing (matches the evidence signing key). */
  keyId: string;
  /** Signing algorithm (matches the evidence signing algorithm). */
  algorithm: string;
}

/**
 * A snapshot of one replica's chain tip at a specific point in time.
 *
 * Used as a leaf in the {@link CrossChainCommitment} Merkle tree so that
 * any modification to a replica's reported tip invalidates the root.
 */
export interface ChainTipSnapshot {
  /** Replica / pod identifier. */
  replicaId: string;
  /** The sequence number of this replica's latest committed record. */
  seq: number;
  /**
   * `canonicalSha256` of the latest `SignedAuditEvidence` for this replica.
   * Matches the `record_hash` column in the per-replica ledger table.
   */
  tipHash: string;
  /** ISO-8601 timestamp when this tip was observed by the coordinator. */
  ts: string;
}

/**
 * Unsigned cross-chain Merkle commitment.
 *
 * Periodically produced by the {@link CrossChainAnchor} to capture the
 * current tips of **all** known replica chains in a single tamper-evident
 * record.  The commitment:
 *
 *   - Proves that the exact set of replica tips listed in `tips` was
 *     observed together (Merkle root over `canonicalSha256(ChainTipSnapshot)`
 *     for each tip — any substitution changes the root).
 *   - Links successive commitments via `previousCommitmentHash` so a gap or
 *     reorder of commitment records is detectable.
 *   - Is signed by {@link SignedCrossChainCommitment} and published to an
 *     S3 Object-Lock bucket (or other configured anchors) so even a full
 *     DB compromise cannot silently remove evidence without invalidating
 *     the S3 anchor trail.
 *
 * The cross-chain commitment provides the missing link that the per-replica
 * model (which removes `pg_advisory_xact_lock`) cannot provide by itself:
 * a periodic tamper-evident snapshot binding all replica chains together at
 * a point in time, visible to external auditors without DB access.
 */
export interface CrossChainCommitment {
  /** Unique identifier for this commitment. */
  commitmentId: string;
  /** Replica / pod that produced this commitment. */
  coordinatorId: string;
  /** ISO-8601 timestamp when the commitment was computed. */
  ts: string;
  /** Replica chain tips included in this commitment (sorted by replicaId). */
  tips: ChainTipSnapshot[];
  /**
   * Merkle root of `canonicalSha256(tip)` for each tip in `tips`.
   * Computed using the same balanced binary Merkle tree as the per-record
   * and per-batch Merkle trees (see `computeMerkleRoot` in utils.ts).
   */
  merkleRoot: string;
  /** Number of tips included. */
  tipCount: number;
  /** Monotonically increasing (1-based) commitment sequence number for this coordinator. */
  commitmentSeq: number;
  /**
   * `canonicalSha256` of the previous `SignedCrossChainCommitment`, or
   * `GENESIS_HASH` for the first commitment from this coordinator.
   */
  previousCommitmentHash: string;
}

/**
 * Cryptographically signed cross-chain Merkle commitment.
 *
 * The signature covers the canonical JSON form of all
 * {@link CrossChainCommitment} fields so the commitment cannot be modified
 * without detection.  Produced by {@link CrossChainAnchor} and published to
 * S3 Object-Lock (or other configured anchors).
 */
export interface SignedCrossChainCommitment extends CrossChainCommitment {
  /** Digital signature over the canonical form of the commitment fields. */
  signature: string;
  /** Key ID used for signing (matches the evidence signing key). */
  keyId: string;
  /** Signing algorithm (matches the evidence signing algorithm). */
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
  /**
   * Unique identifier for this individual grant, minted by the broker at
   * issuance time. Written into every audit log entry so the capability ↔
   * grant relationship can be traced end-to-end in any SIEM that ingests
   * the OCSF stream (see `auditLogEntryToOcsf`). Never taken from agent
   * input — always generated with `generateId()` inside the minter.
   */
  grantId: string;
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
  /**
   * Unique identifier for this individual DB credential, minted by the
   * broker at issuance time.  Written into every audit log entry so the
   * capability ↔ credential relationship can be traced end-to-end in any
   * SIEM that ingests the OCSF stream.  Never taken from agent input —
   * always generated with `generateId()` inside the minter.
   */
  grantId: string;
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

// ---------------------------------------------------------------------------
// Stage-3 remote-enforcer wire protocol (Task 9)
// ---------------------------------------------------------------------------
//
// These types define the HTTP contract between @euno/mcp running in
// remote-enforcer mode and the hosted gateway's POST /api/v1/enforce endpoint.
// The canonical documentation lives in docs/stage-3-gateway-protocol.md.
// Any evolution MUST land here first so both the gateway (tool-gateway) and
// the client (@euno/mcp) share a single source of truth per the cross-cutting
// obligation in docs/stage3executionplan.md.

/**
 * Current protocol version integer. Sent by the client in the
 * `X-Euno-Protocol-Version` request header and echoed by the gateway in the
 * same response header.
 *
 * **Versioning rule:** bump this constant when a breaking change is introduced.
 * The gateway MUST continue to support all previously published versions until
 * they are retired after a deprecation window of ≥1 minor `@euno/mcp` release.
 * Deprecated versions are announced via the `X-Euno-Deprecation` response header.
 */
export const ENFORCE_PROTOCOL_VERSION = 1 as const;

/**
 * Set of protocol version integers the current implementation can serve.
 * The gateway rejects requests whose `X-Euno-Protocol-Version` is not in
 * this set with HTTP 400 / `UNSUPPORTED_PROTOCOL_VERSION`.
 */
export const SUPPORTED_ENFORCE_PROTOCOL_VERSIONS: ReadonlySet<number> = new Set([
  ENFORCE_PROTOCOL_VERSION,
]);

/**
 * Per-request context forwarded by `@euno/mcp` to the remote enforcer.
 *
 * All fields are optional so the client can omit those that are not
 * applicable to the transport or tool. The gateway applies fail-closed
 * semantics: a condition that requires a missing field (e.g. `ipRange`
 * when `sourceIp` is absent) results in a denial with code
 * `MISSING_CONTEXT`.
 */
export interface EnforceRequestContext {
  /**
   * Source IP of the MCP client, stripped of any IPv4-mapped prefix
   * (`::ffff:`). In Cloud, the edge / minter facade overwrites
   * caller-supplied values with the observed connection IP so that
   * `ipRange` conditions cannot be bypassed by a compromised agent.
   * Self-hosters that run their own network boundary MAY supply this
   * from trusted forwarding headers; they MUST document the trust
   * assumption and verify it against their ingress configuration.
   * Omit for stdio-transport requests — ipRange conditions will deny
   * with `MISSING_CONTEXT`.
   */
  sourceIp?: string;

  /**
   * Recipient addresses extracted from the tool arguments
   * (to / recipients / cc / bcc fields). The gateway applies the same
   * recipient-extraction logic as the local `recipientDomain` handler.
   * MAY be omitted when the tool call has no recipient semantics;
   * `recipientDomain` conditions will deny with `MISSING_CONTEXT`.
   */
  recipients?: string[];

  /**
   * Wall-clock time of the request as an ISO-8601 string.
   *
   * When omitted the gateway uses its own authoritative clock for
   * enforcement. When supplied the value is recorded in the audit event
   * for correlation; on the **hosted** service it is NOT used to evaluate
   * `timeWindow` conditions — clients cannot manipulate time-based access
   * decisions. Self-hosters MAY honour this field for `timeWindow`
   * evaluation but MUST document that trust assumption explicitly.
   *
   * Requests where the supplied `now` diverges by more than 60 seconds
   * from the gateway clock are rejected with `INVALID_REQUEST` / clock-skew
   * guard.
   */
  now?: string;
}

/**
 * Request body sent by `@euno/mcp` to `POST /api/v1/enforce`.
 *
 * **Authentication:** The client always presents a JWT Bearer token in
 * `Authorization`. In the hosted deployment topology the minter façade
 * (Task 10) converts the client's API key (`sk-…`) into a short-lived JWT
 * before the request reaches this route; in self-hosted deployments the
 * operator's issuer JWT is sent directly. This route never accepts raw API
 * keys — the façade is the only party that handles them.
 *
 * **Size limit:** 512 KiB. Requests exceeding this limit receive HTTP 413
 * with error code `REQUEST_TOO_LARGE`.
 */
export interface EnforceRequest {
  /**
   * Opaque session identifier from the MCP `initialize` handshake.
   * For stdio transport: the proxy process-lifetime ID.
   * For HTTP transport: the `initialize` → `shutdown` cycle ID.
   * Used by the gateway to apply session-scoped kill-switch checks and
   * to group audit events from the same session.
   */
  sessionId: string;

  /**
   * The MCP tool name exactly as sent in the `tools/call` request.
   * Matched against the policy's `requiredCapabilities[].resource`
   * using the same `matchesResource()` logic as the local PDP.
   */
  toolName: string;

  /**
   * The raw arguments object from the `tools/call` request.
   * The gateway runs `argumentSchema` validation (when present in the
   * policy) and extracts `recipients` / `operations` from this for
   * condition evaluation. MUST be JSON-serialisable; binary values
   * should be base64-encoded strings. When the gateway receives an
   * arguments object that fails schema validation, it denies with code
   * `ARGUMENT_SCHEMA_VIOLATION`.
   */
  arguments: Record<string, unknown>;

  /** Per-request context for condition evaluation. */
  context: EnforceRequestContext;
}

/**
 * A single obligation the caller MUST apply before returning the
 * upstream response to the MCP client. Obligations are applied in
 * declaration order. An empty `obligations` array (or omitted field)
 * means no post-processing is required.
 *
 * Only present in an `EnforceResponse` when `decision` is `'allow'`.
 */
export type Obligation =
  /** Strip the listed dotted-path fields from the upstream response body. */
  | { type: 'redactFields'; paths: string[] }
  /** Attach metadata to the caller's own audit event for this tool call. */
  | { type: 'annotate'; key: string; value: string };

/**
 * Structured details about a denial decision. Only present in an
 * `EnforceResponse` when `decision` is `'deny'`.
 */
export interface DenialInfo {
  /**
   * Machine-readable denial code, drawn from the `ErrorCode` enum in
   * `@euno/common`. Examples: `'AUTHORIZATION_FAILED'`, `'ARGUMENT_SCHEMA_VIOLATION'`,
   * `'RATE_LIMIT_EXCEEDED'`, `'AGENT_TERMINATED'`.
   */
  code: string;

  /**
   * The condition type that triggered the denial, or `'killSwitch'` /
   * `'policy'` / `'tokenVerification'` for non-condition denials.
   */
  conditionType: string;

  /**
   * Human-readable denial message. Suitable for server-side logging;
   * MUST NOT be surfaced verbatim to end-users (may contain internal
   * identifiers).
   */
  message: string;

  /**
   * Optional structured details specific to the denial type:
   * - argumentSchema failures: `{ schemaErrors: ValidationError[] }`
   * - ipRange denials: `{ sourceIp: string, allowedRanges: string[] }`
   * - maxCalls denials: `{ currentCount: number, maxCalls: number, windowSeconds: number }`
   */
  details?: Record<string, unknown>;
}

/**
 * Response body returned by the gateway from `POST /api/v1/enforce`.
 *
 * HTTP status is always `200` when a decision is reached (whether `allow`
 * or `deny`). Non-200 status codes indicate infrastructure-level errors
 * (auth failure, malformed request, etc.) and use the `ErrorResponse` shape.
 *
 * The gateway echoes `X-Euno-Protocol-Version` in the response header.
 */
export interface EnforceResponse {
  /**
   * Echoes the `X-Request-Id` header from the caller, or a gateway-generated
   * UUID when the header was absent. Included in the gateway's own audit log
   * for cross-system correlation. Callers SHOULD log this value alongside the
   * tool call event.
   */
  requestId: string;

  /** The enforcement decision. */
  decision: 'allow' | 'deny';

  /**
   * Obligations the caller MUST apply before returning the upstream response
   * to the MCP client. Obligations are applied in the listed order.
   * Present only when `decision` is `'allow'`; absent (not `null`) otherwise.
   */
  obligations?: Obligation[];

  /**
   * Denial details. Present only when `decision` is `'deny'`;
   * absent (not `null`) otherwise.
   */
  denial?: DenialInfo;

  /**
   * ISO-8601 timestamp of this decision, from the gateway's authoritative
   * clock. Callers may use this to populate the `activityTime` field of
   * their own audit event.
   */
  decidedAt: string;
}

