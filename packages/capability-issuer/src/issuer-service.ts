/**
 * Capability Issuer Service — orchestrator.
 *
 * Thin coordinator: it owns the externally injected dependencies
 * ({@link TokenSigner}, {@link IdentityProvider}, optional credential
 * pipelines, optional posture emitter) and the issuer configuration,
 * but delegates all the actual issuance / attenuation / renewal
 * mechanics to the cohesive modules under `./issuance/`.
 *
 * See `docs/IMPROVEMENTS_AND_REFACTORING.md` § R-1.
 */

import {
  ActionResolver,
  AuditLogEntry,
  BUILTIN_ACTION_RESOLVER,
  CapabilityConstraint,
  CapabilityError,
  CapabilityTokenPayload,
  Cosigner,
  cosignPayload,
  DEFAULT_ROLE_CAPABILITY_MAP,
  DbCredential,
  ErrorCode,
  IdentityProvider,
  IssuanceRateLimitSubject,
  IssuanceRateLimiter,
  IssueCapabilityRequest,
  IssueCapabilityResponse,
  JwkSet,
  Logger,
  PostureEmitterLike,
  RateLimitDecision,
  RoleCapabilityPolicy,
  StorageGrant,
  TokenSigner,
  TransparencyLog,
  UserConsent,
  UserContext,
  createAuditLogger,
  generateId,
  getCurrentTimestamp,
  getExpirationTimestamp,
  jwkToJkt,
  mapRolesToCapabilitiesForPolicy,
  matchesResource,
  witnessPayload,
} from '@euno/common';
import * as crypto from 'crypto';
import type TransportStream from 'winston-transport';
import { DbTokenService } from './db-token';
import { StorageGrantService } from './storage-grant';
import {
  BrokerCallError,
  InProcessSideCredentialBroker,
  SideCredentialBroker,
} from './side-credential-broker';
import {
  buildAttenuatedPayload,
  buildIssuancePayload,
  buildIssuanceContext,
  buildRenewedPayload,
  computeCapabilityPolicyHash,
  computePimCappedExpiry,
  emitPostureRecord,
  enforceConditionalAccess,
  enforcePimRequiredRoles,
  filterRolesContributingToCapabilities,
  mapVerifyError,
  requestedCapabilitiesIncludeSensitive,
  signPayload,
  validateAgainstManifest,
  validateCapabilitySubset,
  validateConditionsForCapabilities,
  validateConsent,
  verifyParentToken,
} from './issuance';

// Re-export PostureEmitterLike from this module for backwards
// compatibility — it now lives in `@euno/common` (per R-1's
// "Promote `PostureEmitterLike` into `@euno/common`" item) but
// older callers and tests import it from this file.
export type { PostureEmitterLike } from '@euno/common';

/**
 * Infer a JWS algorithm from exported JWK key material when the signer
 * does not expose `getAlgorithm()`.
 *
 * Returns `undefined` when the algorithm cannot be determined with confidence
 * (e.g. RSA keys, which support several algorithm families) so that callers
 * can omit `alg` rather than advertising an incorrect value.
 */
/**
 * RFC 7638 SHA-256 JWK thumbprint validator. A correct value is the
 * raw 32-byte SHA-256 digest base64url-encoded *without* padding —
 * exactly 43 characters drawn from the URL-safe alphabet. Anything
 * else (a hex digest, a SHA-1 thumbprint, a typo, …) cannot ever
 * match a verifier's recomputed thumbprint, so we refuse the request
 * at issuance time instead of minting a token that is guaranteed to
 * fail at verification.
 */
const JWK_THUMBPRINT_PATTERN = /^[A-Za-z0-9_-]{43}$/;
function isValidJwkThumbprint(value: string): boolean {
  return JWK_THUMBPRINT_PATTERN.test(value);
}

function inferAlgFromJwk(jwkData: Record<string, unknown>): string | undefined {
  const kty = String(jwkData['kty'] ?? '');
  const crv = typeof jwkData['crv'] === 'string' ? jwkData['crv'] : undefined;

  switch (kty) {
    case 'EC':
      // Elliptic-curve: algorithm is unambiguous from the curve name.
      switch (crv) {
        case 'P-256': return 'ES256';
        case 'P-384': return 'ES384';
        case 'P-521': return 'ES512';
        default: return undefined;
      }
    case 'OKP':
      // Octet-key-pair (Ed25519 / Ed448) always uses EdDSA.
      return 'EdDSA';
    case 'RSA':
      // RSA is used with multiple algorithm families (RS256/384/512,
      // PS256/384/512) — the key material alone is insufficient to choose.
      return undefined;
    default:
      return undefined;
  }
}

/**
 * Identifies which rate limiter fired when the `onIssuanceRateLimited`
 * callback is invoked. Using a typed union prevents unbounded label
 * values from accidentally reaching Prometheus metric labels or audit
 * log `reason` fields.
 */
export type IssuanceLimiterKind = 'issuance' | 'storage-grant' | 'db-token';

/**
 * Per-request enforcement context supplied by the HTTP layer.
 *
 * Separates transport-level metadata (source IP) from the wire-format
 * request body ({@link IssueCapabilityRequest}) so the wire types stay
 * clean while the rate-limiter can still key on the caller's IP.
 */
export interface IssuerEnforcementContext {
  /**
   * Source IP of the HTTP request (`req.ip` in the Express handler).
   * Passed to the issuance rate limiter so the five-component key
   * includes the caller's network address, preventing IP-hopping from
   * multiplying the effective issuance budget. Absent or `undefined`
   * maps to the sentinel `'_no_ip'` inside the limiter.
   */
  clientIp?: string;
}

export interface CapabilityIssuerServiceOptions {
  /**
   * When true, every call to {@link CapabilityIssuerService.issueCapability}
   * MUST include a valid {@link UserConsent} record. Defaults to false to
   * preserve back-compat for deployments that have not yet wired a consent
   * UI; new deployments should enable this in production.
   */
  requireConsent?: boolean;
  /**
   * Optional externalised role → capability policy. When omitted the
   * service falls back to the in-code Sprint-1 default mapping. Supplying
   * a policy here is the recommended way to make the issuer's
   * authorization decisions data-driven (loaded from a file, config
   * service, or per-tenant override map) rather than hard-coded.
   */
  policy?: RoleCapabilityPolicy;
  /**
   * Optional storage-grant service. When supplied and enabled, the
   * issuer mints short-lived cloud storage credentials alongside the
   * VC for every capability whose resource matches the canonical
   * `storage://{cloud}/{bucket}/...` form. See
   * `docs/sprint-3-4-gaps/07-storage-grants.md`.
   */
  storageGrantService?: StorageGrantService;
  /**
   * Optional DB-token service. When supplied and enabled, the issuer
   * mints short-lived IAM-bound database credentials alongside the VC
   * for every capability whose resource matches the canonical
   * `db://{cloud}/{instance}/...` form. See
   * `docs/sprint-3-4-gaps/08-db-token-issuance.md`.
   */
  dbTokenService?: DbTokenService;
  /**
   * Operator-declared list of role display names that MUST be currently
   * active via Privileged Identity Management (or equivalent JIT
   * elevation). Issuance is denied when any of these roles appears in
   * the user's resolved roles but is not in `pim-active` state in
   * `userContext.roleSources`. When `userContext.roleSources` is
   * absent (provider does not implement PIM), this list is ignored —
   * deployments that need enforcement should configure a provider that
   * populates `roleSources` (today, Azure AD with `pim` set).
   *
   * See `docs/sprint-3-4-gaps/04-pim-activation.md`.
   */
  pimRequiredRoles?: string[];
  /**
   * When true, capability TTL is capped at the smallest remaining
   * `pim-active` window across all roles in
   * `userContext.roleSources`. Defaults to true. Has no effect when
   * the user has no `pim-active` roles.
   */
  capTtlToPimActivation?: boolean;
  /**
   * Optional AI posture-management emitter. When supplied, the
   * issuer fires a fire-and-forget {@link PostureEmitterLike.emitObserved}
   * after every successful issuance so cloud posture-management
   * surfaces (Defender CSPM / Security Hub / SCC) keep an accurate
   * inventory of the agent estate. Failures never affect issuance.
   * See `docs/sprint-3-4-gaps/09-ai-posture-inventory.md`.
   */
  postureEmitter?: PostureEmitterLike;
  /**
   * Logical region tag for this issuer instance (F-7). When set,
   * stamped on:
   *  - the `region` claim of issued capability tokens (preserved
   *    across attenuation and renewal),
   *  - posture inventory records (replaces the legacy
   *    {@link postureRegion} option),
   *  - audit log entries via `AuditLogEntry.region`,
   *  - request span attributes (`euno.region`) — set by the HTTP
   *    layer, not this service.
   *
   * Falls back to `process.env.EUNO_DEPLOYMENT_REGION` (legacy) and
   * finally undefined (the `region` claim is then omitted on tokens
   * for back-compat with single-region deployments).
   */
  region?: string;
  /**
   * @deprecated Use {@link region}. Retained for back-compat with
   * sprint 3-4 posture-emitter wiring; ignored when {@link region} is
   * also set.
   */
  postureRegion?: string;
  /**
   * Optional per-(tenant, user, agent) issuance rate limiter (F-1,
   * addresses I-1 from `docs/IMPROVEMENTS_AND_REFACTORING.md`). When
   * supplied, every successful authentication on
   * {@link CapabilityIssuerService.issueCapability} consumes one
   * token from the bucket; exhaustion denies with
   * {@link ErrorCode.RATE_LIMIT_EXCEEDED} (HTTP 429) BEFORE any
   * signing or side-credential mint runs, so a compromised account
   * cannot exhaust KMS budget either.
   *
   * The limiter is keyed on `(tenantId, userId, agentId)` — tenant
   * first so the limit is **tenant-aware**, the load-bearing
   * prerequisite called out by §6.1 #3 of
   * `docs/IMPROVEMENTS_AND_REFACTORING.md` for F-7 (multi-region
   * active/active issuer).
   *
   * Optional for back-compat: the existing per-IP express rate
   * limiter on `/api/v1/issue` continues to run regardless.
   */
  issuanceRateLimiter?: IssuanceRateLimiter;
  /**
   * Optional callback fired whenever any of the issuance rate limiters
   * (main, storage-grant, or db-token) denies an issuance. Used by the
   * HTTP entrypoint to increment Prometheus counters. Failures inside
   * the callback are logged and swallowed so observability never affects
   * the request decision.
   *
   * The `kind` parameter identifies which limiter fired:
   * - `'issuance'` — the main per-(tenant,user,agent) limiter
   * - `'storage-grant'` — the dedicated storage-grant limiter
   * - `'db-token'` — the dedicated DB-token limiter
   */
  onIssuanceRateLimited?: (
    subject: IssuanceRateLimitSubject,
    reason: 'exceeded' | 'limiter_unavailable',
    kind?: IssuanceLimiterKind,
  ) => void;
  /**
   * Optional dedicated per-(tenant, user, agent) rate limiter for
   * storage-grant issuance. When supplied, every call to
   * {@link mintSideCredentials} that reaches the storage-grant minter
   * first consumes one token from this bucket; exhaustion denies with
   * {@link ErrorCode.RATE_LIMIT_EXCEEDED} (HTTP 429). This limiter is
   * intentionally tighter than {@link issuanceRateLimiter} because each
   * storage grant issues an STS session (a long-lived AWS credential)
   * rather than a short-lived capability JWT.
   */
  storageGrantRateLimiter?: IssuanceRateLimiter;
  /**
   * Optional dedicated per-(tenant, user, agent) rate limiter for
   * DB-token issuance. When supplied, every call to
   * {@link mintSideCredentials} that reaches the DB-token minter
   * first consumes one token from this bucket. Intentionally tighter
   * than {@link issuanceRateLimiter}: a bug in DB-token issuance can
   * expose a 15-minute AWS RDS IAM auth token, which is a larger blast
   * radius than a short-lived capability JWT.
   */
  dbTokenRateLimiter?: IssuanceRateLimiter;
  /**
   * Optional side-credential broker.  When supplied, the issuer
   * delegates all storage-grant and DB-token minting to this broker
   * rather than calling `storageGrantService` / `dbTokenService`
   * directly.  This is the recommended option for operators who have
   * deployed the dedicated `storage-grant-service` and
   * `db-token-service` microservices:
   *
   * ```ts
   * sideCredentialBroker: new HttpSideCredentialBroker({
   *   storageGrantServiceUrl: process.env.STORAGE_GRANT_SERVICE_URL,
   *   dbTokenServiceUrl: process.env.DB_TOKEN_SERVICE_URL,
   * })
   * ```
   *
   * When both a broker **and** the legacy `storageGrantService` /
   * `dbTokenService` options are provided, the broker takes
   * precedence and the legacy options are ignored.
   *
   * When a broker is **not** supplied but the legacy service options
   * are, an `InProcessSideCredentialBroker` is constructed automatically
   * at startup for backward compatibility.
   */
  sideCredentialBroker?: SideCredentialBroker;
  /**
   * Controls what happens when the side-credential broker throws an
   * unrecoverable error (network failure, STS outage, bad config, …).
   *
   * - `'fail-fast'` *(default, back-compat)*: the error propagates and
   *   the caller receives a 502 / 500.  Matches the previous monolith
   *   behaviour.
   * - `'best-effort'`: the error is logged and the optional
   *   {@link onSideCredentialError} callback is fired, but the
   *   capability JWT is still returned without side credentials.
   *   Opt in when the agent runtime is prepared to fall back to
   *   calling the dedicated credential-service endpoints directly, or
   *   when a temporary STS outage should not block all capability
   *   issuance.
   */
  sideCredentialFailureMode?: 'fail-fast' | 'best-effort';
  /**
   * Optional callback fired when the side-credential broker fails in
   * `'best-effort'` mode.  Callers (the HTTP entrypoint) use this to
   * increment Prometheus counters without coupling the service to the
   * metrics registry.  Failures inside the callback are swallowed.
   */
  onSideCredentialError?: (
    kind: 'storage-grant' | 'db-token' | 'unknown',
    error: Error,
  ) => void;
  /**
   * Optional pluggable {@link ActionResolver} (R-7, addresses I-4
   * and I-5). When supplied, the issuer uses it to map every
   * granted capability action to its CA tier during the
   * {@link enforceConditionalAccess} check at issuance time, instead
   * of the legacy substring-matching heuristic. Operators that need
   * to tier deployment-specific verbs (e.g. `db:select`,
   * `acknowledge_alert`) should ship a single resolver shared
   * between the issuer and the gateway via the `ACTION_RESOLVER_FILE`
   * env var so mint-time and enforcement-time tiering agree.
   *
   * Optional for back-compat: when omitted the
   * {@link BUILTIN_ACTION_RESOLVER} is used, which reproduces the
   * legacy CA-tier mapping for every action in the default role
   * policy.
   */
  actionResolver?: ActionResolver;
  /**
   * Optional list of additional winston transports to attach to this
   * issuer's audit logger (in addition to whatever
   * {@link createAuditLogger} attaches by default). Used by the
   * service entrypoint to plug in the F-6 OCSF bridge so every
   * AuditLogEntry the issuer emits is mirrored to the configured SIEM.
   *
   * Failures attaching a transport are not the service's concern —
   * the caller chose to add it, the caller owns its health.
   */
  auditTransports?: TransportStream[];
  /**
   * Audience string stamped into the `aud` JWT claim of every
   * capability token this issuer mints (including attenuated and
   * renewed tokens). Defaults to `"tool-gateway"`.
   *
   * In multi-tenant deployments set this to a unique value per
   * gateway tenant (e.g. `"tool-gateway:acme-corp-prod"`) so a
   * token minted by one tenant's issuer cannot be replayed at
   * another tenant's gateway. MUST match the `GATEWAY_AUDIENCE`
   * configured on the corresponding tool-gateway instance.
   */
  gatewayAudience?: string;
  /**
   * Optional list of independent {@link Cosigner}s that countersign
   * every issuance receipt. Mitigates the "single-issuer trust root"
   * critical risk: an attacker who pivots from a compromised issuer
   * pod to the primary KMS `signDigest` permission still cannot mint
   * usable tokens because they do not control any cosigner's private
   * key. Cosigners SHOULD be held by a different principal than the
   * primary issuer signing key — typical realisations are an offline
   * policy authority key (sealed PEM mounted into the pod), a second
   * KMS key in a different cloud account, or a remote co-signing
   * micro-service.
   *
   * Cosignatures are added to the token's `proofs.cosig[]` claim. The
   * gateway verifies them against its own cosigner JWKS — see
   * `REQUIRE_COSIGNATURE_COUNT` and `COSIGNER_JWKS_FILE` on the gateway.
   *
   * Optional: when omitted, no `cosig` claim is emitted and tokens
   * remain wire-compatible with the previous schema (back-compat).
   */
  cosigners?: ReadonlyArray<Cosigner>;
  /**
   * Optional list of {@link TransparencyLog} clients that this issuer
   * submits every issuance receipt to. Each log returns an
   * {@link Sct}-style witness record that is added to the token's
   * `proofs.sct[]` claim. Provides an external, append-only trail of
   * issuances independent of the issuer's signing key — auditors can
   * reconcile the log against the issuer's audit trail to detect
   * silent issuance fraud. Mitigates the "single-issuer trust root"
   * critical risk together with {@link cosigners}.
   *
   * Submission failures abort the issuance (an SCT-required deployment
   * cannot silently fall back to issuing without an SCT or a partial
   * outage becomes a forge window).
   *
   * Optional: when omitted, no `sct` claim is emitted (back-compat).
   */
  transparencyLogs?: ReadonlyArray<TransparencyLog>;
}

export class CapabilityIssuerService {
  private signer: TokenSigner;
  private identityProvider: IdentityProvider;
  private issuerDid: string;
  private defaultTTL: number;
  private logger: Logger;
  private auditLogger: Logger;
  private requireConsent: boolean;
  private policy: RoleCapabilityPolicy;
  /** @deprecated — kept for back-compat; underlying service is wrapped inside `sideCredentialBroker`. */
  private storageGrantService?: StorageGrantService;
  /** @deprecated — kept for back-compat; underlying service is wrapped inside `sideCredentialBroker`. */
  private dbTokenService?: DbTokenService;
  /**
   * Broker that encapsulates all side-credential minting (storage grants
   * + DB tokens).  Always set in the constructor — falls back to an
   * `InProcessSideCredentialBroker` wrapping the legacy service options
   * so existing callers need no changes.
   */
  private sideCredentialBroker: SideCredentialBroker;
  /**
   * Controls broker failure handling.  `'fail-fast'` (default) propagates
   * errors; `'best-effort'` logs and continues without side credentials.
   */
  private sideCredentialFailureMode: 'fail-fast' | 'best-effort';
  private onSideCredentialError?: (
    kind: 'storage-grant' | 'db-token' | 'unknown',
    error: Error,
  ) => void;
  private pimRequiredRoles: string[];
  private capTtlToPimActivation: boolean;
  private postureEmitter?: PostureEmitterLike;
  /**
   * Effective region tag (F-7). Empty string means "not configured" —
   * audit/posture default to `'unknown'`, the token `region` claim is
   * omitted entirely, and gateways behave exactly as before. See the
   * `region` field on {@link CapabilityIssuerServiceOptions}.
   */
  private region: string;
  /**
   * Region label used by posture emission. Always non-empty (defaults
   * to `'unknown'` so the inventory feed is never sparse). Distinct
   * from {@link region} only because the token `region` claim must be
   * omitted when not configured (back-compat) but posture records have
   * always required a value.
   */
  private postureRegion: string;
  private issuanceRateLimiter?: IssuanceRateLimiter;
  private storageGrantRateLimiter?: IssuanceRateLimiter;
  private dbTokenRateLimiter?: IssuanceRateLimiter;
  private onIssuanceRateLimited?: (
    subject: IssuanceRateLimitSubject,
    reason: 'exceeded' | 'limiter_unavailable',
    kind?: IssuanceLimiterKind,
  ) => void;
  private actionResolver: ActionResolver;
  /** Audience claim for minted tokens. Configurable per-tenant to prevent cross-tenant replay. */
  private gatewayAudience: string;
  /**
   * SHA-256 hex digest of the capability-relevant portions of the
   * role-capability policy (see {@link computeCapabilityPolicyHash}).
   * Computed once at construction time and reused on every sign
   * operation so the hash does not add O(policy-size) cost to the hot
   * path.  Written into every minted token's `policyHash` claim so
   * attenuation and renewal can restore it from the parent token instead
   * of re-hashing whatever policy version is currently loaded.
   */
  private readonly cachedPolicyHash: string;
  /**
   * Independent cosigners attached to every issued / attenuated /
   * renewed token. Empty array means cosignature is disabled for this
   * deployment (back-compat). See {@link CapabilityIssuerServiceOptions.cosigners}.
   */
  private cosigners: ReadonlyArray<Cosigner>;
  /**
   * Transparency-log clients submitted-to on every issuance. Empty
   * array means transparency logging is disabled (back-compat). See
   * {@link CapabilityIssuerServiceOptions.transparencyLogs}.
   */
  private transparencyLogs: ReadonlyArray<TransparencyLog>;

  constructor(
    signer: TokenSigner,
    identityProvider: IdentityProvider,
    issuerDid: string,
    defaultTTL: number = 900, // 15 minutes default
    logger: Logger,
    options: CapabilityIssuerServiceOptions = {},
  ) {
    this.signer = signer;
    this.identityProvider = identityProvider;
    this.issuerDid = issuerDid;
    this.defaultTTL = defaultTTL;
    this.logger = logger;
    // F-7: `region` is the canonical setting; `postureRegion` is the
    // legacy fallback so existing wiring keeps working unchanged.
    // `region` is set by the caller from the validated boot config — see
    // capability-issuer/src/index.ts. The `postureRegion` option is a
    // legacy alias for the same value kept for library back-compat. The
    // env-var fallback has been removed: callers must supply `options.region`
    // (populated from `ISSUER_REGION` / `EUNO_DEPLOYMENT_REGION` via the
    // validated schema) or accept an empty string.
    this.region = options.region ?? options.postureRegion ?? '';
    this.postureRegion = this.region.length > 0 ? this.region : 'unknown';
    this.auditLogger = createAuditLogger('capability-issuer', { region: this.region });
    if (options.auditTransports) {
      for (const t of options.auditTransports) {
        this.auditLogger.add(t);
      }
    }
    this.requireConsent = options.requireConsent === true;
    this.policy = options.policy ?? { default: DEFAULT_ROLE_CAPABILITY_MAP };
    // Broker resolution order:
    //   1. Explicit `sideCredentialBroker` (recommended for microservice deployments).
    //   2. Legacy `storageGrantService` / `dbTokenService` wrapped in an
    //      `InProcessSideCredentialBroker` (back-compat for existing configs).
    //   3. An empty in-process broker (neither service configured — no-op).
    if (options.sideCredentialBroker) {
      this.sideCredentialBroker = options.sideCredentialBroker;
    } else {
      if (options.storageGrantService) this.storageGrantService = options.storageGrantService;
      if (options.dbTokenService) this.dbTokenService = options.dbTokenService;
      this.sideCredentialBroker = new InProcessSideCredentialBroker({
        storageGrantService: this.storageGrantService,
        dbTokenService: this.dbTokenService,
      });
    }
    this.sideCredentialFailureMode = options.sideCredentialFailureMode ?? 'fail-fast';
    if (options.onSideCredentialError) this.onSideCredentialError = options.onSideCredentialError;
    this.pimRequiredRoles = options.pimRequiredRoles ?? [];
    this.capTtlToPimActivation = options.capTtlToPimActivation !== false;
    if (options.postureEmitter) this.postureEmitter = options.postureEmitter;
    if (options.issuanceRateLimiter) this.issuanceRateLimiter = options.issuanceRateLimiter;
    if (options.storageGrantRateLimiter) this.storageGrantRateLimiter = options.storageGrantRateLimiter;
    if (options.dbTokenRateLimiter) this.dbTokenRateLimiter = options.dbTokenRateLimiter;
    if (options.onIssuanceRateLimited) this.onIssuanceRateLimited = options.onIssuanceRateLimited;
    this.actionResolver = options.actionResolver ?? BUILTIN_ACTION_RESOLVER;
    this.gatewayAudience = options.gatewayAudience ?? 'tool-gateway';
    // Precompute once at construction — avoids rehashing on every sign call.
    // Only the capability-granting portions (default + tenants) are hashed;
    // dbUsernamesByRole is excluded so credential-minting config changes that
    // leave capability grants unchanged do not invalidate KMS grants / key maps.
    this.cachedPolicyHash = computeCapabilityPolicyHash(this.policy);
    this.cosigners = options.cosigners ?? [];
    this.transparencyLogs = options.transparencyLogs ?? [];
  }

  /**
   * Logical region tag for this issuer instance (F-7). Returns the
   * empty string when no region is configured. Exposed read-only so
   * the HTTP layer can surface it on the `/.well-known/capability-issuer`
   * metadata endpoint and on tracing spans without having to re-read
   * the env var.
   */
  getRegion(): string {
    return this.region;
  }

  /**
   * Attach the configured `proofs` claim (cosignatures + transparency-log
   * SCTs) to a freshly-built payload, in place. No-op when neither
   * cosigners nor transparency logs are configured (back-compat: the
   * payload remains byte-for-byte identical to the pre-feature shape and
   * gateways without proof requirements continue to accept it).
   *
   * Cosigner / log failures abort the issuance — minting a token whose
   * cosignature or SCT silently failed would degrade to the previous
   * single-signer trust model and create a forge window during partial
   * outages.
   *
   * Returns the (mutated) payload for call-site convenience.
   */
  private async attachIssuanceProofs(
    payload: CapabilityTokenPayload,
  ): Promise<CapabilityTokenPayload> {
    if (this.cosigners.length === 0 && this.transparencyLogs.length === 0) {
      return payload;
    }
    // Run cosignature + transparency-log submission in parallel.
    // Both backends consume the same payload and their outputs are
    // independent, so serialising them would put mint latency at
    // (cosigner-RTT + log-RTT) instead of max(cosigner-RTT, log-RTT).
    // With remote signers / logs this matters on every issuance.
    const [cosigs, scts] = await Promise.all([
      cosignPayload(payload, this.cosigners),
      witnessPayload(payload, this.transparencyLogs),
    ]);
    if (cosigs || scts) {
      payload.proofs = {
        ...(cosigs ? { cosig: cosigs } : {}),
        ...(scts ? { sct: scts } : {}),
      };
    }
    return payload;
  }

  /**
   * Issue a capability token. Coordinates the issuance pipeline:
   * authenticate → role-derive → enforce manifest/consent/CA/conditions
   * → cap TTL to PIM → build payload → sign → mint side-credentials →
   * audit → emit posture.
   */
  async issueCapability(
    request: IssueCapabilityRequest,
    // `_enforcement` is accepted but intentionally unused in the rate-limit
    // path. It is retained so route handlers (index.ts) can continue passing
    // `{ clientIp: req.ip }` for future use (e.g. IP-based audit logging or
    // an additional out-of-band IP guard) without a breaking API change.
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    _enforcement?: IssuerEnforcementContext,
  ): Promise<IssueCapabilityResponse> {
    try {
      // Step 1: Validate the user's authentication token.
      this.logger.info('Validating user authentication token', { agentId: request.agentId });
      const userContext = await this.identityProvider.validateToken(request.authToken);

      // Step 1a: Per-(tenantId, userId, agentId) issuance rate limit (F-1).
      // Runs *after* authentication so the limit is keyed on the resolved
      // subject rather than transport metadata, and *before* any signing or
      // side-credential mint so a compromised account cannot exhaust KMS
      // budget. The three-component key correctly bounds total KMS load per
      // identity across all mint paths (issue/attenuate/renew); see
      // IssuanceRateLimitSubject for why jti and ip are intentionally excluded.
      await this.enforceIssuanceRateLimit({
        tenantId: userContext.tenantId,
        userId: userContext.userId,
        agentId: request.agentId,
      });

      // Step 1b: Enforce PIM-required roles.
      enforcePimRequiredRoles(
        userContext,
        request.agentId,
        this.pimRequiredRoles,
        this.auditLogger,
      );

      // Step 2: Determine capabilities based on user roles.
      this.logger.info('Determining capabilities based on user roles', {
        userId: userContext.userId,
        roles: userContext.roles,
        agentId: request.agentId,
      });

      let capabilities = mapRolesToCapabilitiesForPolicy(
        userContext.roles,
        this.policy,
        userContext.tenantId,
      );

      // Step 3: If specific capabilities were requested, validate them.
      if (request.requestedCapabilities) {
        this.assertRequestedWithinRoleScope(capabilities, request.requestedCapabilities);

        // Step 3b: enforce per-agent manifest constraint at issuance time.
        if (request.manifest) {
          validateAgainstManifest(
            request.manifest,
            request.agentId,
            request.requestedCapabilities,
          );
        }

        // Step 3c: enforce explicit user consent. Sensitive actions or
        // strict mode require it; even when not required, supplied
        // consent is still validated so a stale record is rejected.
        const requiresConsent =
          this.requireConsent ||
          requestedCapabilitiesIncludeSensitive(request.requestedCapabilities);

        if (requiresConsent || request.consent) {
          validateConsent(
            request.consent,
            userContext.userId,
            request.agentId,
            request.requestedCapabilities,
          );
        }

        capabilities = request.requestedCapabilities;
      } else if (this.requireConsent) {
        throw new CapabilityError(
          ErrorCode.INVALID_REQUEST,
          'Explicit user consent (requestedCapabilities + consent) is required by this issuer',
          400,
        );
      }

      // Step 3d: Conditional Access enforcement.
      enforceConditionalAccess(
        userContext,
        capabilities,
        request.agentId,
        this.auditLogger,
        this.actionResolver,
      );

      // Step 3e: Validate every typed condition before signing.
      validateConditionsForCapabilities(capabilities);

      // Step 4: Compute the payload validity window.
      const now = getCurrentTimestamp();
      let expiresAt = getExpirationTimestamp(this.defaultTTL);

      // Step 4b: Cap TTL to the smallest remaining `pim-active` window
      // across only the roles that contributed to the capability set.
      const contributingRoleSources = filterRolesContributingToCapabilities(
        userContext,
        capabilities,
        this.policy,
      );
      const pimCappedExpiry = computePimCappedExpiry(
        contributingRoleSources,
        this.capTtlToPimActivation,
        expiresAt,
      );
      if (pimCappedExpiry !== undefined) {
        if (pimCappedExpiry <= now) {
          this.denyExpiredPimActivation(request.agentId, userContext.userId, now, pimCappedExpiry);
        }
        if (pimCappedExpiry < expiresAt) {
          this.logger.info('Capping capability TTL to remaining PIM activation window', {
            agentId: request.agentId,
            userId: userContext.userId,
            requestedExp: expiresAt,
            cappedExp: pimCappedExpiry,
          });
          expiresAt = pimCappedExpiry;
        }
      }

      // Step 5: Build and sign the token.
      const tokenId = generateId();
      // F-2: resolve the DPoP key binding (if the agent supplied one).
      // We prefer the explicit thumbprint to avoid recomputing it; if
      // the agent only sent the JWK, derive the canonical SHA-256
      // thumbprint here. Failures parsing the JWK are reported as
      // INVALID_REQUEST so the operator can see what's wrong rather
      // than have the token silently mint without a binding.
      const dpopJkt = await this.resolveDpopJkt(request);
      const payload = buildIssuancePayload({
        issuerDid: this.issuerDid,
        agentId: request.agentId,
        iat: now,
        exp: expiresAt,
        jti: tokenId,
        capabilities,
        userContext,
        // Stamp the configured audience so tokens are bound to this
        // specific gateway (cross-tenant replay defence).
        audience: this.gatewayAudience,
        // F-7: stamp the originating region so audit consumers can
        // attribute the token after a regional failover. Falls back to
        // `undefined` (claim omitted) when no region is configured.
        region: this.region.length > 0 ? this.region : undefined,
        // F-2: stamp the holder-key binding when supplied.
        ...(dpopJkt ? { dpopJkt } : {}),
      });

      this.logger.info('Signing capability token', { tokenId, agentId: request.agentId });
      await this.attachIssuanceProofs(payload);
      // Build the signing intent context using the precomputed policy hash so
      // the hash cost is not paid on the hot path.  Pass it both to signPayload
      // (KMS back-end scoping) and stamp it into the payload itself so
      // attenuation/renewal can restore the original policy boundary without
      // re-hashing whatever policy version happens to be loaded at that time.
      payload.policyHash = this.cachedPolicyHash;
      const issuanceContext = buildIssuanceContext({
        policyHash: this.cachedPolicyHash,
        manifest: request.manifest,
        subject: request.agentId,
        audience: this.gatewayAudience,
      });
      const token = await signPayload(this.signer, payload, issuanceContext);

      // Step 5b: Mint short-lived cloud-storage and DB credentials.
      // IMPORTANT: this runs AFTER the JWT is signed (step 5 above) so
      // the KMS call completes before any broker code executes.  In
      // 'best-effort' mode a broker failure returns `{}` and the signed
      // JWT is still delivered — the KMS operation is never lost.
      const { storageGrants, dbCredentials } = await this.mintSideCredentials(
        token,
        request,
        userContext,
        capabilities,
        expiresAt - now,
      );

      // Step 6: Audit log the issuance.
      await this.logIssuance(
        userContext.userId,
        request.agentId,
        tokenId,
        capabilities,
        request.consent,
        storageGrants,
        dbCredentials,
      );

      // Step 6b: Push an inventory record (fire-and-forget).
      emitPostureRecord(this.postureEmitter, this.logger, {
        agentId: request.agentId,
        manifest: request.manifest,
        capabilities,
        region: this.postureRegion,
      });

      this.logger.info('Capability token issued successfully', {
        tokenId,
        agentId: request.agentId,
        userId: userContext.userId,
        expiresAt,
      });

      const response: IssueCapabilityResponse = {
        token,
        expiresAt,
        tokenId,
        capabilities,
      };
      if (storageGrants && storageGrants.length > 0) response.storageGrants = storageGrants;
      if (dbCredentials && dbCredentials.length > 0) response.dbCredentials = dbCredentials;
      return response;
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
        500,
      );
    }
  }

  /**
   * Validate that every requested capability is a subset of what the
   * user's roles allow. Resource matching uses the same wildcard-aware
   * `matchesResource` semantics as the gateway enforcement engine, so
   * role mappings that grant wildcard resources correctly authorize
   * requests for concrete resources beneath them.
   */
  private assertRequestedWithinRoleScope(
    roleDerived: CapabilityConstraint[],
    requested: CapabilityConstraint[],
  ): void {
    for (const req of requested) {
      const matchingCaps = roleDerived.filter((cap) =>
        matchesResource(req.resource, cap.resource),
      );
      if (matchingCaps.length === 0) {
        throw new CapabilityError(
          ErrorCode.INSUFFICIENT_PERMISSIONS,
          `User does not have permission for resource: ${req.resource}`,
          403,
        );
      }

      const allowedActions = new Set<string>();
      for (const cap of matchingCaps) {
        for (const action of cap.actions) {
          allowedActions.add(action);
        }
      }

      for (const action of req.actions) {
        if (!allowedActions.has(action)) {
          throw new CapabilityError(
            ErrorCode.INSUFFICIENT_PERMISSIONS,
            `User does not have permission for action '${action}' on resource: ${req.resource}`,
            403,
          );
        }
      }
    }
  }

  /**
   * Audit and throw when a contributing PIM activation has already
   * expired (or is within the safety margin). Minting a capability
   * with `exp` ≤ `iat` would produce an immediately-unusable token,
   * so deny instead so the caller can re-activate.
   */
  private denyExpiredPimActivation(
    agentId: string,
    userId: string,
    now: number,
    cappedExp: number,
  ): never {
    const auditEntry: AuditLogEntry = {
      id: generateId(),
      timestamp: new Date().toISOString(),
      eventType: 'issuance',
      agentId,
      userId,
      decision: 'deny',
      metadata: {
        reason: 'pim_activation_expired',
        cappedExp,
        now,
      },
    };
    this.auditLogger.warn(
      'Capability issuance denied: contributing PIM activation has expired',
      auditEntry,
    );
    throw new CapabilityError(
      ErrorCode.AUTHORIZATION_FAILED,
      'Contributing PIM activation has expired; re-activate and retry',
      403,
    );
  }

  /**
   * Apply a per-(tenant, user, agent) rate limit. When no limiter is
   * wired this is a no-op (back-compat). On exhaustion logs an
   * audit-deny entry, fires the optional metric callback, and throws
   * {@link CapabilityError} with {@link ErrorCode.RATE_LIMIT_EXCEEDED}
   * (HTTP 429).
   *
   * @param limiterKind - Human-readable label for the limiter, used in
   *   audit and log messages (e.g. `'issuance'`, `'storage-grant'`,
   *   `'db-token'`).
   */
  private async enforceIssuanceRateLimit(
    subject: IssuanceRateLimitSubject,
    limiter?: IssuanceRateLimiter,
    limiterKind: IssuanceLimiterKind = 'issuance',
  ): Promise<void> {
    const activeLimiter = limiter ?? this.issuanceRateLimiter;
    if (!activeLimiter) return;
    let decision: RateLimitDecision;
    try {
      decision = await activeLimiter.consume(subject);
    } catch (error) {
      // The limiter implementation already chose its failure mode
      // (see RedisIssuanceRateLimiter.failClosedOnError). When it
      // chose to propagate, treat the error as fail-closed here too:
      // the issuer cannot mint without a working limiter when one is
      // wired, otherwise the limit is bypassed silently.
      this.logger.error(
        `${limiterKind} rate limiter threw; failing closed (denying issuance)`,
        {
          tenantId: subject.tenantId,
          userId: subject.userId,
          agentId: subject.agentId,
          error: error instanceof Error ? error.message : 'Unknown error',
        },
      );
      this.notifyRateLimited(subject, 'limiter_unavailable', limiterKind);
      const auditEntry: AuditLogEntry = {
        id: generateId(),
        timestamp: new Date().toISOString(),
        eventType: 'issuance',
        agentId: subject.agentId,
        userId: subject.userId,
        decision: 'deny',
        metadata: {
          reason: `${limiterKind}_rate_limiter_unavailable`,
          tenantId: subject.tenantId ?? null,
        },
      };
      this.auditLogger.warn(
        `Capability issuance denied: ${limiterKind} rate limiter unavailable`,
        auditEntry,
      );
      throw new CapabilityError(
        ErrorCode.RATE_LIMIT_EXCEEDED,
        `${limiterKind} rate limiter is unavailable; please retry shortly`,
        429,
        // `Retry-After` mirrors the limiter's configured window: a
        // stampeding herd that retries inside the same window will
        // hit the same outage immediately, so the bound is the
        // earliest reasonable retry horizon. Reading `windowSeconds`
        // from the limiter (rather than the issuer's local config)
        // keeps the value correct when operators change the window
        // without restarting the issuer.
        { 'Retry-After': String(activeLimiter.windowSeconds) },
      );
    }
    if (decision.allowed) return;

    this.notifyRateLimited(subject, 'exceeded', limiterKind);
    const auditEntry: AuditLogEntry = {
      id: generateId(),
      timestamp: new Date().toISOString(),
      eventType: 'issuance',
      agentId: subject.agentId,
      userId: subject.userId,
      decision: 'deny',
      metadata: {
        reason: `${limiterKind}_rate_limit_exceeded`,
        tenantId: subject.tenantId ?? null,
        limit: decision.limit,
        windowSeconds: decision.windowSeconds,
        retryAfterSeconds: decision.retryAfterSeconds,
      },
    };
    this.auditLogger.warn(
      `Capability issuance denied: per-subject ${limiterKind} rate limit exceeded`,
      auditEntry,
    );
    throw new CapabilityError(
      ErrorCode.RATE_LIMIT_EXCEEDED,
      `${limiterKind} rate limit exceeded for this user/agent. Retry after ${decision.retryAfterSeconds}s.`,
      429,
      // RFC 9110 §10.2.3: `Retry-After` is the standard way to tell a
      // client to back off. Always populated for F-1 denials so the
      // SDK / agent runtime does not retry-storm.
      { 'Retry-After': String(decision.retryAfterSeconds) },
    );
  }

  private notifyRateLimited(
    subject: IssuanceRateLimitSubject,
    reason: 'exceeded' | 'limiter_unavailable',
    kind: IssuanceLimiterKind = 'issuance',
  ): void {
    if (!this.onIssuanceRateLimited) return;
    try {
      this.onIssuanceRateLimited(subject, reason, kind);
    } catch (error) {
      this.logger.warn('onIssuanceRateLimited callback threw', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  /**
   * Resolve the holder-key thumbprint to stamp on a freshly-issued
   * capability token's `cnf.jkt` claim (RFC 9449 / F-2). The agent
   * runtime supplies *either* a precomputed thumbprint (`dpopJkt`)
   * *or* the public JWK (`dpopJwk`); when both are absent the token
   * is minted as a plain bearer token (back-compat). When both are
   * supplied, `dpopJkt` wins and `dpopJwk` is ignored — matches the
   * documented contract in {@link IssueCapabilityRequest}.
   *
   * Throws {@link CapabilityError}({@link ErrorCode.INVALID_REQUEST})
   * when `dpopJwk` is supplied but is not a structurally valid JWK
   * we can hash, so the operator sees a clear 400 instead of a token
   * that silently mints without the binding it requested.
   */
  private async resolveDpopJkt(
    request: IssueCapabilityRequest,
  ): Promise<string | undefined> {
    if (typeof request.dpopJkt === 'string' && request.dpopJkt.length > 0) {
      // RFC 7638 SHA-256 thumbprints are exactly 32 raw bytes encoded
      // as 43 unpadded base64url characters. Reject anything else
      // here so a typo / wrong-algorithm value is caught at issuance
      // time — minting a token whose `cnf.jkt` no DPoP proof can
      // ever match would otherwise return a credential the gateway
      // is guaranteed to reject on first use, and the operator
      // would have to debug it from a 401 hours later.
      if (!isValidJwkThumbprint(request.dpopJkt)) {
        throw new CapabilityError(
          ErrorCode.INVALID_REQUEST,
          'dpopJkt must be a base64url-encoded SHA-256 JWK thumbprint (RFC 7638): 43 unpadded base64url characters.',
          400,
        );
      }
      return request.dpopJkt;
    }
    if (request.dpopJwk && typeof request.dpopJwk === 'object') {
      try {
        return await jwkToJkt(request.dpopJwk);
      } catch (err) {
        throw new CapabilityError(
          ErrorCode.INVALID_REQUEST,
          `dpopJwk is not a valid JWK: ${err instanceof Error ? err.message : 'unknown error'}`,
          400,
        );
      }
    }
    return undefined;
  }

  /**
   * Mint short-lived storage and DB credentials via the configured
   * {@link SideCredentialBroker}.
   *
   * KMS isolation: this method is called AFTER the capability JWT has
   * already been signed (see `issueCapability` step 5 → step 5b
   * ordering).  The signing key is therefore never accessed while
   * broker / cloud-credential code runs, so a crash or hang inside
   * the broker cannot interfere with the KMS call and cannot lose an
   * already-signed token when `sideCredentialFailureMode` is
   * `'best-effort'`.
   *
   * Dedicated per-(tenant, user, agent) rate limiters
   * ({@link storageGrantRateLimiter} and {@link dbTokenRateLimiter})
   * are enforced here — after identity resolution and after JWT
   * signing — before each cloud-credential mint.  These are
   * intentionally tighter than the main {@link issuanceRateLimiter}
   * because each mint produces a long-lived cloud credential (STS
   * session / RDS IAM token) rather than a short-lived capability JWT.
   *
   * Rate limiters are only consulted when at least one capability
   * in the request matches the relevant scheme (`storage://`, `db://`)
   * AND the broker reports that path as enabled.  This avoids
   * consuming quota on requests that would produce no cloud
   * credentials.
   *
   * Failure handling respects {@link sideCredentialFailureMode}:
   * `'fail-fast'` propagates errors (default / back-compat);
   * `'best-effort'` logs, fires {@link onSideCredentialError}, and
   * returns `{}` so the caller can return the JWT alone.
   */
  private async mintSideCredentials(
    signedToken: string,
    request: IssueCapabilityRequest,
    userContext: UserContext,
    capabilities: CapabilityConstraint[],
    capabilityTtlSeconds: number,
  ): Promise<{ storageGrants?: StorageGrant[]; dbCredentials?: DbCredential[] }> {
    const rateLimitSubject: IssuanceRateLimitSubject = {
      tenantId: userContext.tenantId,
      userId: userContext.userId,
      agentId: request.agentId,
    };

    // Enforce per-capability-type rate limits before calling the broker.
    // This keeps rate-limit policy in the issuer (a single audit/metrics
    // surface) regardless of whether the broker is in-process or HTTP.
    if (this.sideCredentialBroker.isStorageEnabled()) {
      const hasStorageCaps = capabilities.some(
        (c) => typeof c.resource === 'string' && c.resource.startsWith('storage://'),
      );
      if (hasStorageCaps && this.storageGrantRateLimiter) {
        await this.enforceIssuanceRateLimit(rateLimitSubject, this.storageGrantRateLimiter, 'storage-grant');
      }
    }
    if (this.sideCredentialBroker.isDbEnabled()) {
      const hasDbCaps = capabilities.some(
        (c) => typeof c.resource === 'string' && c.resource.startsWith('db://'),
      );
      if (hasDbCaps && this.dbTokenRateLimiter) {
        await this.enforceIssuanceRateLimit(rateLimitSubject, this.dbTokenRateLimiter, 'db-token');
      }
    }

    try {
      return await this.sideCredentialBroker.mint(signedToken, capabilities, {
        agentId: request.agentId,
        authorizedBy: userContext.userId,
        capabilityTtlSeconds,
        userRoles: userContext.roles,
        policy: this.policy,
      });
    } catch (err) {
      if (this.sideCredentialFailureMode === 'best-effort') {
        const error = err instanceof Error ? err : new Error(String(err));
        // `BrokerCallError` (thrown by `HttpSideCredentialBroker`) carries
        // an explicit `brokerKind` property — use it directly.  Any other
        // error type (in-process service failure, unexpected throw) is
        // classified as 'unknown' which is still useful for dashboarding.
        const kind: 'storage-grant' | 'db-token' | 'unknown' =
          err instanceof BrokerCallError ? err.brokerKind : 'unknown';
        this.logger.warn(
          `Side-credential broker failed (best-effort mode — JWT returned without side credentials)`,
          {
            kind,
            agentId: request.agentId,
            error: error.message,
          },
        );
        try {
          this.onSideCredentialError?.(kind, error);
        } catch {
          // swallow callback errors
        }
        return {};
      }
      throw err;
    }
  }

  /**
   * Log capability issuance for audit trail.
   *
   * Storage grants and DB credentials are summarized at the metadata
   * level (provider / resource / actions / expiresAt) — the credential
   * payload itself (SAS tokens, presigned URLs, AAD JWTs, RDS auth
   * tokens, OAuth access tokens) is **never** written to the audit log.
   * See `docs/sprint-3-4-gaps/07-storage-grants.md` § Risks.
   */
  private async logIssuance(
    userId: string,
    agentId: string,
    tokenId: string,
    capabilities: Array<{ resource: string; actions: string[] }>,
    consent?: UserConsent,
    storageGrants?: StorageGrant[],
    dbCredentials?: DbCredential[],
  ): Promise<void> {
    const auditEntry: AuditLogEntry = {
      id: generateId(),
      timestamp: new Date().toISOString(),
      eventType: 'issuance',
      agentId,
      userId,
      capabilityId: tokenId,
      decision: 'allow',
      metadata: {
        capabilities: capabilities.map((c) => ({
          resource: c.resource,
          actions: c.actions,
        })),
        ...(consent
          ? {
              consent: {
                consentId: consent.consentId,
                grantedAt: consent.grantedAt,
                expiresAt: consent.expiresAt,
              },
            }
          : {}),
        ...(storageGrants && storageGrants.length > 0
          ? {
              storageGrants: storageGrants.map((g) => ({
                grantId: g.grantId,
                provider: g.provider,
                resource: g.resource,
                actions: g.actions,
                expiresAt: g.expiresAt,
              })),
            }
          : {}),
        ...(dbCredentials && dbCredentials.length > 0
          ? {
              dbCredentials: dbCredentials.map((c) => ({
                grantId: c.grantId,
                provider: c.provider,
                resource: c.resource,
                actions: c.actions,
                expiresAt: c.expiresAt,
                host: c.host,
                port: c.port,
                database: c.database,
                username: c.username,
              })),
            }
          : {}),
      },
    };

    this.auditLogger.info('Capability token issued', auditEntry);
  }

  /**
   * Attenuate (reduce scope of) an existing capability token. The
   * child token will have equal or fewer privileges than the parent.
   */
  async attenuateCapability(
    parentToken: string,
    requestedCapabilities: CapabilityConstraint[],
    ttl?: number,
    // Retained for API compatibility and future use; see issueCapability.
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    _enforcement?: IssuerEnforcementContext,
  ): Promise<IssueCapabilityResponse> {
    try {
      this.logger.info('Attenuating capability token');

      const parentPayload = await verifyParentToken(
        this.signer,
        parentToken,
        { issuer: this.issuerDid, audience: this.gatewayAudience },
        'Invalid parent capability token format',
      );

      // Step 2: Validate parent token is not expired.
      const now = getCurrentTimestamp();
      if (parentPayload.exp < now) {
        throw new CapabilityError(
          ErrorCode.EXPIRED_TOKEN,
          'Parent capability token has expired',
          401,
        );
      }

      // Step 2a: Per-(tenantId, userId, agentId) rate limit for attenuation
      // (F-1). Shares the same three-component bucket as fresh issuance so
      // issue + attenuate + renew all compete for the same per-identity
      // budget — a compromised account cannot exhaust KMS by alternating
      // mint paths. See IssuanceRateLimitSubject for why jti and ip are
      // intentionally excluded from the key.
      await this.enforceIssuanceRateLimit({
        tenantId: parentPayload.authorizedBy?.tenantId,
        userId: parentPayload.authorizedBy?.userId ?? 'unknown',
        agentId: parentPayload.sub,
      });

      // Step 3: Validate requested capabilities are a subset of parent's.
      validateCapabilitySubset(parentPayload.capabilities, requestedCapabilities);

      // Step 3b: Validate the typed conditions on the attenuated set.
      // The child may carry a *narrower* condition set (e.g. a tighter
      // `maxCalls`) that must itself be well-formed.
      validateConditionsForCapabilities(requestedCapabilities);

      // Step 4: Calculate expiration (cannot exceed parent's expiration).
      const requestedTTL = ttl || this.defaultTTL;
      const expiresAt = Math.min(now + requestedTTL, parentPayload.exp);

      // Step 5: Build and sign the child token.
      const tokenId = generateId();
      const childPayload = buildAttenuatedPayload({
        issuerDid: this.issuerDid,
        parent: parentPayload,
        iat: now,
        exp: expiresAt,
        jti: tokenId,
        capabilities: requestedCapabilities,
      });

      this.logger.info('Signing attenuated capability token', {
        tokenId,
        parentTokenId: parentPayload.jti,
        agentId: parentPayload.sub,
      });
      await this.attachIssuanceProofs(childPayload);
      // Restore the policy hash from the parent token so the attenuated child
      // is signed under the same policy boundary as the original issuance,
      // regardless of any policy rollout that occurred between the two events.
      // Fall back to the service's current policy hash for legacy tokens that
      // pre-date the policyHash claim (present in all tokens issued by a
      // signing-intent-aware issuer, absent in older tokens).
      const attenuationPolicyHash = parentPayload.policyHash ?? this.cachedPolicyHash;
      const attenuationContext = buildIssuanceContext({
        policyHash: attenuationPolicyHash,
        subject: parentPayload.sub,
        audience: this.gatewayAudience,
      });
      const token = await signPayload(this.signer, childPayload, attenuationContext);

      // Step 6: Audit log the attenuation.
      await this.logAttenuation(
        parentPayload.sub,
        tokenId,
        parentPayload.jti,
        requestedCapabilities,
      );

      this.logger.info('Capability token attenuated successfully', {
        tokenId,
        parentTokenId: parentPayload.jti,
        agentId: parentPayload.sub,
      });

      return {
        token,
        expiresAt,
        tokenId,
        capabilities: requestedCapabilities,
      };
    } catch (error) {
      this.logger.error('Failed to attenuate capability token', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });

      try {
        mapVerifyError(
          error,
          'Parent capability token has expired',
          'Invalid parent capability token',
        );
      } catch (mapped) {
        if (mapped instanceof CapabilityError) throw mapped;
      }

      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        `Failed to attenuate capability: ${error instanceof Error ? error.message : 'Unknown error'}`,
        500,
      );
    }
  }

  /**
   * Log capability attenuation for audit trail.
   */
  private async logAttenuation(
    agentId: string,
    tokenId: string,
    parentTokenId: string,
    capabilities: CapabilityConstraint[],
  ): Promise<void> {
    const auditEntry: AuditLogEntry = {
      id: generateId(),
      timestamp: new Date().toISOString(),
      eventType: 'issuance', // Using issuance for now, could add 'attenuation' type
      agentId,
      capabilityId: tokenId,
      decision: 'allow',
      metadata: {
        parentCapabilityId: parentTokenId,
        capabilities: capabilities.map((c) => ({
          resource: c.resource,
          actions: c.actions,
        })),
      },
    };

    this.auditLogger.info('Capability token attenuated', auditEntry);
  }

  /**
   * Renew an existing capability token with a fresh expiration. Token
   * keeps the same capabilities but gets a new TTL.
   */
  async renewCapability(
    currentToken: string,
    ttl?: number,
    // Retained for API compatibility and future use; see issueCapability.
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    _enforcement?: IssuerEnforcementContext,
  ): Promise<IssueCapabilityResponse> {
    try {
      this.logger.info('Renewing capability token');

      const currentPayload = await verifyParentToken(
        this.signer,
        currentToken,
        { issuer: this.issuerDid, audience: this.gatewayAudience },
        'Invalid capability token format',
      );

      // Step 1a: Per-(tenantId, userId, agentId) rate limit for renewal (F-1).
      // An attacker holding a non-expired token can otherwise extend its
      // lineage forever in a tight renew loop, defeating short TTLs.
      // Shares the same three-component bucket as fresh issuance and
      // attenuation so the per-identity KMS budget covers all mint paths.
      await this.enforceIssuanceRateLimit({
        tenantId: currentPayload.authorizedBy?.tenantId,
        userId: currentPayload.authorizedBy?.userId ?? 'unknown',
        agentId: currentPayload.sub,
      });

      // Step 2: Build the renewed token.
      const now = getCurrentTimestamp();
      const expiresAt = getExpirationTimestamp(ttl || this.defaultTTL);
      const tokenId = generateId();
      const renewedPayload: CapabilityTokenPayload = buildRenewedPayload({
        issuerDid: this.issuerDid,
        current: currentPayload,
        iat: now,
        exp: expiresAt,
        jti: tokenId,
      });

      // Step 3: Sign the renewed token.
      this.logger.info('Signing renewed capability token', {
        tokenId,
        previousTokenId: currentPayload.jti,
        agentId: currentPayload.sub,
      });
      await this.attachIssuanceProofs(renewedPayload);
      // Restore the policy hash from the token being renewed so the new token
      // is signed under the same policy boundary as the original issuance.
      // Fall back to the service's current policy hash for legacy tokens issued
      // before the policyHash claim was introduced.
      const renewalPolicyHash = currentPayload.policyHash ?? this.cachedPolicyHash;
      const renewalContext = buildIssuanceContext({
        policyHash: renewalPolicyHash,
        subject: currentPayload.sub,
        audience: this.gatewayAudience,
      });
      const token = await signPayload(this.signer, renewedPayload, renewalContext);

      // Step 4: Audit log the renewal.
      await this.logRenewal(
        currentPayload.sub,
        tokenId,
        currentPayload.jti,
        currentPayload.capabilities,
      );

      this.logger.info('Capability token renewed successfully', {
        tokenId,
        previousTokenId: currentPayload.jti,
        agentId: currentPayload.sub,
      });

      return {
        token,
        expiresAt,
        tokenId,
        capabilities: currentPayload.capabilities,
      };
    } catch (error) {
      this.logger.error('Failed to renew capability token', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });

      try {
        mapVerifyError(
          error,
          'Capability token has expired; re-authentication is required',
          'Invalid capability token',
        );
      } catch (mapped) {
        if (mapped instanceof CapabilityError) throw mapped;
      }

      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        `Failed to renew capability: ${error instanceof Error ? error.message : 'Unknown error'}`,
        500,
      );
    }
  }

  /**
   * Log capability renewal for audit trail.
   */
  private async logRenewal(
    agentId: string,
    tokenId: string,
    previousTokenId: string,
    capabilities: CapabilityConstraint[],
  ): Promise<void> {
    const auditEntry: AuditLogEntry = {
      id: generateId(),
      timestamp: new Date().toISOString(),
      eventType: 'renewal',
      agentId,
      capabilityId: tokenId,
      decision: 'allow',
      metadata: {
        previousCapabilityId: previousTokenId,
        capabilities: capabilities.map((c) => ({
          resource: c.resource,
          actions: c.actions,
        })),
      },
    };

    this.auditLogger.info('Capability token renewed', auditEntry);
  }

  /**
   * Get public key for token verification.
   */
  async getPublicKey(): Promise<string> {
    return this.signer.getPublicKey();
  }

  /**
   * Get the JWKS (JSON Web Key Set) for this issuer.
   *
   * Derives the JWK from the active signer's public key (SPKI).  The
   * `kid` field in the returned JWK matches the `kid` placed in every
   * JWT protected header by this signer — callers can therefore use it
   * to verify tokens by key ID without a synchronized restart.
   *
   * **Single-key limitation**: this method publishes only the *active*
   * signer's key.  It does **not** publish old and new keys simultaneously.
   * During a signer rotation, tokens minted by the previous signer will be
   * rejected by gateways once they refresh their JWKS cache.  To achieve
   * zero-downtime rotation, wait for outstanding tokens signed with the
   * old key to expire before switching the signer (see the production
   * deployment checklist).  Future work: inject a "previous-key" buffer so
   * overlapping keys can be published during the rotation window.
   */
  async getJwks(): Promise<JwkSet> {
    const spki = await this.signer.getPublicKey();
    const kid = await this.signer.getKeyId();

    // Export the SPKI public key as a JWK using Node.js crypto so that we
    // don't need to pass the algorithm when importing (no chicken-and-egg).
    let jwkData: Record<string, unknown>;
    try {
      const keyObject = crypto.createPublicKey(spki);
      jwkData = keyObject.export({ format: 'jwk' }) as Record<string, unknown>;
    } catch {
      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        'Failed to export public key as JWK',
        500,
      );
    }

    // Determine algorithm: prefer the signer's own getAlgorithm() when
    // available (all SigningAdapter subclasses implement it), then try to
    // infer from the exported JWK key material, and omit `alg` only when
    // the algorithm genuinely cannot be determined (prevents advertising an
    // incorrect `alg` which would cause interoperability failures).
    const signerAlg: string | undefined =
      typeof this.signer.getAlgorithm === 'function'
        ? this.signer.getAlgorithm()
        : inferAlgFromJwk(jwkData);

    const keyEntry: Record<string, unknown> = {
      kty: String(jwkData['kty'] ?? 'RSA'),
      ...jwkData,
      kid,
      use: 'sig',
    };
    if (signerAlg) {
      keyEntry['alg'] = signerAlg;
    }

    return {
      keys: [keyEntry as import('@euno/common').JwkKey],
    };
  }

  /**
   * Thin protected wrapper preserved for tests that reach into the
   * pre-R-1 internal API. Delegates to the standalone
   * {@link validateCapabilitySubset} in `./issuance/attenuation`.
   * Marked `protected` (rather than `private`) so subclasses — and
   * the test-only type-cast that historically reached into this
   * method — keep working without TypeScript's `noUnusedLocals`
   * flagging it as dead code.
   */
  protected validateCapabilitySubset(
    parentCapabilities: CapabilityConstraint[],
    requestedCapabilities: CapabilityConstraint[],
  ): void {
    validateCapabilitySubset(parentCapabilities, requestedCapabilities);
  }
}
