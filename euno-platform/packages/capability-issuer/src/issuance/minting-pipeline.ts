/**
 * MintingPipeline — shared issuance machinery.
 *
 * Encapsulates the stateful dependencies and reusable steps that are
 * common to all three mint operations (issue / attenuate / renew):
 *
 *   • DPoP key-binding resolution
 *   • Per-subject rate-limit enforcement
 *   • Cosignature + transparency-log proof attachment
 *   • JWT signing via the configured {@link TokenSigner}
 *   • Side-credential minting via the {@link SideCredentialBroker}
 *   • Metric callback notification
 *
 * Nothing in this class is request-routing logic; it is a value object
 * that the per-endpoint controllers delegate to.
 *
 * See `docs/IMPROVEMENTS_AND_REFACTORING.md` § R-3.
 */

import {
  AuditLogEntry,
  CapabilityConstraint,
  CapabilityError,
  CapabilityTokenPayload,
  Cosigner,
  cosignPayload,
  DbCredential,
  ErrorCode,
  IssuanceContext,
  IssuanceRateLimitSubject,
  IssuanceRateLimiter,
  Logger,
  RateLimitDecision,
  RoleCapabilityPolicy,
  StorageGrant,
  TokenSigner,
  TransparencyLog,
  UserContext,
  generateId,
  jwkToJkt,
  witnessPayload,
} from '@euno/common';
import type { IssueCapabilityRequest } from '@euno/common';
import { BrokerCallError, SideCredentialBroker } from '../side-credential-broker';
import { signPayload } from './signer-pipeline';
import { computeCapabilityPolicyHash } from './issuance-context';

/**
 * Minimal request shape needed by {@link MintingPipeline.mintSideCredentials}.
 * Both {@link IssueCapabilityRequest} and {@link IssueFromUserContextRequest}
 * satisfy this interface because only `agentId` is used in that path.
 */
interface MintRequestMinimal {
  agentId: string;
}

/**
 * Identifies which rate limiter fired when the `onIssuanceRateLimited`
 * callback is invoked. Typed union prevents unbounded label values from
 * accidentally reaching Prometheus metric labels or audit log `reason` fields.
 */
export type IssuanceLimiterKind = 'issuance' | 'storage-grant' | 'db-token';

/**
 * RFC 7638 SHA-256 JWK thumbprint validator.
 * A correct value is the raw 32-byte SHA-256 digest base64url-encoded
 * *without* padding — exactly 43 characters from the URL-safe alphabet.
 */
const JWK_THUMBPRINT_PATTERN = /^[A-Za-z0-9_-]{43}$/;
function isValidJwkThumbprint(value: string): boolean {
  return JWK_THUMBPRINT_PATTERN.test(value);
}

export interface MintingPipelineOptions {
  /** Token signer. All three mint paths share the same key. */
  signer: TokenSigner;
  /** DID of this issuer, stamped on every minted token's `iss` claim. */
  issuerDid: string;
  /**
   * Audience claim stamped on every minted token's `aud` claim.
   * Defaults to `"tool-gateway"`.
   */
  gatewayAudience?: string;
  /**
   * Pre-computed SHA-256 hex digest of the capability-relevant portions
   * of the role-capability policy. Computed once at construction time.
   */
  cachedPolicyHash: string;
  /**
   * Effective role-capability policy. Needed by the side-credential
   * broker for username lookup when minting DB credentials.
   */
  policy: RoleCapabilityPolicy;
  /** Optional per-(tenant, user, agent) issuance rate limiter (F-1). */
  issuanceRateLimiter?: IssuanceRateLimiter;
  /** Optional dedicated rate limiter for storage-grant issuance. */
  storageGrantRateLimiter?: IssuanceRateLimiter;
  /** Optional dedicated rate limiter for DB-token issuance. */
  dbTokenRateLimiter?: IssuanceRateLimiter;
  /** Optional callback fired whenever any rate limiter denies issuance. */
  onIssuanceRateLimited?: (
    subject: IssuanceRateLimitSubject,
    reason: 'exceeded' | 'limiter_unavailable',
    kind?: IssuanceLimiterKind,
  ) => void;
  /** Broker that encapsulates all side-credential minting. */
  sideCredentialBroker: SideCredentialBroker;
  /**
   * Controls broker failure handling:
   * - `'fail-fast'` (default): propagates errors (HTTP 502/500)
   * - `'best-effort'`: logs and returns JWT alone without side credentials
   */
  sideCredentialFailureMode?: 'fail-fast' | 'best-effort';
  /** Optional callback fired when the broker fails in `'best-effort'` mode. */
  onSideCredentialError?: (
    kind: 'storage-grant' | 'db-token' | 'unknown',
    error: Error,
  ) => void;
  /**
   * Independent cosigners attached to every issued / attenuated /
   * renewed token. Empty array = cosignature disabled (back-compat).
   */
  cosigners?: ReadonlyArray<Cosigner>;
  /**
   * Transparency-log clients submitted-to on every issuance. Empty
   * array = transparency logging disabled (back-compat).
   */
  transparencyLogs?: ReadonlyArray<TransparencyLog>;
  /** Audit logger for structured issuance records. */
  auditLogger: Logger;
  /** Operational logger for info/warn/error lines. */
  logger: Logger;
}

/**
 * MintingPipeline — shared machinery for the three issuance operations.
 *
 * Owns the signing key, rate limiters, side-credential broker, proof
 * attachers, and audit logger. The per-endpoint controllers call into
 * it rather than duplicating these concerns.
 */
/** Atomic snapshot of the active policy and its pre-computed hash. */
export interface PolicySnapshot {
  policy: RoleCapabilityPolicy;
  hash: string;
}

export class MintingPipeline {
  readonly signer: TokenSigner;
  readonly issuerDid: string;
  readonly gatewayAudience: string;

  // Stored as a single object so that `updatePolicy()` can replace both
  // fields in one assignment — a single reference write is atomic in the
  // JS engine, so an in-flight `handle()` that reads `policySnapshot` once
  // at the top will always see a consistent (policy, hash) pair.
  private _policyState: PolicySnapshot;

  /** Active role → capability policy (read from the current snapshot). */
  get policy(): RoleCapabilityPolicy {
    return this._policyState.policy;
  }

  /**
   * Pre-computed SHA-256 hash of the active policy (read from the current
   * snapshot). Stamped on every minted token's `policyHash` claim.
   */
  get cachedPolicyHash(): string {
    return this._policyState.hash;
  }

  /**
   * Atomic snapshot of the currently active policy together with its
   * pre-computed hash.  Callers that read both values (e.g. the issuance
   * handler) should capture this once at the top of their call, before any
   * `await`, to guarantee they observe a consistent pair even if a SIGHUP
   * hot-reload fires during an in-flight async operation.
   */
  get policySnapshot(): PolicySnapshot {
    return this._policyState;
  }

  private readonly issuanceRateLimiter?: IssuanceRateLimiter;
  private readonly storageGrantRateLimiter?: IssuanceRateLimiter;
  private readonly dbTokenRateLimiter?: IssuanceRateLimiter;
  private readonly onIssuanceRateLimited?: (
    subject: IssuanceRateLimitSubject,
    reason: 'exceeded' | 'limiter_unavailable',
    kind?: IssuanceLimiterKind,
  ) => void;
  private readonly sideCredentialBroker: SideCredentialBroker;
  readonly sideCredentialFailureMode: 'fail-fast' | 'best-effort';
  private readonly onSideCredentialError?: (
    kind: 'storage-grant' | 'db-token' | 'unknown',
    error: Error,
  ) => void;
  private readonly cosigners: ReadonlyArray<Cosigner>;
  private readonly transparencyLogs: ReadonlyArray<TransparencyLog>;
  readonly auditLogger: Logger;
  readonly logger: Logger;

  constructor(opts: MintingPipelineOptions) {
    this.signer = opts.signer;
    this.issuerDid = opts.issuerDid;
    this.gatewayAudience = opts.gatewayAudience ?? 'tool-gateway';
    this._policyState = { policy: opts.policy, hash: opts.cachedPolicyHash };
    this.issuanceRateLimiter = opts.issuanceRateLimiter;
    this.storageGrantRateLimiter = opts.storageGrantRateLimiter;
    this.dbTokenRateLimiter = opts.dbTokenRateLimiter;
    this.onIssuanceRateLimited = opts.onIssuanceRateLimited;
    this.sideCredentialBroker = opts.sideCredentialBroker;
    this.sideCredentialFailureMode = opts.sideCredentialFailureMode ?? 'fail-fast';
    this.onSideCredentialError = opts.onSideCredentialError;
    this.cosigners = opts.cosigners ?? [];
    this.transparencyLogs = opts.transparencyLogs ?? [];
    this.auditLogger = opts.auditLogger;
    this.logger = opts.logger;
  }

  // ── Hot-reload ────────────────────────────────────────────────────────────

  /**
   * Hot-reload the active role → capability policy.
   *
   * Called by the admin API route after a mutation is persisted (or by
   * the SIGHUP handler after re-reading the Postgres store).  Updates
   * both the in-memory policy reference (used by the side-credential
   * broker for DB username lookup) and the cached policy hash (stamped
   * on every minted token's `policyHash` claim).
   */
  updatePolicy(policy: RoleCapabilityPolicy): void {
    // Single reference assignment — both `policy` and `hash` are visible
    // together atomically to any subsequent read of `policySnapshot`.
    this._policyState = { policy, hash: computeCapabilityPolicyHash(policy) };
  }

  // ── DPoP ─────────────────────────────────────────────────────────────────

  /**
   * Resolve the holder-key thumbprint to stamp on a freshly-issued
   * capability token's `cnf.jkt` claim (RFC 9449 / F-2).
   *
   * The agent runtime supplies *either* a precomputed thumbprint
   * (`dpopJkt`) *or* the public JWK (`dpopJwk`). When both are absent
   * the token is minted as a plain bearer token (back-compat). When both
   * are supplied, `dpopJkt` wins.
   */
  async resolveDpopJkt(
    request: Pick<IssueCapabilityRequest, 'dpopJkt' | 'dpopJwk'>,
  ): Promise<string | undefined> {
    if (typeof request.dpopJkt === 'string' && request.dpopJkt.length > 0) {
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

  // ── Rate limiting ─────────────────────────────────────────────────────────

  /**
   * Enforce the per-(tenant, user, agent) rate limit. No-op when no
   * limiter is wired. On exhaustion logs an audit-deny entry, fires the
   * optional metric callback, and throws with HTTP 429.
   */
  async enforceRateLimit(
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

  /** Returns the dedicated storage-grant rate limiter, if wired. */
  getStorageGrantRateLimiter(): IssuanceRateLimiter | undefined {
    return this.storageGrantRateLimiter;
  }

  /** Returns the dedicated DB-token rate limiter, if wired. */
  getDbTokenRateLimiter(): IssuanceRateLimiter | undefined {
    return this.dbTokenRateLimiter;
  }

  // ── Proof attachment ──────────────────────────────────────────────────────

  /**
   * Attach the configured `proofs` claim (cosignatures + transparency-log
   * SCTs) to a freshly-built payload, in place. No-op when neither
   * cosigners nor transparency logs are configured (back-compat).
   *
   * Cosigner / log failures abort the issuance — minting a token whose
   * cosignature or SCT silently failed degrades to single-signer trust.
   */
  async attachProofs(
    payload: CapabilityTokenPayload,
  ): Promise<CapabilityTokenPayload> {
    if (this.cosigners.length === 0 && this.transparencyLogs.length === 0) {
      return payload;
    }
    // Cosignature + transparency-log submission run in parallel: their
    // outputs are independent and serialising them adds both latencies.
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

  // ── Signing ───────────────────────────────────────────────────────────────

  /**
   * Sign a payload with the configured TokenSigner, using the supplied
   * signing-intent context for KMS policy-scoping.
   */
  async signToken(payload: CapabilityTokenPayload, context: IssuanceContext): Promise<string> {
    return signPayload(this.signer, payload, context);
  }

  // ── Side credentials ──────────────────────────────────────────────────────

  /**
   * Mint short-lived storage and DB credentials via the configured
   * {@link SideCredentialBroker}.
   *
   * KMS isolation: callers MUST invoke this AFTER the capability JWT has
   * been signed so the signing key is never accessed while broker code runs.
   *
   * Dedicated per-type rate limiters are enforced before each cloud-
   * credential mint.
   */
  async mintSideCredentials(
    signedToken: string,
    request: MintRequestMinimal,
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
    if (this.sideCredentialBroker.isStorageEnabled()) {
      const hasStorageCaps = capabilities.some(
        (c) => typeof c.resource === 'string' && c.resource.startsWith('storage://'),
      );
      if (hasStorageCaps && this.storageGrantRateLimiter) {
        await this.enforceRateLimit(rateLimitSubject, this.storageGrantRateLimiter, 'storage-grant');
      }
    }
    if (this.sideCredentialBroker.isDbEnabled()) {
      const hasDbCaps = capabilities.some(
        (c) => typeof c.resource === 'string' && c.resource.startsWith('db://'),
      );
      if (hasDbCaps && this.dbTokenRateLimiter) {
        await this.enforceRateLimit(rateLimitSubject, this.dbTokenRateLimiter, 'db-token');
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
}
