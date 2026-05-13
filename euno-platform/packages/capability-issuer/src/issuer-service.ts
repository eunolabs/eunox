/**
 * Capability Issuer Service — thin facade.
 *
 * Owns the externally injected dependencies ({@link TokenSigner},
 * {@link IdentityProvider}, credential pipelines, posture emitter) and
 * the issuer configuration, but delegates all issuance / attenuation /
 * renewal mechanics to the per-endpoint controllers backed by a shared
 * {@link MintingPipeline}.
 *
 * Public API is fully preserved for backward compatibility.
 *
 * See `docs/IMPROVEMENTS_AND_REFACTORING.md` § R-1, R-3.
 */

import {
  ActionResolver,
  BUILTIN_ACTION_RESOLVER,
  CapabilityConstraint,
  CapabilityError,
  Cosigner,
  DEFAULT_ROLE_CAPABILITY_MAP,
  ErrorCode,
  IdentityProvider,
  IssuanceRateLimitSubject,
  IssuanceRateLimiter,
  IssueCapabilityRequest,
  IssueCapabilityResponse,
  JwkSet,
  Logger,
  PostureEmitterLike,
  RoleCapabilityPolicy,
  TokenSigner,
  TransparencyLog,
  UserContext,
  createAuditLogger,
} from '@euno/common';
import * as crypto from 'crypto';
import type TransportStream from 'winston-transport';
import { DbTokenService } from './db-token';
import { StorageGrantService } from './storage-grant';
import {
  InProcessSideCredentialBroker,
  SideCredentialBroker,
} from './side-credential-broker';
import {
  AttenuateController,
  IssueController,
  IssueFromUserContextRequest,
  MintingPipeline,
  RenewalController,
  computeCapabilityPolicyHash,
  validateCapabilitySubset,
} from './issuance';

// Re-export PostureEmitterLike from this module for backwards
// compatibility — it now lives in `@euno/common` (per R-1's
// "Promote `PostureEmitterLike` into `@euno/common`" item) but
// older callers and tests import it from this file.
export type { PostureEmitterLike } from '@euno/common';

// Re-export IssuanceLimiterKind from the pipeline module so the type
// continues to be importable from this file.
export type { IssuanceLimiterKind } from './issuance';

/**
 * Infer a JWS algorithm from exported JWK key material when the signer
 * does not expose `getAlgorithm()`.
 *
 * Returns `undefined` when the algorithm cannot be determined with confidence
 * (e.g. RSA keys, which support several algorithm families) so that callers
 * can omit `alg` rather than advertising an incorrect value.
 */
function inferAlgFromJwk(jwkData: Record<string, unknown>): string | undefined {
  const kty = String(jwkData['kty'] ?? '');
  const crv = typeof jwkData['crv'] === 'string' ? jwkData['crv'] : undefined;

  switch (kty) {
    case 'EC':
      switch (crv) {
        case 'P-256': return 'ES256';
        case 'P-384': return 'ES384';
        case 'P-521': return 'ES512';
        default: return undefined;
      }
    case 'OKP':
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
   * `storage://{cloud}/{bucket}/...` form.
   */
  storageGrantService?: StorageGrantService;
  /**
   * Optional DB-token service. When supplied and enabled, the issuer
   * mints short-lived IAM-bound database credentials alongside the VC
   * for every capability whose resource matches the canonical
   * `db://{cloud}/{instance}/...` form.
   */
  dbTokenService?: DbTokenService;
  /**
   * Operator-declared list of role display names that MUST be currently
   * active via Privileged Identity Management (or equivalent JIT
   * elevation). Issuance is denied when any of these roles appears in
   * the user's resolved roles but is not in `pim-active` state in
   * `userContext.roleSources`.
   */
  pimRequiredRoles?: string[];
  /**
   * When true, capability TTL is capped at the smallest remaining
   * `pim-active` window across all roles in
   * `userContext.roleSources`. Defaults to true.
   */
  capTtlToPimActivation?: boolean;
  /**
   * Optional AI posture-management emitter. When supplied, the issuer
   * awaits {@link PostureEmitterLike.emitObserved} immediately after
   * signing each token so the inventory record is durably enqueued
   * before any other async work proceeds. With
   * {@link DurablePostureEmitter} this is a sub-millisecond synchronous
   * SQLite WAL write; with the basic {@link PostureEmitter} the plugin
   * I/O is awaited inline (adds network latency). Failures are caught
   * and logged but never affect issuance.
   * See `docs/sprint-3-4-gaps/09-ai-posture-inventory.md`.
   */
  postureEmitter?: PostureEmitterLike;
  /**
   * Logical region tag for this issuer instance (F-7).
   */
  region?: string;
  /**
   * @deprecated Use {@link region}. Retained for back-compat.
   */
  postureRegion?: string;
  /**
   * Optional per-(tenant, user, agent) issuance rate limiter (F-1).
   */
  issuanceRateLimiter?: IssuanceRateLimiter;
  /**
   * Optional callback fired whenever any of the issuance rate limiters
   * (main, storage-grant, or db-token) denies an issuance.
   */
  onIssuanceRateLimited?: (
    subject: IssuanceRateLimitSubject,
    reason: 'exceeded' | 'limiter_unavailable',
    kind?: import('./issuance').IssuanceLimiterKind,
  ) => void;
  /**
   * Optional dedicated per-(tenant, user, agent) rate limiter for
   * storage-grant issuance.
   */
  storageGrantRateLimiter?: IssuanceRateLimiter;
  /**
   * Optional dedicated per-(tenant, user, agent) rate limiter for
   * DB-token issuance.
   */
  dbTokenRateLimiter?: IssuanceRateLimiter;
  /**
   * Optional side-credential broker. Preferred over legacy
   * `storageGrantService` / `dbTokenService` options.
   */
  sideCredentialBroker?: SideCredentialBroker;
  /**
   * Controls what happens when the side-credential broker throws an
   * unrecoverable error.
   *
   * - `'fail-fast'` *(default)*: error propagates (502/500).
   * - `'best-effort'`: logs and returns the JWT alone.
   */
  sideCredentialFailureMode?: 'fail-fast' | 'best-effort';
  /**
   * Optional callback fired when the side-credential broker fails in
   * `'best-effort'` mode.
   */
  onSideCredentialError?: (
    kind: 'storage-grant' | 'db-token' | 'unknown',
    error: Error,
  ) => void;
  /**
   * Optional pluggable {@link ActionResolver} (R-7).
   */
  actionResolver?: ActionResolver;
  /**
   * Optional additional winston transports for the audit logger.
   */
  auditTransports?: TransportStream[];
  /**
   * Audience string stamped into the `aud` JWT claim of every capability
   * token this issuer mints. Defaults to `"tool-gateway"`.
   */
  gatewayAudience?: string;
  /**
   * Optional list of independent {@link Cosigner}s that countersign
   * every issuance receipt.
   */
  cosigners?: ReadonlyArray<Cosigner>;
  /**
   * Optional list of {@link TransparencyLog} clients submitted-to on
   * every issuance.
   */
  transparencyLogs?: ReadonlyArray<TransparencyLog>;
}

/**
 * CapabilityIssuerService — thin public facade.
 *
 * Constructs a {@link MintingPipeline} and three per-endpoint
 * controllers, then delegates every public operation to them.
 * Preserves the pre-R-3 constructor signature and return types so
 * existing callers require no changes.
 */
export class CapabilityIssuerService {
  /**
   * Effective region tag (F-7). Empty string means "not configured".
   * Exposed read-only so the HTTP layer can surface it on
   * `/.well-known/capability-issuer` without re-reading the env var.
   */
  private readonly region: string;

  /**
   * The configured global identity provider. Stored here so
   * {@link getIdentityProvider} can return it for callers that need to
   * perform token validation outside the standard issuance pipeline (e.g.
   * the OIDC code-exchange endpoint).
   */
  private readonly globalIdentityProvider: IdentityProvider;

  /**
   * Shared minting machinery backing all three controllers.
   */
  private readonly pipeline: MintingPipeline;

  /** Fresh-issuance handler. */
  private readonly issueCtrl: IssueController;
  /** Attenuation handler. */
  private readonly attenuateCtrl: AttenuateController;
  /** Renewal handler. */
  private readonly renewCtrl: RenewalController;

  constructor(
    signer: TokenSigner,
    identityProvider: IdentityProvider,
    issuerDid: string,
    defaultTTL: number = 900,
    logger: Logger,
    options: CapabilityIssuerServiceOptions = {},
  ) {
    this.globalIdentityProvider = identityProvider;
    // F-7: `region` is the canonical setting; `postureRegion` is the
    // legacy fallback so existing wiring keeps working unchanged.
    this.region = options.region ?? options.postureRegion ?? '';
    const postureRegion = this.region.length > 0 ? this.region : 'unknown';

    // Build the audit logger once and share it between the pipeline and
    // the controllers — all three paths emit to the same logger instance.
    const auditLogger = createAuditLogger('capability-issuer', { region: this.region });
    if (options.auditTransports) {
      for (const t of options.auditTransports) {
        auditLogger.add(t);
      }
    }

    const policy: RoleCapabilityPolicy = options.policy ?? { default: DEFAULT_ROLE_CAPABILITY_MAP };

    // Broker resolution order:
    //   1. Explicit `sideCredentialBroker` (recommended for microservice deployments).
    //   2. Legacy `storageGrantService` / `dbTokenService` wrapped in an
    //      `InProcessSideCredentialBroker` (back-compat for existing configs).
    //   3. An empty in-process broker (neither service configured — no-op).
    const sideCredentialBroker: SideCredentialBroker = options.sideCredentialBroker
      ?? new InProcessSideCredentialBroker({
        storageGrantService: options.storageGrantService,
        dbTokenService: options.dbTokenService,
      });

    this.pipeline = new MintingPipeline({
      signer,
      issuerDid,
      gatewayAudience: options.gatewayAudience ?? 'tool-gateway',
      cachedPolicyHash: computeCapabilityPolicyHash(policy),
      policy,
      issuanceRateLimiter: options.issuanceRateLimiter,
      storageGrantRateLimiter: options.storageGrantRateLimiter,
      dbTokenRateLimiter: options.dbTokenRateLimiter,
      onIssuanceRateLimited: options.onIssuanceRateLimited,
      sideCredentialBroker,
      sideCredentialFailureMode: options.sideCredentialFailureMode ?? 'fail-fast',
      onSideCredentialError: options.onSideCredentialError,
      cosigners: options.cosigners ?? [],
      transparencyLogs: options.transparencyLogs ?? [],
      auditLogger,
      logger,
    });

    this.issueCtrl = new IssueController(this.pipeline, {
      identityProvider,
      requireConsent: options.requireConsent,
      policy,
      pimRequiredRoles: options.pimRequiredRoles ?? [],
      capTtlToPimActivation: options.capTtlToPimActivation !== false,
      postureEmitter: options.postureEmitter,
      postureRegion,
      tokenRegion: this.region,
      actionResolver: options.actionResolver ?? BUILTIN_ACTION_RESOLVER,
      defaultTtl: defaultTTL,
      auditLogger,
      logger,
    });

    this.attenuateCtrl = new AttenuateController(this.pipeline, { defaultTtl: defaultTTL });
    this.renewCtrl = new RenewalController(this.pipeline, { defaultTtl: defaultTTL });
  }

  // ── Public API ────────────────────────────────────────────────────────────

  /**
   * Logical region tag for this issuer instance (F-7). Returns the
   * empty string when no region is configured.
   */
  getRegion(): string {
    return this.region;
  }

  /**
   * Returns the global identity provider configured for this issuer instance.
   * Used by the OIDC code-exchange endpoint to perform token validation
   * against the right IdP when no per-tenant override is present.
   */
  getIdentityProvider(): IdentityProvider {
    return this.globalIdentityProvider;
  }

  /**
   * Issue a capability token from a pre-validated {@link UserContext}.
   *
   * Equivalent to {@link issueCapability} but skips the identity-provider
   * token validation step. Use this when the caller has already validated
   * the upstream IdP token (e.g. the OIDC code-exchange endpoint), so that
   * the validation is not repeated and per-tenant IdP adapters are honoured
   * correctly.
   */
  async issueCapabilityFromUserContext(
    request: IssueFromUserContextRequest,
    enforcement?: IssuerEnforcementContext,
  ): Promise<IssueCapabilityResponse> {
    return this.issueCtrl.handleFromUserContext(request, enforcement);
  }

  /**
   * Issue a capability token. Coordinates the issuance pipeline:
   * authenticate → role-derive → enforce manifest/consent/CA/conditions
   * → cap TTL to PIM → build payload → sign → mint side-credentials →
   * audit → emit posture.
   */
  async issueCapability(
    request: IssueCapabilityRequest,
    enforcement?: IssuerEnforcementContext,
  ): Promise<IssueCapabilityResponse> {
    return this.issueCtrl.handle(request, enforcement);
  }

  /**
   * Attenuate (reduce scope of) an existing capability token. The
   * child token will have equal or fewer privileges than the parent.
   */
  async attenuateCapability(
    parentToken: string,
    requestedCapabilities: CapabilityConstraint[],
    ttl?: number,
    enforcement?: IssuerEnforcementContext,
  ): Promise<IssueCapabilityResponse> {
    return this.attenuateCtrl.handle(parentToken, requestedCapabilities, ttl, enforcement);
  }

  /**
   * Renew an existing capability token with a fresh expiration. Token
   * keeps the same capabilities but gets a new TTL.
   */
  async renewCapability(
    currentToken: string,
    ttl?: number,
    enforcement?: IssuerEnforcementContext,
  ): Promise<IssueCapabilityResponse> {
    return this.renewCtrl.handle(currentToken, ttl, enforcement);
  }

  /**
   * Get public key for token verification.
   */
  async getPublicKey(): Promise<string> {
    return this.pipeline.signer.getPublicKey();
  }

  /**
   * Get the JWKS (JSON Web Key Set) for this issuer.
   *
   * Derives the JWK from the active signer's public key (SPKI). The
   * `kid` field in the returned JWK matches the `kid` placed in every
   * JWT protected header by this signer.
   *
   * **Single-key limitation**: this method publishes only the *active*
   * signer's key. During a signer rotation, tokens minted by the
   * previous signer will be rejected by gateways once they refresh
   * their JWKS cache. To achieve zero-downtime rotation, wait for
   * outstanding tokens signed with the old key to expire before
   * switching the signer.
   */
  async getJwks(): Promise<JwkSet> {
    const spki = await this.pipeline.signer.getPublicKey();
    const kid = await this.pipeline.signer.getKeyId();

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

    const signerAlg: string | undefined =
      typeof this.pipeline.signer.getAlgorithm === 'function'
        ? this.pipeline.signer.getAlgorithm()
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
