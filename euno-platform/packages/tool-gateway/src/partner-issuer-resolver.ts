/**
 * Partner-Issuer Trust Resolver
 *
 * Implements the "trust a remote organization's capability issuer" half of
 * the cross-org harness (see `docs/sprint-3-4-gaps/05-cross-org-trust-harness.md`).
 *
 * The default `JWTTokenVerifier` was built around a single shared SPKI
 * public key fetched from the gateway's own issuer at start-up.  For
 * cross-org delegation the gateway must additionally accept JWTs from
 * pre-declared *partner* DIDs and verify their signatures against keys
 * advertised in each partner's DID document.
 *
 * Trust model (declarative, not transitive):
 *   - The gateway operator opts a partner DID into trust via the
 *     {@link PartnerDidRegistry} (two-eyes workflow, optional pin) **or**
 *     the legacy `TRUSTED_PARTNER_DIDS` env-var (backwards-compat, no pin).
 *   - For each trusted DID, the resolver fetches the DID document via
 *     `resolveDID()` and caches the resulting (alg, public-key) pair for
 *     `cacheTtlMs` (default 5 minutes).  A signature failure invalidates
 *     the cache so an out-of-band key rotation is picked up on the next
 *     attempt.
 *   - Failed resolutions are negatively-cached for `negativeCacheTtlMs`
 *     (default 30 s) to absorb transient resolver outages without
 *     amplifying traffic — shorter than the positive TTL so key rotations
 *     are never blocked for long.
 *   - The default issuer (the gateway's own SPKI) is *unaffected* when
 *     no partner DIDs are configured.
 */

import * as jose from 'jose';
import {
  CapabilityError,
  ErrorCode,
  Logger,
  createAuditLogger,
  RedisCircuitBreaker,
  CircuitOpenError,
  type CircuitBreakerOptions,
  type CircuitState,
} from '@euno/common';
import {
  resolveDID,
  resolveDidIon,
  findVerificationMethod,
  extractPublicKeyPem,
  determineSigningAlgorithm,
  parseDidWebHttpAllowList,
  type DIDDocument,
  type VerificationMethod,
} from '@euno/capability-issuer/adapters';
import {
  PartnerDidRegistry,
  PartnerDidEntry,
  jcsSha256,
  fetchJson,
  verifyPinAttestation,
} from './partner-did-registry';

/** Cached entry for one (DID, kid?) pair. */
interface CachedKey {
  /** Imported jose key object — algorithm is fixed to `alg` below. */
  key: jose.KeyLike | Uint8Array;
  /** Algorithm to use with this key (e.g. `EdDSA`, `ES256`). */
  alg: string;
  /** Wall-clock expiry (ms since epoch) for cache invalidation. */
  expiresAt: number;
}

/** Negative cache entry: records a DID-level resolution failure with its own (shorter) TTL.
 *
 * Keyed by DID only (not DID::kid) so that:
 *  (a) all kid variants for a DID share one entry — bounded by the trusted-DID set, and
 *  (b) an attacker sending tokens with a trusted `iss` but many random `kid` values
 *      cannot grow this map unboundedly.
 *
 * "Kid not found" failures are NOT stored here: when the DID document was resolved
 * successfully the positive cache already holds the result, and a missing-kid failure
 * is cheap to repeat (just a Map lookup + kid scan), so negative caching adds no value
 * and would expose an amplification surface.
 */
interface NegativeCacheEntry {
  /** Wall-clock expiry (ms since epoch) after which a re-resolution attempt is allowed. */
  expiresAt: number;
}

export interface PartnerIssuerResolverOptions {
  /**
   * Set of issuer DIDs the gateway is willing to trust (legacy path).
   * Tokens whose `iss` claim is not present in this set (and not active in
   * the registry) are rejected before any network resolution is attempted.
   */
  trustedIssuerDids: string[];
  /**
   * Optional registry.  When supplied `trusts(did)` returns true if the DID
   * is `active` in the registry **or** present in `trustedIssuerDids`.  The
   * registry also supplies pin material for `getKey()`.
   */
  registry?: PartnerDidRegistry;
  /** TTL for successfully cached resolver results (default 5 minutes). */
  cacheTtlMs?: number;
  /**
   * TTL for negatively-cached (failed-resolution) entries (default 30 s).
   * A shorter window than `cacheTtlMs` absorbs transient outages without
   * pinning a stale denial for a long time.  Set to 0 to disable negative
   * caching.
   */
  negativeCacheTtlMs?: number;
  /**
   * Optional structured logger.  When supplied, the resolver emits an
   * audit-level event on every cache miss (DID document re-fetch) and on
   * every cache invalidation.  An abnormally high miss rate is an
   * indicator that an attacker is forcing repeated re-fetches.
   */
  logger?: Logger;
  /**
   * HMAC secret for verifying {@link PinAttestation}s (see
   * `PARTNER_DID_PIN_SECRET`).  When set, the resolver verifies the
   * attestation stored in the registry entry before trusting any
   * `pinnedDocSha256` — tampered Redis entries cannot forge a valid
   * attestation without knowing this secret.
   *
   * Verification behaviour:
   *   - Entry has a pin AND a valid attestation → pin is trusted.
   *   - Entry has a pin AND an invalid / mismatched attestation → fail-closed
   *     (treated as a tampering signal).
   *   - Entry has a pin but NO attestation (e.g. legacy env-seeded entry or
   *     entry created before the feature) → a warning is logged and the pin is
   *     still checked hash-only (no HMAC guarantee).  This preserves
   *     backwards-compatibility while the secret is first rolled out.
   *   - Entry has no pin → hash check is skipped entirely (same as before).
   */
  pinAttestationSecret?: string;
  /**
   * Pre-parsed HTTP allow-list for did:web resolution.  Any host[:port] in
   * this set is fetched over plain HTTP instead of HTTPS.  Construct via
   * `parseDidWebHttpAllowList(cfg.DID_WEB_ALLOW_HTTP_FOR_HOSTS)` at boot.
   * Leave unset (or pass an empty Set) in production — HTTPS is the default.
   */
  httpAllowList?: Set<string>;
  /**
   * did:ion resolver base URL.  When set, overrides the compiled-in default
   * (`https://ion.msidentity.com/api/v1.0/identifiers`).
   * Source from `cfg.ION_RESOLVER_URL` at boot.
   */
  ionResolverUrl?: string;
  /**
   * Per-DID circuit-breaker tuning.  A dedicated {@link RedisCircuitBreaker}
   * is instantiated for each trusted DID.  When the partner's DID-document
   * endpoint becomes slow or unreachable the circuit trips open and subsequent
   * `getKey` calls fast-fail without any network round-trip until the cooldown
   * elapses and a single probe request succeeds.
   *
   * Only the `resolveDID` network call is wrapped — pin-mismatch and
   * key-validation errors do not count as circuit failures because they
   * indicate data problems, not network outages.
   *
   * Tune aggressively for production: a flapping partner should open the
   * circuit quickly so its latency tail does not bleed into unrelated
   * cross-org requests sharing the same gateway worker pool.
   */
  circuitBreaker?: Pick<CircuitBreakerOptions, 'failureThreshold' | 'windowMs' | 'cooldownMs'>;
  /**
   * Optional callback invoked whenever a per-DID circuit breaker transitions
   * between states.  Inject a Prometheus counter increment or log line here.
   *
   * @param did  The partner DID whose circuit changed.
   * @param from Previous state.
   * @param to   New state.
   */
  onCircuitStateChange?: (did: string, from: CircuitState, to: CircuitState) => void;
}

/**
 * Resolves and caches public keys for partner DIDs so the gateway can
 * verify their JWT signatures.
 *
 * Construction is cheap: no network calls happen until a token from a
 * trusted DID is verified.
 */
export class PartnerIssuerResolver {
  private readonly trusted: Set<string>;
  private readonly registry?: PartnerDidRegistry;
  private readonly cacheTtlMs: number;
  private readonly negativeCacheTtlMs: number;
  private readonly cache = new Map<string, CachedKey>();
  private readonly negativeCache = new Map<string, NegativeCacheEntry>();
  private readonly logger?: Logger;
  private readonly auditLogger = createAuditLogger('tool-gateway');
  private readonly pinAttestationSecret?: string;
  private readonly httpAllowList?: Set<string>;
  private readonly ionResolverUrl?: string;
  /**
   * Per-DID circuit breakers keyed by DID string.  Created lazily on the
   * first `getKey` call for a given DID so that resolver construction
   * remains cheap and deterministic.  Each breaker is independent: a
   * flapping partner's circuit state has no effect on other trusted DIDs.
   */
  private readonly circuitBreakers = new Map<string, RedisCircuitBreaker>();
  /** Constructor options shared by every per-DID circuit breaker. */
  private readonly circuitBreakerOpts: Pick<CircuitBreakerOptions, 'failureThreshold' | 'windowMs' | 'cooldownMs'>;
  private readonly onCircuitStateChange?: (did: string, from: CircuitState, to: CircuitState) => void;
  /**
   * In-flight resolution Promises keyed by `${did}::${kid ?? ''}`.
   *
   * When a cache miss occurs, the outgoing `_doResolve` Promise is registered
   * here so that concurrent requests for the **identical** (DID, kid) pair
   * coalesce onto the same Promise instead of each launching a redundant
   * network round-trip.  The entry is removed once the Promise settles so the
   * map size is bounded by the number of simultaneously-in-flight distinct
   * (DID, kid) lookups — typically very small in normal operation.
   */
  private readonly inFlight = new Map<string, Promise<{ key: jose.KeyLike | Uint8Array; alg: string }>>();
  private static readonly DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000;
  private static readonly DEFAULT_NEGATIVE_CACHE_TTL_MS = 30 * 1000;
  /** Default number of fetch failures within the window that trips the circuit. */
  private static readonly DEFAULT_CB_FAILURE_THRESHOLD = 3;
  /** Default sliding-window width (ms) for failure counting. */
  private static readonly DEFAULT_CB_WINDOW_MS = 30_000;
  /** Default time (ms) the circuit stays open before a probe is allowed. */
  private static readonly DEFAULT_CB_COOLDOWN_MS = 60_000;

  constructor(opts: PartnerIssuerResolverOptions) {
    this.trusted = new Set(opts.trustedIssuerDids.filter((d) => d && d.length > 0));
    this.registry = opts.registry;
    this.cacheTtlMs = opts.cacheTtlMs ?? PartnerIssuerResolver.DEFAULT_CACHE_TTL_MS;
    this.negativeCacheTtlMs = opts.negativeCacheTtlMs ?? PartnerIssuerResolver.DEFAULT_NEGATIVE_CACHE_TTL_MS;
    this.logger = opts.logger;
    this.pinAttestationSecret = opts.pinAttestationSecret;
    this.httpAllowList = opts.httpAllowList;
    this.ionResolverUrl = opts.ionResolverUrl;
    const cb = opts.circuitBreaker ?? {};
    this.circuitBreakerOpts = {
      failureThreshold: cb.failureThreshold ?? PartnerIssuerResolver.DEFAULT_CB_FAILURE_THRESHOLD,
      windowMs: cb.windowMs ?? PartnerIssuerResolver.DEFAULT_CB_WINDOW_MS,
      cooldownMs: cb.cooldownMs ?? PartnerIssuerResolver.DEFAULT_CB_COOLDOWN_MS,
    };
    this.onCircuitStateChange = opts.onCircuitStateChange;
  }

  /**
   * Return the circuit breaker for `did`, creating one if it does not yet
   * exist.  Lazily instantiated so resolver construction stays cheap.
   */
  private getOrCreateBreaker(did: string): RedisCircuitBreaker {
    let breaker = this.circuitBreakers.get(did);
    if (!breaker) {
      breaker = new RedisCircuitBreaker({
        ...this.circuitBreakerOpts,
        onStateChange: this.onCircuitStateChange
          ? (from, to) => this.onCircuitStateChange!(did, from, to)
          : undefined,
      });
      this.circuitBreakers.set(did, breaker);
    }
    return breaker;
  }

  /** Whether the resolver has any partner DIDs configured at all. */
  get isEmpty(): boolean {
    return this.trusted.size === 0 && !this.registry;
  }

  /**
   * Return a new Map snapshot of the current circuit-breaker state for every
   * DID that has had at least one `getKey` call since this resolver was
   * constructed.
   *
   * The map is keyed by DID string and the value is one of `'closed'`,
   * `'open'`, or `'half-open'`.  DIDs that are trusted but have never been
   * resolved (no network call attempted) are absent — their breaker does not
   * exist yet (created lazily) so their state is implicitly `'closed'`.
   *
   * Intended for Prometheus gauge collection on the `/metrics` scrape path;
   * the result is a new Map snapshot so the gauge `collect()` function does
   * not hold a reference into internal state.
   */
  getCircuitBreakerStates(): ReadonlyMap<string, CircuitState> {
    const snapshot = new Map<string, CircuitState>();
    for (const [did, breaker] of this.circuitBreakers) {
      snapshot.set(did, breaker.getState());
    }
    return snapshot;
  }

  /**
   * Whether the given DID is trusted (in the legacy set or active in the
   * registry).  Async because the registry may be Redis-backed.
   */
  async trustsAsync(did: string): Promise<boolean> {
    if (this.trusted.has(did)) return true;
    if (this.registry) return this.registry.trusts(did);
    return false;
  }

  /**
   * Synchronous trust check for the legacy env-var path.
   * Only checks the in-memory trusted set; does NOT check the registry.
   * Use `trustsAsync` when a registry is wired.
   */
  trusts(did: string): boolean {
    return this.trusted.has(did);
  }

  /**
   * Synchronous "might trust" check used by {@link PartnerDidTrustAnchor.owns}.
   *
   * Returns `true` when the DID is known to be trusted without any async
   * I/O (env-var set), **or** when a registry is configured and the DID is
   * non-empty — in that case the definitive async check is deferred to
   * {@link getKey} (via {@link trustsAsync}) so that registry-backed partner
   * DIDs are not silently dropped at the `owns()` gate.
   *
   * Never performs network I/O.
   */
  mightTrust(did: string): boolean {
    if (this.trusted.has(did)) return true;
    // If a registry is wired, we can't rule out this DID synchronously —
    // defer to the async check in getKey().
    return !!this.registry && did.length > 0;
  }

  /**
   * Look up the (key, algorithm) pair for a (DID, kid?) tuple, resolving
   * and caching as necessary.  Throws {@link CapabilityError} when the DID
   * is not trusted, cannot be resolved, or has no usable key.
   */
  async getKey(did: string, kid?: string): Promise<{ key: jose.KeyLike | Uint8Array; alg: string }> {
    // Trust check: either legacy set or registry.
    const trusted = await this.trustsAsync(did);
    if (!trusted) {
      throw new CapabilityError(
        ErrorCode.AUTHENTICATION_FAILED,
        `Issuer DID is not in TRUSTED_PARTNER_DIDS: ${did}`,
        401
      );
    }

    const cacheKey = `${did}::${kid ?? ''}`;
    const now = Date.now();

    // Positive cache hit — fast path, no locking needed.
    const cached = this.cache.get(cacheKey);
    if (cached && cached.expiresAt > now) {
      return { key: cached.key, alg: cached.alg };
    }

    // Negative cache: absorb a recent DID-level resolution failure (network
    // error, DID doc not fetchable) without re-fetching.  Checked before
    // in-flight coalescing so a request is never coalesced onto an in-flight
    // that is doomed to fail because another concurrent call (for a different
    // kid of the same DID) already recorded a DID-level error.
    const negEntry = this.negativeCache.get(did);
    if (negEntry && negEntry.expiresAt > now) {
      throw new CapabilityError(
        ErrorCode.INVALID_TOKEN,
        `Partner DID ${did} is temporarily unavailable`,
        401
      );
    }
    // Remove stale negative cache entries eagerly.
    if (negEntry) {
      this.negativeCache.delete(did);
    }

    // In-flight coalescing: if an identical (DID, kid) resolution is already
    // in progress, attach to it rather than launching a redundant network
    // round-trip.  This prevents a thundering herd when the cache expires
    // under concurrent load — only the first caller fetches; the rest wait.
    const pending = this.inFlight.get(cacheKey);
    if (pending) return pending;

    // Start a new resolution and register it as in-flight so concurrent
    // requests for the same (DID, kid) pair coalesce onto this Promise.
    // The entry is removed once the Promise settles (success or failure).
    // Use await + try/finally rather than a floating .finally() chain so
    // that rejections do not surface as unhandled Promise rejections in
    // the host process — the error propagates to the awaiting caller.
    const resolution = this._doResolve(did, kid, cacheKey);
    this.inFlight.set(cacheKey, resolution);
    try {
      return await resolution;
    } finally {
      this.inFlight.delete(cacheKey);
    }
  }

  /**
   * Internal: perform the network fetch + pin/key validation for one
   * (DID, kid) pair and populate the positive cache on success.
   *
   * Must only be called when the positive and negative caches have both
   * missed.  Callers should register the returned Promise in `inFlight`
   * before awaiting it (done by `getKey`).
   */
  private async _doResolve(
    did: string,
    kid: string | undefined,
    cacheKey: string,
  ): Promise<{ key: jose.KeyLike | Uint8Array; alg: string }> {
    // Cache miss — re-fetch.  Emit a structured audit event so an
    // abnormally high rate (e.g. an attacker forcing repeated re-fetches)
    // is visible in the audit trail.
    this.logger?.info('Partner DID cache miss — fetching DID document', {
      eventType: 'partner_did_cache_miss',
      did,
      kid: kid ?? null,
    });

    // Look up registry entry for pin material (may be undefined for legacy path).
    const registryEntry = this.registry ? await this.registry.get(did) : undefined;

    // ── Network fetch, wrapped in the per-DID circuit breaker ────────────────
    //
    // Only `resolveDID` is inside the breaker.  Pin-mismatch and key-validation
    // errors signal data problems (not network outages) and must NOT count as
    // circuit failures — doing so would let an attacker with a malformed DID
    // document force the circuit open against a partner that is perfectly
    // reachable.
    const breaker = this.getOrCreateBreaker(did);
    let didDoc: DIDDocument;
    try {
      didDoc = await breaker.execute(() =>
        resolveDID(did, { httpAllowList: this.httpAllowList, ionResolverUrl: this.ionResolverUrl }),
      );
    } catch (resolveErr) {
      if (resolveErr instanceof CircuitOpenError) {
        // The circuit is open (or a half-open probe is already in flight).
        // Fast-fail without a network round-trip and without storing a new
        // negative-cache entry — the circuit already manages its own cooldown
        // and an additional stale-denial entry would only extend the effective
        // blackout unnecessarily.
        this.logger?.warn('Partner DID circuit open — fast failing', {
          eventType: 'partner_did_circuit_open',
          did,
          kid: kid ?? null,
        });
        throw new CapabilityError(
          ErrorCode.INVALID_TOKEN,
          `Partner DID ${did} is temporarily unavailable (circuit open)`,
          401,
        );
      }
      // Network error, timeout, or non-200 response from the DID endpoint.
      // Store a negative cache entry so requests during the circuit-opening
      // window (before the threshold is reached) do not all pay the full
      // TCP/TLS timeout.
      const detail = resolveErr instanceof Error ? resolveErr.message : String(resolveErr);
      this.logger?.error('Partner DID resolution failed', {
        eventType: 'partner_did_resolution_error',
        did,
        error: detail,
      });
      this.storeNegativeDid(did);
      throw new CapabilityError(
        ErrorCode.INVALID_TOKEN,
        `Partner DID ${did} is temporarily unavailable`,
        401,
      );
    }

    // ── Post-resolution validation (pin checks, key extraction) ─────────────
    try {
      // Pin verification (2C): check JCS-SHA-256 of the DID document.
      if (registryEntry?.pinnedDocSha256) {
        await this.verifyDocPin(did, didDoc, registryEntry.pinnedDocSha256, registryEntry);
      }

      // Secondary-resolver cross-check (2C).
      if (registryEntry?.secondaryResolver) {
        await this.verifySecondaryResolver(did, didDoc, registryEntry);
      }

      const vm = findVerificationMethod(didDoc, kid);
      if (!vm) {
        // The DID document was resolved successfully — do NOT negatively
        // cache this; the error is kid-specific and caching it by DID
        // would wrongly block valid kids.  The DID doc itself is in the
        // positive cache (implicitly — the next lookup will re-fetch only
        // when the positive TTL expires), so repeating with a random kid
        // is cheap (one Map lookup + kid scan, no network call).
        const msg = `No verification method ${kid ? `(kid=${kid}) ` : ''}found in DID document for ${did}`;
        this.logger?.warn('Partner DID key lookup failed — kid not found', {
          eventType: 'partner_did_kid_not_found',
          did,
          kid: kid ?? null,
        });
        throw new CapabilityError(ErrorCode.INVALID_TOKEN, msg, 401);
      }

      // Per-VM JWK thumbprint pin (2C).
      if (registryEntry?.pinnedVerificationKeys && kid) {
        const expectedThumbprint = registryEntry.pinnedVerificationKeys[kid];
        if (expectedThumbprint !== undefined) {
          await this.verifyKidPin(did, kid, vm, expectedThumbprint);
        }
      }

      const pem = await extractPublicKeyPem(vm);
      const alg = determineSigningAlgorithm(vm);
      let key: jose.KeyLike | Uint8Array;
      try {
        key = await jose.importSPKI(pem, alg);
      } catch (err) {
        // Key import failure is a DID-document-level problem (malformed
        // key material), so we negatively cache by DID.
        const detail = err instanceof Error ? err.message : 'unknown';
        this.logger?.error('Partner DID key import failed', {
          eventType: 'partner_did_key_import_error',
          did,
          kid: kid ?? null,
          error: detail,
        });
        this.storeNegativeDid(did);
        throw new CapabilityError(
          ErrorCode.INVALID_TOKEN,
          `Partner DID ${did} has an unusable key material`,
          401,
        );
      }

      this.cache.set(cacheKey, { key, alg, expiresAt: Date.now() + this.cacheTtlMs });
      this.negativeCache.delete(did);

      this.logger?.info('Partner DID document fetched and cached', {
        eventType: 'partner_did_cache_refresh',
        did,
        kid: kid ?? null,
        ttlMs: this.cacheTtlMs,
        // Only tracks document-level pin verification; key-level pins
        // (pinnedVerificationKeys) and secondary resolver checks are
        // performed above but not reflected in this field.
        pinnedDocSha256Verified: !!(registryEntry?.pinnedDocSha256),
      });

      return { key, alg };
    } catch (err) {
      if (err instanceof CapabilityError) throw err;
      // Unexpected error in post-resolution processing.
      const detail = err instanceof Error ? err.message : String(err);
      this.logger?.error('Partner DID resolution failed', {
        eventType: 'partner_did_resolution_error',
        did,
        error: detail,
      });
      this.storeNegativeDid(did);
      throw new CapabilityError(
        ErrorCode.INVALID_TOKEN,
        `Partner DID ${did} is temporarily unavailable`,
        401
      );
    }
  }

  // ── Pin verification helpers ──────────────────────────────────────────────

  private async verifyDocPin(
    did: string,
    didDoc: unknown,
    pinnedSha256: string,
    entry: PartnerDidEntry,
  ): Promise<void> {
    // ── Attestation verification ───────────────────────────────────────────────
    //
    // When pinAttestationSecret is configured, verify the HMAC attestation
    // before trusting the hash.  This detects Redis-level tampering even when
    // the hash itself looks plausible.
    if (this.pinAttestationSecret) {
      if (entry.pinAttestation) {
        if (!verifyPinAttestation(entry.pinAttestation, this.pinAttestationSecret)) {
          this.auditLogger.warn('partner_did_pin_attestation_invalid', {
            eventType: 'partner_did_pin_attestation_invalid',
            did,
            reason: 'hmac_mismatch',
          });
          this.storeNegativeDid(did);
          throw new CapabilityError(
            ErrorCode.INVALID_TOKEN,
            `Partner DID ${did} pin attestation HMAC mismatch — possible registry tampering`,
            401,
          );
        }
        // Attestation HMAC valid; also verify the did and hash fields match
        // what we're currently evaluating (prevents cross-entry splicing).
        if (entry.pinAttestation.did !== did) {
          this.auditLogger.warn('partner_did_pin_attestation_invalid', {
            eventType: 'partner_did_pin_attestation_invalid',
            did,
            reason: 'did_mismatch',
          });
          this.storeNegativeDid(did);
          throw new CapabilityError(
            ErrorCode.INVALID_TOKEN,
            `Partner DID ${did} pin attestation DID field mismatch`,
            401,
          );
        }
        if (entry.pinAttestation.pinnedDocSha256.toLowerCase() !== pinnedSha256.toLowerCase()) {
          this.auditLogger.warn('partner_did_pin_attestation_invalid', {
            eventType: 'partner_did_pin_attestation_invalid',
            did,
            reason: 'hash_field_mismatch',
          });
          this.storeNegativeDid(did);
          throw new CapabilityError(
            ErrorCode.INVALID_TOKEN,
            `Partner DID ${did} pin attestation hash field does not match stored pinnedDocSha256`,
            401,
          );
        }
      } else {
        // Secret is configured but no attestation was found.  Warn but do not
        // fail — this allows a smooth rollout: entries created before the
        // feature was enabled continue to work with hash-only verification
        // until they are refreshed / re-approved.
        this.logger?.warn('Partner DID entry has no pin attestation (legacy entry — hash-only check)', {
          eventType: 'partner_did_pin_attestation_missing',
          did,
        });
      }
    }

    // ── Hash check ────────────────────────────────────────────────────────────
    const actualHash = jcsSha256(didDoc);
    if (actualHash !== pinnedSha256.toLowerCase()) {
      this.auditLogger.warn('partner_did_pin_violation', {
        eventType: 'partner_did_pin_violation',
        did,
        expectedSha256: pinnedSha256,
        actualSha256: actualHash,
      });
      this.storeNegativeDid(did);
      throw new CapabilityError(
        ErrorCode.INVALID_TOKEN,
        `Partner DID ${did} document hash mismatch — possible tampering`,
        401,
      );
    }
  }

  private async verifyKidPin(
    did: string,
    kid: string,
    vm: VerificationMethod,
    expectedThumbprint: string,
  ): Promise<void> {
    // A per-VM thumbprint pin is configured — we MUST fail-closed if we cannot
    // compute the thumbprint.  Silently skipping the check would allow an
    // attacker to bypass pinning by advertising a key in publicKeyPem /
    // publicKeyMultibase instead of publicKeyJwk.
    let thumbprint: string;
    try {
      // Preferred path: the VM has an inline publicKeyJwk.
      const jwk = vm.publicKeyJwk as jose.JWK | undefined;
      if (jwk) {
        thumbprint = await jose.calculateJwkThumbprint(jwk, 'sha256');
      } else {
        // Fallback: derive the JWK from the PEM extracted by the existing
        // adapter and export it so we can call calculateJwkThumbprint.
        // extractPublicKeyPem + determineSigningAlgorithm are always
        // available for any VM that reaches this path (we already call them
        // after pin verification).
        const pem = await extractPublicKeyPem(vm);
        const alg = determineSigningAlgorithm(vm);
        const importedKey = await jose.importSPKI(pem, alg);
        const derivedJwk = await jose.exportJWK(importedKey);
        thumbprint = await jose.calculateJwkThumbprint(derivedJwk, 'sha256');
      }
    } catch (err) {
      if (err instanceof CapabilityError) throw err;
      // We could not compute the thumbprint (e.g. unsupported key format or
      // broken adapter output).  With a pin configured this is fail-closed:
      // trust without verification is not acceptable.
      this.auditLogger.warn('partner_did_kid_pin_violation', {
        eventType: 'partner_did_kid_pin_violation',
        did,
        kid,
        expectedThumbprint,
        actualThumbprint: null,
        reason: 'thumbprint_computation_failed',
      });
      this.storeNegativeDid(did);
      throw new CapabilityError(
        ErrorCode.INVALID_TOKEN,
        `Partner DID ${did} kid=${kid} thumbprint could not be computed — pin check fail-closed`,
        401,
      );
    }
    if (thumbprint !== expectedThumbprint) {
      this.auditLogger.warn('partner_did_kid_pin_violation', {
        eventType: 'partner_did_kid_pin_violation',
        did,
        kid,
        expectedThumbprint,
        actualThumbprint: thumbprint,
      });
      this.storeNegativeDid(did);
      throw new CapabilityError(
        ErrorCode.INVALID_TOKEN,
        `Partner DID ${did} kid=${kid} thumbprint mismatch — possible key substitution`,
        401,
      );
    }
  }

  private async verifySecondaryResolver(
    did: string,
    primaryDoc: unknown,
    entry: PartnerDidEntry,
  ): Promise<void> {
    const spec = entry.secondaryResolver!;
    try {
      let secondaryDoc: unknown;

      if (spec.method === 'ion-anchor') {
        // Use the dedicated ION resolver which properly unwraps the DIF
        // universal resolver wrapper ({ didDocument: {...} }) and validates
        // the DID identifier match.  The `url` field on the spec is treated
        // as informational documentation; the actual URL comes from the
        // ionResolverUrl option (sourced from cfg.ION_RESOLVER_URL at boot).
        try {
          secondaryDoc = await resolveDidIon(did, this.ionResolverUrl);
        } catch (ionErr) {
          // Re-wrap as a generic error so the outer catch below handles it
          // uniformly (negative-cache + fail-closed).
          throw new Error(
            `ION anchor cross-check failed for ${did}: ${ionErr instanceof Error ? ionErr.message : String(ionErr)}`,
          );
        }
      } else {
        // 'web' or 'ipfs': fetch the URL as raw JSON.
        secondaryDoc = await fetchJson(spec.url);
      }

      if (spec.expectedSha256) {
        // Compare against a pre-computed hash (e.g. from an out-of-band ledger).
        const actualHash = jcsSha256(secondaryDoc);
        if (actualHash !== spec.expectedSha256.toLowerCase()) {
          this.auditLogger.warn('partner_did_secondary_resolver_mismatch', {
            eventType: 'partner_did_secondary_resolver_mismatch',
            did,
            method: spec.method,
            url: spec.url,
            expectedSha256: spec.expectedSha256,
            actualSha256: actualHash,
          });
          this.storeNegativeDid(did);
          throw new CapabilityError(
            ErrorCode.INVALID_TOKEN,
            `Partner DID ${did} secondary resolver hash mismatch`,
            401,
          );
        }
      } else {
        // Byte-equality: both canonicalized documents must match.
        const primaryCanon = jcsSha256(primaryDoc);
        const secondaryCanon = jcsSha256(secondaryDoc);
        if (primaryCanon !== secondaryCanon) {
          this.auditLogger.warn('partner_did_secondary_resolver_mismatch', {
            eventType: 'partner_did_secondary_resolver_mismatch',
            did,
            method: spec.method,
            url: spec.url,
            primarySha256: primaryCanon,
            secondarySha256: secondaryCanon,
          });
          this.storeNegativeDid(did);
          throw new CapabilityError(
            ErrorCode.INVALID_TOKEN,
            `Partner DID ${did} primary and secondary resolver documents disagree`,
            401,
          );
        }
      }
    } catch (err) {
      if (err instanceof CapabilityError) throw err;
      this.logger?.error('Partner DID secondary resolver fetch failed', {
        did,
        method: spec.method,
        url: spec.url,
        error: err instanceof Error ? err.message : String(err),
      });
      this.storeNegativeDid(did);
      throw new CapabilityError(
        ErrorCode.INVALID_TOKEN,
        `Partner DID ${did} secondary resolver unavailable`,
        401,
      );
    }
  }

  /**
   * Drop the cached key for a (DID, kid?) tuple.  Callers should invoke
   * this after a verification failure so the next request re-resolves the
   * DID document and picks up any out-of-band key rotation.  Also clears
   * the DID-level negative-cache entry for that DID.
   */
  invalidate(did: string, kid?: string): void {
    const key = `${did}::${kid ?? ''}`;
    this.cache.delete(key);
    this.negativeCache.delete(did);
    this.logger?.info('Partner DID cache entry invalidated', {
      eventType: 'partner_did_cache_invalidated',
      did,
      kid: kid ?? null,
    });
  }

  /**
   * Drop ALL cached entries (positive and negative) for a given DID,
   * regardless of kid.  Used by the admin refresh endpoint for incident
   * response when the operator knows the DID document has changed.
   */
  invalidateAll(did: string): void {
    const prefix = `${did}::`;
    for (const key of [...this.cache.keys()]) {
      if (key.startsWith(prefix)) this.cache.delete(key);
    }
    this.negativeCache.delete(did);
    this.logger?.info('Partner DID cache fully invalidated', {
      eventType: 'partner_did_cache_invalidated_all',
      did,
    });
  }

  /**
   * Store a DID-level resolution failure in the negative cache.  Keyed by
   * DID only (not DID::kid) — see {@link NegativeCacheEntry} for the
   * reasoning.  A no-op when negative caching is disabled
   * (`negativeCacheTtlMs === 0`).
   */
  private storeNegativeDid(did: string): void {
    if (this.negativeCacheTtlMs > 0) {
      this.negativeCache.set(did, {
        expiresAt: Date.now() + this.negativeCacheTtlMs,
      });
    }
  }
}

/**
 * Options accepted by {@link createPartnerIssuerResolverFromEnv} beyond what
 * is derived from environment variables.
 */
export interface PartnerIssuerResolverFromEnvOptions {
  /**
   * Optional callback invoked whenever a per-DID circuit breaker transitions
   * state.  Inject a Prometheus counter increment here.
   */
  onCircuitStateChange?: (did: string, from: CircuitState, to: CircuitState) => void;
}

/**
 * Build a {@link PartnerIssuerResolver} from environment variables.
 * Returns `undefined` when `TRUSTED_PARTNER_DIDS` is unset or empty so
 * single-issuer deployments incur zero overhead.
 *
 * Circuit-breaker tuning is read from `PARTNER_DID_CB_FAILURE_THRESHOLD`,
 * `PARTNER_DID_CB_WINDOW_SECONDS`, and `PARTNER_DID_CB_COOLDOWN_SECONDS`.
 * Omitting any of those falls back to the class-level defaults (3 / 30 s / 60 s).
 */
export function createPartnerIssuerResolverFromEnv(
  env: NodeJS.ProcessEnv,
  logger?: Logger,
  registry?: PartnerDidRegistry,
  options?: PartnerIssuerResolverFromEnvOptions,
): PartnerIssuerResolver | undefined {
  const raw = env.TRUSTED_PARTNER_DIDS;
  const dids = raw
    ? raw.split(',').map((d) => d.trim()).filter((d) => d.length > 0)
    : [];

  // Build resolver when either a non-empty TRUSTED_PARTNER_DIDS or a registry is supplied.
  if (dids.length === 0 && !registry) {
    return undefined;
  }

  // PARTNER_DID_CACHE_TTL_SECONDS supersedes the legacy TRUSTED_PARTNER_CACHE_TTL_MS.
  const ttlSecRaw = env.PARTNER_DID_CACHE_TTL_SECONDS;
  const ttlSec = ttlSecRaw ? parseInt(ttlSecRaw, 10) : undefined;
  const cacheTtlMs = ttlSec && Number.isFinite(ttlSec) && ttlSec > 0 ? ttlSec * 1000 : undefined;

  const negTtlSecRaw = env.PARTNER_DID_NEGATIVE_CACHE_TTL_SECONDS;
  const negTtlSec = negTtlSecRaw ? parseInt(negTtlSecRaw, 10) : undefined;
  const negativeCacheTtlMs = negTtlSec !== undefined && Number.isFinite(negTtlSec) ? negTtlSec * 1000 : undefined;

  // Circuit-breaker env vars (all optional; class defaults apply when absent).
  const cbThreshRaw = env.PARTNER_DID_CB_FAILURE_THRESHOLD;
  const cbThresh = cbThreshRaw ? parseInt(cbThreshRaw, 10) : undefined;
  const cbWindowRaw = env.PARTNER_DID_CB_WINDOW_SECONDS;
  const cbWindow = cbWindowRaw ? parseInt(cbWindowRaw, 10) : undefined;
  const cbCooldownRaw = env.PARTNER_DID_CB_COOLDOWN_SECONDS;
  const cbCooldown = cbCooldownRaw ? parseInt(cbCooldownRaw, 10) : undefined;

  const circuitBreaker: PartnerIssuerResolverOptions['circuitBreaker'] = {
    ...(cbThresh && Number.isFinite(cbThresh) && cbThresh > 0 ? { failureThreshold: cbThresh } : {}),
    ...(cbWindow && Number.isFinite(cbWindow) && cbWindow > 0 ? { windowMs: cbWindow * 1000 } : {}),
    ...(cbCooldown && Number.isFinite(cbCooldown) && cbCooldown > 0 ? { cooldownMs: cbCooldown * 1000 } : {}),
  };

  return new PartnerIssuerResolver({
    trustedIssuerDids: dids,
    registry,
    cacheTtlMs,
    negativeCacheTtlMs,
    logger,
    pinAttestationSecret: env.PARTNER_DID_PIN_SECRET || undefined,
    httpAllowList: parseDidWebHttpAllowList(env.DID_WEB_ALLOW_HTTP_FOR_HOSTS),
    ionResolverUrl: env.ION_RESOLVER_URL || undefined,
    circuitBreaker,
    onCircuitStateChange: options?.onCircuitStateChange,
  });
}
