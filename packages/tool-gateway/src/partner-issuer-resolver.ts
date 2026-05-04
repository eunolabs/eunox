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
 *   - The gateway operator opts a partner DID into trust by listing it in
 *     `TRUSTED_PARTNER_DIDS` (comma-separated).  Tokens from any other
 *     issuer DID are rejected even if the DID resolves successfully.
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
import { CapabilityError, ErrorCode, Logger } from '@euno/common';
import {
  resolveDID,
  findVerificationMethod,
  extractPublicKeyPem,
  determineSigningAlgorithm,
} from '@euno/capability-issuer/adapters';

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
   * Set of issuer DIDs the gateway is willing to trust.  Tokens whose
   * `iss` claim is not present in this set are rejected before any
   * network resolution is attempted.
   */
  trustedIssuerDids: string[];
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
  private readonly cacheTtlMs: number;
  private readonly negativeCacheTtlMs: number;
  private readonly cache = new Map<string, CachedKey>();
  private readonly negativeCache = new Map<string, NegativeCacheEntry>();
  private readonly logger?: Logger;
  private static readonly DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000;
  private static readonly DEFAULT_NEGATIVE_CACHE_TTL_MS = 30 * 1000;

  constructor(opts: PartnerIssuerResolverOptions) {
    this.trusted = new Set(opts.trustedIssuerDids.filter((d) => d && d.length > 0));
    this.cacheTtlMs = opts.cacheTtlMs ?? PartnerIssuerResolver.DEFAULT_CACHE_TTL_MS;
    this.negativeCacheTtlMs = opts.negativeCacheTtlMs ?? PartnerIssuerResolver.DEFAULT_NEGATIVE_CACHE_TTL_MS;
    this.logger = opts.logger;
  }

  /** Whether the resolver has any partner DIDs configured at all. */
  get isEmpty(): boolean {
    return this.trusted.size === 0;
  }

  /** Whether the given DID is in the trusted set. */
  trusts(did: string): boolean {
    return this.trusted.has(did);
  }

  /**
   * Look up the (key, algorithm) pair for a (DID, kid?) tuple, resolving
   * and caching as necessary.  Throws {@link CapabilityError} when the DID
   * is not trusted, cannot be resolved, or has no usable key.
   */
  async getKey(did: string, kid?: string): Promise<{ key: jose.KeyLike | Uint8Array; alg: string }> {
    if (!this.trusts(did)) {
      throw new CapabilityError(
        ErrorCode.AUTHENTICATION_FAILED,
        `Issuer DID is not in TRUSTED_PARTNER_DIDS: ${did}`,
        401
      );
    }

    const cacheKey = `${did}::${kid ?? ''}`;
    const now = Date.now();

    // Positive cache hit.
    const cached = this.cache.get(cacheKey);
    if (cached && cached.expiresAt > now) {
      return { key: cached.key, alg: cached.alg };
    }

    // Negative cache: absorb a recent DID-level resolution failure (network
    // error, DID doc not fetchable) without re-fetching.  Keyed by DID only —
    // see NegativeCacheEntry comment for why this is intentional.
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

    // Cache miss — re-fetch.  Emit a structured audit event so an
    // abnormally high rate (e.g. an attacker forcing repeated re-fetches)
    // is visible in the audit trail.
    this.logger?.info('Partner DID cache miss — fetching DID document', {
      eventType: 'partner_did_cache_miss',
      did,
      kid: kid ?? null,
    });

    try {
      const didDoc = await resolveDID(did);
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

      this.cache.set(cacheKey, { key, alg, expiresAt: now + this.cacheTtlMs });
      this.negativeCache.delete(did);

      this.logger?.info('Partner DID document fetched and cached', {
        eventType: 'partner_did_cache_refresh',
        did,
        kid: kid ?? null,
        ttlMs: this.cacheTtlMs,
      });

      return { key, alg };
    } catch (err) {
      if (err instanceof CapabilityError) throw err;
      // Unexpected error (network failure, etc.) — negatively cache by DID.
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
 * Build a {@link PartnerIssuerResolver} from environment variables.
 * Returns `undefined` when `TRUSTED_PARTNER_DIDS` is unset or empty so
 * single-issuer deployments incur zero overhead.
 */
export function createPartnerIssuerResolverFromEnv(
  env: NodeJS.ProcessEnv,
  logger?: Logger,
): PartnerIssuerResolver | undefined {
  const raw = env.TRUSTED_PARTNER_DIDS;
  if (!raw) {
    return undefined;
  }
  const dids = raw
    .split(',')
    .map((d) => d.trim())
    .filter((d) => d.length > 0);
  if (dids.length === 0) {
    return undefined;
  }

  // PARTNER_DID_CACHE_TTL_SECONDS supersedes the legacy TRUSTED_PARTNER_CACHE_TTL_MS.
  const ttlSecRaw = env.PARTNER_DID_CACHE_TTL_SECONDS;
  const ttlSec = ttlSecRaw ? parseInt(ttlSecRaw, 10) : undefined;
  const cacheTtlMs = ttlSec && Number.isFinite(ttlSec) && ttlSec > 0 ? ttlSec * 1000 : undefined;

  const negTtlSecRaw = env.PARTNER_DID_NEGATIVE_CACHE_TTL_SECONDS;
  const negTtlSec = negTtlSecRaw ? parseInt(negTtlSecRaw, 10) : undefined;
  const negativeCacheTtlMs = negTtlSec !== undefined && Number.isFinite(negTtlSec) ? negTtlSec * 1000 : undefined;

  return new PartnerIssuerResolver({
    trustedIssuerDids: dids,
    cacheTtlMs,
    negativeCacheTtlMs,
    logger,
  });
}
