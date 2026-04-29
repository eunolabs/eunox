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
 *   - The default issuer (the gateway's own SPKI) is *unaffected* when
 *     no partner DIDs are configured.
 */

import * as jose from 'jose';
import { CapabilityError, ErrorCode } from '@euno/common';
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

export interface PartnerIssuerResolverOptions {
  /**
   * Set of issuer DIDs the gateway is willing to trust.  Tokens whose
   * `iss` claim is not present in this set are rejected before any
   * network resolution is attempted.
   */
  trustedIssuerDids: string[];
  /** TTL for cached resolver results (default 5 minutes). */
  cacheTtlMs?: number;
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
  private readonly cache = new Map<string, CachedKey>();
  private static readonly DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000;

  constructor(opts: PartnerIssuerResolverOptions) {
    this.trusted = new Set(opts.trustedIssuerDids.filter((d) => d && d.length > 0));
    this.cacheTtlMs = opts.cacheTtlMs ?? PartnerIssuerResolver.DEFAULT_CACHE_TTL_MS;
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
    const cached = this.cache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) {
      return { key: cached.key, alg: cached.alg };
    }

    const didDoc = await resolveDID(did);
    const vm = findVerificationMethod(didDoc, kid);
    if (!vm) {
      throw new CapabilityError(
        ErrorCode.INVALID_TOKEN,
        `No verification method ${kid ? `(kid=${kid}) ` : ''}found in DID document for ${did}`,
        401
      );
    }

    const pem = await extractPublicKeyPem(vm);
    const alg = determineSigningAlgorithm(vm);
    let key: jose.KeyLike | Uint8Array;
    try {
      key = await jose.importSPKI(pem, alg);
    } catch (err) {
      throw new CapabilityError(
        ErrorCode.INVALID_TOKEN,
        `Failed to import partner public key for ${did}: ${err instanceof Error ? err.message : 'unknown'}`,
        401
      );
    }

    this.cache.set(cacheKey, { key, alg, expiresAt: Date.now() + this.cacheTtlMs });
    return { key, alg };
  }

  /**
   * Drop the cached key for a (DID, kid?) tuple.  Callers should invoke
   * this after a verification failure so the next request re-resolves the
   * DID document and picks up any out-of-band key rotation.
   */
  invalidate(did: string, kid?: string): void {
    this.cache.delete(`${did}::${kid ?? ''}`);
  }
}

/**
 * Build a {@link PartnerIssuerResolver} from environment variables.
 * Returns `undefined` when `TRUSTED_PARTNER_DIDS` is unset or empty so
 * single-issuer deployments incur zero overhead.
 */
export function createPartnerIssuerResolverFromEnv(
  env: NodeJS.ProcessEnv
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
  const ttlRaw = env.TRUSTED_PARTNER_CACHE_TTL_MS;
  const ttl = ttlRaw ? parseInt(ttlRaw, 10) : undefined;
  return new PartnerIssuerResolver({
    trustedIssuerDids: dids,
    cacheTtlMs: ttl && Number.isFinite(ttl) && ttl > 0 ? ttl : undefined,
  });
}
