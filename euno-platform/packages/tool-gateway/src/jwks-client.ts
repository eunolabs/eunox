/**
 * JWKS Client for Tool Gateway — R-6
 *
 * Fetches and caches the issuer's JSON Web Key Set from
 * `/.well-known/jwks.json`.  On every token verification the verifier
 * calls {@link JwksClient.getJwks} or {@link JwksClient.getKeyByKid};
 * HTTP is only used on cache miss or a forced refresh.
 *
 * Cache behaviour:
 *   - Cache entries expire after {@link cacheTtlMs} ms (default 5 min).
 *   - When the cache is stale AND a prior cached value exists, the stale
 *     value is returned immediately while a background refresh is
 *     scheduled (stale-while-revalidate).  This keeps the hot path
 *     synchronous for the common case where the signing key has not
 *     changed.
 *   - When no cached value exists at all, the first call blocks until
 *     the fetch completes (fail-fast at startup).
 *   - If the `kid` from a token's header is not found in the cache, a
 *     single forced (synchronous) refresh is attempted before rejecting
 *     the token.
 *   - On refresh failure, the existing cached keys are preserved and a
 *     warning is logged.  If there is no cached value at all the error
 *     is propagated (fail-closed: no key → reject).
 *
 * See `docs/IMPROVEMENTS_AND_REFACTORING.md` § R-6 for the full
 * rotation procedure.
 */

import axios from 'axios';
import { JwkKey, JwkSet, JwksKeySource, CapabilityError, ErrorCode, pickJwkByKid } from '@euno/common';

export interface JwksClientOptions {
  /** Full URL of the JWKS endpoint (e.g. `http://issuer:3001/.well-known/jwks.json`). */
  jwksUrl: string;
  /** Cache TTL in milliseconds.  Default 300 000 ms (5 min). */
  cacheTtlMs?: number;
  /** Optional logger for warnings (e.g. cache-refresh failures). */
  logger?: { warn: (msg: string, meta?: Record<string, unknown>) => void };
}

interface CacheEntry {
  jwks: JwkSet;
  /** Wall-clock expiry (ms since epoch). */
  expiresAt: number;
}

/** Default JWKS cache TTL: 5 minutes. */
const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000;

/**
 * Thread-safe (single Node.js event-loop) JWKS cache with
 * stale-while-revalidate and forced-refresh semantics.
 *
 * Implements {@link JwksKeySource} so the gateway verifier can consume it
 * through the same interface used for partner-DID key resolution.
 */
export class JwksClient implements JwksKeySource {
  private readonly jwksUrl: string;
  private readonly cacheTtlMs: number;
  private readonly logger?: JwksClientOptions['logger'];

  private cache: CacheEntry | null = null;
  /** Deduplicates concurrent refresh calls — only one HTTP request in flight at a time. */
  private refreshPromise: Promise<JwkSet> | null = null;
  /**
   * Per-kid singleflight map (CI-8).
   *
   * On key rotation, tokens with the new `kid` arrive simultaneously at a
   * cache that still holds the old key set.  Without this map each concurrent
   * miss would call `doRefresh()` independently, creating an N × M fan-out to
   * the issuer's JWKS endpoint (one refresh per concurrent request per
   * replica).  By storing a single pending `getKeyByKid` promise per `kid` we
   * guarantee that only one outstanding forced refresh exists per kid at a
   * time: all other callers for the same kid wait on the same promise and
   * resolve from the refreshed cache.
   */
  private readonly kidPendingRefreshes = new Map<string, Promise<JwkKey>>();

  constructor(opts: JwksClientOptions) {
    this.jwksUrl = opts.jwksUrl;
    this.cacheTtlMs = opts.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
    this.logger = opts.logger;
  }

  // ── JwksKeySource ─────────────────────────────────────────────────────────

  /**
   * Return the current JWK Set, fetching from the issuer when the cache
   * is empty.  When the cache is stale but non-empty, the stale value is
   * returned immediately and a background refresh is triggered.
   */
  async getJwks(): Promise<JwkSet> {
    return this.getJwksInternal({ forceRefresh: false, allowStale: true });
  }

  // ── Key selection ─────────────────────────────────────────────────────────

  /**
   * Find the JWK for `kid`.  If the kid is not present in the cache a
   * single forced refresh is attempted (handles a freshly-rotated key).
   * Throws {@link CapabilityError} (fail-closed) when the kid is still
   * absent after the refresh.
   *
   * **Singleflight per kid (CI-8):** concurrent requests for the same
   * unknown `kid` share a single pending refresh promise.  This prevents
   * the N×M fan-out stampede to the JWKS endpoint that otherwise occurs
   * when many in-flight tokens all carry a freshly-rotated key that is
   * not yet in the local cache.
   */
  async getKeyByKid(kid: string): Promise<JwkKey> {
    // Fast path: kid is in the (possibly stale) cache.
    const cached = await this.getJwks();
    const key = pickJwkByKid(cached, kid);
    if (key) {
      return key;
    }

    // Slow path: force a synchronous refresh — the key might have just
    // been added at the issuer.  Singleflight per kid: if another caller is
    // already refreshing for this kid, piggy-back on their promise instead
    // of issuing a second HTTP request.
    const existing = this.kidPendingRefreshes.get(kid);
    if (existing) {
      return existing;
    }

    const refreshAndFind = this.getJwksInternal({ forceRefresh: true, allowStale: false }).then(
      (fresh) => {
        const freshKey = pickJwkByKid(fresh, kid);
        if (!freshKey) {
          throw new CapabilityError(
            ErrorCode.INVALID_TOKEN,
            `No public key found for kid="${kid}" — key may have been removed or the JWKS endpoint is unreachable`,
            401,
          );
        }
        return freshKey;
      },
    );

    // Register before awaiting so any concurrent caller for the same kid
    // that arrives while the refresh is in flight will join this promise.
    this.kidPendingRefreshes.set(kid, refreshAndFind);
    try {
      return await refreshAndFind;
    } finally {
      // Remove only if it's still the same promise (no newer refresh was
      // registered while we were awaiting).
      if (this.kidPendingRefreshes.get(kid) === refreshAndFind) {
        this.kidPendingRefreshes.delete(kid);
      }
    }
  }

  // ── Internal helpers ──────────────────────────────────────────────────────

  private async getJwksInternal(opts: {
    forceRefresh: boolean;
    allowStale: boolean;
  }): Promise<JwkSet> {
    const now = Date.now();
    const cacheValid = this.cache !== null && this.cache.expiresAt > now;

    if (!opts.forceRefresh && cacheValid) {
      return this.cache!.jwks;
    }

    // Cache is stale (or forced refresh).
    if (!opts.forceRefresh && this.cache !== null) {
      // Stale-while-revalidate: return immediately, refresh in background.
      this.scheduleBackgroundRefresh();
      return this.cache.jwks;
    }

    // No cache or forced refresh — must await the fetch.
    return this.doRefresh();
  }

  /** Trigger a background refresh without blocking the caller. */
  private scheduleBackgroundRefresh(): void {
    if (this.refreshPromise) {
      // A refresh is already in flight — no need to start another.
      return;
    }
    this.doRefresh().catch((err) => {
      this.logger?.warn('Background JWKS refresh failed; serving stale keys', {
        url: this.jwksUrl,
        error: err instanceof Error ? err.message : String(err),
      });
    });
  }

  /**
   * Perform a synchronous JWKS fetch, deduplicating concurrent callers
   * so only one HTTP request is issued at a time.
   */
  private doRefresh(): Promise<JwkSet> {
    if (!this.refreshPromise) {
      this.refreshPromise = this.fetchAndCache().finally(() => {
        this.refreshPromise = null;
      });
    }
    return this.refreshPromise;
  }

  private async fetchAndCache(): Promise<JwkSet> {
    const previousKeys = this.cache?.jwks;
    try {
      const response = await axios.get<JwkSet>(this.jwksUrl, {
        timeout: 10_000,
        headers: { Accept: 'application/json' },
      });

      const data = response.data;
      if (!data || !Array.isArray(data.keys)) {
        throw new Error(
          `Unexpected JWKS response from ${this.jwksUrl}: missing "keys" array`,
        );
      }

      this.cache = {
        jwks: data,
        expiresAt: Date.now() + this.cacheTtlMs,
      };
      return data;
    } catch (err) {
      if (previousKeys) {
        // Keep serving the last known-good JWKS (fail-open on *refresh*, but
        // fail-closed on verification: if the kid is absent we still reject).
        this.logger?.warn(
          'JWKS refresh failed; keeping previous cached keys — do NOT skip signature checks',
          {
            url: this.jwksUrl,
            error: err instanceof Error ? err.message : String(err),
          },
        );
        // Extend the cache so the next request doesn't immediately retry
        // and amplify errors (back-off via re-using the existing TTL).
        this.cache = {
          jwks: previousKeys,
          expiresAt: Date.now() + this.cacheTtlMs,
        };
        return previousKeys;
      }

      // No previous cache — fail-closed: we have no keys to verify with.
      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        `Cannot verify tokens: JWKS fetch from ${this.jwksUrl} failed — ${err instanceof Error ? err.message : String(err)}`,
        503,
      );
    }
  }
}
