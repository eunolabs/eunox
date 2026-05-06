/**
 * Revocation Store
 *
 * Pluggable backing store for the JWT revocation list used by
 * {@link JWTTokenVerifier}.  In single-instance deployments the in-memory
 * implementation is sufficient.  In multi-instance / production deployments
 * a shared store (such as Redis) MUST be used so a revocation issued on one
 * gateway instance is immediately visible to all other instances.
 *
 * The architecture and operational guidance for Redis deployments is
 * documented in `docs/DISTRIBUTED_REVOCATION.md`.
 */

import { Logger, MinHeap, RedisCircuitBreaker, CircuitOpenError, CapabilityError, ErrorCode } from '@euno/common';

/**
 * Thrown (and propagated to the caller as HTTP 503) when the revocation store
 * is temporarily unreachable and `unavailableMode` is set to `'503'`.
 *
 * Extending {@link CapabilityError} means this propagates correctly through
 * the verifier's `try/catch` (which re-throws any `CapabilityError` unchanged)
 * and through the gateway's error-handling middleware (which reads
 * `error.statusCode` to set the HTTP status).  Callers — notably agent
 * runtimes — MUST treat 503 as a transient failure and retry with backoff
 * rather than discarding the token.
 *
 * This error is only thrown when `REVOCATION_UNAVAILABLE_MODE=503` is
 * configured.  The default (fail-closed) preserves backward-compatible
 * behavior: a Redis outage causes all tokens to be treated as revoked (401).
 */
export class RevocationUnavailableError extends CapabilityError {
  constructor() {
    super(
      ErrorCode.REVOCATION_UNAVAILABLE,
      'Revocation check unavailable — the backing store is temporarily unreachable. Retry the request.',
      503,
    );
    this.name = 'RevocationUnavailableError';
  }
}

/**
 * Common interface implemented by all revocation backends.
 */
export interface RevocationStore {
  /**
   * Returns true if the supplied token id has been revoked AND the revocation
   * has not yet expired.  Implementations MUST return false for unknown ids
   * and MUST treat expired revocation entries as absent.
   */
  isRevoked(tokenId: string): Promise<boolean>;

  /**
   * Mark a token id as revoked.  `expiresAt` is the unix-seconds timestamp at
   * which the underlying token would naturally expire; the revocation entry
   * may be pruned once that time has passed.
   */
  revoke(tokenId: string, expiresAt: number): Promise<void>;

  /**
   * Release any resources held by the store (network connections, timers,
   * etc.).  Idempotent.
   */
  close(): Promise<void>;
}

/**
 * In-process revocation store.
 *
 * Uses a Map keyed by JTI with the token expiry (unix seconds) as the value.
 * Stale entries are pruned lazily on lookup and eagerly on insert so the map
 * remains bounded to the active-token window.
 *
 * NOTE: this store is NOT shared across processes.  Use it only for local
 * development, single-instance deployments, or as a fallback when Redis is
 * not configured.
 */
export class InMemoryRevocationStore implements RevocationStore {
  private readonly revokedTokens: Map<string, number> = new Map();
  private readonly expiryHeap = new MinHeap();

  async isRevoked(tokenId: string): Promise<boolean> {
    const expiry = this.revokedTokens.get(tokenId);
    if (expiry === undefined) {
      return false;
    }
    if (expiry <= nowSeconds()) {
      // Lazily remove this specific stale entry; the heap entry will be
      // skipped (lazy-deleted) the next time drainExpired() runs.
      this.revokedTokens.delete(tokenId);
      return false;
    }
    return true;
  }

  async revoke(tokenId: string, expiresAt: number): Promise<void> {
    // Pop every expired entry off the heap front — O(k log n) where k is the
    // number of newly-expired entries — instead of the former O(n) full-map
    // scan that made sustained revocation traffic O(n²).
    const now = nowSeconds();
    this.drainExpired(now);
    this.revokedTokens.set(tokenId, expiresAt);
    this.expiryHeap.push(tokenId, expiresAt);
    // Lazy-deleted entries (removed from the map by isRevoked() but still in
    // the heap) accumulate over time.  If the heap has grown more than twice
    // the map size, rebuild it from the map in O(n) to reclaim memory.
    if (this.expiryHeap.size() > 2 * this.revokedTokens.size) {
      this.expiryHeap.rebuildFrom(this.revokedTokens);
    }
  }

  async close(): Promise<void> {
    this.revokedTokens.clear();
    this.expiryHeap.clear();
  }

  /** Test/debug helper: number of currently-tracked entries. */
  size(): number {
    return this.revokedTokens.size;
  }

  /**
   * Pop every heap node whose expiry has passed and remove it from the map.
   *
   * Lazy-deletion guard: if the map entry for a popped key no longer carries
   * the same expiry (because {@link isRevoked} already cleaned it up, or the
   * token was re-revoked with a different expiry) we simply skip the map
   * deletion — the map is always the authoritative source of truth.
   */
  private drainExpired(now: number): void {
    for (;;) {
      const top = this.expiryHeap.peek();
      if (top === undefined || top.expiry > now) break;
      this.expiryHeap.pop();
      if (this.revokedTokens.get(top.key) === top.expiry) {
        this.revokedTokens.delete(top.key);
      }
    }
  }
}

/**
 * Minimal subset of the redis client surface we depend on.  Defined locally
 * so we do not take a hard runtime dependency on `ioredis` (or any specific
 * client) – callers wire one in via {@link createRedisRevocationStore}.
 *
 * Two `set` overloads are intentional:
 *   - `set(key, value, 'EX', ttl)` — write with an expiry (used by the
 *     per-token revocation store so entries age out automatically).
 *   - `set(key, value)` — write without an expiry (used by the epoch store;
 *     epochs are persistent operator decisions that must survive Redis
 *     restarts and should only be replaced by an explicit admin action).
 */
export interface RedisLikeClient {
  /** Retrieve the value stored at `key`, or `null` if absent. */
  get(key: string): Promise<string | null>;
  exists(key: string): Promise<number>;
  /**
   * Returns the remaining TTL of `key` in seconds.
   * Returns -1 if the key has no expiry, -2 if the key does not exist.
   * Used by the stale-readable revocation store to populate the local cache
   * with the actual Redis expiry instead of a hard-coded sentinel.
   */
  ttl(key: string): Promise<number>;
  /** SET with a TTL — used by the per-token revocation store. */
  set(key: string, value: string, mode: 'EX', ttlSeconds: number): Promise<unknown>;
  /** SET without TTL — used by the epoch store for persistent entries. */
  set(key: string, value: string): Promise<unknown>;
  quit(): Promise<unknown>;
  on(event: string, listener: (...args: unknown[]) => void): unknown;
}

/**
 * Distributed revocation store backed by Redis.
 *
 * Each revocation is stored as a key `revoked:<jti>` with a TTL equal to the
 * remaining lifetime of the underlying token, so Redis itself prunes expired
 * entries.  A revocation issued on one gateway instance is therefore visible
 * to all other instances on the next `isRevoked()` call.
 *
 * **Fail-closed semantics:** if Redis is unreachable the store treats lookups
 * as "revoked" by default so a partitioned gateway cannot accidentally accept
 * tokens that may have been revoked elsewhere.  Pass `failOpen: true` to opt
 * into the (less safe) opposite behaviour for environments where availability
 * matters more than revocation freshness.
 *
 * **503 semantics** (`unavailableMode: '503'`): when Redis is unreachable and
 * no stale-cache entry is available, the store throws a
 * {@link RevocationUnavailableError} (HTTP 503 Service Unavailable) instead
 * of silently treating the token as revoked.  This gives clients accurate
 * retry semantics — they receive 503 ("service temporarily unavailable")
 * rather than a misleading 401 ("token revoked").  Enable via
 * `REVOCATION_UNAVAILABLE_MODE=503`.  Ignored when `staleReadable: true` is
 * also set (the stale cache handles unavailability before reaching this path).
 *
 * **Stale-readable mode** (`staleReadable: true`): the store maintains a
 * local write-through cache of confirmed revocations (JTIs revoked via
 * {@link revoke} or confirmed as revoked by Redis).  When Redis is
 * unreachable and the circuit breaker is open, the store serves from this
 * local cache — tokens that are locally known to be revoked are still
 * denied, while tokens not yet seen are allowed through.  This prevents a
 * Redis blip from becoming a brownout at the cost of a brief window where
 * cross-replica revocations issued after the cache was last refreshed may
 * not be honoured on this replica.  Only enable when availability must be
 * prioritised over perfect cross-replica revocation freshness.
 *
 * **Circuit breaker**: when `circuitBreaker` is supplied, repeated Redis
 * failures trip the circuit to "open" so subsequent `isRevoked()` calls
 * immediately fall through to the local-cache / fail-closed logic without
 * incurring a full TCP timeout on every authorization decision.
 */
export class RedisRevocationStore implements RevocationStore {
  private readonly client: RedisLikeClient;
  private readonly logger: Logger;
  private readonly keyPrefix: string;
  private readonly onError?: () => void;
  private readonly onUnavailable?: () => void;
  private readonly circuitBreaker?: RedisCircuitBreaker;
  /**
   * How to behave when Redis is unreachable and the stale cache cannot serve
   * the request:
   *
   *   - `'fail-closed'` (default): treat the token as revoked → HTTP 401.
   *     Maximally conservative; a Redis outage blocks all traffic.
   *   - `'503'`: throw {@link RevocationUnavailableError} → HTTP 503.
   *     Accurate retry semantics; clients retry rather than abandoning their
   *     token.  Recommended over `fail-closed` when you have operational SLAs
   *     that require transparent retry.
   *   - `'open'`: treat the token as not revoked → allow through.
   *     Use only when availability matters more than revocation correctness.
   *     Equivalent to `failOpen: true` on the legacy API.
   */
  private readonly unavailableMode: 'fail-closed' | '503' | 'open';
  /**
   * When `staleReadable` is true this map is kept in sync with every
   * `revoke()` call and every confirmed-revoked response from Redis.
   * Entries expire in lock-step with the token TTL so the map stays
   * bounded to the active-token window.
   */
  private readonly staleReadable: boolean;
  private readonly localRevokedCache: Map<string, number> = new Map(); // jti → expiresAt (unix s)

  constructor(
    client: RedisLikeClient,
    logger: Logger,
    options: {
      keyPrefix?: string;
      failOpen?: boolean;
      onError?: () => void;
      /**
       * Callback invoked whenever the revocation store cannot complete a check
       * because Redis is unavailable (circuit open or connection error) AND
       * the store is returning a degraded response (fail-closed, 503, or stale).
       * Use to increment a Prometheus counter so operators can distinguish
       * "store degraded" from "store healthy" on the metrics dashboard.
       */
      onUnavailable?: () => void;
      /**
       * Optional circuit breaker.  When provided, Redis calls are wrapped so
       * that repeated failures trip the circuit to "open" and subsequent
       * requests fail immediately (no TCP timeout on the hot path).
       */
      circuitBreaker?: RedisCircuitBreaker;
      /**
       * When true, a local write-through cache of confirmed revocations is
       * kept.  On circuit-open (or any Redis error), the store serves from
       * this cache instead of blanket-denying all tokens.  Default: false.
       */
      staleReadable?: boolean;
      /**
       * How to handle a Redis unavailability when the stale cache cannot
       * serve the request.  Default: `'fail-closed'` (back-compat).
       *
       * - `'fail-closed'`: treat the token as revoked (→ 401).
       * - `'503'`: throw {@link RevocationUnavailableError} (→ 503).
       * - `'open'`: allow the token through (→ allow).
       *
       * Ignored when `staleReadable: true` is also set; in that case the
       * stale cache handles unavailability.
       */
      unavailableMode?: 'fail-closed' | '503' | 'open';
    } = {}
  ) {
    this.client = client;
    this.logger = logger;
    this.keyPrefix = options.keyPrefix ?? 'revoked:';
    // Legacy `failOpen` option maps to `unavailableMode: 'open'` when set.
    // `unavailableMode` takes precedence when both are supplied.
    const legacyFailOpen = options.failOpen ?? false;
    this.unavailableMode = options.unavailableMode ?? (legacyFailOpen ? 'open' : 'fail-closed');
    this.onError = options.onError;
    this.onUnavailable = options.onUnavailable;
    this.circuitBreaker = options.circuitBreaker;
    this.staleReadable = options.staleReadable ?? false;

    this.client.on('error', (err: unknown) => {
      this.logger.error('Redis revocation store connection error', {
        error: err instanceof Error ? err.message : 'Unknown error',
      });
      // Surface connection-level errors to the circuit breaker so it can
      // trip even when no in-flight execute() call is pending.
      this.circuitBreaker?.recordFailure();
    });
  }

  async isRevoked(tokenId: string): Promise<boolean> {
    try {
      let exists: number;
      if (this.circuitBreaker) {
        exists = await this.circuitBreaker.execute(() => this.client.exists(this.key(tokenId)));
      } else {
        exists = await this.client.exists(this.key(tokenId));
      }
      const revoked = exists === 1;
      if (this.staleReadable) {
        // Prune expired entries on every successful Redis round-trip so the
        // local cache stays bounded even when entries are only added via
        // isRevoked() (and never via revoke()).
        this.pruneLocalCache();
        if (revoked) {
          // Cache the revocation with the real Redis TTL so the stale entry
          // expires in lock-step with the key in Redis, regardless of the
          // token's configured TTL.
          try {
            let remaining: number;
            if (this.circuitBreaker) {
              remaining = await this.circuitBreaker.execute(() =>
                this.client.ttl(this.key(tokenId)),
              );
            } else {
              remaining = await this.client.ttl(this.key(tokenId));
            }
            // remaining === -2: key vanished between exists and ttl (race) — skip
            // remaining === -1: key has no expiry (unexpected) — use existing entry
            if (remaining > 0) {
              this.localRevokedCache.set(tokenId, nowSeconds() + remaining);
            }
          } catch {
            // TTL fetch failed; fall back to the value already in the cache
            // (set by a prior revoke() call) or leave the entry absent.
            // Either way we already have the correct `revoked = true` answer.
          }
        }
      }
      return revoked;
    } catch (error) {
      const isCircuitOpen = error instanceof CircuitOpenError;
      if (!isCircuitOpen) {
        this.logger.error('Failed to query revocation status from Redis', {
          tokenId,
          error: error instanceof Error ? error.message : 'Unknown error',
          unavailableMode: this.unavailableMode,
          staleReadable: this.staleReadable,
        });
        this.onError?.();
      }
      // Stale-readable: serve from local cache on circuit-open or Redis error.
      if (this.staleReadable) {
        const expiry = this.localRevokedCache.get(tokenId);
        if (expiry !== undefined) {
          if (expiry > nowSeconds()) {
            this.logger.debug('Serving revocation status from stale local cache', {
              tokenId,
              circuitOpen: isCircuitOpen,
            });
            return true;
          }
          // Cached entry has expired — prune and treat as not revoked.
          this.localRevokedCache.delete(tokenId);
        }
        // Not in local revocation cache and Redis is unreachable: allow.
        // The operator has opted in to availability over perfect consistency.
        if (!isCircuitOpen) {
          this.logger.debug('Redis unavailable for revocation check; token not in local cache — allowing (stale-readable mode)', {
            tokenId,
          });
        }
        return false;
      }
      // Signal unavailability via the callback for any non-open mode.
      if (this.unavailableMode !== 'open') {
        this.onUnavailable?.();
      }
      if (this.unavailableMode === '503') {
        // Throw a 503 error so the gateway can surface accurate retry
        // semantics to the agent runtime (service temporarily unavailable)
        // rather than a misleading 401 (token revoked).
        if (!isCircuitOpen) {
          this.logger.warn('Redis revocation store unavailable; returning 503 (unavailableMode=503)', {
            tokenId,
          });
        }
        throw new RevocationUnavailableError();
      }
      if (this.unavailableMode === 'open') {
        return false;
      }
      // Default: fail-closed — treat token as revoked.
      return true;
    }
  }

  async revoke(tokenId: string, expiresAt: number): Promise<void> {
    const now = nowSeconds();
    const ttl = Math.max(expiresAt - now, 0);
    if (ttl <= 0) {
      // Token is already past its natural expiry – nothing to revoke.
      this.logger.warn('Skipping Redis revocation for already-expired token', { tokenId });
      return;
    }
    // Always update the local stale cache so the circuit-open fallback
    // can honour revocations issued on this replica even when Redis is down.
    if (this.staleReadable) {
      this.pruneLocalCache();
      this.localRevokedCache.set(tokenId, expiresAt);
    }
    try {
      await this.client.set(this.key(tokenId), '1', 'EX', ttl);
      this.logger.info('Token revoked in Redis', { tokenId, ttlSeconds: ttl });
    } catch (error) {
      this.logger.error('Failed to revoke token in Redis', {
        tokenId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw error;
    }
  }

  async close(): Promise<void> {
    this.localRevokedCache.clear();
    try {
      await this.client.quit();
    } catch (error) {
      this.logger.warn('Error while closing Redis revocation store client', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  private key(tokenId: string): string {
    return `${this.keyPrefix}${tokenId}`;
  }

  /** Prune expired entries from the local stale cache. */
  private pruneLocalCache(): void {
    const now = nowSeconds();
    for (const [jti, expiry] of this.localRevokedCache) {
      if (expiry <= now) {
        this.localRevokedCache.delete(jti);
      }
    }
  }

  /** Test/debug helper: size of the stale-readable local cache. */
  localCacheSize(): number {
    return this.localRevokedCache.size;
  }
}

/**
 * Lazily construct a {@link RedisRevocationStore} backed by `ioredis`.
 *
 * `ioredis` is loaded with a runtime `require()` so deployments that do not
 * use Redis are not forced to install it.  When the dependency is absent and
 * the operator has explicitly requested Redis (by setting `REDIS_URL` or
 * `REVOCATION_REDIS_URL`), this function logs a clear error and falls back to
 * {@link InMemoryRevocationStore} so the gateway can still start.
 *
 * **Per-store Redis URL**: `REVOCATION_REDIS_URL` takes precedence over the
 * shared `REDIS_URL`.  This allows the revocation store to be backed by a
 * dedicated Redis instance (e.g. a highly-available cluster or Sentinel setup)
 * that is isolated from the kill-switch and call-counter Redis, so an outage
 * on one store does not cascade to the others.
 */
export async function createRevocationStoreFromEnv(
  env: NodeJS.ProcessEnv,
  logger: Logger,
  /** Optional callback invoked on every Redis error so callers can increment a Prometheus counter. */
  onError?: () => void,
  /** Optional externally-created circuit breaker so the caller can read its state for metrics. */
  circuitBreaker?: RedisCircuitBreaker,
  /**
   * Optional callback invoked whenever the revocation store cannot serve a
   * check because Redis is unavailable and the degraded response is returned.
   * Fires for both `fail-closed` and `503` modes (not for `open` mode since
   * that represents an intentional availability trade-off).  Use to increment
   * a dedicated Prometheus counter so operators can distinguish a degraded
   * revocation surface from general Redis errors.
   */
  onUnavailable?: () => void,
): Promise<RevocationStore> {
  const redisUrl = env.REVOCATION_REDIS_URL || env.REDIS_URL;
  if (!redisUrl) {
    logger.info('REDIS_URL not configured, using in-memory revocation store');
    return new InMemoryRevocationStore();
  }

  let RedisCtor: unknown;
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    RedisCtor = require('ioredis');
  } catch (error) {
    const isProduction =
      env.NODE_ENV === 'production' ||
      (env.EUNO_DEPLOYMENT_TIER && env.EUNO_DEPLOYMENT_TIER !== 'single-replica');
    if (isProduction) {
      throw new Error(
        'REDIS_URL is set but the "ioredis" package is not installed. ' +
        'Install it (npm install ioredis) to enable distributed revocation. ' +
        'Refusing to fall back to the in-memory revocation store in a production / ' +
        'multi-replica deployment: revocations issued on one instance would be ' +
        'invisible to all others, defeating the revocation guarantee. ' +
        `Original error: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    }
    logger.error(
      'REDIS_URL is set but the "ioredis" package is not installed. ' +
      'Install it (npm install ioredis) to enable distributed revocation. ' +
      'Falling back to in-memory revocation store; revocations WILL NOT be ' +
      'shared across gateway instances. This is only acceptable in development / ' +
      'single-replica deployments.',
      { error: error instanceof Error ? error.message : 'Unknown error' },
    );
    return new InMemoryRevocationStore();
  }

  // ioredis exports the constructor as either the module itself (CJS default)
  // or as `default` when imported via interop.
  const Ctor = (RedisCtor as { default?: unknown }).default ?? RedisCtor;
  const client = new (Ctor as new (url: string, opts?: unknown) => RedisLikeClient)(redisUrl, {
    // Bounded exponential backoff so transient outages do not turn into
    // unbounded latency on the request path.
    retryStrategy: (times: number) => Math.min(times * 50, 2000),
    maxRetriesPerRequest: 3,
    lazyConnect: false,
  });

  const failOpen = env.REVOCATION_FAIL_OPEN === 'true';
  const staleReadable = env.REVOCATION_STALE_READABLE === 'true';
  const keyPrefix = env.REVOCATION_KEY_PREFIX || 'revoked:';

  // Parse REVOCATION_UNAVAILABLE_MODE; default is 'fail-closed' for back-compat.
  // When REVOCATION_FAIL_OPEN=true is set without an explicit unavailableMode,
  // treat it as 'open' (legacy behaviour preserved).
  const rawUnavailableMode = env.REVOCATION_UNAVAILABLE_MODE;
  let unavailableMode: 'fail-closed' | '503' | 'open';
  if (rawUnavailableMode === '503' || rawUnavailableMode === 'open' || rawUnavailableMode === 'fail-closed') {
    unavailableMode = rawUnavailableMode;
  } else if (failOpen) {
    unavailableMode = 'open';
  } else {
    unavailableMode = 'fail-closed';
  }

  const modeDescription = staleReadable
    ? 'stale-readable (local cache fallback on Redis outage)'
    : unavailableMode;
  logger.info('Using Redis revocation store for distributed token revocation', {
    keyPrefix,
    unavailableMode: modeDescription,
    circuitBreakerEnabled: !!circuitBreaker,
    dedicatedUrl: !!env.REVOCATION_REDIS_URL,
  });

  return new RedisRevocationStore(client, logger, {
    keyPrefix,
    unavailableMode: staleReadable ? 'fail-closed' : unavailableMode,
    onError,
    onUnavailable,
    circuitBreaker,
    staleReadable,
  });
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

// ── RevocationEpochStore ──────────────────────────────────────────────────

/**
 * Per-issuer revocation epoch store.
 *
 * An epoch is a unix-seconds timestamp recorded against an issuer identifier
 * (`iss` claim).  The gateway rejects any token whose `iat` (issued-at) is
 * strictly before the epoch, regardless of whether the individual `jti` is in
 * the revocation list.
 *
 * This gives incident responders a single-knob "cut-off" mechanism: setting
 * an epoch to "now" immediately invalidates every outstanding token from that
 * issuer without enumerating their individual JTIs.
 *
 * Operationally this complements (not replaces) per-token revocation:
 *   - Per-token revocation: precise, O(outstanding-tokens) write cost.
 *   - Epoch revocation: coarse, O(1) write cost — use when a signing key is
 *     compromised and every issued token must be invalidated.
 */
export interface RevocationEpochStore {
  /**
   * Returns the epoch (unix seconds) for the given issuer, or `null` if no
   * epoch is configured.  The caller MUST reject any token whose `iat` is
   * strictly less than the returned epoch.
   *
   * **Fail-closed contract:** implementations that cannot reach their backing
   * store MUST either throw or return a present-time epoch value (rather than
   * `null`), so a storage outage cannot silently bypass the epoch cut-off.
   * `RedisRevocationEpochStore` honours this via `failOpen` — default `false`.
   */
  getEpoch(issuer: string): Promise<number | null>;

  /**
   * Set (or replace) the epoch for an issuer.  Any token from this issuer
   * with `iat < epochSeconds` will be rejected on the next verification.
   *
   * Passing an `epochSeconds` of `0` is equivalent to clearing the epoch.
   */
  setEpoch(issuer: string, epochSeconds: number): Promise<void>;

  /**
   * Release any resources held by the store.  Idempotent.
   */
  close(): Promise<void>;
}

/**
 * In-process epoch store.
 *
 * Keyed by issuer with the epoch (unix seconds) as the value.  Suitable for
 * single-instance deployments and local development; use
 * {@link RedisRevocationEpochStore} for multi-replica deployments so an epoch
 * set on one gateway instance is immediately honoured by all others.
 */
export class InMemoryRevocationEpochStore implements RevocationEpochStore {
  private epochs: Map<string, number> = new Map();

  async getEpoch(issuer: string): Promise<number | null> {
    return this.epochs.get(issuer) ?? null;
  }

  async setEpoch(issuer: string, epochSeconds: number): Promise<void> {
    this.epochs.set(issuer, epochSeconds);
  }

  async close(): Promise<void> {
    this.epochs.clear();
  }

  /** Test/debug helper: number of currently-tracked entries. */
  size(): number {
    return this.epochs.size;
  }
}

/**
 * Distributed epoch store backed by Redis.
 *
 * Each epoch is stored as a key `<prefix><issuer>` with the unix-seconds
 * timestamp as the string value (no TTL — epochs are persistent until
 * overwritten by an operator action).  An epoch set on one gateway instance
 * is therefore honoured by every other replica on the next `getEpoch()` call.
 *
 * **Fail-closed semantics:** if Redis is unreachable the store returns
 * the current wall-clock time as the epoch, which causes the verifier to
 * reject all tokens (since any validly-issued token has `iat <= now`).
 * Pass `failOpen: true` to opt into the (less safe) behaviour of treating
 * an unavailable epoch store as "no epoch configured" — available requests
 * are accepted at the cost of potentially bypassing an active epoch.
 *
 * **Stale-readable mode** (`staleReadable: true`): the store maintains a
 * local write-through cache of epochs set via {@link setEpoch} and confirmed
 * values from Redis.  On circuit-open or any Redis error it returns the cached
 * epoch (or `null` if no epoch has been observed for this issuer).  This
 * avoids a Redis blip invalidating every token fleet-wide, while still
 * honouring any epoch previously written through this or another replica's
 * cache.
 *
 * **Circuit breaker**: when `circuitBreaker` is supplied, repeated Redis
 * failures trip the circuit to "open" so subsequent `getEpoch()` calls
 * immediately fall through to the stale-cache / fail-closed logic.
 */
export class RedisRevocationEpochStore implements RevocationEpochStore {
  private readonly client: RedisLikeClient;
  private readonly logger: Logger;
  private readonly keyPrefix: string;
  private readonly failOpen: boolean;
  private readonly onError?: () => void;
  private readonly circuitBreaker?: RedisCircuitBreaker;
  private readonly staleReadable: boolean;
  /**
   * Local write-through cache for epochs.  Populated by `setEpoch()` calls
   * and by successful `getEpoch()` responses so the stale-readable fallback
   * has data to serve when Redis is temporarily unavailable.
   */
  private readonly localEpochCache: Map<string, number> = new Map();

  constructor(
    client: RedisLikeClient,
    logger: Logger,
    options: {
      keyPrefix?: string;
      failOpen?: boolean;
      onError?: () => void;
      /**
       * Optional circuit breaker.  When provided, Redis calls are wrapped so
       * that repeated failures trip the circuit to "open" and subsequent
       * requests fail immediately.
       */
      circuitBreaker?: RedisCircuitBreaker;
      /**
       * When true, a local cache of epochs is maintained.  On circuit-open
       * or any Redis error the store returns the cached value instead of
       * failing closed.  Default: false.
       */
      staleReadable?: boolean;
    } = {}
  ) {
    this.client = client;
    this.logger = logger;
    this.keyPrefix = options.keyPrefix ?? 'epoch:';
    this.failOpen = options.failOpen ?? false;
    this.onError = options.onError;
    this.circuitBreaker = options.circuitBreaker;
    this.staleReadable = options.staleReadable ?? false;

    this.client.on('error', (err: unknown) => {
      this.logger.error('Redis epoch store connection error', {
        error: err instanceof Error ? err.message : 'Unknown error',
      });
      this.circuitBreaker?.recordFailure();
    });
  }

  async getEpoch(issuer: string): Promise<number | null> {
    try {
      let raw: string | null;
      if (this.circuitBreaker) {
        raw = await this.circuitBreaker.execute(() => this.client.get(this.key(issuer)));
      } else {
        raw = await this.client.get(this.key(issuer));
      }
      if (raw === null) {
        if (this.staleReadable) {
          // Cache a confirmed "no epoch" so we don't keep hitting Redis for
          // the same issuer — but we don't store null, we just leave the
          // cache empty for this issuer.
        }
        return null;
      }
      const epoch = parseInt(raw, 10);
      const value = isNaN(epoch) ? null : epoch;
      // Populate stale cache with confirmed epoch values.
      if (value !== null && this.staleReadable) {
        this.localEpochCache.set(issuer, value);
      }
      return value;
    } catch (error) {
      const isCircuitOpen = error instanceof CircuitOpenError;
      if (!isCircuitOpen) {
        this.logger.error('Failed to query epoch from Redis', {
          issuer,
          error: error instanceof Error ? error.message : 'Unknown error',
          failMode: this.failOpen ? 'open' : 'closed',
          staleReadable: this.staleReadable,
        });
        this.onError?.();
      }
      // Stale-readable: return cached epoch (if any) on circuit-open or error.
      if (this.staleReadable) {
        const cached = this.localEpochCache.get(issuer);
        if (cached !== undefined) {
          this.logger.debug('Serving revocation epoch from stale local cache', {
            issuer,
            epoch: cached,
            circuitOpen: isCircuitOpen,
          });
          return cached;
        }
        // No cached epoch for this issuer — treat as no epoch (allow).
        return null;
      }
      if (this.failOpen) {
        return null;
      }
      // Fail closed: return one second past the current wall-clock time.
      // The verifier rejects tokens where iat < epoch (strict less-than), so
      // returning nowSeconds() would allow a token minted in the same second
      // as the Redis error to slip through (iat === now → not rejected).
      // Adding one second ensures that even a token minted right now satisfies
      // iat <= now < now+1, and is therefore correctly blocked until the store
      // recovers.
      return nowSeconds() + 1;
    }
  }

  async setEpoch(issuer: string, epochSeconds: number): Promise<void> {
    // Always update the local stale cache first so this replica honours
    // the epoch immediately (regardless of whether Redis is reachable).
    if (this.staleReadable) {
      this.localEpochCache.set(issuer, epochSeconds);
    }
    try {
      await this.client.set(this.key(issuer), String(epochSeconds));
      this.logger.info('Revocation epoch set in Redis', { issuer, epochSeconds });
    } catch (error) {
      this.logger.error('Failed to set epoch in Redis', {
        issuer,
        epochSeconds,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw error;
    }
  }

  async close(): Promise<void> {
    this.localEpochCache.clear();
    try {
      await this.client.quit();
    } catch (error) {
      this.logger.warn('Error while closing Redis epoch store client', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  private key(issuer: string): string {
    return `${this.keyPrefix}${issuer}`;
  }
}

/**
 * Lazily construct a {@link RedisRevocationEpochStore} backed by `ioredis`,
 * following the same pattern as {@link createRevocationStoreFromEnv}.
 *
 * Falls back to {@link InMemoryRevocationEpochStore} when neither
 * `REVOCATION_REDIS_URL` nor `REDIS_URL` is set.  In production /
 * multi-replica deployments without Redis the function throws so
 * misconfiguration is caught at startup rather than silently providing an
 * epoch store that is invisible to other replicas.
 *
 * **Per-store Redis URL**: `REVOCATION_REDIS_URL` takes precedence over the
 * shared `REDIS_URL` — the epoch store shares a Redis instance with the
 * per-token revocation store so a single dedicated cluster covers both.
 */
export async function createRevocationEpochStoreFromEnv(
  env: NodeJS.ProcessEnv,
  logger: Logger,
  /** Optional callback invoked on every Redis error so callers can increment a Prometheus counter. */
  onError?: () => void,
  /** Optional externally-created circuit breaker so the caller can read its state for metrics. */
  circuitBreaker?: RedisCircuitBreaker,
): Promise<RevocationEpochStore> {
  const redisUrl = env.REVOCATION_REDIS_URL || env.REDIS_URL;
  if (!redisUrl) {
    logger.info('REDIS_URL not configured, using in-memory revocation epoch store');
    return new InMemoryRevocationEpochStore();
  }

  let RedisCtor: unknown;
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    RedisCtor = require('ioredis');
  } catch (error) {
    const isProduction =
      env.NODE_ENV === 'production' ||
      (env.EUNO_DEPLOYMENT_TIER && env.EUNO_DEPLOYMENT_TIER !== 'single-replica');
    if (isProduction) {
      throw new Error(
        'REDIS_URL is set but the "ioredis" package is not installed. ' +
        'Install it (npm install ioredis) to enable distributed epoch revocation. ' +
        'Refusing to fall back to the in-memory epoch store in a production / ' +
        'multi-replica deployment: epochs set on one instance would be invisible ' +
        'to all others, defeating the epoch-revocation guarantee. ' +
        `Original error: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    }
    logger.error(
      'REDIS_URL is set but the "ioredis" package is not installed. ' +
      'Falling back to in-memory epoch store; epochs WILL NOT be shared ' +
      'across gateway instances. This is only acceptable in development / ' +
      'single-replica deployments.',
      { error: error instanceof Error ? error.message : 'Unknown error' },
    );
    return new InMemoryRevocationEpochStore();
  }

  const Ctor = (RedisCtor as { default?: unknown }).default ?? RedisCtor;
  const client = new (Ctor as new (url: string, opts?: unknown) => RedisLikeClient)(redisUrl, {
    retryStrategy: (times: number) => Math.min(times * 50, 2000),
    maxRetriesPerRequest: 3,
    lazyConnect: false,
  });

  const failOpen = env.REVOCATION_EPOCH_FAIL_OPEN === 'true';
  const staleReadable = env.REVOCATION_STALE_READABLE === 'true';
  const keyPrefix = env.REVOCATION_EPOCH_KEY_PREFIX || 'epoch:';

  const modeDescription = staleReadable
    ? 'stale-readable (local cache fallback on Redis outage)'
    : failOpen
      ? 'open'
      : 'closed';
  logger.info('Using Redis epoch store for distributed epoch revocation', {
    keyPrefix,
    failMode: modeDescription,
    circuitBreakerEnabled: !!circuitBreaker,
    dedicatedUrl: !!env.REVOCATION_REDIS_URL,
  });

  return new RedisRevocationEpochStore(client, logger, {
    keyPrefix,
    failOpen: staleReadable ? false : failOpen,
    onError,
    circuitBreaker,
    staleReadable,
  });
}
