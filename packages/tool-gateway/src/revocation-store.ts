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

import { Logger, MinHeap } from '@euno/common';

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
 */
export class RedisRevocationStore implements RevocationStore {
  private readonly client: RedisLikeClient;
  private readonly logger: Logger;
  private readonly keyPrefix: string;
  private readonly failOpen: boolean;
  private readonly onError?: () => void;

  constructor(
    client: RedisLikeClient,
    logger: Logger,
    options: { keyPrefix?: string; failOpen?: boolean; onError?: () => void } = {}
  ) {
    this.client = client;
    this.logger = logger;
    this.keyPrefix = options.keyPrefix ?? 'revoked:';
    this.failOpen = options.failOpen ?? false;
    this.onError = options.onError;

    this.client.on('error', (err: unknown) => {
      this.logger.error('Redis revocation store connection error', {
        error: err instanceof Error ? err.message : 'Unknown error',
      });
    });
  }

  async isRevoked(tokenId: string): Promise<boolean> {
    try {
      const exists = await this.client.exists(this.key(tokenId));
      return exists === 1;
    } catch (error) {
      this.logger.error('Failed to query revocation status from Redis', {
        tokenId,
        error: error instanceof Error ? error.message : 'Unknown error',
        failMode: this.failOpen ? 'open' : 'closed',
      });
      this.onError?.();
      // Default: fail closed.  An attacker (or split-brain network) cannot
      // bypass revocation by knocking out Redis.
      return !this.failOpen;
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
}

/**
 * Lazily construct a {@link RedisRevocationStore} backed by `ioredis`.
 *
 * `ioredis` is loaded with a runtime `require()` so deployments that do not
 * use Redis are not forced to install it.  When the dependency is absent and
 * the operator has explicitly requested Redis (by setting `REDIS_URL`), this
 * function logs a clear error and falls back to {@link InMemoryRevocationStore}
 * so the gateway can still start.
 */
export async function createRevocationStoreFromEnv(
  env: NodeJS.ProcessEnv,
  logger: Logger,
  /** Optional callback invoked on every Redis error so callers can increment a Prometheus counter. */
  onError?: () => void,
): Promise<RevocationStore> {
  const redisUrl = env.REDIS_URL;
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
  const keyPrefix = env.REVOCATION_KEY_PREFIX || 'revoked:';

  logger.info('Using Redis revocation store for distributed token revocation', {
    keyPrefix,
    failMode: failOpen ? 'open' : 'closed',
  });

  return new RedisRevocationStore(client, logger, { keyPrefix, failOpen, onError });
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
 */
export class RedisRevocationEpochStore implements RevocationEpochStore {
  private readonly client: RedisLikeClient;
  private readonly logger: Logger;
  private readonly keyPrefix: string;
  private readonly failOpen: boolean;
  private readonly onError?: () => void;

  constructor(
    client: RedisLikeClient,
    logger: Logger,
    options: { keyPrefix?: string; failOpen?: boolean; onError?: () => void } = {}
  ) {
    this.client = client;
    this.logger = logger;
    this.keyPrefix = options.keyPrefix ?? 'epoch:';
    this.failOpen = options.failOpen ?? false;
    this.onError = options.onError;

    this.client.on('error', (err: unknown) => {
      this.logger.error('Redis epoch store connection error', {
        error: err instanceof Error ? err.message : 'Unknown error',
      });
    });
  }

  async getEpoch(issuer: string): Promise<number | null> {
    try {
      const raw = await this.client.get(this.key(issuer));
      if (raw === null) return null;
      const epoch = parseInt(raw, 10);
      return isNaN(epoch) ? null : epoch;
    } catch (error) {
      this.logger.error('Failed to query epoch from Redis', {
        issuer,
        error: error instanceof Error ? error.message : 'Unknown error',
        failMode: this.failOpen ? 'open' : 'closed',
      });
      this.onError?.();
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
 * Falls back to {@link InMemoryRevocationEpochStore} when `REDIS_URL` is unset.
 * In production / multi-replica deployments without Redis the function throws
 * so misconfiguration is caught at startup rather than silently providing an
 * epoch store that is invisible to other replicas.
 */
export async function createRevocationEpochStoreFromEnv(
  env: NodeJS.ProcessEnv,
  logger: Logger,
  /** Optional callback invoked on every Redis error so callers can increment a Prometheus counter. */
  onError?: () => void,
): Promise<RevocationEpochStore> {
  const redisUrl = env.REDIS_URL;
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
  const keyPrefix = env.REVOCATION_EPOCH_KEY_PREFIX || 'epoch:';

  logger.info('Using Redis epoch store for distributed epoch revocation', {
    keyPrefix,
    failMode: failOpen ? 'open' : 'closed',
  });

  return new RedisRevocationEpochStore(client, logger, { keyPrefix, failOpen, onError });
}
