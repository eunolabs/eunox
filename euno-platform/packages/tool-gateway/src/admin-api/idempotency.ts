/**
 * Idempotency store for admin API mutations.
 *
 * Extracted from admin-api.ts to keep the monolith under control.  The public
 * types and classes are re-exported from `admin-api.ts` for backward compat.
 */

// =============================================================================
// Types
// =============================================================================

/**
 * A single entry in the idempotency store.
 *
 * Exported so callers can type-hint against the stored shape (e.g. when
 * implementing an alternative `AdminIdempotencyStore` backed by Redis).
 */
export interface IdempotencyEntry {
  /** The HTTP status code of the original response. */
  status: number;
  /** The JSON body of the original response. */
  body: unknown;
  /** Endpoint that handled the original request (method + concrete request path). */
  endpoint: string;
  /** Expiry in milliseconds since epoch. */
  expiresAt: number;
}

/**
 * Shared interface for both the in-memory and Redis-backed idempotency stores.
 *
 * `get` and `set` may return synchronously or via a Promise so that the
 * in-memory implementation can keep its simple synchronous internals while
 * allowing the Redis-backed implementation to use proper async I/O.  All
 * call sites use `await Promise.resolve(store.get(...))` to handle both.
 */
export interface IAdminIdempotencyStore {
  get(key: string): Promise<IdempotencyEntry | undefined> | (IdempotencyEntry | undefined);
  set(
    key: string,
    endpoint: string,
    status: number,
    body: unknown,
  ): Promise<IdempotencyEntry> | IdempotencyEntry;
}

/**
 * Minimal Redis client surface required by {@link RedisAdminIdempotencyStore}.
 * Defined locally so the gateway does not take a hard runtime dependency on
 * `ioredis` — callers supply a pre-wired Redis client (e.g. an ioredis `Redis`
 * instance) and pass it to `new RedisAdminIdempotencyStore(client)`.
 */
export interface RedisIdempotencyClient {
  set(
    key: string,
    value: string,
    expiryMode: 'EX',
    ttlSeconds: number,
    setMode: 'NX',
  ): Promise<'OK' | null>;
  get(key: string): Promise<string | null>;
  quit(): Promise<unknown>;
  on(event: string, listener: (...args: unknown[]) => void): unknown;
}

// =============================================================================
// Implementations
// =============================================================================

/**
 * In-memory idempotency store for admin API mutations.
 *
 * Keyed by the value of the caller-supplied `Idempotency-Key` header.
 * Entries expire after `ttlMs` (default {@link AdminIdempotencyStore.DEFAULT_TTL_MS}, 24 hours) and are pruned lazily on
 * insert when the map grows beyond `maxSize`.
 *
 * This implementation is local-process only.  In a multi-replica deployment
 * the same idempotency key sent to two different replicas will be processed
 * twice.  For Stage 3 this is acceptable — the admin surface already lives
 * on a separate port targeted by a ClusterIP Service, so a single replica
 * typically handles all admin traffic.  A Redis-backed implementation can
 * replace this class without changing the callers.
 */
export class AdminIdempotencyStore {
  private readonly store = new Map<string, IdempotencyEntry>();
  private readonly ttlMs: number;
  private readonly maxSize: number;

  /**
   * Default TTL for idempotency entries: 24 hours in milliseconds.
   * Exposed as a named constant so callers can reference it without magic numbers.
   */
  static readonly DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;

  constructor(opts: { ttlMs?: number; maxSize?: number } = {}) {
    this.ttlMs = opts.ttlMs ?? AdminIdempotencyStore.DEFAULT_TTL_MS;
    this.maxSize = opts.maxSize ?? 10_000;
  }

  /** Return a cached entry if one exists and has not expired; undefined otherwise. */
  get(key: string): IdempotencyEntry | undefined {
    const entry = this.store.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return undefined;
    }
    return entry;
  }

  /** Store a completed response keyed by the idempotency key. */
  set(key: string, endpoint: string, status: number, body: unknown): IdempotencyEntry {
    // When the store is at capacity, first try to prune expired entries.
    if (this.store.size >= this.maxSize) {
      const now = Date.now();
      for (const [k, v] of this.store) {
        if (now > v.expiresAt) this.store.delete(k);
      }
    }
    // If still at capacity after pruning, evict oldest entries (Map iteration
    // order is insertion order) until we have room for the new entry.
    while (this.store.size >= this.maxSize) {
      const oldestKey = this.store.keys().next().value;
      if (oldestKey !== undefined) {
        this.store.delete(oldestKey);
      } else {
        break; // Defensive: should not happen, but avoid infinite loop.
      }
    }
    const entry: IdempotencyEntry = {
      status,
      body,
      endpoint,
      expiresAt: Date.now() + this.ttlMs,
    };
    this.store.set(key, entry);
    return entry;
  }
}

/**
 * Redis-backed idempotency store for admin API mutations (DI-3).
 *
 * Replaces the in-memory {@link AdminIdempotencyStore} for multi-replica
 * deployments where the same idempotency key might be sent to different
 * replicas (e.g. after a rolling restart re-routes admin traffic).
 *
 * Uses atomic `SET key value EX ttl NX` on write — the NX flag means the
 * first replica to process a given key wins; all subsequent replicas return
 * the cached entry.  `GET key` on read returns `null` when the entry has
 * expired (Redis TTL enforcement) or was never set.
 *
 * Key format: `<keyPrefix><idempotencyKey>` (default prefix `idempotency:`).
 */
export class RedisAdminIdempotencyStore {
  private readonly client: RedisIdempotencyClient;
  private readonly keyPrefix: string;
  private readonly ttlMs: number;
  private readonly logger?: { warn: (msg: string, meta?: Record<string, unknown>) => void };

  static readonly DEFAULT_TTL_MS = AdminIdempotencyStore.DEFAULT_TTL_MS;
  static readonly DEFAULT_KEY_PREFIX = 'idempotency:';

  constructor(
    client: RedisIdempotencyClient,
    opts: {
      keyPrefix?: string;
      ttlMs?: number;
      logger?: { warn: (msg: string, meta?: Record<string, unknown>) => void };
    } = {},
  ) {
    this.client = client;
    this.keyPrefix = opts.keyPrefix ?? RedisAdminIdempotencyStore.DEFAULT_KEY_PREFIX;
    this.ttlMs = opts.ttlMs ?? RedisAdminIdempotencyStore.DEFAULT_TTL_MS;
    this.logger = opts.logger;
  }

  /**
   * Return a cached entry if one exists and has not expired; undefined
   * otherwise.  Expired entries are evicted by Redis TTL automatically.
   */
  async get(key: string): Promise<IdempotencyEntry | undefined> {
    const raw = await this.client.get(this.keyPrefix + key);
    if (!raw) return undefined;
    try {
      const entry = JSON.parse(raw) as IdempotencyEntry;
      // Guard against a race where the entry expires after GET but before
      // the caller uses it (very narrow window; tolerable for idempotency).
      if (Date.now() > entry.expiresAt) return undefined;
      return entry;
    } catch {
      return undefined;
    }
  }

  /**
   * Store a completed response keyed by the idempotency key, using NX
   * semantics so a concurrent replica cannot overwrite an in-flight entry.
   */
  async set(key: string, endpoint: string, status: number, body: unknown): Promise<IdempotencyEntry> {
    const entry: IdempotencyEntry = {
      status,
      body,
      endpoint,
      expiresAt: Date.now() + this.ttlMs,
    };
    const ttlSeconds = Math.ceil(this.ttlMs / 1000);
    // Fire-and-forget — a Redis write failure is not fatal for idempotency
    // (the operation has already executed; not caching the result means the
    // caller might re-execute on a retry, which is the pre-Redis behaviour).
    // We log at warn level so operators can detect Redis connectivity issues.
    await this.client
      .set(this.keyPrefix + key, JSON.stringify(entry), 'EX', ttlSeconds, 'NX')
      .catch((err: unknown) => {
        this.logger?.warn('RedisAdminIdempotencyStore: failed to cache idempotency key', {
          key,
          error: err instanceof Error ? err.message : String(err),
        });
      });
    return entry;
  }
}

/**
 * Factory that returns a {@link RedisAdminIdempotencyStore} when a pre-wired
 * Redis client is supplied, or an in-memory {@link AdminIdempotencyStore}
 * otherwise.
 *
 * Usage in the gateway bootstrap:
 * ```typescript
 * import Redis from 'ioredis';
 * const idempotencyStore = createAdminIdempotencyStore({
 *   redisClient: new Redis(process.env.ADMIN_IDEMPOTENCY_REDIS_URL ?? process.env.REDIS_URL),
 *   logger,
 * });
 * createAdminRouter({ killSwitchManager, logger, idempotencyStore });
 * ```
 *
 * When no `redisClient` is provided the in-memory store is returned, which is
 * correct for single-replica / development deployments.
 */
export function createAdminIdempotencyStore(
  opts: {
    redisClient?: RedisIdempotencyClient;
    ttlMs?: number;
    logger?: { warn: (msg: string, meta?: Record<string, unknown>) => void };
  } = {},
): IAdminIdempotencyStore {
  if (opts.redisClient) {
    return new RedisAdminIdempotencyStore(opts.redisClient, {
      ttlMs: opts.ttlMs,
      logger: opts.logger,
    });
  }
  return new AdminIdempotencyStore({ ttlMs: opts.ttlMs });
}
