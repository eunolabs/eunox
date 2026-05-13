import { createLogger } from '@euno/common';

type Logger = ReturnType<typeof createLogger>;

export interface MintRateLimiterOptions {
  maxMintsPerWindow: number;
  windowSeconds: number;
}

export interface MintRateLimiter {
  check(tenantId: string): Promise<{ allowed: boolean; retryAfterSeconds?: number }>;
  /**
   * Decrement the rate-limit counter for a tenant by one.
   *
   * Called when a mint request was allowed through the rate limiter but
   * subsequently failed for a reason unrelated to the tenant's behaviour
   * (e.g. the audit store was unavailable).  Returning the slot prevents
   * audit-store transients from permanently eroding the tenant's quota.
   *
   * Implementations should treat a failed decrement as non-fatal (the slot
   * remains consumed for the current window, which is acceptable for abnormal
   * error paths).
   */
  decrement(tenantId: string): Promise<void>;
}

export class InMemoryMintRateLimiter implements MintRateLimiter {
  private readonly counts = new Map<string, { count: number; windowStart: number }>();
  private readonly maxMints: number;
  private readonly windowMs: number;

  constructor(opts: MintRateLimiterOptions = { maxMintsPerWindow: 100, windowSeconds: 60 }) {
    if (!Number.isFinite(opts.maxMintsPerWindow) || !Number.isInteger(opts.maxMintsPerWindow) || opts.maxMintsPerWindow <= 0) {
      throw new Error(
        `InMemoryMintRateLimiter: invalid maxMintsPerWindow ${opts.maxMintsPerWindow}. Must be a finite positive integer.`,
      );
    }
    if (!Number.isFinite(opts.windowSeconds) || !Number.isInteger(opts.windowSeconds) || opts.windowSeconds <= 0) {
      throw new Error(
        `InMemoryMintRateLimiter: invalid windowSeconds ${opts.windowSeconds}. Must be a finite positive integer.`,
      );
    }
    this.maxMints = opts.maxMintsPerWindow;
    this.windowMs = opts.windowSeconds * 1000;
  }

  async check(tenantId: string): Promise<{ allowed: boolean; retryAfterSeconds?: number }> {
    const now = Date.now();
    const entry = this.counts.get(tenantId);

    if (!entry || now - entry.windowStart >= this.windowMs) {
      this.counts.set(tenantId, { count: 1, windowStart: now });
      return { allowed: true };
    }

    if (entry.count >= this.maxMints) {
      const retryAfterMs = this.windowMs - (now - entry.windowStart);
      return { allowed: false, retryAfterSeconds: Math.ceil(retryAfterMs / 1000) };
    }

    entry.count++;
    return { allowed: true };
  }

  async decrement(tenantId: string): Promise<void> {
    const entry = this.counts.get(tenantId);
    if (entry && entry.count > 0) {
      entry.count--;
    }
  }
}

// ---------------------------------------------------------------------------
// Redis-backed rate limiter
// ---------------------------------------------------------------------------

/**
 * Minimal subset of the Redis client surface required by
 * {@link RedisBackedMintRateLimiter}. Defined locally so the minter does not
 * take a hard compile-time dependency on any specific Redis client package —
 * the actual client is wired by the caller (typically via
 * {@link createPingRateLimiterFromEnv}).
 */
export interface RedisMintRateLimiterClient {
  incr(key: string): Promise<number>;
  decr(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<unknown>;
  ttl(key: string): Promise<number>;
  /**
   * Execute a Lua script atomically on the Redis server.
   *
   * Used by {@link RedisBackedMintRateLimiter} to run the INCR+EXPIRE
   * operation as a single atomic unit, eliminating the race where
   * `INCR` succeeds but the subsequent `EXPIRE` call fails.
   *
   * @param script  The Lua script to evaluate.
   * @param numkeys Number of key arguments (passed as KEYS[]).
   * @param args    Key and value arguments (KEYS[] then ARGV[]).
   */
  eval(script: string, numkeys: number, ...args: (string | number)[]): Promise<unknown>;
  quit(): Promise<unknown>;
  on(event: string, listener: (...args: unknown[]) => void): unknown;
}

/**
 * Fleet-wide rate limiter backed by Redis.
 *
 * Uses the `INCR + EXPIRE` pattern (identical to `RedisCallCounterStore` in
 * `@euno/common-infra`) to maintain a tumbling-window counter keyed by
 * `<keyPrefix><key>`. Counts are shared across every minter replica that
 * points at the same Redis instance, so an attacker cannot bypass the limit by
 * distributing requests across pods.
 *
 * On any Redis error the limiter falls back to the provided `localFallback`
 * (when supplied) or fails open — i.e. returns `{ allowed: true }` — so a
 * Redis outage does not cause legitimate API-key validation requests to be
 * rejected. The error is always logged.
 *
 * @example
 * ```ts
 * const client = new Redis(process.env.REDIS_URL);
 * const limiter = new RedisBackedMintRateLimiter(client, {
 *   maxMintsPerWindow: 20,
 *   windowSeconds: 60,
 * });
 * ```
 */

/**
 * Lua script that atomically increments a counter and sets its TTL on the
 * first call. Using a single EVAL eliminates the race condition where INCR
 * succeeds but the subsequent EXPIRE call fails, which would leave a key
 * with no expiry and block the tenant permanently.
 *
 * KEYS[1] — the rate-limit key
 * ARGV[1] — TTL in seconds (string-coerced integer)
 * Returns — the new counter value after the increment (number)
 */
const LUA_ATOMIC_INCR_EXPIRE = `\
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count`;
export class RedisBackedMintRateLimiter implements MintRateLimiter {
  private readonly client: RedisMintRateLimiterClient;
  private readonly maxMints: number;
  private readonly windowSeconds: number;
  private readonly keyPrefix: string;
  private readonly localFallback?: InMemoryMintRateLimiter;
  private readonly logger?: Logger;

  constructor(
    client: RedisMintRateLimiterClient,
    opts: MintRateLimiterOptions & {
      /** Key prefix for Redis keys; default `"mintrl:"`. */
      keyPrefix?: string;
      /**
       * Optional in-memory fallback for when Redis is unreachable.
       * When omitted, Redis errors result in `{ allowed: true }` (fail-open).
       */
      localFallback?: InMemoryMintRateLimiter;
      /** Logger for Redis error visibility. */
      logger?: Logger;
    },
  ) {
    if (
      !Number.isFinite(opts.maxMintsPerWindow) ||
      !Number.isInteger(opts.maxMintsPerWindow) ||
      opts.maxMintsPerWindow <= 0
    ) {
      throw new Error(
        `RedisBackedMintRateLimiter: invalid maxMintsPerWindow ${opts.maxMintsPerWindow}. Must be a finite positive integer.`,
      );
    }
    if (
      !Number.isFinite(opts.windowSeconds) ||
      !Number.isInteger(opts.windowSeconds) ||
      opts.windowSeconds <= 0
    ) {
      throw new Error(
        `RedisBackedMintRateLimiter: invalid windowSeconds ${opts.windowSeconds}. Must be a finite positive integer.`,
      );
    }
    this.client = client;
    this.maxMints = opts.maxMintsPerWindow;
    this.windowSeconds = opts.windowSeconds;
    this.keyPrefix = opts.keyPrefix ?? 'mintrl:';
    this.localFallback = opts.localFallback;
    this.logger = opts.logger;

    this.client.on('error', (err: unknown) => {
      this.logger?.error('RedisBackedMintRateLimiter: Redis connection error', {
        error: err instanceof Error ? err.message : 'Unknown error',
      });
    });
  }

  async check(key: string): Promise<{ allowed: boolean; retryAfterSeconds?: number }> {
    const fullKey = `${this.keyPrefix}${key}`;
    try {
      // Atomically increment the counter and set the TTL on the first call.
      // Using a Lua EVAL eliminates the race where INCR succeeds but the
      // subsequent EXPIRE call fails, leaving a key with no expiry and
      // blocking the tenant permanently.
      const count = (await this.client.eval(
        LUA_ATOMIC_INCR_EXPIRE,
        1,
        fullKey,
        String(this.windowSeconds),
      )) as number;
      if (count > this.maxMints) {
        // Fetch the remaining TTL to provide an accurate Retry-After value.
        let remainingSeconds = this.windowSeconds;
        try {
          const ttl = await this.client.ttl(fullKey);
          if (ttl > 0) {
            remainingSeconds = ttl;
          } else if (ttl === -1) {
            // Belt-and-suspenders: if somehow the key has no expiry, re-apply.
            await this.client.expire(fullKey, this.windowSeconds);
            remainingSeconds = this.windowSeconds;
          }
        } catch {
          // Non-critical — Retry-After is informational only; the deny is
          // still correct regardless of the TTL value.
        }
        return { allowed: false, retryAfterSeconds: remainingSeconds };
      }
      return { allowed: true };
    } catch (error) {
      this.logger?.error('RedisBackedMintRateLimiter: Redis operation failed; falling back', {
        key: fullKey,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      if (this.localFallback) {
        return this.localFallback.check(key);
      }
      // Fail-open: a rate-limiter outage must not block legitimate traffic.
      return { allowed: true };
    }
  }

  async decrement(tenantId: string): Promise<void> {
    const fullKey = `${this.keyPrefix}${tenantId}`;
    try {
      await this.client.decr(fullKey);
    } catch (error) {
      // Non-fatal: if the decrement fails, the slot remains consumed for this
      // window.  Audit failures are already abnormal; a best-effort decrement is
      // acceptable.  Log at warn so operators can spot persistent Redis issues.
      this.logger?.warn('RedisBackedMintRateLimiter: failed to decrement rate-limit counter', {
        key: fullKey,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  /** Close the underlying Redis client. Idempotent best-effort. */
  async close(): Promise<void> {    try {
      await this.client.quit();
    } catch (error) {
      this.logger?.warn('RedisBackedMintRateLimiter: error closing Redis client', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }
}

// ---------------------------------------------------------------------------
// Environment-driven factory
// ---------------------------------------------------------------------------

/**
 * Build a {@link MintRateLimiter} for the `GET /api/v1/ping` endpoint from
 * environment variables.
 *
 * Resolution order:
 *   1. `MINTER_PING_REDIS_URL` — dedicated Redis URL for the ping limiter.
 *   2. `REDIS_URL` — shared Redis URL (used when the dedicated var is absent).
 *   3. In-memory fallback — when neither is set.
 *
 * Rate-limit parameters:
 *   - `MINTER_PING_RATE_LIMIT_MAX` — max requests per window (default 20).
 *   - `MINTER_PING_RATE_LIMIT_WINDOW_SECONDS` — window length in seconds (default 60).
 *
 * In multi-replica deployments, configure `REDIS_URL` (or
 * `MINTER_PING_REDIS_URL`) so the per-IP limit is enforced fleet-wide. Without
 * Redis, the effective cap is `MINTER_PING_RATE_LIMIT_MAX × replicaCount`, which
 * substantially weakens brute-force protection on API key prefix enumeration.
 *
 * `ioredis` is loaded with a runtime `require()` so operators that do not use
 * Redis are not forced to install it.
 */
export async function createPingRateLimiterFromEnv(
  env: NodeJS.ProcessEnv,
  logger?: Logger,
): Promise<MintRateLimiter> {
  const maxRaw = parseInt(env['MINTER_PING_RATE_LIMIT_MAX'] ?? '20', 10);
  const max = Number.isFinite(maxRaw) && Number.isInteger(maxRaw) && maxRaw > 0 ? maxRaw : 20;

  const windowRaw = parseInt(env['MINTER_PING_RATE_LIMIT_WINDOW_SECONDS'] ?? '60', 10);
  const windowSeconds =
    Number.isFinite(windowRaw) && Number.isInteger(windowRaw) && windowRaw > 0 ? windowRaw : 60;

  const redisUrl = env['MINTER_PING_REDIS_URL'] || env['REDIS_URL'];

  if (!redisUrl) {
    logger?.warn(
      '[minter] createPingRateLimiterFromEnv: neither MINTER_PING_REDIS_URL nor REDIS_URL is set. ' +
        'Using per-process in-memory rate limiter for GET /api/v1/ping. ' +
        'In a multi-replica deployment the effective rate limit is ' +
        `${max} req/${windowSeconds}s × replicaCount, which weakens brute-force protection. ` +
        'Set REDIS_URL or MINTER_PING_REDIS_URL to enforce the limit fleet-wide.',
    );
    return new InMemoryMintRateLimiter({ maxMintsPerWindow: max, windowSeconds });
  }

  let RedisCtor: unknown;
  try {
    // ioredis is an optional peer dependency.  We use require() rather than
    // await import() because this function is synchronous-style — it does not
    // need the async microtask overhead just to load a module — and because
    // require() gives synchronous error handling (the catch block below) for
    // the "ioredis not installed" path. Both factories (createPingRateLimiterFromEnv
    // and createMintRateLimiterFromEnv) use the same pattern for consistency.
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    RedisCtor = require('ioredis');
  } catch (error) {
    const detectedVar = env['MINTER_PING_REDIS_URL'] ? 'MINTER_PING_REDIS_URL' : 'REDIS_URL';
    logger?.error(
      `[minter] createPingRateLimiterFromEnv: ${detectedVar} is set but "ioredis" is not installed. ` +
        'Install it (npm install ioredis) to enable fleet-wide ping rate limiting ' +
        '(supports both MINTER_PING_REDIS_URL and REDIS_URL). ' +
        'Falling back to in-memory rate limiter.',
      { error: error instanceof Error ? error.message : 'Unknown error', detectedVar },
    );
    return new InMemoryMintRateLimiter({ maxMintsPerWindow: max, windowSeconds });
  }

  const Ctor = (RedisCtor as { default?: unknown }).default ?? RedisCtor;
  const client = new (Ctor as new (url: string, opts?: unknown) => RedisMintRateLimiterClient)(
    redisUrl,
    {
      retryStrategy: (times: number) => Math.min(times * 50, 2000),
      maxRetriesPerRequest: 3,
      lazyConnect: false,
    },
  );

  const localFallback = new InMemoryMintRateLimiter({ maxMintsPerWindow: max, windowSeconds });

  logger?.info(
    '[minter] createPingRateLimiterFromEnv: using Redis-backed fleet-wide rate limiter for GET /api/v1/ping',
    { max, windowSeconds, dedicatedUrl: !!env['MINTER_PING_REDIS_URL'] },
  );

  return new RedisBackedMintRateLimiter(client, {
    maxMintsPerWindow: max,
    windowSeconds,
    keyPrefix: 'pingrl:',
    localFallback,
    logger,
  });
}

/**
 * Build a {@link MintRateLimiter} for the `POST /api/v1/mint` route from
 * environment variables, using the following priority order:
 *
 *   1. `MINTER_MINT_REDIS_URL` — dedicated Redis URL for mint rate limiting.
 *   2. `REDIS_URL` — shared Redis URL (used when the dedicated var is absent).
 *   3. In-memory fallback — when neither is set.
 *
 * Rate-limit parameters:
 *   - `MINTER_MINT_RATE_LIMIT_MAX` — max requests per window (default 100).
 *   - `MINTER_MINT_RATE_LIMIT_WINDOW_SECONDS` — window length in seconds (default 60).
 *
 * In multi-replica deployments, configure `REDIS_URL` (or
 * `MINTER_MINT_REDIS_URL`) so the per-tenant limit is enforced fleet-wide.
 * Without Redis, the effective cap is `MINTER_MINT_RATE_LIMIT_MAX × replicaCount`.
 *
 * `ioredis` is loaded with a runtime `require()` so operators that do not use
 * Redis are not forced to install it.
 */
export async function createMintRateLimiterFromEnv(
  env: NodeJS.ProcessEnv,
  logger?: Logger,
): Promise<MintRateLimiter> {
  const maxRaw = parseInt(env['MINTER_MINT_RATE_LIMIT_MAX'] ?? '100', 10);
  const max = Number.isFinite(maxRaw) && Number.isInteger(maxRaw) && maxRaw > 0 ? maxRaw : 100;

  const windowRaw = parseInt(env['MINTER_MINT_RATE_LIMIT_WINDOW_SECONDS'] ?? '60', 10);
  const windowSeconds =
    Number.isFinite(windowRaw) && Number.isInteger(windowRaw) && windowRaw > 0 ? windowRaw : 60;

  const redisUrl = env['MINTER_MINT_REDIS_URL'] || env['REDIS_URL'];

  if (!redisUrl) {
    logger?.warn(
      '[minter] createMintRateLimiterFromEnv: neither MINTER_MINT_REDIS_URL nor REDIS_URL is set. ' +
        'Using per-process in-memory rate limiter for POST /api/v1/mint. ' +
        'In a multi-replica deployment the effective rate limit is ' +
        `${max} req/${windowSeconds}s × replicaCount, which weakens brute-force protection. ` +
        'Set REDIS_URL or MINTER_MINT_REDIS_URL to enforce the limit fleet-wide.',
    );
    return new InMemoryMintRateLimiter({ maxMintsPerWindow: max, windowSeconds });
  }

  let RedisCtor: unknown;
  try {
    // ioredis is an optional peer dependency.  We use require() rather than
    // await import() because this function is synchronous-style — it does not
    // need the async microtask overhead just to load a module — and because
    // require() gives synchronous error handling (the catch block below) for
    // the "ioredis not installed" path. Both factories (createPingRateLimiterFromEnv
    // and createMintRateLimiterFromEnv) use the same pattern for consistency.
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    RedisCtor = require('ioredis');
  } catch (error) {
    const detectedVar = env['MINTER_MINT_REDIS_URL'] ? 'MINTER_MINT_REDIS_URL' : 'REDIS_URL';
    logger?.error(
      `[minter] createMintRateLimiterFromEnv: ${detectedVar} is set but "ioredis" is not installed. ` +
        'Install it (npm install ioredis) to enable fleet-wide mint rate limiting ' +
        '(supports both MINTER_MINT_REDIS_URL and REDIS_URL). ' +
        'Falling back to in-memory rate limiter.',
      { error: error instanceof Error ? error.message : 'Unknown error', detectedVar },
    );
    return new InMemoryMintRateLimiter({ maxMintsPerWindow: max, windowSeconds });
  }

  const Ctor = (RedisCtor as { default?: unknown }).default ?? RedisCtor;
  const client = new (Ctor as new (url: string, opts?: unknown) => RedisMintRateLimiterClient)(
    redisUrl,
    {
      retryStrategy: (times: number) => Math.min(times * 50, 2000),
      maxRetriesPerRequest: 3,
      lazyConnect: false,
    },
  );

  const localFallback = new InMemoryMintRateLimiter({ maxMintsPerWindow: max, windowSeconds });

  logger?.info(
    '[minter] createMintRateLimiterFromEnv: using Redis-backed fleet-wide rate limiter for POST /api/v1/mint',
    { max, windowSeconds, dedicatedUrl: !!env['MINTER_MINT_REDIS_URL'] },
  );

  return new RedisBackedMintRateLimiter(client, {
    maxMintsPerWindow: max,
    windowSeconds,
    keyPrefix: 'mintrl:mint:',
    localFallback,
    logger,
  });
}
