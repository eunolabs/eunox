import { createLogger } from '@euno/common';

type Logger = ReturnType<typeof createLogger>;

export interface MintRateLimiterOptions {
  maxMintsPerWindow: number;
  windowSeconds: number;
}

export interface MintRateLimiter {
  check(tenantId: string): Promise<{ allowed: boolean; retryAfterSeconds?: number }>;
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
  expire(key: string, seconds: number): Promise<unknown>;
  ttl(key: string): Promise<number>;
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
      const count = await this.client.incr(fullKey);
      // Set the TTL only on the first increment so the window is tumbling
      // (same semantics as RedisCallCounterStore — the first writer owns the
      // window boundary).
      if (count === 1) {
        await this.client.expire(fullKey, this.windowSeconds);
      }
      if (count > this.maxMints) {
        // Fetch the remaining TTL to provide an accurate Retry-After value.
        // The TTL fetch also serves as a safety guard: if expire() failed on
        // the initial increment (count was 1), the key has no TTL and the
        // caller would be blocked permanently.  When we detect ttl === -1
        // (key exists but has no expiry) we re-apply expire so the block is
        // always temporary.
        let remainingSeconds = this.windowSeconds;
        try {
          const ttl = await this.client.ttl(fullKey);
          if (ttl > 0) {
            remainingSeconds = ttl;
          } else if (ttl === -1) {
            // Safety guard: no TTL on the key — this happens when the initial
            // expire() call (count === 1 path) threw after incr() succeeded.
            // Re-apply expire so the counter eventually resets.
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

  /** Close the underlying Redis client. Idempotent best-effort. */
  async close(): Promise<void> {
    try {
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
