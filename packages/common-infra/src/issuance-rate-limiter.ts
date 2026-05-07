/**
 * Redis-backed issuance rate limiter implementations.
 *
 * The interfaces, in-memory implementation, and CallCounterStore-backed
 * implementation live in @euno/common-core. This module adds the legacy
 * direct-Redis {@link RedisIssuanceRateLimiter} and the env-driven factory
 * {@link createIssuanceRateLimiterFromEnv}.
 */

import {
  IssuanceRateLimiter,
  IssuanceRateLimiterOptions,
  IssuanceRateLimitSubject,
  RateLimitDecision,
  DEFAULT_ISSUANCE_RATE_LIMIT_MAX,
  DEFAULT_ISSUANCE_RATE_LIMIT_WINDOW_SECONDS,
  InMemoryIssuanceRateLimiter,
  CallCounterBackedIssuanceRateLimiter,
  buildIssuanceRateLimitKey,
} from '@euno/common-core';
import { Logger } from '@euno/common-core';
import { createCallCounterStoreFromEnv } from './call-counter-store';

const DEFAULT_KEY_PREFIX = 'issrl:';

/**
 * Minimal subset of the `ioredis` client surface this limiter
 * depends on. Defined locally so the package does not take a hard
 * runtime dependency on `ioredis` (callers wire one in via
 * {@link createIssuanceRateLimiterFromEnv} or by passing a client to
 * {@link RedisIssuanceRateLimiter} directly).
 */
export interface RedisIssuanceRateLimitClient {
  incr(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<unknown>;
  pttl(key: string): Promise<number>;
  quit(): Promise<unknown>;
  on(event: string, listener: (...args: unknown[]) => void): unknown;
}

export interface RedisIssuanceRateLimiterOptions extends IssuanceRateLimiterOptions {
  /** Key prefix, default `"issrl:"`. */
  keyPrefix?: string;
  /**
   * When true (default), a Redis error becomes a `deny` so the issuer
   * fails closed. When false, the error is propagated to the caller.
   */
  failClosedOnError?: boolean;
}

/**
 * Distributed token-bucket limiter backed by Redis.
 *
 * Uses `INCR` (atomic) plus a best-effort `EXPIRE` to attach the
 * tumbling window — the same pattern as
 * {@link RedisCallCounterStore} so the operational story is identical
 * (key prefix scan, TTL inspection, failure mode).
 */
export class RedisIssuanceRateLimiter implements IssuanceRateLimiter {
  private readonly client: RedisIssuanceRateLimitClient;
  private readonly logger?: Logger;
  private readonly keyPrefix: string;
  private readonly max: number;
  /** Configured tumbling-window length; satisfies the interface contract. */
  public readonly windowSeconds: number;
  private readonly failClosedOnError: boolean;

  constructor(
    client: RedisIssuanceRateLimitClient,
    logger?: Logger,
    options: Partial<RedisIssuanceRateLimiterOptions> = {},
  ) {
    this.client = client;
    this.logger = logger;
    this.keyPrefix = options.keyPrefix ?? DEFAULT_KEY_PREFIX;
    this.max = options.max ?? DEFAULT_ISSUANCE_RATE_LIMIT_MAX;
    this.windowSeconds = options.windowSeconds ?? DEFAULT_ISSUANCE_RATE_LIMIT_WINDOW_SECONDS;
    this.failClosedOnError = options.failClosedOnError ?? true;
    this.client.on('error', (err: unknown) => {
      this.logger?.error('Redis issuance rate-limit connection error', {
        error: err instanceof Error ? err.message : 'Unknown error',
      });
    });
  }

  async consume(subject: IssuanceRateLimitSubject): Promise<RateLimitDecision> {
    const fullKey = `${this.keyPrefix}${buildIssuanceRateLimitKey(subject)}`;
    try {
      const value = await this.client.incr(fullKey);
      // First increment in the window owns the TTL. Subsequent ones
      // leave the existing TTL alone — that's what makes this a
      // *tumbling* window.
      if (value === 1) {
        await this.client.expire(fullKey, this.windowSeconds);
      }
      if (value > this.max) {
        let retryAfterSeconds = this.windowSeconds;
        try {
          const pttlMs = await this.client.pttl(fullKey);
          if (pttlMs > 0) {
            retryAfterSeconds = Math.max(1, Math.ceil(pttlMs / 1000));
          }
        } catch {
          // Best-effort; fall back to the window length.
        }
        return {
          allowed: false,
          limit: this.max,
          remaining: 0,
          windowSeconds: this.windowSeconds,
          retryAfterSeconds,
        };
      }
      return {
        allowed: true,
        limit: this.max,
        remaining: Math.max(0, this.max - value),
        windowSeconds: this.windowSeconds,
        retryAfterSeconds: 0,
      };
    } catch (error) {
      this.logger?.error('Redis issuance rate-limit consume failed', {
        key: fullKey,
        error: error instanceof Error ? error.message : 'Unknown error',
        failClosedOnError: this.failClosedOnError,
      });
      if (this.failClosedOnError) {
        return {
          allowed: false,
          limit: this.max,
          remaining: 0,
          windowSeconds: this.windowSeconds,
          retryAfterSeconds: this.windowSeconds,
        };
      }
      // Fail-open: an unavailable limiter MUST NOT block issuance
      // when the operator has explicitly opted into availability over
      // F-1 enforcement. Returning `allowed: true` here (rather than
      // re-throwing) is what makes `ISSUANCE_RATE_LIMIT_FAIL_CLOSED=
      // false` actually take effect — the issuer's catch path treats
      // any propagated error as fail-closed because at that point the
      // operator's intent has already been honoured by the limiter.
      return {
        allowed: true,
        limit: this.max,
        remaining: this.max,
        windowSeconds: this.windowSeconds,
        retryAfterSeconds: 0,
      };
    }
  }

  /** Close the underlying Redis client. Idempotent best-effort. */
  async close(): Promise<void> {
    try {
      await this.client.quit();
    } catch (error) {
      this.logger?.warn('Error while closing Redis issuance rate-limit client', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }
}

export interface IssuanceRateLimiterEnvOptions {
  /** Optional logger for boot diagnostics. */
  logger?: Logger;
  /**
   * Explicit maximum issuances per window.  When set, overrides the
   * `ISSUANCE_RATE_LIMIT_MAX` env var so callers can configure
   * per-credential-type limits (storage-grant, DB-token) without
   * constructing a synthetic `NodeJS.ProcessEnv`.
   */
  max?: number;
  /**
   * Explicit window length in seconds.  When set, overrides
   * `ISSUANCE_RATE_LIMIT_WINDOW_SECONDS`.
   */
  windowSeconds?: number;
  /**
   * Explicit Redis key prefix.  When set, overrides
   * `ISSUANCE_RATE_LIMIT_KEY_PREFIX`.  Useful to namespace per-
   * credential-type limiters (e.g. `'sgrl:'` for storage grants,
   * `'dbrl:'` for DB tokens).
   */
  keyPrefix?: string;
  /**
   * Explicit fail-closed flag.  When set, overrides
   * `ISSUANCE_RATE_LIMIT_FAIL_CLOSED`.
   */
  failClosedOnError?: boolean;
}

/**
 * Construct an {@link IssuanceRateLimiter} from environment variables.
 *
 * Returns the in-process {@link InMemoryIssuanceRateLimiter} when
 * `REDIS_URL` is unset (single-replica / development). When `REDIS_URL`
 * is set, returns a {@link CallCounterBackedIssuanceRateLimiter} backed
 * by a {@link createCallCounterStoreFromEnv | Redis CallCounterStore} —
 * the same infrastructure that powers `maxCalls`-condition enforcement
 * and the gateway quota engine. This eliminates the separate per-service
 * Redis connection that the legacy {@link RedisIssuanceRateLimiter} required.
 *
 * Environment variables (all can be overridden via `options`):
 *  - `REDIS_URL` — Redis connection string. When unset, falls back
 *    to the in-memory limiter.
 *  - `ISSUANCE_RATE_LIMIT_MAX` — max issuances per window. Default 60.
 *  - `ISSUANCE_RATE_LIMIT_WINDOW_SECONDS` — window length. Default 60.
 *  - `ISSUANCE_RATE_LIMIT_KEY_PREFIX` — overrides default `"issrl:"`.
 *  - `ISSUANCE_RATE_LIMIT_FAIL_CLOSED` — `'true'` (default) or `'false'`.
 */
export async function createIssuanceRateLimiterFromEnv(
  env: NodeJS.ProcessEnv,
  options: IssuanceRateLimiterEnvOptions = {},
): Promise<IssuanceRateLimiter> {
  const logger = options.logger;

  const max =
    options.max ?? parsePositiveInt(env.ISSUANCE_RATE_LIMIT_MAX, DEFAULT_ISSUANCE_RATE_LIMIT_MAX);
  const windowSeconds =
    options.windowSeconds ??
    parsePositiveInt(
      env.ISSUANCE_RATE_LIMIT_WINDOW_SECONDS,
      DEFAULT_ISSUANCE_RATE_LIMIT_WINDOW_SECONDS,
    );
  const failClosedOnError =
    options.failClosedOnError ?? env.ISSUANCE_RATE_LIMIT_FAIL_CLOSED !== 'false';
  const keyPrefix = options.keyPrefix ?? env.ISSUANCE_RATE_LIMIT_KEY_PREFIX ?? DEFAULT_KEY_PREFIX;

  const redisUrl = env.REDIS_URL;
  if (!redisUrl) {
    logger?.info(
      'REDIS_URL not configured, using in-memory issuance rate limiter (single-replica only)',
      { max, windowSeconds },
    );
    return new InMemoryIssuanceRateLimiter({ max, windowSeconds });
  }

  // Use the shared CallCounterStore infrastructure (same as the gateway quota
  // engine) instead of spinning up a dedicated ioredis client. This keeps the
  // connection budget predictable and ensures all counter operations share the
  // same Redis keyspace conventions.
  //
  // Explicitly force CALL_COUNTER_FAIL_OPEN=false so that Redis outages are
  // NOT silently absorbed by a per-replica in-memory fallback. If we honoured
  // the env var here, ISSUANCE_RATE_LIMIT_FAIL_CLOSED would be meaningless:
  // outage → fallback kicks in → effective limit becomes max × replicaCount,
  // not a hard denial. The CallCounterBackedIssuanceRateLimiter's own
  // failClosedOnError / outageDecision() logic handles the outage signal
  // (POSITIVE_INFINITY) consistently across all replicas.
  //
  // Use 'false' (string) rather than `undefined` so createCallCounterStoreFromEnv
  // sees an explicit env override. Setting to `undefined` would leave the key
  // absent and the factory would re-read the real env var — which could still
  // be 'true' if the operator set it.
  const store = await createCallCounterStoreFromEnv(
    { ...env, CALL_COUNTER_FAIL_OPEN: 'false' },
    logger,
  );
  logger?.info('Using CallCounterStore-backed issuance rate limiter', {
    max,
    windowSeconds,
    keyPrefix,
    failClosedOnError,
  });
  return new CallCounterBackedIssuanceRateLimiter(
    store,
    { max, windowSeconds, keyPrefix, failClosedOnError },
    logger,
  );
}

function parsePositiveInt(raw: string | undefined, fallback: number): number {
  if (!raw || raw.length === 0) return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return n;
}
