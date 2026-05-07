/**
 * Redis-backed counter store implementation for {@link MaxCallsCondition}
 * enforcement.
 *
 * The interface-seam and in-memory implementations live in @euno/common-core.
 * This module adds the Redis-backed {@link RedisCallCounterStore} and the
 * env-driven factory {@link createCallCounterStoreFromEnv}.
 */

import { CallCounterStore } from '@euno/common-core';
import { Logger } from '@euno/common-core';
import { InMemoryCallCounterStore } from '@euno/common-core';
import { RedisCircuitBreaker, CircuitOpenError } from './redis-circuit-breaker';

/**
 * Subset of the `ioredis` client surface this store depends on. Defined
 * locally so the package does not take a hard runtime dependency on
 * `ioredis` (callers wire one in via {@link createCallCounterStoreFromEnv}
 * or by passing a client to {@link RedisCallCounterStore} directly).
 */
export interface RedisCallCounterClient {
  incr(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<unknown>;
  quit(): Promise<unknown>;
  on(event: string, listener: (...args: unknown[]) => void): unknown;
}

export interface RedisCallCounterOptions {
  /** Key prefix, default `"capcall:"`. */
  keyPrefix?: string;
  /**
   * When true (default), a Redis error is converted to a deny-by-default
   * by returning `Number.POSITIVE_INFINITY` from `incrementAndGet` so
   * the condition evaluation reports "exceeded". When false, the error
   * is propagated to the caller.
   *
   * When `localFallback` is provided this option is effectively overridden:
   * on any Redis error (or circuit-open) the store delegates to `localFallback`
   * instead of failing closed or propagating the error.
   */
  failClosedOnError?: boolean;
  /** Optional callback invoked on every Redis error, e.g. to increment a Prometheus counter. */
  onError?: () => void;
  /**
   * Optional callback invoked every time the counter falls back to the
   * `localFallback` store — whether because of a Redis error or because the
   * circuit breaker is open.  Distinct from `onError` (which fires only on
   * actual Redis errors, not on circuit-open).  Use to increment a dedicated
   * Prometheus counter (e.g. `euno_gateway_counter_fallback_total`) so
   * operators can distinguish "counter degraded" from "general Redis error".
   *
   * The callback fires before the `localFallback` store is consulted, so it
   * is emitted even when the fallback eventually succeeds (which is the
   * common case — the agent still gets a 200, just against a per-replica
   * counter rather than the shared Redis counter).
   */
  onFallback?: () => void;
  /**
   * Optional circuit breaker.  When provided, `incrementAndGet` calls are
   * wrapped so that repeated Redis failures trip the circuit to "open" and
   * subsequent requests fail immediately, avoiding TCP timeout latency on
   * the authorization hot path.
   */
  circuitBreaker?: RedisCircuitBreaker;
  /**
   * Optional in-process fallback store used when the circuit breaker is
   * open or any Redis error occurs.  When set, a Redis outage degrades
   * to per-replica counting rather than a full brownout (all `maxCalls`
   * requests denied).
   *
   * **Trade-off**: counters tracked locally are not shared across replicas,
   * so the effective cap is `maxCalls × replicaCount` during an outage.
   * This is the correct trade-off for most operators: a brief Redis blip
   * should not cause service disruption; the `maxCalls` budget is a
   * soft rate-limit, not a hard security boundary.
   */
  localFallback?: InMemoryCallCounterStore;
}

const DEFAULT_COUNTER_KEY_PREFIX = 'capcall:';

/**
 * Distributed counter backed by Redis. Uses Redis `INCR` (atomic) plus
 * a best-effort `EXPIRE` to attach the sliding window. The first
 * increment in a window sets the TTL; subsequent increments inside the
 * same window leave the TTL untouched, which is the correct behavior
 * for a tumbling window of `windowSeconds`. We deliberately do not
 * issue a script-based "set TTL only if missing" (`SET … NX EX`)
 * pattern: with `INCR` the first writer's `EXPIRE` is what wins, so
 * the simpler two-command sequence is correct as long as both commands
 * are dispatched before the next caller observes the counter — which
 * the `await this.client.incr(...)` ordering guarantees.
 */
export class RedisCallCounterStore implements CallCounterStore {
  private readonly client: RedisCallCounterClient;
  private readonly logger?: Logger;
  private readonly keyPrefix: string;
  private readonly failClosedOnError: boolean;
  private readonly onError?: () => void;
  private readonly onFallback?: () => void;
  private readonly circuitBreaker?: RedisCircuitBreaker;
  private readonly localFallback?: InMemoryCallCounterStore;

  constructor(
    client: RedisCallCounterClient,
    logger?: Logger,
    options: RedisCallCounterOptions = {},
  ) {
    this.client = client;
    this.logger = logger;
    this.keyPrefix = options.keyPrefix ?? DEFAULT_COUNTER_KEY_PREFIX;
    this.failClosedOnError = options.failClosedOnError ?? true;
    this.onError = options.onError;
    this.onFallback = options.onFallback;
    this.circuitBreaker = options.circuitBreaker;
    this.localFallback = options.localFallback;
    this.client.on('error', (err: unknown) => {
      this.logger?.error('Redis call-counter connection error', {
        error: err instanceof Error ? err.message : 'Unknown error',
      });
      // Surface connection-level errors to the circuit breaker so it can
      // trip even when no in-flight execute() call is pending.
      this.circuitBreaker?.recordFailure();
    });
  }

  async incrementAndGet(key: string, windowSeconds: number, _agentSub?: string): Promise<number> {
    const fullKey = `${this.keyPrefix}${key}`;
    try {
      let value: number;
      if (this.circuitBreaker) {
        value = await this.circuitBreaker.execute(async () => {
          const v = await this.client.incr(fullKey);
          if (v === 1) {
            await this.client.expire(fullKey, windowSeconds);
          }
          return v;
        });
      } else {
        value = await this.client.incr(fullKey);
        // `EXPIRE` is best-effort. If it fails on the first increment the
        // counter would otherwise live forever; we re-raise so the caller
        // can surface the error rather than silently leaking state.
        if (value === 1) {
          await this.client.expire(fullKey, windowSeconds);
        }
      }
      return value;
    } catch (error) {
      const isCircuitOpen = error instanceof CircuitOpenError;
      if (!isCircuitOpen) {
        this.logger?.error('Redis call-counter increment failed', {
          key: fullKey,
          error: error instanceof Error ? error.message : 'Unknown error',
          failClosedOnError: this.failClosedOnError,
        });
        this.onError?.();
      }
      // Local fallback: degrade to per-replica counting rather than denying all.
      if (this.localFallback) {
        // Fire the fallback callback on every degradation, whether caused by
        // a Redis error or a circuit-open. This lets the caller emit a
        // dedicated metric (e.g. euno_gateway_counter_fallback_total) even
        // when no TCP error occurred (circuit already open → no error event).
        this.onFallback?.();
        if (!isCircuitOpen) {
          this.logger?.warn('Redis call-counter unavailable — falling back to local in-memory counter', {
            key: fullKey,
          });
        }
        return this.localFallback.incrementAndGet(key, windowSeconds);
      }
      if (this.failClosedOnError) {
        // Deny-by-default: report a count above any reasonable budget so
        // the `maxCalls` handler trips the limit. Using POSITIVE_INFINITY
        // makes the deny independent of whatever `count` the caller
        // configured.
        return Number.POSITIVE_INFINITY;
      }
      throw error;
    }
  }

  /** Close the underlying Redis client. Idempotent best-effort. */
  async close(): Promise<void> {
    try {
      await this.client.quit();
    } catch (error) {
      this.logger?.warn('Error while closing Redis call-counter client', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }
}

/**
 * Construct a {@link CallCounterStore} from environment variables.
 *
 * Returns the in-process {@link InMemoryCallCounterStore} when neither
 * `CALL_COUNTER_REDIS_URL` nor `REDIS_URL` is set (single-replica /
 * development). When a Redis URL is configured, returns a
 * {@link RedisCallCounterStore} backed by `ioredis`.
 *
 * **Per-store Redis URL**: `CALL_COUNTER_REDIS_URL` takes precedence over
 * the shared `REDIS_URL`, allowing the call-counter store to target a
 * dedicated Redis cluster isolated from the kill-switch and revocation stores.
 *
 * **Local fallback** (`CALL_COUNTER_FAIL_OPEN=true`): when Redis is
 * unavailable, delegates to an {@link InMemoryCallCounterStore} instead of
 * failing closed.  The effective `maxCalls` cap during an outage becomes
 * `maxCalls × replicaCount`, but agents are not denied service wholesale.
 *
 * `ioredis` is loaded with a runtime `require()` so callers that do not
 * use Redis are not forced to install it. When `REDIS_URL` is set but
 * `ioredis` is missing, the function logs a clear error and falls back
 * to the in-memory store.
 *
 * Environment variables:
 *   - `CALL_COUNTER_REDIS_URL` — dedicated Redis URL for this store.
 *   - `REDIS_URL` — shared Redis URL (fallback when `CALL_COUNTER_REDIS_URL`
 *     is unset).
 *   - `CALL_COUNTER_KEY_PREFIX` — overrides the default `capcall:`.
 *   - `CALL_COUNTER_FAIL_OPEN` — when `true`, use local fallback on error.
 */
export async function createCallCounterStoreFromEnv(
  env: NodeJS.ProcessEnv,
  logger?: Logger,
  /** Optional callback invoked on every Redis error so callers can increment a Prometheus counter. */
  onError?: () => void,
  /** Optional externally-created circuit breaker so the caller can read its state for metrics. */
  circuitBreaker?: RedisCircuitBreaker,
  /**
   * Optional callback invoked every time the store falls back to the local
   * in-memory counter — whether due to a Redis error or circuit-open.  Fires
   * even when the fallback succeeds (the request returns 200); use to
   * increment `euno_gateway_counter_fallback_total` so operators can detect
   * Redis degradation on the counter surface without watching for errors.
   */
  onFallback?: () => void,
): Promise<CallCounterStore> {
  const redisUrl = env.CALL_COUNTER_REDIS_URL || env.REDIS_URL;
  if (!redisUrl) {
    logger?.info('REDIS_URL not configured, using in-memory call-counter store');
    return new InMemoryCallCounterStore();
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
          'Install it (npm install ioredis) to enable distributed maxCalls enforcement. ' +
          'Refusing to fall back to the in-memory call-counter store in a production / ' +
          'multi-replica deployment: per-capability call budgets would be tracked per-pod ' +
          'rather than fleet-wide, multiplying the effective limit by the replica count. ' +
          `Original error: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    }
    logger?.error(
      'REDIS_URL is set but the "ioredis" package is not installed. ' +
        'Install it (npm install ioredis) to enable distributed maxCalls enforcement. ' +
        'Falling back to in-memory call-counter store; counters WILL NOT be ' +
        'shared across gateway instances. This is only acceptable in development / ' +
        'single-replica deployments.',
      { error: error instanceof Error ? error.message : 'Unknown error' },
    );
    return new InMemoryCallCounterStore();
  }

  const Ctor = (RedisCtor as { default?: unknown }).default ?? RedisCtor;
  const client = new (Ctor as new (url: string, opts?: unknown) => RedisCallCounterClient)(
    redisUrl,
    {
      retryStrategy: (times: number) => Math.min(times * 50, 2000),
      maxRetriesPerRequest: 3,
      lazyConnect: false,
    },
  );

  const keyPrefix = env.CALL_COUNTER_KEY_PREFIX || DEFAULT_COUNTER_KEY_PREFIX;
  // Direct `=== 'true'` comparison is intentional: factory functions receive
  // raw `process.env` strings, not the schema-validated config object.  All
  // other factory functions in this package use the same pattern for
  // boolean env vars.
  const failOpen = env.CALL_COUNTER_FAIL_OPEN === 'true';

  // When CALL_COUNTER_FAIL_OPEN=true, wire a local in-memory store as
  // fallback so a Redis outage degrades gracefully to per-replica counting
  // rather than denying all maxCalls-conditioned requests.
  const localFallback = failOpen ? new InMemoryCallCounterStore() : undefined;

  logger?.info('Using Redis call-counter store for distributed maxCalls enforcement', {
    keyPrefix,
    failOpen,
    circuitBreakerEnabled: !!circuitBreaker,
    dedicatedUrl: !!env.CALL_COUNTER_REDIS_URL,
  });

  return new RedisCallCounterStore(client, logger, {
    keyPrefix,
    onError,
    onFallback,
    circuitBreaker,
    localFallback,
    // When a local fallback is configured, failClosedOnError is irrelevant
    // (the fallback takes over before fail-closed logic runs). Leave it at
    // the default (true) so deployments without a fallback remain safe.
  });
}
