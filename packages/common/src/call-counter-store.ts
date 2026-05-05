/**
 * Counter store implementations for {@link MaxCallsCondition}
 * enforcement.
 *
 * The condition registry consults a {@link CallCounterStore} every time
 * a `maxCalls` condition is evaluated. Two implementations are
 * provided here:
 *
 *  - {@link InMemoryCallCounterStore} — a single-process map suitable
 *    for local development, single-replica gateways, and unit tests.
 *  - {@link RedisCallCounterStore} — a distributed counter using the
 *    same `ioredis`-shaped client interface used by
 *    {@link RedisKillSwitchManager}, so a multi-replica gateway
 *    converges on the same per-capability call budget.
 *
 * The {@link createCallCounterStoreFromEnv} helper picks the right
 * implementation based on `REDIS_URL`, mirroring the pattern of
 * {@link createKillSwitchManagerFromEnv}.
 */

import { CallCounterStore } from './condition-registry';
import { Logger } from './logger';
import { computeAgentShardIndex } from './shard';

/**
 * Per-process counter store. Counters are tracked with a stored
 * "first-touch" timestamp; on every increment the store discards the
 * counter when the window has fully elapsed. Suitable for development
 * and single-replica deployments only.
 */
export class InMemoryCallCounterStore implements CallCounterStore {
  private readonly counters = new Map<string, { count: number; expiresAt: number }>();

  /** Test/inspection helper. */
  size(): number {
    return this.counters.size;
  }

  /** Drop every counter — primarily for tests. */
  reset(): void {
    this.counters.clear();
  }

  async incrementAndGet(key: string, windowSeconds: number, _agentSub?: string): Promise<number> {
    const now = Date.now();
    const existing = this.counters.get(key);
    if (!existing || existing.expiresAt <= now) {
      const fresh = { count: 1, expiresAt: now + windowSeconds * 1000 };
      this.counters.set(key, fresh);
      return 1;
    }
    existing.count += 1;
    return existing.count;
  }
}

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
   */
  failClosedOnError?: boolean;
  /** Optional callback invoked on every Redis error, e.g. to increment a Prometheus counter. */
  onError?: () => void;
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
    this.client.on('error', (err: unknown) => {
      this.logger?.error('Redis call-counter connection error', {
        error: err instanceof Error ? err.message : 'Unknown error',
      });
    });
  }

  async incrementAndGet(key: string, windowSeconds: number, _agentSub?: string): Promise<number> {
    const fullKey = `${this.keyPrefix}${key}`;
    try {
      const value = await this.client.incr(fullKey);
      // `EXPIRE` is best-effort. If it fails on the first increment the
      // counter would otherwise live forever; we re-raise so the caller
      // can surface the error rather than silently leaking state.
      if (value === 1) {
        await this.client.expire(fullKey, windowSeconds);
      }
      return value;
    } catch (error) {
      this.logger?.error('Redis call-counter increment failed', {
        key: fullKey,
        error: error instanceof Error ? error.message : 'Unknown error',
        failClosedOnError: this.failClosedOnError,
      });
      this.onError?.();
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
 * Returns the in-process {@link InMemoryCallCounterStore} when
 * `REDIS_URL` is unset (single-replica / development). When `REDIS_URL`
 * is set, returns a {@link RedisCallCounterStore} backed by `ioredis`,
 * mirroring the wiring of {@link createKillSwitchManagerFromEnv} so
 * deployments that already use Redis for the kill switch do not need
 * an additional client to enable distributed `maxCalls` enforcement.
 *
 * `ioredis` is loaded with a runtime `require()` so callers that do not
 * use Redis are not forced to install it. When `REDIS_URL` is set but
 * `ioredis` is missing, the function logs a clear error and falls back
 * to the in-memory store.
 *
 * Environment variables:
 *   - `REDIS_URL` — Redis connection string. When unset, falls back to
 *     the in-memory store.
 *   - `CALL_COUNTER_KEY_PREFIX` — overrides the default `capcall:`.
 */
export async function createCallCounterStoreFromEnv(
  env: NodeJS.ProcessEnv,
  logger?: Logger,
  /** Optional callback invoked on every Redis error so callers can increment a Prometheus counter. */
  onError?: () => void,
): Promise<CallCounterStore> {
  const redisUrl = env.REDIS_URL;
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
  return new RedisCallCounterStore(client, logger, { keyPrefix, onError });
}

// ---------------------------------------------------------------------------
// Shard-local counter store
// ---------------------------------------------------------------------------

/**
 * Options for {@link ShardLocalCallCounterStore}.
 */
export interface ShardLocalCallCounterStoreOptions {
  /**
   * Zero-based index of this gateway shard. Must be in [0, shardCount - 1].
   * Plumbed from `GATEWAY_SHARD_INDEX`.
   */
  shardIndex: number;
  /**
   * Total number of gateway shards. Must be >= 2 for sharding to take
   * effect (passing 1 makes every agent "local", equivalent to a plain
   * {@link InMemoryCallCounterStore}). Plumbed from `GATEWAY_SHARD_COUNT`.
   */
  shardCount: number;
  /**
   * Optional callback invoked every time a request is detected as
   * mis-routed (its `sub` hashes to a different shard). Use to increment
   * a Prometheus counter for the `euno_gateway_shard_misrouted_total` metric.
   */
  onMisrouted?: () => void;
}

/**
 * Shard-local call-counter store.
 *
 * This is the core performance win from horizontal gateway sharding.  When
 * the Envoy load balancer routes all traffic for a given agent (`sub`) to
 * the same gateway replica, that replica can track the `maxCalls` counter in
 * its own memory — no Redis `INCR` on the hot path.
 *
 * ## Design
 *
 * - **Local path** (owned agents): `incrementAndGet` is delegated to
 *   `localStore` (an {@link InMemoryCallCounterStore}). Zero Redis traffic.
 * - **Fallback path** (mis-routed agents): `incrementAndGet` is delegated to
 *   `remoteStore` (a {@link RedisCallCounterStore}). This covers:
 *   - The brief topology-change window when shards are added / removed and
 *     a few requests reach the wrong pod before the LB catches up.
 *   - Development / single-replica mode where all agents are "owned" by
 *     shard 0 and `remoteStore` is a plain in-memory fallback.
 * - **No `agentSub` hint**: if the caller does not supply an `agentSub`
 *   (because the `ConditionContext` was built without it), we fall back to
 *   the `remoteStore` conservatively — this matches the pre-sharding
 *   behaviour exactly.
 *
 * ## Scaling curve
 *
 * Without sharding: every gateway replica calls `INCR` on the shared Redis
 * cluster for every `maxCalls`-conditioned request — O(N × QPS) Redis ops.
 *
 * With sharding: each shard handles 1/N of the fleet's agents locally.
 * Redis `INCR` is only called for the small mis-routed fraction during
 * topology changes. Steady-state Redis call-counter load approaches zero.
 */
export class ShardLocalCallCounterStore implements CallCounterStore {
  private readonly localStore: InMemoryCallCounterStore;
  private readonly remoteStore: CallCounterStore;
  private readonly shardIndex: number;
  private readonly shardCount: number;
  private readonly logger?: Logger;
  private readonly onMisrouted?: () => void;
  // Rate-limit the mis-route warning to at most once per minute to avoid
  // flooding logs during topology changes or router misconfiguration.
  // Rely on euno_gateway_shard_misrouted_total for steady-state observability.
  private lastMisrouteWarnAt = 0;
  private static readonly MISROUTE_WARN_INTERVAL_MS = 60_000;

  constructor(
    localStore: InMemoryCallCounterStore,
    remoteStore: CallCounterStore,
    options: ShardLocalCallCounterStoreOptions,
    logger?: Logger,
  ) {
    this.localStore = localStore;
    this.remoteStore = remoteStore;
    this.shardIndex = options.shardIndex;
    this.shardCount = options.shardCount;
    this.logger = logger;
    this.onMisrouted = options.onMisrouted;
  }

  async incrementAndGet(key: string, windowSeconds: number, agentSub?: string): Promise<number> {
    if (!agentSub) {
      // No sub hint — fall back to the shared store so we don't silently
      // mis-count for an unknown agent.
      return this.remoteStore.incrementAndGet(key, windowSeconds);
    }

    const ownerShard = computeAgentShardIndex(agentSub, this.shardCount);
    if (ownerShard === this.shardIndex) {
      // Fast local path: this shard owns the agent.
      return this.localStore.incrementAndGet(key, windowSeconds);
    }

    // Mis-routed: the Envoy LB sent this agent's traffic to the wrong pod.
    // Fall back to Redis so the count is at least propagated cluster-wide.
    // Rate-limit the log to avoid flooding during topology changes.
    const now = Date.now();
    if (now - this.lastMisrouteWarnAt >= ShardLocalCallCounterStore.MISROUTE_WARN_INTERVAL_MS) {
      this.lastMisrouteWarnAt = now;
      this.logger?.warn('maxCalls: mis-routed agent — using remote counter store', {
        agentSub,
        expectedShard: ownerShard,
        thisShard: this.shardIndex,
        shardCount: this.shardCount,
      });
    }
    this.onMisrouted?.();
    return this.remoteStore.incrementAndGet(key, windowSeconds, agentSub);
  }

  /**
   * Expose the local (in-memory) store's entry count for Prometheus.
   * Always 0 for the remote store path.
   */
  localSize(): number {
    return this.localStore.size();
  }

  /**
   * Reset the local in-memory counters.  Primarily for tests.
   */
  resetLocal(): void {
    this.localStore.reset();
  }
}
