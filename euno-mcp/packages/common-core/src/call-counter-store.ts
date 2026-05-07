/**
 * In-process counter store implementations for {@link MaxCallsCondition}
 * enforcement.
 *
 * This module provides the interface-seam and in-memory implementations.
 * The Redis-backed implementation lives in @euno/common-infra.
 *
 *  - {@link InMemoryCallCounterStore} — a single-process map suitable
 *    for local development, single-replica gateways, and unit tests.
 *  - {@link ShardLocalCallCounterStore} — a shard-aware store that uses
 *    in-memory counting for locally-owned agents and delegates to a
 *    remote store for mis-routed traffic.
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
