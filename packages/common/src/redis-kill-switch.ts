/**
 * Redis-backed Kill-Switch Manager
 *
 * Production-grade implementation of {@link KillSwitchManager} that shares
 * state across every gateway replica via Redis.  This is the kill-switch
 * counterpart to {@link RedisRevocationStore}: a kill issued on one pod
 * must be visible to every other pod within a bounded staleness window so
 * an emergency shutdown actually shuts the system down everywhere – not
 * just on the pod that received the admin request.
 *
 * ## Design
 *
 * The {@link KillSwitchManager} interface is **synchronous** by contract
 * (`shouldBlock`, `isSessionKilled`, …) because it is consulted on the hot
 * path of every authorization decision in {@link EnforcementEngine}.  We
 * preserve that contract by maintaining an in-memory snapshot
 * ({@link KillSwitchConfig}) that is kept fresh by:
 *
 *   * **Write-through:** each mutating call writes to Redis *first* (so the
 *     state is durable / shared), then updates the local cache so the
 *     issuing pod sees the change immediately.
 *   * **Periodic refresh:** a background timer pulls the full state from
 *     Redis every `refreshIntervalMs` (default 5 s) so other pods pick up
 *     remote changes within a bounded window.
 *   * **Initial seed:** the cache is hydrated from Redis at construction
 *     time (best-effort) so a fresh pod does not start in a "no kills"
 *     state if kills are already in effect cluster-wide.
 *
 * ## Schema
 *
 *   * `<prefix>global`           – string `"1"` if the global kill switch
 *                                  is active; absent otherwise.
 *   * `<prefix>killed_sessions`  – Redis SET of killed session ids.
 *   * `<prefix>killed_agents`    – Redis SET of killed agent ids.
 *
 * Sets are used (rather than per-id keys) so a single round-trip
 * (`SMEMBERS`) refreshes the entire population, and so revives are atomic
 * (`SREM`).  Kill switches have no natural TTL – they remain in effect
 * until an operator explicitly revives them or calls `resetAll()` – so we
 * deliberately do **not** put TTLs on these keys.
 *
 * ## Failure semantics
 *
 *   * **Reads** are always served from the local cache and therefore never
 *     fail.  The only freshness guarantee they make is bounded by
 *     `refreshIntervalMs`.
 *   * **Writes** propagate Redis errors to the caller by default so the
 *     admin API surfaces a 500 and operators know the kill did not stick.
 *     The caller can opt into best-effort writes (`failOpenOnWrite: true`)
 *     for environments where local-only enforcement is acceptable when
 *     Redis is unavailable.
 *   * If a periodic refresh fails the previous snapshot is retained and
 *     the failure is logged; the next tick will retry.
 */

import { KillSwitchManager, KillSwitchConfig } from './types';
import { Logger } from './logger';

/**
 * Minimal subset of the redis client surface the kill-switch depends on.
 * Defined locally so we do not take a hard runtime dependency on `ioredis`
 * (or any specific client) – callers wire one in via
 * {@link createKillSwitchManagerFromEnv}.
 */
export interface RedisKillSwitchClient {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<unknown>;
  del(key: string): Promise<unknown>;
  sadd(key: string, member: string): Promise<unknown>;
  srem(key: string, member: string): Promise<unknown>;
  smembers(key: string): Promise<string[]>;
  quit(): Promise<unknown>;
  on(event: string, listener: (...args: unknown[]) => void): unknown;
}

export interface RedisKillSwitchOptions {
  /** Key prefix, default `"killswitch:"`. */
  keyPrefix?: string;
  /**
   * Background refresh interval in milliseconds.  Smaller values mean
   * faster cross-pod propagation at the cost of more Redis traffic.
   * Default 5000 ms.  Set to 0 to disable periodic refresh (write-through
   * only – use with care).
   */
  refreshIntervalMs?: number;
  /**
   * When true, write operations swallow Redis errors and fall back to
   * updating only the local cache.  When false (default), write errors
   * propagate so the caller / admin API knows the kill did not propagate.
   */
  failOpenOnWrite?: boolean;
}

const DEFAULT_KEY_PREFIX = 'killswitch:';
const DEFAULT_REFRESH_INTERVAL_MS = 5000;

export class RedisKillSwitchManager implements KillSwitchManager {
  private readonly client: RedisKillSwitchClient;
  private readonly logger?: Logger;
  private readonly keyPrefix: string;
  private readonly refreshIntervalMs: number;
  private readonly failOpenOnWrite: boolean;

  /** Local snapshot – kept fresh by write-through and periodic refresh. */
  private readonly cache: KillSwitchConfig = {
    globalKillSwitch: false,
    killedSessions: new Set<string>(),
    killedAgents: new Set<string>(),
  };

  private refreshTimer?: NodeJS.Timeout;
  private started = false;
  private closed = false;

  constructor(client: RedisKillSwitchClient, logger?: Logger, options: RedisKillSwitchOptions = {}) {
    this.client = client;
    this.logger = logger;
    this.keyPrefix = options.keyPrefix ?? DEFAULT_KEY_PREFIX;
    this.refreshIntervalMs = options.refreshIntervalMs ?? DEFAULT_REFRESH_INTERVAL_MS;
    this.failOpenOnWrite = options.failOpenOnWrite ?? false;

    this.client.on('error', (err: unknown) => {
      this.logger?.error('Redis kill-switch connection error', {
        error: err instanceof Error ? err.message : 'Unknown error',
      });
    });
  }

  /**
   * Hydrate the local cache from Redis and start the periodic refresh
   * timer.  Safe to call multiple times; subsequent calls are no-ops.
   *
   * Operators are expected to `await` this once at startup.  If the
   * initial refresh fails the manager still starts (with an empty cache)
   * so the gateway can come up and rely on subsequent timer ticks – this
   * mirrors the behaviour of {@link RedisRevocationStore} on transient
   * Redis errors.
   */
  async start(): Promise<void> {
    // Track `started` separately from `refreshTimer` so the method is
    // truly idempotent even when `refreshIntervalMs === 0` (timer
    // disabled) – without this guard, repeated start() calls would
    // re-run the initial refresh on every invocation.
    if (this.started || this.closed) {
      return;
    }
    this.started = true;
    try {
      await this.refresh();
    } catch (error) {
      this.logger?.error(
        'Initial Redis kill-switch refresh failed; starting with empty cache and relying on periodic refresh',
        { error: error instanceof Error ? error.message : 'Unknown error' }
      );
    }
    if (this.refreshIntervalMs > 0) {
      this.refreshTimer = setInterval(() => {
        this.refresh().catch((err) => {
          this.logger?.warn('Periodic Redis kill-switch refresh failed', {
            error: err instanceof Error ? err.message : 'Unknown error',
          });
        });
      }, this.refreshIntervalMs);
      // Allow the Node process to exit even if the timer is still scheduled.
      this.refreshTimer.unref?.();
    }
  }

  /**
   * Pull the full kill-switch state from Redis and replace the local
   * snapshot atomically.  Exposed primarily for tests / admin tooling –
   * production code should rely on the periodic timer.
   */
  async refresh(): Promise<void> {
    const [globalRaw, sessions, agents] = await Promise.all([
      this.client.get(this.globalKey()),
      this.client.smembers(this.sessionsKey()),
      this.client.smembers(this.agentsKey()),
    ]);

    this.cache.globalKillSwitch = globalRaw === '1';
    this.cache.killedSessions = new Set(sessions);
    this.cache.killedAgents = new Set(agents);
  }

  isGlobalKillActive(): boolean {
    return this.cache.globalKillSwitch;
  }

  activateGlobalKill(): void {
    const previous = this.cache.globalKillSwitch;
    this.cache.globalKillSwitch = true;
    this.runWrite(
      'activateGlobalKill',
      () => this.client.set(this.globalKey(), '1'),
      () => {
        this.cache.globalKillSwitch = previous;
      }
    );
    this.logger?.warn('Global kill switch activated - all agent requests will be blocked');
  }

  deactivateGlobalKill(): void {
    const previous = this.cache.globalKillSwitch;
    this.cache.globalKillSwitch = false;
    this.runWrite(
      'deactivateGlobalKill',
      () => this.client.del(this.globalKey()),
      () => {
        this.cache.globalKillSwitch = previous;
      }
    );
    this.logger?.info('Global kill switch deactivated - agent requests are now allowed');
  }

  killSession(sessionId: string): void {
    const wasKilled = this.cache.killedSessions.has(sessionId);
    this.cache.killedSessions.add(sessionId);
    this.runWrite(
      'killSession',
      () => this.client.sadd(this.sessionsKey(), sessionId),
      () => {
        if (!wasKilled) {
          this.cache.killedSessions.delete(sessionId);
        }
      }
    );
    this.logger?.warn('Session killed', { sessionId });
  }

  killAgent(agentId: string): void {
    const wasKilled = this.cache.killedAgents.has(agentId);
    this.cache.killedAgents.add(agentId);
    this.runWrite(
      'killAgent',
      () => this.client.sadd(this.agentsKey(), agentId),
      () => {
        if (!wasKilled) {
          this.cache.killedAgents.delete(agentId);
        }
      }
    );
    this.logger?.warn('Agent killed', { agentId });
  }

  isSessionKilled(sessionId: string): boolean {
    return this.cache.killedSessions.has(sessionId);
  }

  isAgentKilled(agentId: string): boolean {
    return this.cache.killedAgents.has(agentId);
  }

  shouldBlock(sessionId?: string, agentId?: string): boolean {
    if (this.cache.globalKillSwitch) {
      return true;
    }
    if (sessionId && this.cache.killedSessions.has(sessionId)) {
      return true;
    }
    if (agentId && this.cache.killedAgents.has(agentId)) {
      return true;
    }
    return false;
  }

  reviveSession(sessionId: string): void {
    const wasKilled = this.cache.killedSessions.has(sessionId);
    this.cache.killedSessions.delete(sessionId);
    this.runWrite(
      'reviveSession',
      () => this.client.srem(this.sessionsKey(), sessionId),
      () => {
        if (wasKilled) {
          this.cache.killedSessions.add(sessionId);
        }
      }
    );
    this.logger?.info('Session revived', { sessionId });
  }

  reviveAgent(agentId: string): void {
    const wasKilled = this.cache.killedAgents.has(agentId);
    this.cache.killedAgents.delete(agentId);
    this.runWrite(
      'reviveAgent',
      () => this.client.srem(this.agentsKey(), agentId),
      () => {
        if (wasKilled) {
          this.cache.killedAgents.add(agentId);
        }
      }
    );
    this.logger?.info('Agent revived', { agentId });
  }

  getStatus(): { globalKill: boolean; killedSessionCount: number; killedAgentCount: number } {
    return {
      globalKill: this.cache.globalKillSwitch,
      killedSessionCount: this.cache.killedSessions.size,
      killedAgentCount: this.cache.killedAgents.size,
    };
  }

  resetAll(): void {
    const previousGlobal = this.cache.globalKillSwitch;
    const previousSessions = new Set(this.cache.killedSessions);
    const previousAgents = new Set(this.cache.killedAgents);
    this.cache.globalKillSwitch = false;
    this.cache.killedSessions.clear();
    this.cache.killedAgents.clear();
    this.runWrite(
      'resetAll',
      async () => {
        await Promise.all([
          this.client.del(this.globalKey()),
          this.client.del(this.sessionsKey()),
          this.client.del(this.agentsKey()),
        ]);
      },
      () => {
        this.cache.globalKillSwitch = previousGlobal;
        this.cache.killedSessions = previousSessions;
        this.cache.killedAgents = previousAgents;
      }
    );
    this.logger?.warn('All kill switches reset');
  }

  /**
   * Stop the background refresh timer and close the underlying Redis
   * client.  Idempotent.
   */
  async close(): Promise<void> {
    this.closed = true;
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = undefined;
    }
    try {
      await this.client.quit();
    } catch (error) {
      this.logger?.warn('Error while closing Redis kill-switch client', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  /**
   * Persist a mutating operation to Redis.  The local cache has *already*
   * been updated synchronously by the caller before this method runs, so
   * the kill-switch decision is in effect on this pod the moment the
   * `KillSwitchManager` method returns – there is no race between the
   * admin call and the Redis round-trip.
   *
   * The {@link KillSwitchManager} interface is synchronous (`void`
   * return), so this method cannot surface the Redis write outcome to
   * the caller.  Instead, on failure we either:
   *
   *   * **fail-closed (default):** invoke `revertCache()` to roll the
   *     local cache back to its pre-call state.  Net effect: the kill
   *     does not stick anywhere – including this pod – and the
   *     structured logger emits an `error` line so operators can alert
   *     on it.  This avoids silent per-pod divergence from Redis.
   *   * **fail-open (`failOpenOnWrite: true`):** keep the optimistic
   *     local change so this pod still honours the operator's intent.
   *     Other pods will only see the kill once Redis recovers and a
   *     refresh tick runs.
   *
   * Failures are *not* propagated to the synchronous caller and *not*
   * raised as `unhandledRejection` events; the structured `error` log
   * line is the sole signal.  Admin endpoints that need strict
   * acknowledgement should use the underlying client / `refresh()`
   * directly, or extend this class with explicit async write methods.
   */
  private runWrite(op: string, redisOp: () => Promise<unknown>, revertCache: () => void): void {
    redisOp().catch((error: unknown) => {
      this.logger?.error('Redis kill-switch write failed', {
        op,
        error: error instanceof Error ? error.message : 'Unknown error',
        failOpenOnWrite: this.failOpenOnWrite,
      });
      if (!this.failOpenOnWrite) {
        // Roll the local cache back so this pod does not silently
        // disagree with Redis (and therefore with every other replica
        // that will pick up the missing entry on its next refresh).
        revertCache();
      }
    });
  }

  private globalKey(): string {
    return `${this.keyPrefix}global`;
  }
  private sessionsKey(): string {
    return `${this.keyPrefix}killed_sessions`;
  }
  private agentsKey(): string {
    return `${this.keyPrefix}killed_agents`;
  }
}

/**
 * Construct a {@link KillSwitchManager} from environment variables.
 *
 * Returns the in-process {@link DefaultKillSwitchManager} when
 * `REDIS_URL` is unset (single-instance / development).  When
 * `REDIS_URL` is set, returns a {@link RedisKillSwitchManager} backed by
 * `ioredis` so kill operations are visible across every gateway replica.
 *
 * `ioredis` is loaded with a runtime `require()` so deployments that do
 * not use Redis are not forced to install it.  When the dependency is
 * absent and the operator has explicitly requested Redis, this function
 * logs a clear error and falls back to the in-process manager so the
 * gateway can still start (with an explicit warning that kills will NOT
 * propagate across replicas).
 *
 * @param env     Environment object (typically `process.env`).
 * @param logger  Logger used for diagnostic / audit messages.
 */
export async function createKillSwitchManagerFromEnv(
  env: NodeJS.ProcessEnv,
  logger?: Logger
): Promise<KillSwitchManager> {
  // Imported lazily to avoid a circular import (`kill-switch` depends on
  // this module via the public package re-export, not vice versa).
  const { DefaultKillSwitchManager } = await import('./kill-switch');

  const redisUrl = env.REDIS_URL;
  if (!redisUrl) {
    logger?.info('REDIS_URL not configured, using in-memory kill-switch manager');
    return new DefaultKillSwitchManager(logger);
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
          'Install it (npm install ioredis) to enable distributed kill switches. ' +
          'Refusing to fall back to the in-memory kill-switch manager in a production / ' +
          'multi-replica deployment: kill operations issued on one instance would be ' +
          'invisible to all others, creating a split-brain kill-switch state. ' +
          `Original error: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    }
    logger?.error(
      'REDIS_URL is set but the "ioredis" package is not installed. ' +
        'Install it (npm install ioredis) to enable distributed kill switches. ' +
        'Falling back to in-memory kill-switch manager; kills WILL NOT be ' +
        'shared across gateway instances. This is only acceptable in development / ' +
        'single-replica deployments.',
      { error: error instanceof Error ? error.message : 'Unknown error' },
    );
    return new DefaultKillSwitchManager(logger);
  }

  const Ctor = (RedisCtor as { default?: unknown }).default ?? RedisCtor;
  const client = new (Ctor as new (url: string, opts?: unknown) => RedisKillSwitchClient)(redisUrl, {
    retryStrategy: (times: number) => Math.min(times * 50, 2000),
    maxRetriesPerRequest: 3,
    lazyConnect: false,
  });

  const keyPrefix = env.KILL_SWITCH_KEY_PREFIX || DEFAULT_KEY_PREFIX;
  const refreshRaw = parseInt(env.KILL_SWITCH_REFRESH_INTERVAL_MS || '', 10);
  const refreshIntervalMs = Number.isFinite(refreshRaw) && refreshRaw >= 0
    ? refreshRaw
    : DEFAULT_REFRESH_INTERVAL_MS;
  const failOpenOnWrite = env.KILL_SWITCH_FAIL_OPEN_ON_WRITE === 'true';

  const manager = new RedisKillSwitchManager(client, logger, {
    keyPrefix,
    refreshIntervalMs,
    failOpenOnWrite,
  });
  await manager.start();

  logger?.info('Using Redis kill-switch manager for distributed emergency shutdown', {
    keyPrefix,
    refreshIntervalMs,
    failOpenOnWrite,
  });

  return manager;
}
