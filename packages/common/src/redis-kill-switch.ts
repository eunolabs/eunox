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
 * ({@link KillSwitchConfig}) that is kept fresh by three complementary
 * mechanisms, in priority order:
 *
 *   * **Write-through (issuing pod):** each mutating call writes to Redis
 *     *first* (so the state is durable / shared), then updates the local
 *     cache so the issuing pod sees the change immediately.
 *   * **Pub/sub (every other pod, primary):** after a successful Redis
 *     write the issuing pod publishes a granular event on
 *     `<prefix>events`.  Every replica subscribes to that channel and
 *     applies the event to its local cache the moment it arrives –
 *     typically in single-digit milliseconds end-to-end.  This makes
 *     "kill switch now" actually mean *now*, not "now + up to
 *     `refreshIntervalMs`".  Each pod tags its own publishes with a
 *     unique `instanceId` and ignores echoes of its own events.
 *   * **Periodic refresh (every pod, safety net):** a background timer
 *     pulls the full state from Redis every `refreshIntervalMs` (default
 *     30 s now that pub/sub is the primary propagation mechanism).  This
 *     guarantees convergence even if a pub/sub message is lost (Redis
 *     pub/sub is at-most-once and is **not** delivered to subscribers
 *     that are momentarily disconnected) and re-seeds pods that just
 *     reconnected to Redis.
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
 *     fail.  Their freshness is normally bounded by pub/sub delivery
 *     latency (single-digit milliseconds intra-DC); `refreshIntervalMs`
 *     bounds the worst case if a pub/sub message is dropped.
 *   * **Writes** propagate Redis errors to the caller by default so the
 *     admin API surfaces a 500 and operators know the kill did not stick.
 *     The caller can opt into best-effort writes (`failOpenOnWrite: true`)
 *     for environments where local-only enforcement is acceptable when
 *     Redis is unavailable.
 *   * **Pub/sub publish failures** are logged but never fail the write.
 *     Remote replicas converge on the next periodic refresh.
 *   * If a periodic refresh fails the previous snapshot is retained and
 *     the failure is logged; the next tick will retry.
 */

import { randomUUID } from 'crypto';
import { KillSwitchManager, KillSwitchConfig } from './types';
import { Logger } from './logger';

/**
 * Minimal subset of the redis client surface the kill-switch depends on
 * for state I/O.  Defined locally so we do not take a hard runtime
 * dependency on `ioredis` (or any specific client) – callers wire one in
 * via {@link createKillSwitchManagerFromEnv}.
 *
 * `publish` is used to broadcast cache-invalidation events; see
 * {@link RedisKillSwitchSubscriber} for the receiving side.
 */
export interface RedisKillSwitchClient {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<unknown>;
  del(key: string): Promise<unknown>;
  sadd(key: string, member: string): Promise<unknown>;
  srem(key: string, member: string): Promise<unknown>;
  smembers(key: string): Promise<string[]>;
  publish(channel: string, message: string): Promise<unknown>;
  quit(): Promise<unknown>;
  on(event: string, listener: (...args: unknown[]) => void): unknown;
}

/**
 * Minimal subset of a Redis subscriber connection.  Redis pub/sub
 * requires a *dedicated* connection because once a client enters
 * subscriber mode it can no longer issue normal commands.  In `ioredis`
 * the canonical pattern is `subscriber = client.duplicate()`.
 *
 * The subscriber emits `'message'` events with `(channel, message)`
 * arguments for every published payload on a subscribed channel.
 */
export interface RedisKillSwitchSubscriber {
  subscribe(channel: string): Promise<unknown>;
  unsubscribe(channel?: string): Promise<unknown>;
  quit(): Promise<unknown>;
  on(event: string, listener: (...args: unknown[]) => void): unknown;
}

export interface RedisKillSwitchOptions {
  /** Key prefix, default `"killswitch:"`. */
  keyPrefix?: string;
  /**
   * Background refresh interval in milliseconds.  Acts as a **safety
   * net** for missed pub/sub messages (Redis pub/sub is at-most-once and
   * subscribers temporarily disconnected from Redis silently lose
   * events).  Smaller values mean faster recovery from a lost message
   * at the cost of more Redis traffic.  Default 30 000 ms now that
   * pub/sub is the primary propagation mechanism.  Set to 0 to disable
   * periodic refresh (pub/sub-only – use only if you understand the
   * at-most-once delivery semantics).
   */
  refreshIntervalMs?: number;
  /**
   * When true, write operations swallow Redis errors and fall back to
   * updating only the local cache.  When false (default), write errors
   * propagate so the caller / admin API knows the kill did not propagate.
   */
  failOpenOnWrite?: boolean;
  /**
   * Optional dedicated Redis subscriber connection.  When provided the
   * manager subscribes to `<keyPrefix>events` and applies kill-switch
   * mutations published by other replicas to its local cache the
   * moment they arrive – sub-second cross-replica propagation.  When
   * omitted the manager falls back to the (slower) periodic-refresh
   * mechanism only.
   */
  subscriber?: RedisKillSwitchSubscriber;
  /**
   * Stable identifier for this manager instance, used to tag published
   * events so the originating replica can ignore the echo of its own
   * broadcast (it has already updated the local cache via write-through).
   * Auto-generated when omitted; tests can pin a value for determinism.
   */
  instanceId?: string;
}

const DEFAULT_KEY_PREFIX = 'killswitch:';
/**
 * Default safety-net refresh interval.  Was 5 s when periodic refresh
 * was the primary propagation mechanism; raised to 30 s now that
 * pub/sub handles real-time propagation.  Operators on Redis
 * deployments with high message-loss risk can lower this; operators
 * confident in their Redis link can raise it further.
 */
const DEFAULT_REFRESH_INTERVAL_MS = 30000;
const DEFAULT_EVENTS_SUFFIX = 'events';
const EVENT_SCHEMA_VERSION = 1;

/**
 * Wire format for cross-replica kill-switch invalidation events.
 *
 * Kept deliberately small – Redis pub/sub payloads are JSON-encoded and
 * fan out to every subscriber.  The `v` field lets future versions
 * extend the schema without breaking older subscribers (which simply
 * ignore unknown versions and rely on the periodic refresh safety net
 * to converge).
 */
type KillSwitchEvent =
  | { v: 1; src: string; op: 'activate_global' }
  | { v: 1; src: string; op: 'deactivate_global' }
  | { v: 1; src: string; op: 'kill_session'; id: string }
  | { v: 1; src: string; op: 'revive_session'; id: string }
  | { v: 1; src: string; op: 'kill_agent'; id: string }
  | { v: 1; src: string; op: 'revive_agent'; id: string }
  | { v: 1; src: string; op: 'reset_all' };

export class RedisKillSwitchManager implements KillSwitchManager {
  private readonly client: RedisKillSwitchClient;
  private readonly logger?: Logger;
  private readonly keyPrefix: string;
  private readonly refreshIntervalMs: number;
  private readonly failOpenOnWrite: boolean;
  private readonly subscriber?: RedisKillSwitchSubscriber;
  private readonly instanceId: string;

  /**
   * Local snapshot – kept fresh by write-through (issuing pod), pub/sub
   * (every other pod, primary), and periodic refresh (safety net).
   */
  private readonly cache: KillSwitchConfig = {
    globalKillSwitch: false,
    killedSessions: new Set<string>(),
    killedAgents: new Set<string>(),
  };

  private refreshTimer?: NodeJS.Timeout;
  private started = false;
  private closed = false;
  private subscribed = false;

  constructor(client: RedisKillSwitchClient, logger?: Logger, options: RedisKillSwitchOptions = {}) {
    this.client = client;
    this.logger = logger;
    this.keyPrefix = options.keyPrefix ?? DEFAULT_KEY_PREFIX;
    this.refreshIntervalMs = options.refreshIntervalMs ?? DEFAULT_REFRESH_INTERVAL_MS;
    this.failOpenOnWrite = options.failOpenOnWrite ?? false;
    this.subscriber = options.subscriber;
    this.instanceId = options.instanceId ?? randomUUID();

    this.client.on('error', (err: unknown) => {
      this.logger?.error('Redis kill-switch connection error', {
        error: err instanceof Error ? err.message : 'Unknown error',
      });
    });

    if (this.subscriber) {
      this.subscriber.on('error', (err: unknown) => {
        this.logger?.error('Redis kill-switch subscriber connection error', {
          error: err instanceof Error ? err.message : 'Unknown error',
        });
      });
      this.subscriber.on('message', (channel: unknown, message: unknown) => {
        if (typeof channel !== 'string' || typeof message !== 'string') {
          return;
        }
        if (channel !== this.eventsChannel()) {
          return;
        }
        this.handleIncomingEvent(message);
      });
    }
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
    // Subscribe BEFORE the initial refresh so that any event published
    // between the refresh's SMEMBERS round-trip and the subscription
    // becoming active is also covered by the next periodic refresh
    // (rather than relying solely on the at-most-once pub/sub channel).
    if (this.subscriber) {
      try {
        await this.subscriber.subscribe(this.eventsChannel());
        this.subscribed = true;
      } catch (error) {
        this.logger?.error(
          'Failed to subscribe to Redis kill-switch events; falling back to periodic-refresh propagation only',
          { error: error instanceof Error ? error.message : 'Unknown error' }
        );
      }
    }
    try {
      await this.refresh();
    } catch (error) {
      this.logger?.error(
        'Initial Redis kill-switch refresh failed; starting with empty cache and relying on pub/sub + periodic refresh',
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
   * production code should rely on pub/sub propagation with the
   * periodic timer as a safety net.
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
      },
      { v: EVENT_SCHEMA_VERSION, src: this.instanceId, op: 'activate_global' }
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
      },
      { v: EVENT_SCHEMA_VERSION, src: this.instanceId, op: 'deactivate_global' }
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
      },
      { v: EVENT_SCHEMA_VERSION, src: this.instanceId, op: 'kill_session', id: sessionId }
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
      },
      { v: EVENT_SCHEMA_VERSION, src: this.instanceId, op: 'kill_agent', id: agentId }
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
      },
      { v: EVENT_SCHEMA_VERSION, src: this.instanceId, op: 'revive_session', id: sessionId }
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
      },
      { v: EVENT_SCHEMA_VERSION, src: this.instanceId, op: 'revive_agent', id: agentId }
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
      },
      { v: EVENT_SCHEMA_VERSION, src: this.instanceId, op: 'reset_all' }
    );
    this.logger?.warn('All kill switches reset');
  }

  /**
   * Stop the background refresh timer, unsubscribe from the event
   * channel, and close both Redis connections.  Idempotent.
   */
  async close(): Promise<void> {
    this.closed = true;
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = undefined;
    }
    if (this.subscriber) {
      try {
        if (this.subscribed) {
          await this.subscriber.unsubscribe(this.eventsChannel());
          this.subscribed = false;
        }
      } catch (error) {
        this.logger?.warn('Error while unsubscribing Redis kill-switch subscriber', {
          error: error instanceof Error ? error.message : 'Unknown error',
        });
      }
      try {
        await this.subscriber.quit();
      } catch (error) {
        this.logger?.warn('Error while closing Redis kill-switch subscriber', {
          error: error instanceof Error ? error.message : 'Unknown error',
        });
      }
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
   * On a successful Redis write we publish a granular invalidation
   * event so every other replica's subscriber updates its local cache
   * in single-digit milliseconds, instead of waiting up to
   * `refreshIntervalMs` for the safety-net timer to tick.  Publish
   * failures are non-fatal: the periodic refresh on remote pods is the
   * fallback.
   *
   * The {@link KillSwitchManager} interface is synchronous (`void`
   * return), so this method cannot surface the Redis write outcome to
   * the caller.  Instead, on failure we either:
   *
   *   * **fail-closed (default):** invoke `revertCache()` to roll the
   *     local cache back to its pre-call state.  Net effect: the kill
   *     does not stick anywhere – including this pod – and the
   *     structured logger emits an `error` line so operators can alert
   *     on it.  This avoids silent per-pod divergence from Redis.  No
   *     event is published in this case (the write did not happen).
   *   * **fail-open (`failOpenOnWrite: true`):** keep the optimistic
   *     local change so this pod still honours the operator's intent.
   *     Other pods will only see the kill once Redis recovers and a
   *     refresh tick runs.  No event is published in this case either
   *     (Redis is unreachable, so publish would fail too).
   *
   * Failures are *not* propagated to the synchronous caller and *not*
   * raised as `unhandledRejection` events; the structured `error` log
   * line is the sole signal.  Admin endpoints that need strict
   * acknowledgement should use the underlying client / `refresh()`
   * directly, or extend this class with explicit async write methods.
   */
  private runWrite(
    op: string,
    redisOp: () => Promise<unknown>,
    revertCache: () => void,
    event: KillSwitchEvent
  ): void {
    redisOp()
      .then(() => {
        // Only publish when pub/sub is enabled (i.e. a subscriber
        // connection was wired in).  When KILL_SWITCH_PUBSUB_ENABLED=false
        // the subscriber is undefined, which means no pod is listening
        // on the events channel, so publishing would be a no-op round-trip
        // and would contradict the documented "periodic-refresh-only
        // propagation" fall-back.
        if (!this.subscriber) {
          return;
        }
        // Fire-and-forget publish so the synchronous caller is not
        // delayed by an extra Redis round-trip.  Pub/sub is a
        // best-effort optimisation on top of the periodic refresh
        // safety net, so we only log publish failures.
        this.client.publish(this.eventsChannel(), JSON.stringify(event)).catch((error: unknown) => {
          this.logger?.warn('Redis kill-switch publish failed; remote replicas will converge via periodic refresh', {
            op,
            error: error instanceof Error ? error.message : 'Unknown error',
          });
        });
      })
      .catch((error: unknown) => {
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

  /**
   * Apply a kill-switch event broadcast by another replica to the
   * local cache.  Events originating from this same instance are
   * ignored because the issuing pod already updated its cache via
   * write-through.  Unknown / malformed payloads are dropped silently
   * (with a debug log) – the next periodic refresh will converge.
   */
  private handleIncomingEvent(payload: string): void {
    let event: KillSwitchEvent;
    try {
      event = JSON.parse(payload) as KillSwitchEvent;
    } catch (error) {
      this.logger?.debug?.('Ignoring malformed kill-switch event payload', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return;
    }
    if (!event || typeof event !== 'object' || event.v !== EVENT_SCHEMA_VERSION) {
      // Older / newer schema – ignore and rely on the periodic refresh
      // safety net to converge.
      return;
    }
    if (event.src === this.instanceId) {
      // Echo of our own publish – cache is already up to date.
      return;
    }
    switch (event.op) {
      case 'activate_global':
        this.cache.globalKillSwitch = true;
        break;
      case 'deactivate_global':
        this.cache.globalKillSwitch = false;
        break;
      case 'kill_session':
      case 'revive_session':
      case 'kill_agent':
      case 'revive_agent':
        // Guard against malformed payloads where the id field is absent or
        // not a string (e.g. `{ v:1, op:"kill_session" }`) – inserting
        // `undefined` into the in-memory Set would corrupt the cache until
        // the next periodic refresh overwrites it.
        if (typeof event.id !== 'string') {
          this.logger?.debug?.('Ignoring kill-switch event with missing or non-string id', { op: event.op });
          return;
        }
        if (event.op === 'kill_session') {
          this.cache.killedSessions.add(event.id);
        } else if (event.op === 'revive_session') {
          this.cache.killedSessions.delete(event.id);
        } else if (event.op === 'kill_agent') {
          this.cache.killedAgents.add(event.id);
        } else {
          this.cache.killedAgents.delete(event.id);
        }
        break;
      case 'reset_all':
        this.cache.globalKillSwitch = false;
        this.cache.killedSessions.clear();
        this.cache.killedAgents.clear();
        break;
      default:
        // Unknown op (forward-compatible schema bump) – ignore.
        return;
    }
    this.logger?.debug?.('Applied remote kill-switch event', {
      op: (event as { op: string }).op,
      src: event.src,
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
  private eventsChannel(): string {
    return `${this.keyPrefix}${DEFAULT_EVENTS_SUFFIX}`;
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
  type IoRedisLike = RedisKillSwitchClient & {
    duplicate?: () => RedisKillSwitchSubscriber;
  };
  const ClientCtor = Ctor as new (url: string, opts?: unknown) => IoRedisLike;
  const client = new ClientCtor(redisUrl, {
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
  // Pub/sub is on by default because it is the whole point of the
  // distributed kill switch: "kill now" must mean now, not "now + up to
  // refreshIntervalMs".  Operators can disable it (KILL_SWITCH_PUBSUB_ENABLED=false)
  // for environments where the duplicate Redis connection is undesirable
  // (e.g. very tight connection budgets on a managed Redis), at the cost
  // of cross-replica propagation falling back to the periodic refresh.
  const pubsubEnabled = env.KILL_SWITCH_PUBSUB_ENABLED !== 'false';

  let subscriber: RedisKillSwitchSubscriber | undefined;
  if (pubsubEnabled) {
    if (typeof client.duplicate !== 'function') {
      logger?.warn(
        'Configured Redis client does not support duplicate(); kill-switch pub/sub disabled, ' +
          'falling back to periodic-refresh propagation only.',
      );
    } else {
      subscriber = client.duplicate();
    }
  }

  const manager = new RedisKillSwitchManager(client, logger, {
    keyPrefix,
    refreshIntervalMs,
    failOpenOnWrite,
    subscriber,
  });
  await manager.start();

  logger?.info('Using Redis kill-switch manager for distributed emergency shutdown', {
    keyPrefix,
    refreshIntervalMs,
    failOpenOnWrite,
    pubsubEnabled: !!subscriber,
  });

  return manager;
}
