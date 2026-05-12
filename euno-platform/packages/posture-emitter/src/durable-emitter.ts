/**
 * Guaranteed-delivery posture emitter.
 *
 * Replaces the fire-and-forget fan-out in {@link PostureEmitter} with
 * a durable write-ahead pipeline:
 *
 *   1. **Inline write** — `emitObserved` / `emitRevoked` serialise the
 *      event to a SQLite WAL-mode queue before returning.  The write
 *      typically takes < 1 ms and the caller bears no plugin latency.
 *
 *   2. **Asynchronous delivery** — a {@link DeliveryWorker} background
 *      loop polls the queue, fans out to all configured plugins, and
 *      removes the event only after every plugin acknowledges delivery.
 *      Failed attempts are retried with exponential back-off; events
 *      that exhaust `maxAttempts` are dead-lettered (removed from queue
 *      and counted via the `onDeadLettered` metric hook) so a
 *      permanently-broken plugin does not prevent other events from
 *      draining.
 *
 *   3. **Lag metric** — callers can call {@link queueDepth} and
 *      {@link oldestLagMs} at any time to update Prometheus gauges:
 *
 *      ```typescript
 *      setInterval(() => {
 *        depthGauge.set(emitter.queueDepth());
 *        lagGauge.set(emitter.oldestLagMs());
 *      }, 5_000).unref();
 *      ```
 *
 * ## Back-compat
 *
 * The original {@link PostureEmitter} (best-effort, no persistence) is
 * unchanged.  `DurablePostureEmitter` is an additive class; callers
 * that need guaranteed delivery should construct it instead.
 *
 * ## Usage
 *
 * ```typescript
 * const emitter = DurablePostureEmitter.fromEnv(process.env, logger);
 * emitter.start();
 *
 * // On every agent issuance:
 * await emitter.emitObserved(record);  // fast — just a SQLite insert
 *
 * // On shutdown:
 * await emitter.stop();
 * ```
 */
import {
  AgentCapabilityManifest,
  AgentInventoryRecord,
  CapabilityConstraint,
  Logger,
  canonicalSha256,
} from '@euno/common';
import {
  DEFAULT_DEDUPE_WINDOW_MS,
  DEFAULT_PLUGIN_TIMEOUT_MS,
  DEFAULT_REFRESH_INTERVAL_MS,
  PostureEmitterPlugin,
} from './types';
import { RecordStore } from './record-store';
import { DurableQueue } from './durable-queue';
import { DeliveryWorker, DeliveryMetricsHooks, DeliveryWorkerOptions } from './delivery-worker';
import { StdoutPosturePlugin } from './plugins/stdout';
import { DefenderCspmPlugin } from './plugins/defender-cspm';
import { SecurityHubPlugin } from './plugins/security-hub';
import { SccPlugin } from './plugins/scc';

/** Re-export for callers that only use `DurablePostureEmitter`. */
export const hashManifest = canonicalSha256;

export interface DurablePostureEmitterOptions {
  /**
   * When `false` the emitter is a no-op. Defaults to `true`.
   * `fromEnv` honours `POSTURE_EMITTER_ENABLED`.
   */
  enabled?: boolean;

  /** Plugins to deliver events to. */
  plugins: PostureEmitterPlugin[];

  /**
   * SQLite file path for the durable queue.
   * Use `':memory:'` for tests or when you deliberately want no
   * persistence (effectively the same durability as `PostureEmitter`).
   * Defaults to `':memory:'`.
   */
  queuePath?: string;

  /** Number of events pulled per poll tick. Default: 50. */
  deliveryBatchSize?: number;

  /** Poll interval when the queue is empty (ms). Default: 1 000 ms. */
  deliveryPollIntervalMs?: number;

  /** Per-plugin delivery timeout (ms). Default: 5 000 ms. */
  pluginTimeoutMs?: number;

  /**
   * Maximum delivery attempts before an event is dead-lettered.
   * Default: 10.
   */
  maxAttempts?: number;

  /**
   * Base back-off delay (ms).
   * Delay after attempt n = `min(backoffBaseMs * 2^n, backoffMaxMs)`.
   * Default: 1 000 ms.
   */
  backoffBaseMs?: number;

  /** Maximum back-off delay (ms). Default: 300 000 ms (5 min). */
  backoffMaxMs?: number;

  /** Window during which a duplicate `emitObserved` is suppressed. */
  dedupeWindowMs?: number;

  /** Optional logger for worker diagnostics and warnings. */
  logger?: Logger;

  /** Optional metrics hooks for counters and gauges. */
  metrics?: DeliveryMetricsHooks;
}

/**
 * Posture emitter backed by a local SQLite WAL queue for guaranteed
 * delivery.  See module JSDoc for the delivery contract.
 */
export class DurablePostureEmitter {
  private readonly enabled: boolean;
  private readonly hasPlugins: boolean;
  private readonly store: RecordStore;
  private readonly queue: DurableQueue;
  private readonly worker: DeliveryWorker;

  constructor(opts: DurablePostureEmitterOptions) {
    this.hasPlugins = opts.plugins.length > 0;
    // Force disabled when no plugins are configured so that events are
    // never silently dropped by an ack-without-delivery worker.
    this.enabled = opts.enabled !== false && this.hasPlugins;
    this.store = new RecordStore({
      dedupeWindowMs: opts.dedupeWindowMs ?? DEFAULT_DEDUPE_WINDOW_MS,
    });

    this.queue = new DurableQueue({ path: opts.queuePath ?? ':memory:' });

    const workerOpts: DeliveryWorkerOptions = {
      queue: this.queue,
      plugins: opts.plugins,
      batchSize: opts.deliveryBatchSize,
      pollIntervalMs: opts.deliveryPollIntervalMs,
      pluginTimeoutMs: opts.pluginTimeoutMs ?? DEFAULT_PLUGIN_TIMEOUT_MS,
      maxAttempts: opts.maxAttempts,
      backoffBaseMs: opts.backoffBaseMs,
      backoffMaxMs: opts.backoffMaxMs,
      logger: opts.logger,
      metrics: opts.metrics,
    };
    this.worker = new DeliveryWorker(workerOpts);
  }

  /** `true` when emission is enabled AND at least one plugin is configured. */
  isEnabled(): boolean {
    return this.enabled;
  }

  /**
   * Start the background delivery worker.
   * Safe to call multiple times; subsequent calls are no-ops.
   */
  start(): void {
    if (!this.enabled) return;
    this.worker.start();
  }

  /**
   * Stop the background worker and close the SQLite connection.
   * Awaiting the returned promise ensures the in-flight poll tick has
   * finished before the caller continues (e.g. process shutdown).
   */
  async stop(): Promise<void> {
    await this.worker.stop();
    this.queue.close();
  }

  /**
   * Enqueue an inventory record for delivery to all plugins.
   *
   * Writes to the SQLite WAL synchronously, then returns.  A duplicate
   * emit inside the dedupe window is dropped (dedupe is still in-memory,
   * so duplicates from before a restart are re-emitted — this is the
   * safe direction: a duplicate posture record on the SIEM is harmless,
   * whereas a gap is a detection blind spot).
   */
  async emitObserved(record: AgentInventoryRecord): Promise<void> {
    if (!this.enabled) return;
    const shouldEmit = this.store.upsert(record);
    if (!shouldEmit) return;
    this.queue.push('observed', JSON.stringify({ record }));
  }

  /**
   * Enqueue a revocation event for delivery to all plugins.
   *
   * Marks the agent as revoked in the local dedupe store so a
   * concurrent periodic refresh does not re-emit it as `ACTIVE`.
   */
  async emitRevoked(agentId: string, revokedAt: string): Promise<void> {
    if (!this.enabled) return;
    this.store.markRevoked(agentId, revokedAt);
    this.queue.push('revoked', JSON.stringify({ agentId, revokedAt }));
  }

  /**
   * Start a periodic timer that re-emits every non-revoked record.
   * Returns a function that cancels the timer.
   *
   * The timer is unref'd so it does not keep the Node event loop alive.
   */
  startPeriodicRefresh(intervalMs: number = DEFAULT_REFRESH_INTERVAL_MS): () => void {
    if (!this.enabled || intervalMs <= 0) return () => undefined;
    const timer = setInterval(() => {
      void this.refreshOnce();
    }, intervalMs);
    if (typeof timer.unref === 'function') timer.unref();
    return () => clearInterval(timer);
  }

  /**
   * Re-enqueue every active record exactly once.
   * Exposed for tests; the periodic refresh timer calls this internally.
   */
  async refreshOnce(): Promise<void> {
    if (!this.enabled) return;
    const active = this.store.listActive();
    const nowIso = new Date().toISOString();
    for (const record of active) {
      const refreshed: AgentInventoryRecord = { ...record, lastSeen: nowIso };
      this.store.upsert(refreshed);
      // Bypass the dedupe window — refresh always enqueues.
      this.queue.push('observed', JSON.stringify({ record: refreshed }));
    }
  }

  // -------------------------------------------------------------------------
  // Metrics helpers

  /**
   * Current number of events in the durable queue.
   * Use this to set a Prometheus gauge.
   */
  queueDepth(): number {
    return this.queue.depth();
  }

  /**
   * Age in ms of the oldest undelivered event, or `0` when the queue is
   * empty.  Use this to set a Prometheus gauge for delivery lag.
   */
  oldestLagMs(nowMs: number = Date.now()): number {
    const oldest = this.queue.oldestInsertedAt();
    if (oldest === null) return 0;
    return Math.max(0, nowMs - oldest);
  }

  /** Snapshot of the local dedupe store. Exposed for tests. */
  snapshot(): AgentInventoryRecord[] {
    return this.store.listAll();
  }

  // -------------------------------------------------------------------------
  // Static helpers (mirrors PostureEmitter API)

  /**
   * Build a canonical {@link AgentInventoryRecord} from the fields
   * commonly available at issuance time.  Identical to
   * `PostureEmitter.buildRecord`.
   */
  static buildRecord(input: {
    agentId: string;
    manifest?: AgentCapabilityManifest;
    capabilities?: CapabilityConstraint[];
    region?: string;
    cloudAccount?: string;
    nowIso?: string;
  }): AgentInventoryRecord {
    const nowIso = input.nowIso ?? new Date().toISOString();
    const owningTeam = input.manifest?.metadata?.owner ?? 'unknown';
    const runtime = input.manifest?.metadata?.runtime ?? 'unknown';
    const region = input.region ?? 'unknown';
    const capabilityManifestHash = input.manifest
      ? hashManifest(input.manifest)
      : hashManifest({ agentId: input.agentId });
    const record: AgentInventoryRecord = {
      schemaVersion: '1.0',
      agentId: input.agentId,
      owningTeam,
      capabilityManifestHash,
      runtime,
      region,
      firstSeen: nowIso,
      lastSeen: nowIso,
    };
    if (input.cloudAccount !== undefined) record.cloudAccount = input.cloudAccount;
    if (input.capabilities !== undefined) record.capabilities = input.capabilities;
    return record;
  }

  /**
   * Construct a {@link DurablePostureEmitter} from environment variables.
   *
   * Recognised vars (inherits all vars from `PostureEmitter.fromEnv` plus):
   *   - `POSTURE_EMITTER_ENABLED`          — `true` to activate.
   *   - `POSTURE_EMITTER_PLUGINS`          — comma-separated plugin list.
   *   - `POSTURE_REFRESH_INTERVAL_MS`      — periodic refresh; callers
   *     must call {@link startPeriodicRefresh} to activate.
   *   - `POSTURE_DURABLE_QUEUE_PATH`       — SQLite file path.
   *     Defaults to `':memory:'` (no persistence across restarts).
   *     In production set this to a path on a persistent volume, e.g.
   *     `/var/lib/euno/posture-queue.db`.
   *   - `POSTURE_DURABLE_POLL_INTERVAL_MS` — worker poll interval ms.
   *   - `POSTURE_DURABLE_MAX_ATTEMPTS`     — max delivery attempts.
   *   - `POSTURE_DURABLE_BATCH_SIZE`       — events per poll tick.
   *   - Plugin-specific env vars (same as `PostureEmitter.fromEnv`):
   *     `AZURE_SUBSCRIPTION_ID`, `AWS_ACCOUNT_ID`, `AWS_REGION`,
   *     `SECURITY_HUB_PRODUCT_ARN`, `GCP_SCC_SOURCE_NAME`,
   *     `GCP_PROJECT_ID`.
   *
   * Returns a disabled emitter when `POSTURE_EMITTER_ENABLED` is not
   * `'true'`, preserving the existing opt-in behaviour.
   */
  static fromEnv(
    env: NodeJS.ProcessEnv = process.env,
    logger?: Logger,
    metrics?: DeliveryMetricsHooks,
  ): DurablePostureEmitter {
    const enabled = String(env.POSTURE_EMITTER_ENABLED ?? '').toLowerCase() === 'true';
    if (!enabled) {
      return new DurablePostureEmitter({ enabled: false, plugins: [], logger });
    }

    const requestedRaw = (env.POSTURE_EMITTER_PLUGINS ?? 'stdout').trim();
    const requested = requestedRaw
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter((s) => s.length > 0);

    const plugins: PostureEmitterPlugin[] = [];
    for (const name of requested) {
      try {
        const plugin = buildPluginFromEnv(name, env);
        if (plugin) plugins.push(plugin);
      } catch (err) {
        logger?.warn?.('posture-emitter plugin disabled: misconfigured', {
          plugin: name,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }
    if (plugins.length === 0) {
      plugins.push(new StdoutPosturePlugin());
    }

    const queuePath = env.POSTURE_DURABLE_QUEUE_PATH;
    if (!queuePath) {
      // `NODE_ENV` must be exactly `'production'` to trigger the hard error —
      // this is the standard Node.js convention (used by Express, webpack, etc.).
      // Aliases such as 'prod' are NOT recognised: operators MUST set
      // NODE_ENV=production in their production Kubernetes manifests.
      const isProduction = env.NODE_ENV === 'production';
      if (isProduction) {
        throw new Error(
          'posture-emitter: POSTURE_DURABLE_QUEUE_PATH must be set in production. ' +
            "Refusing to start with ':memory:' queue because events will be lost on pod " +
            'restart, defeating the durability guarantee the WAL design exists to provide. ' +
            'Set POSTURE_DURABLE_QUEUE_PATH to a path on a persistent volume, e.g. ' +
            '/var/lib/euno/posture-queue.db',
        );
      }
      logger?.warn?.(
        'posture-emitter: POSTURE_DURABLE_QUEUE_PATH is not set; ' +
          "using ':memory:' queue — events will not survive restarts. " +
          'Set POSTURE_DURABLE_QUEUE_PATH to a persistent volume path in production ' +
          '(a hard startup error will be thrown when NODE_ENV=production).',
        {},
      );
    }

    const pollIntervalMs = parsePositiveInt(env.POSTURE_DURABLE_POLL_INTERVAL_MS, 'POSTURE_DURABLE_POLL_INTERVAL_MS', logger);
    const maxAttempts = parsePositiveInt(env.POSTURE_DURABLE_MAX_ATTEMPTS, 'POSTURE_DURABLE_MAX_ATTEMPTS', logger);
    const batchSize = parsePositiveInt(env.POSTURE_DURABLE_BATCH_SIZE, 'POSTURE_DURABLE_BATCH_SIZE', logger);

    return new DurablePostureEmitter({
      enabled: true,
      plugins,
      queuePath: queuePath ?? ':memory:',
      deliveryPollIntervalMs: pollIntervalMs,
      maxAttempts,
      deliveryBatchSize: batchSize,
      logger,
      metrics,
    });
  }
}

// ---------------------------------------------------------------------------
// Internal helpers

/**
 * Parse an env var as a positive integer.
 * Returns `undefined` (so the caller uses the default) if the var is
 * unset, and logs a warning + returns `undefined` if the value is not
 * a finite positive integer, preventing pathological `setTimeout(NaN)`
 * or zero-delay tight-loop behaviour.
 */
function parsePositiveInt(
  raw: string | undefined,
  varName: string,
  logger?: Logger,
): number | undefined {
  if (!raw) return undefined;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0 || !Number.isInteger(n)) {
    logger?.warn?.(
      `posture-emitter: ${varName} has an invalid value '${raw}'; using default`,
      {},
    );
    return undefined;
  }
  return n;
}

// ---------------------------------------------------------------------------
// Internal: plugin factory (same logic as PostureEmitter.fromEnv)

function buildPluginFromEnv(
  name: string,
  env: NodeJS.ProcessEnv,
): PostureEmitterPlugin | undefined {
  switch (name) {
    case 'stdout':
      return new StdoutPosturePlugin();
    case 'defender-cspm': {
      const subscriptionId = env.AZURE_SUBSCRIPTION_ID;
      if (!subscriptionId) {
        throw new Error('AZURE_SUBSCRIPTION_ID is required for defender-cspm plugin');
      }
      return new DefenderCspmPlugin({ subscriptionId });
    }
    case 'security-hub': {
      const awsAccountId = env.AWS_ACCOUNT_ID;
      const region = env.AWS_REGION ?? env.AWS_DEFAULT_REGION;
      const productArn = env.SECURITY_HUB_PRODUCT_ARN;
      if (!awsAccountId || !region || !productArn) {
        throw new Error(
          'AWS_ACCOUNT_ID, AWS_REGION and SECURITY_HUB_PRODUCT_ARN are required for security-hub plugin',
        );
      }
      return new SecurityHubPlugin({ awsAccountId, region, productArn });
    }
    case 'scc': {
      const sourceName = env.GCP_SCC_SOURCE_NAME;
      const projectId = env.GCP_PROJECT_ID;
      if (!sourceName || !projectId) {
        throw new Error('GCP_SCC_SOURCE_NAME and GCP_PROJECT_ID are required for scc plugin');
      }
      return new SccPlugin({ sourceName, projectId });
    }
    default:
      throw new Error(`Unknown posture-emitter plugin: '${name}'`);
  }
}
