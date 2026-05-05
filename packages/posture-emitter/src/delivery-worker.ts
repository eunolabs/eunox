/**
 * Background delivery worker for the durable posture-emitter pipeline.
 *
 * The worker runs a continuous polling loop:
 *
 *   1. `queue.peek(batchSize)` — fetch events whose retry delay has
 *      elapsed.
 *   2. For each event, fan out to all configured plugins (parallel,
 *      per-plugin timeout).
 *   3. `queue.ack(id)` on success, `queue.nack(id, …)` on failure with
 *      exponential backoff.  After `maxAttempts` the event is
 *      dead-lettered (removed from queue, `onDeadLettered` callback
 *      called) so a permanently-broken plugin does not block other
 *      events forever.
 *
 * ## Metrics surface
 *
 * The worker does not register Prometheus metrics directly because the
 * posture-emitter package does not own a `prom-client` Registry.
 * Instead it exposes callback hooks so the hosting service can wire
 * its own counters / gauges:
 *
 *   - `onDelivered(type, plugin)`    — increment on each successful
 *                                      per-plugin delivery.
 *   - `onDeliveryError(type, plugin)` — increment on each per-plugin
 *                                      failure (includes final failure
 *                                      before dead-letter).
 *   - `onDeadLettered(type)`          — increment when an event is
 *                                      removed after exhausting retries.
 *
 * Queue depth and delivery lag are observable via {@link DurableQueue.depth}
 * and {@link DurableQueue.oldestInsertedAt}; a hosting service should
 * poll these on its own scrape interval and update gauges:
 *
 * ```typescript
 * setInterval(() => {
 *   queueDepthGauge.set(queue.depth());
 *   const oldest = queue.oldestInsertedAt();
 *   queueLagGauge.set(oldest == null ? 0 : Date.now() - oldest);
 * }, 5_000).unref();
 * ```
 */
import { AgentInventoryRecord, Logger } from '@euno/common';
import {
  PostureEmitterPlugin,
  DEFAULT_DELIVERY_BATCH_SIZE,
  DEFAULT_DELIVERY_POLL_INTERVAL_MS,
  DEFAULT_PLUGIN_TIMEOUT_MS,
  DEFAULT_MAX_ATTEMPTS,
  DEFAULT_BACKOFF_BASE_MS,
  DEFAULT_BACKOFF_MAX_MS,
} from './types';
import { DurableQueue, QueuedEvent, QueuedEventType } from './durable-queue';

/** Hooks for Prometheus / custom metrics sinks. */
export interface DeliveryMetricsHooks {
  /**
   * Called once per plugin per event on a successful delivery.
   * @param type   `'observed'` or `'revoked'`.
   * @param plugin Plugin name (`'stdout'`, `'defender-cspm'`, …).
   */
  onDelivered?: (type: QueuedEventType, plugin: string) => void;

  /**
   * Called once per plugin per event when a delivery attempt fails.
   * Also called for the final failing attempt before dead-lettering.
   * @param type   `'observed'` or `'revoked'`.
   * @param plugin Plugin name.
   */
  onDeliveryError?: (type: QueuedEventType, plugin: string) => void;

  /**
   * Called when an event is permanently removed after exhausting all
   * allowed attempts.
   * @param type `'observed'` or `'revoked'`.
   */
  onDeadLettered?: (type: QueuedEventType) => void;
}

export interface DeliveryWorkerOptions {
  /** Durable queue to drain. */
  queue: DurableQueue;
  /** Plugins to fan out to. */
  plugins: PostureEmitterPlugin[];
  /**
   * How many events to pull from the queue per poll tick.
   * Default: 50.
   */
  batchSize?: number;
  /**
   * How long to wait between poll ticks when the queue is empty (ms).
   * Default: 1 000 ms.
   */
  pollIntervalMs?: number;
  /**
   * Per-plugin delivery timeout (ms).
   * Default: 5 000 ms.
   */
  pluginTimeoutMs?: number;
  /**
   * Maximum total attempts per event before it is dead-lettered.
   * Default: 10.
   */
  maxAttempts?: number;
  /**
   * Base interval for exponential back-off (ms).
   * Delay after attempt n = `min(backoffBaseMs * 2^n, backoffMaxMs)`.
   * Default: 1 000 ms.
   */
  backoffBaseMs?: number;
  /**
   * Maximum back-off interval (ms).
   * Default: 300 000 ms (5 min).
   */
  backoffMaxMs?: number;
  /** Optional logger for worker diagnostics. */
  logger?: Logger;
  /** Optional metrics hooks. */
  metrics?: DeliveryMetricsHooks;
}

/** Parsed `observed` payload. */
interface ObservedPayload {
  record: AgentInventoryRecord;
}

/** Parsed `revoked` payload. */
interface RevokedPayload {
  agentId: string;
  revokedAt: string;
}

/**
 * Background worker that drains the {@link DurableQueue} with retries.
 *
 * Call {@link start} once to begin polling, {@link stop} (and await
 * the returned promise) on graceful shutdown.
 */
export class DeliveryWorker {
  private readonly queue: DurableQueue;
  private readonly plugins: PostureEmitterPlugin[];
  private readonly batchSize: number;
  private readonly pollIntervalMs: number;
  private readonly pluginTimeoutMs: number;
  private readonly maxAttempts: number;
  private readonly backoffBaseMs: number;
  private readonly backoffMaxMs: number;
  private readonly logger?: Logger;
  private readonly metrics: DeliveryMetricsHooks;

  private running = false;
  private stopPromise: Promise<void> | null = null;
  private resolveStop: (() => void) | null = null;

  constructor(opts: DeliveryWorkerOptions) {
    this.queue = opts.queue;
    this.plugins = [...opts.plugins];
    this.batchSize = opts.batchSize ?? DEFAULT_DELIVERY_BATCH_SIZE;
    this.pollIntervalMs = opts.pollIntervalMs ?? DEFAULT_DELIVERY_POLL_INTERVAL_MS;
    this.pluginTimeoutMs = opts.pluginTimeoutMs ?? DEFAULT_PLUGIN_TIMEOUT_MS;
    this.maxAttempts = opts.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
    this.backoffBaseMs = opts.backoffBaseMs ?? DEFAULT_BACKOFF_BASE_MS;
    this.backoffMaxMs = opts.backoffMaxMs ?? DEFAULT_BACKOFF_MAX_MS;
    this.logger = opts.logger;
    this.metrics = opts.metrics ?? {};
  }

  /**
   * Start the background poll loop.
   * Safe to call multiple times; subsequent calls are ignored.
   */
  start(): void {
    if (this.running) return;
    this.running = true;
    this.stopPromise = new Promise<void>((resolve) => {
      this.resolveStop = resolve;
    });
    void this.loop();
  }

  /**
   * Signal the worker to stop and return a promise that resolves
   * once the in-flight tick has finished.
   */
  stop(): Promise<void> {
    this.running = false;
    return this.stopPromise ?? Promise.resolve();
  }

  // -------------------------------------------------------------------------
  // Internal

  private async loop(): Promise<void> {
    while (this.running) {
      const events = this.queue.peek(this.batchSize);
      if (events.length === 0) {
        // Nothing to deliver — sleep before checking again.
        await this.sleep(this.pollIntervalMs);
        continue;
      }
      // Process events in this tick sequentially so a burst of retries
      // does not simultaneously hammer all plugins.
      for (const event of events) {
        if (!this.running) break;
        await this.deliver(event);
      }
    }
    this.resolveStop?.();
  }

  private async deliver(event: QueuedEvent): Promise<void> {
    const { allSucceeded, lastError } = await this.fanOut(event);
    if (allSucceeded) {
      this.queue.ack(event.id);
    } else {
      const nextAttempts = event.attempts + 1;
      if (nextAttempts >= this.maxAttempts) {
        // Give up — dead-letter the event so it doesn't block the queue.
        this.logger?.warn?.('posture-emitter: dead-lettering event after max attempts', {
          id: event.id,
          type: event.type,
          attempts: nextAttempts,
        });
        this.metrics.onDeadLettered?.(event.type as QueuedEventType);
        this.queue.ack(event.id);
      } else {
        const backoffMs = Math.min(
          this.backoffBaseMs * Math.pow(2, event.attempts),
          this.backoffMaxMs,
        );
        this.queue.nack(
          event.id,
          Date.now() + backoffMs,
          lastError ?? 'delivery failed',
        );
      }
    }
  }

  /**
   * Fan out a queued event to all plugins in parallel.
   * Returns `allSucceeded=true` when ALL plugins succeeded, plus the
   * last error message seen during this attempt (for storage in the
   * queue's `last_error` column via `nack`).
   *
   * Note: "all or none" ack semantics — if even one plugin fails the
   * event stays in the queue and will be retried.  This is the safe
   * default for SIEM pipelines where partial delivery is worse than
   * duplicate delivery.
   */
  private async fanOut(event: QueuedEvent): Promise<{ allSucceeded: boolean; lastError: string | null }> {
    if (this.plugins.length === 0) return { allSucceeded: true, lastError: null };

    let allSucceeded = true;
    let lastError: string | null = null;
    const results = await Promise.all(
      this.plugins.map(async (plugin) => {
        try {
          await this.invokePlugin(plugin, event);
          this.metrics.onDelivered?.(event.type as QueuedEventType, plugin.name);
          return { ok: true, error: null };
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          this.metrics.onDeliveryError?.(event.type as QueuedEventType, plugin.name);
          this.logger?.warn?.('posture-emitter: plugin delivery error', {
            id: event.id,
            type: event.type,
            plugin: plugin.name,
            attempts: event.attempts + 1,
            error: message,
          });
          return { ok: false, error: message };
        }
      }),
    );

    for (const { ok, error } of results) {
      if (!ok) {
        allSucceeded = false;
        if (error) lastError = error;
      }
    }
    return { allSucceeded, lastError };
  }

  private async invokePlugin(plugin: PostureEmitterPlugin, event: QueuedEvent): Promise<void> {
    let call: Promise<void>;
    if (event.type === 'observed') {
      const { record } = JSON.parse(event.payload) as ObservedPayload;
      call = plugin.emitObserved(record);
    } else {
      const { agentId, revokedAt } = JSON.parse(event.payload) as RevokedPayload;
      call = plugin.emitRevoked(agentId, revokedAt);
    }
    await this.withTimeout(call, this.pluginTimeoutMs, plugin.name);
  }

  private withTimeout<T>(p: Promise<T>, ms: number, pluginName: string): Promise<T> {
    if (ms <= 0) return p;
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`posture-emitter plugin '${pluginName}' timed out after ${ms}ms`));
      }, ms);
      if (typeof timer.unref === 'function') timer.unref();
      p.then(
        (v) => { clearTimeout(timer); resolve(v); },
        (e) => { clearTimeout(timer); reject(e); },
      );
    });
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => {
      const t = setTimeout(resolve, ms);
      if (typeof t.unref === 'function') t.unref();
    });
  }
}
