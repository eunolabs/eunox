/**
 * RedisAnomalyDetector — fleet-wide mint anomaly detection backed by Redis
 * ────────────────────────────────────────────────────────────────────────────
 * Implements the same three anomaly rules as {@link AnomalyDetector} but
 * stores bucket state in Redis hashes so all minter replicas share a coherent
 * view of per-tenant mint activity.  This addresses the per-replica limitation
 * documented in docs/architecture-review-2026-05.md §CR-4.
 *
 * ## How it works
 *
 * Each tenant gets two Redis hashes:
 *
 *   `minter:anomaly:short:{tenantId}` — short-term buckets (1-min resolution,
 *   `rateWindowMs + baselineWindowMs` retention)
 *
 *   `minter:anomaly:long:{tenantId}` — long-term buckets (1-hour resolution,
 *   7-day retention)
 *
 * Hash fields are `{bucketTs}:s` (success count) and `{bucketTs}:f` (failure
 * count) where `bucketTs` is the millisecond timestamp of the bucket start.
 * HINCRBY provides atomicity across concurrent replicas without locking.
 *
 * ## Fall-back behaviour
 *
 * On any Redis error, `recordMint` falls back transparently to the in-memory
 * `AnomalyDetector` so anomaly detection is never completely disabled by a
 * Redis outage — it just reverts to per-replica behaviour.
 *
 * ## TTL management
 *
 * EXPIRE is called on every write so the key TTL resets to the window size on
 * each activity.  Stale tenants' keys age out automatically.
 *
 * ## Usage
 *
 * ```typescript
 * const detector = new RedisAnomalyDetector(redisClient, {
 *   replicaId: process.env.MINTER_REPLICA_ID ?? os.hostname(),
 * });
 *
 * // Same interface as AnomalyDetector:
 * const firedRules = await detector.recordMint(tenantId, success);
 * ```
 *
 * Wire from environment in the minter bootstrap via `ANOMALY_REDIS_URL` or
 * `REDIS_URL`.  The bootstrap returns an `AnomalyDetector` (in-memory) when
 * no Redis URL is configured, so existing single-replica deployments are
 * unaffected.
 */

import { AnomalyDetectorOptions, AnomalyDetector } from './anomaly-detector';
import { anomalyAlertsTotal } from './metrics';

// ── Minimal Redis client interface ──────────────────────────────────────────

/**
 * Minimal Redis client surface required by {@link RedisAnomalyDetector}.
 * Defined locally so deployments that do not use Redis are not forced to
 * install ioredis.
 */
export interface RedisAnomalyClient {
  /** Atomically increment the integer stored at `hash[field]` by `increment`. */
  hincrby(key: string, field: string, increment: number): Promise<number>;
  /**
   * Retrieve all fields and their values from the hash stored at `key`.
   * Returns `null` when the key does not exist.
   */
  hgetall(key: string): Promise<Record<string, string> | null>;
  /**
   * Set a key's time to live in seconds.
   * @returns 1 if the timeout was set; 0 if the key does not exist.
   */
  expire(key: string, seconds: number): Promise<number>;
  on(event: string, listener: (...args: unknown[]) => void): unknown;
  quit(): Promise<unknown>;
}

// ── RedisAnomalyDetector ────────────────────────────────────────────────────

// Long-term bucket constants (same as AnomalyDetector).
const LONG_BUCKET_MS = 60 * 60 * 1000;   // 1 hour
const LONG_CAPACITY  = 170;               // 7 days + 2 spare
const LONG_TTL_SEC   = 8 * 24 * 3600;    // 8 days (7 days + 1 day buffer)

export class RedisAnomalyDetector {
  private readonly client: RedisAnomalyClient;
  /**
   * In-memory fallback used when Redis is unavailable.  Reverts to per-replica
   * behaviour but prevents complete loss of anomaly detection.
   */
  private readonly fallback: AnomalyDetector;

  // Rule parameters (mirrors AnomalyDetector).
  private readonly rateSpikeMultiplier: number;
  private readonly rateWindowMs: number;
  private readonly baselineWindowMs: number;
  private readonly offHoursStartHour: number;
  private readonly offHoursEndHour: number;
  private readonly lowActivityThreshold: number;
  private readonly failureRateThreshold: number;
  private readonly failureRateWindowMs: number;
  private readonly nowFn: () => number;
  readonly replicaId: string;

  private readonly shortBucketMs: number;
  private readonly shortTtlSec: number;
  private readonly keyPrefix: string;

  constructor(client: RedisAnomalyClient, opts: AnomalyDetectorOptions & {
    /**
     * Redis key prefix for bucket hashes.
     * @default 'minter:anomaly:'
     */
    keyPrefix?: string;
  } = {}) {
    this.client = client;
    this.rateSpikeMultiplier = opts.rateSpikeMultiplier ?? 10;
    this.rateWindowMs = opts.rateWindowMs ?? 5 * 60 * 1000;
    this.baselineWindowMs = opts.baselineWindowMs ?? 60 * 60 * 1000;
    this.offHoursStartHour = opts.offHoursStartHour ?? 22;
    this.offHoursEndHour = opts.offHoursEndHour ?? 6;
    this.lowActivityThreshold = opts.lowActivityThreshold ?? 10;
    this.failureRateThreshold = opts.failureRateThreshold ?? 0.5;
    this.failureRateWindowMs = opts.failureRateWindowMs ?? 5 * 60 * 1000;
    this.nowFn = opts.nowFn ?? (() => Date.now());
    this.replicaId = opts.replicaId ?? '';
    this.keyPrefix = opts.keyPrefix ?? 'minter:anomaly:';

    // Same short-bucket resolution as AnomalyDetector.
    this.shortBucketMs = Math.max(
      Math.floor(Math.min(this.rateWindowMs, this.failureRateWindowMs) / 5),
      1_000,
    );

    // Short-term hash TTL: full window + 20% buffer so Redis expires stale
    // hashes without evicting buckets still within the evaluation window.
    const shortWindowSec = (this.baselineWindowMs + this.rateWindowMs) / 1000;
    this.shortTtlSec = Math.ceil(shortWindowSec * 1.2);

    // In-memory fallback — same options, same replica label.
    this.fallback = new AnomalyDetector(opts);

    this.client.on('error', () => {
      // Surface Redis errors to the fallback detector's error context.
      // The fallback itself is always healthy; errors here are transient.
    });
  }

  /**
   * Record a mint attempt and evaluate anomaly rules using fleet-wide Redis state.
   *
   * Falls back to the in-memory {@link AnomalyDetector} on any Redis error
   * so anomaly detection is never completely disabled by an outage.
   *
   * @returns Alphabetically sorted list of rule names that fired (empty for
   *          normal mints).
   */
  async recordMint(tenantId: string, success: boolean): Promise<string[]> {
    try {
      return await this.recordMintRedis(tenantId, success);
    } catch {
      // Redis unavailable — fall back to per-replica in-memory detector.
      return this.fallback.recordMint(tenantId, success);
    }
  }

  private async recordMintRedis(tenantId: string, success: boolean): Promise<string[]> {
    const now = this.nowFn();

    const shortBucketTs = Math.floor(now / this.shortBucketMs) * this.shortBucketMs;
    const longBucketTs  = Math.floor(now / LONG_BUCKET_MS) * LONG_BUCKET_MS;

    const shortKey = `${this.keyPrefix}short:${tenantId}`;
    const longKey  = `${this.keyPrefix}long:${tenantId}`;

    const shortField = success ? `${shortBucketTs}:s` : `${shortBucketTs}:f`;
    const longField  = success ? `${longBucketTs}:s`  : `${longBucketTs}:f`;

    // Atomic bucket increments + TTL refresh.  All four operations run in
    // parallel to minimise round-trip overhead on the mint hot path.
    await Promise.all([
      this.client.hincrby(shortKey, shortField, 1),
      this.client.expire(shortKey, this.shortTtlSec),
      this.client.hincrby(longKey, longField, 1),
      this.client.expire(longKey, LONG_TTL_SEC),
    ]);

    // Read both hashes concurrently to evaluate rules.
    const [shortData, longData] = await Promise.all([
      this.client.hgetall(shortKey),
      this.client.hgetall(longKey),
    ]);

    const fired: string[] = [];

    if (this.evaluateRateSpikeRedis(shortData ?? {}, now)) {
      fired.push('rate_spike');
      anomalyAlertsTotal.inc({ tenant: tenantId, rule: 'rate_spike', replica: this.replicaId });
    }

    if (success && this.evaluateOffHoursRedis(longData ?? {}, now)) {
      fired.push('off_hours_low_activity');
      anomalyAlertsTotal.inc({ tenant: tenantId, rule: 'off_hours_low_activity', replica: this.replicaId });
    }

    if (this.evaluateFailureClusteringRedis(shortData ?? {}, now)) {
      fired.push('failure_clustering');
      anomalyAlertsTotal.inc({ tenant: tenantId, rule: 'failure_clustering', replica: this.replicaId });
    }

    fired.sort();
    return fired;
  }

  async close(): Promise<void> {
    try {
      await this.client.quit();
    } catch {
      // Swallow quit errors — same pattern as other Redis stores.
    }
  }

  // ── Rule evaluators ────────────────────────────────────────────────────────

  private evaluateRateSpikeRedis(data: Record<string, string>, now: number): boolean {
    const currentWindowStart  = now - this.rateWindowMs;
    const baselineWindowStart = currentWindowStart - this.baselineWindowMs;

    let current = 0;
    let historical = 0;

    for (const [field, value] of Object.entries(data)) {
      const colonIdx = field.lastIndexOf(':');
      if (colonIdx === -1) continue;
      const bucketTs = Number(field.slice(0, colonIdx));
      if (!Number.isFinite(bucketTs)) continue;
      const count = Number(value) || 0;

      if (bucketTs >= currentWindowStart) {
        current += count;
      } else if (bucketTs >= baselineWindowStart) {
        historical += count;
      }
    }

    if (historical === 0) return false;

    // Normalise to per-window counts so the multiplier threshold is consistent
    // regardless of window sizes.
    const baselineWindowCount = this.baselineWindowMs / this.rateWindowMs;
    const baselinePerWindow = baselineWindowCount > 0 ? historical / baselineWindowCount : 0;
    return baselinePerWindow > 0 && current > this.rateSpikeMultiplier * baselinePerWindow;
  }

  private evaluateOffHoursRedis(data: Record<string, string>, now: number): boolean {
    const hour = new Date(now).getUTCHours();
    const isOffHours = this.offHoursStartHour > this.offHoursEndHour
      ? hour >= this.offHoursStartHour || hour < this.offHoursEndHour
      : hour >= this.offHoursStartHour && hour < this.offHoursEndHour;

    if (!isOffHours) return false;

    const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;
    const windowStart = now - sevenDaysMs;
    let successCount = 0;

    for (const [field, value] of Object.entries(data)) {
      if (!field.endsWith(':s')) continue;
      const colonIdx = field.lastIndexOf(':');
      const bucketTs = Number(field.slice(0, colonIdx));
      if (!Number.isFinite(bucketTs)) continue;
      if (bucketTs >= windowStart) {
        successCount += Number(value) || 0;
      }
    }

    return successCount < this.lowActivityThreshold;
  }

  private evaluateFailureClusteringRedis(data: Record<string, string>, now: number): boolean {
    const windowStart = now - this.failureRateWindowMs;
    let success = 0;
    let failure = 0;

    for (const [field, value] of Object.entries(data)) {
      const colonIdx = field.lastIndexOf(':');
      if (colonIdx === -1) continue;
      const bucketTs = Number(field.slice(0, colonIdx));
      if (!Number.isFinite(bucketTs)) continue;
      if (bucketTs < windowStart) continue;

      const type = field.slice(colonIdx + 1);
      const count = Number(value) || 0;
      if (type === 's') success += count;
      else if (type === 'f') failure += count;
    }

    const total = success + failure;
    if (total < 2) return false;
    return failure / total > this.failureRateThreshold;
  }
}

/**
 * Factory function that creates a `RedisAnomalyDetector` from environment
 * variables, or falls back to the in-memory `AnomalyDetector` when no Redis
 * URL is configured.
 *
 * @param env - `process.env` (or a subset thereof).
 * @param opts - Additional detector options (thresholds, `nowFn`, etc.).
 * @returns `RedisAnomalyDetector` when `ANOMALY_REDIS_URL` or `REDIS_URL`
 *          is set; `AnomalyDetector` otherwise.
 */
export function createAnomalyDetectorFromEnv(
  env: NodeJS.ProcessEnv,
  opts: AnomalyDetectorOptions & { keyPrefix?: string } = {},
): RedisAnomalyDetector | AnomalyDetector {
  const redisUrl = env.ANOMALY_REDIS_URL || env.REDIS_URL;
  if (!redisUrl) {
    return new AnomalyDetector(opts);
  }

  let RedisCtor: unknown;
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires, @typescript-eslint/no-require-imports
    RedisCtor = require('ioredis');
  } catch {
    // ioredis not available — fall back to in-memory.
    return new AnomalyDetector(opts);
  }

  const Ctor = (RedisCtor as { default?: unknown }).default ?? RedisCtor;
  const client = new (Ctor as new (url: string, opts?: unknown) => RedisAnomalyClient)(redisUrl, {
    retryStrategy: (times: number) => Math.min(times * 50, 2000),
    maxRetriesPerRequest: 3,
    lazyConnect: false,
  });

  return new RedisAnomalyDetector(client, opts);
}
