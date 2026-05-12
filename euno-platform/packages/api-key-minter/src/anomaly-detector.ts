/**
 * AnomalyDetector — in-process mint anomaly detection
 * ────────────────────────────────────────────────────────────────────────────
 * Implements the three in-process anomaly rules defined in
 * docs/security/minter-threat-model.md §7 (Monitoring and Alerting).
 * When a rule fires, `euno_minter_anomaly_alerts_total{tenant, rule, replica}`
 * is incremented.  The Prometheus alerting rules in
 * `prometheus/minter-alert-rules.yaml` provide the production alert routing;
 * this detector provides:
 *
 *   1. Sub-minute anomaly detection (faster than Prometheus scrape intervals).
 *   2. Defence in depth — fires even when the Prometheus server is unreachable.
 *   3. A counter that enables per-tenant anomaly rate dashboards without
 *      complex PromQL.
 *
 * ## ⚠️ Per-replica limitation (CR-4)
 *
 * `AnomalyDetector` is an **in-process** ring-buffer structure.  Each minter
 * replica maintains completely **independent** per-tenant bucket state.  An
 * attacker distributing mint requests across N replicas (e.g. via a load
 * balancer) will appear at only 1/N of the actual mint rate on each replica,
 * potentially staying below all three rule thresholds.
 *
 * **Mitigations:**
 * - Set `replicaId` (from `MINTER_REPLICA_ID` or `os.hostname()`) so the
 *   `replica` label on `euno_minter_anomaly_alerts_total` makes per-instance
 *   discrepancies visible in Prometheus.
 * - For the hosted service, replace this detector with `RedisAnomalyDetector`
 *   (see `src/redis-anomaly-detector.ts`) which backs bucket state with Redis
 *   hashes so all replicas share a coherent view.
 * - Set `ANOMALY_REDIS_URL` (or `REDIS_URL`) in the minter bootstrap to
 *   automatically wire the Redis-backed detector.
 *
 * ## Rules implemented
 *
 * | Rule | `rule` label | Condition |
 * |---|---|---|
 * | Rate spike | `rate_spike` | Current 5-min mint count > 10× 60-min rolling average |
 * | Off-hours low-activity | `off_hours_low_activity` | Mint during 22:00–06:00 UTC AND < 10 mints in last 7 days |
 * | Failure clustering | `failure_clustering` | Failure rate > 50% over last 5 minutes |
 *
 * ## Usage
 *
 * ```typescript
 * const detector = new AnomalyDetector();
 *
 * // In the mint route after each attempt:
 * const firedRules = detector.recordMint(tenantId, success /* true=minted *\/);
 * // firedRules is [] for a normal mint, or e.g. ['rate_spike'] for anomalies.
 * ```
 *
 * ## Memory bounds
 *
 * Per-tenant state is stored in fixed-capacity ring buffers (BucketStore) —
 * one short-term store (1-min resolution, ≤ 70 buckets) for the rate-spike
 * and failure-clustering rules, and one long-term store (1-hour resolution,
 * 170 buckets = 7 days) for the off-hours rule.
 *
 * Worst-case memory at 10,000 active tenants:
 *   - Short-term:  70 buckets × 24 bytes × 10,000 tenants ≈ 17 MB
 *   - Long-term:  170 buckets × 24 bytes × 10,000 tenants ≈ 41 MB
 *   - Total: ≈ 58 MB — bounded regardless of request volume.
 *
 * `recordMint` is O(1) amortized per call: bucket updates are O(1), and
 * rule evaluation iterates at most `shortCapacity` (≤ ~70) or `longCapacity`
 * (170) buckets — both are small, fixed constants.
 */

import { anomalyAlertsTotal } from './metrics';

// ── BucketStore ────────────────────────────────────────────────────────────────

/**
 * A fixed-capacity ring buffer of time-bucketed mint counts.
 *
 * Each bucket covers a fixed interval (`resolutionMs`) and accumulates
 * the number of successful and failed mint attempts that fell within it.
 * Once `capacity` buckets have been filled, the oldest bucket slot is
 * reused for the newest data, ensuring O(1) amortized writes and O(capacity)
 * space — both independent of request volume.
 */
class BucketStore {
  private readonly buf: Array<{ ts: number; success: number; failure: number }>;
  private head = 0;  // index of the oldest valid bucket
  private count = 0; // number of valid entries (≤ capacity)
  readonly resolutionMs: number;
  readonly capacity: number;

  constructor(resolutionMs: number, capacity: number) {
    this.resolutionMs = resolutionMs;
    this.capacity = capacity;
    // Pre-allocate all slots with sentinel values so the ring buffer never
    // needs to grow after construction.
    this.buf = [];
    for (let i = 0; i < capacity; i++) {
      this.buf.push({ ts: -Infinity, success: 0, failure: 0 });
    }
  }

  /** Add a mint attempt to the appropriate time bucket.  O(1) amortized. */
  record(ts: number, success: boolean): void {
    const bts = Math.floor(ts / this.resolutionMs) * this.resolutionMs;

    // Fast path: the newest bucket already covers this timestamp.
    if (this.count > 0) {
      const tail = this.buf[(this.head + this.count - 1) % this.capacity]!;
      if (tail.ts === bts) {
        if (success) tail.success++;
        else tail.failure++;
        return;
      }
    }

    // New bucket needed.
    if (this.count < this.capacity) {
      // Buffer not yet full — append after the current tail.
      const next = (this.head + this.count) % this.capacity;
      this.buf[next] = { ts: bts, success: success ? 1 : 0, failure: success ? 0 : 1 };
      this.count++;
    } else {
      // Buffer full — overwrite the oldest slot (at `head`) and advance head.
      this.buf[this.head] = { ts: bts, success: success ? 1 : 0, failure: success ? 0 : 1 };
      this.head = (this.head + 1) % this.capacity;
    }
  }

  /**
   * Sum all buckets whose start time is `>= fromMs`.
   * Used for the "current window" and "7-day total" queries where there is no
   * upper bound (the ring buffer contains no future data).
   */
  sumFrom(fromMs: number): { success: number; failure: number } {
    let s = 0;
    let f = 0;
    for (let i = 0; i < this.count; i++) {
      const b = this.buf[(this.head + i) % this.capacity]!;
      if (b.ts >= fromMs) {
        s += b.success;
        f += b.failure;
      }
    }
    return { success: s, failure: f };
  }

  /**
   * Sum all buckets whose start time falls within `[fromMs, toMs)`.
   * Used for the "historical baseline" query where an explicit upper bound is
   * required to exclude the current rate-window from the baseline.
   */
  sumRange(fromMs: number, toMs: number): { success: number; failure: number } {
    let s = 0;
    let f = 0;
    for (let i = 0; i < this.count; i++) {
      const b = this.buf[(this.head + i) % this.capacity]!;
      if (b.ts >= fromMs && b.ts < toMs) {
        s += b.success;
        f += b.failure;
      }
    }
    return { success: s, failure: f };
  }
}

// ── AnomalyDetectorOptions ────────────────────────────────────────────────────

export interface AnomalyDetectorOptions {
  /**
   * Factor by which the current 5-min rate must exceed the 60-min rolling
   * average before the `rate_spike` rule fires.
   * @default 10
   */
  rateSpikeMultiplier?: number;

  /**
   * Width of the "current rate" window in milliseconds.
   * @default 300_000 (5 minutes)
   */
  rateWindowMs?: number;

  /**
   * Width of the "historical baseline" window in milliseconds.
   * The baseline is computed from the window that ends at `rateWindowMs` ago.
   * @default 3_600_000 (60 minutes)
   */
  baselineWindowMs?: number;

  /**
   * UTC hour at which off-hours begins (inclusive, 0–23).
   * @default 22
   */
  offHoursStartHour?: number;

  /**
   * UTC hour at which off-hours ends (exclusive, 0–23).
   * @default 6
   */
  offHoursEndHour?: number;

  /**
   * A tenant is "low-activity" if its successful-mint count in the last 7
   * days is below this threshold.  The off-hours rule only fires for
   * low-activity tenants.
   * @default 10
   */
  lowActivityThreshold?: number;

  /**
   * Minimum proportion of failed mints over the last `failureRateWindowMs`
   * that triggers the `failure_clustering` rule.
   * @default 0.5 (50%)
   */
  failureRateThreshold?: number;

  /**
   * Sliding window for the failure-rate rule in milliseconds.
   * @default 300_000 (5 minutes)
   */
  failureRateWindowMs?: number;

  /**
   * Injectable clock function for unit tests.  Defaults to `Date.now`.
   * @default Date.now
   */
  nowFn?: () => number;

  /**
   * Replica identifier included as the `replica` label on the
   * `euno_minter_anomaly_alerts_total` Prometheus counter (CR-4).
   *
   * Setting this allows operators to compare per-instance anomaly rates in
   * Prometheus dashboards.  Discrepancies between replicas are a signal that
   * traffic is being distributed across replicas and the per-replica detector
   * is only seeing a fraction of the fleet-wide mint rate.
   *
   * Defaults to `''` (unset).  Wire from `MINTER_REPLICA_ID` env var or
   * `os.hostname()` in the minter bootstrap.
   */
  replicaId?: string;
}

// ── AnomalyDetector ───────────────────────────────────────────────────────────

export class AnomalyDetector {
  // Per-tenant ring-buffer stores: one for short-term windows (rate_spike,
  // failure_clustering) and one for the 7-day off_hours lookback.
  private readonly shortStores = new Map<string, BucketStore>();
  private readonly longStores = new Map<string, BucketStore>();

  // Rule parameters (all in milliseconds unless suffixed otherwise).
  private readonly rateSpikeMultiplier: number;
  private readonly rateWindowMs: number;
  private readonly baselineWindowMs: number;
  private readonly offHoursStartHour: number;
  private readonly offHoursEndHour: number;
  private readonly lowActivityThreshold: number;
  private readonly failureRateThreshold: number;
  private readonly failureRateWindowMs: number;
  private readonly nowFn: () => number;
  /** Replica ID label for the anomalyAlertsTotal counter (CR-4). */
  readonly replicaId: string;

  // Short-term bucket resolution and capacity (derived from window parameters).
  private readonly shortBucketMs: number;
  private readonly shortCapacity: number;

  // Long-term bucket store constants (1-hour resolution, 7+ days of retention).
  private static readonly LONG_BUCKET_MS = 60 * 60 * 1000; // 1 hour
  private static readonly LONG_CAPACITY = 170;              // 7 days + 2 spare

  // 7 days in milliseconds — lookback window for the off-hours rule.
  private static readonly SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;

  constructor(opts: AnomalyDetectorOptions = {}) {
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

    // Derive short-term bucket resolution from the smallest configured window.
    // Targeting ~5 buckets per window gives adequate granularity while keeping
    // capacity small.  Minimum resolution is 1 second.
    this.shortBucketMs = Math.max(
      Math.floor(Math.min(this.rateWindowMs, this.failureRateWindowMs) / 5),
      1_000,
    );

    // Capacity must span the full baseline + current window, with a few spare
    // buckets for partial-bucket boundaries.
    this.shortCapacity =
      Math.ceil((this.baselineWindowMs + this.rateWindowMs) / this.shortBucketMs) + 4;
  }

  /**
   * Record a mint attempt and evaluate all anomaly rules.
   *
   * Call this from the mint route handler after every attempt (success or
   * failure), with `tenantId` set to the resolved tenant (or `'unknown'` if
   * auth failed before the tenant was determined).
   *
   * @param tenantId - The tenant identifier (label value for `anomalyAlertsTotal`).
   * @param success  - `true` when the token was successfully issued.
   * @returns        - Alphabetically sorted list of rule names that fired
   *                   (empty array for normal mints).  Useful for testing and
   *                   structured logging.
   */
  recordMint(tenantId: string, success: boolean): string[] {
    const now = this.nowFn();

    const short = this.getOrCreateStore(tenantId, this.shortStores, this.shortBucketMs, this.shortCapacity);
    const long = this.getOrCreateStore(tenantId, this.longStores, AnomalyDetector.LONG_BUCKET_MS, AnomalyDetector.LONG_CAPACITY);

    // Record into both stores before evaluating rules so that the current
    // event is included in the rule calculations.
    short.record(now, success);
    long.record(now, success);

    // Evaluate rules and collect fired rule names.
    const fired: string[] = [];

    if (this.evaluateRateSpike(short, now)) {
      fired.push('rate_spike');
      anomalyAlertsTotal.inc({ tenant: tenantId, rule: 'rate_spike', replica: this.replicaId });
    }

    if (success && this.evaluateOffHours(long, now)) {
      fired.push('off_hours_low_activity');
      anomalyAlertsTotal.inc({ tenant: tenantId, rule: 'off_hours_low_activity', replica: this.replicaId });
    }

    if (this.evaluateFailureClustering(short, now)) {
      fired.push('failure_clustering');
      anomalyAlertsTotal.inc({ tenant: tenantId, rule: 'failure_clustering', replica: this.replicaId });
    }

    // Sort so callers receive a stable, deterministic ordering regardless of
    // rule evaluation order.
    fired.sort();
    return fired;
  }

  // ── Rule evaluators ───────────────────────────────────────────────────────

  /**
   * Rule 1 — Rate spike.
   *
   * Fires when the total mint count in the last `rateWindowMs` (5 min) exceeds
   * `rateSpikeMultiplier` (10) × the per-window average over the preceding
   * `baselineWindowMs` (60 min).
   *
   * Does NOT fire when the tenant has no historical baseline (new tenant or
   * first batch of mints in a fresh baseline window) to avoid false positives
   * on account creation day.
   */
  private evaluateRateSpike(short: BucketStore, now: number): boolean {
    const currentWindowStart = now - this.rateWindowMs;
    const baselineWindowStart = currentWindowStart - this.baselineWindowMs;

    // `sumFrom` (no upper bound) correctly captures the current bucket even
    // when it starts at exactly `currentWindowStart`.
    const currentCounts = short.sumFrom(currentWindowStart);
    const currentCount = currentCounts.success + currentCounts.failure;

    // `sumRange` uses an exclusive upper bound to avoid double-counting buckets
    // that straddle the current-window boundary.
    const historicalCounts = short.sumRange(baselineWindowStart, currentWindowStart);
    const historicalCount = historicalCounts.success + historicalCounts.failure;

    // No baseline yet → no spike to detect.
    if (historicalCount === 0) {
      return false;
    }

    // Average mint count per `rateWindowMs`-sized window over the baseline.
    const numBaselineWindows = this.baselineWindowMs / this.rateWindowMs;
    const historicalAvgPerWindow = historicalCount / numBaselineWindows;

    return currentCount > this.rateSpikeMultiplier * historicalAvgPerWindow;
  }

  /**
   * Rule 2 — Off-hours mint for a low-activity tenant.
   *
   * Fires when ALL of the following are true:
   *   - The current UTC hour falls within [offHoursStartHour, 24) ∪ [0, offHoursEndHour).
   *   - The tenant has fewer than `lowActivityThreshold` successful mints in
   *     the last 7 days (including the current mint, which is already recorded).
   *
   * Only called when the current mint was successful (`success === true`).
   */
  private evaluateOffHours(long: BucketStore, now: number): boolean {
    // Check if the current UTC hour is in the off-hours window.
    const hourUtc = new Date(now).getUTCHours();
    const isOffHours =
      hourUtc >= this.offHoursStartHour || hourUtc < this.offHoursEndHour;

    if (!isOffHours) {
      return false;
    }

    // Count successful mints in the last 7 days (including the current one).
    const sevenDaysAgo = now - AnomalyDetector.SEVEN_DAYS_MS;
    const { success: successfulCount } = long.sumFrom(sevenDaysAgo);

    return successfulCount < this.lowActivityThreshold;
  }

  /**
   * Rule 3 — Failure clustering.
   *
   * Fires when the failure rate within the last `failureRateWindowMs` (5 min)
   * exceeds `failureRateThreshold` (50%), provided there are at least 2
   * events in the window (to avoid a single failed attempt triggering the rule
   * on a fresh tenant).
   */
  private evaluateFailureClustering(short: BucketStore, now: number): boolean {
    const windowStart = now - this.failureRateWindowMs;
    const { success, failure } = short.sumFrom(windowStart);
    const total = success + failure;

    // Require at least 2 events to avoid single-event noise.
    if (total < 2) {
      return false;
    }

    return failure / total > this.failureRateThreshold;
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  private getOrCreateStore(
    tenantId: string,
    storeMap: Map<string, BucketStore>,
    resolutionMs: number,
    capacity: number,
  ): BucketStore {
    let store = storeMap.get(tenantId);
    if (store === undefined) {
      store = new BucketStore(resolutionMs, capacity);
      storeMap.set(tenantId, store);
    }
    return store;
  }
}
