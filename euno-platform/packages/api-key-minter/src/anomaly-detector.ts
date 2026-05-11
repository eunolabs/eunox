/**
 * AnomalyDetector — in-process mint anomaly detection
 * ────────────────────────────────────────────────────────────────────────────
 * Implements the three in-process anomaly rules defined in
 * docs/security/minter-threat-model.md §7 (Monitoring and Alerting).
 * When a rule fires, `euno_minter_anomaly_alerts_total{tenant, rule}` is
 * incremented.  The Prometheus alerting rules in
 * `prometheus/minter-alert-rules.yaml` provide the production alert routing;
 * this detector provides:
 *
 *   1. Sub-minute anomaly detection (faster than Prometheus scrape intervals).
 *   2. Defence in depth — fires even when the Prometheus server is unreachable.
 *   3. A counter that enables per-tenant anomaly rate dashboards without
 *      complex PromQL.
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
 * The detector retains at most 7 days of events per tenant and purges expired
 * entries on every `recordMint` call.  At 10,000 mints/second across 100
 * tenants, the maximum in-memory footprint is ≈ 60 MB (10k×100×24×7 events
 * of 40 bytes each), well within typical minter pod limits.  In practice,
 * tenants with normal activity hold far fewer events.
 */

import { anomalyAlertsTotal } from './metrics';

// ── Types ─────────────────────────────────────────────────────────────────────

interface MintEvent {
  /** Unix millisecond timestamp of the mint attempt. */
  ts: number;
  /** `true` when the token was successfully issued, `false` for any failure. */
  success: boolean;
}

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
   * Maximum retention period for per-tenant mint events in milliseconds.
   * Events older than this are discarded.  Must be ≥ max(baselineWindowMs,
   * 7 days) to support the low-activity check.
   * @default 604_800_000 (7 days)
   */
  maxRetentionMs?: number;

  /**
   * Injectable clock function for unit tests.  Defaults to `Date.now`.
   * @default Date.now
   */
  nowFn?: () => number;
}

// ── AnomalyDetector ───────────────────────────────────────────────────────────

export class AnomalyDetector {
  // Per-tenant sliding windows of mint events.
  private readonly events = new Map<string, MintEvent[]>();

  // Rule parameters (all in milliseconds unless suffixed otherwise).
  private readonly rateSpikeMultiplier: number;
  private readonly rateWindowMs: number;
  private readonly baselineWindowMs: number;
  private readonly offHoursStartHour: number;
  private readonly offHoursEndHour: number;
  private readonly lowActivityThreshold: number;
  private readonly failureRateThreshold: number;
  private readonly failureRateWindowMs: number;
  private readonly maxRetentionMs: number;
  private readonly nowFn: () => number;

  // 7 days in milliseconds — minimum retention for the low-activity check.
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
    // maxRetentionMs must be at least 7 days to support the low-activity check.
    this.maxRetentionMs = Math.max(
      opts.maxRetentionMs ?? AnomalyDetector.SEVEN_DAYS_MS,
      AnomalyDetector.SEVEN_DAYS_MS,
    );
    this.nowFn = opts.nowFn ?? (() => Date.now());
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
   * @returns        - Sorted list of rule names that fired (empty for normal mints).
   *                   Useful for testing and structured logging.
   */
  recordMint(tenantId: string, success: boolean): string[] {
    const now = this.nowFn();
    const cutoff = now - this.maxRetentionMs;

    // Retrieve or create the tenant's event list.
    let list = this.events.get(tenantId);
    if (list === undefined) {
      list = [];
      this.events.set(tenantId, list);
    }

    // Evict events older than maxRetentionMs.
    // The list is append-only and therefore sorted by ts ascending; we can
    // binary-search for the cutoff or just use findIndex for simplicity at
    // the expected cardinalities (≤ few thousand active events per tenant).
    const firstValid = list.findIndex(e => e.ts >= cutoff);
    if (firstValid > 0) {
      list.splice(0, firstValid);
    } else if (firstValid === -1) {
      // All events are expired.
      list.length = 0;
    }

    // Append the current event.
    list.push({ ts: now, success });

    // Evaluate rules and collect fired rule names.
    const fired: string[] = [];

    if (this.evaluateRateSpike(list, now)) {
      fired.push('rate_spike');
      anomalyAlertsTotal.inc({ tenant: tenantId, rule: 'rate_spike' });
    }

    if (success && this.evaluateOffHours(list, now)) {
      fired.push('off_hours_low_activity');
      anomalyAlertsTotal.inc({ tenant: tenantId, rule: 'off_hours_low_activity' });
    }

    if (this.evaluateFailureClustering(list, now)) {
      fired.push('failure_clustering');
      anomalyAlertsTotal.inc({ tenant: tenantId, rule: 'failure_clustering' });
    }

    return fired;
  }

  // ── Rule evaluators ───────────────────────────────────────────────────────

  /**
   * Rule 1 — Rate spike.
   *
   * Fires when the number of mints in the last `rateWindowMs` (5 min) exceeds
   * `rateSpikeMultiplier` (10) × the per-window average over the preceding
   * `baselineWindowMs` (60 min).
   *
   * Does NOT fire when the tenant has no historical baseline (new tenant or
   * first batch of mints in a fresh baseline window) to avoid false positives
   * on account creation day.
   */
  private evaluateRateSpike(list: MintEvent[], now: number): boolean {
    const currentWindowStart = now - this.rateWindowMs;
    const baselineWindowStart = currentWindowStart - this.baselineWindowMs;

    // Count events in the current window (last 5 min, excluding the baseline).
    let currentCount = 0;
    // Count events in the historical window (5–65 min ago).
    let historicalCount = 0;

    for (const e of list) {
      if (e.ts >= currentWindowStart) {
        currentCount++;
      } else if (e.ts >= baselineWindowStart) {
        historicalCount++;
      }
    }

    // No baseline yet → no spike to detect.
    if (historicalCount === 0) {
      return false;
    }

    // Average 5-min count over the baseline window
    // = historicalCount / (baselineWindowMs / rateWindowMs)
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
  private evaluateOffHours(list: MintEvent[], now: number): boolean {
    // Check if the current UTC hour is in the off-hours window.
    const hourUtc = new Date(now).getUTCHours();
    const isOffHours =
      hourUtc >= this.offHoursStartHour || hourUtc < this.offHoursEndHour;

    if (!isOffHours) {
      return false;
    }

    // Count successful mints in the last 7 days.
    const sevenDaysAgo = now - AnomalyDetector.SEVEN_DAYS_MS;
    let successfulCount = 0;
    for (const e of list) {
      if (e.ts >= sevenDaysAgo && e.success) {
        successfulCount++;
      }
    }

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
  private evaluateFailureClustering(list: MintEvent[], now: number): boolean {
    const windowStart = now - this.failureRateWindowMs;
    let total = 0;
    let failures = 0;

    for (const e of list) {
      if (e.ts >= windowStart) {
        total++;
        if (!e.success) {
          failures++;
        }
      }
    }

    // Require at least 2 events to avoid single-event noise.
    if (total < 2) {
      return false;
    }

    return failures / total > this.failureRateThreshold;
  }
}
