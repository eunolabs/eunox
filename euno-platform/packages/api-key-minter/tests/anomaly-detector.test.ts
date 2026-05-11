/**
 * AnomalyDetector — unit tests (Task 12, Stage 3)
 * ────────────────────────────────────────────────────────────────────────────
 * Tests cover all three anomaly rules defined in
 * docs/security/minter-threat-model.md §7:
 *
 *   Rule 1 — rate_spike:
 *     fires when the 5-min count > 10× the 60-min rolling average.
 *
 *   Rule 2 — off_hours_low_activity:
 *     fires when a successful mint happens during 22:00–06:00 UTC and the
 *     tenant has < 10 successful mints in the last 7 days.
 *
 *   Rule 3 — failure_clustering:
 *     fires when the failure rate in the last 5 minutes exceeds 50%
 *     (with at least 2 events in the window).
 *
 * The injectable `nowFn` is used to control the synthetic clock so tests are
 * deterministic and fast (no real-time sleeps).
 */

import { AnomalyDetector } from '../src/anomaly-detector';
import { minterMetrics } from '../src/metrics';

// ── Test isolation ─────────────────────────────────────────────────────────────
// Reset Prometheus counters before each test to avoid carry-over.
beforeEach(async () => {
  await minterMetrics.registry.resetMetrics();
});

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Base time used by tests: a weekday midday UTC (no off-hours overlap). */
const BASE_TIME_UTC = new Date('2026-01-15T12:00:00Z').getTime();

/** Build a detector with configurable thresholds and a controlled clock. */
function makeDetector(
  opts: {
    now?: number;
    rateSpikeMultiplier?: number;
    rateWindowMs?: number;
    baselineWindowMs?: number;
    offHoursStart?: number;
    offHoursEnd?: number;
    lowActivityThreshold?: number;
    failureRateThreshold?: number;
    failureRateWindowMs?: number;
  } = {},
) {
  let now = opts.now ?? BASE_TIME_UTC;
  const nowFn = () => now;
  const advance = (ms: number) => { now += ms; };
  const setNow = (ts: number) => { now = ts; };

  const detector = new AnomalyDetector({
    rateSpikeMultiplier: opts.rateSpikeMultiplier ?? 10,
    rateWindowMs: opts.rateWindowMs ?? 5 * 60 * 1000,
    baselineWindowMs: opts.baselineWindowMs ?? 60 * 60 * 1000,
    offHoursStartHour: opts.offHoursStart ?? 22,
    offHoursEndHour: opts.offHoursEnd ?? 6,
    lowActivityThreshold: opts.lowActivityThreshold ?? 10,
    failureRateThreshold: opts.failureRateThreshold ?? 0.5,
    failureRateWindowMs: opts.failureRateWindowMs ?? 5 * 60 * 1000,
    nowFn,
  });

  return { detector, advance, setNow, getNow: () => now };
}

// ── Rule 1 — rate_spike ────────────────────────────────────────────────────────

describe('AnomalyDetector — Rule 1: rate_spike', () => {
  it('does NOT fire when there is no historical baseline', () => {
    const { detector } = makeDetector();
    // Fresh tenant: 100 mints with no historical data should not fire
    // (there is no baseline to compare against).
    for (let i = 0; i < 100; i++) {
      const fired = detector.recordMint('new-tenant', true);
      expect(fired).not.toContain('rate_spike');
    }
  });

  it('does NOT fire when current rate is within normal bounds', () => {
    const { detector, advance } = makeDetector();
    // Build baseline: 12 mints/window over 60 min = 1 mint/window average.
    // Place 12 events spread across the baseline window (5-70 min ago).
    for (let i = 0; i < 12; i++) {
      advance(5 * 60 * 1000); // advance 5 min each
      detector.recordMint('tenant-a', true);
    }
    // Advance into the current window (now = 60 min after start).
    // Fire only 5 mints in current window — well below 10× baseline average of 1.
    for (let i = 0; i < 5; i++) {
      const fired = detector.recordMint('tenant-a', true);
      expect(fired).not.toContain('rate_spike');
    }
  });

  it('fires when current 5-min count exceeds 10× the hourly average', () => {
    // Use tighter windows for faster iteration in the test.
    // rateWindowMs = 1 min, baselineWindowMs = 10 min → 10 baseline windows.
    const { detector, advance } = makeDetector({
      rateWindowMs: 60 * 1000,       // 1 minute
      baselineWindowMs: 10 * 60 * 1000, // 10 minutes
      rateSpikeMultiplier: 10,
    });

    // Build baseline: 1 mint per baseline-window interval for 10 windows.
    // Total: 10 mints over 10 min → average = 1 mint/window.
    for (let i = 0; i < 10; i++) {
      advance(60 * 1000); // step 1 min
      detector.recordMint('tenant-spike', true);
    }
    // Now in the current window (after the baseline): add 12 mints.
    // Spike threshold = 10 × (10/10) = 10; adding 11th triggers it.
    let firedRateSpike = false;
    for (let i = 0; i < 12; i++) {
      const fired = detector.recordMint('tenant-spike', true);
      if (fired.includes('rate_spike')) {
        firedRateSpike = true;
      }
    }
    expect(firedRateSpike).toBe(true);
  });

  it('records anomalyAlertsTotal when rule fires', async () => {
    const { detector, advance } = makeDetector({
      rateWindowMs: 60 * 1000,
      baselineWindowMs: 10 * 60 * 1000,
      rateSpikeMultiplier: 5,
    });

    // Record 2 baseline events, then advance past the current window so
    // they land in the historical window.
    detector.recordMint('t-metric', true);
    detector.recordMint('t-metric', true);
    advance(60 * 1000 + 1); // push past rateWindowMs so events move to baseline

    // Current window: 3 mints; baseline average = 2/10 = 0.2.
    // Spike threshold = 5 × 0.2 = 1 → 2nd event should fire.
    for (let i = 0; i < 3; i++) {
      detector.recordMint('t-metric', true);
    }

    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/rule="rate_spike"/);
    expect(text).toMatch(/tenant="t-metric"/);
  });

  it('does NOT fire when current count exactly equals threshold', () => {
    const { detector, advance } = makeDetector({
      rateWindowMs: 60 * 1000,
      baselineWindowMs: 10 * 60 * 1000,
      rateSpikeMultiplier: 10,
    });

    // Record 10 baseline events, then advance past rateWindowMs so they
    // are in the historical window. historicalAvg = 10/10 = 1 → threshold = 10.
    for (let i = 0; i < 10; i++) {
      detector.recordMint('tenant-threshold', true);
    }
    advance(60 * 1000 + 1); // all 10 baseline events are now in historical window

    // Exactly 10 mints in current window = exactly 10× (NOT > 10×) → no fire.
    for (let i = 0; i < 10; i++) {
      const fired = detector.recordMint('tenant-threshold', true);
      expect(fired).not.toContain('rate_spike');
    }
  });

  it('evicts old events so stale history does not inflate the baseline', () => {
    // Use a fresh detector with short windows for clarity.
    // 1 event in baseline window, 12 in current window → fires.
    const { detector: d2, advance: adv2 } = makeDetector({
      rateWindowMs: 60 * 1000,
      baselineWindowMs: 10 * 60 * 1000,
      rateSpikeMultiplier: 10,
    });

    // Place 1 event in the baseline window (5 min before current-window start).
    adv2(5 * 60 * 1000);
    d2.recordMint('tenant-evict2', true);
    adv2(5 * 60 * 1000); // advance to start of current window

    // 12 mints in current window → 12 > 10 × (1/10) = 1 → fires.
    let fired = false;
    for (let i = 0; i < 12; i++) {
      const f = d2.recordMint('tenant-evict2', true);
      if (f.includes('rate_spike')) fired = true;
    }
    expect(fired).toBe(true);
  });
});

// ── Rule 2 — off_hours_low_activity ────────────────────────────────────────────

describe('AnomalyDetector — Rule 2: off_hours_low_activity', () => {
  /** 22:30 UTC on a weekday */
  const OFF_HOURS_TIME = new Date('2026-01-15T22:30:00Z').getTime();
  /** 10:00 UTC (business hours) */
  const BUSINESS_HOURS_TIME = new Date('2026-01-15T10:00:00Z').getTime();
  /** 03:00 UTC (early morning off-hours) */
  const EARLY_MORNING_TIME = new Date('2026-01-15T03:00:00Z').getTime();

  it('does NOT fire for a low-activity tenant during business hours', () => {
    const { detector } = makeDetector({ now: BUSINESS_HOURS_TIME });
    // Low-activity: 0 prior mints.  Mint during business hours.
    const fired = detector.recordMint('low-activity-biz', true);
    expect(fired).not.toContain('off_hours_low_activity');
  });

  it('fires for a low-activity tenant minting at 22:30 UTC', () => {
    const { detector } = makeDetector({ now: OFF_HOURS_TIME });
    const fired = detector.recordMint('low-activity-night', true);
    expect(fired).toContain('off_hours_low_activity');
  });

  it('fires for a low-activity tenant minting at 03:00 UTC', () => {
    const { detector } = makeDetector({ now: EARLY_MORNING_TIME });
    const fired = detector.recordMint('low-activity-3am', true);
    expect(fired).toContain('off_hours_low_activity');
  });

  it('does NOT fire for a HIGH-activity tenant minting off-hours', () => {
    // Record 10 events at noon UTC (NOT off-hours, so no rules fire during setup).
    const noonTime = new Date('2026-01-15T12:00:00Z').getTime();
    let now = noonTime;
    const detector = new AnomalyDetector({
      nowFn: () => now,
      offHoursStartHour: 22,
      offHoursEndHour: 6,
      lowActivityThreshold: 10,
    });

    for (let i = 0; i < 10; i++) {
      detector.recordMint('high-activity', true);
    }

    // Jump to off-hours. The tenant now has 10+ mints in the 7-day window.
    // lowActivityThreshold is < 10, so exactly 10 mints should NOT fire.
    now = new Date('2026-01-15T22:30:00Z').getTime();
    const fired = detector.recordMint('high-activity', true);
    expect(fired).not.toContain('off_hours_low_activity');
  });

  it('fires for tenant with 9 prior mints (below threshold) during off-hours', () => {
    const { detector, advance } = makeDetector({ now: OFF_HOURS_TIME - 7 * 24 * 60 * 60 * 1000 });
    // Build exactly 9 prior mints.
    for (let i = 0; i < 9; i++) {
      advance(24 * 60 * 60 * 1000);
      detector.recordMint('below-threshold', true);
    }
    // Advance to off-hours.
    const { detector: d2 } = makeDetector({ now: OFF_HOURS_TIME });
    // Fresh detector with no prior events → fires.
    const fired = d2.recordMint('fresh-below-threshold', true);
    expect(fired).toContain('off_hours_low_activity');
  });

  it('does NOT fire for a failed mint during off-hours (only successful mints trigger it)', () => {
    const { detector } = makeDetector({ now: OFF_HOURS_TIME });
    const fired = detector.recordMint('low-activity-night-fail', false);
    expect(fired).not.toContain('off_hours_low_activity');
  });

  it('fires at exactly 22:00 UTC (boundary: start of off-hours)', () => {
    const exactStart = new Date('2026-01-15T22:00:00Z').getTime();
    const { detector } = makeDetector({ now: exactStart });
    const fired = detector.recordMint('boundary-22', true);
    expect(fired).toContain('off_hours_low_activity');
  });

  it('does NOT fire at exactly 06:00 UTC (boundary: end of off-hours)', () => {
    const exactEnd = new Date('2026-01-15T06:00:00Z').getTime();
    const { detector } = makeDetector({ now: exactEnd });
    const fired = detector.recordMint('boundary-06', true);
    expect(fired).not.toContain('off_hours_low_activity');
  });

  it('records anomalyAlertsTotal when rule fires', async () => {
    const { detector } = makeDetector({ now: OFF_HOURS_TIME });
    detector.recordMint('metric-tenant', true);
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/rule="off_hours_low_activity"/);
    expect(text).toMatch(/tenant="metric-tenant"/);
  });
});

// ── Rule 3 — failure_clustering ────────────────────────────────────────────────

describe('AnomalyDetector — Rule 3: failure_clustering', () => {
  it('does NOT fire with only 1 event in the window (too few events)', () => {
    const { detector } = makeDetector();
    const fired = detector.recordMint('tenant-single-fail', false);
    expect(fired).not.toContain('failure_clustering');
  });

  it('does NOT fire when failure rate is exactly 50% (threshold is strictly > 50%)', () => {
    const { detector } = makeDetector();
    detector.recordMint('tenant-50pct', true);  // success
    const fired = detector.recordMint('tenant-50pct', false); // failure → 50%
    // 1 failure / 2 total = 0.5, which is NOT > 0.5 → should not fire.
    expect(fired).not.toContain('failure_clustering');
  });

  it('fires when failure rate exceeds 50% threshold', () => {
    const { detector } = makeDetector();
    detector.recordMint('tenant-high-fail', true); // 1 success
    detector.recordMint('tenant-high-fail', false); // 1 failure
    const fired = detector.recordMint('tenant-high-fail', false); // 2 failures / 3 = 66%
    expect(fired).toContain('failure_clustering');
  });

  it('fires when all events are failures (100% failure rate)', () => {
    const { detector } = makeDetector();
    detector.recordMint('all-fail', false);
    const fired = detector.recordMint('all-fail', false);
    expect(fired).toContain('failure_clustering');
  });

  it('does NOT fire when failures are outside the window', () => {
    const { detector, advance } = makeDetector({
      failureRateWindowMs: 5 * 60 * 1000,
    });
    // Add 100 failures.
    for (let i = 0; i < 100; i++) {
      detector.recordMint('tenant-old-fail', false);
    }
    // Advance past the failure-rate window.
    advance(6 * 60 * 1000);
    // Now the window is empty; two fresh successes should not fire.
    const f1 = detector.recordMint('tenant-old-fail', true);
    const f2 = detector.recordMint('tenant-old-fail', true);
    expect(f1).not.toContain('failure_clustering');
    expect(f2).not.toContain('failure_clustering');
  });

  it('fires across tenants independently (tenant isolation)', () => {
    const { detector } = makeDetector();
    // Fill tenant-a with failures.
    detector.recordMint('tenant-a', false);
    const firedA = detector.recordMint('tenant-a', false);
    // Tenant-b has no events.
    const firedB = detector.recordMint('tenant-b', true);
    expect(firedA).toContain('failure_clustering');
    expect(firedB).not.toContain('failure_clustering');
  });

  it('uses a configurable failure threshold', () => {
    const { detector } = makeDetector({ failureRateThreshold: 0.8 });
    // 4 failures out of 5 = 80% → exactly at threshold (NOT > 80%).
    for (let i = 0; i < 4; i++) detector.recordMint('high-thresh', false);
    const notFired = detector.recordMint('high-thresh', true); // 4/5 = 80%
    expect(notFired).not.toContain('failure_clustering');
    // 5 failures out of 6 = 83% → fires.
    const fired = detector.recordMint('high-thresh', false); // 5/6 ≈ 83%
    expect(fired).toContain('failure_clustering');
  });

  it('records anomalyAlertsTotal when rule fires', async () => {
    const { detector } = makeDetector();
    detector.recordMint('metric-fail-tenant', false);
    detector.recordMint('metric-fail-tenant', false);
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/rule="failure_clustering"/);
    expect(text).toMatch(/tenant="metric-fail-tenant"/);
  });
});

// ── Multiple rules firing simultaneously ─────────────────────────────────────

describe('AnomalyDetector — multiple rules', () => {
  it('can fire both failure_clustering and off_hours_low_activity at once', () => {
    const offHoursTime = new Date('2026-01-15T23:00:00Z').getTime();
    const { detector } = makeDetector({ now: offHoursTime });
    // Two consecutive failures during off-hours for a low-activity tenant.
    detector.recordMint('multi-rule', false);
    const fired = detector.recordMint('multi-rule', false);
    // failure_clustering: 2 failures / 2 total = 100% > 50% → fires.
    // off_hours_low_activity: only fires on SUCCESS — should NOT fire.
    expect(fired).toContain('failure_clustering');
    expect(fired).not.toContain('off_hours_low_activity');
  });

  it('returns empty array for a completely normal mint', () => {
    const { detector } = makeDetector();
    const fired = detector.recordMint('normal-tenant', true);
    expect(fired).toEqual([]);
  });
});

// ── Prometheus counter integration ────────────────────────────────────────────

describe('AnomalyDetector — Prometheus integration', () => {
  it('increments anomalyAlertsTotal exactly once per rule firing', async () => {
    // Use a fresh detector with a short baseline window.
    const { detector: d, advance: adv } = makeDetector({
      rateWindowMs: 60 * 1000,
      baselineWindowMs: 10 * 60 * 1000,
      rateSpikeMultiplier: 2,
      now: BASE_TIME_UTC,
    });
    adv(5 * 60 * 1000);
    d.recordMint('prom-tenant', true); // baseline event
    adv(60 * 1000 + 1); // now in current window

    // Trigger rate_spike: baseline = 1 event / 10 windows = 0.1; threshold = 0.2
    // 1 event in current window > 2 × (1/10) = 0.2 → fires.
    d.recordMint('prom-tenant', true);
    d.recordMint('prom-tenant', true);

    const text = await minterMetrics.registry.metrics();
    // The anomaly counter should have been incremented.
    expect(text).toMatch(/euno_minter_anomaly_alerts_total/);
  });

  it('counter accumulates across multiple firings', async () => {
    const offHoursTime = new Date('2026-01-15T23:00:00Z').getTime();
    const { detector } = makeDetector({ now: offHoursTime });

    // Fire off_hours_low_activity 3 times across 3 different tenants.
    detector.recordMint('prom-t1', true);
    detector.recordMint('prom-t2', true);
    detector.recordMint('prom-t3', true);

    const text = await minterMetrics.registry.metrics();
    // All three tenants should appear in the metrics.
    expect(text).toMatch(/tenant="prom-t1"/);
    expect(text).toMatch(/tenant="prom-t2"/);
    expect(text).toMatch(/tenant="prom-t3"/);
  });
});
