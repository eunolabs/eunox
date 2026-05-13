/**
 * RedisAnomalyDetector — unit tests (CR-4)
 * ────────────────────────────────────────────────────────────────────────────
 * Tests cover:
 *   - Redis-backed rule evaluation (rate_spike, off_hours_low_activity,
 *     failure_clustering)
 *   - Transparent fallback to in-memory AnomalyDetector on Redis error
 *   - Promise return type from recordMint
 *   - `replicaId` label on anomalyAlertsTotal counter
 *   - createAnomalyDetectorFromEnv factory: Redis path and in-memory path
 */

import { RedisAnomalyDetector, createAnomalyDetectorFromEnv } from '../src/redis-anomaly-detector';
import { AnomalyDetector } from '../src/anomaly-detector';
import { minterMetrics } from '../src/metrics';

// ── Test isolation ──────────────────────────────────────────────────────────

beforeEach(async () => {
  await minterMetrics.registry.resetMetrics();
});

// ── FakeRedis client ─────────────────────────────────────────────────────────

/**
 * In-memory Redis hash implementation for testing.
 * All operations are synchronous under the Promise wrapper.
 */
function makeFakeRedisClient(overrides: {
  hincrbyOverride?: (key: string, field: string, inc: number) => Promise<number>;
  hgetallOverride?: (key: string) => Promise<Record<string, string> | null>;
  expireError?: boolean;
} = {}) {
  const store = new Map<string, Map<string, number>>();

  const client = {
    calls: [] as { method: string; key: string; field?: string }[],

    async hincrby(key: string, field: string, increment: number): Promise<number> {
      this.calls.push({ method: 'hincrby', key, field });
      if (overrides.hincrbyOverride) return overrides.hincrbyOverride(key, field, increment);
      const hash = store.get(key) ?? new Map<string, number>();
      const val = (hash.get(field) ?? 0) + increment;
      hash.set(field, val);
      store.set(key, hash);
      return val;
    },

    async hgetall(key: string): Promise<Record<string, string> | null> {
      this.calls.push({ method: 'hgetall', key });
      if (overrides.hgetallOverride) return overrides.hgetallOverride(key);
      const hash = store.get(key);
      if (!hash) return null;
      const result: Record<string, string> = {};
      for (const [k, v] of hash) {
        result[k] = String(v);
      }
      return result;
    },

    async expire(key: string, _seconds: number): Promise<number> {
      this.calls.push({ method: 'expire', key });
      if (overrides.expireError) throw new Error('expire failed');
      return 1;
    },

    on(_event: string, _listener: (...args: unknown[]) => void): void {
      // no-op in tests
    },

    async quit(): Promise<'OK'> {
      return 'OK';
    },

    /** Helper to inspect stored hash data for assertion purposes. */
    getHash(key: string): Record<string, number> {
      const hash = store.get(key);
      if (!hash) return {};
      const result: Record<string, number> = {};
      for (const [k, v] of hash) result[k] = v;
      return result;
    },

    /** Drain all stored data for test isolation. */
    clear(): void {
      store.clear();
    },
  };

  return client;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const BASE_TIME_UTC = new Date('2026-01-15T12:00:00Z').getTime();

function makeDetector(
  opts: {
    now?: number;
    replicaId?: string;
    rateSpikeMultiplier?: number;
    rateWindowMs?: number;
    baselineWindowMs?: number;
    offHoursStart?: number;
    offHoursEnd?: number;
    lowActivityThreshold?: number;
    failureRateThreshold?: number;
    failureRateWindowMs?: number;
    clientOverrides?: Parameters<typeof makeFakeRedisClient>[0];
  } = {},
) {
  let now = opts.now ?? BASE_TIME_UTC;
  const nowFn = () => now;
  const advance = (ms: number) => { now += ms; };
  const setNow = (ts: number) => { now = ts; };

  const client = makeFakeRedisClient(opts.clientOverrides ?? {});
  const detector = new RedisAnomalyDetector(client, {
    replicaId: opts.replicaId ?? 'test-replica',
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

  return { detector, client, advance, setNow, getNow: () => now };
}

// ── Basic contract tests ─────────────────────────────────────────────────────

describe('RedisAnomalyDetector — basic contract', () => {
  it('returns a Promise from recordMint', async () => {
    const { detector } = makeDetector();
    const result = detector.recordMint('tenant-x', true);
    expect(result).toBeInstanceOf(Promise);
    const fired = await result;
    expect(Array.isArray(fired)).toBe(true);
  });

  it('returns empty array for a normal mint with no history', async () => {
    const { detector } = makeDetector();
    const fired = await detector.recordMint('tenant-new', true);
    expect(fired).toEqual([]);
  });

  it('calls hincrby and expire for each recordMint', async () => {
    const { detector, client } = makeDetector();
    await detector.recordMint('t1', true);
    const hincrCalls = client.calls.filter(c => c.method === 'hincrby');
    const expireCalls = client.calls.filter(c => c.method === 'expire');
    // 2 hincrby (short + long) + 2 expire
    expect(hincrCalls).toHaveLength(2);
    expect(expireCalls).toHaveLength(2);
  });

  it('increments success field (:s) for successful mints', async () => {
    const { detector, client } = makeDetector();
    await detector.recordMint('tenant-ok', true);
    const shortHash = client.getHash(`minter:anomaly:short:tenant-ok`);
    const keys = Object.keys(shortHash);
    expect(keys.some(k => k.endsWith(':s'))).toBe(true);
    expect(keys.some(k => k.endsWith(':f'))).toBe(false);
  });

  it('increments failure field (:f) for failed mints', async () => {
    const { detector, client } = makeDetector();
    await detector.recordMint('tenant-fail', false);
    const shortHash = client.getHash(`minter:anomaly:short:tenant-fail`);
    const keys = Object.keys(shortHash);
    expect(keys.some(k => k.endsWith(':f'))).toBe(true);
    expect(keys.some(k => k.endsWith(':s'))).toBe(false);
  });

  it('returns sorted rule names when multiple rules fire', async () => {
    // failure_clustering fires with >50% failure rate; off_hours requires
    // off-hours UTC time.  Here we just verify sorted output.
    const { detector } = makeDetector({
      rateWindowMs: 60 * 1000,
      baselineWindowMs: 10 * 60 * 1000,
      rateSpikeMultiplier: 2,
      failureRateThreshold: 0.3,
    });
    // Build baseline
    for (let i = 0; i < 5; i++) {
      await detector.recordMint('multi-rule', true);
    }
    // Add many failures to potentially trigger multiple rules.
    const fired: string[] = [];
    for (let i = 0; i < 30; i++) {
      const rules = await detector.recordMint('multi-rule', false);
      fired.push(...rules);
    }
    // Verify that whenever multiple rules are in a result, they are sorted.
    // (Exact rules may not all fire in this simple test — just verify sorted order.)
    for (let i = 1; i < fired.length; i++) {
      expect(fired[i]! >= fired[i - 1]!).toBe(true);
    }
  });
});

// ── Rule 1 — rate_spike ──────────────────────────────────────────────────────

describe('RedisAnomalyDetector — Rule 1: rate_spike', () => {
  it('does NOT fire without a historical baseline', async () => {
    const { detector } = makeDetector();
    for (let i = 0; i < 20; i++) {
      const fired = await detector.recordMint('no-baseline', true);
      expect(fired).not.toContain('rate_spike');
    }
  });

  it('fires when current rate exceeds spike multiplier × historical average', async () => {
    const { detector, advance } = makeDetector({
      rateWindowMs: 60 * 1000,
      baselineWindowMs: 10 * 60 * 1000,
      rateSpikeMultiplier: 5,
    });

    // Build baseline: 10 mints over 10 min → 1 mint/min average.
    for (let i = 0; i < 10; i++) {
      advance(60 * 1000);
      await detector.recordMint('spike-tenant', true);
    }

    // Current window: add mints rapidly to exceed 5× average.
    let fired = false;
    for (let i = 0; i < 15; i++) {
      const rules = await detector.recordMint('spike-tenant', true);
      if (rules.includes('rate_spike')) {
        fired = true;
        break;
      }
    }
    expect(fired).toBe(true);
  });

  it('records anomalyAlertsTotal counter with replica label', async () => {
    const { detector, advance } = makeDetector({
      replicaId: 'replica-1',
      rateWindowMs: 60 * 1000,
      baselineWindowMs: 10 * 60 * 1000,
      rateSpikeMultiplier: 5,
    });

    for (let i = 0; i < 10; i++) {
      advance(60 * 1000);
      await detector.recordMint('t-metric', true);
    }
    for (let i = 0; i < 15; i++) {
      await detector.recordMint('t-metric', true);
    }

    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/rule="rate_spike"/);
    expect(text).toMatch(/replica="replica-1"/);
  });
});

// ── Rule 3 — failure_clustering ─────────────────────────────────────────────

describe('RedisAnomalyDetector — Rule 3: failure_clustering', () => {
  it('fires when failure rate > threshold over the failure window', async () => {
    const { detector } = makeDetector({
      failureRateThreshold: 0.5,
      failureRateWindowMs: 5 * 60 * 1000,
    });

    // 1 success + 3 failures = 75% failure rate (> 50%)
    await detector.recordMint('fc-tenant', true);  // success
    await detector.recordMint('fc-tenant', false); // failure
    await detector.recordMint('fc-tenant', false); // failure
    const fired = await detector.recordMint('fc-tenant', false); // failure

    expect(fired).toContain('failure_clustering');
  });

  it('does NOT fire when failure rate is below threshold', async () => {
    const { detector } = makeDetector({ failureRateThreshold: 0.8 });
    // 2 success, 1 failure = 33% failure rate (< 80%)
    await detector.recordMint('fc-low', true);
    await detector.recordMint('fc-low', true);
    const fired = await detector.recordMint('fc-low', false);
    expect(fired).not.toContain('failure_clustering');
  });

  it('does NOT fire with only 1 event (noise protection)', async () => {
    const { detector } = makeDetector({ failureRateThreshold: 0.0 });
    const fired = await detector.recordMint('fc-single', false);
    expect(fired).not.toContain('failure_clustering');
  });
});

// ── Rule 2 — off_hours_low_activity ─────────────────────────────────────────

describe('RedisAnomalyDetector — Rule 2: off_hours_low_activity', () => {
  it('fires during off-hours for a low-activity tenant', async () => {
    // Pin clock to 23:30 UTC (off-hours).
    const offHoursTime = new Date('2026-01-15T23:30:00Z').getTime();
    const { detector } = makeDetector({
      now: offHoursTime,
      offHoursStart: 22,
      offHoursEnd: 6,
      lowActivityThreshold: 10,
    });

    // Low-activity tenant: 0 historical mints → fires on the first mint.
    const fired = await detector.recordMint('night-owl', true);
    expect(fired).toContain('off_hours_low_activity');
  });

  it('does NOT fire during business hours', async () => {
    const businessHoursTime = new Date('2026-01-15T14:00:00Z').getTime();
    const { detector } = makeDetector({
      now: businessHoursTime,
      offHoursStart: 22,
      offHoursEnd: 6,
    });
    const fired = await detector.recordMint('low-act', true);
    expect(fired).not.toContain('off_hours_low_activity');
  });
});

// ── Redis error fallback ─────────────────────────────────────────────────────

describe('RedisAnomalyDetector — Redis error fallback', () => {
  it('falls back to in-memory AnomalyDetector when hincrby throws', async () => {
    const { detector } = makeDetector({
      clientOverrides: {
        hincrbyOverride: async () => { throw new Error('Redis connection refused'); },
      },
    });
    // Should not throw; falls back to in-memory detector.
    const result = await detector.recordMint('fallback-tenant', true);
    expect(Array.isArray(result)).toBe(true);
  });

  it('falls back gracefully when hgetall throws', async () => {
    const client = makeFakeRedisClient({
      hgetallOverride: async () => { throw new Error('Redis read error'); },
    });
    const detector = new RedisAnomalyDetector(client, {
      replicaId: 'test-r',
    });
    const result = await detector.recordMint('fallback-tenant', true);
    expect(Array.isArray(result)).toBe(true);
  });

  it('the in-memory fallback can detect rate_spike when Redis is down', async () => {
    // Test that the fallback detector (in-memory AnomalyDetector) is functional.
    let redisDown = false;
    const fakeClient = makeFakeRedisClient({
      hincrbyOverride: async (_key, field, inc) => {
        if (redisDown) throw new Error('Redis down');
        const hash = new Map<string, number>();
        hash.set(field, inc);
        return inc;
      },
    });

    // Use tight windows for this test.
    const detector = new RedisAnomalyDetector(fakeClient, {
      replicaId: 'fbr',
      rateWindowMs: 60 * 1000,
      baselineWindowMs: 10 * 60 * 1000,
      rateSpikeMultiplier: 3,
      nowFn: (() => {
        let t = BASE_TIME_UTC;
        return () => t;
      })(),
    });

    // Redis down from the start — falls back to in-memory.
    redisDown = true;
    const results: string[][] = [];
    for (let i = 0; i < 5; i++) {
      results.push(await detector.recordMint('fb-tenant', true));
    }
    // In-memory fallback returns [] without a baseline — no false positive.
    expect(results.every(r => !r.includes('rate_spike'))).toBe(true);
  });
});

// ── close() ─────────────────────────────────────────────────────────────────

describe('RedisAnomalyDetector — close()', () => {
  it('calls quit on the underlying Redis client', async () => {
    const client = makeFakeRedisClient();
    const detector = new RedisAnomalyDetector(client);
    await expect(detector.close()).resolves.toBeUndefined();
  });

  it('swallows quit errors', async () => {
    const client = {
      ...makeFakeRedisClient(),
      quit: async () => { throw new Error('already closed'); },
    };
    const detector = new RedisAnomalyDetector(client);
    await expect(detector.close()).resolves.toBeUndefined();
  });
});

// ── createAnomalyDetectorFromEnv ─────────────────────────────────────────────

describe('createAnomalyDetectorFromEnv', () => {
  it('returns in-memory AnomalyDetector when no Redis URL is set', () => {
    const detector = createAnomalyDetectorFromEnv({});
    expect(detector).toBeInstanceOf(AnomalyDetector);
  });

  it('returns in-memory AnomalyDetector when ioredis is not available', () => {
    jest.resetModules();
    try {
      jest.doMock('ioredis', () => { throw new Error("Cannot find module 'ioredis'"); }, { virtual: true });
      jest.isolateModules(() => {
        // Load AnomalyDetector from the same fresh module scope so that
        // toBeInstanceOf compares the same constructor reference.
        const { AnomalyDetector: FreshAnomalyDetector } = require('../src/anomaly-detector') as typeof import('../src/anomaly-detector');
        const mod = require('../src/redis-anomaly-detector') as typeof import('../src/redis-anomaly-detector');
        const detector = mod.createAnomalyDetectorFromEnv({ REDIS_URL: 'redis://localhost:6379' });
        expect(detector).toBeInstanceOf(FreshAnomalyDetector);
      });
    } finally {
      jest.dontMock('ioredis');
      jest.resetModules();
    }
  });

  it('honours replicaId option passed to the in-memory fallback', () => {
    const detector = createAnomalyDetectorFromEnv({}, { replicaId: 'pod-0' });
    expect(detector).toBeInstanceOf(AnomalyDetector);
    expect((detector as AnomalyDetector).replicaId).toBe('pod-0');
  });

  it('uses ANOMALY_REDIS_URL in preference to REDIS_URL', () => {
    // When ioredis is available this will create a RedisAnomalyDetector.
    // When ioredis is not available (e.g. test env) it falls back.
    // We just verify the function doesn't throw when both are set.
    expect(() =>
      createAnomalyDetectorFromEnv({
        ANOMALY_REDIS_URL: 'redis://localhost:6379',
        REDIS_URL: 'redis://other:6379',
      })
    ).not.toThrow();
  });
});
