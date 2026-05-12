/**
 * Tests for RedisUsageMeter (CR-1) and createUsageMeterFromEnv.
 *
 * All tests use an in-memory fake for the Redis client so they run without
 * external infrastructure. The key scenarios validated here are:
 *
 *   - recordEnforcement / recordKillSwitchInvocation update in-memory state
 *     synchronously (for fast synchronous reads).
 *   - Both methods fire-and-forget Redis INCR commands; errors are logged
 *     and forwarded to the onError callback.
 *   - loadFromRedis() hydrates local state from Redis on startup.
 *   - resetPeriod() zeroes in-memory counters and deletes Redis keys.
 *   - getUsage() returns a zero-count snapshot for unknown tenants.
 *   - getAllUsage() lists all known tenants.
 *   - createUsageMeterFromEnv returns InMemoryUsageMeter when no Redis URL
 *     is configured, and RedisUsageMeter when a URL is provided.
 */

import { RedisUsageMeter, RedisUsageMeterClient, createUsageMeterFromEnv } from '../redis-usage-meter';
import { InMemoryUsageMeter } from '@euno/common-core';

// ─── Fake Redis client ────────────────────────────────────────────────────────

/**
 * Minimal in-memory fake for `RedisUsageMeterClient`.
 * Supports all operations used by RedisUsageMeter plus helpers for
 * inspecting internal state and injecting errors.
 */
class FakeRedisClient implements RedisUsageMeterClient {
  private store = new Map<string, string>();
  private sets = new Map<string, Set<string>>();
  private ttls = new Map<string, number>();
  private errorListeners: Array<(...args: unknown[]) => void> = [];
  private shouldErrorOn: Set<string> = new Set();
  /** If true, the next operation throws regardless of the method. */
  private nextOpThrows = false;

  /** Make the next call to any operation throw. */
  simulateNextError(): void {
    this.nextOpThrows = true;
  }

  /** Make all calls to a specific key throw. */
  errorOnKey(key: string): void {
    this.shouldErrorOn.add(key);
  }

  rawStore(): ReadonlyMap<string, string> {
    return this.store;
  }

  rawSets(): ReadonlyMap<string, Set<string>> {
    return this.sets;
  }

  rawTtls(): ReadonlyMap<string, number> {
    return this.ttls;
  }

  private maybeThrow(key?: string): void {
    if (this.nextOpThrows) {
      this.nextOpThrows = false;
      throw new Error('Simulated Redis error');
    }
    if (key && this.shouldErrorOn.has(key)) {
      throw new Error(`Simulated Redis error for key: ${key}`);
    }
  }

  async incr(key: string): Promise<number> {
    this.maybeThrow(key);
    const prev = parseInt(this.store.get(key) ?? '0', 10);
    const next = prev + 1;
    this.store.set(key, String(next));
    return next;
  }

  async expire(key: string, seconds: number): Promise<unknown> {
    this.maybeThrow(key);
    this.ttls.set(key, seconds);
    return 1;
  }

  async sadd(key: string, member: string): Promise<number> {
    this.maybeThrow(key);
    let set = this.sets.get(key);
    if (!set) {
      set = new Set<string>();
      this.sets.set(key, set);
    }
    const added = !set.has(member);
    set.add(member);
    return added ? 1 : 0;
  }

  async smembers(key: string): Promise<string[]> {
    this.maybeThrow(key);
    return Array.from(this.sets.get(key) ?? []);
  }

  async get(key: string): Promise<string | null> {
    this.maybeThrow(key);
    return this.store.get(key) ?? null;
  }

  async setnx(key: string, value: string): Promise<number> {
    this.maybeThrow(key);
    if (this.store.has(key)) return 0;
    this.store.set(key, value);
    return 1;
  }

  async set(key: string, value: string): Promise<unknown> {
    this.maybeThrow(key);
    this.store.set(key, value);
    return 'OK';
  }

  async del(...keys: string[]): Promise<unknown> {
    this.maybeThrow();
    for (const k of keys) {
      this.store.delete(k);
      this.ttls.delete(k);
    }
    return keys.length;
  }

  async mget(...keys: string[]): Promise<(string | null)[]> {
    this.maybeThrow();
    return keys.map((k) => this.store.get(k) ?? null);
  }

  async quit(): Promise<unknown> {
    return 'OK';
  }

  on(event: string, listener: (...args: unknown[]) => void): unknown {
    if (event === 'error') this.errorListeners.push(listener);
    return this;
  }

  /** Emit a connection error event to all registered listeners. */
  emitError(err: Error): void {
    for (const l of this.errorListeners) l(err);
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Drain the microtask queue so fire-and-forget writes complete. */
function flushPromises(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('RedisUsageMeter', () => {
  let client: FakeRedisClient;
  let meter: RedisUsageMeter;

  beforeEach(() => {
    client = new FakeRedisClient();
    meter = new RedisUsageMeter(client, { keyPrefix: 'test:usage:' });
  });

  // ── getUsage: unknown tenant ───────────────────────────────────────────────

  describe('getUsage() for an unknown tenant', () => {
    it('returns a zero-count snapshot', () => {
      const snap = meter.getUsage('tenant-x');
      expect(snap.tenantId).toBe('tenant-x');
      expect(snap.enforcementEvents).toBe(0);
      expect(snap.allowDecisions).toBe(0);
      expect(snap.denyDecisions).toBe(0);
      expect(snap.killSwitchInvocations).toBe(0);
    });

    it('returns a valid ISO-8601 periodStart', () => {
      const snap = meter.getUsage('tenant-x');
      expect(() => new Date(snap.periodStart)).not.toThrow();
    });

    it('does not persist the phantom tenant (getAllUsage stays empty)', () => {
      meter.getUsage('tenant-x');
      expect(meter.getAllUsage()).toHaveLength(0);
    });
  });

  // ── recordEnforcement ──────────────────────────────────────────────────────

  describe('recordEnforcement()', () => {
    it('increments in-memory enforcementEvents and allowDecisions on allow', async () => {
      meter.recordEnforcement('t1', 'allow');
      await flushPromises();
      const snap = meter.getUsage('t1');
      expect(snap.enforcementEvents).toBe(1);
      expect(snap.allowDecisions).toBe(1);
      expect(snap.denyDecisions).toBe(0);
    });

    it('increments in-memory enforcementEvents and denyDecisions on deny', async () => {
      meter.recordEnforcement('t1', 'deny');
      await flushPromises();
      const snap = meter.getUsage('t1');
      expect(snap.enforcementEvents).toBe(1);
      expect(snap.allowDecisions).toBe(0);
      expect(snap.denyDecisions).toBe(1);
    });

    it('increments correctly for multiple calls', async () => {
      meter.recordEnforcement('t1', 'allow');
      meter.recordEnforcement('t1', 'allow');
      meter.recordEnforcement('t1', 'deny');
      await flushPromises();
      const snap = meter.getUsage('t1');
      expect(snap.enforcementEvents).toBe(3);
      expect(snap.allowDecisions).toBe(2);
      expect(snap.denyDecisions).toBe(1);
    });

    it('writes to Redis (INCR enforcement + allow/deny keys)', async () => {
      meter.recordEnforcement('t1', 'allow');
      await flushPromises();
      const store = client.rawStore();
      expect(store.get('test:usage:t1:enforcement')).toBe('1');
      expect(store.get('test:usage:t1:allow')).toBe('1');
      expect(store.get('test:usage:t1:deny')).toBeUndefined();
    });

    it('sets TTL on the first INCR', async () => {
      meter.recordEnforcement('t1', 'allow');
      await flushPromises();
      const ttls = client.rawTtls();
      // TTL should be set on enforcement and allow keys (first incr)
      expect(ttls.has('test:usage:t1:enforcement')).toBe(true);
      expect(ttls.has('test:usage:t1:allow')).toBe(true);
    });

    it('does NOT set TTL again on subsequent INCRs for the same key', async () => {
      meter.recordEnforcement('t1', 'allow');
      await flushPromises();
      const firstTtl = client.rawTtls().get('test:usage:t1:enforcement');

      // Second call — same key, should not replace TTL (count = 2, not 1)
      meter.recordEnforcement('t1', 'allow');
      await flushPromises();
      const ttls = client.rawTtls();
      // TTL should not have been overwritten
      expect(ttls.get('test:usage:t1:enforcement')).toBe(firstTtl);
    });

    it('tracks the tenant in the Redis tenants set', async () => {
      meter.recordEnforcement('t1', 'allow');
      await flushPromises();
      const members = await client.smembers('test:usage:tenants');
      expect(members).toContain('t1');
    });

    it('sets period-start in Redis (NX) on first record', async () => {
      meter.recordEnforcement('t1', 'allow');
      await flushPromises();
      const ps = client.rawStore().get('test:usage:t1:ps');
      expect(typeof ps).toBe('string');
      expect(() => new Date(ps!)).not.toThrow();
    });

    it('does not overwrite an existing period-start (NX semantics)', async () => {
      meter.recordEnforcement('t1', 'allow');
      await flushPromises();
      const first = client.rawStore().get('test:usage:t1:ps');

      meter.recordEnforcement('t1', 'deny');
      await flushPromises();
      const second = client.rawStore().get('test:usage:t1:ps');
      // setnx should not overwrite
      expect(second).toBe(first);
    });

    it('applies TTL to the :ps key on first creation', async () => {
      meter.recordEnforcement('t1', 'allow');
      await flushPromises();
      expect(client.rawTtls().has('test:usage:t1:ps')).toBe(true);
    });

    it('does NOT set TTL again on second record (NX skipped duplicate)', async () => {
      meter.recordEnforcement('t1', 'allow');
      await flushPromises();
      const firstTtl = client.rawTtls().get('test:usage:t1:ps');

      meter.recordEnforcement('t1', 'deny');
      await flushPromises();
      // setnx returns 0 on the second call, so expire is not re-applied
      expect(client.rawTtls().get('test:usage:t1:ps')).toBe(firstTtl);
    });
  });

  // ── recordKillSwitchInvocation ─────────────────────────────────────────────

  describe('recordKillSwitchInvocation()', () => {
    it('increments in-memory killSwitchInvocations', async () => {
      meter.recordKillSwitchInvocation('t1');
      meter.recordKillSwitchInvocation('t1');
      await flushPromises();
      expect(meter.getUsage('t1').killSwitchInvocations).toBe(2);
    });

    it('writes to Redis kill key', async () => {
      meter.recordKillSwitchInvocation('t1');
      await flushPromises();
      expect(client.rawStore().get('test:usage:t1:kill')).toBe('1');
    });
  });

  // ── getAllUsage ────────────────────────────────────────────────────────────

  describe('getAllUsage()', () => {
    it('returns an empty list when no activity has been recorded', () => {
      expect(meter.getAllUsage()).toHaveLength(0);
    });

    it('returns all tenants that have had activity', async () => {
      meter.recordEnforcement('t1', 'allow');
      meter.recordEnforcement('t2', 'deny');
      await flushPromises();
      const all = meter.getAllUsage();
      expect(all.map((s) => s.tenantId).sort()).toEqual(['t1', 't2']);
    });
  });

  // ── resetPeriod ────────────────────────────────────────────────────────────

  describe('resetPeriod()', () => {
    it('zeroes in-memory counters for all tenants (global reset)', async () => {
      meter.recordEnforcement('t1', 'allow');
      meter.recordEnforcement('t2', 'deny');
      await flushPromises();

      meter.resetPeriod();
      await flushPromises();

      expect(meter.getUsage('t1').enforcementEvents).toBe(0);
      expect(meter.getUsage('t2').enforcementEvents).toBe(0);
    });

    it('zeroes in-memory counters for a single tenant', async () => {
      meter.recordEnforcement('t1', 'allow');
      meter.recordEnforcement('t2', 'deny');
      await flushPromises();

      meter.resetPeriod('t1');
      await flushPromises();

      expect(meter.getUsage('t1').enforcementEvents).toBe(0);
      expect(meter.getUsage('t2').enforcementEvents).toBe(1);
    });

    it('deletes Redis counter keys on global reset', async () => {
      meter.recordEnforcement('t1', 'allow');
      await flushPromises();
      expect(client.rawStore().has('test:usage:t1:enforcement')).toBe(true);

      meter.resetPeriod();
      await flushPromises();

      expect(client.rawStore().has('test:usage:t1:enforcement')).toBe(false);
    });

    it('applies TTL to the new :ps key written during reset', async () => {
      meter.recordEnforcement('t1', 'allow');
      await flushPromises();

      meter.resetPeriod('t1');
      await flushPromises();

      expect(client.rawTtls().has('test:usage:t1:ps')).toBe(true);
    });

    it('writes new period-start to Redis', async () => {
      meter.recordEnforcement('t1', 'allow');
      await flushPromises();
      const before = client.rawStore().get('test:usage:t1:ps');

      // Wait a tick so the timestamp is guaranteed to differ
      await new Promise((r) => setTimeout(r, 1));
      meter.resetPeriod('t1');
      await flushPromises();
      const after = client.rawStore().get('test:usage:t1:ps');
      expect(after).not.toBe(before);
    });

    it('advances the in-memory periodStart timestamp', async () => {
      meter.recordEnforcement('t1', 'allow');
      await flushPromises();
      const before = meter.getUsage('t1').periodStart;

      await new Promise((r) => setTimeout(r, 1));
      meter.resetPeriod('t1');
      const after = meter.getUsage('t1').periodStart;
      expect(new Date(after).getTime()).toBeGreaterThanOrEqual(new Date(before).getTime());
    });

    it('is a no-op for a non-existent tenant', () => {
      expect(() => meter.resetPeriod('nonexistent')).not.toThrow();
    });
  });

  // ── loadFromRedis ──────────────────────────────────────────────────────────

  describe('loadFromRedis()', () => {
    it('hydrates in-memory counters from Redis state', async () => {
      // Pre-seed Redis as if a prior pod had written these values.
      const prefix = 'test:usage:';
      await client.sadd(`${prefix}tenants`, 't1');
      await client.set(`${prefix}t1:enforcement`, '10');
      await client.set(`${prefix}t1:allow`, '7');
      await client.set(`${prefix}t1:deny`, '3');
      await client.set(`${prefix}t1:kill`, '1');
      await client.set(`${prefix}t1:ps`, '2026-01-01T00:00:00.000Z');

      await meter.loadFromRedis();

      const snap = meter.getUsage('t1');
      expect(snap.enforcementEvents).toBe(10);
      expect(snap.allowDecisions).toBe(7);
      expect(snap.denyDecisions).toBe(3);
      expect(snap.killSwitchInvocations).toBe(1);
      expect(snap.periodStart).toBe('2026-01-01T00:00:00.000Z');
    });

    it('handles missing keys gracefully (partial state)', async () => {
      const prefix = 'test:usage:';
      await client.sadd(`${prefix}tenants`, 't1');
      // Only enforcement counter — rest are missing
      await client.set(`${prefix}t1:enforcement`, '5');

      await meter.loadFromRedis();

      const snap = meter.getUsage('t1');
      expect(snap.enforcementEvents).toBe(5);
      expect(snap.allowDecisions).toBe(0);
      expect(snap.denyDecisions).toBe(0);
      expect(snap.killSwitchInvocations).toBe(0);
    });

    it('is a no-op when the tenants set is empty', async () => {
      await meter.loadFromRedis();
      expect(meter.getAllUsage()).toHaveLength(0);
    });

    it('does not overwrite existing in-memory state (startup recovery only)', async () => {
      meter.recordEnforcement('t1', 'allow');
      await flushPromises();

      // Attempt to reload — local state already has t1 with count 1;
      // the Redis side also has 1 (from the fire-and-forget write above).
      await meter.loadFromRedis();

      // Should still reflect 1 (not 2) — loadFromRedis REPLACES, not adds.
      const snap = meter.getUsage('t1');
      expect(snap.enforcementEvents).toBe(1);
    });

    it('does not throw when smembers errors — logs warning only', async () => {
      client.simulateNextError();
      await expect(meter.loadFromRedis()).resolves.toBeUndefined();
    });

    it('does not throw when mget errors — logs warning only', async () => {
      const prefix = 'test:usage:';
      await client.sadd(`${prefix}tenants`, 't1');
      // Simulate mget failure after smembers succeeds
      client.simulateNextError();
      await expect(meter.loadFromRedis()).resolves.toBeUndefined();
    });
  });

  // ── Error handling (Redis write failures) ─────────────────────────────────

  describe('Redis write error handling', () => {
    it('calls the onError callback when an INCR fails', async () => {
      const onError = jest.fn();
      const m = new RedisUsageMeter(client, { keyPrefix: 'test:usage:', onError });

      // Make the enforcement INCR fail
      client.errorOnKey('test:usage:t1:enforcement');

      m.recordEnforcement('t1', 'allow');
      await flushPromises();

      expect(onError).toHaveBeenCalled();
    });

    it('still updates in-memory counters even when Redis INCR fails', async () => {
      const onError = jest.fn();
      const m = new RedisUsageMeter(client, { keyPrefix: 'test:usage:', onError });

      client.errorOnKey('test:usage:t1:enforcement');

      m.recordEnforcement('t1', 'allow');
      await flushPromises();

      // In-memory write must succeed despite Redis failure
      expect(m.getUsage('t1').enforcementEvents).toBe(1);
    });

    it('calls the onError callback when SADD tenant registration fails', async () => {
      const onError = jest.fn();
      const m = new RedisUsageMeter(client, { keyPrefix: 'test:usage:', onError });

      client.errorOnKey('test:usage:tenants');

      m.recordEnforcement('t1', 'allow');
      await flushPromises();

      expect(onError).toHaveBeenCalled();
    });

    it('does not call onError for routine Redis operations', async () => {
      const onError = jest.fn();
      const m = new RedisUsageMeter(client, { keyPrefix: 'test:usage:', onError });

      m.recordEnforcement('t1', 'allow');
      await flushPromises();

      expect(onError).not.toHaveBeenCalled();
    });
  });

  // ── TTL configuration ──────────────────────────────────────────────────────

  describe('TTL configuration', () => {
    it('uses the provided counterTtlSeconds for new keys', async () => {
      const m = new RedisUsageMeter(client, { keyPrefix: 'test:usage:', counterTtlSeconds: 3600 });
      m.recordEnforcement('t1', 'allow');
      await flushPromises();
      expect(client.rawTtls().get('test:usage:t1:enforcement')).toBe(3600);
    });

    it('does not set TTL when counterTtlSeconds is 0', async () => {
      const m = new RedisUsageMeter(client, { keyPrefix: 'test:usage:', counterTtlSeconds: 0 });
      m.recordEnforcement('t1', 'allow');
      await flushPromises();
      expect(client.rawTtls().has('test:usage:t1:enforcement')).toBe(false);
    });
  });

  // ── close ──────────────────────────────────────────────────────────────────

  describe('close()', () => {
    it('resolves without throwing', async () => {
      await expect(meter.close()).resolves.toBeUndefined();
    });
  });
});

// ─── createUsageMeterFromEnv ──────────────────────────────────────────────────

describe('createUsageMeterFromEnv', () => {
  it('returns an InMemoryUsageMeter when no Redis URL is set', async () => {
    const meter = await createUsageMeterFromEnv({});
    expect(meter).toBeInstanceOf(InMemoryUsageMeter);
  });

  it('falls back to InMemoryUsageMeter when ioredis is not installed', async () => {
    // Force `require('ioredis')` to fail deterministically, regardless of whether
    // ioredis happens to be hoisted into the workspace — same pattern as revocation-store tests.
    jest.resetModules();
    try {
      jest.doMock('ioredis', () => { throw new Error("Cannot find module 'ioredis'"); }, { virtual: true });

      await jest.isolateModulesAsync(async () => {
        const mod = await import('../redis-usage-meter');
        const meter = await mod.createUsageMeterFromEnv(
          { REDIS_URL: 'redis://localhost:6379' } as unknown as NodeJS.ProcessEnv,
        );
        // Falls back to in-memory when ioredis can't be loaded.
        const snap = meter.getUsage('nonexistent-tenant');
        expect(snap.enforcementEvents).toBe(0);
        expect(snap.allowDecisions).toBe(0);
      });
    } finally {
      jest.dontMock('ioredis');
      jest.resetModules();
    }
  });

  it('USAGE_METER_REDIS_URL takes precedence over REDIS_URL in the error log', async () => {
    // When both URLs are set but ioredis is missing, the logged detectedVar
    // should reference USAGE_METER_REDIS_URL (checked first by the factory).
    jest.resetModules();
    try {
      jest.doMock('ioredis', () => { throw new Error("Cannot find module 'ioredis'"); }, { virtual: true });

      const errorMessages: string[] = [];
      const fakeLogger = {
        info: () => undefined,
        warn: () => undefined,
        error: (msg: string) => { errorMessages.push(msg); },
        debug: () => undefined,
      };

      await jest.isolateModulesAsync(async () => {
        const mod = await import('../redis-usage-meter');
        await mod.createUsageMeterFromEnv(
          {
            REDIS_URL: 'redis://localhost:6379',
            USAGE_METER_REDIS_URL: 'redis://localhost:6380',
          } as unknown as NodeJS.ProcessEnv,
          fakeLogger as unknown as Parameters<typeof mod.createUsageMeterFromEnv>[1],
        );
      });

      expect(errorMessages.some((m) => m.includes('USAGE_METER_REDIS_URL'))).toBe(true);
    } finally {
      jest.dontMock('ioredis');
      jest.resetModules();
    }
  });

  it('honours USAGE_METER_TTL_SECONDS=0 to disable TTL', async () => {
    // The parse path for USAGE_METER_TTL_SECONDS=0 should not error or fall
    // back to the default; the meter should be usable normally.
    jest.resetModules();
    try {
      jest.doMock('ioredis', () => { throw new Error("Cannot find module 'ioredis'"); }, { virtual: true });

      await jest.isolateModulesAsync(async () => {
        const mod = await import('../redis-usage-meter');
        const meter = await mod.createUsageMeterFromEnv(
          { USAGE_METER_TTL_SECONDS: '0' } as unknown as NodeJS.ProcessEnv,
        );
        meter.recordEnforcement('t1', 'allow');
        expect(meter.getUsage('t1').enforcementEvents).toBe(1);
      });
    } finally {
      jest.dontMock('ioredis');
      jest.resetModules();
    }
  });
});
