/**
 * Tests for InMemoryMintRateLimiter and RedisBackedMintRateLimiter.
 *
 * The Redis-backed tests use a hand-rolled mock client that implements
 * {@link RedisMintRateLimiterClient} so no real Redis instance is needed.
 */

import {
  InMemoryMintRateLimiter,
  RedisBackedMintRateLimiter,
  RedisMintRateLimiterClient,
  MintRateLimiter,
  createPingRateLimiterFromEnv,
} from '../src/mint-rate-limiter';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * In-memory Redis mock that satisfies {@link RedisMintRateLimiterClient}.
 * Keys are stored with an explicit expiry so `ttl()` returns a meaningful value.
 *
 * `expiresAt = -1` is the internal sentinel meaning "key exists but has no TTL"
 * (mirrors Redis's `TTL → -1` for persistent keys). This lets tests exercise
 * the safety guard that re-applies expire() when the initial expire() call
 * failed after a successful incr().
 */
class FakeRedisClient implements RedisMintRateLimiterClient {
  private readonly store = new Map<string, { count: number; expiresAt: number }>();
  private readonly eventListeners = new Map<string, Array<(...args: unknown[]) => void>>();

  // Used by tests to simulate a fully broken client.
  shouldThrow = false;

  // Number of times expire() should throw before succeeding. Used to simulate
  // a transient Redis error on the initial expire() call (INCR succeeds but
  // EXPIRE fails), leaving the key with no TTL. Each call decrements the
  // counter; once it reaches 0 expire() operates normally.
  expireFailsRemaining = 0;

  async incr(key: string): Promise<number> {
    if (this.shouldThrow) throw new Error('Redis connection refused');
    const now = Date.now();
    const entry = this.store.get(key);
    // Reset when: (a) key missing, or (b) key has a real expiry that has passed.
    // A key with expiresAt === -1 (no TTL yet) is NOT treated as expired; it is
    // a valid persistent key awaiting its first expire() call.
    if (!entry || (entry.expiresAt !== -1 && now >= entry.expiresAt)) {
      // Expired or missing — start a new window. expiresAt=-1 means no TTL set yet.
      this.store.set(key, { count: 1, expiresAt: -1 });
      return 1;
    }
    entry.count++;
    return entry.count;
  }

  async decr(key: string): Promise<number> {
    if (this.shouldThrow) throw new Error('Redis connection refused');
    const entry = this.store.get(key);
    if (!entry) return 0;
    if (entry.count > 0) entry.count--;
    return entry.count;
  }

  async expire(key: string, seconds: number): Promise<number> {
    if (this.shouldThrow) throw new Error('Redis connection refused');
    if (this.expireFailsRemaining > 0) {
      this.expireFailsRemaining--;
      throw new Error('Redis expire error');
    }
    const entry = this.store.get(key);
    if (entry) {
      entry.expiresAt = Date.now() + seconds * 1000;
    }
    return entry ? 1 : 0;
  }

  async ttl(key: string): Promise<number> {
    if (this.shouldThrow) throw new Error('Redis connection refused');
    const entry = this.store.get(key);
    if (!entry) return -2; // key does not exist
    if (entry.expiresAt === -1) return -1; // key exists but has no TTL
    const remaining = Math.ceil((entry.expiresAt - Date.now()) / 1000);
    return remaining > 0 ? remaining : -1;
  }

  async quit(): Promise<'OK'> {
    return 'OK';
  }

  on(event: string, listener: (...args: unknown[]) => void): this {
    const listeners = this.eventListeners.get(event) ?? [];
    listeners.push(listener);
    this.eventListeners.set(event, listeners);
    return this;
  }

  /** Emit an event (used in tests to trigger the 'error' listener). */
  emit(event: string, ...args: unknown[]): void {
    const listeners = this.eventListeners.get(event) ?? [];
    for (const fn of listeners) fn(...args);
  }
}

// ---------------------------------------------------------------------------
// InMemoryMintRateLimiter
// ---------------------------------------------------------------------------

describe('InMemoryMintRateLimiter', () => {
  it('allows requests below the limit', async () => {
    const limiter = new InMemoryMintRateLimiter({ maxMintsPerWindow: 3, windowSeconds: 60 });
    expect((await limiter.check('ip-1')).allowed).toBe(true);
    expect((await limiter.check('ip-1')).allowed).toBe(true);
    expect((await limiter.check('ip-1')).allowed).toBe(true);
  });

  it('denies when the limit is exceeded', async () => {
    const limiter = new InMemoryMintRateLimiter({ maxMintsPerWindow: 2, windowSeconds: 60 });
    await limiter.check('ip-2');
    await limiter.check('ip-2');
    const result = await limiter.check('ip-2');
    expect(result.allowed).toBe(false);
    expect(result.retryAfterSeconds).toBeGreaterThan(0);
  });

  it('tracks different keys independently', async () => {
    const limiter = new InMemoryMintRateLimiter({ maxMintsPerWindow: 1, windowSeconds: 60 });
    const r1 = await limiter.check('ip-a');
    const r2 = await limiter.check('ip-b');
    expect(r1.allowed).toBe(true);
    expect(r2.allowed).toBe(true);
  });

  it('resets after the window expires', async () => {
    jest.useFakeTimers();
    const limiter = new InMemoryMintRateLimiter({ maxMintsPerWindow: 1, windowSeconds: 1 });
    await limiter.check('ip-3'); // first call — uses the 1-request budget
    // Second call in the same window is denied.
    expect((await limiter.check('ip-3')).allowed).toBe(false);
    // Advance clock past the 1-second window.
    jest.advanceTimersByTime(1001);
    // After the window expires, the counter resets.
    const result = await limiter.check('ip-3');
    expect(result.allowed).toBe(true);
    jest.useRealTimers();
  });

  it('throws on non-positive maxMintsPerWindow', () => {
    expect(() => new InMemoryMintRateLimiter({ maxMintsPerWindow: 0, windowSeconds: 60 })).toThrow(
      /maxMintsPerWindow/,
    );
  });

  it('throws on non-positive windowSeconds', () => {
    expect(() => new InMemoryMintRateLimiter({ maxMintsPerWindow: 10, windowSeconds: -1 })).toThrow(
      /windowSeconds/,
    );
  });

  describe('decrement()', () => {
    it('allows an additional request after a decremented allow', async () => {
      const limiter = new InMemoryMintRateLimiter({ maxMintsPerWindow: 1, windowSeconds: 60 });
      await limiter.check('t1'); // consumes the only slot
      expect((await limiter.check('t1')).allowed).toBe(false); // limit hit

      await limiter.decrement('t1'); // return the slot

      expect((await limiter.check('t1')).allowed).toBe(true); // slot restored
    });

    it('does not go below zero', async () => {
      const limiter = new InMemoryMintRateLimiter({ maxMintsPerWindow: 2, windowSeconds: 60 });
      await limiter.decrement('empty-key'); // no entry yet — should not throw
      await limiter.check('t2'); // check still works normally after decrement on empty key
      expect((await limiter.check('t2')).allowed).toBe(true);
    });

    it('is a no-op for an unknown tenantId', async () => {
      const limiter = new InMemoryMintRateLimiter({ maxMintsPerWindow: 2, windowSeconds: 60 });
      await expect(limiter.decrement('nonexistent')).resolves.toBeUndefined();
    });
  });
});

// ---------------------------------------------------------------------------
// RedisBackedMintRateLimiter
// ---------------------------------------------------------------------------

describe('RedisBackedMintRateLimiter', () => {
  let fakeRedis: FakeRedisClient;
  let limiter: RedisBackedMintRateLimiter;

  beforeEach(() => {
    fakeRedis = new FakeRedisClient();
    fakeRedis.shouldThrow = false;
    limiter = new RedisBackedMintRateLimiter(fakeRedis, {
      maxMintsPerWindow: 3,
      windowSeconds: 60,
    });
  });

  it('allows requests below the limit', async () => {
    expect((await limiter.check('::1')).allowed).toBe(true);
    expect((await limiter.check('::1')).allowed).toBe(true);
    expect((await limiter.check('::1')).allowed).toBe(true);
  });

  it('denies when the count exceeds the limit', async () => {
    await limiter.check('::1');
    await limiter.check('::1');
    await limiter.check('::1');
    const result = await limiter.check('::1');
    expect(result.allowed).toBe(false);
    expect(result.retryAfterSeconds).toBeGreaterThan(0);
  });

  it('tracks different IPs independently', async () => {
    const r1 = await limiter.check('1.2.3.4');
    const r2 = await limiter.check('5.6.7.8');
    expect(r1.allowed).toBe(true);
    expect(r2.allowed).toBe(true);
  });

  it('uses the configured key prefix', async () => {
    const prefixed = new RedisBackedMintRateLimiter(fakeRedis, {
      maxMintsPerWindow: 1,
      windowSeconds: 60,
      keyPrefix: 'test:',
    });
    // First call should be allowed.
    const r1 = await prefixed.check('myip');
    expect(r1.allowed).toBe(true);
    // Second call exceeds limit of 1.
    const r2 = await prefixed.check('myip');
    expect(r2.allowed).toBe(false);
  });

  it('falls back to localFallback when Redis throws', async () => {
    fakeRedis.shouldThrow = true;
    const fallback = new InMemoryMintRateLimiter({ maxMintsPerWindow: 5, windowSeconds: 60 });
    const withFallback = new RedisBackedMintRateLimiter(fakeRedis, {
      maxMintsPerWindow: 3,
      windowSeconds: 60,
      localFallback: fallback,
    });
    // Redis throws but localFallback allows the request.
    const result = await withFallback.check('::1');
    expect(result.allowed).toBe(true);
  });

  it('fails open (allows) when Redis throws and no localFallback is configured', async () => {
    fakeRedis.shouldThrow = true;
    const result = await limiter.check('::1');
    expect(result.allowed).toBe(true);
  });

  it('throws on non-positive maxMintsPerWindow', () => {
    expect(
      () => new RedisBackedMintRateLimiter(fakeRedis, { maxMintsPerWindow: 0, windowSeconds: 60 }),
    ).toThrow(/maxMintsPerWindow/);
  });

  it('throws on non-positive windowSeconds', () => {
    expect(
      () =>
        new RedisBackedMintRateLimiter(fakeRedis, { maxMintsPerWindow: 5, windowSeconds: -5 }),
    ).toThrow(/windowSeconds/);
  });

  it('close() calls quit() on the Redis client', async () => {
    const quitSpy = jest.spyOn(fakeRedis, 'quit');
    await limiter.close();
    expect(quitSpy).toHaveBeenCalledTimes(1);
  });

  it('close() does not throw when quit() rejects', async () => {
    jest.spyOn(fakeRedis, 'quit').mockRejectedValue(new Error('already closed'));
    await expect(limiter.close()).resolves.toBeUndefined();
  });

  it('re-applies TTL in the deny path when the initial expire() failed (safety guard)', async () => {
    // Simulate a transient Redis error on the very first expire() call.
    // incr() succeeds and stores count=1, but expire() throws → outer catch
    // fires → fail-open (allowed=true). The key is left with no TTL.
    fakeRedis.expireFailsRemaining = 1;
    // Default keyPrefix is 'mintrl:' — match it when querying fakeRedis directly.
    const fullKey = 'mintrl:ip-guard';

    // Call 1: incr → 1, expire fails → outer catch → fail-open.
    const r1 = await limiter.check('ip-guard');
    expect(r1.allowed).toBe(true);

    // The key now has count=1 with no TTL (expiresAt === -1 in the mock).
    expect(await fakeRedis.ttl(fullKey)).toBe(-1);

    // Calls 2-3: count reaches maxMints=3 without triggering the deny path.
    await limiter.check('ip-guard');
    await limiter.check('ip-guard');

    // Call 4: count=4 > maxMints=3. The deny path calls ttl(), detects -1,
    // and re-applies expire so the block is time-bounded rather than permanent.
    const r4 = await limiter.check('ip-guard');
    expect(r4.allowed).toBe(false);
    expect(r4.retryAfterSeconds).toBeGreaterThan(0);
    expect(r4.retryAfterSeconds).toBeLessThanOrEqual(60);

    // The TTL should now be set — the key is no longer persistent.
    expect(await fakeRedis.ttl(fullKey)).toBeGreaterThan(0);
  });

  describe('decrement()', () => {
    it('allows an additional request after a decremented allow', async () => {
      const limiter = new RedisBackedMintRateLimiter(fakeRedis, {
        maxMintsPerWindow: 1,
        windowSeconds: 60,
      });
      // Simulate: check succeeds (slot consumed), then audit fails → decrement → retry.
      // Redis INCR is unconditional, so the correct scenario is:
      //   check (count: 0→1, allowed) → decrement (count: 1→0) → check (count: 0→1, allowed)
      expect((await limiter.check('t1')).allowed).toBe(true); // slot consumed
      await limiter.decrement('t1'); // slot returned
      expect((await limiter.check('t1')).allowed).toBe(true); // retry allowed
    });

    it('issues a DECR call to Redis', async () => {
      const decrSpy = jest.spyOn(fakeRedis, 'decr');
      await limiter.decrement('somekey');
      expect(decrSpy).toHaveBeenCalledWith('mintrl:somekey');
    });

    it('does not throw when Redis DECR fails', async () => {
      jest.spyOn(fakeRedis, 'decr').mockRejectedValue(new Error('Redis down'));
      await expect(limiter.decrement('t1')).resolves.toBeUndefined();
    });

    it('is a no-op for an unknown key', async () => {
      await expect(limiter.decrement('nonexistent-key')).resolves.toBeUndefined();
    });
  });
});

// ---------------------------------------------------------------------------
// createPingRateLimiterFromEnv
// ---------------------------------------------------------------------------

describe('createPingRateLimiterFromEnv', () => {
  it('returns InMemoryMintRateLimiter when no Redis URL is configured', async () => {
    const limiter = await createPingRateLimiterFromEnv({});
    // Should allow requests (InMemory with defaults: 20/60s).
    const result = await limiter.check('127.0.0.1');
    expect(result.allowed).toBe(true);
    expect(limiter).toBeInstanceOf(InMemoryMintRateLimiter);
  });

  it('falls back to InMemoryMintRateLimiter when no Redis URL is configured (ioredis not relevant)', async () => {
    // When neither MINTER_PING_REDIS_URL nor REDIS_URL is set, ioredis is
    // never required — the factory short-circuits to InMemoryMintRateLimiter.
    const limiter = await createPingRateLimiterFromEnv({});
    expect(limiter).toBeInstanceOf(InMemoryMintRateLimiter);
  });

  it('respects MINTER_PING_RATE_LIMIT_MAX and MINTER_PING_RATE_LIMIT_WINDOW_SECONDS', async () => {
    const limiter = await createPingRateLimiterFromEnv({
      MINTER_PING_RATE_LIMIT_MAX: '2',
      MINTER_PING_RATE_LIMIT_WINDOW_SECONDS: '120',
    });
    // Exhaust the 2-request budget.
    await limiter.check('ip');
    await limiter.check('ip');
    const third = await limiter.check('ip');
    expect(third.allowed).toBe(false);
    // retryAfterSeconds should reflect the 120-second window.
    expect(third.retryAfterSeconds).toBeLessThanOrEqual(120);
  });

  it('falls back to default max=20 when MINTER_PING_RATE_LIMIT_MAX is invalid', async () => {
    const limiter = await createPingRateLimiterFromEnv({
      MINTER_PING_RATE_LIMIT_MAX: 'not-a-number',
    });
    expect(limiter).toBeInstanceOf(InMemoryMintRateLimiter);
    // With default 20 max, 20 allowed requests should not be rate-limited.
    for (let i = 0; i < 20; i++) {
      expect((await limiter.check('ip-test')).allowed).toBe(true);
    }
  });

  it('returns a MintRateLimiter interface', async () => {
    const limiter: MintRateLimiter = await createPingRateLimiterFromEnv({});
    expect(typeof limiter.check).toBe('function');
  });
});
