/**
 * Tests for the {@link CallCounterStore} implementations used by
 * `maxCalls` enforcement.
 *
 * The Redis-backed implementation is exercised against a hand-rolled
 * fake that mirrors the `ioredis` surface — keeping the test
 * dependency-free while still pinning the contract the production
 * client relies on (atomic INCR + EXPIRE-on-first-touch).
 */

import {
  InMemoryCallCounterStore,
  RedisCallCounterStore,
  RedisCallCounterClient,
  createCallCounterStoreFromEnv,
  createLogger,
} from '../src';

const logger = createLogger('test');

describe('InMemoryCallCounterStore', () => {
  it('counts calls within the window', async () => {
    const s = new InMemoryCallCounterStore();
    expect(await s.incrementAndGet('a', 60)).toBe(1);
    expect(await s.incrementAndGet('a', 60)).toBe(2);
    expect(await s.incrementAndGet('a', 60)).toBe(3);
  });

  it('keeps counters per key', async () => {
    const s = new InMemoryCallCounterStore();
    expect(await s.incrementAndGet('a', 60)).toBe(1);
    expect(await s.incrementAndGet('b', 60)).toBe(1);
    expect(await s.incrementAndGet('a', 60)).toBe(2);
  });

  it('resets the counter once the window has elapsed', async () => {
    const s = new InMemoryCallCounterStore();
    const realNow = Date.now;
    let now = 1_000_000;
    Date.now = () => now;
    try {
      expect(await s.incrementAndGet('a', 1)).toBe(1);
      expect(await s.incrementAndGet('a', 1)).toBe(2);
      now += 2000;
      expect(await s.incrementAndGet('a', 1)).toBe(1);
    } finally {
      Date.now = realNow;
    }
  });

  it('reset() drops all counters', async () => {
    const s = new InMemoryCallCounterStore();
    await s.incrementAndGet('a', 60);
    expect(s.size()).toBe(1);
    s.reset();
    expect(s.size()).toBe(0);
  });
});

/**
 * Hand-rolled fake ioredis client. Reproduces just enough of `INCR` /
 * `EXPIRE` for the store under test.
 */
class FakeRedis implements RedisCallCounterClient {
  values = new Map<string, number>();
  expiries = new Map<string, number>();
  errorOn?: 'incr' | 'expire';
  closed = false;

  async incr(key: string): Promise<number> {
    if (this.errorOn === 'incr') throw new Error('incr-failed');
    const v = (this.values.get(key) ?? 0) + 1;
    this.values.set(key, v);
    return v;
  }
  async expire(key: string, seconds: number): Promise<unknown> {
    if (this.errorOn === 'expire') throw new Error('expire-failed');
    this.expiries.set(key, seconds);
    return 1;
  }
  async quit(): Promise<unknown> {
    this.closed = true;
    return 'OK';
  }
  on(): unknown {
    return this;
  }
}

describe('RedisCallCounterStore', () => {
  it('prefixes keys and sets the TTL on the first increment only', async () => {
    const fake = new FakeRedis();
    const store = new RedisCallCounterStore(fake, logger, { keyPrefix: 'pre:' });

    expect(await store.incrementAndGet('cap-1', 30)).toBe(1);
    expect(fake.values.get('pre:cap-1')).toBe(1);
    expect(fake.expiries.get('pre:cap-1')).toBe(30);

    // Subsequent increments must NOT re-set the TTL — the counter
    // window stays aligned to the first call.
    fake.expiries.delete('pre:cap-1');
    expect(await store.incrementAndGet('cap-1', 30)).toBe(2);
    expect(fake.expiries.has('pre:cap-1')).toBe(false);
  });

  it('fails closed on Redis errors by default', async () => {
    const fake = new FakeRedis();
    fake.errorOn = 'incr';
    const store = new RedisCallCounterStore(fake, logger);
    const v = await store.incrementAndGet('cap-1', 30);
    expect(v).toBe(Number.POSITIVE_INFINITY);
  });

  it('propagates Redis errors when failClosedOnError is false', async () => {
    const fake = new FakeRedis();
    fake.errorOn = 'incr';
    const store = new RedisCallCounterStore(fake, logger, { failClosedOnError: false });
    await expect(store.incrementAndGet('cap-1', 30)).rejects.toThrow(/incr-failed/);
  });

  it('treats EXPIRE failure as a fail-closed', async () => {
    const fake = new FakeRedis();
    fake.errorOn = 'expire';
    const store = new RedisCallCounterStore(fake, logger);
    const v = await store.incrementAndGet('cap-1', 30);
    expect(v).toBe(Number.POSITIVE_INFINITY);
  });

  it('close() quits the underlying client', async () => {
    const fake = new FakeRedis();
    const store = new RedisCallCounterStore(fake, logger);
    await store.close();
    expect(fake.closed).toBe(true);
  });
});

describe('createCallCounterStoreFromEnv', () => {
  it('returns an in-memory store when REDIS_URL is unset', async () => {
    const store = await createCallCounterStoreFromEnv({}, logger);
    expect(store).toBeInstanceOf(InMemoryCallCounterStore);
  });

  it('falls back to in-memory when ioredis is missing (REDIS_URL set, package absent)', async () => {
    // ioredis is not installed in this workspace, so this path is the
    // production fallback exercised end-to-end.
    const store = await createCallCounterStoreFromEnv({ REDIS_URL: 'redis://localhost:6379' }, logger);
    expect(store).toBeInstanceOf(InMemoryCallCounterStore);
  });
});
