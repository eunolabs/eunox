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
  ShardLocalCallCounterStore,
  createCallCounterStoreFromEnv,
  createLogger,
} from '../src';
import { computeAgentShardIndex } from '../src/shard';

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

// ---------------------------------------------------------------------------
// ShardLocalCallCounterStore
// ---------------------------------------------------------------------------

// Helper: find a sub value that hashes to the given shard index.
// Iterates numbered sub strings until it finds a match.  With small shard
// counts (2-10), the first matching value is typically found within a few
// hundred iterations.
function subForShard(targetShard: number, shardCount: number): string {
  for (let i = 0; i < 10_000; i++) {
    const sub = `agent-${i}`;
    if (computeAgentShardIndex(sub, shardCount) === targetShard) return sub;
  }
  throw new Error(`Could not find a sub for shard ${targetShard}/${shardCount}`);
}

describe('ShardLocalCallCounterStore', () => {
  const SHARD_COUNT = 3;
  const MY_SHARD = 1;

  // Pre-compute subs that hash to each shard index for a 3-shard ring.
  const ownedSub = subForShard(MY_SHARD, SHARD_COUNT);
  const foreignSub0 = subForShard(0, SHARD_COUNT);
  const foreignSub2 = subForShard(2, SHARD_COUNT);

  function makeStore(opts?: { onMisrouted?: () => void }) {
    const local = new InMemoryCallCounterStore();
    const remote = new InMemoryCallCounterStore();
    const store = new ShardLocalCallCounterStore(
      local,
      remote,
      { shardIndex: MY_SHARD, shardCount: SHARD_COUNT, ...opts },
      logger,
    );
    return { store, local, remote };
  }

  it('routes an owned agent to the local store', async () => {
    const { store, local, remote } = makeStore();
    const v = await store.incrementAndGet('key', 60, ownedSub);
    expect(v).toBe(1);
    expect(local.size()).toBe(1);
    expect(remote.size()).toBe(0);
  });

  it('local counter increments on repeated owned-agent calls', async () => {
    const { store, local } = makeStore();
    await store.incrementAndGet('k', 60, ownedSub);
    await store.incrementAndGet('k', 60, ownedSub);
    const v = await store.incrementAndGet('k', 60, ownedSub);
    expect(v).toBe(3);
    expect(local.size()).toBe(1);
  });

  it('routes a mis-routed agent to the remote store', async () => {
    const { store, local, remote } = makeStore();
    const v = await store.incrementAndGet('key', 60, foreignSub0);
    expect(v).toBe(1);
    expect(local.size()).toBe(0);
    expect(remote.size()).toBe(1);
  });

  it('increments the onMisrouted callback for mis-routed agents', async () => {
    let count = 0;
    const { store } = makeStore({ onMisrouted: () => { count++; } });
    await store.incrementAndGet('key', 60, foreignSub0);
    await store.incrementAndGet('key', 60, foreignSub2);
    expect(count).toBe(2);
  });

  it('does NOT invoke onMisrouted for owned agents', async () => {
    let count = 0;
    const { store } = makeStore({ onMisrouted: () => { count++; } });
    await store.incrementAndGet('key', 60, ownedSub);
    expect(count).toBe(0);
  });

  it('falls back to the remote store when no agentSub hint is given', async () => {
    const { store, local, remote } = makeStore();
    const v = await store.incrementAndGet('key', 60);
    expect(v).toBe(1);
    expect(local.size()).toBe(0);
    expect(remote.size()).toBe(1);
  });

  it('does NOT invoke onMisrouted when no agentSub hint is given', async () => {
    let count = 0;
    const { store } = makeStore({ onMisrouted: () => { count++; } });
    await store.incrementAndGet('key', 60);
    expect(count).toBe(0);
  });

  it('localSize() reflects only the local store entry count', async () => {
    const { store } = makeStore();
    await store.incrementAndGet('local-key', 60, ownedSub);
    await store.incrementAndGet('remote-key', 60, foreignSub0);
    expect(store.localSize()).toBe(1);
  });

  it('resetLocal() clears only the local store', async () => {
    const { store, remote } = makeStore();
    await store.incrementAndGet('local-key', 60, ownedSub);
    await store.incrementAndGet('remote-key', 60, foreignSub0);
    store.resetLocal();
    expect(store.localSize()).toBe(0);
    // Remote store is unaffected.
    expect(remote.size()).toBe(1);
  });

  it('rate-limits the mis-route warn log (only logs once per interval)', async () => {
    const warnSpy = jest.spyOn(logger, 'warn');
    const realNow = Date.now;
    let now = 1_000_000;
    Date.now = () => now;
    try {
      const { store } = makeStore();
      // First mis-route should log.
      await store.incrementAndGet('k', 60, foreignSub0);
      const firstWarnCount = warnSpy.mock.calls.length;
      expect(firstWarnCount).toBeGreaterThan(0);

      // Second mis-route within the interval should NOT log.
      await store.incrementAndGet('k', 60, foreignSub0);
      expect(warnSpy.mock.calls.length).toBe(firstWarnCount);

      // After the interval elapses, the next mis-route should log again.
      now += 61_000;
      await store.incrementAndGet('k', 60, foreignSub0);
      expect(warnSpy.mock.calls.length).toBeGreaterThan(firstWarnCount);
    } finally {
      Date.now = realNow;
      warnSpy.mockRestore();
    }
  });
});
