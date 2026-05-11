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

/**
 * Shared fake Redis client. Two instances created from the same `values`/`expiries`
 * maps share a common backing store, simulating two gateway replicas pointing at
 * the same Redis cluster. `errorMode` makes every `incr`/`expire` call throw.
 */
class SharedFakeRedis implements RedisCallCounterClient {
  errorMode = false;

  constructor(
    public readonly values: Map<string, number>,
    public readonly expiries: Map<string, number>,
  ) {}

  async incr(key: string): Promise<number> {
    if (this.errorMode) throw new Error('incr-failed');
    const v = (this.values.get(key) ?? 0) + 1;
    this.values.set(key, v);
    return v;
  }

  async expire(key: string, seconds: number): Promise<unknown> {
    if (this.errorMode) throw new Error('expire-failed');
    this.expiries.set(key, seconds);
    return 1;
  }

  async quit(): Promise<unknown> {
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

describe('RedisCallCounterStore circuit breaker integration', () => {
  it('fast-fails without hitting Redis when circuit is open', async () => {
    const fake = new FakeRedis();
    fake.errorOn = 'incr';
    const { RedisCircuitBreaker } = await import('../src/redis-circuit-breaker');
    const cb = new RedisCircuitBreaker({ failureThreshold: 2, windowMs: 5000, cooldownMs: 30000 });
    const store = new RedisCallCounterStore(fake, logger, { circuitBreaker: cb });
    const incrSpy = jest.spyOn(fake, 'incr');

    // Trip the circuit
    await store.incrementAndGet('a', 60);
    await store.incrementAndGet('b', 60);
    expect(cb.getState()).toBe('open');

    // Circuit is open: Redis must not be called.
    incrSpy.mockClear();
    await store.incrementAndGet('c', 60);
    expect(incrSpy).not.toHaveBeenCalled();
  });

  it('returns POSITIVE_INFINITY from circuit-open fast-fail (fail-closed, no fallback)', async () => {
    const fake = new FakeRedis();
    fake.errorOn = 'incr';
    const { RedisCircuitBreaker } = await import('../src/redis-circuit-breaker');
    const cb = new RedisCircuitBreaker({ failureThreshold: 2, windowMs: 5000, cooldownMs: 30000 });
    const store = new RedisCallCounterStore(fake, logger, { circuitBreaker: cb });

    // Trip the circuit
    await store.incrementAndGet('a', 60);
    await store.incrementAndGet('b', 60);
    expect(cb.getState()).toBe('open');

    // fast-fail → fail-closed → POSITIVE_INFINITY
    const result = await store.incrementAndGet('c', 60);
    expect(result).toBe(Number.POSITIVE_INFINITY);
  });
});

describe('RedisCallCounterStore local fallback', () => {
  it('delegates to local fallback when Redis errors and localFallback is configured', async () => {
    const fake = new FakeRedis();
    fake.errorOn = 'incr';
    const localFallback = new InMemoryCallCounterStore();
    const store = new RedisCallCounterStore(fake, logger, { localFallback });

    // Redis fails → uses local fallback
    const v1 = await store.incrementAndGet('cap', 60);
    expect(v1).toBe(1);
    const v2 = await store.incrementAndGet('cap', 60);
    expect(v2).toBe(2);
  });

  it('delegates to local fallback when circuit is open', async () => {
    const fake = new FakeRedis();
    fake.errorOn = 'incr';
    const { RedisCircuitBreaker } = await import('../src/redis-circuit-breaker');
    const cb = new RedisCircuitBreaker({ failureThreshold: 2, windowMs: 5000, cooldownMs: 30000 });
    const localFallback = new InMemoryCallCounterStore();
    const store = new RedisCallCounterStore(fake, logger, { circuitBreaker: cb, localFallback });

    // Trip the circuit
    await store.incrementAndGet('a', 60);
    await store.incrementAndGet('b', 60);
    expect(cb.getState()).toBe('open');

    // circuit open → use local fallback (counting continues, not denied)
    const v = await store.incrementAndGet('cap', 60);
    expect(v).toBe(1);
    expect(v).not.toBe(Number.POSITIVE_INFINITY);
  });

  it('onFallback fires on Redis error with localFallback', async () => {
    const fake = new FakeRedis();
    fake.errorOn = 'incr';
    const localFallback = new InMemoryCallCounterStore();
    const onFallback = jest.fn();
    const store = new RedisCallCounterStore(fake, logger, { localFallback, onFallback });

    await store.incrementAndGet('cap', 60);
    expect(onFallback).toHaveBeenCalledTimes(1);
  });

  it('onFallback fires on circuit-open even with no Redis error', async () => {
    const fake = new FakeRedis();
    fake.errorOn = 'incr';
    const { RedisCircuitBreaker } = await import('../src/redis-circuit-breaker');
    const cb = new RedisCircuitBreaker({ failureThreshold: 2, windowMs: 5000, cooldownMs: 30000 });
    const localFallback = new InMemoryCallCounterStore();
    const onFallback = jest.fn();
    const store = new RedisCallCounterStore(fake, logger, {
      circuitBreaker: cb,
      localFallback,
      onFallback,
    });

    // Trip the circuit (fires onFallback for each of these calls too)
    await store.incrementAndGet('a', 60);
    await store.incrementAndGet('b', 60);
    expect(cb.getState()).toBe('open');

    onFallback.mockClear();
    // Now circuit is open — no actual Redis error, just CircuitOpenError
    await store.incrementAndGet('cap', 60);
    // Should fire onFallback from the circuit-open path
    expect(onFallback).toHaveBeenCalledTimes(1);
  });

  it('onFallback does NOT fire when there is no localFallback (fail-closed path)', async () => {
    const fake = new FakeRedis();
    fake.errorOn = 'incr';
    const onFallback = jest.fn();
    const store = new RedisCallCounterStore(fake, logger, { onFallback });

    await store.incrementAndGet('cap', 60);
    // No localFallback configured — goes to fail-closed (POSITIVE_INFINITY), not fallback
    expect(onFallback).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Multi-replica simulation
// ---------------------------------------------------------------------------

describe('RedisCallCounterStore multi-replica simulation', () => {
  /**
   * Simulates two gateway replicas that share a single Redis instance.
   * Both replicas point their RedisCallCounterStore at the same FakeRedis
   * client, which is equivalent to pointing two real store instances at
   * the same Redis cluster.
   *
   * Correct behaviour: increments from replica A are immediately visible to
   * replica B because both stores issue INCR against the same shared Redis
   * backing store.
   */

  it('counters accumulate jointly across two replicas sharing a Redis store', async () => {
    const redis = new FakeRedis();
    const storeA = new RedisCallCounterStore(redis, logger, { keyPrefix: 'r:' });
    const storeB = new RedisCallCounterStore(redis, logger, { keyPrefix: 'r:' });

    // Replica A increments; counter becomes 1.
    expect(await storeA.incrementAndGet('cap', 60)).toBe(1);
    // Replica B increments the same key; counter becomes 2.
    expect(await storeB.incrementAndGet('cap', 60)).toBe(2);
    // Replica A increments again; counter becomes 3.
    expect(await storeA.incrementAndGet('cap', 60)).toBe(3);
    // Replica B sees counter at 4.
    expect(await storeB.incrementAndGet('cap', 60)).toBe(4);
  });

  it('exhausts a budget jointly: one call on each replica consumes the shared budget', async () => {
    const shared = { values: new Map<string, number>(), expiries: new Map<string, number>() };
    const storeA = new RedisCallCounterStore(new SharedFakeRedis(shared.values, shared.expiries), logger, { keyPrefix: 'r2:' });
    const storeB = new RedisCallCounterStore(new SharedFakeRedis(shared.values, shared.expiries), logger, { keyPrefix: 'r2:' });

    // maxCalls = 2; each replica contributes one call.
    const count1 = await storeA.incrementAndGet('budget', 60);
    const count2 = await storeB.incrementAndGet('budget', 60);

    // Both calls were within budget; values reflect the joint counter.
    expect(count1).toBe(1);
    expect(count2).toBe(2);

    // A third increment from either replica returns 3 — the caller
    // (EnforcementEngine) compares count > maxCalls and denies.
    const count3 = await storeA.incrementAndGet('budget', 60);
    expect(count3).toBe(3);
  });

  it('independent stores (different Redis) do NOT share counters', async () => {
    const sharedA = { values: new Map<string, number>(), expiries: new Map<string, number>() };
    const sharedB = { values: new Map<string, number>(), expiries: new Map<string, number>() };
    const storeA = new RedisCallCounterStore(new SharedFakeRedis(sharedA.values, sharedA.expiries), logger, { keyPrefix: 'ind:' });
    const storeB = new RedisCallCounterStore(new SharedFakeRedis(sharedB.values, sharedB.expiries), logger, { keyPrefix: 'ind:' });

    // Each store's counter starts independently at 1.
    expect(await storeA.incrementAndGet('cap', 60)).toBe(1);
    expect(await storeB.incrementAndGet('cap', 60)).toBe(1);
    // Second call on each store increments its own local counter only.
    expect(await storeA.incrementAndGet('cap', 60)).toBe(2);
    expect(await storeB.incrementAndGet('cap', 60)).toBe(2);
  });

  it('circuit-open on replica A does not trip circuit on replica B', async () => {
    const { RedisCircuitBreaker: CB } = await import('../src/redis-circuit-breaker');
    const shared = { values: new Map<string, number>(), expiries: new Map<string, number>() };
    const cbA = new CB({ failureThreshold: 1, windowMs: 5000, cooldownMs: 60000 });
    const cbB = new CB({ failureThreshold: 5, windowMs: 5000, cooldownMs: 60000 });

    const redisA = new SharedFakeRedis(shared.values, shared.expiries);
    const storeA = new RedisCallCounterStore(redisA, logger, { keyPrefix: 'cb:', circuitBreaker: cbA });

    const redisB = new SharedFakeRedis(shared.values, shared.expiries);
    const storeB = new RedisCallCounterStore(redisB, logger, { keyPrefix: 'cb:', circuitBreaker: cbB });

    // Trip replica A's circuit by making its Redis fail.
    redisA.errorMode = true;
    await storeA.incrementAndGet('key', 60); // trips cbA
    expect(cbA.getState()).toBe('open');

    // Replica B's circuit is independent and should still be closed.
    expect(cbB.getState()).toBe('closed');

    // Redis B is healthy, so replica B can still count.
    const v = await storeB.incrementAndGet('other', 60);
    expect(v).toBe(1);
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

  it('uses CALL_COUNTER_REDIS_URL in preference to REDIS_URL', async () => {
    // With neither ioredis nor a real Redis we should still get in-memory
    // (the env contains both URLs; factory picks CALL_COUNTER_REDIS_URL first)
    const store = await createCallCounterStoreFromEnv({
      REDIS_URL: 'redis://shared:6379',
      CALL_COUNTER_REDIS_URL: 'redis://dedicated:6379',
    }, logger);
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
