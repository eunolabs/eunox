/**
 * Tests for the per-(tenant, user, agent, jti, ip) issuance rate limiter
 * (F-1, addresses I-1 in `docs/IMPROVEMENTS_AND_REFACTORING.md`).
 *
 * Covers three implementations:
 *  1. {@link InMemoryIssuanceRateLimiter} — single-process, for development
 *     and unit tests.
 *  2. {@link RedisIssuanceRateLimiter} — legacy Redis-backed implementation
 *     with its own ioredis client. Retained for backward compatibility.
 *  3. {@link CallCounterBackedIssuanceRateLimiter} — preferred production
 *     implementation backed by a {@link CallCounterStore} (same infrastructure
 *     as the gateway quota engine).
 */

import {
  InMemoryIssuanceRateLimiter,
  RedisIssuanceRateLimiter,
  RedisIssuanceRateLimitClient,
  CallCounterBackedIssuanceRateLimiter,
  buildIssuanceRateLimitKey,
  createIssuanceRateLimiterFromEnv,
  InMemoryCallCounterStore,
  createLogger,
} from '../src';

const logger = createLogger('test');

describe('buildIssuanceRateLimitKey', () => {
  it('produces a five-component key: tenantId|userId|agentId|jti|ip', () => {
    expect(
      buildIssuanceRateLimitKey({ tenantId: 't1', userId: 'u', agentId: 'a', jti: 'j', ip: '1.2.3.4' }),
    ).toBe('t1|u|a|j|1.2.3.4');
  });

  it('puts tenant first so a Redis prefix scan isolates a tenant', () => {
    const key = buildIssuanceRateLimitKey({ tenantId: 't1', userId: 'u', agentId: 'a' });
    expect(key.startsWith('t1|')).toBe(true);
  });

  it('falls back to a synthetic tenant bucket when tenantId is absent', () => {
    expect(buildIssuanceRateLimitKey({ userId: 'u', agentId: 'a' })).toBe(
      '_no_tenant|u|a|_no_jti|_no_ip',
    );
    expect(
      buildIssuanceRateLimitKey({ tenantId: '', userId: 'u', agentId: 'a' }),
    ).toBe('_no_tenant|u|a|_no_jti|_no_ip');
  });

  it('uses _no_jti sentinel for fresh issuance (no jti supplied)', () => {
    const key = buildIssuanceRateLimitKey({ tenantId: 't', userId: 'u', agentId: 'a' });
    expect(key).toBe('t|u|a|_no_jti|_no_ip');
  });

  it('uses _no_ip sentinel when ip is absent', () => {
    const key = buildIssuanceRateLimitKey({ tenantId: 't', userId: 'u', agentId: 'a', jti: 'j' });
    expect(key).toBe('t|u|a|j|_no_ip');
  });

  it('includes jti so attenuation/renewal use a per-lineage sub-budget', () => {
    const issueKey = buildIssuanceRateLimitKey({ tenantId: 't', userId: 'u', agentId: 'a' });
    const attenuateKey = buildIssuanceRateLimitKey({ tenantId: 't', userId: 'u', agentId: 'a', jti: 'parent-jti' });
    expect(issueKey).not.toBe(attenuateKey);
  });

  it('includes ip so each egress address gets its own sub-budget', () => {
    const ip1Key = buildIssuanceRateLimitKey({ tenantId: 't', userId: 'u', agentId: 'a', ip: '10.0.0.1' });
    const ip2Key = buildIssuanceRateLimitKey({ tenantId: 't', userId: 'u', agentId: 'a', ip: '10.0.0.2' });
    expect(ip1Key).not.toBe(ip2Key);
  });

  it('produces distinct keys for different (tenant, user, agent) tuples', () => {
    const k1 = buildIssuanceRateLimitKey({ tenantId: 't1', userId: 'u', agentId: 'a' });
    const k2 = buildIssuanceRateLimitKey({ tenantId: 't2', userId: 'u', agentId: 'a' });
    const k3 = buildIssuanceRateLimitKey({ tenantId: 't1', userId: 'u2', agentId: 'a' });
    const k4 = buildIssuanceRateLimitKey({ tenantId: 't1', userId: 'u', agentId: 'a2' });
    expect(new Set([k1, k2, k3, k4]).size).toBe(4);
  });

  it('escapes the `|` separator so components cannot collide (review fix)', () => {
    // Without escaping, these two distinct subjects collapsed to the
    // same key `t|u|v|a|...`, which an attacker controlling agentId could
    // weaponise to steal another subject's bucket.
    const collide1 = buildIssuanceRateLimitKey({ tenantId: 't', userId: 'u|v', agentId: 'a' });
    const collide2 = buildIssuanceRateLimitKey({ tenantId: 't', userId: 'u', agentId: 'v|a' });
    expect(collide1).not.toBe(collide2);
    // And the escape char itself is escaped, so `\|` in input cannot
    // forge a separator either.
    const escaped1 = buildIssuanceRateLimitKey({ tenantId: 't', userId: 'u\\', agentId: '|a' });
    const escaped2 = buildIssuanceRateLimitKey({ tenantId: 't', userId: 'u', agentId: '\\|a' });
    expect(escaped1).not.toBe(escaped2);
  });

  it('escapes pipe-separator in jti and ip components', () => {
    const k1 = buildIssuanceRateLimitKey({ tenantId: 't', userId: 'u', agentId: 'a', jti: 'j|evil', ip: '1.2.3.4' });
    const k2 = buildIssuanceRateLimitKey({ tenantId: 't', userId: 'u', agentId: 'a', jti: 'j', ip: 'evil|1.2.3.4' });
    expect(k1).not.toBe(k2);
  });
});

describe('InMemoryIssuanceRateLimiter', () => {
  it('allows up to `max` calls per window then denies', async () => {
    const limiter = new InMemoryIssuanceRateLimiter({ max: 3, windowSeconds: 60 });
    const subject = { tenantId: 't', userId: 'u', agentId: 'a' };
    const r1 = await limiter.consume(subject);
    const r2 = await limiter.consume(subject);
    const r3 = await limiter.consume(subject);
    const r4 = await limiter.consume(subject);
    expect(r1.allowed).toBe(true);
    expect(r1.remaining).toBe(2);
    expect(r2.allowed).toBe(true);
    expect(r2.remaining).toBe(1);
    expect(r3.allowed).toBe(true);
    expect(r3.remaining).toBe(0);
    expect(r4.allowed).toBe(false);
    expect(r4.limit).toBe(3);
    expect(r4.remaining).toBe(0);
    expect(r4.retryAfterSeconds).toBeGreaterThan(0);
  });

  it('isolates buckets per (tenant, user, agent) — no jti/ip supplied', async () => {
    const limiter = new InMemoryIssuanceRateLimiter({ max: 1, windowSeconds: 60 });
    expect((await limiter.consume({ tenantId: 't1', userId: 'u', agentId: 'a' })).allowed).toBe(true);
    expect((await limiter.consume({ tenantId: 't2', userId: 'u', agentId: 'a' })).allowed).toBe(true);
    expect((await limiter.consume({ tenantId: 't1', userId: 'u2', agentId: 'a' })).allowed).toBe(true);
    expect((await limiter.consume({ tenantId: 't1', userId: 'u', agentId: 'a2' })).allowed).toBe(true);
    // Hit the original bucket again -> over budget
    expect((await limiter.consume({ tenantId: 't1', userId: 'u', agentId: 'a' })).allowed).toBe(false);
  });

  it('isolates buckets per jti (fresh vs. lineage)', async () => {
    const limiter = new InMemoryIssuanceRateLimiter({ max: 1, windowSeconds: 60 });
    // fresh issuance (_no_jti)
    expect((await limiter.consume({ tenantId: 't', userId: 'u', agentId: 'a' })).allowed).toBe(true);
    // attenuation of a specific lineage — different jti → different bucket
    expect((await limiter.consume({ tenantId: 't', userId: 'u', agentId: 'a', jti: 'parent-1' })).allowed).toBe(true);
    // second fresh issuance exhausts its own bucket
    expect((await limiter.consume({ tenantId: 't', userId: 'u', agentId: 'a' })).allowed).toBe(false);
  });

  it('isolates buckets per ip', async () => {
    const limiter = new InMemoryIssuanceRateLimiter({ max: 1, windowSeconds: 60 });
    expect((await limiter.consume({ tenantId: 't', userId: 'u', agentId: 'a', ip: '10.0.0.1' })).allowed).toBe(true);
    expect((await limiter.consume({ tenantId: 't', userId: 'u', agentId: 'a', ip: '10.0.0.2' })).allowed).toBe(true);
    // Same (user, agent, ip) exhausted
    expect((await limiter.consume({ tenantId: 't', userId: 'u', agentId: 'a', ip: '10.0.0.1' })).allowed).toBe(false);
  });

  it('resets after the window elapses', async () => {
    const realNow = Date.now;
    let now = 1_000_000;
    Date.now = () => now;
    try {
      const limiter = new InMemoryIssuanceRateLimiter({ max: 1, windowSeconds: 1 });
      const s = { tenantId: 't', userId: 'u', agentId: 'a' };
      expect((await limiter.consume(s)).allowed).toBe(true);
      expect((await limiter.consume(s)).allowed).toBe(false);
      now += 2000;
      expect((await limiter.consume(s)).allowed).toBe(true);
    } finally {
      Date.now = realNow;
    }
  });

  it('reset() drops every bucket — primarily for test hygiene', async () => {
    const limiter = new InMemoryIssuanceRateLimiter({ max: 1, windowSeconds: 60 });
    await limiter.consume({ tenantId: 't', userId: 'u', agentId: 'a' });
    expect(limiter.size()).toBe(1);
    limiter.reset();
    expect(limiter.size()).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// CallCounterBackedIssuanceRateLimiter
// ---------------------------------------------------------------------------

describe('CallCounterBackedIssuanceRateLimiter', () => {
  it('allows up to max calls then denies', async () => {
    const store = new InMemoryCallCounterStore();
    const limiter = new CallCounterBackedIssuanceRateLimiter(store, { max: 2, windowSeconds: 60 }, logger);
    const s = { tenantId: 't', userId: 'u', agentId: 'a' };
    expect((await limiter.consume(s)).allowed).toBe(true);
    expect((await limiter.consume(s)).allowed).toBe(true);
    const denied = await limiter.consume(s);
    expect(denied.allowed).toBe(false);
    expect(denied.remaining).toBe(0);
    expect(denied.retryAfterSeconds).toBe(60);
  });

  it('prepends keyPrefix to the store key, so two limiters sharing a store but with different prefixes use independent buckets', async () => {
    // Both limiters share the same InMemoryCallCounterStore instance to prove
    // that prefix isolation is enforced by the limiter (not by using separate
    // stores).
    const store = new InMemoryCallCounterStore();
    const limiterA = new CallCounterBackedIssuanceRateLimiter(
      store,
      { max: 1, windowSeconds: 60, keyPrefix: 'prefix-a:' },
      logger,
    );
    const limiterB = new CallCounterBackedIssuanceRateLimiter(
      store,
      { max: 1, windowSeconds: 60, keyPrefix: 'prefix-b:' },
      logger,
    );
    const subject = { tenantId: 't', userId: 'u', agentId: 'a' };
    // limiterA's slot: allow once, then deny
    expect((await limiterA.consume(subject)).allowed).toBe(true);
    expect((await limiterA.consume(subject)).allowed).toBe(false);
    // limiterB's slot is independent (different prefix → different key in the shared store)
    expect((await limiterB.consume(subject)).allowed).toBe(true);
    expect((await limiterB.consume(subject)).allowed).toBe(false);
  });

  it('isolates buckets per (tenant, user, agent, jti, ip)', async () => {
    const store = new InMemoryCallCounterStore();
    const limiter = new CallCounterBackedIssuanceRateLimiter(store, { max: 1, windowSeconds: 60 }, logger);
    // Different jti → different bucket
    expect((await limiter.consume({ tenantId: 't', userId: 'u', agentId: 'a', jti: 'j1' })).allowed).toBe(true);
    expect((await limiter.consume({ tenantId: 't', userId: 'u', agentId: 'a', jti: 'j2' })).allowed).toBe(true);
    // Different ip → different bucket
    expect((await limiter.consume({ tenantId: 't', userId: 'u', agentId: 'a', jti: 'j1', ip: '1.2.3.4' })).allowed).toBe(true);
    // Same (jti, ip) is exhausted
    expect((await limiter.consume({ tenantId: 't', userId: 'u', agentId: 'a', jti: 'j1' })).allowed).toBe(false);
  });

  it('fails closed by default on CallCounterStore error (outage decision denies)', async () => {
    const brokenStore = {
      incrementAndGet: async (_key: string, _w: number) => {
        throw new Error('redis-down');
      },
    };
    const limiter = new CallCounterBackedIssuanceRateLimiter(
      brokenStore,
      { max: 5, windowSeconds: 30 },
      logger,
    );
    const decision = await limiter.consume({ tenantId: 't', userId: 'u', agentId: 'a' });
    expect(decision.allowed).toBe(false);
    expect(decision.retryAfterSeconds).toBe(30);
  });

  it('fails open when failClosedOnError=false on store error', async () => {
    const brokenStore = {
      incrementAndGet: async (_key: string, _w: number) => {
        throw new Error('redis-down');
      },
    };
    const limiter = new CallCounterBackedIssuanceRateLimiter(
      brokenStore,
      { max: 5, windowSeconds: 30, failClosedOnError: false },
      logger,
    );
    const decision = await limiter.consume({ tenantId: 't', userId: 'u', agentId: 'a' });
    expect(decision.allowed).toBe(true);
  });

  it('treats POSITIVE_INFINITY store response as unavailable (same as GatewayQuotaEngine)', async () => {
    const infiniteStore = {
      incrementAndGet: async (_key: string, _w: number) => Number.POSITIVE_INFINITY,
    };
    const limiter = new CallCounterBackedIssuanceRateLimiter(
      infiniteStore,
      { max: 5, windowSeconds: 30, failClosedOnError: true },
      logger,
    );
    const decision = await limiter.consume({ tenantId: 't', userId: 'u', agentId: 'a' });
    // failClosed=true → deny on backend-unavailable signal
    expect(decision.allowed).toBe(false);
  });

  it('treats POSITIVE_INFINITY as allow when failClosedOnError=false', async () => {
    const infiniteStore = {
      incrementAndGet: async (_key: string, _w: number) => Number.POSITIVE_INFINITY,
    };
    const limiter = new CallCounterBackedIssuanceRateLimiter(
      infiniteStore,
      { max: 5, windowSeconds: 30, failClosedOnError: false },
      logger,
    );
    const decision = await limiter.consume({ tenantId: 't', userId: 'u', agentId: 'a' });
    expect(decision.allowed).toBe(true);
  });
});

/**
 * Hand-rolled fake ioredis client. Reproduces just enough of `INCR` /
 * `EXPIRE` / `PTTL` for the limiter under test.
 */
class FakeRedis implements RedisIssuanceRateLimitClient {
  values = new Map<string, number>();
  expiries = new Map<string, number>();
  errorOn?: 'incr' | 'expire' | 'pttl';
  closed = false;

  async incr(key: string): Promise<number> {
    if (this.errorOn === 'incr') throw new Error('incr-failed');
    const next = (this.values.get(key) ?? 0) + 1;
    this.values.set(key, next);
    return next;
  }

  async expire(key: string, seconds: number): Promise<unknown> {
    if (this.errorOn === 'expire') throw new Error('expire-failed');
    this.expiries.set(key, Date.now() + seconds * 1000);
    return 1;
  }

  async pttl(key: string): Promise<number> {
    if (this.errorOn === 'pttl') throw new Error('pttl-failed');
    const exp = this.expiries.get(key);
    if (exp === undefined) return -1;
    return Math.max(0, exp - Date.now());
  }

  async quit(): Promise<unknown> {
    this.closed = true;
    return 'OK';
  }

  on(_event: string, _listener: (...args: unknown[]) => void): unknown {
    return this;
  }
}

describe('RedisIssuanceRateLimiter', () => {
  it('uses INCR + EXPIRE-on-first-touch under the configured prefix with 5-component key', async () => {
    const fake = new FakeRedis();
    const limiter = new RedisIssuanceRateLimiter(fake, logger, {
      max: 5,
      windowSeconds: 30,
      keyPrefix: 'issrl-test:',
    });
    const r1 = await limiter.consume({ tenantId: 't', userId: 'u', agentId: 'a' });
    expect(r1.allowed).toBe(true);
    // Key is now 5-component: t|u|a|_no_jti|_no_ip
    expect(fake.values.get('issrl-test:t|u|a|_no_jti|_no_ip')).toBe(1);
    expect(fake.expiries.has('issrl-test:t|u|a|_no_jti|_no_ip')).toBe(true);

    const r2 = await limiter.consume({ tenantId: 't', userId: 'u', agentId: 'a' });
    expect(r2.allowed).toBe(true);
    expect(r2.remaining).toBe(3);
  });

  it('uses distinct buckets for different jti values', async () => {
    const fake = new FakeRedis();
    const limiter = new RedisIssuanceRateLimiter(fake, logger, { max: 1, windowSeconds: 60 });
    // fresh issuance (_no_jti)
    await limiter.consume({ tenantId: 't', userId: 'u', agentId: 'a' });
    // lineage attenuation (jti=parent-jti) — separate bucket
    const lineageResult = await limiter.consume({ tenantId: 't', userId: 'u', agentId: 'a', jti: 'parent-jti' });
    expect(lineageResult.allowed).toBe(true);
    // two Redis keys were created
    expect(fake.values.size).toBe(2);
  });

  it('denies once the count exceeds max', async () => {
    const fake = new FakeRedis();
    const limiter = new RedisIssuanceRateLimiter(fake, logger, {
      max: 2,
      windowSeconds: 60,
    });
    const subject = { tenantId: 't', userId: 'u', agentId: 'a' };
    expect((await limiter.consume(subject)).allowed).toBe(true);
    expect((await limiter.consume(subject)).allowed).toBe(true);
    const denied = await limiter.consume(subject);
    expect(denied.allowed).toBe(false);
    expect(denied.limit).toBe(2);
    expect(denied.remaining).toBe(0);
    expect(denied.retryAfterSeconds).toBeGreaterThan(0);
  });

  it('falls back to the configured window when PTTL fails', async () => {
    const fake = new FakeRedis();
    const limiter = new RedisIssuanceRateLimiter(fake, logger, {
      max: 1,
      windowSeconds: 42,
    });
    const s = { tenantId: 't', userId: 'u', agentId: 'a' };
    await limiter.consume(s);
    fake.errorOn = 'pttl';
    const denied = await limiter.consume(s);
    expect(denied.allowed).toBe(false);
    expect(denied.retryAfterSeconds).toBe(42);
  });

  it('fails closed by default when Redis throws on INCR', async () => {
    const fake = new FakeRedis();
    fake.errorOn = 'incr';
    const limiter = new RedisIssuanceRateLimiter(fake, logger, {
      max: 5,
      windowSeconds: 30,
    });
    const decision = await limiter.consume({ tenantId: 't', userId: 'u', agentId: 'a' });
    expect(decision.allowed).toBe(false);
    expect(decision.retryAfterSeconds).toBe(30);
  });

  it('fails open (allowed=true) on Redis error when failClosedOnError=false', async () => {
    const fake = new FakeRedis();
    fake.errorOn = 'incr';
    const limiter = new RedisIssuanceRateLimiter(fake, logger, {
      max: 5,
      windowSeconds: 30,
      failClosedOnError: false,
    });
    const decision = await limiter.consume({ tenantId: 't', userId: 'u', agentId: 'a' });
    expect(decision.allowed).toBe(true);
    expect(decision.retryAfterSeconds).toBe(0);
  });

  it('close() shuts down the underlying client', async () => {
    const fake = new FakeRedis();
    const limiter = new RedisIssuanceRateLimiter(fake, logger);
    await limiter.close();
    expect(fake.closed).toBe(true);
  });
});

describe('createIssuanceRateLimiterFromEnv', () => {
  it('returns the in-memory limiter when REDIS_URL is unset', async () => {
    const l = await createIssuanceRateLimiterFromEnv({}, { logger });
    expect(l).toBeInstanceOf(InMemoryIssuanceRateLimiter);
  });

  it('honours custom max/window from env', async () => {
    const l = await createIssuanceRateLimiterFromEnv(
      { ISSUANCE_RATE_LIMIT_MAX: '2', ISSUANCE_RATE_LIMIT_WINDOW_SECONDS: '60' },
      { logger },
    );
    const s = { tenantId: 't', userId: 'u', agentId: 'a' };
    expect((await l.consume(s)).allowed).toBe(true);
    expect((await l.consume(s)).allowed).toBe(true);
    expect((await l.consume(s)).allowed).toBe(false);
  });

  it('returns CallCounterBackedIssuanceRateLimiter backed by an in-memory store when ioredis is missing', async () => {
    const l = await createIssuanceRateLimiterFromEnv(
      { REDIS_URL: 'redis://localhost:6379' },
      { logger },
    );
    // ioredis is not installed in the common package's test environment.
    // createCallCounterStoreFromEnv falls back to InMemoryCallCounterStore,
    // so the result is a CallCounterBackedIssuanceRateLimiter (not
    // InMemoryIssuanceRateLimiter) — the backing store is in-memory but
    // the outer wrapper is the CallCounterStore-backed implementation.
    expect(l).toBeInstanceOf(CallCounterBackedIssuanceRateLimiter);
    // Functional check: the in-memory store beneath it still works
    const s = { tenantId: 't', userId: 'u', agentId: 'a' };
    expect((await l.consume(s)).allowed).toBe(true);
  });
});
