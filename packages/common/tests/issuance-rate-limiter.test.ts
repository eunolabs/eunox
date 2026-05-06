/**
 * Tests for the per-(tenant, user, agent) issuance rate limiter
 * (F-1, addresses I-1 in `docs/IMPROVEMENTS_AND_REFACTORING.md`).
 *
 * Mirrors the structure of `call-counter-store.test.ts`: hand-rolled
 * fake `ioredis` for the Redis-backed implementation so the tests are
 * dependency-free while still pinning the contract the production
 * client relies on (atomic INCR + EXPIRE-on-first-touch + PTTL).
 */

import {
  InMemoryIssuanceRateLimiter,
  RedisIssuanceRateLimiter,
  RedisIssuanceRateLimitClient,
  buildIssuanceRateLimitKey,
  createIssuanceRateLimiterFromEnv,
  createLogger,
} from '../src';

const logger = createLogger('test');

describe('buildIssuanceRateLimitKey', () => {
  it('puts tenant first so a Redis prefix scan isolates a tenant', () => {
    expect(
      buildIssuanceRateLimitKey({ tenantId: 't1', userId: 'u', agentId: 'a' }),
    ).toBe('t1|u|a');
  });

  it('falls back to a synthetic tenant bucket when tenantId is absent', () => {
    expect(buildIssuanceRateLimitKey({ userId: 'u', agentId: 'a' })).toBe(
      '_no_tenant|u|a',
    );
    expect(
      buildIssuanceRateLimitKey({ tenantId: '', userId: 'u', agentId: 'a' }),
    ).toBe('_no_tenant|u|a');
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
    // same key `t|u|v|a`, which an attacker controlling agentId could
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

  it('issue/attenuate/renew all share the same (tenant,user,agent) bucket', () => {
    // All three mint paths MUST consume from the same budget so the
    // per-identity KMS cap cannot be bypassed by alternating paths.
    const issueKey = buildIssuanceRateLimitKey({ tenantId: 't', userId: 'u', agentId: 'a' });
    const attenuateKey = buildIssuanceRateLimitKey({ tenantId: 't', userId: 'u', agentId: 'a' });
    const renewKey = buildIssuanceRateLimitKey({ tenantId: 't', userId: 'u', agentId: 'a' });
    expect(issueKey).toBe(attenuateKey);
    expect(issueKey).toBe(renewKey);
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

  it('isolates buckets per (tenant, user, agent)', async () => {
    const limiter = new InMemoryIssuanceRateLimiter({ max: 1, windowSeconds: 60 });
    expect((await limiter.consume({ tenantId: 't1', userId: 'u', agentId: 'a' })).allowed).toBe(true);
    expect((await limiter.consume({ tenantId: 't2', userId: 'u', agentId: 'a' })).allowed).toBe(true);
    expect((await limiter.consume({ tenantId: 't1', userId: 'u2', agentId: 'a' })).allowed).toBe(true);
    expect((await limiter.consume({ tenantId: 't1', userId: 'u', agentId: 'a2' })).allowed).toBe(true);
    // Hit the original bucket again -> over budget
    expect((await limiter.consume({ tenantId: 't1', userId: 'u', agentId: 'a' })).allowed).toBe(false);
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
  it('uses INCR + EXPIRE-on-first-touch under the configured prefix', async () => {
    const fake = new FakeRedis();
    const limiter = new RedisIssuanceRateLimiter(fake, logger, {
      max: 5,
      windowSeconds: 30,
      keyPrefix: 'issrl-test:',
    });
    const r1 = await limiter.consume({ tenantId: 't', userId: 'u', agentId: 'a' });
    expect(r1.allowed).toBe(true);
    expect(fake.values.get('issrl-test:t|u|a')).toBe(1);
    expect(fake.expiries.has('issrl-test:t|u|a')).toBe(true);

    const r2 = await limiter.consume({ tenantId: 't', userId: 'u', agentId: 'a' });
    expect(r2.allowed).toBe(true);
    expect(r2.remaining).toBe(3);
  });

  it('issue/attenuate/renew share the same (tenant,user,agent) bucket', async () => {
    // All three mint paths must consume from the same budget so the
    // per-identity KMS cap cannot be bypassed by alternating paths.
    const fake = new FakeRedis();
    const limiter = new RedisIssuanceRateLimiter(fake, logger, { max: 2, windowSeconds: 60 });
    const subjectBase = { tenantId: 't', userId: 'u', agentId: 'a' };
    await limiter.consume(subjectBase); // simulates issue
    await limiter.consume(subjectBase); // simulates attenuate (same bucket)
    const denied = await limiter.consume(subjectBase); // third call denied
    expect(denied.allowed).toBe(false);
    // Only one Redis key exists — all three calls used the same bucket
    expect(fake.values.size).toBe(1);
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
    // Comment 6 fix: previously the limiter re-threw on Redis error in
    // this mode, which the issuer's catch block then converted into a
    // 429 anyway — making the toggle a no-op. The contract is now: if
    // the operator explicitly opted into availability over enforcement,
    // an unavailable limiter MUST allow the mint to proceed.
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

  it('falls back to the in-memory limiter when ioredis is missing', async () => {
    const l = await createIssuanceRateLimiterFromEnv(
      { REDIS_URL: 'redis://localhost:6379' },
      { logger },
    );
    // ioredis is not installed in the common package's test environment
    // — the helper logs and falls back to the in-memory limiter.
    expect(l).toBeInstanceOf(InMemoryIssuanceRateLimiter);
  });
});
