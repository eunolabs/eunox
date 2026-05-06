/**
 * Tests for the per-(jti, action, resource) gateway quota engine
 * (F-1b, addresses I-1b in `docs/IMPROVEMENTS_AND_REFACTORING.md`).
 *
 * Uses the in-memory {@link CallCounterStore} so tests are
 * dependency-free while covering the contract the enforcement engine
 * relies on.
 */

import {
  buildGatewayQuotaKey,
  CallCounterBackedGatewayQuotaEngine,
  GATEWAY_QUOTA_KEY_PREFIX,
  GatewayQuotaKey,
  GatewayQuotaKeyComponents,
  InMemoryCallCounterStore,
  createLogger,
} from '../src';

const logger = createLogger('test');

// ---------------------------------------------------------------------------
// buildGatewayQuotaKey
// ---------------------------------------------------------------------------

describe('buildGatewayQuotaKey', () => {
  it('prepends the GATEWAY_QUOTA_KEY_PREFIX sentinel', () => {
    const k: GatewayQuotaKeyComponents = { jti: 'jti1', action: 'read', resource: 'tool://weather' };
    const key = buildGatewayQuotaKey(k);
    expect(key.startsWith(GATEWAY_QUOTA_KEY_PREFIX)).toBe(true);
  });

  it('produces distinct keys for different jti values', () => {
    const k1 = buildGatewayQuotaKey({ jti: 'jti-a', action: 'read', resource: 'r' });
    const k2 = buildGatewayQuotaKey({ jti: 'jti-b', action: 'read', resource: 'r' });
    expect(k1).not.toBe(k2);
  });

  it('produces distinct keys for different actions on the same token', () => {
    const k1 = buildGatewayQuotaKey({ jti: 'jti1', action: 'read', resource: 'r' });
    const k2 = buildGatewayQuotaKey({ jti: 'jti1', action: 'write', resource: 'r' });
    expect(k1).not.toBe(k2);
  });

  it('produces distinct keys for different resources', () => {
    const k1 = buildGatewayQuotaKey({ jti: 'jti1', action: 'read', resource: 'tool://weather' });
    const k2 = buildGatewayQuotaKey({ jti: 'jti1', action: 'read', resource: 'tool://calendar' });
    expect(k1).not.toBe(k2);
  });

  it('escapes pipe-separator in jti to prevent key injection', () => {
    const malicious = buildGatewayQuotaKey({ jti: 'jti|evil', action: 'read', resource: 'r' });
    const benign = buildGatewayQuotaKey({ jti: 'jtiXevil', action: 'read', resource: 'r' });
    expect(malicious).not.toBe(benign);
  });

  it('escapes pipe-separator in action', () => {
    const k1 = buildGatewayQuotaKey({ jti: 'j', action: 'read|write', resource: 'r' });
    const k2 = buildGatewayQuotaKey({ jti: 'j', action: 'read', resource: 'write|r' });
    expect(k1).not.toBe(k2);
  });

  it('escapes pipe-separator in resource', () => {
    const k1 = buildGatewayQuotaKey({ jti: 'j', action: 'read', resource: 'tool://a|b' });
    const k2 = buildGatewayQuotaKey({ jti: 'j', action: 'read|tool://a', resource: 'b' });
    expect(k1).not.toBe(k2);
  });
});

// ---------------------------------------------------------------------------
// CallCounterBackedGatewayQuotaEngine
// ---------------------------------------------------------------------------

function makeEngine(max = 3, windowSeconds = 60) {
  const store = new InMemoryCallCounterStore();
  const engine = new CallCounterBackedGatewayQuotaEngine(store, { max, windowSeconds, failOpen: true }, logger);
  return { engine, store };
}

const testKey: GatewayQuotaKey = { jti: 'jti-test', action: 'read', resource: 'tool://weather', agentSub: 'agent-1' };

describe('CallCounterBackedGatewayQuotaEngine', () => {
  it('allows up to max invocations then denies', async () => {
    const { engine } = makeEngine(2);
    const r1 = await engine.checkAndCount(testKey);
    const r2 = await engine.checkAndCount(testKey);
    const r3 = await engine.checkAndCount(testKey);
    expect(r1.allowed).toBe(true);
    expect(r1.remaining).toBe(1);
    expect(r2.allowed).toBe(true);
    expect(r2.remaining).toBe(0);
    expect(r3.allowed).toBe(false);
    expect(r3.limit).toBe(2);
    expect(r3.remaining).toBe(0);
    expect(r3.retryAfterSeconds).toBeGreaterThan(0);
  });

  it('exposes windowSeconds', () => {
    const { engine } = makeEngine(10, 120);
    expect(engine.windowSeconds).toBe(120);
  });

  it('isolates budgets by jti', async () => {
    const { engine } = makeEngine(1);
    const key1 = { jti: 'jti-1', action: 'read', resource: 'r', agentSub: 'agent-1' };
    const key2 = { jti: 'jti-2', action: 'read', resource: 'r', agentSub: 'agent-1' };
    await engine.checkAndCount(key1);
    const denied = await engine.checkAndCount(key1);
    expect(denied.allowed).toBe(false);
    const allowed = await engine.checkAndCount(key2);
    expect(allowed.allowed).toBe(true);
  });

  it('isolates budgets by action', async () => {
    const { engine } = makeEngine(1);
    const readKey = { jti: 'j', action: 'read', resource: 'r', agentSub: 'agent-1' };
    const writeKey = { jti: 'j', action: 'write', resource: 'r', agentSub: 'agent-1' };
    await engine.checkAndCount(readKey); // exhaust read budget
    const readDenied = await engine.checkAndCount(readKey);
    expect(readDenied.allowed).toBe(false);
    const writeAllowed = await engine.checkAndCount(writeKey);
    expect(writeAllowed.allowed).toBe(true); // write budget is independent
  });

  it('isolates budgets by resource', async () => {
    const { engine } = makeEngine(1);
    const weatherKey = { jti: 'j', action: 'read', resource: 'tool://weather', agentSub: 'agent-1' };
    const calendarKey = { jti: 'j', action: 'read', resource: 'tool://calendar', agentSub: 'agent-1' };
    await engine.checkAndCount(weatherKey);
    const weatherDenied = await engine.checkAndCount(weatherKey);
    expect(weatherDenied.allowed).toBe(false);
    const calendarAllowed = await engine.checkAndCount(calendarKey);
    expect(calendarAllowed.allowed).toBe(true);
  });

  it('passes agentSub to incrementAndGet for shard-local fast path', async () => {
    const calls: { agentSub: string | undefined }[] = [];
    const spyStore = {
      incrementAndGet: async (_key: string, _window: number, sub?: string) => {
        calls.push({ agentSub: sub });
        return 1;
      },
    };
    const engine = new CallCounterBackedGatewayQuotaEngine(spyStore, { max: 5, windowSeconds: 60 }, logger);
    await engine.checkAndCount({ jti: 'j', action: 'read', resource: 'r', agentSub: 'sub-123' });
    expect(calls[0]?.agentSub).toBe('sub-123');
  });

  describe('fail-open mode (default)', () => {
    it('allows the request when the store throws', async () => {
      const brokenStore = {
        incrementAndGet: async () => { throw new Error('store unavailable'); },
      };
      const engine = new CallCounterBackedGatewayQuotaEngine(
        brokenStore,
        { max: 5, windowSeconds: 60, failOpen: true },
        logger,
      );
      const result = await engine.checkAndCount(testKey);
      expect(result.allowed).toBe(true);
    });

    it('allows the request when the store returns POSITIVE_INFINITY (RedisCallCounterStore fail-closed sentinel)', async () => {
      // RedisCallCounterStore returns POSITIVE_INFINITY on Redis outage
      // instead of throwing when failClosedOnError=true (the default).
      // The quota engine must treat this as an outage and apply its own
      // fail-open / fail-closed policy rather than incorrectly denying.
      const infinityStore = {
        incrementAndGet: async () => Number.POSITIVE_INFINITY,
      };
      const engine = new CallCounterBackedGatewayQuotaEngine(
        infinityStore,
        { max: 5, windowSeconds: 60, failOpen: true },
        logger,
      );
      const result = await engine.checkAndCount(testKey);
      expect(result.allowed).toBe(true);
    });
  });

  describe('fail-closed mode', () => {
    it('denies the request when the store throws', async () => {
      const brokenStore = {
        incrementAndGet: async () => { throw new Error('store unavailable'); },
      };
      const engine = new CallCounterBackedGatewayQuotaEngine(
        brokenStore,
        { max: 5, windowSeconds: 60, failOpen: false },
        logger,
      );
      const result = await engine.checkAndCount(testKey);
      expect(result.allowed).toBe(false);
      expect(result.retryAfterSeconds).toBe(60);
    });

    it('denies when the store returns POSITIVE_INFINITY', async () => {
      const infinityStore = {
        incrementAndGet: async () => Number.POSITIVE_INFINITY,
      };
      const engine = new CallCounterBackedGatewayQuotaEngine(
        infinityStore,
        { max: 5, windowSeconds: 60, failOpen: false },
        logger,
      );
      const result = await engine.checkAndCount(testKey);
      expect(result.allowed).toBe(false);
      expect(result.retryAfterSeconds).toBe(60);
    });
  });
});
