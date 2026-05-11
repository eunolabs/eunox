/**
 * Task 4 — RedisCallCounterStore: multi-replica and circuit-open tests
 * -----------------------------------------------------------------------
 * These tests exercise the call-counter enforcement path at the gateway
 * level and explicitly verify the two behaviours mandated by Task 4:
 *
 *   1. **Multi-replica counter sharing** — two EnforcementEngine instances
 *      backed by the *same* underlying Redis store (simulated here by a shared
 *      FakeRedis) accumulate their counters jointly.  A capability that allows
 *      two calls total is exhausted after one call on replica A and one call
 *      on replica B, so replica B's second call is correctly denied.
 *
 *   2. **Circuit-open path** — when the Redis call-counter store's circuit
 *      breaker opens (after repeated Redis errors), the gateway must return
 *      the documented decision:
 *        - **fail-closed** (CALL_COUNTER_FAIL_OPEN=false, the default for the
 *          hosted offering): any request carrying a maxCalls condition is denied.
 *        - **fail-open** (CALL_COUNTER_FAIL_OPEN=true, the self-host override):
 *          falls back to the per-replica in-memory counter; the request is allowed
 *          with degraded (per-replica) counting rather than denied outright.
 *
 * The FakeRedis class is shared from this file to keep tests self-contained.
 * No real Redis process is needed.
 */

import { EnforcementEngine } from '../src/enforcement';
import { JWTTokenVerifier } from '../src/verifier';
import {
  CapabilityTokenPayload,
  CapabilityConstraint,
  getCurrentTimestamp,
  getExpirationTimestamp,
  CAPABILITY_TOKEN_SCHEMA_VERSION,
  createLogger,
  InMemoryCallCounterStore,
  RedisCallCounterStore,
  RedisCallCounterClient,
  RedisCircuitBreaker,
} from '@euno/common';
import * as jose from 'jose';

// ---------------------------------------------------------------------------
// Minimal FakeRedis — reproduces the ioredis surface that
// RedisCallCounterStore depends on.
// ---------------------------------------------------------------------------

class FakeRedis implements RedisCallCounterClient {
  /** Shared state across all FakeRedis instances that back the same key space. */
  readonly values: Map<string, number>;
  readonly expiries: Map<string, number>;

  /**
   * When `errorMode` is set, every INCR call throws a Redis error.
   * Use this to simulate a Redis outage and trip the circuit breaker.
   */
  errorMode = false;

  constructor(shared?: { values: Map<string, number>; expiries: Map<string, number> }) {
    this.values = shared?.values ?? new Map();
    this.expiries = shared?.expiries ?? new Map();
  }

  async incr(key: string): Promise<number> {
    if (this.errorMode) throw new Error('redis-unavailable');
    const v = (this.values.get(key) ?? 0) + 1;
    this.values.set(key, v);
    return v;
  }

  async expire(key: string, seconds: number): Promise<unknown> {
    if (this.errorMode) throw new Error('redis-unavailable');
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

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const logger = createLogger('test');

interface ReplicaSetup {
  engine: EnforcementEngine;
  store: RedisCallCounterStore;
  redis: FakeRedis;
}

/**
 * Build a gateway replica (enforcement engine + Redis-backed counter store)
 * that shares key-space with any other replica using the same
 * `sharedState`.  When `circuitBreaker` is provided it is installed on
 * the store; pass `localFallback` to simulate the fail-open path.
 */
async function buildReplica(
  verifier: JWTTokenVerifier,
  sharedState: { values: Map<string, number>; expiries: Map<string, number> },
  opts: {
    circuitBreaker?: RedisCircuitBreaker;
    localFallback?: InMemoryCallCounterStore;
    keyPrefix?: string;
  } = {},
): Promise<ReplicaSetup> {
  const redis = new FakeRedis(sharedState);
  const store = new RedisCallCounterStore(redis, logger, {
    keyPrefix: opts.keyPrefix ?? 'test:',
    circuitBreaker: opts.circuitBreaker,
    localFallback: opts.localFallback,
    // failClosedOnError defaults to true — that is the correct setting for the
    // hosted offering and is intentionally left as the default here.
  });

  const engine = new EnforcementEngine({
    dpop: { required: false },
    verifier,
    logger,
    callCounterStore: store,
  });

  return { engine, store, redis };
}

async function makeToken(
  capabilities: CapabilityConstraint[],
  privateKey: jose.KeyLike,
): Promise<string> {
  const payload: CapabilityTokenPayload = {
    iss: 'did:web:test.example',
    sub: 'test-agent',
    aud: 'tool-gateway',
    iat: getCurrentTimestamp(),
    exp: getExpirationTimestamp(900),
    jti: `jti-${Date.now()}-${Math.random()}`,
    schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
    capabilities,
  };
  return new jose.SignJWT(payload as unknown as jose.JWTPayload)
    .setProtectedHeader({ alg: 'RS256' })
    .sign(privateKey);
}

// ---------------------------------------------------------------------------
// Shared key pair for all test suites in this file
// ---------------------------------------------------------------------------

let privateKey: jose.KeyLike;
let publicKey: string;
let verifier: JWTTokenVerifier;

beforeAll(async () => {
  const kp = await jose.generateKeyPair('RS256');
  privateKey = kp.privateKey;
  publicKey = await jose.exportSPKI(kp.publicKey);
  verifier = new JWTTokenVerifier(publicKey, { requireKid: false });
});

// ===========================================================================
// 1. Multi-replica counter sharing
// ===========================================================================

describe('Task 4 — multi-replica counter sharing', () => {
  /**
   * Two replicas back their call-counter store with the same FakeRedis key
   * space (simulating a shared Redis cluster).  A capability with count=2
   * should be exhausted after one call on replica A and one call on replica B,
   * so the third call (on either replica) is denied.
   *
   * This is the core correctness requirement for cross-replica maxCalls
   * enforcement: without a shared backing store the effective cap would be
   * `count × replicaCount` — exactly the unsafe behaviour the Redis store
   * prevents.
   */
  it('jointly exhausts the call budget across two replicas sharing a Redis store', async () => {
    const sharedState = {
      values: new Map<string, number>(),
      expiries: new Map<string, number>(),
    };

    const replicaA = await buildReplica(verifier, sharedState);
    const replicaB = await buildReplica(verifier, sharedState);

    // Both replicas verify the same token (fresh jti each test run).
    const token = await makeToken(
      [{ resource: 'api://shared/resource', actions: ['read'], conditions: [{ type: 'maxCalls', count: 2, windowSeconds: 60 }] }],
      privateKey,
    );

    const req = { token, action: 'read', resource: 'api://shared/resource' };

    // Call 1 on replica A — within budget.
    const r1 = await replicaA.engine.validateAction(req);
    expect(r1.allowed).toBe(true);

    // Call 2 on replica B — still within budget, but counter now at 2 in Redis.
    const r2 = await replicaB.engine.validateAction(req);
    expect(r2.allowed).toBe(true);

    // Call 3 on either replica — budget exhausted; must be denied.
    const r3a = await replicaA.engine.validateAction(req);
    expect(r3a.allowed).toBe(false);
    expect(r3a.reason).toMatch(/maxCalls/);

    const r3b = await replicaB.engine.validateAction(req);
    expect(r3b.allowed).toBe(false);
    expect(r3b.reason).toMatch(/maxCalls/);
  });

  it('uses independent counters when two replicas have different Redis stores', async () => {
    // Two independent FakeRedis instances → two independent counter spaces.
    const stateA = { values: new Map<string, number>(), expiries: new Map<string, number>() };
    const stateB = { values: new Map<string, number>(), expiries: new Map<string, number>() };

    const replicaA = await buildReplica(verifier, stateA);
    const replicaB = await buildReplica(verifier, stateB);

    const token = await makeToken(
      [{ resource: 'api://isolated/resource', actions: ['read'], conditions: [{ type: 'maxCalls', count: 1, windowSeconds: 60 }] }],
      privateKey,
    );

    const req = { token, action: 'read', resource: 'api://isolated/resource' };

    // Each replica starts with a fresh counter so both accept the first call.
    const r1a = await replicaA.engine.validateAction(req);
    expect(r1a.allowed).toBe(true);

    const r1b = await replicaB.engine.validateAction(req);
    expect(r1b.allowed).toBe(true);

    // But each replica denies the second call against its own counter.
    const r2a = await replicaA.engine.validateAction(req);
    expect(r2a.allowed).toBe(false);

    const r2b = await replicaB.engine.validateAction(req);
    expect(r2b.allowed).toBe(false);
  });

  it('counter increments from replica A are immediately visible to replica B', async () => {
    const sharedState = {
      values: new Map<string, number>(),
      expiries: new Map<string, number>(),
    };

    const replicaA = await buildReplica(verifier, sharedState);
    const replicaB = await buildReplica(verifier, sharedState);

    const token = await makeToken(
      [{ resource: 'api://counting/resource', actions: ['write'], conditions: [{ type: 'maxCalls', count: 3, windowSeconds: 60 }] }],
      privateKey,
    );
    const req = { token, action: 'write', resource: 'api://counting/resource' };

    // Three calls spread across replicas — each increments the shared counter.
    await replicaA.engine.validateAction(req); // counter = 1
    await replicaB.engine.validateAction(req); // counter = 2
    await replicaA.engine.validateAction(req); // counter = 3

    // The next call on replica B must see the accumulated count and deny.
    const denied = await replicaB.engine.validateAction(req);
    expect(denied.allowed).toBe(false);
    expect(denied.reason).toMatch(/maxCalls/);
  });
});

// ===========================================================================
// 2. Circuit-open path — fail-closed (CALL_COUNTER_FAIL_OPEN=false, default)
// ===========================================================================

describe('Task 4 — circuit-open, fail-closed (hosted default)', () => {
  /**
   * When the circuit breaker opens after repeated Redis errors, and no local
   * fallback is configured (CALL_COUNTER_FAIL_OPEN=false), the gateway must
   * deny every request that carries a maxCalls condition.
   *
   * This is the correct default for the hosted offering: correctness (never
   * under-counting calls) takes precedence over availability.
   */
  it('denies maxCalls requests when the circuit is open and no fallback is configured', async () => {
    const sharedState = {
      values: new Map<string, number>(),
      expiries: new Map<string, number>(),
    };
    const cb = new RedisCircuitBreaker({ failureThreshold: 2, windowMs: 10_000, cooldownMs: 60_000 });
    const replica = await buildReplica(verifier, sharedState, { circuitBreaker: cb });

    // Make Redis fail so the circuit breaker trips.
    replica.redis.errorMode = true;
    await replica.store.incrementAndGet('trip:1', 60); // failure 1
    await replica.store.incrementAndGet('trip:2', 60); // failure 2 → circuit opens
    expect(cb.getState()).toBe('open');

    const token = await makeToken(
      [{ resource: 'api://cb/resource', actions: ['read'], conditions: [{ type: 'maxCalls', count: 100, windowSeconds: 60 }] }],
      privateKey,
    );

    // Even though the budget is generous (100 calls), the circuit is open and
    // no local fallback is wired → the engine must deny.
    const result = await replica.engine.validateAction({ token, action: 'read', resource: 'api://cb/resource' });
    expect(result.allowed).toBe(false);
    expect(result.reason).toMatch(/maxCalls/);
  });

  it('continues to deny while the circuit stays open', async () => {
    const sharedState = {
      values: new Map<string, number>(),
      expiries: new Map<string, number>(),
    };
    const cb = new RedisCircuitBreaker({ failureThreshold: 1, windowMs: 10_000, cooldownMs: 60_000 });
    const replica = await buildReplica(verifier, sharedState, { circuitBreaker: cb });

    replica.redis.errorMode = true;
    await replica.store.incrementAndGet('trip', 60); // trips the circuit
    expect(cb.getState()).toBe('open');

    const token = await makeToken(
      [{ resource: 'api://cb/persist', actions: ['read'], conditions: [{ type: 'maxCalls', count: 99, windowSeconds: 60 }] }],
      privateKey,
    );
    const req = { token, action: 'read', resource: 'api://cb/persist' };

    // Multiple consecutive calls must all be denied while the circuit is open.
    for (let i = 0; i < 5; i++) {
      const r = await replica.engine.validateAction(req);
      expect(r.allowed).toBe(false);
      expect(r.reason).toMatch(/maxCalls/);
    }
  });

  it('returns a decision with the expected denial reason when circuit is open', async () => {
    const sharedState = {
      values: new Map<string, number>(),
      expiries: new Map<string, number>(),
    };
    const cb = new RedisCircuitBreaker({ failureThreshold: 1, windowMs: 10_000, cooldownMs: 60_000 });
    const replica = await buildReplica(verifier, sharedState, { circuitBreaker: cb });

    replica.redis.errorMode = true;
    await replica.store.incrementAndGet('trip', 60);
    expect(cb.getState()).toBe('open');

    const token = await makeToken(
      [{ resource: 'api://cb/reason', actions: ['exec'], conditions: [{ type: 'maxCalls', count: 50, windowSeconds: 60 }] }],
      privateKey,
    );
    const result = await replica.engine.validateAction({ token, action: 'exec', resource: 'api://cb/reason' });

    expect(result.allowed).toBe(false);
    // The denial reason must identify the maxCalls condition so operators can
    // correlate with the Redis outage alert.
    expect(result.reason).toBeDefined();
    expect(result.reason).toMatch(/maxCalls/);
  });
});

// ===========================================================================
// 3. Circuit-open path — fail-open (CALL_COUNTER_FAIL_OPEN=true, self-host)
// ===========================================================================

describe('Task 4 — circuit-open, fail-open (self-host override)', () => {
  /**
   * When the circuit breaker opens and a local in-memory fallback is configured
   * (CALL_COUNTER_FAIL_OPEN=true), the gateway must continue allowing requests
   * using per-replica counting rather than denying them.
   *
   * This is the operator-overridable behaviour for self-hosted deployments
   * where Redis blips are more disruptive than temporarily relaxed rate limits.
   */
  it('allows requests using local per-replica counting when circuit is open and fail-open is configured', async () => {
    const sharedState = {
      values: new Map<string, number>(),
      expiries: new Map<string, number>(),
    };
    const cb = new RedisCircuitBreaker({ failureThreshold: 2, windowMs: 10_000, cooldownMs: 60_000 });
    const localFallback = new InMemoryCallCounterStore();
    const replica = await buildReplica(verifier, sharedState, { circuitBreaker: cb, localFallback });

    // Trip the circuit.
    replica.redis.errorMode = true;
    await replica.store.incrementAndGet('trip:1', 60); // failure 1
    await replica.store.incrementAndGet('trip:2', 60); // failure 2 → circuit opens
    expect(cb.getState()).toBe('open');

    const token = await makeToken(
      [{ resource: 'api://failopen/resource', actions: ['read'], conditions: [{ type: 'maxCalls', count: 3, windowSeconds: 60 }] }],
      privateKey,
    );
    const req = { token, action: 'read', resource: 'api://failopen/resource' };

    // Should succeed, falling back to local in-memory counting.
    const r1 = await replica.engine.validateAction(req);
    expect(r1.allowed).toBe(true);

    const r2 = await replica.engine.validateAction(req);
    expect(r2.allowed).toBe(true);

    const r3 = await replica.engine.validateAction(req);
    expect(r3.allowed).toBe(true);

    // Local budget exhausted on this replica.
    const r4 = await replica.engine.validateAction(req);
    expect(r4.allowed).toBe(false);
    expect(r4.reason).toMatch(/maxCalls/);
  });

  it('local fallback counting is independent per replica (effective cap = maxCalls × replicaCount)', async () => {
    // This test documents the known trade-off: during a Redis outage, each
    // replica tracks its own counter independently, so the effective call cap
    // across the fleet is maxCalls × replicaCount.  This is explicitly
    // acceptable for the self-host fail-open configuration.
    const sharedState = {
      values: new Map<string, number>(),
      expiries: new Map<string, number>(),
    };
    const cbA = new RedisCircuitBreaker({ failureThreshold: 1, windowMs: 10_000, cooldownMs: 60_000 });
    const cbB = new RedisCircuitBreaker({ failureThreshold: 1, windowMs: 10_000, cooldownMs: 60_000 });
    const fallbackA = new InMemoryCallCounterStore();
    const fallbackB = new InMemoryCallCounterStore();

    const replicaA = await buildReplica(verifier, sharedState, { circuitBreaker: cbA, localFallback: fallbackA });
    const replicaB = await buildReplica(verifier, sharedState, { circuitBreaker: cbB, localFallback: fallbackB });

    // Trip both circuits.
    replicaA.redis.errorMode = true;
    replicaB.redis.errorMode = true;
    await replicaA.store.incrementAndGet('trip', 60);
    await replicaB.store.incrementAndGet('trip', 60);
    expect(cbA.getState()).toBe('open');
    expect(cbB.getState()).toBe('open');

    const token = await makeToken(
      [{ resource: 'api://tradeoff/resource', actions: ['read'], conditions: [{ type: 'maxCalls', count: 1, windowSeconds: 60 }] }],
      privateKey,
    );
    const req = { token, action: 'read', resource: 'api://tradeoff/resource' };

    // Replica A's local counter starts at 0 → first call allowed.
    const r1a = await replicaA.engine.validateAction(req);
    expect(r1a.allowed).toBe(true);

    // Replica B's local counter also starts at 0 → first call on B also allowed
    // (effective cap is 2 = 1 × 2 replicas during an outage).
    const r1b = await replicaB.engine.validateAction(req);
    expect(r1b.allowed).toBe(true);

    // Second call on each replica exceeds the per-replica local budget.
    const r2a = await replicaA.engine.validateAction(req);
    expect(r2a.allowed).toBe(false);

    const r2b = await replicaB.engine.validateAction(req);
    expect(r2b.allowed).toBe(false);
  });
});

// ===========================================================================
// 4. Store closed — deny-by-default (no counter store wired)
// ===========================================================================

describe('Task 4 — deny-by-default when no counter store is wired', () => {
  /**
   * When no call-counter store is provided to the EnforcementEngine, any
   * token carrying a maxCalls condition must be denied rather than silently
   * allowed. This is the fail-closed baseline: missing infrastructure cannot
   * cause maxCalls conditions to be silently bypassed.
   */
  it('denies a maxCalls-conditioned request when no store is wired', async () => {
    const engine = new EnforcementEngine({
      dpop: { required: false },
      verifier,
      logger,
      // No callCounterStore wired.
    });

    const token = await makeToken(
      [{ resource: 'api://nostoreresource', actions: ['read'], conditions: [{ type: 'maxCalls', count: 99, windowSeconds: 60 }] }],
      privateKey,
    );

    const result = await engine.validateAction({ token, action: 'read', resource: 'api://nostoreresource' });
    expect(result.allowed).toBe(false);
    expect(result.reason).toMatch(/maxCalls/);
  });
});
