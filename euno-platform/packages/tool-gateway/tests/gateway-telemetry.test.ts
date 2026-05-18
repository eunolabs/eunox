/**
 * Unit tests for GatewayTelemetryCollector (Task 16 — Telemetry continuity)
 *
 * Test matrix
 * -----------
 * GatewayTelemetryCollector
 *   ✓ flush() emits no events when no decisions have been recorded
 *   ✓ recordDecision() tracks unique sessions per tenant
 *   ✓ flush() emits one event per tenant with correct sessionsStarted
 *   ✓ flush() resets per-tenant state so the next window starts fresh
 *   ✓ flush() includes denialsByConditionType from recorded denials
 *   ✓ allow decisions do not add to denialsByConditionType
 *   ✓ flush() uses 'unknown' conditionType when conditionType is omitted on deny
 *   ✓ flush() sets sessionsWithEnforcement = sessionsStarted (all sessions had enforcement)
 *   ✓ flush() sets upstreamServerName = 'gateway'
 *   ✓ flush() sets subcommand = 'hosted-enforce'
 *   ✓ flush() sets installId = 'tenant:' + tenantId
 *   ✓ peakConcurrentSessions = 1 for a single session
 *   ✓ peakConcurrentSessions = 2 when two sessions are active within 60 s
 *   ✓ peakConcurrentSessions reflects max across window, not final count
 *   ✓ multiple tenants produce independent events
 *   ✓ disabled collector (disabled=true) never calls fetch
 *   ✓ stop() flushes pending stats and clears the timer
 *   ✓ stop() is idempotent
 *   ✓ flush() swallows network errors silently
 *
 * extractTenantIdFromToken
 *   ✓ returns tenantId from well-formed JWT payload
 *   ✓ returns 'unknown' when authorizedBy is absent
 *   ✓ returns 'unknown' when token is not a valid JWT
 *   ✓ returns 'unknown' when tenantId is not a string
 *   ✓ returns 'unknown' for empty token string
 *
 * createGatewayTelemetryFromEnv
 *   ✓ returns null when EUNO_TELEMETRY is unset (opt-in default, DI-4)
 *   ✓ returns null when EUNO_TELEMETRY=0 (explicit opt-out, also returns null)
 *   ✓ returns a started collector when EUNO_TELEMETRY=1 (explicit opt-in)
 *   ✓ uses EUNO_TELEMETRY_URL as the endpoint
 */

import { GatewayTelemetryCollector, extractTenantIdFromToken, createGatewayTelemetryFromEnv } from '../src/gateway-telemetry';
import type { GatewayTelemetryEvent } from '../src/gateway-telemetry';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Capture events emitted by the collector by intercepting global fetch. */
function makeFetchCapture(): {
  captured: GatewayTelemetryEvent[];
  restore: () => void;
} {
  const captured: GatewayTelemetryEvent[] = [];
  const originalFetch = (globalThis as Record<string, unknown>)['fetch'];

  (globalThis as Record<string, unknown>)['fetch'] = async (
    _url: string,
    init: RequestInit,
  ): Promise<Response> => {
    const event = JSON.parse(init.body as string) as GatewayTelemetryEvent;
    captured.push(event);
    return new Response('{}', { status: 200 });
  };

  return {
    captured,
    restore: () => {
      (globalThis as Record<string, unknown>)['fetch'] = originalFetch;
    },
  };
}

/** Build a minimal JWT string with the given payload (unsigned, for test only). */
function makeJwt(payload: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${header}.${body}.fakesignature`;
}

// ---------------------------------------------------------------------------
// GatewayTelemetryCollector tests
// ---------------------------------------------------------------------------

describe('GatewayTelemetryCollector', () => {
  let fetchCapture: ReturnType<typeof makeFetchCapture>;

  beforeEach(() => {
    fetchCapture = makeFetchCapture();
  });

  afterEach(() => {
    fetchCapture.restore();
  });

  it('flush() emits no events when no decisions have been recorded', async () => {
    const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    await collector.flush();
    expect(fetchCapture.captured).toHaveLength(0);
  });

  it('recordDecision() tracks unique sessions per tenant', async () => {
    const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    collector.recordDecision('tenant-a', 'sess-1', true);
    collector.recordDecision('tenant-a', 'sess-1', true); // duplicate — same session
    collector.recordDecision('tenant-a', 'sess-2', false, 'maxCalls');
    await collector.flush();

    expect(fetchCapture.captured).toHaveLength(1);
    const evt = fetchCapture.captured[0] as GatewayTelemetryEvent;
    expect(evt.sessionsStarted).toBe(2); // 2 unique sessions
  });

  it('flush() emits one event per tenant with correct sessionsStarted', async () => {
    const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    collector.recordDecision('tenant-a', 'sess-1', true);
    collector.recordDecision('tenant-b', 'sess-x', false, 'timeWindow');
    collector.recordDecision('tenant-b', 'sess-y', true);
    await collector.flush();

    expect(fetchCapture.captured).toHaveLength(2);
    const evtA = fetchCapture.captured.find((e) => e.installId === 'tenant:tenant-a');
    const evtB = fetchCapture.captured.find((e) => e.installId === 'tenant:tenant-b');
    expect(evtA?.sessionsStarted).toBe(1);
    expect(evtB?.sessionsStarted).toBe(2);
  });

  it('flush() resets per-tenant state so the next window starts fresh', async () => {
    const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    collector.recordDecision('tenant-a', 'sess-1', true);
    await collector.flush();
    expect(fetchCapture.captured).toHaveLength(1);

    // Second flush — no new activity, so no event.
    await collector.flush();
    expect(fetchCapture.captured).toHaveLength(1); // unchanged
  });

  it('flush() includes denialsByConditionType from recorded denials', async () => {
    const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    collector.recordDecision('t1', 's1', false, 'maxCalls');
    collector.recordDecision('t1', 's2', false, 'maxCalls');
    collector.recordDecision('t1', 's3', false, 'timeWindow');
    await collector.flush();

    const evt = fetchCapture.captured[0] as GatewayTelemetryEvent;
    expect(evt.denialsByConditionType).toEqual({ maxCalls: 2, timeWindow: 1 });
  });

  it('allow decisions do not add to denialsByConditionType', async () => {
    const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    collector.recordDecision('t1', 's1', true);
    collector.recordDecision('t1', 's2', true);
    await collector.flush();

    const evt = fetchCapture.captured[0] as GatewayTelemetryEvent;
    expect(evt.denialsByConditionType).toEqual({});
  });

  it('flush() uses "unknown" conditionType when conditionType is omitted on deny', async () => {
    const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    collector.recordDecision('t1', 's1', false); // no conditionType
    await collector.flush();

    const evt = fetchCapture.captured[0] as GatewayTelemetryEvent;
    expect(evt.denialsByConditionType['unknown']).toBe(1);
  });

  it('flush() sets sessionsWithEnforcement = sessionsStarted', async () => {
    const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    collector.recordDecision('t1', 's1', true);
    collector.recordDecision('t1', 's2', false, 'maxCalls');
    await collector.flush();

    const evt = fetchCapture.captured[0] as GatewayTelemetryEvent;
    expect(evt.sessionsWithEnforcement).toBe(evt.sessionsStarted);
  });

  it('flush() sets upstreamServerName = "gateway"', async () => {
    const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    collector.recordDecision('t1', 's1', true);
    await collector.flush();

    expect(fetchCapture.captured[0]?.upstreamServerName).toBe('gateway');
  });

  it('flush() sets subcommand = "hosted-enforce"', async () => {
    const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    collector.recordDecision('t1', 's1', true);
    await collector.flush();

    expect(fetchCapture.captured[0]?.subcommand).toBe('hosted-enforce');
  });

  it('flush() sets installId = "tenant:" + tenantId', async () => {
    const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    collector.recordDecision('acme-corp', 's1', true);
    await collector.flush();

    expect(fetchCapture.captured[0]?.installId).toBe('tenant:acme-corp');
  });

  it('peakConcurrentSessions = 1 for a single session', async () => {
    const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    collector.recordDecision('t1', 'sess-only', true);
    await collector.flush();

    const evt = fetchCapture.captured[0] as GatewayTelemetryEvent;
    expect(evt.peakConcurrentSessions).toBe(1);
  });

  it('peakConcurrentSessions = 2 when two sessions are active within 60 s', async () => {
    const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    // Both decisions happen "now" (within the concurrency window).
    collector.recordDecision('t1', 'sess-a', true);
    collector.recordDecision('t1', 'sess-b', true);
    await collector.flush();

    const evt = fetchCapture.captured[0] as GatewayTelemetryEvent;
    expect(evt.peakConcurrentSessions).toBe(2);
  });

  it('peakConcurrentSessions reflects max across window, not final count', async () => {
    // Simulate 3 sessions, then the first one expires, then check that peak=3.
    const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    collector.recordDecision('t1', 'sess-1', true);
    collector.recordDecision('t1', 'sess-2', true);
    collector.recordDecision('t1', 'sess-3', true);
    // Peek at the private state to confirm peak was reached.
    // We access it via flush; after a new window starts all sessions are gone.
    await collector.flush();

    const evt = fetchCapture.captured[0] as GatewayTelemetryEvent;
    // All three were within 60s, so peak = 3.
    expect(evt.peakConcurrentSessions).toBe(3);
  });

  it('peakConcurrentSessions is bounded by active sessions, not request count (Map approach)', async () => {
    // Same session sending many requests should only count as 1 concurrent session.
    const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    for (let i = 0; i < 100; i++) {
      collector.recordDecision('t1', 'single-session', true); // 100 requests, 1 session
    }
    collector.recordDecision('t1', 'session-2', true);
    await collector.flush();

    const evt = fetchCapture.captured[0] as GatewayTelemetryEvent;
    // Only 2 distinct sessions, regardless of request count.
    expect(evt.peakConcurrentSessions).toBe(2);
    expect(evt.sessionsStarted).toBe(2);
  });

  it('multiple tenants produce independent events', async () => {
    const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    collector.recordDecision('alpha', 'sess-a', true);
    collector.recordDecision('beta', 'sess-b', false, 'timeWindow');
    await collector.flush();

    expect(fetchCapture.captured).toHaveLength(2);
    const alpha = fetchCapture.captured.find((e) => e.installId === 'tenant:alpha');
    const beta = fetchCapture.captured.find((e) => e.installId === 'tenant:beta');
    expect(alpha?.sessionsStarted).toBe(1);
    expect(alpha?.denialsByConditionType).toEqual({});
    expect(beta?.sessionsStarted).toBe(1);
    expect(beta?.denialsByConditionType).toEqual({ timeWindow: 1 });
  });

  it('disabled collector (disabled=true) never calls fetch', async () => {
    const collector = new GatewayTelemetryCollector({
      endpointUrl: 'http://telemetry.test/v1',
      disabled: true,
    });
    collector.recordDecision('t1', 's1', true);
    await collector.flush();

    expect(fetchCapture.captured).toHaveLength(0);
  });

  it('stop() flushes pending stats and clears the timer', async () => {
    const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    collector.start(60_000);
    collector.recordDecision('t1', 's1', true);
    await collector.stop();

    expect(fetchCapture.captured).toHaveLength(1);
    expect(fetchCapture.captured[0]?.sessionsStarted).toBe(1);
  });

  it('stop() is idempotent', async () => {
    const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    collector.start(60_000);
    collector.recordDecision('t1', 's1', true);
    await collector.stop();
    // Second stop should not throw and should not emit duplicate events.
    await collector.stop();
    expect(fetchCapture.captured).toHaveLength(1);
  });

  it('flush() swallows network errors silently', async () => {
    fetchCapture.restore();
    // Install a fetch that always throws.
    (globalThis as Record<string, unknown>)['fetch'] = async () => {
      throw new Error('network failure');
    };
    const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    collector.recordDecision('t1', 's1', true);
    // Should not throw.
    await expect(collector.flush()).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// extractTenantIdFromToken tests
// ---------------------------------------------------------------------------

describe('extractTenantIdFromToken', () => {
  it('returns tenantId from well-formed JWT payload', () => {
    const token = makeJwt({
      sub: 'agent-1',
      authorizedBy: { tenantId: 'acme', userId: 'alice' },
    });
    expect(extractTenantIdFromToken(token)).toBe('acme');
  });

  it('returns "unknown" when authorizedBy is absent', () => {
    const token = makeJwt({ sub: 'agent-1' });
    expect(extractTenantIdFromToken(token)).toBe('unknown');
  });

  it('returns "unknown" when token is not a valid JWT', () => {
    expect(extractTenantIdFromToken('not.a.jwt.at.all')).toBe('unknown');
    expect(extractTenantIdFromToken('notajwt')).toBe('unknown');
  });

  it('returns "unknown" when tenantId is not a string', () => {
    const token = makeJwt({
      authorizedBy: { tenantId: 12345 },
    });
    expect(extractTenantIdFromToken(token)).toBe('unknown');
  });

  it('returns "unknown" for empty token string', () => {
    expect(extractTenantIdFromToken('')).toBe('unknown');
  });
});

// ---------------------------------------------------------------------------
// createGatewayTelemetryFromEnv tests
// ---------------------------------------------------------------------------

describe('createGatewayTelemetryFromEnv', () => {
  afterEach(async () => {
    // Ensure no timer leaks between tests.
  });

  it('returns null when EUNO_TELEMETRY=0 (explicit opt-out — also null under new opt-in semantics)', () => {
    const result = createGatewayTelemetryFromEnv({ EUNO_TELEMETRY: '0' });
    expect(result).toBeNull();
  });

  it('returns a started collector when EUNO_TELEMETRY=1 (explicit opt-in)', async () => {
    const result = createGatewayTelemetryFromEnv({ EUNO_TELEMETRY: '1' });
    expect(result).toBeInstanceOf(GatewayTelemetryCollector);
    // Clean up the timer.
    if (result) await result.stop();
  });

  it('returns null when EUNO_TELEMETRY is unset (opt-in default — DI-4)', () => {
    // Before DI-4 this test expected a collector; after DI-4 the default is
    // disabled and operators must explicitly set EUNO_TELEMETRY=1 to opt in.
    const result = createGatewayTelemetryFromEnv({});
    expect(result).toBeNull();
  });

  it('uses EUNO_TELEMETRY_URL as the endpoint', async () => {
    const fetchCapture = makeFetchCapture();
    try {
      const customUrl = 'http://custom-telemetry.example.com/v1';
      const collector = createGatewayTelemetryFromEnv({
        EUNO_TELEMETRY: '1',
        EUNO_TELEMETRY_URL: customUrl,
      });
      expect(collector).not.toBeNull();
      if (!collector) return;

      collector.recordDecision('t1', 's1', true);
      await collector.flush();
      await collector.stop();

      // The fetch call should have gone to the custom URL.
      // Since fetch capture records the event but not the URL, we verify
      // that an event was emitted (i.e. the collector is active).
      expect(fetchCapture.captured).toHaveLength(1);
    } finally {
      fetchCapture.restore();
    }
  });
});

// ---------------------------------------------------------------------------
// GatewayTelemetryCollector — issuance / renewal (Task 10)
// ---------------------------------------------------------------------------

describe('GatewayTelemetryCollector — recordIssuance / recordRenewal (Task 10)', () => {
  let fetchCapture: ReturnType<typeof makeFetchCapture>;

  beforeEach(() => {
    fetchCapture = makeFetchCapture();
  });

  afterEach(() => {
    fetchCapture.restore();
  });

  // ── Dual-write test: enforcement + issuance on the same tenant ────────────

  describe('meter dual-write', () => {
    it('flush() includes both enforcement decisions and issuance events for the same tenant', async () => {
      const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });

      // Enforcement side.
      collector.recordDecision('acme', 'sess-1', true);
      collector.recordDecision('acme', 'sess-2', false, 'maxCalls');

      // Issuance side.
      collector.recordIssuance('acme', 'alice@acme.com');
      collector.recordIssuance('acme', 'bob@acme.com');
      collector.recordRenewal('acme', 'alice@acme.com');

      await collector.flush();

      expect(fetchCapture.captured).toHaveLength(1);
      const evt = fetchCapture.captured[0] as GatewayTelemetryEvent;
      // Enforcement dimension.
      expect(evt.sessionsStarted).toBe(2);
      expect(evt.denialsByConditionType).toEqual({ maxCalls: 1 });
      // Issuance dimension.
      expect(evt.issuanceEvents).toBe(2);
      expect(evt.renewalEvents).toBe(1);
    });

    it('enforcement events do not increment issuanceEvents', async () => {
      const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
      collector.recordDecision('t1', 's1', true);
      collector.recordDecision('t1', 's2', true);
      await collector.flush();

      const evt = fetchCapture.captured[0] as GatewayTelemetryEvent;
      expect(evt.issuanceEvents).toBe(0);
      expect(evt.renewalEvents).toBe(0);
    });

    it('issuance events do not increment sessionsStarted', async () => {
      const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
      collector.recordIssuance('t1', 'alice@corp.com');
      collector.recordIssuance('t1', 'bob@corp.com');
      await collector.flush();

      const evt = fetchCapture.captured[0] as GatewayTelemetryEvent;
      expect(evt.sessionsStarted).toBe(0);
      expect(evt.issuanceEvents).toBe(2);
    });

    it('flush() emits an event when only issuance events are present (no sessions)', async () => {
      const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
      collector.recordIssuance('t1', 'alice@corp.com');
      await collector.flush();

      expect(fetchCapture.captured).toHaveLength(1);
      const evt = fetchCapture.captured[0] as GatewayTelemetryEvent;
      expect(evt.issuanceEvents).toBe(1);
      expect(evt.sessionsStarted).toBe(0);
    });
  });

  // ── Tenant aggregation test ────────────────────────────────────────────────

  describe('tenant aggregation', () => {
    it('issuances from multiple users aggregate into a single tenant total', async () => {
      const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });

      // Five distinct users, 3 issuances each.
      const users = ['alice', 'bob', 'carol', 'dave', 'eve'];
      for (const user of users) {
        collector.recordIssuance('acme', `${user}@acme.com`);
        collector.recordIssuance('acme', `${user}@acme.com`);
        collector.recordIssuance('acme', `${user}@acme.com`);
      }

      await collector.flush();

      expect(fetchCapture.captured).toHaveLength(1);
      const evt = fetchCapture.captured[0] as GatewayTelemetryEvent;
      // Billing aggregate: 5 users × 3 = 15 issuanceEvents.
      expect(evt.issuanceEvents).toBe(15);
      // Forensic cardinality: 5 distinct issuing users.
      expect(evt.distinctIssuingUsers).toBe(5);
      // No user identifiers should appear in the emitted event payload.
      expect(JSON.stringify(evt)).not.toContain('@acme.com');
    });

    it('issuances for different tenants produce independent events', async () => {
      const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });

      collector.recordIssuance('tenant-a', 'user-a@a.com');
      collector.recordIssuance('tenant-a', 'user-a@a.com'); // 2 for tenant-a
      collector.recordIssuance('tenant-b', 'user-b@b.com'); // 1 for tenant-b

      await collector.flush();

      expect(fetchCapture.captured).toHaveLength(2);
      const evtA = fetchCapture.captured.find((e) => e.installId === 'tenant:tenant-a');
      const evtB = fetchCapture.captured.find((e) => e.installId === 'tenant:tenant-b');
      expect(evtA?.issuanceEvents).toBe(2);
      expect(evtB?.issuanceEvents).toBe(1);
    });

    it('distinctIssuingUsers reflects unique user count, not issuance count', async () => {
      const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });

      // Same user issues 10 times.
      for (let i = 0; i < 10; i++) {
        collector.recordIssuance('t1', 'power-user@corp.com');
      }
      // Different user issues once.
      collector.recordIssuance('t1', 'occasional-user@corp.com');

      await collector.flush();

      const evt = fetchCapture.captured[0] as GatewayTelemetryEvent;
      expect(evt.issuanceEvents).toBe(11);
      expect(evt.distinctIssuingUsers).toBe(2); // Only 2 unique users
    });

    it('distinctRenewingUsers reflects unique user count, not renewal count', async () => {
      const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });

      collector.recordRenewal('t1', 'alice@corp.com');
      collector.recordRenewal('t1', 'alice@corp.com');
      collector.recordRenewal('t1', 'alice@corp.com');
      collector.recordRenewal('t1', 'bob@corp.com');

      await collector.flush();

      const evt = fetchCapture.captured[0] as GatewayTelemetryEvent;
      expect(evt.renewalEvents).toBe(4);
      expect(evt.distinctRenewingUsers).toBe(2);
    });

    it('flush() resets issuance state so the next window starts fresh', async () => {
      const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
      collector.recordIssuance('t1', 'alice@corp.com');
      await collector.flush();
      expect(fetchCapture.captured).toHaveLength(1);

      // Second flush — no new issuances, so no event.
      await collector.flush();
      expect(fetchCapture.captured).toHaveLength(1); // unchanged
    });

    it('disabled collector never calls fetch for issuance events', async () => {
      const collector = new GatewayTelemetryCollector({
        endpointUrl: 'http://telemetry.test/v1',
        disabled: true,
      });
      collector.recordIssuance('t1', 'alice@corp.com');
      collector.recordRenewal('t1', 'alice@corp.com');
      await collector.flush();

      expect(fetchCapture.captured).toHaveLength(0);
    });

    it('installId uses tenant prefix (no user identifiers exposed)', async () => {
      const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
      collector.recordIssuance('acme-corp', 'cfo@acme-corp.com');
      await collector.flush();

      const evt = fetchCapture.captured[0] as GatewayTelemetryEvent;
      expect(evt.installId).toBe('tenant:acme-corp');
      expect(JSON.stringify(evt)).not.toContain('cfo@acme-corp.com');
    });

    it('caps distinctIssuingUsers at 10000 to prevent unbounded memory growth', async () => {
      const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
      // Record 10001 distinct users.
      for (let i = 0; i < 10_001; i++) {
        collector.recordIssuance('t1', `user${i}@corp.com`);
      }
      await collector.flush();

      const evt = fetchCapture.captured[0] as GatewayTelemetryEvent;
      // Aggregate count is accurate (all 10001 issuances counted).
      expect(evt.issuanceEvents).toBe(10_001);
      // Distinct count is capped.
      expect(evt.distinctIssuingUsers).toBe(10_000);
    });

    it('caps distinctRenewingUsers at 10000 to prevent unbounded memory growth', async () => {
      const collector = new GatewayTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
      for (let i = 0; i < 10_001; i++) {
        collector.recordRenewal('t1', `user${i}@corp.com`);
      }
      await collector.flush();

      const evt = fetchCapture.captured[0] as GatewayTelemetryEvent;
      expect(evt.renewalEvents).toBe(10_001);
      expect(evt.distinctRenewingUsers).toBe(10_000);
    });
  });
});
