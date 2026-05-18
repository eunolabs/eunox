/**
 * Tests for IssuerTelemetryCollector and extractTelemetryClaimsFromToken
 * (Stage 4, Task 10 — Telemetry continuity)
 */

import { IssuerTelemetryCollector, extractTelemetryClaimsFromToken } from '../src/issuer-telemetry';

// ---------------------------------------------------------------------------
// Fetch mock helper
// ---------------------------------------------------------------------------

interface CapturedEmission {
  installId: string;
  issuanceEvents: number;
  renewalEvents: number;
  distinctIssuingUsers: number;
  distinctRenewingUsers: number;
  subcommand: string;
  [k: string]: unknown;
}

function makeFetchCapture(): {
  captured: CapturedEmission[];
  restore: () => void;
} {
  const captured: CapturedEmission[] = [];
  const origFetch = (globalThis as Record<string, unknown>)['fetch'];

  (globalThis as Record<string, unknown>)['fetch'] = async (_url: unknown, init: unknown) => {
    const body = (init as { body?: string })?.body;
    if (body) captured.push(JSON.parse(body) as CapturedEmission);
    return { ok: true, status: 200 };
  };

  return {
    captured,
    restore: () => {
      (globalThis as Record<string, unknown>)['fetch'] = origFetch;
    },
  };
}

// ---------------------------------------------------------------------------
// extractTelemetryClaimsFromToken
// ---------------------------------------------------------------------------

function makeJwtWithClaims(payload: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: 'ES256' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${header}.${body}.fakesig`;
}

describe('extractTelemetryClaimsFromToken', () => {
  it('returns tenantId and userId from a well-formed capability token', () => {
    const token = makeJwtWithClaims({
      authorizedBy: { tenantId: 'acme-corp', userId: 'alice@acme.com' },
    });
    const { tenantId, userId } = extractTelemetryClaimsFromToken(token);
    expect(tenantId).toBe('acme-corp');
    expect(userId).toBe('alice@acme.com');
  });

  it('returns "unknown" when authorizedBy is absent', () => {
    const token = makeJwtWithClaims({ sub: 'agent-abc' });
    const { tenantId, userId } = extractTelemetryClaimsFromToken(token);
    expect(tenantId).toBe('unknown');
    expect(userId).toBe('unknown');
  });

  it('returns "unknown" for malformed JWT (not 3 parts)', () => {
    const { tenantId, userId } = extractTelemetryClaimsFromToken('not-a-jwt');
    expect(tenantId).toBe('unknown');
    expect(userId).toBe('unknown');
  });

  it('returns "unknown" when tenantId is empty string', () => {
    const token = makeJwtWithClaims({ authorizedBy: { tenantId: '', userId: 'alice' } });
    const { tenantId } = extractTelemetryClaimsFromToken(token);
    expect(tenantId).toBe('unknown');
  });

  it('returns "unknown" when token payload is not valid JSON', () => {
    const header = Buffer.from('{}').toString('base64url');
    const bad = Buffer.from('not-json-{{').toString('base64url');
    const { tenantId, userId } = extractTelemetryClaimsFromToken(`${header}.${bad}.sig`);
    expect(tenantId).toBe('unknown');
    expect(userId).toBe('unknown');
  });
});

// ---------------------------------------------------------------------------
// IssuerTelemetryCollector — disabled by default
// ---------------------------------------------------------------------------

describe('IssuerTelemetryCollector — disabled by default', () => {
  it('does not emit events when constructed with disabled=true', async () => {
    const fetchCapture = makeFetchCapture();
    try {
      const collector = new IssuerTelemetryCollector({ disabled: true });
      collector.recordIssuance('t1', 'alice@corp.com');
      collector.recordRenewal('t1', 'alice@corp.com');
      await collector.flush();
      expect(fetchCapture.captured).toHaveLength(0);
    } finally {
      fetchCapture.restore();
    }
  });
});

// ---------------------------------------------------------------------------
// IssuerTelemetryCollector — recording and flushing
// ---------------------------------------------------------------------------

describe('IssuerTelemetryCollector', () => {
  let fetchCapture: ReturnType<typeof makeFetchCapture>;

  beforeEach(() => {
    fetchCapture = makeFetchCapture();
  });

  afterEach(() => {
    fetchCapture.restore();
  });

  // ── recordIssuance / recordRenewal ────────────────────────────────────────

  it('flush() emits one event per active tenant after recordIssuance', async () => {
    const collector = new IssuerTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    collector.recordIssuance('acme', 'alice@acme.com');
    collector.recordIssuance('acme', 'bob@acme.com');
    await collector.flush();

    expect(fetchCapture.captured).toHaveLength(1);
    const evt = fetchCapture.captured[0]!;
    expect(evt.installId).toBe('tenant:acme');
    expect(evt.issuanceEvents).toBe(2);
    expect(evt.renewalEvents).toBe(0);
    expect(evt.subcommand).toBe('hosted-enforce');
  });

  it('flush() emits one event per active tenant after recordRenewal', async () => {
    const collector = new IssuerTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    collector.recordRenewal('t1', 'alice@corp.com');
    await collector.flush();

    expect(fetchCapture.captured).toHaveLength(1);
    expect(fetchCapture.captured[0]!.renewalEvents).toBe(1);
    expect(fetchCapture.captured[0]!.issuanceEvents).toBe(0);
  });

  it('flush() emits no event when no issuance or renewal has been recorded', async () => {
    const collector = new IssuerTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    await collector.flush();
    expect(fetchCapture.captured).toHaveLength(0);
  });

  // ── Tenant aggregation ────────────────────────────────────────────────────

  it('issuances from multiple users aggregate into a single tenant total', async () => {
    const collector = new IssuerTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    const users = ['alice', 'bob', 'carol', 'dave', 'eve'];
    for (const u of users) {
      collector.recordIssuance('acme', `${u}@acme.com`);
      collector.recordIssuance('acme', `${u}@acme.com`);
    }

    await collector.flush();

    const evt = fetchCapture.captured[0]!;
    expect(evt.issuanceEvents).toBe(10);       // 5 users × 2 issuances
    expect(evt.distinctIssuingUsers).toBe(5);   // cardinality
    // Privacy: no user identifiers in emitted payload
    expect(JSON.stringify(evt)).not.toContain('@acme.com');
  });

  it('tenants are isolated — issuances for different tenants produce separate events', async () => {
    const collector = new IssuerTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    collector.recordIssuance('tenant-a', 'user@a.com');
    collector.recordIssuance('tenant-a', 'user@a.com');
    collector.recordIssuance('tenant-b', 'user@b.com');

    await collector.flush();

    expect(fetchCapture.captured).toHaveLength(2);
    const evtA = fetchCapture.captured.find((e) => e.installId === 'tenant:tenant-a');
    const evtB = fetchCapture.captured.find((e) => e.installId === 'tenant:tenant-b');
    expect(evtA?.issuanceEvents).toBe(2);
    expect(evtB?.issuanceEvents).toBe(1);
  });

  it('distinctIssuingUsers reflects cardinality, not total count', async () => {
    const collector = new IssuerTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    for (let i = 0; i < 10; i++) {
      collector.recordIssuance('t1', 'power-user@corp.com');
    }
    collector.recordIssuance('t1', 'other-user@corp.com');

    await collector.flush();

    const evt = fetchCapture.captured[0]!;
    expect(evt.issuanceEvents).toBe(11);
    expect(evt.distinctIssuingUsers).toBe(2);
  });

  // ── flush() resets state ──────────────────────────────────────────────────

  it('flush() resets state so the next window starts fresh', async () => {
    const collector = new IssuerTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    collector.recordIssuance('t1', 'alice@corp.com');
    await collector.flush();
    expect(fetchCapture.captured).toHaveLength(1);

    // Second flush — nothing new, no event.
    await collector.flush();
    expect(fetchCapture.captured).toHaveLength(1);
  });

  // ── stop() flushes and is idempotent ─────────────────────────────────────

  it('stop() flushes pending state', async () => {
    const collector = new IssuerTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    collector.start(60_000);
    collector.recordIssuance('t1', 'alice@corp.com');
    await collector.stop();
    expect(fetchCapture.captured).toHaveLength(1);
  });

  it('stop() is idempotent', async () => {
    const collector = new IssuerTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    collector.start(60_000);
    collector.recordIssuance('t1', 'alice@corp.com');
    await collector.stop();
    await collector.stop(); // second stop should not throw or double-emit
    expect(fetchCapture.captured).toHaveLength(1);
  });

  // ── Network errors are swallowed ──────────────────────────────────────────

  it('flush() swallows network errors silently', async () => {
    fetchCapture.restore();
    (globalThis as Record<string, unknown>)['fetch'] = async () => {
      throw new Error('network failure');
    };
    const collector = new IssuerTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    collector.recordIssuance('t1', 'alice@corp.com');
    await expect(collector.flush()).resolves.toBeUndefined();
  });

  // ── Event schema matches GatewayTelemetryEvent ────────────────────────────

  it('emits events with subcommand=hosted-enforce and upstreamServerName=gateway', async () => {
    const collector = new IssuerTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    collector.recordIssuance('t1', 'alice@corp.com');
    await collector.flush();

    const evt = fetchCapture.captured[0]!;
    expect(evt.subcommand).toBe('hosted-enforce');
    expect(evt['upstreamServerName']).toBe('gateway');
    expect(typeof evt['nodeMajor']).toBe('number');
    expect(typeof evt['osFamily']).toBe('string');
    expect(typeof evt['timestamp']).toBe('number');
  });

  it('installId is "tenant:<tenantId>" (no user identifiers)', async () => {
    const collector = new IssuerTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    collector.recordIssuance('my-company', 'ceo@my-company.com');
    await collector.flush();

    const evt = fetchCapture.captured[0]!;
    expect(evt.installId).toBe('tenant:my-company');
    expect(JSON.stringify(evt)).not.toContain('ceo@my-company.com');
  });

  it('caps distinctIssuingUsers at 10000 to prevent unbounded memory growth', async () => {
    const collector = new IssuerTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    for (let i = 0; i < 10_001; i++) {
      collector.recordIssuance('t1', `user${i}@corp.com`);
    }
    await collector.flush();

    const evt = fetchCapture.captured[0]!;
    expect(evt.issuanceEvents).toBe(10_001);
    expect(evt.distinctIssuingUsers).toBe(10_000);
  });

  it('caps distinctRenewingUsers at 10000 to prevent unbounded memory growth', async () => {
    const collector = new IssuerTelemetryCollector({ endpointUrl: 'http://telemetry.test/v1' });
    for (let i = 0; i < 10_001; i++) {
      collector.recordRenewal('t1', `user${i}@corp.com`);
    }
    await collector.flush();

    const evt = fetchCapture.captured[0]!;
    expect(evt.renewalEvents).toBe(10_001);
    expect(evt.distinctRenewingUsers).toBe(10_000);
  });
});
