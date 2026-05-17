/**
 * Tests for `GET /api/v1/audit/records` — Task 7 (Stage 3)
 *
 * Tests cover:
 *  1. Authentication: missing token, invalid token, token without tenantId.
 *  2. Happy path: basic query returns correct shape.
 *  3. Pagination: cursor forwarding, direction, limit capping.
 *  4. Filter parameters: agentId, jti, decision, conditionType, denialCode,
 *     fromTs, toTs.
 *  5. Tenant scoping: results are always filtered to the caller's tenantId.
 *  6. Route absent when no ledger backend configured.
 *  7. Bad query parameters.
 */

import request from 'supertest';
import * as jose from 'jose';
import {
  AuditEvidence,
  SignedAuditEvidence,
  GENESIS_HASH,
  canonicalSha256,
  createLogger,
  DefaultKillSwitchManager,
  ServiceConfig,
  createMetricsRegistry,
  Counter,
  BUILTIN_ACTION_RESOLVER,
  CAPABILITY_TOKEN_SCHEMA_VERSION,
  CapabilityTokenPayload,
  getCurrentTimestamp,
  getExpirationTimestamp,
  LedgerBackend,
  LedgerEntry,
  AuditQueryFilter,
  AuditQueryPagination,
  AuditQueryPage,
} from '@euno/common';
import { createApp } from '../src/app-factory';
import { JWTTokenVerifier } from '../src/verifier';
import { EnforcementEngine } from '../src/enforcement';
import type { GatewayDependencies } from '../src/bootstrap';

// ── Shared RSA key pair ───────────────────────────────────────────────────────

let privateKey: jose.KeyLike;
let verifier: JWTTokenVerifier;

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeSignedEvidence(overrides: Partial<AuditEvidence> = {}): SignedAuditEvidence {
  const base: AuditEvidence = {
    id: `ev-${Math.random().toString(36).slice(2)}`,
    sessionId: 'sess-1',
    userId: 'user-1',
    promptHash: '0'.repeat(64),
    tool: 'api://crm/contacts',
    argsHash: '0'.repeat(64),
    nonce: 'nonce-1',
    ts: new Date().toISOString(),
    policyVersion: '0.1.0',
    agentId: 'agent-1',
    resource: 'api://crm/contacts',
    action: 'read',
    capabilityId: 'jti-1',
    decision: 'allow',
    tenantId: 'tenant-1',
    ...overrides,
  };
  return {
    ...base,
    signature: 'sig',
    keyId: 'kid',
    algorithm: 'RS256',
    previousHash: GENESIS_HASH,
    seq: 1,
  };
}

function makeLedgerEntry(ev: SignedAuditEvidence, seq: number): LedgerEntry {
  return {
    seq,
    previousHash: GENESIS_HASH,
    recordHash: canonicalSha256(ev),
    replicaId: 'replica-1',
    signedEvidence: ev,
    ts: ev.ts,
  };
}

/**
 * Build a mock `LedgerBackend` backed by a pre-populated list of entries.
 * `queryEntries` applies all filters in-memory (same logic as InMemoryLedgerBackend).
 */
function makeMockBackend(entries: LedgerEntry[]): LedgerBackend {
  // Inject entries directly into the in-memory backend via its public API
  // would require signing; instead we implement a thin mock that delegates
  // to the InMemoryLedgerBackend's queryEntries after pre-loading via the
  // internal entries array.
  // Since InMemoryLedgerBackend exposes `allEntries()` but no public write
  // API that bypasses signing, we build a lightweight inline stub.
  return {
    name: 'mock',
    async appendEntry(_evidence, _replicaId, _sign) {
      throw new Error('Not implemented');
    },
    async getChainTip() {
      const last = entries[entries.length - 1];
      return last ? { seq: last.seq, tipHash: last.recordHash } : null;
    },
    async getEntries(from, to) {
      return entries.filter((e) => e.seq >= from && e.seq <= to);
    },
    async queryEntries(filter: AuditQueryFilter, pagination: AuditQueryPagination): Promise<AuditQueryPage> {
      const limit = Math.min(pagination.limit ?? 50, 1000);
      const direction = pagination.direction ?? 'asc';

      let cursorSeq: number | undefined;
      if (pagination.cursor) {
        const parsed = parseInt(pagination.cursor, 10);
        if (!Number.isNaN(parsed)) cursorSeq = parsed;
      }

      let candidates = entries.filter((e) => {
        const ev = e.signedEvidence;
        if (filter.agentId !== undefined && ev.agentId !== filter.agentId) return false;
        if (filter.jti !== undefined && ev.capabilityId !== filter.jti) return false;
        if (filter.decision !== undefined && ev.decision !== filter.decision) return false;
        if (filter.tenantId !== undefined && ev.tenantId !== filter.tenantId) return false;
        if (filter.conditionType !== undefined && ev.conditionType !== filter.conditionType) return false;
        if (filter.denialCode !== undefined && ev.denialCode !== filter.denialCode) return false;
        if (filter.fromTs !== undefined && ev.ts < filter.fromTs) return false;
        if (filter.toTs !== undefined && ev.ts > filter.toTs) return false;
        return true;
      });

      if (direction === 'desc') candidates = [...candidates].reverse();

      if (cursorSeq !== undefined) {
        if (direction === 'asc') {
          candidates = candidates.filter((e) => e.seq > cursorSeq!);
        } else {
          candidates = candidates.filter((e) => e.seq < cursorSeq!);
        }
      }

      const page = candidates.slice(0, limit);
      const lastEntry = page[page.length - 1];
      const hasMore = candidates.length > limit;
      const nextCursor = hasMore && lastEntry ? String(lastEntry.seq) : undefined;

      return { entries: page, nextCursor };
    },
  };
}

async function buildDeps(opts?: {
  ledgerBackend?: LedgerBackend;
  customVerifier?: JWTTokenVerifier;
}): Promise<GatewayDependencies> {
  const logger = createLogger('audit-route-test');
  const killSwitchManager = new DefaultKillSwitchManager(logger);
  const usedVerifier = opts?.customVerifier ?? verifier;
  const enforcementEngine = new EnforcementEngine({
    verifier: usedVerifier,
    logger,
    killSwitchManager,
    dpop: { required: false },
  });

  const config: ServiceConfig = {
    name: 'tool-gateway',
    port: 0,
    environment: 'test' as ServiceConfig['environment'],
    enableCryptographicAudit: false,
    policyVersion: '0.1.0',
  };

  const metricsRegistry = createMetricsRegistry({
    serviceName: 'audit-route-test',
    collectDefaults: false,
  });

  const deps: GatewayDependencies = {
    config,
    logger,
    verifier: usedVerifier,
    enforcementEngine,
    killSwitchManager,
    backendServiceUrl: 'http://localhost:65535',
    allowedOrigins: [],
    rateLimitWindowMs: 60_000,
    rateLimitMax: 10_000,
    metricsRegistry,
    decisionsCounter: new Counter({
      name: `euno_gateway_decisions_total_audit_test_${Date.now()}`,
      help: 'test',
      labelNames: ['decision'],
      registers: [metricsRegistry],
    }),
    auditPipelineDrainTimeoutMs: 5_000,
    isReady: () => true,
    actionResolver: BUILTIN_ACTION_RESOLVER,
    adminPort: 0,
    responseRedactionMaxBytes: 1048576,
    ...(opts?.ledgerBackend ? { auditLedgerBackend: opts.ledgerBackend } : {}),
  };

  return deps;
}

/**
 * Sign a JWT with the shared private key. Always includes `authorizedBy.tenantId`
 * unless explicitly overridden.
 */
async function signToken(opts: {
  tenantId?: string | null;
  extra?: Partial<CapabilityTokenPayload>;
} = {}): Promise<string> {
  const { tenantId = 'tenant-1', extra = {} } = opts;
  const payload: CapabilityTokenPayload = {
    iss: 'did:web:test.com',
    sub: 'test-agent',
    aud: 'tool-gateway',
    iat: getCurrentTimestamp(),
    exp: getExpirationTimestamp(900),
    jti: `test-${Date.now()}-${Math.random()}`,
    schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
    capabilities: [],
    ...(tenantId !== null
      ? { authorizedBy: { userId: 'user-1', roles: [], tenantId } }
      : {}),
    ...extra,
  };

  return new jose.SignJWT(payload as unknown as jose.JWTPayload)
    .setProtectedHeader({ alg: 'RS256' })
    .sign(privateKey);
}

// ── Setup ─────────────────────────────────────────────────────────────────────

beforeAll(async () => {
  const { publicKey: pubKey, privateKey: privKey } = await jose.generateKeyPair('RS256');
  privateKey = privKey;
  const pubKeyStr = await jose.exportSPKI(pubKey);
  verifier = new JWTTokenVerifier(pubKeyStr, { requireKid: false });
});

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('GET /api/v1/audit/records — authentication', () => {
  it('returns 401 when no Authorization header is supplied', async () => {
    const ev = makeSignedEvidence();
    const backend = makeMockBackend([makeLedgerEntry(ev, 1)]);
    const deps = await buildDeps({ ledgerBackend: backend });
    const app = createApp(deps);

    const res = await request(app).get('/api/v1/audit/records');

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('AUTHENTICATION_FAILED');
  });

  it('returns 401 when the token is malformed', async () => {
    const backend = makeMockBackend([]);
    const deps = await buildDeps({ ledgerBackend: backend });
    const app = createApp(deps);

    const res = await request(app)
      .get('/api/v1/audit/records')
      .set('Authorization', 'Bearer not-a-jwt');

    expect(res.status).toBe(401);
  });

  it('returns 403 when the token has no tenantId', async () => {
    const backend = makeMockBackend([]);
    const deps = await buildDeps({ ledgerBackend: backend });
    const app = createApp(deps);

    // Token without authorizedBy (no tenantId)
    const token = await signToken({ tenantId: null });
    const res = await request(app)
      .get('/api/v1/audit/records')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(403);
  });
});

describe('GET /api/v1/audit/records — route availability', () => {
  it('returns 404 when no ledger backend is configured', async () => {
    // No auditLedgerBackend in deps → route is not mounted.
    const deps = await buildDeps();
    const app = createApp(deps);

    const token = await signToken();
    const res = await request(app)
      .get('/api/v1/audit/records')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(404);
  });
});

describe('GET /api/v1/audit/records — happy path', () => {
  it('returns a page of signedEvidence records', async () => {
    const ev = makeSignedEvidence({ tenantId: 'tenant-1', decision: 'allow' });
    const backend = makeMockBackend([makeLedgerEntry(ev, 1)]);
    const deps = await buildDeps({ ledgerBackend: backend });
    const app = createApp(deps);

    const token = await signToken({ tenantId: 'tenant-1' });
    const res = await request(app)
      .get('/api/v1/audit/records')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.records)).toBe(true);
    expect(res.body.records).toHaveLength(1);
    expect(res.body.records[0].id).toBe(ev.id);
    expect(res.body.nextCursor).toBeNull();
  });

  it('returns empty records array when ledger is empty', async () => {
    const backend = makeMockBackend([]);
    const deps = await buildDeps({ ledgerBackend: backend });
    const app = createApp(deps);

    const token = await signToken({ tenantId: 'tenant-1' });
    const res = await request(app)
      .get('/api/v1/audit/records')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.records).toHaveLength(0);
    expect(res.body.nextCursor).toBeNull();
  });

  it('does not expose rowHmac in the response', async () => {
    const ev = makeSignedEvidence({ tenantId: 'tenant-1' });
    const entry: LedgerEntry = {
      ...makeLedgerEntry(ev, 1),
      rowHmac: Buffer.from('raw-hmac'),
    };
    const backend = makeMockBackend([entry]);
    const deps = await buildDeps({ ledgerBackend: backend });
    const app = createApp(deps);

    const token = await signToken({ tenantId: 'tenant-1' });
    const res = await request(app)
      .get('/api/v1/audit/records')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    // The route returns `entry.signedEvidence`, not the full LedgerEntry.
    // rowHmac must not appear in the response body.
    for (const record of res.body.records as Record<string, unknown>[]) {
      expect(record['rowHmac']).toBeUndefined();
    }
  });
});

describe('GET /api/v1/audit/records — tenant scoping', () => {
  it('only returns records for the caller\'s tenant', async () => {
    const evTenant1 = makeSignedEvidence({ tenantId: 'tenant-1', agentId: 'agent-A' });
    const evTenant2 = makeSignedEvidence({ tenantId: 'tenant-2', agentId: 'agent-B' });
    const backend = makeMockBackend([
      makeLedgerEntry(evTenant1, 1),
      makeLedgerEntry(evTenant2, 2),
    ]);
    const deps = await buildDeps({ ledgerBackend: backend });
    const app = createApp(deps);

    const token = await signToken({ tenantId: 'tenant-1' });
    const res = await request(app)
      .get('/api/v1/audit/records')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.records).toHaveLength(1);
    expect((res.body.records as { agentId: string }[])[0]!.agentId).toBe('agent-A');
  });
});

describe('GET /api/v1/audit/records — filter parameters', () => {
  let backend: LedgerBackend;

  beforeAll(() => {
    const ts1 = '2025-01-01T00:00:00.000Z';
    const ts2 = '2025-06-01T00:00:00.000Z';
    const ts3 = '2025-12-31T23:59:59.000Z';

    const entries: LedgerEntry[] = [
      makeLedgerEntry(makeSignedEvidence({
        tenantId: 'tenant-1',
        agentId: 'agent-A',
        capabilityId: 'jti-A',
        decision: 'allow',
        ts: ts1,
      }), 1),
      makeLedgerEntry(makeSignedEvidence({
        tenantId: 'tenant-1',
        agentId: 'agent-B',
        capabilityId: 'jti-B',
        decision: 'deny',
        denialCode: 'NO_MATCHING_CAPABILITY',
        ts: ts2,
      }), 2),
      makeLedgerEntry(makeSignedEvidence({
        tenantId: 'tenant-1',
        agentId: 'agent-A',
        capabilityId: 'jti-C',
        decision: 'deny',
        conditionType: 'timeWindow',
        denialCode: 'CONDITION_FAILED',
        ts: ts3,
      }), 3),
    ];

    backend = makeMockBackend(entries);
  });

  it('filters by agentId', async () => {
    const deps = await buildDeps({ ledgerBackend: backend });
    const token = await signToken({ tenantId: 'tenant-1' });
    const res = await request(createApp(deps))
      .get('/api/v1/audit/records?agentId=agent-A')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.records).toHaveLength(2);
    for (const r of res.body.records as { agentId: string }[]) {
      expect(r.agentId).toBe('agent-A');
    }
  });

  it('filters by jti', async () => {
    const deps = await buildDeps({ ledgerBackend: backend });
    const token = await signToken({ tenantId: 'tenant-1' });
    const res = await request(createApp(deps))
      .get('/api/v1/audit/records?jti=jti-B')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.records).toHaveLength(1);
    expect((res.body.records as { capabilityId: string }[])[0]!.capabilityId).toBe('jti-B');
  });

  it('filters by decision=allow', async () => {
    const deps = await buildDeps({ ledgerBackend: backend });
    const token = await signToken({ tenantId: 'tenant-1' });
    const res = await request(createApp(deps))
      .get('/api/v1/audit/records?decision=allow')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.records).toHaveLength(1);
    expect((res.body.records as { decision: string }[])[0]!.decision).toBe('allow');
  });

  it('filters by decision=deny', async () => {
    const deps = await buildDeps({ ledgerBackend: backend });
    const token = await signToken({ tenantId: 'tenant-1' });
    const res = await request(createApp(deps))
      .get('/api/v1/audit/records?decision=deny')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.records).toHaveLength(2);
    for (const r of res.body.records as { decision: string }[]) {
      expect(r.decision).toBe('deny');
    }
  });

  it('filters by conditionType', async () => {
    const deps = await buildDeps({ ledgerBackend: backend });
    const token = await signToken({ tenantId: 'tenant-1' });
    const res = await request(createApp(deps))
      .get('/api/v1/audit/records?conditionType=timeWindow')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.records).toHaveLength(1);
    expect((res.body.records as { conditionType: string }[])[0]!.conditionType).toBe('timeWindow');
  });

  it('filters by denialCode', async () => {
    const deps = await buildDeps({ ledgerBackend: backend });
    const token = await signToken({ tenantId: 'tenant-1' });
    const res = await request(createApp(deps))
      .get('/api/v1/audit/records?denialCode=NO_MATCHING_CAPABILITY')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.records).toHaveLength(1);
    expect((res.body.records as { denialCode: string }[])[0]!.denialCode).toBe('NO_MATCHING_CAPABILITY');
  });

  it('filters by fromTs (inclusive lower bound)', async () => {
    const deps = await buildDeps({ ledgerBackend: backend });
    const token = await signToken({ tenantId: 'tenant-1' });
    const res = await request(createApp(deps))
      .get('/api/v1/audit/records?fromTs=2025-06-01T00:00:00.000Z')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.records).toHaveLength(2);
  });

  it('filters by toTs (inclusive upper bound)', async () => {
    const deps = await buildDeps({ ledgerBackend: backend });
    const token = await signToken({ tenantId: 'tenant-1' });
    const res = await request(createApp(deps))
      .get('/api/v1/audit/records?toTs=2025-06-01T00:00:00.000Z')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.records).toHaveLength(2);
  });

  it('combines agentId + decision filters (AND semantics)', async () => {
    const deps = await buildDeps({ ledgerBackend: backend });
    const token = await signToken({ tenantId: 'tenant-1' });
    const res = await request(createApp(deps))
      .get('/api/v1/audit/records?agentId=agent-A&decision=deny')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.records).toHaveLength(1);
    const rec = (res.body.records as { agentId: string; decision: string }[])[0]!;
    expect(rec.agentId).toBe('agent-A');
    expect(rec.decision).toBe('deny');
  });

  it('silently ignores an unrecognised decision value and returns all records', async () => {
    // Invalid decision values are silently ignored (treated as absent),
    // returning all decisions. The route only rejects malformed date strings.
    // Decision is parsed via parseEnum which returns undefined for invalid values.
    const deps = await buildDeps({ ledgerBackend: backend });
    const token = await signToken({ tenantId: 'tenant-1' });
    const res = await request(createApp(deps))
      .get('/api/v1/audit/records?decision=maybe')
      .set('Authorization', `Bearer ${token}`);

    // Invalid enum → filter ignored → all 3 records returned
    expect(res.status).toBe(200);
    expect(res.body.records).toHaveLength(3);
  });

  it('returns 400 for an invalid fromTs format', async () => {
    const deps = await buildDeps({ ledgerBackend: backend });
    const token = await signToken({ tenantId: 'tenant-1' });
    const res = await request(createApp(deps))
      .get('/api/v1/audit/records?fromTs=not-a-date')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(400);
  });

  it('returns 400 for an invalid toTs format', async () => {
    const deps = await buildDeps({ ledgerBackend: backend });
    const token = await signToken({ tenantId: 'tenant-1' });
    const res = await request(createApp(deps))
      .get('/api/v1/audit/records?toTs=2025-99-99')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(400);
  });
});

describe('GET /api/v1/audit/records — pagination', () => {
  let backend: LedgerBackend;
  const ALL_ENTRIES: LedgerEntry[] = [];

  beforeAll(() => {
    for (let i = 1; i <= 10; i++) {
      ALL_ENTRIES.push(
        makeLedgerEntry(makeSignedEvidence({ tenantId: 'tenant-1', agentId: `agent-${i}` }), i),
      );
    }
    backend = makeMockBackend(ALL_ENTRIES);
  });

  it('respects the limit parameter', async () => {
    const deps = await buildDeps({ ledgerBackend: backend });
    const token = await signToken({ tenantId: 'tenant-1' });
    const res = await request(createApp(deps))
      .get('/api/v1/audit/records?limit=3')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.records).toHaveLength(3);
    expect(res.body.nextCursor).not.toBeNull();
  });

  it('caps limit at 100', async () => {
    const deps = await buildDeps({ ledgerBackend: backend });
    const token = await signToken({ tenantId: 'tenant-1' });
    // request more than 100 — should be capped; 10 records available so
    // we just verify the response is still valid (no error).
    const res = await request(createApp(deps))
      .get('/api/v1/audit/records?limit=500')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    // The backend has 10 records, all within the cap.
    expect(res.body.records).toHaveLength(10);
    expect(res.body.nextCursor).toBeNull();
  });

  it('paginates through all records using nextCursor', async () => {
    const deps = await buildDeps({ ledgerBackend: backend });
    const token = await signToken({ tenantId: 'tenant-1' });
    const app = createApp(deps);

    const allRecords: unknown[] = [];
    let cursor: string | undefined;

    for (let page = 0; page < 5; page++) {
      const url = cursor
        ? `/api/v1/audit/records?limit=3&cursor=${cursor}`
        : '/api/v1/audit/records?limit=3';
      const res = await request(app)
        .get(url)
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      allRecords.push(...(res.body.records as unknown[]));
      cursor = res.body.nextCursor ?? undefined;
      if (!cursor) break;
    }

    // 10 records total with limit=3: pages of 3,3,3,1
    expect(allRecords).toHaveLength(10);
  });

  it('returns records in descending order when direction=desc', async () => {
    const deps = await buildDeps({ ledgerBackend: backend });
    const token = await signToken({ tenantId: 'tenant-1' });
    const res = await request(createApp(deps))
      .get('/api/v1/audit/records?limit=10&direction=desc')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    const records = res.body.records as { agentId: string }[];
    expect(records).toHaveLength(10);
    // Descending: last appended (seq=10, agent-10) should appear first.
    expect(records[0]!.agentId).toBe('agent-10');
    expect(records[9]!.agentId).toBe('agent-1');
  });

  it('returns no nextCursor when all records fit in one page', async () => {
    const deps = await buildDeps({ ledgerBackend: backend });
    const token = await signToken({ tenantId: 'tenant-1' });
    const res = await request(createApp(deps))
      .get('/api/v1/audit/records?limit=100')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.nextCursor).toBeNull();
  });
});
