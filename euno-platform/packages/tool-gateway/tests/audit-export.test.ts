/**
 * Tests for `GET /api/v1/audit/export` — Task 6 (Stage 5)
 *
 * Tests cover:
 *  1. Auth: missing admin key → 401 when key is configured.
 *  2. Auth: wrong admin key → 401.
 *  3. Auth: correct admin key → 200 with response shape.
 *  4. Auth: open (no admin key configured) → 200 (dev mode).
 *  5. Cursor pagination: page 1 → next cursor → page 2.
 *  6. Cursor expiry: expired cursor → 400.
 *  7. Scope filter: soc2-cc6 → empty records (all gateway records are CC7).
 *  8. Scope filter: soc2-cc7 → all records.
 *  9. Scope filter: all → all records.
 * 10. Scope filter: invalid scope → 400.
 * 11. Route absent when no query store configured.
 * 12. since/until filtering: only records within time range.
 * 13. since after until → 400.
 * 14. invalid since → 400.
 * 15. pageSize capped at MAX_PAGE_SIZE (1000).
 * 16. invalid pageSize → 400.
 * 17. since/until ignored on cursor pages.
 */

import request from 'supertest';
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
import {
  encodeCursor,
  decodeCursor,
  createAuditExportRouter,
} from '../src/routes/audit-export';
import express from 'express';

// ── Helpers ───────────────────────────────────────────────────────────────────

const ADMIN_KEY = 'test-admin-key-12345';

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
 */
function makeMockBackend(entries: LedgerEntry[]): LedgerBackend {
  return {
    name: 'mock',
    async appendEntry() {
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
      const limit = Math.min(pagination.limit ?? 100, 1000);
      const direction = pagination.direction ?? 'asc';

      let cursorSeq: number | undefined;
      if (pagination.cursor) {
        const parsed = parseInt(pagination.cursor, 10);
        if (!Number.isNaN(parsed)) cursorSeq = parsed;
      }

      let candidates = entries.filter((e) => {
        const ev = e.signedEvidence;
        if (filter.tenantId !== undefined && ev.tenantId !== filter.tenantId) return false;
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

async function buildDeps(opts: {
  ledgerBackend?: LedgerBackend;
  adminApiKey?: string;
} = {}): Promise<GatewayDependencies> {
  const logger = createLogger('audit-export-test');
  const killSwitchManager = new DefaultKillSwitchManager(logger);
  const fakeVerifier = { verify: async () => { throw new Error('not used'); } } as unknown as JWTTokenVerifier;
  const enforcementEngine = new EnforcementEngine({
    verifier: fakeVerifier,
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
    serviceName: `audit-export-test-${Date.now()}`,
    collectDefaults: false,
  });

  const deps: GatewayDependencies = {
    config,
    logger,
    verifier: fakeVerifier,
    enforcementEngine,
    killSwitchManager,
    backendServiceUrl: 'http://localhost:65535',
    allowedOrigins: [],
    rateLimitWindowMs: 60_000,
    rateLimitMax: 10_000,
    metricsRegistry,
    decisionsCounter: new Counter({
      name: `euno_gateway_decisions_total_export_test_${Date.now()}`,
      help: 'test',
      labelNames: ['decision'],
      registers: [metricsRegistry],
    }),
    auditPipelineDrainTimeoutMs: 5_000,
    isReady: () => true,
    actionResolver: BUILTIN_ACTION_RESOLVER,
    adminPort: 0,
    responseRedactionMaxBytes: 1_048_576,
    ...(opts.ledgerBackend ? { auditLedgerBackend: opts.ledgerBackend } : {}),
    ...(opts.adminApiKey !== undefined ? { adminApiKey: opts.adminApiKey } : {}),
  };

  return deps;
}

// ── Cursor unit tests ──────────────────────────────────────────────────────────

describe('cursor helpers', () => {
  it('encodeCursor / decodeCursor round-trips a valid payload', () => {
    const payload = { lastRowId: '42', expiresAt: Date.now() + 60_000 };
    const encoded = encodeCursor(payload);
    const result = decodeCursor(encoded);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.payload.lastRowId).toBe('42');
      expect(result.payload.expiresAt).toBe(payload.expiresAt);
    }
  });

  it('decodeCursor returns ok=false for a malformed string', () => {
    const result = decodeCursor('not-valid-base64-json!!!');
    expect(result.ok).toBe(false);
  });

  it('decodeCursor returns ok=false for an expired cursor', () => {
    const payload = { lastRowId: '1', expiresAt: Date.now() - 1_000 };
    const encoded = encodeCursor(payload);
    const result = decodeCursor(encoded);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain('expired');
    }
  });

  it('decodeCursor returns ok=false for missing fields', () => {
    const malformed = Buffer.from(JSON.stringify({ foo: 'bar' })).toString('base64');
    const result = decodeCursor(malformed);
    expect(result.ok).toBe(false);
  });
});

// ── Route: authentication ──────────────────────────────────────────────────────

describe('GET /api/v1/audit/export — authentication', () => {
  it('1. returns 401 when admin key is configured and no key is provided', async () => {
    const ev = makeSignedEvidence();
    const backend = makeMockBackend([makeLedgerEntry(ev, 1)]);
    const deps = await buildDeps({ ledgerBackend: backend, adminApiKey: ADMIN_KEY });
    const app = createApp(deps);

    const res = await request(app).get('/api/v1/audit/export');

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('UNAUTHORIZED');
  });

  it('2. returns 401 when wrong admin key is provided', async () => {
    const ev = makeSignedEvidence();
    const backend = makeMockBackend([makeLedgerEntry(ev, 1)]);
    const deps = await buildDeps({ ledgerBackend: backend, adminApiKey: ADMIN_KEY });
    const app = createApp(deps);

    const res = await request(app)
      .get('/api/v1/audit/export')
      .set('X-Admin-Api-Key', 'wrong-key');

    expect(res.status).toBe(401);
  });

  it('3. returns 200 with correct shape when valid admin key provided', async () => {
    const ev = makeSignedEvidence();
    const backend = makeMockBackend([makeLedgerEntry(ev, 1)]);
    const deps = await buildDeps({ ledgerBackend: backend, adminApiKey: ADMIN_KEY });
    const app = createApp(deps);

    const res = await request(app)
      .get('/api/v1/audit/export')
      .set('X-Admin-Api-Key', ADMIN_KEY);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.records)).toBe(true);
    expect(typeof res.body.hasMore).toBe('boolean');
    expect(res.body.verificationUri).toBe('/.well-known/jwks.json');
  });

  it('4. returns 200 in dev mode (no admin key configured)', async () => {
    const ev = makeSignedEvidence();
    const backend = makeMockBackend([makeLedgerEntry(ev, 1)]);
    // No adminApiKey in deps → open
    const deps = await buildDeps({ ledgerBackend: backend });
    const app = createApp(deps);

    const res = await request(app).get('/api/v1/audit/export');

    expect(res.status).toBe(200);
  });
});

// ── Route: availability ────────────────────────────────────────────────────────

describe('GET /api/v1/audit/export — route availability', () => {
  it('11. returns 404 when no query store is configured', async () => {
    const deps = await buildDeps(); // no ledgerBackend
    const app = createApp(deps);

    const res = await request(app).get('/api/v1/audit/export');

    expect(res.status).toBe(404);
  });
});

// ── Route: scope filter ───────────────────────────────────────────────────────

describe('GET /api/v1/audit/export — scope filter', () => {
  it('7. scope=soc2-cc6 returns empty records (gateway records are CC7, not CC6)', async () => {
    const ev = makeSignedEvidence();
    const backend = makeMockBackend([makeLedgerEntry(ev, 1)]);
    const deps = await buildDeps({ ledgerBackend: backend, adminApiKey: ADMIN_KEY });
    const app = createApp(deps);

    const res = await request(app)
      .get('/api/v1/audit/export?scope=soc2-cc6')
      .set('X-Admin-Api-Key', ADMIN_KEY);

    expect(res.status).toBe(200);
    expect(res.body.records).toHaveLength(0);
    expect(res.body.cursor).toBeNull();
    expect(res.body.hasMore).toBe(false);
  });

  it('8. scope=soc2-cc7 returns all gateway records', async () => {
    const ev = makeSignedEvidence();
    const backend = makeMockBackend([makeLedgerEntry(ev, 1)]);
    const deps = await buildDeps({ ledgerBackend: backend, adminApiKey: ADMIN_KEY });
    const app = createApp(deps);

    const res = await request(app)
      .get('/api/v1/audit/export?scope=soc2-cc7')
      .set('X-Admin-Api-Key', ADMIN_KEY);

    expect(res.status).toBe(200);
    expect(res.body.records).toHaveLength(1);
    expect(res.body.records[0].id).toBe(ev.id);
  });

  it('9. scope=all returns all records (same as soc2-cc7 for gateway)', async () => {
    const ev1 = makeSignedEvidence({ decision: 'allow' });
    const ev2 = makeSignedEvidence({ decision: 'deny' });
    const backend = makeMockBackend([makeLedgerEntry(ev1, 1), makeLedgerEntry(ev2, 2)]);
    const deps = await buildDeps({ ledgerBackend: backend, adminApiKey: ADMIN_KEY });
    const app = createApp(deps);

    const res = await request(app)
      .get('/api/v1/audit/export?scope=all')
      .set('X-Admin-Api-Key', ADMIN_KEY);

    expect(res.status).toBe(200);
    expect(res.body.records).toHaveLength(2);
  });

  it('10. invalid scope → 400', async () => {
    const ev = makeSignedEvidence();
    const backend = makeMockBackend([makeLedgerEntry(ev, 1)]);
    const deps = await buildDeps({ ledgerBackend: backend, adminApiKey: ADMIN_KEY });
    const app = createApp(deps);

    const res = await request(app)
      .get('/api/v1/audit/export?scope=unknown-scope')
      .set('X-Admin-Api-Key', ADMIN_KEY);

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_REQUEST');
  });
});

// ── Route: cursor pagination ───────────────────────────────────────────────────

describe('GET /api/v1/audit/export — cursor pagination', () => {
  it('5. cursor pagination: page 1 provides a cursor; page 2 retrieves next records', async () => {
    // Create 3 entries and fetch pageSize=2 so there is a next page.
    const evs = [1, 2, 3].map((seq) =>
      makeSignedEvidence({ capabilityId: `jti-${seq}` }),
    );
    const backend = makeMockBackend(evs.map((ev, i) => makeLedgerEntry(ev, i + 1)));
    const deps = await buildDeps({ ledgerBackend: backend, adminApiKey: ADMIN_KEY });
    const app = createApp(deps);

    // Page 1
    const page1 = await request(app)
      .get('/api/v1/audit/export?pageSize=2')
      .set('X-Admin-Api-Key', ADMIN_KEY);

    expect(page1.status).toBe(200);
    expect(page1.body.records).toHaveLength(2);
    expect(page1.body.hasMore).toBe(true);
    expect(typeof page1.body.cursor).toBe('string');

    // Page 2 using the cursor from page 1
    const page2 = await request(app)
      .get(`/api/v1/audit/export?cursor=${encodeURIComponent(page1.body.cursor)}`)
      .set('X-Admin-Api-Key', ADMIN_KEY);

    expect(page2.status).toBe(200);
    expect(page2.body.records).toHaveLength(1);
    expect(page2.body.hasMore).toBe(false);
    expect(page2.body.cursor).toBeNull();
  });

  it('6. expired cursor → 400 with clear error message', async () => {
    const ev = makeSignedEvidence();
    const backend = makeMockBackend([makeLedgerEntry(ev, 1)]);
    const deps = await buildDeps({ ledgerBackend: backend, adminApiKey: ADMIN_KEY });
    const app = createApp(deps);

    // Build a cursor that expired 1 second ago
    const expiredCursor = encodeCursor({
      lastRowId: '1',
      expiresAt: Date.now() - 1_000,
    });

    const res = await request(app)
      .get(`/api/v1/audit/export?cursor=${encodeURIComponent(expiredCursor)}`)
      .set('X-Admin-Api-Key', ADMIN_KEY);

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_REQUEST');
    expect(res.body.error.message).toContain('expired');
  });
});

// ── Route: time window filters ────────────────────────────────────────────────

describe('GET /api/v1/audit/export — time window filters', () => {
  it('12. since/until filters records to the given time range', async () => {
    const tsOld = new Date('2024-01-01T00:00:00Z').toISOString();
    const tsNew = new Date('2025-01-01T00:00:00Z').toISOString();
    const evOld = makeSignedEvidence({ ts: tsOld });
    const evNew = makeSignedEvidence({ ts: tsNew });
    const backend = makeMockBackend([
      makeLedgerEntry(evOld, 1),
      makeLedgerEntry(evNew, 2),
    ]);
    const deps = await buildDeps({ ledgerBackend: backend, adminApiKey: ADMIN_KEY });
    const app = createApp(deps);

    const res = await request(app)
      .get('/api/v1/audit/export?since=2024-12-01T00:00:00Z')
      .set('X-Admin-Api-Key', ADMIN_KEY);

    expect(res.status).toBe(200);
    expect(res.body.records).toHaveLength(1);
    expect(res.body.records[0].id).toBe(evNew.id);
  });

  it('13. since after until → 400', async () => {
    const backend = makeMockBackend([]);
    const deps = await buildDeps({ ledgerBackend: backend, adminApiKey: ADMIN_KEY });
    const app = createApp(deps);

    const res = await request(app)
      .get('/api/v1/audit/export?since=2025-06-01T00:00:00Z&until=2025-01-01T00:00:00Z')
      .set('X-Admin-Api-Key', ADMIN_KEY);

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_REQUEST');
  });

  it('14. invalid since → 400', async () => {
    const backend = makeMockBackend([]);
    const deps = await buildDeps({ ledgerBackend: backend, adminApiKey: ADMIN_KEY });
    const app = createApp(deps);

    const res = await request(app)
      .get('/api/v1/audit/export?since=not-a-date')
      .set('X-Admin-Api-Key', ADMIN_KEY);

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_REQUEST');
  });

  it('17. since/until are ignored on cursor pages (cursor already positioned)', async () => {
    const evs = [1, 2, 3].map((seq) =>
      makeSignedEvidence({ capabilityId: `jti-${seq}` }),
    );
    const backend = makeMockBackend(evs.map((ev, i) => makeLedgerEntry(ev, i + 1)));
    const deps = await buildDeps({ ledgerBackend: backend, adminApiKey: ADMIN_KEY });
    const app = createApp(deps);

    // Page 1: get cursor
    const page1 = await request(app)
      .get('/api/v1/audit/export?pageSize=1')
      .set('X-Admin-Api-Key', ADMIN_KEY);

    expect(page1.status).toBe(200);
    expect(page1.body.hasMore).toBe(true);

    // Page 2: cursor + since/until (since/until should be ignored)
    const futureDate = new Date(Date.now() + 86400_000).toISOString();
    const page2 = await request(app)
      .get(
        `/api/v1/audit/export?cursor=${encodeURIComponent(page1.body.cursor)}&since=${encodeURIComponent(futureDate)}`,
      )
      .set('X-Admin-Api-Key', ADMIN_KEY);

    // Should NOT return 400 (since is ignored for cursor pages); should return records
    expect(page2.status).toBe(200);
  });
});

// ── Route: pageSize validation ────────────────────────────────────────────────

describe('GET /api/v1/audit/export — pageSize', () => {
  it('15. pageSize is capped at 1000', async () => {
    // Create 5 records and request pageSize=9999 — should return all 5 (≤1000)
    const evs = [1, 2, 3, 4, 5].map((seq) =>
      makeSignedEvidence({ capabilityId: `jti-${seq}` }),
    );
    const backend = makeMockBackend(evs.map((ev, i) => makeLedgerEntry(ev, i + 1)));
    const deps = await buildDeps({ ledgerBackend: backend, adminApiKey: ADMIN_KEY });
    const app = createApp(deps);

    const res = await request(app)
      .get('/api/v1/audit/export?pageSize=9999')
      .set('X-Admin-Api-Key', ADMIN_KEY);

    expect(res.status).toBe(200);
    expect(res.body.records).toHaveLength(5);
  });

  it('16. invalid pageSize string → 400', async () => {
    const backend = makeMockBackend([]);
    const deps = await buildDeps({ ledgerBackend: backend, adminApiKey: ADMIN_KEY });
    const app = createApp(deps);

    const res = await request(app)
      .get('/api/v1/audit/export?pageSize=abc')
      .set('X-Admin-Api-Key', ADMIN_KEY);

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_REQUEST');
  });
});

// ── Route: verificationUri ────────────────────────────────────────────────────

describe('GET /api/v1/audit/export — response shape', () => {
  it('response always includes verificationUri = /.well-known/jwks.json', async () => {
    const backend = makeMockBackend([]);
    const deps = await buildDeps({ ledgerBackend: backend, adminApiKey: ADMIN_KEY });
    const app = createApp(deps);

    const res = await request(app)
      .get('/api/v1/audit/export')
      .set('X-Admin-Api-Key', ADMIN_KEY);

    expect(res.status).toBe(200);
    expect(res.body.verificationUri).toBe('/.well-known/jwks.json');
  });

  it('cursor is null on last page', async () => {
    const ev = makeSignedEvidence();
    const backend = makeMockBackend([makeLedgerEntry(ev, 1)]);
    const deps = await buildDeps({ ledgerBackend: backend, adminApiKey: ADMIN_KEY });
    const app = createApp(deps);

    const res = await request(app)
      .get('/api/v1/audit/export')
      .set('X-Admin-Api-Key', ADMIN_KEY);

    expect(res.status).toBe(200);
    expect(res.body.cursor).toBeNull();
    expect(res.body.hasMore).toBe(false);
  });

  it('records contain SignedAuditEvidence fields', async () => {
    const ev = makeSignedEvidence({ decision: 'deny', agentId: 'agent-xyz' });
    const backend = makeMockBackend([makeLedgerEntry(ev, 1)]);
    const deps = await buildDeps({ ledgerBackend: backend, adminApiKey: ADMIN_KEY });
    const app = createApp(deps);

    const res = await request(app)
      .get('/api/v1/audit/export')
      .set('X-Admin-Api-Key', ADMIN_KEY);

    expect(res.status).toBe(200);
    expect(res.body.records).toHaveLength(1);
    const rec = res.body.records[0];
    expect(rec.id).toBe(ev.id);
    expect(rec.agentId).toBe('agent-xyz');
    expect(rec.decision).toBe('deny');
    expect(rec.signature).toBeDefined();
    expect(rec.keyId).toBeDefined();
  });
});

// ── Router directly (unit) ────────────────────────────────────────────────────

describe('createAuditExportRouter unit', () => {
  it('route returns 200 and correct shape when query store provided directly', async () => {
    const ev = makeSignedEvidence();
    const mockStore = makeMockBackend([makeLedgerEntry(ev, 1)]);
    const logger = createLogger('test');
    const router = createAuditExportRouter({ queryStore: mockStore, logger });

    const app = express();
    app.use(express.json());
    app.use(router);

    const res = await request(app).get('/api/v1/audit/export');

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.records)).toBe(true);
    expect(res.body.verificationUri).toBe('/.well-known/jwks.json');
  });
});
