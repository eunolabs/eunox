/**
 * Tests for PartnerDidRegistry
 * ---------------------------------------------------------------------------
 * Covers:
 *   - InMemoryPartnerDidRegistry lifecycle: propose → approve → revoke
 *   - Two-eyes violation enforcement
 *   - Pin (pinnedDocSha256) validation helpers
 *   - notBefore / notAfter validity window
 *   - Admin API endpoints: POST /partner-dids/proposals,
 *     POST /partner-dids/proposals/:did/approve,
 *     DELETE /partner-dids/:did,
 *     GET /partner-dids,
 *     POST /partner-dids/:did/refresh
 */

import request from 'supertest';
import express from 'express';
import * as http from 'http';
import type { AddressInfo } from 'net';
import {
  InMemoryPartnerDidRegistry,
  jcsSerialize,
  jcsSha256,
  TwoEyesViolationError,
  fetchJson,
  createPinAttestation,
  verifyPinAttestation,
  createPartnerDidRegistryFromEnv,
} from '../src/partner-did-registry';
import { createAdminRouter } from '../src/admin-api';

/** Shared admin API key for tests that exercise partner-did admin endpoints. */
const PARTNER_DID_TEST_KEY = 'partner-did-test-key';
import { createLogger, DefaultKillSwitchManager } from '@euno/common';

// ─────────────────────────────────────────────────────────────────────────────
// InMemoryPartnerDidRegistry unit tests
// ─────────────────────────────────────────────────────────────────────────────

describe('InMemoryPartnerDidRegistry', () => {
  const DID = 'did:web:partner.example.com';
  const PROPOSER = 'alice';
  const APPROVER = 'bob';

  function makeRegistry() {
    return new InMemoryPartnerDidRegistry();
  }

  it('starts empty', async () => {
    const reg = makeRegistry();
    expect(await reg.list()).toHaveLength(0);
    expect(await reg.trusts(DID)).toBe(false);
    expect(await reg.get(DID)).toBeUndefined();
  });

  it('propose creates a proposed entry', async () => {
    const reg = makeRegistry();
    const entry = await reg.propose({ did: DID, proposer: PROPOSER });
    expect(entry.did).toBe(DID);
    expect(entry.status).toBe('proposed');
    expect(entry.proposer).toBe(PROPOSER);
    expect(entry.proposedAt).toBeGreaterThan(0);
    expect(await reg.trusts(DID)).toBe(false);
  });

  it('trusts returns true after approval', async () => {
    const reg = makeRegistry();
    await reg.propose({ did: DID, proposer: PROPOSER });
    const entry = await reg.approve(DID, APPROVER);
    expect(entry.status).toBe('active');
    expect(entry.approver).toBe(APPROVER);
    expect(entry.activatedAt).toBeGreaterThan(0);
    expect(await reg.trusts(DID)).toBe(true);
  });

  it('throws TwoEyesViolationError when approver === proposer', async () => {
    const reg = makeRegistry();
    await reg.propose({ did: DID, proposer: PROPOSER });
    await expect(reg.approve(DID, PROPOSER)).rejects.toBeInstanceOf(TwoEyesViolationError);
  });

  it('trusts returns false after revocation', async () => {
    const reg = makeRegistry();
    await reg.propose({ did: DID, proposer: PROPOSER });
    await reg.approve(DID, APPROVER);
    const entry = await reg.revoke(DID, APPROVER);
    expect(entry.status).toBe('revoked');
    expect(await reg.trusts(DID)).toBe(false);
  });

  it('propose throws CONFLICT when DID is already active', async () => {
    const reg = makeRegistry();
    await reg.propose({ did: DID, proposer: PROPOSER });
    await reg.approve(DID, APPROVER);
    await expect(
      reg.propose({ did: DID, proposer: 'carol' }),
    ).rejects.toThrow(/already exists/);
  });

  it('propose throws CONFLICT when DID is already proposed', async () => {
    const reg = makeRegistry();
    await reg.propose({ did: DID, proposer: PROPOSER });
    await expect(
      reg.propose({ did: DID, proposer: 'carol' }),
    ).rejects.toThrow(/already exists/);
  });

  it('approve allows re-proposing after revoke', async () => {
    const reg = makeRegistry();
    await reg.propose({ did: DID, proposer: PROPOSER });
    await reg.approve(DID, APPROVER);
    await reg.revoke(DID, APPROVER);
    // Can re-propose after revoke.
    const entry = await reg.propose({ did: DID, proposer: 'carol' });
    expect(entry.status).toBe('proposed');
  });

  it('approve throws NOT_FOUND for unknown DID', async () => {
    const reg = makeRegistry();
    await expect(reg.approve('did:web:unknown.com', APPROVER)).rejects.toThrow(/not found/i);
  });

  it('approve throws CONFLICT when entry is already active', async () => {
    const reg = makeRegistry();
    await reg.propose({ did: DID, proposer: PROPOSER });
    await reg.approve(DID, APPROVER);
    await expect(reg.approve(DID, 'carol')).rejects.toThrow(/cannot be approved/i);
  });

  it('revoke throws NOT_FOUND for unknown DID', async () => {
    const reg = makeRegistry();
    await expect(reg.revoke('did:web:unknown.com', APPROVER)).rejects.toThrow(/not found/i);
  });

  it('list() returns all entries', async () => {
    const reg = makeRegistry();
    await reg.propose({ did: DID, proposer: PROPOSER });
    await reg.propose({ did: 'did:web:other.example.com', proposer: PROPOSER });
    expect(await reg.list()).toHaveLength(2);
  });

  it('list(active) returns only active entries', async () => {
    const reg = makeRegistry();
    await reg.propose({ did: DID, proposer: PROPOSER });
    await reg.approve(DID, APPROVER);
    await reg.propose({ did: 'did:web:other.example.com', proposer: PROPOSER });
    const active = await reg.list('active');
    expect(active).toHaveLength(1);
    expect(active[0]!.did).toBe(DID);
  });

  it('trusts respects notBefore (future)', async () => {
    const reg = makeRegistry();
    await reg.propose({
      did: DID,
      proposer: PROPOSER,
      notBefore: Date.now() + 60_000,
    });
    await reg.approve(DID, APPROVER);
    expect(await reg.trusts(DID)).toBe(false);
  });

  it('trusts respects notAfter (past)', async () => {
    const reg = makeRegistry();
    await reg.propose({
      did: DID,
      proposer: PROPOSER,
      notAfter: Date.now() - 60_000,
    });
    await reg.approve(DID, APPROVER);
    expect(await reg.trusts(DID)).toBe(false);
  });

  it('seed() adds active entries for TRUSTED_PARTNER_DIDS migration', async () => {
    const reg = makeRegistry();
    reg.seed([DID, 'did:web:other.example.com']);
    expect(await reg.trusts(DID)).toBe(true);
    expect(await reg.trusts('did:web:other.example.com')).toBe(true);
  });

  it('seed() is idempotent', async () => {
    const reg = makeRegistry();
    reg.seed([DID]);
    reg.seed([DID]);
    expect(await reg.list()).toHaveLength(1);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// JCS helpers
// ─────────────────────────────────────────────────────────────────────────────

describe('jcsSerialize', () => {
  it('sorts object keys', () => {
    expect(jcsSerialize({ z: 1, a: 2 })).toBe('{"a":2,"z":1}');
  });

  it('handles nested objects', () => {
    expect(jcsSerialize({ b: { z: 1, a: 2 }, a: 3 })).toBe('{"a":3,"b":{"a":2,"z":1}}');
  });

  it('handles arrays', () => {
    expect(jcsSerialize([3, 1, 2])).toBe('[3,1,2]');
  });

  it('handles null', () => {
    expect(jcsSerialize(null)).toBe('null');
  });
});

describe('jcsSha256', () => {
  it('produces a 64-char lowercase hex string', () => {
    const hash = jcsSha256({ did: 'did:web:example.com' });
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is deterministic regardless of key insertion order', () => {
    const h1 = jcsSha256({ b: 2, a: 1 });
    const h2 = jcsSha256({ a: 1, b: 2 });
    expect(h1).toBe(h2);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Admin API registry endpoints
// ─────────────────────────────────────────────────────────────────────────────

function buildAdminApp(registry?: InMemoryPartnerDidRegistry, opts: { requirePin?: boolean } = {}) {
  const logger = createLogger('test');
  const killSwitchManager = new DefaultKillSwitchManager(logger);
  const app = express();
  app.use(express.json());
  app.use(
    '/admin',
    createAdminRouter({
      killSwitchManager,
      logger,
      adminApiKey: PARTNER_DID_TEST_KEY,
      partnerRegistry: registry,
      requirePin: opts.requirePin,
    }),
  );
  return app;
}

describe('GET /admin/partner-dids', () => {
  it('returns 404 when no registry is configured', async () => {
    const app = buildAdminApp();
    const res = await request(app).get('/admin/partner-dids')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY);
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('NOT_CONFIGURED');
  });

  it('returns empty list initially', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    const app = buildAdminApp(reg);
    const res = await request(app).get('/admin/partner-dids')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY);
    expect(res.status).toBe(200);
    expect(res.body.entries).toHaveLength(0);
  });

  it('returns all entries', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    await reg.propose({ did: 'did:web:a.com', proposer: 'alice' });
    await reg.propose({ did: 'did:web:b.com', proposer: 'alice' });
    const app = buildAdminApp(reg);
    const res = await request(app).get('/admin/partner-dids')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY);
    expect(res.status).toBe(200);
    expect(res.body.entries).toHaveLength(2);
  });

  it('filters by status', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    await reg.propose({ did: 'did:web:a.com', proposer: 'alice' });
    await reg.approve('did:web:a.com', 'bob');
    await reg.propose({ did: 'did:web:b.com', proposer: 'alice' });
    const app = buildAdminApp(reg);

    const activeRes = await request(app).get('/admin/partner-dids?status=active')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY);
    expect(activeRes.body.entries).toHaveLength(1);
    expect(activeRes.body.entries[0].did).toBe('did:web:a.com');

    const proposedRes = await request(app).get('/admin/partner-dids?status=proposed')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY);
    expect(proposedRes.body.entries).toHaveLength(1);
    expect(proposedRes.body.entries[0].did).toBe('did:web:b.com');
  });
});

describe('POST /admin/partner-dids/proposals', () => {
  it('returns 404 when no registry is configured', async () => {
    const app = buildAdminApp();
    const res = await request(app)
      .post('/admin/partner-dids/proposals')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY)
      .set('X-Admin-Operator', 'alice')
      .send({ did: 'did:web:example.com' });
    expect(res.status).toBe(404);
  });

  it('returns 400 when X-Admin-Operator header is missing', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    const app = buildAdminApp(reg);
    const res = await request(app)
      .post('/admin/partner-dids/proposals')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY)
      .send({ did: 'did:web:example.com' });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('MISSING_OPERATOR');
  });

  it('returns 400 when did is missing', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    const app = buildAdminApp(reg);
    const res = await request(app)
      .post('/admin/partner-dids/proposals')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY)
      .set('X-Admin-Operator', 'alice')
      .send({});
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_REQUEST');
  });

  it('creates a proposed entry and returns 201', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    const app = buildAdminApp(reg);
    const res = await request(app)
      .post('/admin/partner-dids/proposals')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY)
      .set('X-Admin-Operator', 'alice')
      .send({ did: 'did:web:partner.example.com', notes: 'Acme Corp' });
    expect(res.status).toBe(201);
    expect(res.body.entry.did).toBe('did:web:partner.example.com');
    expect(res.body.entry.status).toBe('proposed');
    expect(res.body.entry.proposer).toBe('alice');
  });

  it('returns 409 when DID already exists', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    await reg.propose({ did: 'did:web:partner.example.com', proposer: 'alice' });
    const app = buildAdminApp(reg);
    const res = await request(app)
      .post('/admin/partner-dids/proposals')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY)
      .set('X-Admin-Operator', 'carol')
      .send({ did: 'did:web:partner.example.com' });
    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('CONFLICT');
  });
});

describe('POST /admin/partner-dids/proposals — requirePin enforcement', () => {
  it('rejects proposals without pinnedDocSha256 when requirePin=true', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    const app = buildAdminApp(reg, { requirePin: true });
    const res = await request(app)
      .post('/admin/partner-dids/proposals')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY)
      .set('X-Admin-Operator', 'alice')
      .send({ did: 'did:web:partner.example.com', notes: 'no pin' });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('PIN_REQUIRED');
  });

  it('accepts proposals with pinnedDocSha256 when requirePin=true', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    const app = buildAdminApp(reg, { requirePin: true });
    const pin = jcsSha256({ id: 'did:web:partner.example.com' });
    const res = await request(app)
      .post('/admin/partner-dids/proposals')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY)
      .set('X-Admin-Operator', 'alice')
      .send({ did: 'did:web:partner.example.com', pinnedDocSha256: pin });
    expect(res.status).toBe(201);
    expect(res.body.entry.pinnedDocSha256).toBe(pin);
  });

  it('accepts proposals without pinnedDocSha256 when requirePin=false (default)', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    const app = buildAdminApp(reg);
    const res = await request(app)
      .post('/admin/partner-dids/proposals')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY)
      .set('X-Admin-Operator', 'alice')
      .send({ did: 'did:web:partner.example.com' });
    expect(res.status).toBe(201);
  });
});

describe('POST /admin/partner-dids/proposals/:did/approve', () => {
  it('returns 404 when no registry is configured', async () => {
    const app = buildAdminApp();
    const res = await request(app)
      .post('/admin/partner-dids/proposals/did%3Aweb%3Aexample.com/approve')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY)
      .set('X-Admin-Operator', 'bob');
    expect(res.status).toBe(404);
  });

  it('returns 400 when X-Admin-Operator header is missing', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    const app = buildAdminApp(reg);
    const res = await request(app)
      .post('/admin/partner-dids/proposals/did%3Aweb%3Aexample.com/approve')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY);
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('MISSING_OPERATOR');
  });

  it('approves a proposed entry', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    await reg.propose({ did: 'did:web:partner.example.com', proposer: 'alice' });
    const app = buildAdminApp(reg);
    const res = await request(app)
      .post('/admin/partner-dids/proposals/did%3Aweb%3Apartner.example.com/approve')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY)
      .set('X-Admin-Operator', 'bob');
    expect(res.status).toBe(200);
    expect(res.body.entry.status).toBe('active');
    expect(res.body.entry.approver).toBe('bob');
    expect(await reg.trusts('did:web:partner.example.com')).toBe(true);
  });

  it('returns 403 TWO_EYES_VIOLATION when approver === proposer', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    await reg.propose({ did: 'did:web:partner.example.com', proposer: 'alice' });
    const app = buildAdminApp(reg);
    const res = await request(app)
      .post('/admin/partner-dids/proposals/did%3Aweb%3Apartner.example.com/approve')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY)
      .set('X-Admin-Operator', 'alice');
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('TWO_EYES_VIOLATION');
  });

  it('returns 404 for unknown DID', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    const app = buildAdminApp(reg);
    const res = await request(app)
      .post('/admin/partner-dids/proposals/did%3Aweb%3Aunknown.com/approve')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY)
      .set('X-Admin-Operator', 'bob');
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('NOT_FOUND');
  });

  it('returns 409 when entry is already active', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    await reg.propose({ did: 'did:web:partner.example.com', proposer: 'alice' });
    await reg.approve('did:web:partner.example.com', 'bob');
    const app = buildAdminApp(reg);
    const res = await request(app)
      .post('/admin/partner-dids/proposals/did%3Aweb%3Apartner.example.com/approve')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY)
      .set('X-Admin-Operator', 'carol');
    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('CONFLICT');
  });

  it('returns 400 INVALID_REQUEST when :did is malformed percent-encoding', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    const app = buildAdminApp(reg);
    const res = await request(app)
      .post('/admin/partner-dids/proposals/%25/approve')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY)
      .set('X-Admin-Operator', 'bob');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_REQUEST');
  });
});

describe('DELETE /admin/partner-dids/:did', () => {
  it('returns 404 when no registry is configured', async () => {
    const app = buildAdminApp();
    const res = await request(app)
      .delete('/admin/partner-dids/did%3Aweb%3Aexample.com')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY)
      .set('X-Admin-Operator', 'alice');
    expect(res.status).toBe(404);
  });

  it('revokes an active entry', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    await reg.propose({ did: 'did:web:partner.example.com', proposer: 'alice' });
    await reg.approve('did:web:partner.example.com', 'bob');
    const app = buildAdminApp(reg);
    const res = await request(app)
      .delete('/admin/partner-dids/did%3Aweb%3Apartner.example.com')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY)
      .set('X-Admin-Operator', 'alice');
    expect(res.status).toBe(200);
    expect(res.body.entry.status).toBe('revoked');
    expect(await reg.trusts('did:web:partner.example.com')).toBe(false);
  });

  it('returns 400 when X-Admin-Operator header is missing', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    const app = buildAdminApp(reg);
    const res = await request(app)
      .delete('/admin/partner-dids/did%3Aweb%3Aexample.com')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY);
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('MISSING_OPERATOR');
  });

  it('returns 404 for unknown DID', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    const app = buildAdminApp(reg);
    const res = await request(app)
      .delete('/admin/partner-dids/did%3Aweb%3Aunknown.com')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY)
      .set('X-Admin-Operator', 'alice');
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('NOT_FOUND');
  });

  it('returns 400 INVALID_REQUEST when :did is malformed percent-encoding', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    const app = buildAdminApp(reg);
    const res = await request(app)
      .delete('/admin/partner-dids/%25')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY)
      .set('X-Admin-Operator', 'alice');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_REQUEST');
  });
});

describe('POST /admin/partner-dids/:did/refresh', () => {
  it('returns 404 when neither resolver nor registry is configured', async () => {
    const app = buildAdminApp();
    const res = await request(app)
      .post('/admin/partner-dids/did%3Aweb%3Aexample.com/refresh')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY)
      .set('X-Admin-Operator', 'alice');
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('NOT_CONFIGURED');
  });

  it('returns 400 when X-Admin-Operator header is missing', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    await reg.propose({ did: 'did:web:partner.example.com', proposer: 'alice' });
    await reg.approve('did:web:partner.example.com', 'bob');
    const app = buildAdminApp(reg);
    const res = await request(app)
      .post('/admin/partner-dids/did%3Aweb%3Apartner.example.com/refresh')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY);
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('MISSING_OPERATOR');
  });

  it('returns 404 when DID is not trusted', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    const app = buildAdminApp(reg);
    const res = await request(app)
      .post('/admin/partner-dids/did%3Aweb%3Aexample.com/refresh')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY)
      .set('X-Admin-Operator', 'alice');
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('UNKNOWN_DID');
  });

  it('returns 200 and clears cache for an active DID', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    await reg.propose({ did: 'did:web:partner.example.com', proposer: 'alice' });
    await reg.approve('did:web:partner.example.com', 'bob');
    const app = buildAdminApp(reg);
    const res = await request(app)
      .post('/admin/partner-dids/did%3Aweb%3Apartner.example.com/refresh')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY)
      .set('X-Admin-Operator', 'alice');
    expect(res.status).toBe(200);
    expect(res.body.did).toBe('did:web:partner.example.com');
  });

  it('returns 400 INVALID_REQUEST when :did is malformed percent-encoding', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    const app = buildAdminApp(reg);
    const res = await request(app)
      .post('/admin/partner-dids/%25/refresh')
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY)
      .set('X-Admin-Operator', 'alice');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_REQUEST');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// fetchJson — timeout and max-size cap
// ─────────────────────────────────────────────────────────────────────────────

describe('fetchJson', () => {
  function startTestServer(handler: (req: http.IncomingMessage, res: http.ServerResponse) => void) {
    return new Promise<{ url: string; close: () => Promise<void> }>((resolve) => {
      const server = http.createServer(handler);
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address() as AddressInfo;
        resolve({
          url: `http://127.0.0.1:${addr.port}`,
          close: () => new Promise<void>((r) => server.close(() => r())),
        });
      });
    });
  }

  it('fetches and parses valid JSON', async () => {
    const { url, close } = await startTestServer((_req, res) => {
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ ok: true }));
    });
    try {
      const result = await fetchJson(url);
      expect(result).toEqual({ ok: true });
    } finally {
      await close();
    }
  });

  it('rejects when response exceeds maxBytes', async () => {
    const { url, close } = await startTestServer((_req, res) => {
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      // Send 100 bytes of JSON — we will cap at 50
      res.end(JSON.stringify({ data: 'x'.repeat(80) }));
    });
    try {
      await expect(fetchJson(url, { maxBytes: 50 })).rejects.toThrow(/exceeded size limit/);
    } finally {
      await close();
    }
  });

  it('rejects when server hangs (timeout)', async () => {
    const { url, close } = await startTestServer((_req, _res) => {
      // Never respond — triggers timeout
    });
    try {
      await expect(fetchJson(url, { timeoutMs: 100 })).rejects.toThrow(/timed out/);
    } finally {
      await close();
    }
  }, 2_000);

  it('rejects on non-200 status', async () => {
    const { url, close } = await startTestServer((_req, res) => {
      res.statusCode = 404;
      res.end();
    });
    try {
      await expect(fetchJson(url)).rejects.toThrow(/HTTP 404/);
    } finally {
      await close();
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Pin attestation — createPinAttestation / verifyPinAttestation
// ─────────────────────────────────────────────────────────────────────────────

describe('createPinAttestation / verifyPinAttestation', () => {
  const SECRET = 'test-secret-32-bytes-padding!!';
  const FIELDS = {
    did: 'did:web:partner.example.com',
    pinnedDocSha256: jcsSha256({ id: 'did:web:partner.example.com' }),
    approver: 'bob',
    activatedAt: 1_700_000_000_000,
  };

  it('creates an attestation with a valid HMAC', () => {
    const att = createPinAttestation(FIELDS, SECRET);
    expect(att.hmac).toMatch(/^[0-9a-f]{64}$/);
    expect(att.did).toBe(FIELDS.did);
    expect(att.pinnedDocSha256).toBe(FIELDS.pinnedDocSha256);
    expect(att.approver).toBe(FIELDS.approver);
    expect(att.activatedAt).toBe(FIELDS.activatedAt);
  });

  it('verifies a valid attestation', () => {
    const att = createPinAttestation(FIELDS, SECRET);
    expect(verifyPinAttestation(att, SECRET)).toBe(true);
  });

  it('rejects a tampered HMAC', () => {
    const att = createPinAttestation(FIELDS, SECRET);
    const tampered = { ...att, hmac: att.hmac.replace(/^./, '0') };
    expect(verifyPinAttestation(tampered, SECRET)).toBe(false);
  });

  it('rejects when the did field is changed', () => {
    const att = createPinAttestation(FIELDS, SECRET);
    const tampered = { ...att, did: 'did:web:evil.example.com' };
    expect(verifyPinAttestation(tampered, SECRET)).toBe(false);
  });

  it('rejects when the pinnedDocSha256 is changed', () => {
    const att = createPinAttestation(FIELDS, SECRET);
    const tampered = { ...att, pinnedDocSha256: 'a'.repeat(64) };
    expect(verifyPinAttestation(tampered, SECRET)).toBe(false);
  });

  it('rejects when a different secret is used', () => {
    const att = createPinAttestation(FIELDS, SECRET);
    expect(verifyPinAttestation(att, 'different-secret')).toBe(false);
  });

  it('is deterministic: same inputs produce the same HMAC', () => {
    const att1 = createPinAttestation(FIELDS, SECRET);
    const att2 = createPinAttestation(FIELDS, SECRET);
    expect(att1.hmac).toBe(att2.hmac);
  });

  it('returns false (not throws) when hmac contains non-hex characters', () => {
    const att = createPinAttestation(FIELDS, SECRET);
    // Replace 2 chars with non-hex to produce a valid-length but invalid-hex string.
    const badHmac = 'zz' + att.hmac.slice(2);
    expect(badHmac).toHaveLength(64);
    expect(() => verifyPinAttestation({ ...att, hmac: badHmac }, SECRET)).not.toThrow();
    expect(verifyPinAttestation({ ...att, hmac: badHmac }, SECRET)).toBe(false);
  });

  it('returns false (not throws) when hmac is the empty string', () => {
    const att = createPinAttestation(FIELDS, SECRET);
    expect(() => verifyPinAttestation({ ...att, hmac: '' }, SECRET)).not.toThrow();
    expect(verifyPinAttestation({ ...att, hmac: '' }, SECRET)).toBe(false);
  });

  it('accepts a valid uppercase-hex hmac (Buffer.from hex is case-insensitive)', () => {
    const att = createPinAttestation(FIELDS, SECRET);
    // hex decoding is case-insensitive: uppercase HMAC decodes to the same bytes.
    const upperHmac = att.hmac.toUpperCase();
    expect(() => verifyPinAttestation({ ...att, hmac: upperHmac }, SECRET)).not.toThrow();
    expect(verifyPinAttestation({ ...att, hmac: upperHmac }, SECRET)).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// PartnerDidRegistry.approve() with pinOverrides
// ─────────────────────────────────────────────────────────────────────────────

describe('InMemoryPartnerDidRegistry.approve() pinOverrides', () => {
  const DID = 'did:web:partner.example.com';
  const SECRET = 'test-secret-32-bytes-padding!!';

  it('stores pinOverrides in the activated entry', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    await reg.propose({ did: DID, proposer: 'alice' });
    const pin = jcsSha256({ id: DID });
    const att = createPinAttestation(
      { did: DID, pinnedDocSha256: pin, approver: 'bob', activatedAt: Date.now() },
      SECRET,
    );
    const entry = await reg.approve(DID, 'bob', { pinnedDocSha256: pin, pinAttestation: att });
    expect(entry.status).toBe('active');
    expect(entry.pinnedDocSha256).toBe(pin);
    expect(entry.pinAttestation).toBeDefined();
    expect(verifyPinAttestation(entry.pinAttestation!, SECRET)).toBe(true);
  });

  it('approval without pinOverrides still works (backwards compat)', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    await reg.propose({ did: DID, proposer: 'alice' });
    const entry = await reg.approve(DID, 'bob');
    expect(entry.status).toBe('active');
    expect(entry.pinAttestation).toBeUndefined();
  });

  it('normalizes pinnedDocSha256 to lowercase at proposal time', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    const upperPin = jcsSha256({ id: DID }).toUpperCase();
    const entry = await reg.propose({ did: DID, proposer: 'alice', pinnedDocSha256: upperPin });
    expect(entry.pinnedDocSha256).toBe(upperPin.toLowerCase());
  });

  it('normalizes pinnedDocSha256 to lowercase at approval time via pinOverrides', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    await reg.propose({ did: DID, proposer: 'alice' });
    const upperPin = jcsSha256({ id: DID }).toUpperCase();
    const entry = await reg.approve(DID, 'bob', { pinnedDocSha256: upperPin });
    expect(entry.pinnedDocSha256).toBe(upperPin.toLowerCase());
  });

  it('normalizes a proposer-supplied uppercase pin when no pinOverrides passed to approve', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    const upperPin = jcsSha256({ id: DID }).toUpperCase();
    await reg.propose({ did: DID, proposer: 'alice', pinnedDocSha256: upperPin });
    const entry = await reg.approve(DID, 'bob');
    expect(entry.pinnedDocSha256).toBe(upperPin.toLowerCase());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Admin API: auto-fetch pin at approval time
// ─────────────────────────────────────────────────────────────────────────────

function buildAdminAppWithFetch(
  registry: InMemoryPartnerDidRegistry,
  opts: {
    requirePin?: boolean;
    pinAttestationSecret?: string;
    resolveDidDocument?: (did: string) => Promise<unknown>;
  } = {},
) {
  const logger = createLogger('test');
  const killSwitchManager = new DefaultKillSwitchManager(logger);
  const app = express();
  app.use(express.json());
  app.use(
    '/admin',
    createAdminRouter({
      killSwitchManager,
      logger,
      adminApiKey: PARTNER_DID_TEST_KEY,
      partnerRegistry: registry,
      requirePin: opts.requirePin,
      pinAttestationSecret: opts.pinAttestationSecret,
      resolveDidDocument: opts.resolveDidDocument,
    }),
  );
  return app;
}

describe('POST /admin/partner-dids/proposals/:did/approve — auto-fetch + pin attestation', () => {
  const DID = 'did:web:partner.example.com';
  const MOCK_DOC = { '@context': ['https://www.w3.org/ns/did/v1'], id: DID };
  const MOCK_HASH = jcsSha256(MOCK_DOC);
  const SECRET = 'test-secret-32-bytes-padding!!';

  it('auto-computes pin from resolveDidDocument when proposal has no pin', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    await reg.propose({ did: DID, proposer: 'alice' });
    const resolveFn = jest.fn().mockResolvedValue(MOCK_DOC);
    const app = buildAdminAppWithFetch(reg, { resolveDidDocument: resolveFn });

    const res = await request(app)
      .post(`/admin/partner-dids/proposals/${encodeURIComponent(DID)}/approve`)
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY)
      .set('X-Admin-Operator', 'bob');

    expect(res.status).toBe(200);
    expect(res.body.entry.status).toBe('active');
    expect(res.body.entry.pinnedDocSha256).toBe(MOCK_HASH);
    expect(resolveFn).toHaveBeenCalledWith(DID);
  });

  it('creates a pin attestation when pinAttestationSecret and resolveDidDocument are set', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    await reg.propose({ did: DID, proposer: 'alice' });
    const resolveFn = jest.fn().mockResolvedValue(MOCK_DOC);
    const app = buildAdminAppWithFetch(reg, {
      resolveDidDocument: resolveFn,
      pinAttestationSecret: SECRET,
    });

    const res = await request(app)
      .post(`/admin/partner-dids/proposals/${encodeURIComponent(DID)}/approve`)
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY)
      .set('X-Admin-Operator', 'bob');

    expect(res.status).toBe(200);
    const entry = res.body.entry;
    expect(entry.pinnedDocSha256).toBe(MOCK_HASH);
    expect(entry.pinAttestation).toBeDefined();
    expect(verifyPinAttestation(entry.pinAttestation, SECRET)).toBe(true);
    expect(entry.pinAttestation.did).toBe(DID);
    expect(entry.pinAttestation.approver).toBe('bob');
  });

  it('returns 502 when resolveDidDocument throws', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    await reg.propose({ did: DID, proposer: 'alice' });
    const resolveFn = jest.fn().mockRejectedValue(new Error('network error'));
    const app = buildAdminAppWithFetch(reg, { resolveDidDocument: resolveFn });

    const res = await request(app)
      .post(`/admin/partner-dids/proposals/${encodeURIComponent(DID)}/approve`)
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY)
      .set('X-Admin-Operator', 'bob');

    expect(res.status).toBe(502);
    expect(res.body.error.code).toBe('DID_FETCH_FAILED');
  });

  it('does not override a proposer-supplied pin when resolveDidDocument is set', async () => {
    const existingPin = 'a'.repeat(64);
    const reg = new InMemoryPartnerDidRegistry();
    await reg.propose({ did: DID, proposer: 'alice', pinnedDocSha256: existingPin });
    // resolveDidDocument should not be called since a pin already exists
    const resolveFn = jest.fn().mockResolvedValue(MOCK_DOC);
    const app = buildAdminAppWithFetch(reg, {
      resolveDidDocument: resolveFn,
      pinAttestationSecret: SECRET,
    });

    const res = await request(app)
      .post(`/admin/partner-dids/proposals/${encodeURIComponent(DID)}/approve`)
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY)
      .set('X-Admin-Operator', 'bob');

    // The proposer-supplied pin is kept; attestation is signed over it.
    expect(res.status).toBe(200);
    expect(res.body.entry.pinnedDocSha256).toBe(existingPin);
    expect(verifyPinAttestation(res.body.entry.pinAttestation, SECRET)).toBe(true);
    expect(resolveFn).not.toHaveBeenCalled();
  });

  it('signs attestation over proposer pin even without resolveDidDocument', async () => {
    const existingPin = jcsSha256({ id: DID });
    const reg = new InMemoryPartnerDidRegistry();
    await reg.propose({ did: DID, proposer: 'alice', pinnedDocSha256: existingPin });
    const app = buildAdminAppWithFetch(reg, {
      pinAttestationSecret: SECRET,
      // No resolveDidDocument — only signs over existing pin
    });

    const res = await request(app)
      .post(`/admin/partner-dids/proposals/${encodeURIComponent(DID)}/approve`)
      .set('X-Admin-API-Key', PARTNER_DID_TEST_KEY)
      .set('X-Admin-Operator', 'bob');

    expect(res.status).toBe(200);
    expect(res.body.entry.pinnedDocSha256).toBe(existingPin);
    expect(verifyPinAttestation(res.body.entry.pinAttestation, SECRET)).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// createPartnerDidRegistryFromEnv — production env-var hardening
// ─────────────────────────────────────────────────────────────────────────────

describe('createPartnerDidRegistryFromEnv — production env-var hardening', () => {
  const logger = createLogger('test');

  it('throws when TRUSTED_PARTNER_DIDS is set in production (default behaviour)', async () => {
    await expect(
      createPartnerDidRegistryFromEnv(
        { TRUSTED_PARTNER_DIDS: 'did:web:partner.example.com', NODE_ENV: 'production' },
        logger,
      ),
    ).rejects.toThrow(/TRUSTED_PARTNER_DIDS is set but the partner-DID registry is required/);
  });

  it('warns (not throws) when PARTNER_DID_REGISTRY_REQUIRED=false in production', async () => {
    const warnSpy = jest.spyOn(logger, 'warn');
    await createPartnerDidRegistryFromEnv(
      {
        TRUSTED_PARTNER_DIDS: 'did:web:partner.example.com',
        NODE_ENV: 'production',
        PARTNER_DID_REGISTRY_REQUIRED: 'false',
      },
      logger,
    );
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('TRUSTED_PARTNER_DIDS is set'),
    );
    warnSpy.mockRestore();
  });

  it('warns (not throws) when TRUSTED_PARTNER_DIDS is set in non-production (default)', async () => {
    const warnSpy = jest.spyOn(logger, 'warn');
    await createPartnerDidRegistryFromEnv(
      { TRUSTED_PARTNER_DIDS: 'did:web:partner.example.com', NODE_ENV: 'development' },
      logger,
    );
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('TRUSTED_PARTNER_DIDS is set'),
    );
    warnSpy.mockRestore();
  });

  it('throws in non-production when PARTNER_DID_REGISTRY_REQUIRED=true', async () => {
    await expect(
      createPartnerDidRegistryFromEnv(
        {
          TRUSTED_PARTNER_DIDS: 'did:web:partner.example.com',
          NODE_ENV: 'development',
          PARTNER_DID_REGISTRY_REQUIRED: 'true',
        },
        logger,
      ),
    ).rejects.toThrow(/TRUSTED_PARTNER_DIDS is set but the partner-DID registry is required/);
  });

  it('seeds the registry in non-production with a warning', async () => {
    const warnSpy = jest.spyOn(logger, 'warn');
    const registry = await createPartnerDidRegistryFromEnv(
      { TRUSTED_PARTNER_DIDS: 'did:web:a.com,did:web:b.com', NODE_ENV: 'development' },
      logger,
    );
    expect(await registry.trusts('did:web:a.com')).toBe(true);
    expect(await registry.trusts('did:web:b.com')).toBe(true);
    expect(await registry.trusts('did:web:c.com')).toBe(false);
    warnSpy.mockRestore();
  });

  it('does not throw when TRUSTED_PARTNER_DIDS is unset in production', async () => {
    await expect(
      createPartnerDidRegistryFromEnv({ NODE_ENV: 'production' }, logger),
    ).resolves.toBeDefined();
  });
});
