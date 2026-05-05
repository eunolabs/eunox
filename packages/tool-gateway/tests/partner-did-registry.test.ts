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
} from '../src/partner-did-registry';
import { createAdminRouter } from '../src/admin-api';
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
      partnerRegistry: registry,
      requirePin: opts.requirePin,
    }),
  );
  return app;
}

describe('GET /admin/partner-dids', () => {
  it('returns 404 when no registry is configured', async () => {
    const app = buildAdminApp();
    const res = await request(app).get('/admin/partner-dids');
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('NOT_CONFIGURED');
  });

  it('returns empty list initially', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    const app = buildAdminApp(reg);
    const res = await request(app).get('/admin/partner-dids');
    expect(res.status).toBe(200);
    expect(res.body.entries).toHaveLength(0);
  });

  it('returns all entries', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    await reg.propose({ did: 'did:web:a.com', proposer: 'alice' });
    await reg.propose({ did: 'did:web:b.com', proposer: 'alice' });
    const app = buildAdminApp(reg);
    const res = await request(app).get('/admin/partner-dids');
    expect(res.status).toBe(200);
    expect(res.body.entries).toHaveLength(2);
  });

  it('filters by status', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    await reg.propose({ did: 'did:web:a.com', proposer: 'alice' });
    await reg.approve('did:web:a.com', 'bob');
    await reg.propose({ did: 'did:web:b.com', proposer: 'alice' });
    const app = buildAdminApp(reg);

    const activeRes = await request(app).get('/admin/partner-dids?status=active');
    expect(activeRes.body.entries).toHaveLength(1);
    expect(activeRes.body.entries[0].did).toBe('did:web:a.com');

    const proposedRes = await request(app).get('/admin/partner-dids?status=proposed');
    expect(proposedRes.body.entries).toHaveLength(1);
    expect(proposedRes.body.entries[0].did).toBe('did:web:b.com');
  });
});

describe('POST /admin/partner-dids/proposals', () => {
  it('returns 404 when no registry is configured', async () => {
    const app = buildAdminApp();
    const res = await request(app)
      .post('/admin/partner-dids/proposals')
      .set('X-Admin-Operator', 'alice')
      .send({ did: 'did:web:example.com' });
    expect(res.status).toBe(404);
  });

  it('returns 400 when X-Admin-Operator header is missing', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    const app = buildAdminApp(reg);
    const res = await request(app)
      .post('/admin/partner-dids/proposals')
      .send({ did: 'did:web:example.com' });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('MISSING_OPERATOR');
  });

  it('returns 400 when did is missing', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    const app = buildAdminApp(reg);
    const res = await request(app)
      .post('/admin/partner-dids/proposals')
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
      .set('X-Admin-Operator', 'bob');
    expect(res.status).toBe(404);
  });

  it('returns 400 when X-Admin-Operator header is missing', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    const app = buildAdminApp(reg);
    const res = await request(app)
      .post('/admin/partner-dids/proposals/did%3Aweb%3Aexample.com/approve');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('MISSING_OPERATOR');
  });

  it('approves a proposed entry', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    await reg.propose({ did: 'did:web:partner.example.com', proposer: 'alice' });
    const app = buildAdminApp(reg);
    const res = await request(app)
      .post('/admin/partner-dids/proposals/did%3Aweb%3Apartner.example.com/approve')
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
      .set('X-Admin-Operator', 'alice');
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('TWO_EYES_VIOLATION');
  });

  it('returns 404 for unknown DID', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    const app = buildAdminApp(reg);
    const res = await request(app)
      .post('/admin/partner-dids/proposals/did%3Aweb%3Aunknown.com/approve')
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
      .set('X-Admin-Operator', 'carol');
    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('CONFLICT');
  });
});

describe('DELETE /admin/partner-dids/:did', () => {
  it('returns 404 when no registry is configured', async () => {
    const app = buildAdminApp();
    const res = await request(app)
      .delete('/admin/partner-dids/did%3Aweb%3Aexample.com')
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
      .set('X-Admin-Operator', 'alice');
    expect(res.status).toBe(200);
    expect(res.body.entry.status).toBe('revoked');
    expect(await reg.trusts('did:web:partner.example.com')).toBe(false);
  });

  it('returns 400 when X-Admin-Operator header is missing', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    const app = buildAdminApp(reg);
    const res = await request(app)
      .delete('/admin/partner-dids/did%3Aweb%3Aexample.com');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('MISSING_OPERATOR');
  });

  it('returns 404 for unknown DID', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    const app = buildAdminApp(reg);
    const res = await request(app)
      .delete('/admin/partner-dids/did%3Aweb%3Aunknown.com')
      .set('X-Admin-Operator', 'alice');
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('NOT_FOUND');
  });
});

describe('POST /admin/partner-dids/:did/refresh', () => {
  it('returns 404 when neither resolver nor registry is configured', async () => {
    const app = buildAdminApp();
    const res = await request(app)
      .post('/admin/partner-dids/did%3Aweb%3Aexample.com/refresh')
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
      .post('/admin/partner-dids/did%3Aweb%3Apartner.example.com/refresh');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('MISSING_OPERATOR');
  });

  it('returns 404 when DID is not trusted', async () => {
    const reg = new InMemoryPartnerDidRegistry();
    const app = buildAdminApp(reg);
    const res = await request(app)
      .post('/admin/partner-dids/did%3Aweb%3Aexample.com/refresh')
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
      .set('X-Admin-Operator', 'alice');
    expect(res.status).toBe(200);
    expect(res.body.did).toBe('did:web:partner.example.com');
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
