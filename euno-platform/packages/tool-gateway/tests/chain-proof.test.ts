/**
 * Tests for `GET /api/v1/audit/chain-proof` — Task 5 (Stage 5)
 *
 * Tests cover:
 *  1. CrossChainCommitmentStore: basic add/query/chainHead behaviour.
 *  2. Store bounded capacity: oldest record is evicted when full.
 *  3. Route: missing admin key → 401 when key is configured.
 *  4. Route: wrong admin key → 401.
 *  5. Route: correct admin key → 200 with { commits, chainHead }.
 *  6. Route: no admin key configured → open (dev mode).
 *  7. Route: since/until filtering.
 *  8. Route: since after until → 400.
 *  9. Route: invalid since → 400.
 * 10. Route: invalid until → 400.
 * 11. Route: absent when commitmentStore is not in deps.
 * 12. Route: chainHead is null when store is empty.
 * 13. Route: chainHead updates after each commitment.
 * 14. audit-module: auto-starts anchor and populates store when ENABLE_CROSS_CHAIN_ANCHOR=true.
 * 15. Route: timingSafeEqual handles multi-byte Unicode header without throwing.
 * 16. buildAuditModule: ENABLE_CROSS_CHAIN_ANCHOR=true creates store and starts anchor.
 */

// Top-level mock for pg Pool — allows buildAuditModule tests to exercise
// the per-replica-postgres branch without a real database connection.
// Jest hoists this call before any imports, so require('pg') inside
// buildAuditModule's function body returns the mock instead of the real driver.
jest.mock('pg', () => ({
  Pool: jest.fn(() => ({
    connect: jest.fn().mockResolvedValue({
      query: jest.fn().mockResolvedValue({ rows: [] }),
      release: jest.fn(),
    }),
    end: jest.fn().mockResolvedValue(undefined),
    query: jest.fn().mockResolvedValue({ rows: [] }),
  })),
}));

import request from 'supertest';
import express from 'express';
import {
  createLogger,
  DefaultKillSwitchManager,
  ServiceConfig,
  createMetricsRegistry,
  Counter,
  BUILTIN_ACTION_RESOLVER,
  GENESIS_HASH,
  canonicalSha256,
  SignedCrossChainCommitment,
  CrossChainAnchor,
  CrossChainAnchorOptions,
} from '@euno/common';
import {
  PerReplicaPostgresLedgerBackend,
} from '@euno/common-infra';
import { createApp } from '../src/app-factory';
import { EnforcementEngine } from '../src/enforcement';
import type { GatewayDependencies } from '../src/bootstrap';
import {
  CrossChainCommitmentStore,
  createChainProofRouter,
} from '../src/routes/chain-proof';
import { buildAuditModule } from '../src/audit-module';

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeCommitment(
  overrides: Partial<SignedCrossChainCommitment> = {},
  ts?: string,
): SignedCrossChainCommitment {
  const base: SignedCrossChainCommitment = {
    commitmentId: `cid-${Math.random().toString(36).slice(2)}`,
    coordinatorId: 'replica-1',
    ts: ts ?? new Date().toISOString(),
    tips: [
      { replicaId: 'replica-1', seq: 1, tipHash: '0'.repeat(64), ts: new Date().toISOString() },
    ],
    merkleRoot: '0'.repeat(64),
    tipCount: 1,
    commitmentSeq: 1,
    previousCommitmentHash: GENESIS_HASH,
    signature: 'sig',
    keyId: 'kid',
    algorithm: 'RS256',
    ...overrides,
  };
  return base;
}

function buildDeps(overrides: Partial<GatewayDependencies> = {}): GatewayDependencies {
  const logger = createLogger('chain-proof-test');
  const killSwitchManager = new DefaultKillSwitchManager(logger);
  const enforcementEngine = new EnforcementEngine({
    verifier: { verify: async () => ({ sub: 'agent-1' }) } as never,
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
    serviceName: `chain-proof-test-${Date.now()}`,
    collectDefaults: false,
  });

  const decisionsCounter = new Counter({
    name: `euno_gateway_decisions_total_chain_proof_${Date.now()}`,
    help: 'test',
    labelNames: ['decision'],
    registers: [metricsRegistry],
  });

  return {
    config,
    logger,
    verifier: { verify: async () => ({ sub: 'agent-1' }) } as never,
    enforcementEngine,
    killSwitchManager,
    backendServiceUrl: 'http://localhost:65535',
    allowedOrigins: [],
    rateLimitWindowMs: 60_000,
    rateLimitMax: 10_000,
    metricsRegistry,
    decisionsCounter,
    auditPipelineDrainTimeoutMs: 5_000,
    isReady: () => true,
    adminPort: 3003,
    actionResolver: BUILTIN_ACTION_RESOLVER,
    ...overrides,
  } as GatewayDependencies;
}

// ── CrossChainCommitmentStore unit tests ──────────────────────────────────────

describe('CrossChainCommitmentStore', () => {
  test('1. add and query returns all commits when no filter', () => {
    const store = new CrossChainCommitmentStore();
    const c1 = makeCommitment();
    const c2 = makeCommitment({ commitmentSeq: 2 });
    store.add(c1);
    store.add(c2);
    const results = store.query();
    expect(results).toHaveLength(2);
    expect(results[0]).toBe(c1);
    expect(results[1]).toBe(c2);
  });

  test('2. bounded capacity evicts oldest when full', () => {
    const store = new CrossChainCommitmentStore(3);
    const c1 = makeCommitment({ commitmentSeq: 1 });
    const c2 = makeCommitment({ commitmentSeq: 2 });
    const c3 = makeCommitment({ commitmentSeq: 3 });
    const c4 = makeCommitment({ commitmentSeq: 4 });
    store.add(c1);
    store.add(c2);
    store.add(c3);
    store.add(c4); // c1 evicted
    const results = store.query();
    expect(results).toHaveLength(3);
    expect(results[0]).toBe(c2);
    expect(results[2]).toBe(c4);
  });

  test('3. since/until filtering excludes out-of-window commits', () => {
    const store = new CrossChainCommitmentStore();
    const early = makeCommitment({ commitmentSeq: 1 }, '2025-01-01T00:00:00Z');
    const mid = makeCommitment({ commitmentSeq: 2 }, '2025-06-01T00:00:00Z');
    const late = makeCommitment({ commitmentSeq: 3 }, '2026-01-01T00:00:00Z');
    store.add(early);
    store.add(mid);
    store.add(late);

    const results = store.query(
      new Date('2025-03-01T00:00:00Z'),
      new Date('2025-09-01T00:00:00Z'),
    );
    expect(results).toHaveLength(1);
    expect(results[0]).toBe(mid);
  });

  test('4. chainHead returns canonicalSha256 of most recent commit', () => {
    const store = new CrossChainCommitmentStore();
    expect(store.chainHead()).toBeNull();
    const c1 = makeCommitment({ commitmentSeq: 1 });
    const c2 = makeCommitment({ commitmentSeq: 2 });
    store.add(c1);
    store.add(c2);
    expect(store.chainHead()).toBe(canonicalSha256(c2));
    expect(store.chainHead()).not.toBe(canonicalSha256(c1));
  });
});

// ── Route tests ───────────────────────────────────────────────────────────────

describe('GET /api/v1/audit/chain-proof', () => {
  const ADMIN_KEY = 'test-admin-key-abc123';

  test('5. 401 when admin key is configured and header is missing', async () => {
    const store = new CrossChainCommitmentStore();
    const router = express();
    router.use(
      createChainProofRouter({ commitmentStore: store, adminApiKey: ADMIN_KEY, logger: createLogger('test') }),
    );
    const res = await request(router).get('/api/v1/audit/chain-proof');
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('UNAUTHORIZED');
  });

  test('6. 401 when admin key does not match', async () => {
    const store = new CrossChainCommitmentStore();
    const router = express();
    router.use(
      createChainProofRouter({ commitmentStore: store, adminApiKey: ADMIN_KEY, logger: createLogger('test') }),
    );
    const res = await request(router)
      .get('/api/v1/audit/chain-proof')
      .set('X-Admin-Api-Key', 'wrong-key-value!!!');
    expect(res.status).toBe(401);
  });

  test('7. 200 with empty commits and null chainHead when store is empty', async () => {
    const store = new CrossChainCommitmentStore();
    const router = express();
    router.use(
      createChainProofRouter({ commitmentStore: store, adminApiKey: ADMIN_KEY, logger: createLogger('test') }),
    );
    const res = await request(router)
      .get('/api/v1/audit/chain-proof')
      .set('X-Admin-Api-Key', ADMIN_KEY);
    expect(res.status).toBe(200);
    expect(res.body.commits).toEqual([]);
    expect(res.body.chainHead).toBeNull();
  });

  test('8. 200 with all commits when no filter', async () => {
    const store = new CrossChainCommitmentStore();
    const c1 = makeCommitment({ commitmentSeq: 1 });
    const c2 = makeCommitment({ commitmentSeq: 2 });
    store.add(c1);
    store.add(c2);

    const router = express();
    router.use(
      createChainProofRouter({ commitmentStore: store, adminApiKey: ADMIN_KEY, logger: createLogger('test') }),
    );
    const res = await request(router)
      .get('/api/v1/audit/chain-proof')
      .set('X-Admin-Api-Key', ADMIN_KEY);
    expect(res.status).toBe(200);
    expect(res.body.commits).toHaveLength(2);
    expect(res.body.chainHead).toBe(canonicalSha256(c2));
  });

  test('9. since/until filtering returns only matching commits', async () => {
    const store = new CrossChainCommitmentStore();
    store.add(makeCommitment({ commitmentSeq: 1 }, '2025-01-01T00:00:00Z'));
    store.add(makeCommitment({ commitmentSeq: 2 }, '2025-06-01T00:00:00Z'));
    store.add(makeCommitment({ commitmentSeq: 3 }, '2026-01-01T00:00:00Z'));

    const router = express();
    router.use(
      createChainProofRouter({ commitmentStore: store, adminApiKey: ADMIN_KEY, logger: createLogger('test') }),
    );
    const res = await request(router)
      .get('/api/v1/audit/chain-proof?since=2025-03-01T00:00:00Z&until=2025-09-01T00:00:00Z')
      .set('X-Admin-Api-Key', ADMIN_KEY);
    expect(res.status).toBe(200);
    expect(res.body.commits).toHaveLength(1);
    expect(res.body.commits[0].commitmentSeq).toBe(2);
    // chainHead should still reflect the latest commit in the entire store.
    expect(typeof res.body.chainHead).toBe('string');
  });

  test('10. 400 when since is not a valid date string', async () => {
    const store = new CrossChainCommitmentStore();
    const router = express();
    router.use(
      createChainProofRouter({ commitmentStore: store, adminApiKey: ADMIN_KEY, logger: createLogger('test') }),
    );
    const res = await request(router)
      .get('/api/v1/audit/chain-proof?since=not-a-date')
      .set('X-Admin-Api-Key', ADMIN_KEY);
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_REQUEST');
  });

  test('11. 400 when until is not a valid date string', async () => {
    const store = new CrossChainCommitmentStore();
    const router = express();
    router.use(
      createChainProofRouter({ commitmentStore: store, adminApiKey: ADMIN_KEY, logger: createLogger('test') }),
    );
    const res = await request(router)
      .get('/api/v1/audit/chain-proof?until=bad-date-value')
      .set('X-Admin-Api-Key', ADMIN_KEY);
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_REQUEST');
  });

  test('12. 400 when since is after until', async () => {
    const store = new CrossChainCommitmentStore();
    const router = express();
    router.use(
      createChainProofRouter({ commitmentStore: store, adminApiKey: ADMIN_KEY, logger: createLogger('test') }),
    );
    const res = await request(router)
      .get('/api/v1/audit/chain-proof?since=2026-01-01T00:00:00Z&until=2025-01-01T00:00:00Z')
      .set('X-Admin-Api-Key', ADMIN_KEY);
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_REQUEST');
  });

  test('13. 404 when route is absent (no commitmentStore in deps)', async () => {
    const deps = buildDeps(); // no crossChainCommitmentStore
    const app = createApp(deps);
    const res = await request(app).get('/api/v1/audit/chain-proof');
    expect(res.status).toBe(404);
  });

  test('14. route is present and works when commitmentStore is in deps', async () => {
    const store = new CrossChainCommitmentStore();
    const commit = makeCommitment({ commitmentSeq: 42 });
    store.add(commit);

    const deps = buildDeps({
      crossChainCommitmentStore: store,
      adminApiKey: ADMIN_KEY,
    });
    const app = createApp(deps);

    const res = await request(app)
      .get('/api/v1/audit/chain-proof')
      .set('X-Admin-Api-Key', ADMIN_KEY);
    expect(res.status).toBe(200);
    expect(res.body.commits).toHaveLength(1);
    expect(res.body.commits[0].commitmentSeq).toBe(42);
    expect(res.body.chainHead).toBe(canonicalSha256(commit));
  });

  test('15. open (no auth) when adminApiKey is not configured', async () => {
    const store = new CrossChainCommitmentStore();
    const router = express();
    router.use(
      createChainProofRouter({ commitmentStore: store, logger: createLogger('test') }),
    );
    // No X-Admin-Api-Key header, no adminApiKey configured → should succeed
    const res = await request(router).get('/api/v1/audit/chain-proof');
    expect(res.status).toBe(200);
    expect(res.body.commits).toEqual([]);
    expect(res.body.chainHead).toBeNull();
  });
});

// ── CrossChainAnchor + buildAuditModule integration smoke test ─────────────────

describe('CrossChainAnchor onCommitment wiring (unit)', () => {
  test('16. CrossChainAnchor calls onCommitment and CrossChainCommitmentStore.add receives it', async () => {
    // Build a minimal mock PerReplicaPostgresLedgerBackend so we can
    // exercise the CrossChainAnchor tick() without a real Postgres connection.
    const store = new CrossChainCommitmentStore();
    const received: SignedCrossChainCommitment[] = [];

    // Minimal mock for PerReplicaPostgresLedgerBackend.getReplicaTips()
    const mockBackend = {
      getReplicaTips: async () => [
        { replicaId: 'r1', seq: 1, tipHash: 'a'.repeat(64), ts: new Date().toISOString() },
      ],
    } as unknown as PerReplicaPostgresLedgerBackend;

    // Generate a fresh key pair for signing commitments.
    const { generateKeyPair } = await import('crypto');
    const { privateKey } = await new Promise<{ privateKey: import('crypto').KeyObject }>((res, rej) =>
      generateKeyPair('rsa', { modulusLength: 2048 }, (err, _pub, priv) =>
        err ? rej(err) : res({ privateKey: priv }),
      ),
    );

    const cryptoSigner = {
      getKeyId: async () => 'kid-test',
      getAlgorithm: () => 'RS256',
      signDigest: async (digest: Buffer) => {
        const { createSign } = await import('crypto');
        const sign = createSign('RSA-SHA256');
        sign.update(digest);
        return sign.sign(privateKey);
      },
    };

    const opts: CrossChainAnchorOptions = {
      intervalMs: 100_000, // long interval — we'll call tick manually via a short interval
      coordinatorId: 'test-coordinator',
      cryptoSigner,
      onCommitment: (c) => {
        store.add(c);
        received.push(c);
      },
    };

    const anchor = new CrossChainAnchor(mockBackend, opts);

    // Manually trigger one tick via a short override interval.  We use a
    // short interval and then stop quickly rather than calling tick() directly
    // (which is private).  Instead we adjust the timer by restarting with a
    // tiny interval, wait for one tick, then stop.
    // Actually since tick() is private, we use the public API: start() then
    // override the interval by constructing with a short one.
    const shortOpts: CrossChainAnchorOptions = {
      ...opts,
      intervalMs: 50, // fire quickly
    };
    const shortAnchor = new CrossChainAnchor(mockBackend, shortOpts);
    shortAnchor.start();

    // Wait for at least one commitment to be emitted.
    await new Promise<void>((resolve) => {
      const check = setInterval(() => {
        if (received.length > 0) {
          clearInterval(check);
          resolve();
        }
      }, 10);
    });

    await shortAnchor.stop();

    expect(received.length).toBeGreaterThan(0);
    expect(store.size()).toBe(received.length);
    expect(store.chainHead()).toBe(canonicalSha256(received[received.length - 1]));

    // Verify the commitment has the expected shape.
    const first = received[0]!;
    expect(first.coordinatorId).toBe('test-coordinator');
    expect(first.commitmentSeq).toBe(1);
    expect(first.previousCommitmentHash).toBe(GENESIS_HASH);
    expect(first.signature).toBeDefined();
    expect(first.keyId).toBe('kid-test');
    expect(first.algorithm).toBe('RS256');

    // Anchor object is unused; suppress lint warning.
    void anchor;
  });
});



// ── timingSafeEqual multi-byte buffer test ────────────────────────────────────

describe('chain-proof route: timingSafeEqual safety', () => {
  test('15. rejects multi-byte Unicode key with 401, not RangeError', () => {
    // HTTP headers are ASCII-only, so we bypass the HTTP layer and invoke the
    // Express route handler directly via a synthetic req/res.  This exercises
    // the buffer byte-length guard that was added to the timingSafeEqual call.
    //
    // The concern: Buffer.from('\u00e9'.repeat(N)) has 2×N bytes while
    // Buffer.from('a'.repeat(N)) has N bytes — if the code compared .length
    // (character count) before calling timingSafeEqual it would crash with
    // RangeError because timingSafeEqual requires equal-length buffers.

    const ADMIN_KEY = 'ascii-admin-key'; // 15 ASCII bytes

    let capturedStatus = 0;
    const mockReq = {
      headers: {
        // '\u00e9' (é) is 2 UTF-8 bytes — 15 of these = 30 bytes vs 15 bytes
        'x-admin-api-key': '\u00e9'.repeat(15),
      },
      ip: '127.0.0.1',
      path: '/api/v1/audit/chain-proof',
      query: {},
    } as unknown as import('express').Request;

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    } as unknown as import('express').Response;

    const mockNext = jest.fn();

    const store = new CrossChainCommitmentStore();
    const router = createChainProofRouter({
      commitmentStore: store,
      adminApiKey: ADMIN_KEY,
      logger: createLogger('test'),
    }) as import('express').Router & {
      stack: Array<{ route?: { stack: Array<{ handle: (req: import('express').Request, res: import('express').Response, next: import('express').NextFunction) => void }> } }>;
    };

    const layer = router.stack.find((l) => l.route?.stack?.[0]?.handle != null);
    const handler = layer?.route?.stack?.[0]?.handle;
    expect(handler).toBeDefined();

    // Must not throw — previously timingSafeEqual would throw RangeError.
    expect(() => handler!(mockReq, mockRes, mockNext)).not.toThrow();
    const statusCall = (mockRes.status as jest.Mock).mock.calls[0];
    capturedStatus = statusCall?.[0] ?? 0;
    expect(capturedStatus).toBe(401);
    expect(mockNext).not.toHaveBeenCalled();
  });
});

// ── buildAuditModule ENABLE_CROSS_CHAIN_ANCHOR focused test ──────────────────

describe('buildAuditModule: ENABLE_CROSS_CHAIN_ANCHOR=true', () => {
  const TEST_RSA_PRIVATE_KEY_PEM = [
    '-----BEGIN PRIVATE KEY-----',
    'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCRbcqcm4RSzpZE',
    'LhFkcBG1JCwd08CEuijtZEv/etyIAv5lQtFui+Tn5JUaCqFYCyog6ISPDLAXWU+q',
    '5rtgZ9T/6glKuVjt6HESV8uyTYhLgjXqurreF1NIzoYY99Bf/ErT183tbXeDUevS',
    'A76zzg5lDIVYXtuJrk8nPCe/lvCSejTG4E9lTU44uiTXGDeiv9tf2jDKHKriwKkW',
    'AQvfxObXMNWGHg6LR85QTc6QhBdx7+7HrJX7+5rDsRj+pCxeCOmAxVbJyNJIE+wu',
    'GaLEjJ3g+1lp7mReC3WrcbDWXwlw1N7TG1/uvCz5/4fnra5pqyAfL8jA3CaHZW08',
    'o9PiAfnbAgMBAAECggEAFKAkgnCWDvkoxl5dmMfs4wAl16HJe1Q8a2rJp+AgzejV',
    'dBQgHZRusIAysLZS6r3untXgvbnCxxT4ym1zTs7Qc+6ZRxqhemB4mkLka2iOojLt',
    '+wQPw7boLiUdpLCPl5rHHA4j29QmL/RFmgwY7GnBkI2ljdfU6CKA1w4zjvsqfy4/',
    'cTFoQjqTTdiQXcVrKpi8de8cpLvq4b3EE+20wjT3bZkrhyxFBrKNBsX8rYcXedCm',
    'GXNtSQ/6B6LxCR9Rg9Ob4YLsuPKS8/xoBrNbHX1/y2qRcEvrqU8blanYc038xayB',
    'rLdODP+WUd31tTmSSBeLfEdPLG7PZE1INgZ1TvKi0QKBgQDHzNVWfSdG9cwlKyZi',
    'Df/Z/8zqBsB+vUN7X3nhvjFa+320ywHrabvj3Vp51nHhEScOQMe9MdClxwNZlqd5',
    '1Fgh3CGU9v0mfDXeO4CpPDwSWCCPKQNlL8F5fOGTrRmYjPnmWoYgNCXNs5euJKd5',
    'Q6J7R/Ei/nMy1gxqbxboxoc2ywKBgQC6Vc3FMn1N1fsk7nzn2tj5sgd3rFCS8Xng',
    '5HqYeN13QBHlo42bBLsP1nlMJ/5meny+XzNI+VJtTnh4xcNYoa+Aqw7J7c5qDTAD',
    '3UBDCHTBU6kj3HiNDtxNIB+jPwbV4f9tRXOVxX6w3rhSfhLp3wxu9G09ssjp6YY9',
    'THShedTXMQKBgB9nfbzbbRoFNnI9JwpQgv+D6nR6XTVOkFXK+wBVgbJ4Rxjss7+J',
    '3gOB3l+6KiojJQ1jd0Gwm8gC0O769BX9H2ErFYgxjjbHXTwyBBYVpqeHfI6j9qmn',
    '6PQsgdRRZ+2HcxwW7HARYkPDz7qKflxcGiTgePF0Jy09YbQ1A9fQpJ4jAoGAVEuc',
    '2ykMJro2824wc3M91TgEyM7bZJ55VJQIIhILnncNoaVr2kU5muCb3yf4nsOqyzSm',
    'Ls0bzPdC6OAOj3oVu0+nURKT3sY4gocFG04oA42lZuPGZYnjf8CYj3Fj1j53Hyfc',
    'MlU2Cy22lRsT01lkdo19HfxTh/5tDC4aVTKYZwECgYEAjtyulM8jacJ/FpJjUGjw',
    '5MtavO+lyrD1kxQVhzT93Oan8tMQKfBksXHlUah7Q2Oi0KV34eRKcHdNzksE4cE+',
    'KZQp59vlDT9PCE87yvOu6dVxznU2m/U36egVbZ6MDAEMDO49QBGT0LuSfUWsdU18',
    '2t71DZdT4IU46NRr4GY/NAU=',
    '-----END PRIVATE KEY-----',
  ].join('\n');

  function makeValidated(
    overrides: Partial<import('@euno/common').GatewayConfig> = {},
  ): import('@euno/common').GatewayConfig {
    return {
      ENABLE_CRYPTOGRAPHIC_AUDIT: true,
      AUDIT_LEDGER_BACKEND: 'per-replica-postgres',
      AUDIT_LEDGER_PG_URL: 'postgresql://mock:mock@localhost:5432/mock',
      AUDIT_LEDGER_HMAC_SECRET: 'test-hmac-secret-at-least-32-bytes-long!!',
      ENABLE_CROSS_CHAIN_ANCHOR: true,
      AUDIT_LEDGER_CROSS_CHAIN_INTERVAL_MS: 60000,
      AUDIT_PIPELINE_ENABLED: false,
      AUDIT_PIPELINE_MAX_SIZE: 1000,
      AUDIT_PIPELINE_WORKERS: 1,
      AUDIT_PIPELINE_MAX_BATCH: 100,
      AUDIT_PIPELINE_MAX_AGE_MS: 5000,
      AUDIT_PIPELINE_DRAIN_TIMEOUT_MS: 5000,
      NODE_ENV: 'test',
      ...overrides,
    } as unknown as import('@euno/common').GatewayConfig;
  }

  function makeAuditModuleArgs(
    logger = createLogger('build-audit-module-test'),
    overrides: {
      validated?: import('@euno/common').GatewayConfig;
      env?: NodeJS.ProcessEnv;
    } = {},
  ) {
    const metricsRegistry = createMetricsRegistry({
      serviceName: `build-audit-module-test-${Date.now()}`,
      collectDefaults: false,
    });
    return {
      validated: overrides.validated ?? makeValidated(),
      env: { EVIDENCE_SIGNING_KEY_PEM: TEST_RSA_PRIVATE_KEY_PEM, ...overrides.env },
      logger,
      config: {
        name: 'tool-gateway',
        port: 0,
        environment: 'test' as ServiceConfig['environment'],
        enableCryptographicAudit: true,
        policyVersion: '0.1.0',
      },
      metricsRegistry,
      replicaId: 'test-replica',
    };
  }

  test('17. creates crossChainCommitmentStore and calls start() on the anchor', async () => {
    // Spy on CrossChainAnchor.prototype.start to verify it is called without
    // letting a real timer fire (and without needing getReplicaTips to succeed).
    const startSpy = jest.spyOn(CrossChainAnchor.prototype, 'start').mockImplementation(() => {
      // no-op: prevents setInterval from being created
    });
    const result = await buildAuditModule(makeAuditModuleArgs());

    // Key assertions: anchor and store are both present.
    expect(result.crossChainAnchor).toBeDefined();
    expect(result.crossChainCommitmentStore).toBeDefined();
    expect(result.crossChainCommitmentStore).toBeInstanceOf(CrossChainCommitmentStore);

    // start() must have been called — this is the core of what the reviewer asked for.
    expect(startSpy).toHaveBeenCalledTimes(1);

    // Verify the anchor was constructed with AUDIT_LEDGER_CROSS_CHAIN_INTERVAL_MS
    // from the validated config (60000 ms in this test fixture).  intervalMs is a
    // private field so we reach it via a typed cast rather than exposing it publicly.
    const anchorInterval = (result.crossChainAnchor as unknown as { intervalMs: number }).intervalMs;
    expect(anchorInterval).toBe(60000);

    startSpy.mockRestore();
    if (result.ledgerPgPool) {
      await result.ledgerPgPool.end();
    }
  });

  test('18. reuses the GCS prefix for object-store-backed per-replica anchors without the legacy warning', async () => {
    const startSpy = jest.spyOn(CrossChainAnchor.prototype, 'start').mockImplementation(() => {
      // no-op
    });
    const logger = createLogger('build-audit-module-gcs-test');
    const warnSpy = jest
      .spyOn(logger, 'warn')
      .mockImplementation((() => logger) as typeof logger.warn);

    const result = await buildAuditModule(
      makeAuditModuleArgs(logger, {
        validated: makeValidated({
          AUDIT_LEDGER_OBJECT_STORE_PROVIDER: 'gcs',
          AUDIT_LEDGER_GCS_BUCKET: 'audit-gcs-bucket',
          AUDIT_LEDGER_GCS_PREFIX: 'cluster-a/',
        }),
        env: {
          AUDIT_LEDGER_OBJECT_STORE_PROVIDER: 'gcs',
          AUDIT_LEDGER_GCS_BUCKET: 'audit-gcs-bucket',
          AUDIT_LEDGER_GCS_PREFIX: 'cluster-a/',
        },
      }),
    );

    expect((result.auditLedgerBackend as unknown as { objectStoresPrefix: string }).objectStoresPrefix)
      .toBe('cluster-a/');
    expect((result.crossChainAnchor as unknown as { objectStoresPrefix: string }).objectStoresPrefix)
      .toBe('cluster-a/');
    expect(
      warnSpy.mock.calls.some((call) => {
        const message = call[0] as unknown;
        return (
          typeof message === 'string' &&
          message.includes('AUDIT_LEDGER_GCS_BUCKET is set with per-replica-postgres')
        );
      }),
    ).toBe(false);

    warnSpy.mockRestore();
    startSpy.mockRestore();
    if (result.ledgerPgPool) {
      await result.ledgerPgPool.end();
    }
  });

  test('19. allows the postgres backend to use the generic GCS object store path', async () => {
    const logger = createLogger('build-audit-module-postgres-gcs-test');
    const result = await buildAuditModule(
      makeAuditModuleArgs(logger, {
        validated: makeValidated({
          AUDIT_LEDGER_BACKEND: 'postgres',
          ENABLE_CROSS_CHAIN_ANCHOR: false,
          AUDIT_LEDGER_OBJECT_STORE_PROVIDER: 'gcs',
          AUDIT_LEDGER_GCS_BUCKET: 'audit-gcs-bucket',
          AUDIT_LEDGER_GCS_PREFIX: 'cluster-b/',
        }),
        env: {
          AUDIT_LEDGER_OBJECT_STORE_PROVIDER: 'gcs',
          AUDIT_LEDGER_GCS_BUCKET: 'audit-gcs-bucket',
          AUDIT_LEDGER_GCS_PREFIX: 'cluster-b/',
        },
      }),
    );

    expect((result.auditLedgerBackend as unknown as { objectStoresPrefix: string }).objectStoresPrefix)
      .toBe('cluster-b/');
    expect(result.crossChainAnchor).toBeUndefined();

    if (result.ledgerPgPool) {
      await result.ledgerPgPool.end();
    }
  });
});
