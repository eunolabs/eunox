/**
 * Minter metrics — unit tests (Task 11, Stage 3)
 * ────────────────────────────────────────────────────────────────────────────
 * Tests cover:
 *
 *   1. All four metric types exist and have the correct names.
 *   2. `mintTotal` increments by tenant and result labels.
 *   3. `mintLatencySeconds` timer resolves and the registry collects it.
 *   4. `kmsErrorTotal` increments by provider and operation.
 *   5. `anomalyAlertsTotal` increments by tenant and kind.
 *   6. The `/metrics` HTTP endpoint returns valid Prometheus text format.
 */

import request from 'supertest';
import { minterMetrics } from '../src/metrics';
import { createMinterApp } from '../src/app-factory';
import { InMemoryMintAuditStore } from '../src/mint-audit';
import { InMemoryMintRateLimiter } from '../src/mint-rate-limiter';
import { ApiKeyVerifier } from '../src/api-key-verifier';
import { TokenMinter } from '../src/token-minter';
import { LocalTokenSigner } from '../src/local-token-signer';
import { InMemoryApiKeyStore } from '../src/api-key-store';
import { createLogger } from '@euno/common';

// ── Test isolation ─────────────────────────────────────────────────────────────
// Reset the isolated registry before each test to avoid counter carry-over.
beforeEach(async () => {
  await minterMetrics.registry.resetMetrics();
});

// ── Test 1: Metric names and types ────────────────────────────────────────────

describe('minterMetrics — metric definitions', () => {
  it('exports a Prometheus Registry', () => {
    expect(minterMetrics.registry).toBeDefined();
    expect(typeof minterMetrics.registry.metrics).toBe('function');
  });

  it('registers euno_minter_mint_total counter', async () => {
    const text = await minterMetrics.registry.metrics();
    minterMetrics.mintTotal.inc({ tenant: 'test-tenant', result: 'minted' });
    const text2 = await minterMetrics.registry.metrics();
    expect(text2).toMatch(/euno_minter_mint_total/);
    void text; // avoid unused
  });

  it('registers euno_minter_mint_latency_seconds histogram', async () => {
    const end = minterMetrics.mintLatencySeconds.startTimer({ tenant: 'test' });
    end();
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/euno_minter_mint_latency_seconds/);
  });

  it('registers euno_minter_kms_error_total counter', async () => {
    minterMetrics.kmsErrorTotal.inc({ provider: 'aws-kms', operation: 'sign' });
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/euno_minter_kms_error_total/);
  });

  it('registers euno_minter_anomaly_alerts_total counter', async () => {
    minterMetrics.anomalyAlertsTotal.inc({ tenant: 't1', kind: 'burst_detected' });
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/euno_minter_anomaly_alerts_total/);
  });
});

// ── Test 2: Counter increments ────────────────────────────────────────────────

describe('mintTotal counter', () => {
  it('increments by 1 for a minted result', async () => {
    minterMetrics.mintTotal.inc({ tenant: 'acme', result: 'minted' });
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/euno_minter_mint_total\{.*tenant="acme".*result="minted".*\} 1/);
  });

  it('increments separately per result label', async () => {
    minterMetrics.mintTotal.inc({ tenant: 'acme', result: 'minted' });
    minterMetrics.mintTotal.inc({ tenant: 'acme', result: 'rate_limited' });
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/result="minted".*1|1.*result="minted"/);
    expect(text).toMatch(/result="rate_limited".*1|1.*result="rate_limited"/);
  });

  it('increments separately per tenant label', async () => {
    minterMetrics.mintTotal.inc({ tenant: 'acme', result: 'minted' });
    minterMetrics.mintTotal.inc({ tenant: 'beta', result: 'minted' });
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/tenant="acme"/);
    expect(text).toMatch(/tenant="beta"/);
  });
});

// ── Test 3: Histogram timer ────────────────────────────────────────────────────

describe('mintLatencySeconds histogram', () => {
  it('startTimer().end() increments the bucket count', async () => {
    const end = minterMetrics.mintLatencySeconds.startTimer({ tenant: 'acme' });
    end();
    const text = await minterMetrics.registry.metrics();
    // The _count metric includes any default labels set on the registry.
    expect(text).toMatch(/euno_minter_mint_latency_seconds_count\{.*tenant="acme".*\} 1/);
  });
});

// ── Test 4: kmsErrorTotal counter ────────────────────────────────────────────

describe('kmsErrorTotal counter', () => {
  it('increments by provider and operation', async () => {
    minterMetrics.kmsErrorTotal.inc({ provider: 'aws-kms', operation: 'sign' });
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/provider="aws-kms"/);
    expect(text).toMatch(/operation="sign"/);
  });

  it('tracks get_public_key operation separately', async () => {
    minterMetrics.kmsErrorTotal.inc({ provider: 'gcp-cloudkms', operation: 'get_public_key' });
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/operation="get_public_key"/);
  });
});

// ── Test 5: anomalyAlertsTotal counter ────────────────────────────────────────

describe('anomalyAlertsTotal counter', () => {
  it('increments by tenant and kind', async () => {
    minterMetrics.anomalyAlertsTotal.inc({ tenant: 'acme', kind: 'burst_detected' });
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/kind="burst_detected"/);
    expect(text).toMatch(/tenant="acme"/);
  });
});

// ── Test 6: /metrics HTTP endpoint ───────────────────────────────────────────

describe('/metrics endpoint', () => {
  async function buildApp() {
    const signer = await LocalTokenSigner.generate('RS256');
    const keyStore = new InMemoryApiKeyStore();
    const auditStore = new InMemoryMintAuditStore();
    const rateLimiter = new InMemoryMintRateLimiter({ maxMintsPerWindow: 100, windowSeconds: 60 });
    const logger = createLogger('test-metrics');
    const peppers = [{ version: 'v1', key: Buffer.alloc(32, 0xab) }];
    const verifier = new ApiKeyVerifier({ store: keyStore, peppers, logger });
    const minter = new TokenMinter({
      signer,
      issuerDid: 'did:web:test',
      gatewayAudience: 'tool-gateway',
      ttlSeconds: 300,
    });
    return createMinterApp({
      mintRouterOpts: { verifier, minter, auditStore, rateLimiter, logger },
      adminKeysRouterOpts: {
        keyStore,
        peppers,
        adminApiKey: 'test-admin',
        logger,
      },
      logger,
    });
  }

  it('responds 200 to GET /metrics', async () => {
    const app = await buildApp();
    const resp = await request(app).get('/metrics');
    expect(resp.status).toBe(200);
  });

  it('responds with Prometheus text content type', async () => {
    const app = await buildApp();
    const resp = await request(app).get('/metrics');
    expect(resp.headers['content-type']).toMatch(/text\/plain/);
  });

  it('response body includes euno_minter_ prefixed metrics', async () => {
    minterMetrics.mintTotal.inc({ tenant: 't1', result: 'minted' });
    const app = await buildApp();
    const resp = await request(app).get('/metrics');
    expect(resp.text).toMatch(/euno_minter_/);
  });
});
