/**
 * Minter metrics — unit tests (Task 12, Stage 3)
 * ────────────────────────────────────────────────────────────────────────────
 * Tests cover:
 *
 *   1. All six metric types exist and have the correct names.
 *   2. `mintTotal` increments by tenant and result labels.
 *   3. `mintLatencySeconds` timer resolves and the registry collects it.
 *   4. `kmsSignLatencySeconds` timer resolves and the registry collects it.
 *   5. `kmsErrorTotal` increments by provider and error_class.
 *   6. `anomalyAlertsTotal` increments by tenant and rule.
 *   7. `keyRotationTotal` increments by kid and reason.
 *   8. The `/metrics` HTTP endpoint returns valid Prometheus text format.
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
    minterMetrics.mintTotal.inc({ tenant: 'test-tenant', result: 'minted' });
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/euno_minter_mint_total/);
  });

  it('registers euno_minter_mint_latency_seconds histogram', async () => {
    const end = minterMetrics.mintLatencySeconds.startTimer({ tenant: 'test' });
    end();
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/euno_minter_mint_latency_seconds/);
  });

  it('registers euno_minter_kms_sign_latency_seconds histogram', async () => {
    const end = minterMetrics.kmsSignLatencySeconds.startTimer({ provider: 'aws-kms' });
    end();
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/euno_minter_kms_sign_latency_seconds/);
  });

  it('registers euno_minter_kms_error_total counter', async () => {
    minterMetrics.kmsErrorTotal.inc({ provider: 'aws-kms', error_class: 'sign_failed' });
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/euno_minter_kms_error_total/);
  });

  it('registers euno_minter_anomaly_alerts_total counter', async () => {
    minterMetrics.anomalyAlertsTotal.inc({ tenant: 't1', rule: 'rate_spike' });
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/euno_minter_anomaly_alerts_total/);
  });

  it('registers euno_minter_key_rotation_total counter', async () => {
    minterMetrics.keyRotationTotal.inc({ kid: 'kid-1', reason: 'scheduled' });
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/euno_minter_key_rotation_total/);
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

  it('supports kms_error result label', async () => {
    minterMetrics.mintTotal.inc({ tenant: 'acme', result: 'kms_error' });
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/result="kms_error"/);
  });
});

// ── Test 3: Histogram timers ─────────────────────────────────────────────────

describe('mintLatencySeconds histogram', () => {
  it('startTimer().end() increments the bucket count', async () => {
    const end = minterMetrics.mintLatencySeconds.startTimer({ tenant: 'acme' });
    end();
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/euno_minter_mint_latency_seconds_count\{.*tenant="acme".*\} 1/);
  });
});

describe('kmsSignLatencySeconds histogram', () => {
  it('records latency for KMS sign operations by provider', async () => {
    const end = minterMetrics.kmsSignLatencySeconds.startTimer({ provider: 'azure-keyvault' });
    end();
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/euno_minter_kms_sign_latency_seconds_count\{.*provider="azure-keyvault".*\} 1/);
  });

  it('tracks different providers separately', async () => {
    const end1 = minterMetrics.kmsSignLatencySeconds.startTimer({ provider: 'aws-kms' });
    end1();
    const end2 = minterMetrics.kmsSignLatencySeconds.startTimer({ provider: 'gcp-cloudkms' });
    end2();
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/provider="aws-kms"/);
    expect(text).toMatch(/provider="gcp-cloudkms"/);
  });
});

// ── Test 4: kmsErrorTotal counter ────────────────────────────────────────────

describe('kmsErrorTotal counter', () => {
  it('increments by provider and error_class', async () => {
    minterMetrics.kmsErrorTotal.inc({ provider: 'aws-kms', error_class: 'sign_failed' });
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/provider="aws-kms"/);
    expect(text).toMatch(/error_class="sign_failed"/);
  });

  it('tracks auth_error class separately', async () => {
    minterMetrics.kmsErrorTotal.inc({ provider: 'azure-keyvault', error_class: 'auth_error' });
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/error_class="auth_error"/);
  });

  it('tracks timeout class separately', async () => {
    minterMetrics.kmsErrorTotal.inc({ provider: 'gcp-cloudkms', error_class: 'timeout' });
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/error_class="timeout"/);
  });

  it('tracks unavailable class separately', async () => {
    minterMetrics.kmsErrorTotal.inc({ provider: 'aws-kms', error_class: 'unavailable' });
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/error_class="unavailable"/);
  });
});

// ── Test 5: anomalyAlertsTotal counter ────────────────────────────────────────

describe('anomalyAlertsTotal counter', () => {
  it('increments by tenant and rule', async () => {
    minterMetrics.anomalyAlertsTotal.inc({ tenant: 'acme', rule: 'rate_spike' });
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/rule="rate_spike"/);
    expect(text).toMatch(/tenant="acme"/);
  });

  it('tracks off_hours_low_activity rule separately', async () => {
    minterMetrics.anomalyAlertsTotal.inc({ tenant: 'acme', rule: 'off_hours_low_activity' });
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/rule="off_hours_low_activity"/);
  });

  it('tracks failure_clustering rule separately', async () => {
    minterMetrics.anomalyAlertsTotal.inc({ tenant: 'acme', rule: 'failure_clustering' });
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/rule="failure_clustering"/);
  });
});

// ── Test 6: keyRotationTotal counter ─────────────────────────────────────────

describe('keyRotationTotal counter', () => {
  it('increments for scheduled rotation', async () => {
    minterMetrics.keyRotationTotal.inc({ kid: 'key-v1', reason: 'scheduled' });
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/kid="key-v1"/);
    expect(text).toMatch(/reason="scheduled"/);
  });

  it('increments for emergency rotation', async () => {
    minterMetrics.keyRotationTotal.inc({ kid: 'key-v2', reason: 'emergency' });
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/reason="emergency"/);
  });

  it('increments for rotation completion', async () => {
    minterMetrics.keyRotationTotal.inc({ kid: 'key-v2', reason: 'completed' });
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/reason="completed"/);
  });

  it('tracks different kids independently', async () => {
    minterMetrics.keyRotationTotal.inc({ kid: 'kid-a', reason: 'scheduled' });
    minterMetrics.keyRotationTotal.inc({ kid: 'kid-b', reason: 'emergency' });
    const text = await minterMetrics.registry.metrics();
    expect(text).toMatch(/kid="kid-a"/);
    expect(text).toMatch(/kid="kid-b"/);
  });
});

// ── Test 7: /metrics HTTP endpoint ───────────────────────────────────────────

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

  it('response includes all six metric families', async () => {
    minterMetrics.mintTotal.inc({ tenant: 'x', result: 'minted' });
    minterMetrics.mintLatencySeconds.startTimer({ tenant: 'x' })();
    minterMetrics.kmsSignLatencySeconds.startTimer({ provider: 'local' })();
    minterMetrics.kmsErrorTotal.inc({ provider: 'local', error_class: 'sign_failed' });
    minterMetrics.anomalyAlertsTotal.inc({ tenant: 'x', rule: 'rate_spike' });
    minterMetrics.keyRotationTotal.inc({ kid: 'k1', reason: 'scheduled' });

    const app = await buildApp();
    const resp = await request(app).get('/metrics');
    expect(resp.text).toMatch(/euno_minter_mint_total/);
    expect(resp.text).toMatch(/euno_minter_mint_latency_seconds/);
    expect(resp.text).toMatch(/euno_minter_kms_sign_latency_seconds/);
    expect(resp.text).toMatch(/euno_minter_kms_error_total/);
    expect(resp.text).toMatch(/euno_minter_anomaly_alerts_total/);
    expect(resp.text).toMatch(/euno_minter_key_rotation_total/);
  });
});
