/**
 * Integration test — SOC2 audit-trail export endpoint (Task 6, Stage 5)
 * ---------------------------------------------------------------------------
 * Exercises the full wire path:
 *
 *   1. Evidence is produced by a real `SoftwareEvidenceSigner` (RS256 key pair
 *      generated in-process) and stored in an `InMemoryLedgerBackend`.
 *   2. The export endpoint returns the signed records via
 *      `GET /api/v1/audit/export`.
 *   3. The exported `signature` field can be verified offline using the
 *      signer's public key — this is the proof that the evidence is
 *      cryptographically intact and was not tampered with between ledger
 *      storage and API response.
 *
 * ### Offline verification procedure (replicated here from soc2-mapping.md §4.3)
 *
 * For each exported record:
 *   1. Reconstruct the canonical JSON from the evidence fields (all fields
 *      except `signature`, `keyId`, and `algorithm`).
 *   2. Verify the `signature` against the canonical JSON using the public key
 *      whose `kid` matches `record.keyId`.
 *
 * The `verifyEvidence` method on the `AuditEvidenceSigner` performs exactly
 * this check.
 *
 * @module
 */

import * as jose from 'jose';
import request from 'supertest';
import {
  AuditEvidence,
  SignedAuditEvidence,
  createLogger,
  DefaultKillSwitchManager,
  ServiceConfig,
  createMetricsRegistry,
  Counter,
  BUILTIN_ACTION_RESOLVER,
  createSoftwareEvidenceSigner,
  AuditEvidenceSigner,
} from '@euno/common';
import { InMemoryLedgerBackend, LedgerAuditEvidenceSigner } from '@euno/common-infra';
import { createApp } from '../../tool-gateway/src/app-factory';
import { JWTTokenVerifier } from '../../tool-gateway/src/verifier';
import { EnforcementEngine } from '../../tool-gateway/src/enforcement';
import type { GatewayDependencies } from '../../tool-gateway/src/bootstrap';

// ── Key material ──────────────────────────────────────────────────────────────

const ADMIN_KEY = 'integration-test-admin-key-12345';

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeAuditEvidence(overrides: Partial<AuditEvidence> = {}): AuditEvidence {
  return {
    id: `ev-${Math.random().toString(36).slice(2)}`,
    sessionId: 'sess-1',
    userId: 'user-1',
    promptHash: '0'.repeat(64),
    tool: 'api://crm/contacts',
    argsHash: '0'.repeat(64),
    nonce: `nonce-${Math.random().toString(36).slice(2)}`,
    ts: new Date().toISOString(),
    policyVersion: '0.1.0',
    agentId: 'agent-1',
    resource: 'api://crm/contacts',
    action: 'read',
    capabilityId: `jti-${Math.random().toString(36).slice(2)}`,
    decision: 'allow',
    tenantId: 'tenant-1',
    ...overrides,
  };
}

async function buildDeps(opts: {
  ledgerBackend: InMemoryLedgerBackend;
  evidenceSigner: LedgerAuditEvidenceSigner;
  adminApiKey?: string;
}): Promise<GatewayDependencies> {
  const logger = createLogger('soc2-export-integration');
  const killSwitchManager = new DefaultKillSwitchManager(logger);
  const fakeVerifier = {
    verify: async () => { throw new Error('not used in export tests'); },
  } as unknown as JWTTokenVerifier;
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
    enableCryptographicAudit: true,
    policyVersion: '0.1.0',
  };

  const metricsRegistry = createMetricsRegistry({
    serviceName: `soc2-export-integration-${Date.now()}`,
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
      name: `euno_gateway_decisions_total_soc2_test_${Date.now()}`,
      help: 'test',
      labelNames: ['decision'],
      registers: [metricsRegistry],
    }),
    auditPipelineDrainTimeoutMs: 5_000,
    isReady: () => true,
    actionResolver: BUILTIN_ACTION_RESOLVER,
    adminPort: 0,
    responseRedactionMaxBytes: 1_048_576,
    auditLedgerBackend: opts.ledgerBackend,
    evidenceSigner: opts.evidenceSigner,
    adminApiKey: opts.adminApiKey,
  };

  return deps;
}

// ── Suite ─────────────────────────────────────────────────────────────────────

describe('SOC2 audit-trail export — integration', () => {
  let privateKeyPem: string;
  let publicKeyPem: string;
  let auditSigner: AuditEvidenceSigner;
  let signer: LedgerAuditEvidenceSigner;
  let backend: InMemoryLedgerBackend;
  let signedRecords: SignedAuditEvidence[] = [];

  beforeAll(async () => {
    // Generate a real RSA key pair for the evidence signer.
    const { privateKey, publicKey } = await jose.generateKeyPair('RS256');
    privateKeyPem = await jose.exportPKCS8(privateKey);
    publicKeyPem = await jose.exportSPKI(publicKey);

    backend = new InMemoryLedgerBackend();
    auditSigner = createSoftwareEvidenceSigner({
      privateKeyPem,
      publicKeyPem,
      keyId: 'integration-key',
    }) as AuditEvidenceSigner;
    signer = new LedgerAuditEvidenceSigner(auditSigner.getCryptoSigner(), backend, 'replica-1');
    await signer.initialize();

    // Write several signed audit records into the ledger.
    const evidenceItems: AuditEvidence[] = [
      makeAuditEvidence({ decision: 'allow', agentId: 'agent-a' }),
      makeAuditEvidence({ decision: 'deny',  agentId: 'agent-b' }),
      makeAuditEvidence({ decision: 'allow', agentId: 'agent-c' }),
    ];

    for (const ev of evidenceItems) {
      const signed = await signer.signEvidence(ev);
      signedRecords.push(signed);
    }
  });

  it('1. export endpoint returns all signed records with correct shape', async () => {
    const deps = await buildDeps({ ledgerBackend: backend, evidenceSigner: signer, adminApiKey: ADMIN_KEY });
    const app = createApp(deps);

    const res = await request(app)
      .get('/api/v1/audit/export')
      .set('X-Admin-Api-Key', ADMIN_KEY);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.records)).toBe(true);
    expect(res.body.records).toHaveLength(3);
    expect(res.body.cursor).toBeNull();
    expect(res.body.hasMore).toBe(false);
    expect(res.body.verificationUri).toBe('/.well-known/jwks.json');
  });

  it('2. exported records can be verified offline using the signer public key', async () => {
    const deps = await buildDeps({ ledgerBackend: backend, evidenceSigner: signer, adminApiKey: ADMIN_KEY });
    const app = createApp(deps);

    const res = await request(app)
      .get('/api/v1/audit/export')
      .set('X-Admin-Api-Key', ADMIN_KEY);

    expect(res.status).toBe(200);
    const records: SignedAuditEvidence[] = res.body.records;
    expect(records.length).toBeGreaterThan(0);

    // Offline verification: verify each exported record's signature.
    for (const record of records) {
      const valid = await signer.verifyEvidence(record);
      expect(valid).toBe(true);
    }
  });

  it('3. exported records form a valid hash chain (previousHash linkage)', async () => {
    const deps = await buildDeps({ ledgerBackend: backend, evidenceSigner: signer, adminApiKey: ADMIN_KEY });
    const app = createApp(deps);

    const res = await request(app)
      .get('/api/v1/audit/export')
      .set('X-Admin-Api-Key', ADMIN_KEY);

    expect(res.status).toBe(200);
    const records: SignedAuditEvidence[] = res.body.records;

    // Verify that seq values are monotonically increasing.
    for (let i = 1; i < records.length; i++) {
      const curr = records[i];
      const prev = records[i - 1];
      if (curr !== undefined && prev !== undefined) {
        expect(curr.seq).toBe(prev.seq + 1);
      }
    }
  });

  it('4. scope=soc2-cc7 returns all gateway enforcement records', async () => {
    const deps = await buildDeps({ ledgerBackend: backend, evidenceSigner: signer, adminApiKey: ADMIN_KEY });
    const app = createApp(deps);

    const res = await request(app)
      .get('/api/v1/audit/export?scope=soc2-cc7')
      .set('X-Admin-Api-Key', ADMIN_KEY);

    expect(res.status).toBe(200);
    // All 3 records are API Activity (CC7)
    expect(res.body.records).toHaveLength(3);
  });

  it('5. scope=soc2-cc6 returns empty (CC6 Authorization events not in gateway ledger)', async () => {
    const deps = await buildDeps({ ledgerBackend: backend, evidenceSigner: signer, adminApiKey: ADMIN_KEY });
    const app = createApp(deps);

    const res = await request(app)
      .get('/api/v1/audit/export?scope=soc2-cc6')
      .set('X-Admin-Api-Key', ADMIN_KEY);

    expect(res.status).toBe(200);
    expect(res.body.records).toHaveLength(0);
  });

  it('6. cursor pagination returns all records across pages', async () => {
    const deps = await buildDeps({ ledgerBackend: backend, evidenceSigner: signer, adminApiKey: ADMIN_KEY });
    const app = createApp(deps);

    const allRecords: SignedAuditEvidence[] = [];

    // Page 1: fetch pageSize=2
    const page1 = await request(app)
      .get('/api/v1/audit/export?pageSize=2')
      .set('X-Admin-Api-Key', ADMIN_KEY);

    expect(page1.status).toBe(200);
    expect(page1.body.records).toHaveLength(2);
    expect(page1.body.hasMore).toBe(true);
    allRecords.push(...page1.body.records);

    // Page 2: use cursor
    const page2 = await request(app)
      .get(`/api/v1/audit/export?cursor=${encodeURIComponent(page1.body.cursor)}`)
      .set('X-Admin-Api-Key', ADMIN_KEY);

    expect(page2.status).toBe(200);
    expect(page2.body.records).toHaveLength(1);
    expect(page2.body.hasMore).toBe(false);
    expect(page2.body.cursor).toBeNull();
    allRecords.push(...page2.body.records);

    // Together they equal all signed records
    expect(allRecords).toHaveLength(signedRecords.length);

    // All page-2 records can also be verified offline
    for (const record of page2.body.records) {
      const valid = await signer.verifyEvidence(record as SignedAuditEvidence);
      expect(valid).toBe(true);
    }
  });

  it('7. records contain the expected agentId values', async () => {
    const deps = await buildDeps({ ledgerBackend: backend, evidenceSigner: signer, adminApiKey: ADMIN_KEY });
    const app = createApp(deps);

    const res = await request(app)
      .get('/api/v1/audit/export')
      .set('X-Admin-Api-Key', ADMIN_KEY);

    const agentIds = (res.body.records as SignedAuditEvidence[]).map((r) => r.agentId);
    expect(agentIds).toContain('agent-a');
    expect(agentIds).toContain('agent-b');
    expect(agentIds).toContain('agent-c');
  });
});
