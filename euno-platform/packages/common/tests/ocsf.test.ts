/**
 * Tests for the OCSF audit transport / mappers (F-6).
 */

import {
  auditLogEntryToOcsf,
  signedEvidenceToOcsf,
  createOcsfTransportFromEnv,
  createStdoutOcsfTransport,
  createFileOcsfTransport,
  createOcsfWinstonTransport,
  OcsfAuditTransport,
  OcsfApiActivityEvent,
  OcsfAuthorizationEvent,
} from '../src/ocsf';
import { AuditLogEntry, SignedAuditEvidence } from '../src/wire';
import { createAuditLogger } from '../src/logger';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const product = { name: 'euno-tool-gateway', vendor: 'Euno', version: '0.1.0' };

describe('auditLogEntryToOcsf', () => {
  it('maps an issuance allow → Authorization 3003 (assign privileges)', () => {
    const entry: AuditLogEntry = {
      id: '11111111-1111-1111-1111-111111111111',
      timestamp: '2026-01-01T00:00:00Z',
      eventType: 'issuance',
      agentId: 'agent-1',
      userId: 'user-1',
      capabilityId: 'cap-1',
      decision: 'allow',
      region: 'eastus2',
    };
    const e = auditLogEntryToOcsf(entry, product) as OcsfAuthorizationEvent;
    expect(e.class_uid).toBe(3003);
    expect(e.category_uid).toBe(3);
    expect(e.activity_id).toBe(1);
    expect(e.type_uid).toBe(3003 * 100 + 1);
    expect(e.status_id).toBe(1);
    expect(e.severity_id).toBe(1);
    expect(e.cloud?.region).toBe('eastus2');
    expect(e.privileges).toEqual(['cap-1']);
    expect(e.metadata.uid).toBe(entry.id);
    expect(e.metadata.product.name).toBe('euno-tool-gateway');
  });

  it('maps a revocation → Authorization activity_id=2', () => {
    const entry: AuditLogEntry = {
      id: 'rev-1',
      timestamp: '2026-01-01T00:00:00Z',
      eventType: 'revocation',
      agentId: 'agent-1',
      decision: 'allow',
    };
    const e = auditLogEntryToOcsf(entry, product) as OcsfAuthorizationEvent;
    expect(e.class_uid).toBe(3003);
    expect(e.activity_id).toBe(2);
    expect(e.type_uid).toBe(3003 * 100 + 2);
  });

  it('maps a denial → API Activity 6003 with status_id=2 (Failure)', () => {
    const entry: AuditLogEntry = {
      id: 'd-1',
      timestamp: '2026-01-01T00:00:00Z',
      eventType: 'denial',
      agentId: 'agent-1',
      userId: 'user-1',
      action: 'write',
      resource: 'api://service/users',
      decision: 'deny',
      reason: 'capability not found',
    };
    const e = auditLogEntryToOcsf(entry, product) as OcsfApiActivityEvent;
    expect(e.class_uid).toBe(6003);
    expect(e.category_uid).toBe(6);
    expect(e.activity_id).toBe(1); // write → Create
    expect(e.type_uid).toBe(6003 * 100 + 1);
    expect(e.status_id).toBe(2);
    expect(e.status).toBe('Failure');
    expect(e.severity_id).toBe(3); // deny → Medium
    expect(e.message).toBe('capability not found');
    expect(e.api?.operation).toBe('write');
    expect(e.resources?.[0]?.uid).toBe('api://service/users');
  });

  it('maps a validation/read → API Activity activity_id=2 (Read)', () => {
    const entry: AuditLogEntry = {
      id: 'v-1',
      timestamp: '2026-01-01T00:00:00Z',
      eventType: 'validation',
      agentId: 'agent-1',
      action: 'read',
      resource: 'api://x',
      decision: 'allow',
    };
    const e = auditLogEntryToOcsf(entry, product) as OcsfApiActivityEvent;
    expect(e.activity_id).toBe(2);
    expect(e.type_uid).toBe(6003 * 100 + 2);
  });

  it('survives an unparseable timestamp by falling back to "now"', () => {
    const entry: AuditLogEntry = {
      id: 'bad-ts',
      timestamp: 'not a date',
      eventType: 'issuance',
      agentId: 'a',
      decision: 'allow',
    };
    const e = auditLogEntryToOcsf(entry, product);
    expect(typeof e.time).toBe('number');
    expect(e.time).toBeGreaterThan(0);
  });

  it('falls back to metadata.reason when top-level reason is absent (PR review #11)', () => {
    // Issuer-side denials (PIM, Conditional Access, rate limit, …)
    // place their human-readable reason in `metadata.reason`. SIEMs
    // consuming OCSF should still see a populated `message` rather
    // than having to look in `unmapped`.
    const entry: AuditLogEntry = {
      id: 'm-1',
      timestamp: '2026-01-01T00:00:00Z',
      eventType: 'denial',
      agentId: 'agent-1',
      decision: 'deny',
      metadata: { reason: 'PIM role not active' },
    };
    const e = auditLogEntryToOcsf(entry, product);
    expect(e.message).toBe('PIM role not active');
  });

  it('top-level reason wins over metadata.reason when both are present', () => {
    const entry: AuditLogEntry = {
      id: 'm-2',
      timestamp: '2026-01-01T00:00:00Z',
      eventType: 'denial',
      agentId: 'agent-1',
      decision: 'deny',
      reason: 'top-level wins',
      metadata: { reason: 'metadata loses' },
    };
    expect(auditLogEntryToOcsf(entry, product).message).toBe('top-level wins');
  });
});

describe('signedEvidenceToOcsf', () => {
  it('packs the signature into an enrichment so SIEMs can verify', () => {
    const evidence: SignedAuditEvidence = {
      id: 'ev-1',
      sessionId: 'sess-1',
      userId: 'user-1',
      promptHash: 'p-hash',
      tool: 'crm.search',
      argsHash: 'a-hash',
      nonce: 'n',
      ts: '2026-01-01T00:00:00Z',
      policyVersion: '0.1.0',
      agentId: 'agent-1',
      resource: 'api://crm/contacts',
      action: 'read',
      capabilityId: 'cap-1',
      decision: 'allow',
      signature: 'sig',
      keyId: 'k1',
      algorithm: 'RS256',
      previousHash: '0000000000000000000000000000000000000000000000000000000000000000',
      seq: 1,
    };
    const e = signedEvidenceToOcsf(evidence, product);
    expect(e.class_uid).toBe(6003);
    expect(e.activity_id).toBe(2);
    expect(e.actor?.user?.uid).toBe('user-1');
    expect(e.actor?.session?.uid).toBe('sess-1');
    expect(e.enrichments?.[0]?.name).toBe('signature');
    expect(e.enrichments?.[0]?.value).toBe('sig');
    expect((e.enrichments?.[0]?.data as Record<string, unknown>)?.algorithm).toBe('RS256');
    expect((e.enrichments?.[0]?.data as Record<string, unknown>)?.keyId).toBe('k1');
  });
});

describe('createStdoutOcsfTransport', () => {
  it('writes one JSON line per event to the configured stream', async () => {
    const chunks: string[] = [];
    const stream: NodeJS.WritableStream = {
      write: (data: string | Buffer) => {
        chunks.push(typeof data === 'string' ? data : data.toString());
        return true;
      },
    } as unknown as NodeJS.WritableStream;
    const t = createStdoutOcsfTransport({ stream });
    await t.send(
      auditLogEntryToOcsf(
        {
          id: 'a',
          timestamp: '2026-01-01T00:00:00Z',
          eventType: 'issuance',
          agentId: 'g',
          decision: 'allow',
        },
        product,
      ),
    );
    await t.flush();
    await t.close();
    expect(chunks).toHaveLength(1);
    const parsed = JSON.parse(chunks[0]!.trim());
    expect(parsed.class_uid).toBe(3003);
  });
});

describe('createFileOcsfTransport', () => {
  it('appends one JSON line per event to the configured file', async () => {
    const tmp = path.join(os.tmpdir(), `ocsf-${Date.now()}-${Math.random().toString(36).slice(2)}.log`);
    const t = createFileOcsfTransport({ path: tmp });
    try {
      await t.send(
        auditLogEntryToOcsf(
          {
            id: 'a',
            timestamp: '2026-01-01T00:00:00Z',
            eventType: 'denial',
            agentId: 'g',
            action: 'read',
            resource: 'api://x',
            decision: 'deny',
          },
          product,
        ),
      );
      await t.flush();
      const lines = (await fs.promises.readFile(tmp, 'utf8')).trim().split('\n');
      expect(lines).toHaveLength(1);
      const parsed = JSON.parse(lines[0]!);
      expect(parsed.class_uid).toBe(6003);
      expect(parsed.status).toBe('Failure');
    } finally {
      await t.close();
      await fs.promises.unlink(tmp).catch(() => undefined);
    }
  });

  it('close() awaits in-flight send() calls (PR review #9)', async () => {
    // Mirrors the gateway/issuer pattern of `void transport.send(...)`
    // followed by SIGTERM-driven `close()`. Without in-flight
    // tracking, `close()` would resolve before the appendFile
    // settled and the tail of the audit stream would be lost.
    const tmp = path.join(os.tmpdir(), `ocsf-inflight-${Date.now()}.log`);
    const t = createFileOcsfTransport({ path: tmp });
    try {
      const e = auditLogEntryToOcsf(
        {
          id: 'b',
          timestamp: '2026-01-01T00:00:00Z',
          eventType: 'denial',
          agentId: 'g',
          action: 'read',
          decision: 'deny',
        },
        product,
      );
      // Fire-and-forget — exactly how bootstrap.ts dispatches OCSF events.
      void t.send(e);
      void t.send(e);
      void t.send(e);
      // close() must await the three pending appends before resolving.
      await t.close();
      const lines = (await fs.promises.readFile(tmp, 'utf8')).trim().split('\n');
      expect(lines).toHaveLength(3);
    } finally {
      await fs.promises.unlink(tmp).catch(() => undefined);
    }
  });
});

describe('createOcsfTransportFromEnv', () => {
  it('returns undefined when OCSF_TRANSPORT is unset (opt-in)', () => {
    expect(createOcsfTransportFromEnv({})).toBeUndefined();
  });

  it('returns a stdout transport when OCSF_TRANSPORT=stdout', () => {
    const t = createOcsfTransportFromEnv({ OCSF_TRANSPORT: 'stdout' });
    expect(t?.name).toBe('ocsf-stdout');
  });

  it('returns undefined for OCSF_TRANSPORT=file when path is missing', () => {
    expect(createOcsfTransportFromEnv({ OCSF_TRANSPORT: 'file' })).toBeUndefined();
  });

  it('returns undefined for OCSF_TRANSPORT=http when url is missing', () => {
    expect(createOcsfTransportFromEnv({ OCSF_TRANSPORT: 'http' })).toBeUndefined();
  });

  it('returns undefined for unknown OCSF_TRANSPORT', () => {
    expect(createOcsfTransportFromEnv({ OCSF_TRANSPORT: 'bogus' })).toBeUndefined();
  });

  it('returns a file transport when path is supplied', async () => {
    const tmp = path.join(os.tmpdir(), `ocsf-env-${Date.now()}.log`);
    const t = createOcsfTransportFromEnv({
      OCSF_TRANSPORT: 'file',
      OCSF_FILE_PATH: tmp,
    });
    try {
      expect(t?.name).toBe('ocsf-file');
    } finally {
      await t?.close();
      await fs.promises.unlink(tmp).catch(() => undefined);
    }
  });
});

describe('createOcsfWinstonTransport', () => {
  it('forwards AuditLogEntry-shaped winston records as OCSF events', async () => {
    const captured: unknown[] = [];
    const transport: OcsfAuditTransport = {
      name: 'capture',
      async send(e) {
        captured.push(e);
      },
      async flush() {},
      async close() {},
    };
    const wt = createOcsfWinstonTransport(transport, product);
    const audit = createAuditLogger('ocsf-winston-test');
    audit.add(wt);
    audit.info('issuance', {
      id: 'w-1',
      timestamp: '2026-01-01T00:00:00Z',
      eventType: 'issuance',
      agentId: 'agent-1',
      userId: 'user-1',
      decision: 'allow',
    } satisfies AuditLogEntry);
    // winston is sync-emit but the test transport is async; give it a tick.
    await new Promise((r) => setImmediate(r));
    audit.remove(wt);
    expect(captured).toHaveLength(1);
    expect((captured[0] as OcsfAuthorizationEvent).class_uid).toBe(3003);
  });

  it('silently drops records that do not look like AuditLogEntry', async () => {
    const captured: unknown[] = [];
    const transport: OcsfAuditTransport = {
      name: 'capture',
      async send(e) {
        captured.push(e);
      },
      async flush() {},
      async close() {},
    };
    const wt = createOcsfWinstonTransport(transport, product);
    const audit = createAuditLogger('ocsf-winston-drop');
    audit.add(wt);
    audit.info('plain log line, not an audit entry');
    await new Promise((r) => setImmediate(r));
    audit.remove(wt);
    expect(captured).toHaveLength(0);
  });
});
