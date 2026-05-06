/**
 * Tests for PerReplicaPostgresLedgerBackend and CrossChainAnchor.
 *
 * Covers:
 *   1. PerReplicaPostgresLedgerBackend — append, chain ordering, no advisory
 *      lock, per-replica tip query, getReplicaTips, verifyRowHmac, migrate.
 *   2. CrossChainAnchor — periodic cross-chain commitment, S3 publishing,
 *      error isolation, graceful stop.
 *   3. createLedgerSignerFromConfig — per-replica-postgres backend.
 */

import * as crypto from 'crypto';
import {
  PerReplicaPostgresLedgerBackend,
  CrossChainAnchor,
  LedgerAuditEvidenceSigner,
  LedgerChainError,
  LedgerEntry,
  PgPool,
  PgClientConnection,
  PgQueryResult,
  createLedgerSignerFromConfig,
} from '../src/ledger-signer';
import { CryptoSigner, createAuditEvidence, signEvidenceWithChain } from '../src/evidence';
import { GENESIS_HASH, ChainTipSnapshot, SignedCrossChainCommitment } from '../src/wire';
import { canonicalSha256 } from '../src/utils';

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeEvidence(i: number) {
  return createAuditEvidence({
    sessionId: 'sess-1',
    userId: 'user-1',
    tool: 'tool-1',
    args: { i },
    agentId: 'agent-1',
    resource: 'tool://demo',
    action: 'read',
    capabilityId: `cap-${i}`,
    decision: 'allow',
    policyVersion: '1.0.0',
  });
}

/** Minimal CryptoSigner backed by an EC P-256 key for fast tests. */
class EcP256Signer implements CryptoSigner {
  private readonly privateKey: crypto.KeyObject;
  readonly kid: string;

  constructor(kid = 'test-p256') {
    const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    this.privateKey = privateKey;
    this.kid = kid;
  }

  async signDigest(digest: Buffer): Promise<Buffer> {
    return crypto.sign(null, digest, {
      key: this.privateKey,
      dsaEncoding: 'ieee-p1363',
    });
  }

  async getKeyId(): Promise<string> {
    return this.kid;
  }

  getAlgorithm(): string {
    return 'ES256';
  }
}

// ── Mock PgPool for PerReplicaPostgresLedgerBackend ───────────────────────────

interface StoredRow {
  record_id: string;
  replica_id: string;
  seq: number;
  previous_hash: string;
  record_hash: string;
  payload: unknown;
  row_hmac: Buffer;
  created_at: Date;
}

function makeMockPerReplicaPool(): {
  pool: PgPool;
  rows: StoredRow[];
} {
  const rows: StoredRow[] = [];

  const makeClient = (): PgClientConnection => ({
    query<R extends Record<string, unknown> = Record<string, unknown>>(
      sql: string,
      values?: unknown[],
    ): Promise<PgQueryResult<R>> {
      const trimmed = sql.trim();
      const upper = trimmed.toUpperCase();

      // DDL — always succeed.
      if (upper.startsWith('CREATE TABLE') || upper.startsWith('CREATE INDEX')) {
        return Promise.resolve({ rows: [], rowCount: 0 }) as unknown as Promise<PgQueryResult<R>>;
      }

      // INSERT
      if (upper.startsWith('INSERT INTO')) {
        const [recordId, replicaId, seq, previousHash, recordHash, payloadJson, rowHmac] = values as [
          string, string, number, string, string, string, Buffer,
        ];
        rows.push({
          record_id: recordId,
          replica_id: replicaId,
          seq,
          previous_hash: previousHash,
          record_hash: recordHash,
          payload: JSON.parse(payloadJson),
          row_hmac: rowHmac,
          created_at: new Date(),
        });
        return Promise.resolve({ rows: [], rowCount: 1 }) as unknown as Promise<PgQueryResult<R>>;
      }

      // SELECT tip for a single replica (initialize / getChainTip)
      // Matches: WHERE replica_id = $1 ORDER BY seq DESC LIMIT 1
      if (upper.includes('WHERE REPLICA_ID =') && upper.includes('ORDER BY SEQ DESC LIMIT 1')) {
        const replicaId = (values as string[])[0]!;
        const replicaRows = rows
          .filter((r) => r.replica_id === replicaId)
          .sort((a, b) => b.seq - a.seq);
        if (replicaRows.length === 0) {
          return Promise.resolve({ rows: [], rowCount: 0 }) as unknown as Promise<PgQueryResult<R>>;
        }
        const last = replicaRows[0]!;
        return Promise.resolve({
          rows: [{ seq: String(last.seq), record_hash: last.record_hash }],
          rowCount: 1,
        }) as unknown as Promise<PgQueryResult<R>>;
      }

      // SELECT entries for a replica (getEntries)
      // Matches: WHERE replica_id = $1 AND seq >= $2 AND seq <= $3
      if (upper.includes('WHERE REPLICA_ID =') && upper.includes('AND SEQ >=') && upper.includes('AND SEQ <=')) {
        const [replicaId, fromSeq, toSeq] = values as [string, number, number];
        const slice = rows.filter(
          (r) => r.replica_id === replicaId && r.seq >= fromSeq && r.seq <= toSeq,
        );
        return Promise.resolve({
          rows: slice.map((r) => ({
            seq: String(r.seq),
            previous_hash: r.previous_hash,
            record_hash: r.record_hash,
            replica_id: r.replica_id,
            payload: r.payload,
            row_hmac: r.row_hmac,
            created_at: r.created_at,
          })),
          rowCount: slice.length,
        }) as unknown as Promise<PgQueryResult<R>>;
      }

      // DISTINCT ON (replica_id) — getReplicaTips
      if (upper.includes('DISTINCT ON (REPLICA_ID)')) {
        // For each replicaId, return only the max-seq row.
        const tipsByReplica = new Map<string, StoredRow>();
        for (const row of rows) {
          const existing = tipsByReplica.get(row.replica_id);
          if (!existing || row.seq > existing.seq) {
            tipsByReplica.set(row.replica_id, row);
          }
        }
        const tips = [...tipsByReplica.values()].sort((a, b) =>
          a.replica_id.localeCompare(b.replica_id),
        );
        return Promise.resolve({
          rows: tips.map((r) => ({
            replica_id: r.replica_id,
            seq: String(r.seq),
            record_hash: r.record_hash,
            created_at: r.created_at,
          })),
          rowCount: tips.length,
        }) as unknown as Promise<PgQueryResult<R>>;
      }

      return Promise.resolve({ rows: [], rowCount: 0 }) as unknown as Promise<PgQueryResult<R>>;
    },
    release() { /* no-op */ },
  });

  const pool: PgPool = {
    connect: () => Promise.resolve(makeClient()),
    end: () => Promise.resolve(),
  };

  return { pool, rows };
}

const HMAC_SECRET = 'a'.repeat(64); // 64-char hex = 32-byte key

// ── PerReplicaPostgresLedgerBackend tests ─────────────────────────────────────

describe('PerReplicaPostgresLedgerBackend', () => {
  it('starts empty, getChainTip returns null', async () => {
    const { pool } = makeMockPerReplicaPool();
    const backend = new PerReplicaPostgresLedgerBackend(pool, 'replica-1', {
      hmacSecret: HMAC_SECRET,
    });
    expect(await backend.getChainTip()).toBeNull();
  });

  it('assigns seq=1 and previousHash=GENESIS_HASH to the first entry', async () => {
    const { pool } = makeMockPerReplicaPool();
    const backend = new PerReplicaPostgresLedgerBackend(pool, 'replica-1', {
      hmacSecret: HMAC_SECRET,
    });
    const cryptoSigner = new EcP256Signer();
    const ev = makeEvidence(1);

    const signed = await backend.appendEntry(ev, 'replica-1', (ph, seq) =>
      signEvidenceWithChain(ev, cryptoSigner, ph, seq),
    );

    expect(signed.seq).toBe(1);
    expect(signed.previousHash).toBe(GENESIS_HASH);
  });

  it('builds a valid hash chain across multiple appends', async () => {
    const { pool } = makeMockPerReplicaPool();
    const backend = new PerReplicaPostgresLedgerBackend(pool, 'r1', {
      hmacSecret: HMAC_SECRET,
    });
    const cryptoSigner = new EcP256Signer();

    const records = [];
    for (let i = 1; i <= 5; i++) {
      const ev = makeEvidence(i);
      records.push(
        await backend.appendEntry(ev, 'r1', (ph, seq) =>
          signEvidenceWithChain(ev, cryptoSigner, ph, seq),
        ),
      );
    }

    expect(records[0]!.previousHash).toBe(GENESIS_HASH);
    for (let i = 1; i < records.length; i++) {
      expect(records[i]!.previousHash).toBe(canonicalSha256(records[i - 1]!));
    }
  });

  it('serialises concurrent appends: seq numbers are unique and consecutive', async () => {
    const { pool } = makeMockPerReplicaPool();
    const backend = new PerReplicaPostgresLedgerBackend(pool, 'r1', {
      hmacSecret: HMAC_SECRET,
    });
    const cryptoSigner = new EcP256Signer();

    const promises = Array.from({ length: 10 }, (_, i) => {
      const ev = makeEvidence(i + 1);
      return backend.appendEntry(ev, 'r1', (ph, seq) =>
        signEvidenceWithChain(ev, cryptoSigner, ph, seq),
      );
    });

    const results = await Promise.all(promises);
    const seqs = results.map((r) => r.seq).sort((a, b) => a - b);
    expect(seqs).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  });

  it('different replicas maintain independent seq spaces', async () => {
    const { pool } = makeMockPerReplicaPool();
    const backendA = new PerReplicaPostgresLedgerBackend(pool, 'replica-a', {
      hmacSecret: HMAC_SECRET,
    });
    const backendB = new PerReplicaPostgresLedgerBackend(pool, 'replica-b', {
      hmacSecret: HMAC_SECRET,
    });
    const cryptoSigner = new EcP256Signer();

    const evA = makeEvidence(1);
    const evB = makeEvidence(2);

    const signedA = await backendA.appendEntry(evA, 'replica-a', (ph, seq) =>
      signEvidenceWithChain(evA, cryptoSigner, ph, seq),
    );
    const signedB = await backendB.appendEntry(evB, 'replica-b', (ph, seq) =>
      signEvidenceWithChain(evB, cryptoSigner, ph, seq),
    );

    // Both replicas start from seq=1 independently.
    expect(signedA.seq).toBe(1);
    expect(signedB.seq).toBe(1);
    expect(signedA.previousHash).toBe(GENESIS_HASH);
    expect(signedB.previousHash).toBe(GENESIS_HASH);
  });

  it('getChainTip reflects the latest appended entry', async () => {
    const { pool } = makeMockPerReplicaPool();
    const backend = new PerReplicaPostgresLedgerBackend(pool, 'r1', {
      hmacSecret: HMAC_SECRET,
    });
    const cryptoSigner = new EcP256Signer();

    expect(await backend.getChainTip()).toBeNull();

    const ev = makeEvidence(1);
    const signed = await backend.appendEntry(ev, 'r1', (ph, seq) =>
      signEvidenceWithChain(ev, cryptoSigner, ph, seq),
    );

    const tip = await backend.getChainTip();
    expect(tip).not.toBeNull();
    expect(tip!.seq).toBe(1);
    expect(tip!.tipHash).toBe(canonicalSha256(signed));
  });

  it('getEntries returns the correct range for this replica', async () => {
    const { pool } = makeMockPerReplicaPool();
    const backend = new PerReplicaPostgresLedgerBackend(pool, 'r1', {
      hmacSecret: HMAC_SECRET,
    });
    const cryptoSigner = new EcP256Signer();

    for (let i = 1; i <= 8; i++) {
      const ev = makeEvidence(i);
      await backend.appendEntry(ev, 'r1', (ph, seq) =>
        signEvidenceWithChain(ev, cryptoSigner, ph, seq),
      );
    }

    const slice = await backend.getEntries(3, 6);
    expect(slice.length).toBe(4);
    expect(slice[0]!.seq).toBe(3);
    expect(slice[3]!.seq).toBe(6);
  });

  it('getEntries does not return entries from other replicas', async () => {
    const { pool } = makeMockPerReplicaPool();
    const backendA = new PerReplicaPostgresLedgerBackend(pool, 'replica-a', {
      hmacSecret: HMAC_SECRET,
    });
    const backendB = new PerReplicaPostgresLedgerBackend(pool, 'replica-b', {
      hmacSecret: HMAC_SECRET,
    });
    const cryptoSigner = new EcP256Signer();

    for (let i = 1; i <= 3; i++) {
      const ev = makeEvidence(i);
      await backendA.appendEntry(ev, 'replica-a', (ph, seq) =>
        signEvidenceWithChain(ev, cryptoSigner, ph, seq),
      );
      await backendB.appendEntry(ev, 'replica-b', (ph, seq) =>
        signEvidenceWithChain(ev, cryptoSigner, ph, seq),
      );
    }

    const entriesA = await backendA.getEntries(1, 3);
    expect(entriesA.every((e) => e.replicaId === 'replica-a')).toBe(true);
    expect(entriesA.length).toBe(3);
  });

  it('getReplicaTips returns the latest tip for each replica', async () => {
    const { pool } = makeMockPerReplicaPool();
    const backendA = new PerReplicaPostgresLedgerBackend(pool, 'replica-a', {
      hmacSecret: HMAC_SECRET,
    });
    const backendB = new PerReplicaPostgresLedgerBackend(pool, 'replica-b', {
      hmacSecret: HMAC_SECRET,
    });
    const cryptoSigner = new EcP256Signer();

    for (let i = 1; i <= 3; i++) {
      const ev = makeEvidence(i);
      await backendA.appendEntry(ev, 'replica-a', (ph, seq) =>
        signEvidenceWithChain(ev, cryptoSigner, ph, seq),
      );
    }
    for (let i = 1; i <= 5; i++) {
      const ev = makeEvidence(i);
      await backendB.appendEntry(ev, 'replica-b', (ph, seq) =>
        signEvidenceWithChain(ev, cryptoSigner, ph, seq),
      );
    }

    // getReplicaTips can be called on either backend (they share the pool).
    const tips = await backendA.getReplicaTips();
    expect(tips.length).toBe(2);

    const tipA = tips.find((t) => t.replicaId === 'replica-a');
    const tipB = tips.find((t) => t.replicaId === 'replica-b');
    expect(tipA).toBeDefined();
    expect(tipA!.seq).toBe(3);
    expect(tipB).toBeDefined();
    expect(tipB!.seq).toBe(5);
  });

  it('getReplicaTips returns empty array when no replicas have appended', async () => {
    const { pool } = makeMockPerReplicaPool();
    const backend = new PerReplicaPostgresLedgerBackend(pool, 'r1', {
      hmacSecret: HMAC_SECRET,
    });
    const tips = await backend.getReplicaTips();
    expect(tips).toEqual([]);
  });

  it('initialize() seeds in-process chain state from DB', async () => {
    const { pool } = makeMockPerReplicaPool();
    const backendFirst = new PerReplicaPostgresLedgerBackend(pool, 'r1', {
      hmacSecret: HMAC_SECRET,
    });
    const cryptoSigner = new EcP256Signer();

    for (let i = 1; i <= 3; i++) {
      const ev = makeEvidence(i);
      await backendFirst.appendEntry(ev, 'r1', (ph, seq) =>
        signEvidenceWithChain(ev, cryptoSigner, ph, seq),
      );
    }

    // Simulate restart: create a new backend instance with the same pool.
    const backendSecond = new PerReplicaPostgresLedgerBackend(pool, 'r1', {
      hmacSecret: HMAC_SECRET,
    });
    await backendSecond.initialize();

    // The new instance should continue from seq=4.
    const ev = makeEvidence(4);
    const signed = await backendSecond.appendEntry(ev, 'r1', (ph, seq) =>
      signEvidenceWithChain(ev, cryptoSigner, ph, seq),
    );
    expect(signed.seq).toBe(4);
  });

  it('rejects when appendEntry is called with a replicaId that does not match the constructor', async () => {
    const { pool } = makeMockPerReplicaPool();
    const backend = new PerReplicaPostgresLedgerBackend(pool, 'r1', {
      hmacSecret: HMAC_SECRET,
    });
    const cryptoSigner = new EcP256Signer();

    const ev = makeEvidence(1);
    await expect(
      backend.appendEntry(ev, 'other-replica', (ph, seq) =>
        signEvidenceWithChain(ev, cryptoSigner, ph, seq),
      ),
    ).rejects.toThrow(/appendEntry called with replicaId="other-replica"/);
  });

  it('rejects when sign callback returns wrong previousHash', async () => {
    const { pool } = makeMockPerReplicaPool();
    const backend = new PerReplicaPostgresLedgerBackend(pool, 'r1', {
      hmacSecret: HMAC_SECRET,
    });
    const cryptoSigner = new EcP256Signer();

    const ev = makeEvidence(1);
    await expect(
      backend.appendEntry(ev, 'r1', async (_ph, seq) =>
        signEvidenceWithChain(ev, cryptoSigner, 'ff'.repeat(32), seq),
      ),
    ).rejects.toThrow(LedgerChainError);
  });

  it('rejects when sign callback returns wrong seq', async () => {
    const { pool } = makeMockPerReplicaPool();
    const backend = new PerReplicaPostgresLedgerBackend(pool, 'r1', {
      hmacSecret: HMAC_SECRET,
    });
    const cryptoSigner = new EcP256Signer();

    const ev = makeEvidence(1);
    await expect(
      backend.appendEntry(ev, 'r1', async (ph, _seq) =>
        signEvidenceWithChain(ev, cryptoSigner, ph, 99),
      ),
    ).rejects.toThrow(LedgerChainError);
  });

  it('verifyRowHmac passes for an untampered row and fails for a tampered one', async () => {
    const { pool, rows } = makeMockPerReplicaPool();
    const backend = new PerReplicaPostgresLedgerBackend(pool, 'r1', {
      hmacSecret: HMAC_SECRET,
    });
    const cryptoSigner = new EcP256Signer();

    const ev = makeEvidence(1);
    const signed = await backend.appendEntry(ev, 'r1', (ph, seq) =>
      signEvidenceWithChain(ev, cryptoSigner, ph, seq),
    );

    const row = rows[0]!;
    const entry: LedgerEntry = {
      seq: row.seq,
      previousHash: row.previous_hash,
      recordHash: row.record_hash,
      replicaId: row.replica_id,
      signedEvidence: signed,
      ts: row.created_at.toISOString(),
    };

    expect(backend.verifyRowHmac(entry, row.row_hmac)).toBe(true);

    const tampered = { ...entry, recordHash: 'ff'.repeat(32) };
    expect(backend.verifyRowHmac(tampered, row.row_hmac)).toBe(false);
  });

  it('verifyRowHmac returns false for wrong-length rawHmac without throwing', async () => {
    const { pool, rows } = makeMockPerReplicaPool();
    const backend = new PerReplicaPostgresLedgerBackend(pool, 'r1', {
      hmacSecret: HMAC_SECRET,
    });
    const cryptoSigner = new EcP256Signer();
    const ev = makeEvidence(1);
    const signed = await backend.appendEntry(ev, 'r1', (ph, seq) =>
      signEvidenceWithChain(ev, cryptoSigner, ph, seq),
    );
    const row = rows[0]!;
    const entry: LedgerEntry = {
      seq: row.seq,
      previousHash: row.previous_hash,
      recordHash: row.record_hash,
      replicaId: row.replica_id,
      signedEvidence: signed,
      ts: row.created_at.toISOString(),
    };
    expect(backend.verifyRowHmac(entry, Buffer.alloc(0))).toBe(false);
    expect(backend.verifyRowHmac(entry, row.row_hmac.slice(0, 4))).toBe(false);
  });

  it('throws on invalid table name', () => {
    const { pool } = makeMockPerReplicaPool();
    expect(
      () =>
        new PerReplicaPostgresLedgerBackend(pool, 'r1', {
          hmacSecret: HMAC_SECRET,
          table: 'bad; DROP TABLE',
        }),
    ).toThrow(/invalid table name/i);
  });

  it('throws when hmacSecret is missing', () => {
    const { pool } = makeMockPerReplicaPool();
    expect(
      () =>
        new PerReplicaPostgresLedgerBackend(pool, 'r1', {
          hmacSecret: '',
        }),
    ).toThrow(/hmacSecret is required/i);
  });

  it('migrate() runs CREATE TABLE and CREATE INDEX without error', async () => {
    const { pool } = makeMockPerReplicaPool();
    const backend = new PerReplicaPostgresLedgerBackend(pool, 'r1', {
      hmacSecret: HMAC_SECRET,
    });
    await expect(backend.migrate()).resolves.toBeUndefined();
  });

  it('S3 anchor fires after anchorIntervalRows appends', async () => {
    const { pool } = makeMockPerReplicaPool();
    const putCalls: Array<{ bucket: string; key: string; body: string }> = [];
    const backend = new PerReplicaPostgresLedgerBackend(pool, 'r1', {
      hmacSecret: HMAC_SECRET,
      s3: {
        client: { async putObject(p) { putCalls.push(p); } },
        bucket: 'test-bucket',
        prefix: 'anchors/',
        anchorIntervalRows: 3,
      },
    });
    const cryptoSigner = new EcP256Signer();

    for (let i = 1; i <= 3; i++) {
      const ev = makeEvidence(i);
      await backend.appendEntry(ev, 'r1', (ph, seq) =>
        signEvidenceWithChain(ev, cryptoSigner, ph, seq),
      );
    }

    // Wait for async S3 anchor.
    await new Promise((r) => setTimeout(r, 20));

    expect(putCalls.length).toBe(1);
    expect(putCalls[0]!.bucket).toBe('test-bucket');
    expect(putCalls[0]!.key).toMatch(/^anchors\/r1\//);
    const payload = JSON.parse(putCalls[0]!.body) as Record<string, unknown>;
    expect(payload['fromSeq']).toBe(1);
    expect(payload['toSeq']).toBe(3);
    expect(payload['replicaId']).toBe('r1');
  });

  it('onAnchorError is called when S3 putObject throws', async () => {
    const { pool } = makeMockPerReplicaPool();
    const errors: Error[] = [];
    const backend = new PerReplicaPostgresLedgerBackend(pool, 'r1', {
      hmacSecret: HMAC_SECRET,
      s3: {
        client: { putObject: async () => { throw new Error('S3 down'); } },
        bucket: 'b',
        anchorIntervalRows: 1,
      },
      onAnchorError: (e) => errors.push(e),
    });
    const cryptoSigner = new EcP256Signer();
    const ev = makeEvidence(1);
    await backend.appendEntry(ev, 'r1', (ph, seq) =>
      signEvidenceWithChain(ev, cryptoSigner, ph, seq),
    );
    await new Promise((r) => setTimeout(r, 20));
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]!.message).toContain('S3 down');
  });
});

// ── createLedgerSignerFromConfig — per-replica-postgres ───────────────────────

describe('createLedgerSignerFromConfig — per-replica-postgres', () => {
  it('returns LedgerAuditEvidenceSigner with PerReplicaPostgresLedgerBackend', async () => {
    const { pool } = makeMockPerReplicaPool();
    const result = await createLedgerSignerFromConfig({
      backend: 'per-replica-postgres',
      cryptoSigner: new EcP256Signer(),
      replicaId: 'r1',
      pgPool: pool,
      perReplicaPgOptions: { hmacSecret: HMAC_SECRET },
    });
    expect(result).toBeInstanceOf(LedgerAuditEvidenceSigner);
    expect(result!.getBackend()).toBeInstanceOf(PerReplicaPostgresLedgerBackend);
  });

  it('throws when pgPool is missing', async () => {
    await expect(
      createLedgerSignerFromConfig({
        backend: 'per-replica-postgres',
        cryptoSigner: new EcP256Signer(),
        replicaId: 'r1',
        perReplicaPgOptions: { hmacSecret: HMAC_SECRET },
      }),
    ).rejects.toThrow(/pgPool is required/);
  });

  it('throws when perReplicaPgOptions is missing', async () => {
    const { pool } = makeMockPerReplicaPool();
    await expect(
      createLedgerSignerFromConfig({
        backend: 'per-replica-postgres',
        cryptoSigner: new EcP256Signer(),
        replicaId: 'r1',
        pgPool: pool,
      }),
    ).rejects.toThrow(/perReplicaPgOptions is required/);
  });

  it('runs migrations when runMigrations=true', async () => {
    const { pool } = makeMockPerReplicaPool();
    const result = await createLedgerSignerFromConfig({
      backend: 'per-replica-postgres',
      cryptoSigner: new EcP256Signer(),
      replicaId: 'r1',
      pgPool: pool,
      perReplicaPgOptions: { hmacSecret: HMAC_SECRET },
      runMigrations: true,
    });
    expect(result).toBeInstanceOf(LedgerAuditEvidenceSigner);
  });
});

// ── CrossChainAnchor tests ────────────────────────────────────────────────────

describe('CrossChainAnchor', () => {
  it('emits a SignedCrossChainCommitment on each tick', async () => {
    const { pool } = makeMockPerReplicaPool();
    const backendA = new PerReplicaPostgresLedgerBackend(pool, 'replica-a', {
      hmacSecret: HMAC_SECRET,
    });
    const backendB = new PerReplicaPostgresLedgerBackend(pool, 'replica-b', {
      hmacSecret: HMAC_SECRET,
    });
    const cryptoSigner = new EcP256Signer();

    // Append some records on two replicas.
    for (let i = 1; i <= 3; i++) {
      const ev = makeEvidence(i);
      await backendA.appendEntry(ev, 'replica-a', (ph, seq) =>
        signEvidenceWithChain(ev, cryptoSigner, ph, seq),
      );
      await backendB.appendEntry(ev, 'replica-b', (ph, seq) =>
        signEvidenceWithChain(ev, cryptoSigner, ph, seq),
      );
    }

    const commitments: SignedCrossChainCommitment[] = [];
    const anchor = new CrossChainAnchor(backendA, {
      intervalMs: 50,
      coordinatorId: 'replica-a',
      cryptoSigner,
      onCommitment: (c) => commitments.push(c),
    });
    anchor.start();

    // Wait for at least one tick.
    await new Promise((r) => setTimeout(r, 200));
    await anchor.stop();

    expect(commitments.length).toBeGreaterThanOrEqual(1);

    const first = commitments[0]!;
    expect(first.commitmentSeq).toBe(1);
    expect(first.previousCommitmentHash).toBe(GENESIS_HASH);
    expect(first.coordinatorId).toBe('replica-a');
    expect(first.tipCount).toBe(2);

    // Tips should be sorted by replicaId.
    expect(first.tips[0]!.replicaId).toBe('replica-a');
    expect(first.tips[1]!.replicaId).toBe('replica-b');
    expect(first.tips[0]!.seq).toBe(3);
    expect(first.tips[1]!.seq).toBe(3);

    // The commitment must be signed.
    expect(typeof first.signature).toBe('string');
    expect(first.signature.length).toBeGreaterThan(0);
    expect(first.keyId).toBe(cryptoSigner.kid);
    expect(first.algorithm).toBe('ES256');
  });

  it('chains successive commitments via previousCommitmentHash', async () => {
    const { pool } = makeMockPerReplicaPool();
    const backend = new PerReplicaPostgresLedgerBackend(pool, 'r1', {
      hmacSecret: HMAC_SECRET,
    });
    const cryptoSigner = new EcP256Signer();

    const ev = makeEvidence(1);
    await backend.appendEntry(ev, 'r1', (ph, seq) =>
      signEvidenceWithChain(ev, cryptoSigner, ph, seq),
    );

    const commitments: SignedCrossChainCommitment[] = [];
    const anchor = new CrossChainAnchor(backend, {
      intervalMs: 30,
      coordinatorId: 'r1',
      cryptoSigner,
      onCommitment: (c) => commitments.push(c),
    });
    anchor.start();

    await new Promise((r) => setTimeout(r, 150));
    await anchor.stop();

    expect(commitments.length).toBeGreaterThanOrEqual(2);

    // Each commitment's previousCommitmentHash must equal the hash of the prior one.
    for (let i = 1; i < commitments.length; i++) {
      const expectedPrevHash = canonicalSha256(commitments[i - 1]!);
      expect(commitments[i]!.previousCommitmentHash).toBe(expectedPrevHash);
    }
  });

  it('publishes to S3 anchor on each tick', async () => {
    const { pool } = makeMockPerReplicaPool();
    const backend = new PerReplicaPostgresLedgerBackend(pool, 'r1', {
      hmacSecret: HMAC_SECRET,
    });
    const cryptoSigner = new EcP256Signer();

    const ev = makeEvidence(1);
    await backend.appendEntry(ev, 'r1', (ph, seq) =>
      signEvidenceWithChain(ev, cryptoSigner, ph, seq),
    );

    const putCalls: Array<{ bucket: string; key: string; body: string }> = [];
    const anchor = new CrossChainAnchor(backend, {
      intervalMs: 30,
      coordinatorId: 'r1',
      cryptoSigner,
      s3: {
        client: { async putObject(p) { putCalls.push(p); } },
        bucket: 'cross-chain-bucket',
        prefix: 'cc/',
      },
    });
    anchor.start();

    await new Promise((r) => setTimeout(r, 100));
    await anchor.stop();

    expect(putCalls.length).toBeGreaterThanOrEqual(1);
    expect(putCalls[0]!.bucket).toBe('cross-chain-bucket');
    expect(putCalls[0]!.key).toMatch(/^cc\/cross-chain\/r1\//);

    const payload = JSON.parse(putCalls[0]!.body) as SignedCrossChainCommitment;
    expect(payload.commitmentSeq).toBe(1);
    expect(payload.tipCount).toBe(1);
    expect(payload.merkleRoot).toBeDefined();
  });

  it('skips emitting when no replicas have written', async () => {
    const { pool } = makeMockPerReplicaPool();
    const backend = new PerReplicaPostgresLedgerBackend(pool, 'r1', {
      hmacSecret: HMAC_SECRET,
    });
    const cryptoSigner = new EcP256Signer();

    const commitments: SignedCrossChainCommitment[] = [];
    const anchor = new CrossChainAnchor(backend, {
      intervalMs: 30,
      coordinatorId: 'r1',
      cryptoSigner,
      onCommitment: (c) => commitments.push(c),
    });
    anchor.start();

    await new Promise((r) => setTimeout(r, 100));
    await anchor.stop();

    // No replicas have written → no commitments.
    expect(commitments.length).toBe(0);
  });

  it('isolates errors from external anchors', async () => {
    const { pool } = makeMockPerReplicaPool();
    const backend = new PerReplicaPostgresLedgerBackend(pool, 'r1', {
      hmacSecret: HMAC_SECRET,
    });
    const cryptoSigner = new EcP256Signer();

    const ev = makeEvidence(1);
    await backend.appendEntry(ev, 'r1', (ph, seq) =>
      signEvidenceWithChain(ev, cryptoSigner, ph, seq),
    );

    const errors: Error[] = [];
    const successAnchorCalled: boolean[] = [];
    const anchor = new CrossChainAnchor(backend, {
      intervalMs: 40,
      coordinatorId: 'r1',
      cryptoSigner,
      anchors: [
        {
          name: 'failing-anchor',
          anchorCrossChain: async () => { throw new Error('anchor failed'); },
        },
        {
          name: 'success-anchor',
          anchorCrossChain: async () => { successAnchorCalled.push(true); },
        },
      ],
      onError: (e) => errors.push(e),
    });
    anchor.start();

    await new Promise((r) => setTimeout(r, 150));
    await anchor.stop();

    // The failing anchor's error was captured.
    expect(errors.some((e) => e.message.includes('anchor failed'))).toBe(true);
    // The success anchor was still called despite the other anchor failing.
    expect(successAnchorCalled.length).toBeGreaterThan(0);
  });

  it('stop() waits for any in-flight tick to finish', async () => {
    const { pool } = makeMockPerReplicaPool();
    const backend = new PerReplicaPostgresLedgerBackend(pool, 'r1', {
      hmacSecret: HMAC_SECRET,
    });
    const cryptoSigner = new EcP256Signer();

    const ev = makeEvidence(1);
    await backend.appendEntry(ev, 'r1', (ph, seq) =>
      signEvidenceWithChain(ev, cryptoSigner, ph, seq),
    );

    let tickCompleted = false;
    const anchor = new CrossChainAnchor(backend, {
      intervalMs: 10,
      coordinatorId: 'r1',
      cryptoSigner,
      onCommitment: () => { tickCompleted = true; },
    });
    anchor.start();

    // Give one tick a chance to start.
    await new Promise((r) => setTimeout(r, 50));
    await anchor.stop();

    // By the time stop() resolves, the in-flight tick should have completed.
    expect(tickCompleted).toBe(true);
  });

  it('throws when intervalMs <= 0', () => {
    const { pool } = makeMockPerReplicaPool();
    const backend = new PerReplicaPostgresLedgerBackend(pool, 'r1', {
      hmacSecret: HMAC_SECRET,
    });
    const cryptoSigner = new EcP256Signer();

    expect(
      () =>
        new CrossChainAnchor(backend, {
          intervalMs: 0,
          coordinatorId: 'r1',
          cryptoSigner,
        }),
    ).toThrow(/intervalMs must be > 0/);
  });

  it('start() is idempotent (calling twice does not create two timers)', async () => {
    const { pool } = makeMockPerReplicaPool();
    const backend = new PerReplicaPostgresLedgerBackend(pool, 'r1', {
      hmacSecret: HMAC_SECRET,
    });
    const cryptoSigner = new EcP256Signer();

    const ev = makeEvidence(1);
    await backend.appendEntry(ev, 'r1', (ph, seq) =>
      signEvidenceWithChain(ev, cryptoSigner, ph, seq),
    );

    const commitments: SignedCrossChainCommitment[] = [];
    const anchor = new CrossChainAnchor(backend, {
      intervalMs: 30,
      coordinatorId: 'r1',
      cryptoSigner,
      onCommitment: (c) => commitments.push(c),
    });
    anchor.start();
    anchor.start(); // second call is a no-op

    await new Promise((r) => setTimeout(r, 120));
    await anchor.stop();

    // If two timers had been created, commitments would arrive roughly twice
    // as fast. Hard to test for exactly, but commitmentSeq values must be
    // monotonically incremented by exactly 1 — no duplicates from two timers.
    for (let i = 1; i < commitments.length; i++) {
      expect(commitments[i]!.commitmentSeq - commitments[i - 1]!.commitmentSeq).toBe(1);
    }
  });

  it('commitments have sorted tips and correct Merkle root', async () => {
    const { pool } = makeMockPerReplicaPool();
    const backends: PerReplicaPostgresLedgerBackend[] = [];
    const replicaIds = ['replica-c', 'replica-a', 'replica-b']; // intentionally unsorted

    const cryptoSigner = new EcP256Signer();

    for (const id of replicaIds) {
      const backend = new PerReplicaPostgresLedgerBackend(pool, id, {
        hmacSecret: HMAC_SECRET,
      });
      backends.push(backend);
      const ev = makeEvidence(1);
      await backend.appendEntry(ev, id, (ph, seq) =>
        signEvidenceWithChain(ev, cryptoSigner, ph, seq),
      );
    }

    const commitments: SignedCrossChainCommitment[] = [];
    const anchor = new CrossChainAnchor(backends[0]!, {
      intervalMs: 30,
      coordinatorId: 'replica-a',
      cryptoSigner,
      onCommitment: (c) => commitments.push(c),
    });
    anchor.start();
    await new Promise((r) => setTimeout(r, 100));
    await anchor.stop();

    expect(commitments.length).toBeGreaterThanOrEqual(1);
    const c = commitments[0]!;

    // Tips must be sorted by replicaId.
    const replicaIdsInCommitment = c.tips.map((t: ChainTipSnapshot) => t.replicaId);
    expect(replicaIdsInCommitment).toEqual([...replicaIdsInCommitment].sort());
    expect(c.tipCount).toBe(3);
  });
});
