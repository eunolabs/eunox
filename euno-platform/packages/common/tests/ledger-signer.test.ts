/**
 * Tests for the pluggable ledger backend (ledger-signer.ts).
 *
 * Covers:
 *   1. InMemoryLedgerBackend — append, chain ordering, chain violation detection.
 *   2. LedgerAuditEvidenceSigner — signs evidence using a ledger backend.
 *   3. PostgresLedgerBackend — unit tests with a mock PgPool.
 *   4. Multi-replica contention — concurrent appends are serialised.
 *   5. verifyRowHmac — detects tampered rows.
 *   6. createLedgerSignerFromConfig — factory smoke test.
 */

import * as crypto from 'crypto';
import {
  InMemoryLedgerBackend,
  LedgerAuditEvidenceSigner,
  LedgerChainError,
  LedgerEntry,
  PostgresLedgerBackend,
  PerReplicaPostgresLedgerBackend,
  PostgresAuditQueryStore,
  AuditQueryStore,
  AzureConfidentialLedgerBackend,
  AzureConfidentialLedgerClient,
  PgPool,
  PgClientConnection,
  PgQueryResult,
  createLedgerSignerFromConfig,
} from '../src/ledger-signer';
import { CryptoSigner, createAuditEvidence, signEvidenceWithChain } from '../src/evidence';
import { GENESIS_HASH } from '../src/wire';
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
  private readonly publicKey: crypto.KeyObject;
  private readonly kid: string;

  constructor(kid = 'test-p256') {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.kid = kid;
  }

  async signDigest(digest: Buffer): Promise<Buffer> {
    return crypto.sign(null, digest, {
      key: this.privateKey,
      dsaEncoding: 'ieee-p1363',
    });
  }

  async verifyDigest(digest: Buffer, sig: Buffer, kid: string, _alg: string): Promise<boolean> {
    if (kid !== this.kid) return false;
    return crypto.verify(null, digest, { key: this.publicKey, dsaEncoding: 'ieee-p1363' }, sig);
  }

  async getKeyId(): Promise<string> {
    return this.kid;
  }

  getAlgorithm(): string {
    return 'ES256';
  }
}

// ── InMemoryLedgerBackend tests ───────────────────────────────────────────────

describe('InMemoryLedgerBackend', () => {
  it('starts empty, getChainTip returns null', async () => {
    const backend = new InMemoryLedgerBackend();
    expect(await backend.getChainTip()).toBeNull();
    expect(backend.size).toBe(0);
  });

  it('assigns seq=1 and previousHash=GENESIS_HASH to the first entry', async () => {
    const backend = new InMemoryLedgerBackend();
    const cryptoSigner = new EcP256Signer();

    const ev = makeEvidence(1);
    const signed = await backend.appendEntry(ev, 'replica-1', (previousHash, nextSeq) => {
      expect(previousHash).toBe(GENESIS_HASH);
      expect(nextSeq).toBe(1);
      return import('../src/evidence').then(({ signEvidenceWithChain }) =>
        signEvidenceWithChain(ev, cryptoSigner, previousHash, nextSeq),
      );
    });

    expect(signed.seq).toBe(1);
    expect(signed.previousHash).toBe(GENESIS_HASH);
    expect(backend.size).toBe(1);
  });

  it('chains records correctly: each previousHash equals the hash of the preceding record', async () => {
    const backend = new InMemoryLedgerBackend();
    const cryptoSigner = new EcP256Signer();

    const records = [];
    for (let i = 1; i <= 5; i++) {
      const ev = makeEvidence(i);
      const signed = await backend.appendEntry(ev, 'replica-1', (ph, seq) =>
        signEvidenceWithChain(ev, cryptoSigner, ph, seq),
      );
      records.push(signed);
    }

    // Verify the chain
    for (let i = 1; i < records.length; i++) {
      const expected = canonicalSha256(records[i - 1]!);
      expect(records[i]!.previousHash).toBe(expected);
    }
    expect(records[0]!.previousHash).toBe(GENESIS_HASH);
  });

  it('getChainTip returns the last entry hash after appends', async () => {
    const backend = new InMemoryLedgerBackend();
    const cryptoSigner = new EcP256Signer();

    const ev = makeEvidence(1);
    const signed = await backend.appendEntry(ev, 'r1', (ph, seq) =>
      signEvidenceWithChain(ev, cryptoSigner, ph, seq),
    );

    const tip = await backend.getChainTip();
    expect(tip).not.toBeNull();
    expect(tip!.seq).toBe(1);
    expect(tip!.tipHash).toBe(canonicalSha256(signed));
  });

  it('getEntries returns the correct range', async () => {
    const backend = new InMemoryLedgerBackend();
    const cryptoSigner = new EcP256Signer();

    for (let i = 1; i <= 10; i++) {
      const ev = makeEvidence(i);
      await backend.appendEntry(ev, 'r1', (ph, seq) =>
        signEvidenceWithChain(ev, cryptoSigner, ph, seq),
      );
    }

    const slice = await backend.getEntries(3, 7);
    expect(slice.length).toBe(5);
    expect(slice[0]!.seq).toBe(3);
    expect(slice[4]!.seq).toBe(7);
  });

  it('rejects when sign callback returns wrong previousHash (LedgerChainError)', async () => {
    const backend = new InMemoryLedgerBackend();
    const cryptoSigner = new EcP256Signer();

    const ev = makeEvidence(1);
    // Tamper: sign with a fake previousHash instead of the one the backend provides.
    await expect(
      backend.appendEntry(ev, 'r1', async (_ph, seq) => {
        const fakePh = 'aabbccdd'.repeat(8); // wrong hash
        return signEvidenceWithChain(ev, cryptoSigner, fakePh, seq);
      }),
    ).rejects.toThrow(LedgerChainError);
  });

  it('serialises concurrent appends so seq numbers are unique and consecutive', async () => {
    const backend = new InMemoryLedgerBackend();
    const cryptoSigner = new EcP256Signer();

    // Fire 10 concurrent appends.
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
});

// ── LedgerAuditEvidenceSigner tests ──────────────────────────────────────────

describe('LedgerAuditEvidenceSigner', () => {
  it('produces signed records with correct seq and previousHash', async () => {
    const backend = new InMemoryLedgerBackend();
    const cryptoSigner = new EcP256Signer();
    const signer = new LedgerAuditEvidenceSigner(cryptoSigner, backend, 'test-replica');

    const ev1 = makeEvidence(1);
    const ev2 = makeEvidence(2);

    const s1 = await signer.signEvidence(ev1);
    const s2 = await signer.signEvidence(ev2);

    expect(s1.seq).toBe(1);
    expect(s1.previousHash).toBe(GENESIS_HASH);
    expect(s2.seq).toBe(2);
    expect(s2.previousHash).toBe(canonicalSha256(s1));
  });

  it('verifyEvidence returns true for a valid signed record', async () => {
    const backend = new InMemoryLedgerBackend();
    const cryptoSigner = new EcP256Signer();
    const signer = new LedgerAuditEvidenceSigner(cryptoSigner, backend, 'test-replica');

    const ev = makeEvidence(1);
    const signed = await signer.signEvidence(ev);
    expect(await signer.verifyEvidence(signed)).toBe(true);
  });

  it('verifyEvidence returns false when signature is tampered', async () => {
    const backend = new InMemoryLedgerBackend();
    const cryptoSigner = new EcP256Signer();
    const signer = new LedgerAuditEvidenceSigner(cryptoSigner, backend, 'test-replica');

    const ev = makeEvidence(1);
    const signed = await signer.signEvidence(ev);
    const tampered = { ...signed, signature: 'AAAA' + signed.signature.slice(4) };
    expect(await signer.verifyEvidence(tampered)).toBe(false);
  });

  it('verifyEvidence returns false when previousHash is tampered', async () => {
    const backend = new InMemoryLedgerBackend();
    const cryptoSigner = new EcP256Signer();
    const signer = new LedgerAuditEvidenceSigner(cryptoSigner, backend, 'test-replica');

    const ev = makeEvidence(1);
    const signed = await signer.signEvidence(ev);
    const tampered = { ...signed, previousHash: 'ff'.repeat(32) };
    expect(await signer.verifyEvidence(tampered)).toBe(false);
  });

  it('serialises concurrent signEvidence calls', async () => {
    const backend = new InMemoryLedgerBackend();
    const cryptoSigner = new EcP256Signer();
    const signer = new LedgerAuditEvidenceSigner(cryptoSigner, backend, 'test-replica');

    const promises = Array.from({ length: 8 }, (_, i) => signer.signEvidence(makeEvidence(i + 1)));
    const results = await Promise.all(promises);
    const seqs = results.map((r) => r.seq).sort((a, b) => a - b);
    expect(seqs).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
  });

  it('getBackend returns the wrapped backend', () => {
    const backend = new InMemoryLedgerBackend();
    const signer = new LedgerAuditEvidenceSigner(new EcP256Signer(), backend, 'r1');
    expect(signer.getBackend()).toBe(backend);
  });
});

// ── PostgresLedgerBackend (mock PgPool) tests ─────────────────────────────────

/**
 * Build a mock PgPool that simulates the PostgreSQL ledger table in memory.
 */
function makeMockPgPool(): {
  pool: PgPool;
  rows: Array<{
    seq: number;
    record_id: string;
    replica_id: string;
    previous_hash: string;
    record_hash: string;
    payload: unknown;
    row_hmac: Buffer;
    created_at: Date;
  }>;
  lockAcquired: boolean;
} {
  const rows: Array<{
    seq: number;
    record_id: string;
    replica_id: string;
    previous_hash: string;
    record_hash: string;
    payload: unknown;
    row_hmac: Buffer;
    created_at: Date;
  }> = [];

  let lockAcquired = false;

  const makeClient = (): PgClientConnection => ({
    query<R extends Record<string, unknown> = Record<string, unknown>>(
      sql: string,
      values?: unknown[],
    ): Promise<PgQueryResult<R>> {
      const trimmed = sql.trim().toUpperCase();

      if (trimmed === 'BEGIN') {
        return Promise.resolve({ rows: [], rowCount: 0 }) as unknown as Promise<PgQueryResult<R>>;
      }
      if (trimmed === 'COMMIT' || trimmed === 'ROLLBACK') {
        lockAcquired = false;
        return Promise.resolve({ rows: [], rowCount: 0 }) as unknown as Promise<PgQueryResult<R>>;
      }
      if (trimmed.startsWith('SELECT PG_ADVISORY_XACT_LOCK')) {
        lockAcquired = true;
        return Promise.resolve({ rows: [], rowCount: 0 }) as unknown as Promise<PgQueryResult<R>>;
      }
      if (trimmed.startsWith('CREATE TABLE') || trimmed.startsWith('CREATE INDEX')) {
        return Promise.resolve({ rows: [], rowCount: 0 }) as unknown as Promise<PgQueryResult<R>>;
      }
      // SELECT ... ORDER BY seq DESC LIMIT 1 — tip query
      if (trimmed.includes('ORDER BY SEQ DESC LIMIT 1')) {
        if (rows.length === 0) {
          return Promise.resolve({ rows: [], rowCount: 0 }) as unknown as Promise<PgQueryResult<R>>;
        }
        const last = rows[rows.length - 1]!;
        return Promise.resolve({
          rows: [{ seq: String(last.seq), record_hash: last.record_hash }],
          rowCount: 1,
        }) as unknown as Promise<PgQueryResult<R>>;
      }
      // INSERT with application-assigned seq (no RETURNING)
      if (trimmed.startsWith('INSERT INTO')) {
        const [seq, recordId, replicaId, previousHash, recordHash, payloadJson, rowHmac] = values as [
          number,
          string,
          string,
          string,
          string,
          string,
          Buffer,
        ];
        rows.push({
          seq,
          record_id: recordId,
          replica_id: replicaId,
          previous_hash: previousHash,
          record_hash: recordHash,
          payload: JSON.parse(payloadJson),
          row_hmac: rowHmac,
          created_at: new Date(),
        });
        return Promise.resolve({
          rows: [],
          rowCount: 1,
        }) as unknown as Promise<PgQueryResult<R>>;
      }
      // SELECT seq, ... WHERE seq >= $1 AND seq <= $2
      if (trimmed.includes('WHERE SEQ >=')) {
        const [fromSeq, toSeq] = values as [number, number];
        const slice = rows.filter((r) => r.seq >= fromSeq && r.seq <= toSeq);
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
      return Promise.resolve({ rows: [], rowCount: 0 }) as unknown as Promise<PgQueryResult<R>>;
    },
    release() { /* no-op */ },
  });

  const pool: PgPool = {
    connect: () => Promise.resolve(makeClient()),
    end: () => Promise.resolve(),
  };

  return { pool, rows, get lockAcquired() { return lockAcquired; } };
}

describe('PostgresLedgerBackend', () => {
  const HMAC_SECRET = 'a'.repeat(64); // 64-char hex = 32-byte key

  it('appends records and returns a valid signed record', async () => {
    const { pool } = makeMockPgPool();
    const backend = new PostgresLedgerBackend(pool, { hmacSecret: HMAC_SECRET });
    const cryptoSigner = new EcP256Signer();

    const ev = makeEvidence(1);
    const signed = await backend.appendEntry(ev, 'replica-1', (ph, seq) =>
      signEvidenceWithChain(ev, cryptoSigner, ph, seq),
    );

    expect(signed.seq).toBe(1);
    expect(signed.previousHash).toBe(GENESIS_HASH);
  });

  it('builds a valid sequential chain across multiple appends', async () => {
    const { pool } = makeMockPgPool();
    const backend = new PostgresLedgerBackend(pool, { hmacSecret: HMAC_SECRET });
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

    for (let i = 1; i < records.length; i++) {
      expect(records[i]!.previousHash).toBe(canonicalSha256(records[i - 1]!));
    }
    expect(records[0]!.previousHash).toBe(GENESIS_HASH);
  });

  it('getChainTip returns null when empty, then the correct tip after appends', async () => {
    const { pool } = makeMockPgPool();
    const backend = new PostgresLedgerBackend(pool, { hmacSecret: HMAC_SECRET });
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

  it('verifyRowHmac detects tampered records', async () => {
    const { pool, rows } = makeMockPgPool();
    const backend = new PostgresLedgerBackend(pool, { hmacSecret: HMAC_SECRET });
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

    // Should pass for an untampered row.
    expect(backend.verifyRowHmac(entry, row.row_hmac)).toBe(true);

    // Tamper: change the recordHash in the entry.
    const tampered: LedgerEntry = { ...entry, recordHash: 'ff'.repeat(32) };
    expect(backend.verifyRowHmac(tampered, row.row_hmac)).toBe(false);
  });

  it('rejects when sign callback returns wrong previousHash', async () => {
    const { pool } = makeMockPgPool();
    const backend = new PostgresLedgerBackend(pool, { hmacSecret: HMAC_SECRET });
    const cryptoSigner = new EcP256Signer();

    const ev = makeEvidence(1);
    await expect(
      backend.appendEntry(ev, 'r1', async (_ph, seq) => {
        // Sign with wrong previousHash.
        return signEvidenceWithChain(ev, cryptoSigner, 'ff'.repeat(32), seq);
      }),
    ).rejects.toThrow(LedgerChainError);
  });

  it('rejects when sign callback returns wrong seq (LedgerChainError)', async () => {
    const { pool } = makeMockPgPool();
    const backend = new PostgresLedgerBackend(pool, { hmacSecret: HMAC_SECRET });
    const cryptoSigner = new EcP256Signer();

    const ev = makeEvidence(1);
    await expect(
      backend.appendEntry(ev, 'r1', async (ph, _seq) => {
        // Sign with the right previousHash but wrong seq (99 instead of 1).
        return signEvidenceWithChain(ev, cryptoSigner, ph, 99);
      }),
    ).rejects.toThrow(LedgerChainError);
  });

  it('verifyRowHmac returns false for truncated/wrong-length rawHmac (no throw)', async () => {
    const { pool, rows } = makeMockPgPool();
    const backend = new PostgresLedgerBackend(pool, { hmacSecret: HMAC_SECRET });
    const cryptoSigner = new EcP256Signer();
    const ev = makeEvidence(1);
    await backend.appendEntry(ev, 'r1', (ph, seq) =>
      signEvidenceWithChain(ev, cryptoSigner, ph, seq),
    );
    const row = rows[0]!;
    const entry = await backend.getEntries(1, 1).then((e) => e[0]!);

    // Truncated HMAC — should return false, not throw.
    expect(backend.verifyRowHmac(entry, row.row_hmac.slice(0, 4))).toBe(false);
    // Empty buffer.
    expect(backend.verifyRowHmac(entry, Buffer.alloc(0))).toBe(false);
  });

  it('throws on invalid table name (SQL injection prevention)', () => {
    const { pool } = makeMockPgPool();
    expect(
      () => new PostgresLedgerBackend(pool, { hmacSecret: HMAC_SECRET, table: 'bad; DROP TABLE' }),
    ).toThrow(/invalid table name/i);
  });

  it('accepts schema-qualified table names', () => {
    const { pool } = makeMockPgPool();
    expect(
      () => new PostgresLedgerBackend(pool, { hmacSecret: HMAC_SECRET, table: 'audit.euno_ledger' }),
    ).not.toThrow();
  });

  it('rejects hmacSecret shorter than 32 bytes', () => {
    const { pool } = makeMockPgPool();
    // 10-char hex = 5 bytes
    expect(
      () => new PostgresLedgerBackend(pool, { hmacSecret: 'a'.repeat(10) }),
    ).toThrow(/minimum 32 bytes/);
  });

  it('accepts 64-char hex hmacSecret (32 bytes)', () => {
    const { pool } = makeMockPgPool();
    expect(
      () => new PostgresLedgerBackend(pool, { hmacSecret: 'a'.repeat(64) }),
    ).not.toThrow();
  });

  it('seeds lastAnchoredSeq from DB tip via initialize()', async () => {
    const { pool } = makeMockPgPool();
    const backend = new PostgresLedgerBackend(pool, {
      hmacSecret: HMAC_SECRET,
      s3: {
        client: { putObject: async () => { /* no-op */ } },
        bucket: 'b',
        anchorIntervalRows: 2,
      },
    });
    const cryptoSigner = new EcP256Signer();
    // Append 2 rows so tip.seq = 2.
    for (let i = 1; i <= 2; i++) {
      const ev = makeEvidence(i);
      await backend.appendEntry(ev, 'r1', (ph, seq) =>
        signEvidenceWithChain(ev, cryptoSigner, ph, seq),
      );
    }

    // Create a new backend instance with the same pool to simulate restart.
    const putCalls: Array<unknown> = [];
    const backend2 = new PostgresLedgerBackend(pool, {
      hmacSecret: HMAC_SECRET,
      s3: {
        client: { putObject: async (p: unknown) => { putCalls.push(p); } },
        bucket: 'b',
        anchorIntervalRows: 2,
      },
    });
    // initialize() seeds lastAnchoredSeq = 2 (the current tip).
    await backend2.initialize();

    // Append 2 more rows: seq 3 and 4. Without initialize(), the anchor
    // would trigger at seq 2 (lastAnchoredSeq=0, 2-0 >= 2). With initialize(),
    // the anchor triggers at seq 4 (lastAnchoredSeq=2, 4-2 >= 2).
    for (let i = 3; i <= 4; i++) {
      const ev = makeEvidence(i);
      await backend2.appendEntry(ev, 'r1', (ph, seq) =>
        signEvidenceWithChain(ev, cryptoSigner, ph, seq),
      );
    }
    await new Promise((r) => setTimeout(r, 20));
    expect(putCalls.length).toBe(1);
  });

  it('calls onAnchorError when S3 client throws', async () => {
    const { pool } = makeMockPgPool();
    const anchorErrors: Error[] = [];
    const failingS3 = {
      putObject: async () => { throw new Error('S3 write failed'); },
    };
    const backend = new PostgresLedgerBackend(pool, {
      hmacSecret: HMAC_SECRET,
      s3: {
        client: failingS3,
        bucket: 'test-bucket',
        anchorIntervalRows: 1, // trigger on every row
      },
      onAnchorError: (err) => anchorErrors.push(err),
    });
    const cryptoSigner = new EcP256Signer();

    const ev = makeEvidence(1);
    // appendEntry itself succeeds; anchor failure is fire-and-forget.
    const signed = await backend.appendEntry(ev, 'r1', (ph, seq) =>
      signEvidenceWithChain(ev, cryptoSigner, ph, seq),
    );
    expect(signed.seq).toBe(1);

    // Wait for the async anchor attempt.
    await new Promise((r) => setTimeout(r, 10));
    expect(anchorErrors.length).toBeGreaterThan(0);
    expect(anchorErrors[0]!.message).toBe('S3 write failed');
  });

  it('migrate runs CREATE TABLE and CREATE INDEX without error', async () => {
    const { pool } = makeMockPgPool();
    const backend = new PostgresLedgerBackend(pool, { hmacSecret: HMAC_SECRET });
    await expect(backend.migrate()).resolves.toBeUndefined();
  });

  it('migrate creates expression indexes for all queryEntries() JSONB predicates', async () => {
    const capturedSql: string[] = [];
    const fakePool: PgPool = {
      connect: () => Promise.resolve({
        query<R extends Record<string, unknown>>(sql: string): Promise<PgQueryResult<R>> {
          capturedSql.push(sql.trim());
          return Promise.resolve({ rows: [], rowCount: 0 }) as unknown as Promise<PgQueryResult<R>>;
        },
        release() { /* no-op */ },
      }),
      end: () => Promise.resolve(),
    };
    const backend = new PostgresLedgerBackend(fakePool, { hmacSecret: HMAC_SECRET });
    await backend.migrate();

    const indexSqls = capturedSql.filter((s) => s.toUpperCase().startsWith('CREATE INDEX'));
    const allIndexSql = indexSqls.join('\n');

    // All five JSONB expression indexes must be present.
    expect(allIndexSql).toMatch(/payload->>'tenantId'/);
    expect(allIndexSql).toMatch(/payload->>'decision'/);
    expect(allIndexSql).toMatch(/payload->>'capabilityId'/);
    expect(allIndexSql).toMatch(/payload->>'agentId'/);
    expect(allIndexSql).toMatch(/payload->>'denialCode'/);
    // The created_at structural index must still be present.
    expect(allIndexSql).toMatch(/idx_euno_audit_ledger_created_at/);
  });

  it('getEntries returns the expected slice', async () => {
    const { pool } = makeMockPgPool();
    const backend = new PostgresLedgerBackend(pool, { hmacSecret: HMAC_SECRET });
    const cryptoSigner = new EcP256Signer();

    for (let i = 1; i <= 5; i++) {
      const ev = makeEvidence(i);
      await backend.appendEntry(ev, 'r1', (ph, seq) =>
        signEvidenceWithChain(ev, cryptoSigner, ph, seq),
      );
    }

    const slice = await backend.getEntries(2, 4);
    expect(slice.length).toBe(3);
    expect(slice[0]!.seq).toBe(2);
    expect(slice[2]!.seq).toBe(4);
  });
});

// ── createLedgerSignerFromConfig factory tests ────────────────────────────────

describe('createLedgerSignerFromConfig', () => {
  it('returns null when backend=none', async () => {
    const result = await createLedgerSignerFromConfig({
      backend: 'none',
      cryptoSigner: new EcP256Signer(),
      replicaId: 'r1',
    });
    expect(result).toBeNull();
  });

  it('returns LedgerAuditEvidenceSigner when backend=in-memory', async () => {
    const result = await createLedgerSignerFromConfig({
      backend: 'in-memory',
      cryptoSigner: new EcP256Signer(),
      replicaId: 'r1',
    });
    expect(result).toBeInstanceOf(LedgerAuditEvidenceSigner);
    expect(result!.getBackend()).toBeInstanceOf(InMemoryLedgerBackend);
  });

  it('throws when backend=postgres and pgPool is missing', async () => {
    await expect(
      createLedgerSignerFromConfig({
        backend: 'postgres',
        cryptoSigner: new EcP256Signer(),
        replicaId: 'r1',
        // pgPool intentionally omitted
        pgOptions: { hmacSecret: 'a'.repeat(64) },
      }),
    ).rejects.toThrow(/pgPool is required/);
  });

  it('throws when backend=postgres and pgOptions is missing', async () => {
    const { pool } = makeMockPgPool();
    await expect(
      createLedgerSignerFromConfig({
        backend: 'postgres',
        cryptoSigner: new EcP256Signer(),
        replicaId: 'r1',
        pgPool: pool,
        // pgOptions intentionally omitted
      }),
    ).rejects.toThrow(/pgOptions is required/);
  });

  it('returns LedgerAuditEvidenceSigner with postgres backend', async () => {
    const { pool } = makeMockPgPool();
    const result = await createLedgerSignerFromConfig({
      backend: 'postgres',
      cryptoSigner: new EcP256Signer(),
      replicaId: 'r1',
      pgPool: pool,
      pgOptions: { hmacSecret: 'a'.repeat(64) },
    });
    expect(result).toBeInstanceOf(LedgerAuditEvidenceSigner);
    expect(result!.getBackend()).toBeInstanceOf(PostgresLedgerBackend);
  });

  it('runs migrations when runMigrations=true', async () => {
    const { pool } = makeMockPgPool();
    // Should not throw.
    const result = await createLedgerSignerFromConfig({
      backend: 'postgres',
      cryptoSigner: new EcP256Signer(),
      replicaId: 'r1',
      pgPool: pool,
      pgOptions: { hmacSecret: 'a'.repeat(64) },
      runMigrations: true,
    });
    expect(result).toBeInstanceOf(LedgerAuditEvidenceSigner);
  });
});

// ── S3 anchor smoke test ──────────────────────────────────────────────────────

describe('PostgresLedgerBackend S3 anchor', () => {
  it('calls putObject with the correct key and JSON payload after anchorIntervalRows rows', async () => {
    const { pool } = makeMockPgPool();
    const putCalls: Array<{ bucket: string; key: string; body: string }> = [];
    const backend = new PostgresLedgerBackend(pool, {
      hmacSecret: 'a'.repeat(64),
      s3: {
        client: {
          async putObject(params) {
            putCalls.push(params);
          },
        },
        bucket: 'my-audit-bucket',
        prefix: 'anchor/',
        anchorIntervalRows: 3,
      },
    });
    const cryptoSigner = new EcP256Signer();

    // Append 3 rows — should trigger the anchor on the 3rd row.
    for (let i = 1; i <= 3; i++) {
      const ev = makeEvidence(i);
      await backend.appendEntry(ev, 'rep-1', (ph, seq) =>
        signEvidenceWithChain(ev, cryptoSigner, ph, seq),
      );
    }

    // Wait for async anchor.
    await new Promise((r) => setTimeout(r, 20));

    expect(putCalls.length).toBe(1);
    const call = putCalls[0]!;
    expect(call.bucket).toBe('my-audit-bucket');
    expect(call.key).toMatch(/^anchor\/rep-1\//);

    const payload = JSON.parse(call.body) as Record<string, unknown>;
    expect(payload['schemaVersion']).toBe('1.0');
    expect(payload['fromSeq']).toBe(1);
    expect(payload['toSeq']).toBe(3);
    expect(typeof payload['merkleRoot']).toBe('string');
    expect(payload['replicaId']).toBe('rep-1');
  });
});

// ── PostgresLedgerBackend.migrate() schema-qualified name fix ─────────────────

describe('PostgresLedgerBackend.migrate() schema-qualified table name', () => {
  it('generates a valid index name (no dot) for schema-qualified table', async () => {
    const capturedSql: string[] = [];
    const fakePool: PgPool = {
      connect: () => Promise.resolve({
        query<R extends Record<string, unknown>>(sql: string): Promise<PgQueryResult<R>> {
          capturedSql.push(sql.trim());
          return Promise.resolve({ rows: [], rowCount: 0 }) as unknown as Promise<PgQueryResult<R>>;
        },
        release() { /* no-op */ },
      }),
      end: () => Promise.resolve(),
    };

    const backend = new PostgresLedgerBackend(fakePool, {
      hmacSecret: 'a'.repeat(64),
      table: 'audit.euno_ledger',
    });
    await backend.migrate();

    const indexSqls = capturedSql.filter((s) => s.toUpperCase().startsWith('CREATE INDEX'));
    expect(indexSqls.length).toBeGreaterThan(0);
    // The first index is the created_at one; validate name correctness.
    expect(indexSqls[0]).not.toMatch(/idx_audit\./);
    expect(indexSqls[0]).toMatch(/idx_euno_ledger_created_at/);
    // None of the index names should contain a dot (schema-qualified name collision).
    for (const sql of indexSqls) {
      const nameMatch = sql.match(/CREATE INDEX IF NOT EXISTS (\S+)/i);
      if (nameMatch) {
        expect(nameMatch[1]).not.toMatch(/\./);
      }
    }
  });
});

// ── PostgresLedgerBackend.getEntries() includes rowHmac ──────────────────────

describe('PostgresLedgerBackend.getEntries() rowHmac field', () => {
  const HMAC_SECRET = 'a'.repeat(64);

  it('returns rowHmac in each LedgerEntry', async () => {
    const { pool, rows } = makeMockPgPool();
    const backend = new PostgresLedgerBackend(pool, { hmacSecret: HMAC_SECRET });
    const cryptoSigner = new EcP256Signer();

    const ev = makeEvidence(1);
    const signed = await backend.appendEntry(ev, 'r1', (ph, seq) =>
      signEvidenceWithChain(ev, cryptoSigner, ph, seq),
    );

    const entries = await backend.getEntries(1, 1);
    expect(entries.length).toBe(1);
    const entry = entries[0]!;

    // rowHmac must be present and match what was stored.
    expect(entry.rowHmac).toBeDefined();
    expect(Buffer.isBuffer(entry.rowHmac)).toBe(true);

    // And verifyRowHmac with the returned rowHmac must pass — callers no
    // longer need a separate raw DB query to do offline verification.
    expect(backend.verifyRowHmac(entry, entry.rowHmac!)).toBe(true);

    // Cross-check: same HMAC as stored in the raw mock rows.
    const row = rows[0]!;
    expect(entry.rowHmac!.equals(row.row_hmac)).toBe(true);

    // Tampered entry should fail.
    const tampered = { ...entry, recordHash: 'ff'.repeat(32) };
    expect(backend.verifyRowHmac(tampered, entry.rowHmac!)).toBe(false);

    void signed; // suppress unused-var
  });
});


// ── AzureConfidentialLedgerBackend tests ──────────────────────────────────────

/**
 * Build a mock AzureConfidentialLedgerClient that stores transactions
 * in memory, simulating a simple round-trip to ACL.
 */
function makeMockAclClient(): {
  client: AzureConfidentialLedgerClient;
  transactions: Array<{ transactionId: string; contents: string }>;
} {
  const transactions: Array<{ transactionId: string; contents: string }> = [];
  let nextTxId = 1;

  const client: AzureConfidentialLedgerClient = {
    async appendTransaction(contents) {
      const transactionId = String(nextTxId++);
      transactions.push({ transactionId, contents });
      return { transactionId };
    },
    async getLatestCommittedTransaction() {
      if (transactions.length === 0) return null;
      return transactions[transactions.length - 1]!;
    },
    async getTransaction(transactionId) {
      return transactions.find((t) => t.transactionId === transactionId) ?? null;
    },
  };

  return { client, transactions };
}

describe('AzureConfidentialLedgerBackend', () => {
  it('starts empty, getChainTip returns null', async () => {
    const { client } = makeMockAclClient();
    const backend = new AzureConfidentialLedgerBackend(client);
    expect(await backend.getChainTip()).toBeNull();
  });

  it('assigns seq=1 and previousHash=GENESIS_HASH to the first entry', async () => {
    const { client } = makeMockAclClient();
    const backend = new AzureConfidentialLedgerBackend(client);
    const cryptoSigner = new EcP256Signer();

    const ev = makeEvidence(1);
    const signed = await backend.appendEntry(ev, 'replica-1', (ph, seq) =>
      signEvidenceWithChain(ev, cryptoSigner, ph, seq),
    );

    expect(signed.seq).toBe(1);
    expect(signed.previousHash).toBe(GENESIS_HASH);
    const tip = await backend.getChainTip();
    expect(tip).not.toBeNull();
    expect(tip!.seq).toBe(1);
  });

  it('chains records correctly across multiple appends', async () => {
    const { client } = makeMockAclClient();
    const backend = new AzureConfidentialLedgerBackend(client);
    const cryptoSigner = new EcP256Signer();

    const records = [];
    for (let i = 1; i <= 5; i++) {
      const ev = makeEvidence(i);
      const signed = await backend.appendEntry(ev, 'r1', (ph, seq) =>
        signEvidenceWithChain(ev, cryptoSigner, ph, seq),
      );
      records.push(signed);
    }

    for (let i = 1; i < records.length; i++) {
      expect(records[i]!.previousHash).toBe(canonicalSha256(records[i - 1]!));
    }
    expect(records[0]!.previousHash).toBe(GENESIS_HASH);
  });

  it('serialises concurrent appends so seq numbers are unique and consecutive', async () => {
    const { client } = makeMockAclClient();
    const backend = new AzureConfidentialLedgerBackend(client);
    const cryptoSigner = new EcP256Signer();

    const promises = Array.from({ length: 8 }, (_, i) => {
      const ev = makeEvidence(i + 1);
      return backend.appendEntry(ev, 'r1', (ph, seq) =>
        signEvidenceWithChain(ev, cryptoSigner, ph, seq),
      );
    });
    const results = await Promise.all(promises);
    const seqs = results.map((r) => r.seq).sort((a, b) => a - b);
    expect(seqs).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
  });

  it('rejects with LedgerChainError when sign callback returns wrong previousHash', async () => {
    const { client } = makeMockAclClient();
    const backend = new AzureConfidentialLedgerBackend(client);
    const cryptoSigner = new EcP256Signer();

    const ev = makeEvidence(1);
    await expect(
      backend.appendEntry(ev, 'r1', async (_ph, seq) => {
        return signEvidenceWithChain(ev, cryptoSigner, 'ff'.repeat(32), seq);
      }),
    ).rejects.toThrow(LedgerChainError);
  });

  it('rejects with LedgerChainError when sign callback returns wrong seq', async () => {
    const { client } = makeMockAclClient();
    const backend = new AzureConfidentialLedgerBackend(client);
    const cryptoSigner = new EcP256Signer();

    const ev = makeEvidence(1);
    await expect(
      backend.appendEntry(ev, 'r1', async (ph, _seq) => {
        return signEvidenceWithChain(ev, cryptoSigner, ph, 99);
      }),
    ).rejects.toThrow(LedgerChainError);
  });

  it('does not advance chain state when ACL append fails', async () => {
    const { client } = makeMockAclClient();
    let failNext = true;
    const failingClient: AzureConfidentialLedgerClient = {
      ...client,
      async appendTransaction(contents) {
        if (failNext) {
          failNext = false;
          throw new Error('ACL write timeout');
        }
        return client.appendTransaction(contents);
      },
    };

    const backend = new AzureConfidentialLedgerBackend(failingClient);
    const cryptoSigner = new EcP256Signer();

    const ev1 = makeEvidence(1);
    // First append fails — chain must stay at genesis.
    await expect(
      backend.appendEntry(ev1, 'r1', (ph, seq) => signEvidenceWithChain(ev1, cryptoSigner, ph, seq)),
    ).rejects.toThrow('ACL write timeout');
    expect(await backend.getChainTip()).toBeNull();

    // Second append succeeds; must continue from genesis (seq=1).
    const ev2 = makeEvidence(1);
    const signed2 = await backend.appendEntry(ev2, 'r1', (ph, seq) =>
      signEvidenceWithChain(ev2, cryptoSigner, ph, seq),
    );
    expect(signed2.seq).toBe(1);
    expect(signed2.previousHash).toBe(GENESIS_HASH);
  });

  it('seeds chain state from ACL on initialize()', async () => {
    const { client } = makeMockAclClient();
    const cryptoSigner = new EcP256Signer();

    // Write 3 entries using one backend instance.
    const backend1 = new AzureConfidentialLedgerBackend(client);
    for (let i = 1; i <= 3; i++) {
      const ev = makeEvidence(i);
      await backend1.appendEntry(ev, 'r1', (ph, seq) =>
        signEvidenceWithChain(ev, cryptoSigner, ph, seq),
      );
    }

    // A new backend instance simulates a process restart.
    const backend2 = new AzureConfidentialLedgerBackend(client);
    // Before initialize(): in-process state is empty.
    expect(await backend2.getChainTip()).toBeNull();

    // After initialize(): chain state is seeded from the latest ACL transaction.
    await backend2.initialize();
    const tip = await backend2.getChainTip();
    expect(tip).not.toBeNull();
    expect(tip!.seq).toBe(3);

    // Appending after restart must continue from seq=4, not restart at seq=1.
    const ev4 = makeEvidence(4);
    const signed4 = await backend2.appendEntry(ev4, 'r1', (ph, seq) =>
      signEvidenceWithChain(ev4, cryptoSigner, ph, seq),
    );
    expect(signed4.seq).toBe(4);
  });

  it('getEntries returns entries from the in-process index', async () => {
    const { client } = makeMockAclClient();
    const backend = new AzureConfidentialLedgerBackend(client);
    const cryptoSigner = new EcP256Signer();

    for (let i = 1; i <= 5; i++) {
      const ev = makeEvidence(i);
      await backend.appendEntry(ev, 'r1', (ph, seq) =>
        signEvidenceWithChain(ev, cryptoSigner, ph, seq),
      );
    }

    const slice = await backend.getEntries(2, 4);
    expect(slice.length).toBe(3);
    expect(slice[0]!.seq).toBe(2);
    expect(slice[2]!.seq).toBe(4);
  });

  it('getEntries silently omits entries not in the in-process index', async () => {
    const { client } = makeMockAclClient();
    // Simulate a fresh backend (no index) pointing at a non-empty ACL.
    const backend = new AzureConfidentialLedgerBackend(client);
    // No entries written through this instance — index is empty.
    const entries = await backend.getEntries(1, 5);
    expect(entries).toEqual([]);
  });

  it('calls onError when getTransaction fails during getEntries', async () => {
    const { client } = makeMockAclClient();
    const cryptoSigner = new EcP256Signer();
    const errors: Error[] = [];

    const failingClient: AzureConfidentialLedgerClient = {
      ...client,
      getTransaction: async () => { throw new Error('ACL fetch error'); },
    };

    const backend = new AzureConfidentialLedgerBackend(failingClient, {
      onError: (err) => errors.push(err),
    });

    const ev = makeEvidence(1);
    await backend.appendEntry(ev, 'r1', (ph, seq) =>
      signEvidenceWithChain(ev, cryptoSigner, ph, seq),
    );

    // getEntries will attempt to call getTransaction, which now throws.
    const entries = await backend.getEntries(1, 1);
    expect(entries).toEqual([]); // silently omitted
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]!.message).toBe('ACL fetch error');
  });

  it('initialize() throws when latest transaction contents are malformed', async () => {
    // Build a mock client that returns garbage contents.
    const malformedClient: AzureConfidentialLedgerClient = {
      async appendTransaction() { return { transactionId: '1' }; },
      async getLatestCommittedTransaction() {
        // Return invalid base64-JSON (not a valid AclEntryPayload).
        return { transactionId: '1', contents: Buffer.from('{"broken":true}').toString('base64') };
      },
      async getTransaction() { return null; },
    };

    const backend = new AzureConfidentialLedgerBackend(malformedClient);
    await expect(backend.initialize()).rejects.toThrow(
      /unrecognised or invalid contents/,
    );
    // Chain state must not have advanced — still at genesis.
    expect(await backend.getChainTip()).toBeNull();
  });

  it('initialize() throws when latest transaction contents fail base64/JSON parsing', async () => {
    const badBase64Client: AzureConfidentialLedgerClient = {
      async appendTransaction() { return { transactionId: '1' }; },
      async getLatestCommittedTransaction() {
        return { transactionId: '1', contents: '!!not-base64!!' };
      },
      async getTransaction() { return null; },
    };

    const backend = new AzureConfidentialLedgerBackend(badBase64Client);
    await expect(backend.initialize()).rejects.toThrow(
      /unrecognised or invalid contents/,
    );
    expect(await backend.getChainTip()).toBeNull();
  });
});

// ── createLedgerSignerFromConfig — acl backend ────────────────────────────────

describe('createLedgerSignerFromConfig — acl backend', () => {
  it('throws when backend=acl and aclClient is missing', async () => {
    await expect(
      createLedgerSignerFromConfig({
        backend: 'acl',
        cryptoSigner: new EcP256Signer(),
        replicaId: 'r1',
        // aclClient intentionally omitted
      }),
    ).rejects.toThrow(/aclClient is required/);
  });

  it('returns LedgerAuditEvidenceSigner with AzureConfidentialLedgerBackend', async () => {
    const { client } = makeMockAclClient();
    const result = await createLedgerSignerFromConfig({
      backend: 'acl',
      cryptoSigner: new EcP256Signer(),
      replicaId: 'r1',
      aclClient: client,
    });
    expect(result).toBeInstanceOf(LedgerAuditEvidenceSigner);
    expect(result!.getBackend()).toBeInstanceOf(AzureConfidentialLedgerBackend);
  });

  it('signs and verifies evidence through the ACL backend', async () => {
    const { client } = makeMockAclClient();
    const result = await createLedgerSignerFromConfig({
      backend: 'acl',
      cryptoSigner: new EcP256Signer(),
      replicaId: 'r1',
      aclClient: client,
    });
    expect(result).not.toBeNull();
    const ev = makeEvidence(1);
    const signed = await result!.signEvidence(ev);
    expect(signed.seq).toBe(1);
    expect(signed.previousHash).toBe(GENESIS_HASH);
    expect(await result!.verifyEvidence(signed)).toBe(true);
  });
});

// ── DI-2: PostgresLedgerBackend per-tenant advisory lock mode ─────────────────

/**
 * Build a mock PgPool that records the advisory lock ID passed to each
 * pg_advisory_xact_lock call.  Used to verify DI-2 per-tenant lock sharding.
 */
function makeLockCapturingPgPool(): {
  pool: PgPool;
  capturedLockIds: string[];
} {
  const capturedLockIds: string[] = [];
  const inMemoryRows: Array<{ seq: number; record_hash: string; record_id: string }> = [];

  const makeClient = (): PgClientConnection => ({
    query<R extends Record<string, unknown> = Record<string, unknown>>(
      sql: string,
      values?: unknown[],
    ): Promise<PgQueryResult<R>> {
      const trimmed = sql.trim().toUpperCase();
      if (trimmed === 'BEGIN' || trimmed === 'COMMIT' || trimmed === 'ROLLBACK') {
        return Promise.resolve({ rows: [], rowCount: 0 }) as unknown as Promise<PgQueryResult<R>>;
      }
      if (trimmed.startsWith('SELECT PG_ADVISORY_XACT_LOCK')) {
        capturedLockIds.push(String(values![0]));
        return Promise.resolve({ rows: [], rowCount: 0 }) as unknown as Promise<PgQueryResult<R>>;
      }
      if (trimmed.includes('ORDER BY SEQ DESC LIMIT 1')) {
        if (inMemoryRows.length === 0) {
          return Promise.resolve({ rows: [], rowCount: 0 }) as unknown as Promise<PgQueryResult<R>>;
        }
        const last = inMemoryRows[inMemoryRows.length - 1]!;
        return Promise.resolve({
          rows: [{ seq: String(last.seq), record_hash: last.record_hash }],
          rowCount: 1,
        }) as unknown as Promise<PgQueryResult<R>>;
      }
      if (trimmed.startsWith('INSERT INTO')) {
        const [seq, recordId, , , recordHash] = values as [number, string, string, string, string];
        inMemoryRows.push({ seq, record_id: recordId, record_hash: recordHash });
        return Promise.resolve({ rows: [], rowCount: 1 }) as unknown as Promise<PgQueryResult<R>>;
      }
      return Promise.resolve({ rows: [], rowCount: 0 }) as unknown as Promise<PgQueryResult<R>>;
    },
    release() {
      // No-op: test pool clients hold no real resources; the mock PgPool
      // never opens a real database connection so there is nothing to release.
    },
  });

  const pool: PgPool = {
    connect: () => Promise.resolve(makeClient()),
    end: () => Promise.resolve(),
  };

  return { pool, capturedLockIds };
}

describe('PostgresLedgerBackend — advisoryLockMode (DI-2)', () => {
  const HMAC_SECRET = 'a'.repeat(64);
  const testSigner = new EcP256Signer();

  it('global mode uses the fixed default advisory lock ID', async () => {
    const { pool, capturedLockIds } = makeLockCapturingPgPool();
    const backend = new PostgresLedgerBackend(pool, { hmacSecret: HMAC_SECRET });
    const ev = makeEvidence(1);
    await backend.appendEntry(ev, 'replica-1', (prev, seq) =>
      signEvidenceWithChain(ev, testSigner, prev, seq),
    );
    expect(capturedLockIds).toHaveLength(1);
    // Default lock: BigInt('0x455534004C454447').toString() = '4995956537521685575'
    expect(capturedLockIds[0]).toBe('4995956537521685575');
  });

  it('per-tenant mode uses a different lock ID than the global default', async () => {
    const { pool, capturedLockIds } = makeLockCapturingPgPool();
    const backend = new PostgresLedgerBackend(pool, {
      hmacSecret: HMAC_SECRET,
      advisoryLockMode: 'per-tenant',
    });
    const ev = { ...makeEvidence(1), tenantId: 'tenant-acme' };
    await backend.appendEntry(ev, 'replica-1', (prev, seq) =>
      signEvidenceWithChain(ev, testSigner, prev, seq),
    );
    expect(capturedLockIds).toHaveLength(1);
    // Lock ID must NOT be the global default
    expect(capturedLockIds[0]).not.toBe('4995956537521685575');
  });

  it('per-tenant mode uses distinct lock IDs for different tenants', async () => {
    // Build two independent lock-capturing pools to isolate appends by tenant.
    const { pool: poolA, capturedLockIds: idsA } = makeLockCapturingPgPool();
    const { pool: poolB, capturedLockIds: idsB } = makeLockCapturingPgPool();

    const backendA = new PostgresLedgerBackend(poolA, {
      hmacSecret: HMAC_SECRET,
      advisoryLockMode: 'per-tenant',
    });
    const backendB = new PostgresLedgerBackend(poolB, {
      hmacSecret: HMAC_SECRET,
      advisoryLockMode: 'per-tenant',
    });

    const evA = { ...makeEvidence(1), tenantId: 'tenant-alpha' };
    const evB = { ...makeEvidence(2), tenantId: 'tenant-beta' };

    await backendA.appendEntry(evA, 'r-1', (prev, seq) => signEvidenceWithChain(evA, testSigner, prev, seq));
    await backendB.appendEntry(evB, 'r-1', (prev, seq) => signEvidenceWithChain(evB, testSigner, prev, seq));

    expect(idsA[0]).toBeDefined();
    expect(idsB[0]).toBeDefined();
    // Two distinct tenants must produce distinct FNV-1a lock IDs.
    expect(idsA[0]).not.toBe(idsB[0]);
  });

  it('per-tenant mode produces the same lock ID on repeated appends for the same tenant', async () => {
    const { pool, capturedLockIds } = makeLockCapturingPgPool();
    const backend = new PostgresLedgerBackend(pool, {
      hmacSecret: HMAC_SECRET,
      advisoryLockMode: 'per-tenant',
    });
    const ev1 = { ...makeEvidence(1), tenantId: 'tenant-stable' };
    const ev2 = { ...makeEvidence(2), tenantId: 'tenant-stable' };

    await backend.appendEntry(ev1, 'r-1', (prev, seq) => signEvidenceWithChain(ev1, testSigner, prev, seq));
    await backend.appendEntry(ev2, 'r-1', (prev, seq) => signEvidenceWithChain(ev2, testSigner, prev, seq));

    expect(capturedLockIds).toHaveLength(2);
    // Same tenant → same lock ID on every append.
    expect(capturedLockIds[0]).toBe(capturedLockIds[1]);
  });

  it('per-tenant mode throws when evidence.tenantId is absent (DI-2)', async () => {
    const { pool } = makeLockCapturingPgPool();
    const backend = new PostgresLedgerBackend(pool, {
      hmacSecret: HMAC_SECRET,
      advisoryLockMode: 'per-tenant',
    });
    const ev = makeEvidence(1); // tenantId is undefined
    await expect(
      backend.appendEntry(ev, 'r-1', (prev, seq) => signEvidenceWithChain(ev, testSigner, prev, seq)),
    ).rejects.toThrow(/per-tenant mode.*tenantId is required/);
  });
});

// ── PerReplicaPostgresLedgerBackend — migrate() JSONB indexes ─────────────────

describe('PerReplicaPostgresLedgerBackend.migrate()', () => {
  const HMAC_SECRET = 'a'.repeat(64);

  it('migrate runs without error', async () => {
    const fakePool: PgPool = {
      connect: () => Promise.resolve({
        query<R extends Record<string, unknown>>(_sql: string): Promise<PgQueryResult<R>> {
          return Promise.resolve({ rows: [], rowCount: 0 }) as unknown as Promise<PgQueryResult<R>>;
        },
        release() { /* no-op */ },
      }),
      end: () => Promise.resolve(),
    };
    const backend = new PerReplicaPostgresLedgerBackend(fakePool, 'r1', { hmacSecret: HMAC_SECRET });
    await expect(backend.migrate()).resolves.toBeUndefined();
  });

  it('creates expression indexes for all queryEntries() JSONB predicates', async () => {
    const capturedSql: string[] = [];
    const fakePool: PgPool = {
      connect: () => Promise.resolve({
        query<R extends Record<string, unknown>>(sql: string): Promise<PgQueryResult<R>> {
          capturedSql.push(sql.trim());
          return Promise.resolve({ rows: [], rowCount: 0 }) as unknown as Promise<PgQueryResult<R>>;
        },
        release() { /* no-op */ },
      }),
      end: () => Promise.resolve(),
    };
    const backend = new PerReplicaPostgresLedgerBackend(fakePool, 'r1', { hmacSecret: HMAC_SECRET });
    await backend.migrate();

    const indexSqls = capturedSql.filter((s) => s.toUpperCase().startsWith('CREATE INDEX'));
    const allIndexSql = indexSqls.join('\n');

    // Structural indexes.
    expect(allIndexSql).toMatch(/idx_euno_audit_ledger_v2_replica_seq/);
    expect(allIndexSql).toMatch(/idx_euno_audit_ledger_v2_created_at/);
    // JSONB expression indexes.
    expect(allIndexSql).toMatch(/payload->>'tenantId'/);
    expect(allIndexSql).toMatch(/payload->>'decision'/);
    expect(allIndexSql).toMatch(/payload->>'capabilityId'/);
    expect(allIndexSql).toMatch(/payload->>'agentId'/);
    expect(allIndexSql).toMatch(/payload->>'denialCode'/);
  });

  it('does not include a dot in index names for schema-qualified table', async () => {
    const capturedSql: string[] = [];
    const fakePool: PgPool = {
      connect: () => Promise.resolve({
        query<R extends Record<string, unknown>>(sql: string): Promise<PgQueryResult<R>> {
          capturedSql.push(sql.trim());
          return Promise.resolve({ rows: [], rowCount: 0 }) as unknown as Promise<PgQueryResult<R>>;
        },
        release() { /* no-op */ },
      }),
      end: () => Promise.resolve(),
    };
    const backend = new PerReplicaPostgresLedgerBackend(fakePool, 'r1', {
      hmacSecret: HMAC_SECRET,
      table: 'audit.euno_ledger_v2',
    });
    await backend.migrate();

    const indexSqls = capturedSql.filter((s) => s.toUpperCase().startsWith('CREATE INDEX'));
    // No index name should contain a dot (that would be parsed as schema.index and fail).
    for (const sql of indexSqls) {
      const nameMatch = sql.match(/CREATE INDEX IF NOT EXISTS (\S+)/i);
      if (nameMatch) {
        expect(nameMatch[1]).not.toMatch(/\./);
      }
    }
  });
});

// ── PostgresAuditQueryStore ───────────────────────────────────────────────────

describe('PostgresAuditQueryStore', () => {
  /** Build a mock PgPool whose SELECT queries scan an in-memory rows array. */
  function makeQueryPool(rows: Array<{
    seq: number;
    previous_hash: string;
    record_hash: string;
    replica_id: string;
    payload: Record<string, unknown>;
    row_hmac: Buffer;
    created_at: Date;
  }>): PgPool {
    let closed = false;
    const pool: PgPool = {
      connect() {
        const client: PgClientConnection = {
          query<R extends Record<string, unknown>>(sql: string, values?: unknown[]): Promise<PgQueryResult<R>> {
            // Parse LIMIT from the query (always the last $N param).
            const limitMatch = sql.match(/LIMIT\s+\$(\d+)/i);
            const limitIdx = limitMatch ? parseInt(limitMatch[1]!, 10) - 1 : null;
            const limitVal = limitIdx !== null && values ? Number(values[limitIdx]) : rows.length + 1;

            // Build candidates from all rows, applying WHERE predicates inline.
            let candidates = rows.filter((row) => {
              if (!values) return true;
              // cursor predicate (seq > $N or seq < $N)
              const ascMatch = sql.match(/seq\s*>\s*\$(\d+)/i);
              const descMatch = sql.match(/seq\s*<\s*\$(\d+)/i);
              if (ascMatch) {
                const idx = parseInt(ascMatch[1]!, 10) - 1;
                if (row.seq <= Number(values[idx])) return false;
              }
              if (descMatch) {
                const idx = parseInt(descMatch[1]!, 10) - 1;
                if (row.seq >= Number(values[idx])) return false;
              }
              // JSONB predicates
              const jsonbMatches = [...sql.matchAll(/payload->>'(\w+)'\s*=\s*\$(\d+)/gi)];
              for (const m of jsonbMatches) {
                const field = m[1]!;
                const idx = parseInt(m[2]!, 10) - 1;
                if (row.payload[field] !== values[idx]) return false;
              }
              return true;
            });

            // Apply ORDER BY direction.
            if (/ORDER BY seq DESC/i.test(sql)) {
              candidates = [...candidates].reverse();
            }

            const page = candidates.slice(0, limitVal);
            return Promise.resolve({
              rows: page.map((r) => ({
                seq: String(r.seq),
                previous_hash: r.previous_hash,
                record_hash: r.record_hash,
                replica_id: r.replica_id,
                payload: r.payload,
                row_hmac: r.row_hmac,
                created_at: r.created_at,
              })),
              rowCount: page.length,
            }) as unknown as Promise<PgQueryResult<R>>;
          },
          release() { /* no-op */ },
        };
        return Promise.resolve(client);
      },
      end() {
        closed = true;
        return Promise.resolve();
      },
    };
    return Object.assign(pool, { get closed() { return closed; } });
  }

  function makeRow(seq: number, overrides: Partial<Record<string, unknown>> = {}): {
    seq: number;
    previous_hash: string;
    record_hash: string;
    replica_id: string;
    payload: Record<string, unknown>;
    row_hmac: Buffer;
    created_at: Date;
  } {
    return {
      seq,
      previous_hash: 'hash-prev',
      record_hash: `hash-${seq}`,
      replica_id: 'r1',
      payload: {
        id: `ev-${seq}`,
        tenantId: 'tenant-1',
        agentId: 'agent-1',
        decision: 'allow',
        capabilityId: `cap-${seq}`,
        ts: new Date(1700000000000 + seq * 1000).toISOString(),
        ...overrides,
      },
      row_hmac: Buffer.alloc(32, seq),
      created_at: new Date(1700000000000 + seq * 1000),
    };
  }

  it('implements AuditQueryStore', () => {
    const pool = makeQueryPool([]);
    const store: AuditQueryStore = new PostgresAuditQueryStore(pool);
    expect(typeof store.queryEntries).toBe('function');
  });

  it('returns all rows when no filter is applied', async () => {
    const rows = [makeRow(1), makeRow(2), makeRow(3)];
    const pool = makeQueryPool(rows);
    const store = new PostgresAuditQueryStore(pool);

    const result = await store.queryEntries({}, { limit: 10 });
    expect(result.entries).toHaveLength(3);
    expect(result.nextCursor).toBeUndefined();
  });

  it('returns an empty result when the table is empty', async () => {
    const pool = makeQueryPool([]);
    const store = new PostgresAuditQueryStore(pool);

    const result = await store.queryEntries({}, {});
    expect(result.entries).toHaveLength(0);
    expect(result.nextCursor).toBeUndefined();
  });

  it('filters by tenantId via JSONB predicate', async () => {
    const rows = [
      makeRow(1, { tenantId: 'tenant-A' }),
      makeRow(2, { tenantId: 'tenant-B' }),
      makeRow(3, { tenantId: 'tenant-A' }),
    ];
    const pool = makeQueryPool(rows);
    const store = new PostgresAuditQueryStore(pool);

    const result = await store.queryEntries({ tenantId: 'tenant-A' }, { limit: 10 });
    expect(result.entries).toHaveLength(2);
    for (const e of result.entries) {
      expect(e.signedEvidence.tenantId).toBe('tenant-A');
    }
  });

  it('filters by decision via JSONB predicate', async () => {
    const rows = [
      makeRow(1, { decision: 'allow' }),
      makeRow(2, { decision: 'deny' }),
      makeRow(3, { decision: 'allow' }),
    ];
    const pool = makeQueryPool(rows);
    const store = new PostgresAuditQueryStore(pool);

    const result = await store.queryEntries({ decision: 'deny' }, { limit: 10 });
    expect(result.entries).toHaveLength(1);
    expect(result.entries[0]!.signedEvidence.decision).toBe('deny');
  });

  it('filters by agentId via JSONB predicate', async () => {
    const rows = [
      makeRow(1, { agentId: 'agent-X' }),
      makeRow(2, { agentId: 'agent-Y' }),
    ];
    const pool = makeQueryPool(rows);
    const store = new PostgresAuditQueryStore(pool);

    const result = await store.queryEntries({ agentId: 'agent-X' }, { limit: 10 });
    expect(result.entries).toHaveLength(1);
    expect(result.entries[0]!.signedEvidence.agentId).toBe('agent-X');
  });

  it('filters by denialCode via JSONB predicate', async () => {
    const rows = [
      makeRow(1, { decision: 'deny', denialCode: 'QUOTA_EXCEEDED' }),
      makeRow(2, { decision: 'allow' }),
      makeRow(3, { decision: 'deny', denialCode: 'CONDITION_FAILED' }),
    ];
    const pool = makeQueryPool(rows);
    const store = new PostgresAuditQueryStore(pool);

    const result = await store.queryEntries({ denialCode: 'QUOTA_EXCEEDED' }, { limit: 10 });
    expect(result.entries).toHaveLength(1);
  });

  it('filters by jti (capabilityId) via JSONB predicate', async () => {
    const rows = [
      makeRow(1, { capabilityId: 'cap-abc' }),
      makeRow(2, { capabilityId: 'cap-xyz' }),
    ];
    const pool = makeQueryPool(rows);
    const store = new PostgresAuditQueryStore(pool);

    const result = await store.queryEntries({ jti: 'cap-abc' }, { limit: 10 });
    expect(result.entries).toHaveLength(1);
    expect(result.entries[0]!.signedEvidence.capabilityId).toBe('cap-abc');
  });

  it('returns nextCursor when there are more rows than limit', async () => {
    const rows = [makeRow(1), makeRow(2), makeRow(3)];
    const pool = makeQueryPool(rows);
    const store = new PostgresAuditQueryStore(pool);

    // limit=2 fetches limit+1=3 rows; 3 rows available → hasMore=true → cursor='2'
    const result = await store.queryEntries({}, { limit: 2 });
    expect(result.entries).toHaveLength(2);
    expect(result.nextCursor).toBe('2');
  });

  it('returns undefined nextCursor when the last page is reached', async () => {
    const rows = [makeRow(1), makeRow(2)];
    const pool = makeQueryPool(rows);
    const store = new PostgresAuditQueryStore(pool);

    const result = await store.queryEntries({}, { limit: 10 });
    expect(result.entries).toHaveLength(2);
    expect(result.nextCursor).toBeUndefined();
  });

  it('returns results in ascending order by default', async () => {
    const rows = [makeRow(1), makeRow(2), makeRow(3)];
    const pool = makeQueryPool(rows);
    const store = new PostgresAuditQueryStore(pool);

    const result = await store.queryEntries({}, { limit: 10, direction: 'asc' });
    const seqs = result.entries.map((e) => e.seq);
    expect(seqs).toEqual([1, 2, 3]);
  });

  it('returns results in descending order when direction=desc', async () => {
    const rows = [makeRow(1), makeRow(2), makeRow(3)];
    const pool = makeQueryPool(rows);
    const store = new PostgresAuditQueryStore(pool);

    const result = await store.queryEntries({}, { limit: 10, direction: 'desc' });
    const seqs = result.entries.map((e) => e.seq);
    expect(seqs).toEqual([3, 2, 1]);
  });

  it('respects a cursor in ascending mode (returns entries after the cursor seq)', async () => {
    const rows = [makeRow(1), makeRow(2), makeRow(3), makeRow(4)];
    const pool = makeQueryPool(rows);
    const store = new PostgresAuditQueryStore(pool);

    // cursor='2' in asc mode → only seq > 2
    const result = await store.queryEntries({}, { limit: 10, direction: 'asc', cursor: '2' });
    const seqs = result.entries.map((e) => e.seq);
    expect(seqs).toEqual([3, 4]);
  });

  it('caps result count at LEDGER_QUERY_MAX_LIMIT (1000) even when a higher limit is requested', async () => {
    // Build more than 1000 rows to exceed the cap.
    const rows = Array.from({ length: 1002 }, (_, i) => makeRow(i + 1));
    const pool = makeQueryPool(rows);
    const store = new PostgresAuditQueryStore(pool);

    // Requesting more than the hard cap should be silently clamped.
    const result = await store.queryEntries({}, { limit: 5000 });
    expect(result.entries.length).toBeLessThanOrEqual(1000);
  });

  it('uses the custom table name supplied in options', async () => {
    const capturedSql: string[] = [];
    const pool: PgPool = {
      connect: () => Promise.resolve({
        query<R extends Record<string, unknown>>(sql: string): Promise<PgQueryResult<R>> {
          capturedSql.push(sql);
          return Promise.resolve({ rows: [], rowCount: 0 }) as unknown as Promise<PgQueryResult<R>>;
        },
        release() { /* no-op */ },
      }),
      end: () => Promise.resolve(),
    };

    const store = new PostgresAuditQueryStore(pool, { table: 'audit.custom_table' });
    await store.queryEntries({}, {});

    expect(capturedSql.some((s) => s.includes('audit.custom_table'))).toBe(true);
  });

  it('does not carry chain state, HMAC material, or advisory lock operations', async () => {
    const capturedSql: string[] = [];
    const pool: PgPool = {
      connect: () => Promise.resolve({
        query<R extends Record<string, unknown>>(sql: string): Promise<PgQueryResult<R>> {
          capturedSql.push(sql.trim().toUpperCase());
          return Promise.resolve({ rows: [], rowCount: 0 }) as unknown as Promise<PgQueryResult<R>>;
        },
        release() { /* no-op */ },
      }),
      end: () => Promise.resolve(),
    };

    const store = new PostgresAuditQueryStore(pool);
    await store.queryEntries({}, {});

    // Must not issue BEGIN/COMMIT/ROLLBACK (no transaction needed for a plain SELECT).
    expect(capturedSql).not.toContain('BEGIN');
    expect(capturedSql).not.toContain('COMMIT');
    // Must not acquire advisory locks.
    expect(capturedSql.some((s) => s.includes('PG_ADVISORY'))).toBe(false);
    // Must issue exactly one SELECT.
    expect(capturedSql.filter((s) => s.startsWith('SELECT')).length).toBe(1);
  });

  it('delegates close() to pool.end()', async () => {
    const rows: never[] = [];
    const rawPool = makeQueryPool(rows);
    // Access the `closed` state via Object.defineProperty so the getter closure
    // is correctly propagated (Object.assign copies values, not getters).
    let _closed = false;
    const origEnd = rawPool.end.bind(rawPool);
    const pool: typeof rawPool & { readonly closed: boolean } = Object.defineProperty(
      Object.assign(rawPool, {
        async end() { await origEnd(); _closed = true; },
      }),
      'closed',
      { get: () => _closed, enumerable: true },
    ) as typeof rawPool & { readonly closed: boolean };

    const store = new PostgresAuditQueryStore(pool);
    expect(pool.closed).toBe(false);
    await store.close!();
    expect(pool.closed).toBe(true);
  });

  it('ignores a malformed cursor (partial-numeric like "10abc") instead of silently truncating', async () => {
    // Before the strict-parse fix, parseInt("10abc", 10) → 10, which would
    // silently apply a seq > 10 predicate. Now parseCursorSeq rejects non-all-digit
    // strings, so the cursor condition is omitted and all rows are returned.
    const rows = [makeRow(1), makeRow(2), makeRow(3)];
    const capturedParams: unknown[][] = [];
    const pool: PgPool = {
      connect: () => Promise.resolve({
        query<R extends Record<string, unknown>>(_sql: string, params: unknown[]): Promise<PgQueryResult<R>> {
          capturedParams.push(params);
          return Promise.resolve({ rows: rows as unknown as R[], rowCount: rows.length }) as unknown as Promise<PgQueryResult<R>>;
        },
        release() { /* no-op */ },
      }),
      end: () => Promise.resolve(),
    };
    const store = new PostgresAuditQueryStore(pool);
    await store.queryEntries({}, { cursor: '10abc' });

    // None of the captured params should equal 10 (the would-be truncated cursor seq).
    const allParams = capturedParams.flat();
    expect(allParams).not.toContain(10);
  });

  it('rejects an invalid table name with a PostgresAuditQueryStore-prefixed error', () => {
    const pool = makeQueryPool([]);
    expect(() => new PostgresAuditQueryStore(pool, { table: 'bad name; DROP TABLE x' })).toThrow(
      /PostgresAuditQueryStore/,
    );
  });
});
