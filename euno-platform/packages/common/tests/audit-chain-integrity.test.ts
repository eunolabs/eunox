/**
 * Tests for audit chain integrity:
 *   - Hash-chain linkage in AuditEvidenceSigner (previousHash / seq)
 *   - Concurrent serialisation of signEvidence calls
 *   - computeMerkleRoot (correctness, empty input, odd-length levels)
 *   - AuditPipeline Merkle batch commitment emission (signBatch / onBatch /
 *     anchors / verifyBatchChain)
 *   - verifyChain / verifyBatchChain helpers
 */

import * as crypto from 'crypto';
import {
  AuditEvidenceSigner,
  createAuditEvidence,
  createSoftwareEvidenceSigner,
  hashSignedRecord,
  hashBatchCommitment,
  verifyChain,
  verifyBatchChain,
  GENESIS_HASH,
} from '../src/evidence';
import {
  computeMerkleRoot,
  MERKLE_EMPTY_ROOT,
} from '../src/utils';
import {
  createAuditPipeline,
} from '../src/audit-pipeline';
import {
  AuditEvidence,
  SignedAuditEvidence,
  SignedBatchCommitment,
  AuditBatchCommitment,
} from '../src/wire';
import { EvidenceSigner, AuditBatchSigner, AuditAnchor } from '../src/runtime';

// ──────────────────────────────────────────────────────────────────────────
// Test helpers
// ──────────────────────────────────────────────────────────────────────────

/**
 * Builds a real RSA-backed AuditEvidenceSigner (used by all the chain tests so
 * verifyEvidence calls exercise the actual cryptographic path).
 */
function makeRsaSigner(chainSeed?: { previousHash: string; seq: number }): AuditEvidenceSigner {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
  return createSoftwareEvidenceSigner({ privateKeyPem: privatePem, publicKeyPem: publicPem, chainSeed });
}

function makeEvidence(overrides?: Partial<Parameters<typeof createAuditEvidence>[0]>): AuditEvidence {
  return createAuditEvidence({
    sessionId: 'sess-1',
    userId: 'user-1',
    prompt: 'test prompt',
    tool: 'test_tool',
    args: { key: 'value' },
    agentId: 'agent-1',
    resource: 'tool://test',
    action: 'read',
    capabilityId: 'cap-1',
    decision: 'allow',
    policyVersion: '1.0.0',
    ...overrides,
  });
}

// A minimal EvidenceSigner that delegates to AuditEvidenceSigner and also
// exposes signBatch for pipeline tests.
class FullSigner implements EvidenceSigner, AuditBatchSigner {
  private inner: AuditEvidenceSigner;

  constructor(inner?: AuditEvidenceSigner) {
    this.inner = inner ?? makeRsaSigner();
  }

  async signEvidence(e: AuditEvidence): Promise<SignedAuditEvidence> {
    return this.inner.signEvidence(e);
  }
  async verifyEvidence(s: SignedAuditEvidence): Promise<boolean> {
    return this.inner.verifyEvidence(s);
  }
  async signBatch(c: AuditBatchCommitment): Promise<SignedBatchCommitment> {
    return this.inner.signBatch(c);
  }
}

// ──────────────────────────────────────────────────────────────────────────
// 1. Hash-chain linkage in AuditEvidenceSigner
// ──────────────────────────────────────────────────────────────────────────

describe('AuditEvidenceSigner — hash-chain linkage', () => {
  it('first record has previousHash=GENESIS_HASH and seq=1', async () => {
    const signer = makeRsaSigner();
    const signed = await signer.signEvidence(makeEvidence());
    expect(signed.previousHash).toBe(GENESIS_HASH);
    expect(signed.seq).toBe(1);
  });

  it('second record previousHash equals canonicalSha256 of first', async () => {
    const signer = makeRsaSigner();
    const first = await signer.signEvidence(makeEvidence());
    const second = await signer.signEvidence(makeEvidence());
    expect(second.previousHash).toBe(hashSignedRecord(first));
    expect(second.seq).toBe(2);
  });

  it('chain of N records passes verifyChain', async () => {
    const signer = makeRsaSigner();
    const records: SignedAuditEvidence[] = [];
    for (let i = 0; i < 5; i++) {
      records.push(await signer.signEvidence(makeEvidence()));
    }
    expect(verifyChain(records)).toBe(true);
  });

  it('tampered previousHash breaks verifyChain', async () => {
    const signer = makeRsaSigner();
    const r0 = await signer.signEvidence(makeEvidence());
    const r1 = await signer.signEvidence(makeEvidence());
    const tampered = { ...r1, previousHash: 'aaaa' + r1.previousHash.slice(4) };
    expect(verifyChain([r0, tampered])).toBe(false);
  });

  it('dropped record (seq gap) breaks verifyChain', async () => {
    const signer = makeRsaSigner();
    const r0 = await signer.signEvidence(makeEvidence());
    await signer.signEvidence(makeEvidence()); // intentionally dropped from the slice passed to verifyChain
    const r2 = await signer.signEvidence(makeEvidence());
    expect(verifyChain([r0, r2])).toBe(false);
  });

  it('verifyChain with empty array returns true', () => {
    expect(verifyChain([])).toBe(true);
  });

  it('verifyChain with single record and matching seed returns true', async () => {
    const signer = makeRsaSigner();
    const r0 = await signer.signEvidence(makeEvidence());
    expect(verifyChain([r0], GENESIS_HASH)).toBe(true);
  });

  it('per-record signature still verifies after chain fields are added', async () => {
    const signer = makeRsaSigner();
    const signed = await signer.signEvidence(makeEvidence());
    expect(await signer.verifyEvidence(signed)).toBe(true);
  });

  it('tampered previousHash invalidates signature', async () => {
    const signer = makeRsaSigner();
    const signed = await signer.signEvidence(makeEvidence());
    const tampered = { ...signed, previousHash: GENESIS_HASH.replace(/0/g, '1') };
    expect(await signer.verifyEvidence(tampered)).toBe(false);
  });

  it('tampered seq invalidates signature', async () => {
    const signer = makeRsaSigner();
    const signed = await signer.signEvidence(makeEvidence());
    const tampered = { ...signed, seq: signed.seq + 99 };
    expect(await signer.verifyEvidence(tampered)).toBe(false);
  });

  it('record missing previousHash fails verification', async () => {
    const signer = makeRsaSigner();
    const signed = await signer.signEvidence(makeEvidence());
    const stripped = { ...signed, previousHash: '' };
    expect(await signer.verifyEvidence(stripped)).toBe(false);
  });

  it('record missing seq fails verification', async () => {
    const signer = makeRsaSigner();
    const signed = await signer.signEvidence(makeEvidence());
    const stripped = { ...signed, seq: undefined } as unknown as SignedAuditEvidence;
    expect(await signer.verifyEvidence(stripped)).toBe(false);
  });

  it('getChainState reflects last signed record', async () => {
    const signer = makeRsaSigner();
    const r0 = await signer.signEvidence(makeEvidence());
    const r1 = await signer.signEvidence(makeEvidence());
    const state = signer.getChainState();
    expect(state.seq).toBe(2);
    expect(state.previousHash).toBe(hashSignedRecord(r1));
    // Also sanity-check: r1.previousHash === hash of r0
    expect(r1.previousHash).toBe(hashSignedRecord(r0));
  });

  it('chainSeed resumes the chain with the correct previousHash', async () => {
    const signer = makeRsaSigner();
    const r0 = await signer.signEvidence(makeEvidence());
    const state = signer.getChainState();

    // New signer instance seeded from the previous run's terminal state
    const signer2 = makeRsaSigner(state);
    const r1 = await signer2.signEvidence(makeEvidence());

    expect(r1.previousHash).toBe(hashSignedRecord(r0));
    expect(r1.seq).toBe(2);
    // The joint chain [r0, r1] must verify
    expect(verifyChain([r0, r1])).toBe(true);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// 2. Concurrent serialisation
// ──────────────────────────────────────────────────────────────────────────

describe('AuditEvidenceSigner — concurrent safety', () => {
  it('10 concurrent signEvidence calls produce a valid chain (no seq gaps / collisions)', async () => {
    const signer = makeRsaSigner();
    const records = await Promise.all(
      Array.from({ length: 10 }, () => signer.signEvidence(makeEvidence())),
    );
    // Sort by seq so we can verify the chain regardless of Promise resolution order
    records.sort((a, b) => a.seq - b.seq);
    // All seq values must be distinct and consecutive
    const seqs = records.map((r) => r.seq);
    expect(seqs).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    // The chain must be valid (each previousHash links correctly)
    expect(verifyChain(records)).toBe(true);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// 3. computeMerkleRoot
// ──────────────────────────────────────────────────────────────────────────

describe('computeMerkleRoot', () => {
  const leaf = (n: number) =>
    crypto.createHash('sha256').update(String(n)).digest('hex');

  it('empty array returns MERKLE_EMPTY_ROOT', () => {
    expect(computeMerkleRoot([])).toBe(MERKLE_EMPTY_ROOT);
  });

  it('single leaf returns the leaf itself', () => {
    const h = leaf(1);
    expect(computeMerkleRoot([h])).toBe(h);
  });

  it('two leaves produce a deterministic root', () => {
    const h0 = leaf(0);
    const h1 = leaf(1);
    const expected = crypto
      .createHash('sha256')
      .update(h0 + h1, 'utf8')
      .digest('hex');
    expect(computeMerkleRoot([h0, h1])).toBe(expected);
  });

  it('odd-length input duplicates last node at each odd level', () => {
    // Three leaves: [l0, l1, l2].
    // Level 1: [H(l0||l1), H(l2||l2)]
    // Level 2: [H(H(l0||l1) || H(l2||l2))]
    const h = (s: string) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
    const l0 = leaf(0);
    const l1 = leaf(1);
    const l2 = leaf(2);
    const lvl1a = h(l0 + l1);
    const lvl1b = h(l2 + l2);
    const root = h(lvl1a + lvl1b);
    expect(computeMerkleRoot([l0, l1, l2])).toBe(root);
  });

  it('result is stable for the same inputs in the same order', () => {
    const leaves = [leaf(1), leaf(2), leaf(3), leaf(4)];
    const r1 = computeMerkleRoot(leaves);
    const r2 = computeMerkleRoot(leaves);
    expect(r1).toBe(r2);
  });

  it('changing one leaf changes the root', () => {
    const leaves = [leaf(1), leaf(2), leaf(3)];
    const r1 = computeMerkleRoot(leaves);
    const mutated = [leaf(1), leaf(99), leaf(3)];
    const r2 = computeMerkleRoot(mutated);
    expect(r1).not.toBe(r2);
  });

  it('rejects leaf hashes that are not 64-character lowercase hex', () => {
    expect(() => computeMerkleRoot(['short'])).toThrow('64-character lowercase hex');
    expect(() => computeMerkleRoot(['zz' + leaf(0).slice(2)])).toThrow('64-character lowercase hex');
  });
});

// ──────────────────────────────────────────────────────────────────────────
// 4. AuditEvidenceSigner.signBatch / verifyBatch
// ──────────────────────────────────────────────────────────────────────────

describe('AuditEvidenceSigner — signBatch / verifyBatch', () => {
  it('signBatch produces a SignedBatchCommitment with a valid signature', async () => {
    const signer = makeRsaSigner();
    const r0 = await signer.signEvidence(makeEvidence());
    const commitment: AuditBatchCommitment = {
      batchId: 'b1',
      replicaId: 'pod-0',
      batchSeq: 1,
      previousBatchHash: GENESIS_HASH,
      merkleRoot: computeMerkleRoot([hashSignedRecord(r0)]),
      recordCount: 1,
      firstSeq: r0.seq,
      lastSeq: r0.seq,
      ts: new Date().toISOString(),
    };
    const signed = await signer.signBatch(commitment);
    expect(signed.signature).toBeTruthy();
    expect(signed.keyId).toBeTruthy();
    expect(signed.algorithm).toBeTruthy();
    expect(await signer.verifyBatch(signed)).toBe(true);
  });

  it('tampered Merkle root invalidates batch signature', async () => {
    const signer = makeRsaSigner();
    const r0 = await signer.signEvidence(makeEvidence());
    const commitment: AuditBatchCommitment = {
      batchId: 'b1',
      replicaId: 'pod-0',
      batchSeq: 1,
      previousBatchHash: GENESIS_HASH,
      merkleRoot: computeMerkleRoot([hashSignedRecord(r0)]),
      recordCount: 1,
      firstSeq: r0.seq,
      lastSeq: r0.seq,
      ts: new Date().toISOString(),
    };
    const signed = await signer.signBatch(commitment);
    const tampered = { ...signed, merkleRoot: signed.merkleRoot.replace(/a/g, 'b') };
    expect(await signer.verifyBatch(tampered)).toBe(false);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// 5. AuditPipeline Merkle batch commitment emission
// ──────────────────────────────────────────────────────────────────────────

describe('AuditPipeline — batch commitments', () => {
  /**
   * Wait until the pipeline has emitted at least `minBatches` batch
   * commitments (or timeout after `ms`). The pipeline uses microtask
   * scheduling so we poll with setImmediate-style yields.
   */
  async function waitForBatches(
    batches: SignedBatchCommitment[],
    minBatches: number,
    ms = 2000,
  ): Promise<void> {
    const deadline = Date.now() + ms;
    while (batches.length < minBatches && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 10));
    }
    if (batches.length < minBatches) {
      throw new Error(`Timed out waiting for ${minBatches} batches; got ${batches.length}`);
    }
  }

  it('emits a batch commitment after signing records', async () => {
    const signer = new FullSigner();
    const batches: SignedBatchCommitment[] = [];

    const pipeline = createAuditPipeline({
      signer,
      batchSigner: signer,
      replicaId: 'test-replica',
      maxSize: 16,
      workers: 1,
      maxBatchSize: 8,
      onBatch: (b) => batches.push(b),
    });

    const e1 = makeEvidence();
    const e2 = makeEvidence();
    void pipeline.enqueue(e1);
    void pipeline.enqueue(e2);

    await waitForBatches(batches, 1);
    await pipeline.drain(1000);

    expect(batches.length).toBeGreaterThanOrEqual(1);
    const b = batches[0]!;
    expect(b.replicaId).toBe('test-replica');
    expect(b.recordCount).toBeGreaterThanOrEqual(1);
    expect(b.merkleRoot).toHaveLength(64);
    expect(b.batchSeq).toBe(1);
    expect(b.previousBatchHash).toBe(GENESIS_HASH);
    // Batch chain: first batch's previous = GENESIS_HASH ✓
  });

  it('batch commitment Merkle root covers the signed records', async () => {
    const signer = new FullSigner();
    const signedRecords: SignedAuditEvidence[] = [];
    const batches: SignedBatchCommitment[] = [];

    const pipeline = createAuditPipeline({
      signer,
      batchSigner: signer,
      replicaId: 'merkle-test',
      maxSize: 16,
      workers: 1,
      maxBatchSize: 16,
      onSigned: (r) => signedRecords.push(r),
      onBatch: (b) => batches.push(b),
    });

    for (let i = 0; i < 4; i++) {
      void pipeline.enqueue(makeEvidence());
    }

    await waitForBatches(batches, 1);
    await pipeline.drain(1000);

    const b = batches[0]!;
    const leafHashes = signedRecords.slice(0, b.recordCount).map(hashSignedRecord);
    const expected = computeMerkleRoot(leafHashes);
    expect(b.merkleRoot).toBe(expected);
  });

  it('successive batches form a valid batch chain (previousBatchHash linkage)', async () => {
    // Use maxBatchSize=1 so each record triggers a separate drain cycle and
    // thus a separate batch commitment.
    const signer = new FullSigner();
    const batches: SignedBatchCommitment[] = [];

    const pipeline = createAuditPipeline({
      signer,
      batchSigner: signer,
      replicaId: 'chain-test',
      maxSize: 32,
      workers: 1,
      maxBatchSize: 1,
      onBatch: (b) => batches.push(b),
    });

    for (let i = 0; i < 3; i++) {
      void pipeline.enqueue(makeEvidence());
    }

    await waitForBatches(batches, 3);
    await pipeline.drain(1000);

    expect(batches.length).toBeGreaterThanOrEqual(3);
    expect(verifyBatchChain(batches.slice(0, 3))).toBe(true);
  });

  it('batch commitment is published to registered anchors', async () => {
    const signer = new FullSigner();
    const anchored: SignedBatchCommitment[] = [];
    const anchor: AuditAnchor = {
      name: 'test',
      async anchorBatch(c: SignedBatchCommitment): Promise<void> {
        anchored.push(c);
      },
    };

    const pipeline = createAuditPipeline({
      signer,
      batchSigner: signer,
      replicaId: 'anchor-test',
      maxSize: 16,
      workers: 1,
      maxBatchSize: 16,
      anchors: [anchor],
    });

    void pipeline.enqueue(makeEvidence());
    // Give the pipeline time to process
    await new Promise((r) => setTimeout(r, 200));
    await pipeline.drain(1000);

    expect(anchored.length).toBeGreaterThanOrEqual(1);
    expect(anchored[0]!.signature).toBeTruthy();
  });

  it('anchor failure does not crash the pipeline and is reported via onBatchError', async () => {
    const signer = new FullSigner();
    const successfulAnchors: SignedBatchCommitment[] = [];
    const batchErrors: unknown[] = [];
    const anchors: AuditAnchor[] = [
      {
        name: 'failing',
        async anchorBatch(): Promise<void> {
          throw new Error('anchor failure');
        },
      },
      {
        name: 'succeeding',
        async anchorBatch(c: SignedBatchCommitment): Promise<void> {
          successfulAnchors.push(c);
        },
      },
    ];

    const pipeline = createAuditPipeline({
      signer,
      batchSigner: signer,
      replicaId: 'anchor-failure-test',
      maxSize: 16,
      workers: 1,
      maxBatchSize: 16,
      anchors,
      onBatchError: (err) => batchErrors.push(err),
    });

    void pipeline.enqueue(makeEvidence());
    await new Promise((r) => setTimeout(r, 200));
    await pipeline.drain(1000);

    // The succeeding anchor should still receive the commitment despite the
    // failing anchor throwing (anchors run concurrently via Promise.allSettled).
    expect(successfulAnchors.length).toBeGreaterThanOrEqual(1);
    // The failing anchor's error must be routed to onBatchError.
    expect(batchErrors.length).toBeGreaterThanOrEqual(1);
    expect(String(batchErrors[0])).toContain('failing');
  });

  it('pipeline without batchSigner emits unsigned commitment with empty signature', async () => {
    const signer = new FullSigner();
    const batches: SignedBatchCommitment[] = [];

    const pipeline = createAuditPipeline({
      signer,
      // No batchSigner: unsigned commitments
      replicaId: 'unsigned-test',
      maxSize: 16,
      workers: 1,
      maxBatchSize: 16,
      onBatch: (b) => batches.push(b),
    });

    void pipeline.enqueue(makeEvidence());
    await new Promise((r) => setTimeout(r, 200));
    await pipeline.drain(1000);

    expect(batches.length).toBeGreaterThanOrEqual(1);
    expect(batches[0]!.signature).toBe('');
    expect(batches[0]!.keyId).toBe('');
    expect(batches[0]!.merkleRoot).toHaveLength(64);
  });

  it('concurrent workers (workers > 1) produce a valid gapless batch chain', async () => {
    // Use 4 workers and a small batch size so multiple workers may interleave
    // at the signBatch await inside doEmitBatchCommitment. The serialization
    // lock (batchChainTail) must keep batchSeq + previousBatchHash correct.
    const signer = new FullSigner();
    const batches: SignedBatchCommitment[] = [];

    const pipeline = createAuditPipeline({
      signer,
      batchSigner: signer,
      replicaId: 'concurrent-batch-test',
      maxSize: 64,
      workers: 4,
      maxBatchSize: 2,
      onBatch: (b) => batches.push(b),
    });

    const RECORD_COUNT = 12;
    for (let i = 0; i < RECORD_COUNT; i++) {
      void pipeline.enqueue(makeEvidence());
    }

    // Wait until we have seen at least 2 batch commitments, then drain.
    await waitForBatches(batches, 2, 5000);
    await pipeline.drain(3000);

    expect(batches.length).toBeGreaterThanOrEqual(2);
    // Sort by batchSeq (onBatch callbacks may arrive out of order due to
    // concurrent signing).
    const sorted = [...batches].sort((a, b) => a.batchSeq - b.batchSeq);
    // batchSeq values must be consecutive starting at 1.
    expect(sorted[0]!.batchSeq).toBe(1);
    for (let i = 1; i < sorted.length; i++) {
      expect(sorted[i]!.batchSeq).toBe(sorted[i - 1]!.batchSeq + 1);
    }
    // The batch chain must be fully linked.
    expect(verifyBatchChain(sorted)).toBe(true);
  });
});

// ──────────────────────────────────────────────────────────────────────────
// 6. verifyBatchChain
// ──────────────────────────────────────────────────────────────────────────

describe('verifyBatchChain', () => {
  function makeBatch(seq: number, prevHash: string): SignedBatchCommitment {
    const merkleRoot = computeMerkleRoot([
      crypto.createHash('sha256').update(String(seq)).digest('hex'),
    ]);
    const commitment: AuditBatchCommitment = {
      batchId: `batch-${seq}`,
      replicaId: 'test',
      batchSeq: seq,
      previousBatchHash: prevHash,
      merkleRoot,
      recordCount: 1,
      firstSeq: seq,
      lastSeq: seq,
      ts: new Date().toISOString(),
    };
    return {
      ...commitment,
      signature: 'sig',
      keyId: 'k1',
      algorithm: 'RS256',
    } as SignedBatchCommitment;
  }

  it('empty array returns true', () => {
    expect(verifyBatchChain([])).toBe(true);
  });

  it('single batch with GENESIS_HASH seed returns true', () => {
    const b = makeBatch(1, GENESIS_HASH);
    expect(verifyBatchChain([b], GENESIS_HASH)).toBe(true);
  });

  it('wrong seed returns false', () => {
    const b = makeBatch(1, GENESIS_HASH);
    expect(verifyBatchChain([b], 'aaaa' + GENESIS_HASH.slice(4))).toBe(false);
  });

  it('tampered batchSeq returns false', () => {
    const b1 = makeBatch(1, GENESIS_HASH);
    const b2 = makeBatch(2, hashBatchCommitment(b1));
    const tampered = { ...b2, batchSeq: 5 };
    expect(verifyBatchChain([b1, tampered])).toBe(false);
  });
});
