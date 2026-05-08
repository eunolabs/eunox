/**
 * Tests for AuditEvidenceSigner.verifyBatch – including a regression test that
 * exercises a class-based CryptoSigner whose verifyDigest reads instance state
 * via `this`, covering the bug where `verifyDigest` was called without its
 * owning `this` context.
 */

import * as crypto from 'crypto';
import { AuditEvidenceSigner, CryptoSigner, hashBatchCommitment } from '../evidence';
import { AuditBatchCommitment, GENESIS_HASH } from '../wire';

/**
 * Class-based CryptoSigner that reads instance state in both `signDigest` and
 * `verifyDigest`.  Any invocation without the correct `this` binding (e.g. via
 * a detached method reference) would throw or return wrong results.
 */
class StatefulRsaSigner implements CryptoSigner {
  private readonly privateKey: crypto.KeyObject;
  private readonly publicKey: crypto.KeyObject;
  private readonly _keyId: string;
  private readonly _algorithm = 'RS256';

  constructor(keyId = 'stateful-key-1') {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this._keyId = keyId;
  }

  async signDigest(digest: Buffer): Promise<Buffer> {
    // Reads this.privateKey — would throw on a detached call.
    return crypto.sign(null, digest, { key: this.privateKey });
  }

  async verifyDigest(
    digest: Buffer,
    signature: Buffer,
    keyId: string,
    _algorithm: string,
  ): Promise<boolean> {
    // Reads this.publicKey and this._keyId — would throw / return wrong
    // results on a detached call.
    if (keyId !== this._keyId) {
      return false;
    }
    return crypto.verify(null, digest, { key: this.publicKey }, signature);
  }

  async getKeyId(): Promise<string> {
    return this._keyId;
  }

  getAlgorithm(): string {
    return this._algorithm;
  }
}

function makeBatchCommitment(overrides: Partial<AuditBatchCommitment> = {}): AuditBatchCommitment {
  return {
    batchId: 'batch-1',
    replicaId: 'replica-1',
    batchSeq: 1,
    previousBatchHash: GENESIS_HASH,
    merkleRoot: 'a'.repeat(64),
    recordCount: 3,
    firstSeq: 1,
    lastSeq: 3,
    ts: new Date().toISOString(),
    ...overrides,
  };
}

describe('AuditEvidenceSigner.verifyBatch', () => {
  it('round-trips: signed batch commitment verifies with a class-based signer that reads this', async () => {
    // StatefulRsaSigner reads `this.publicKey` and `this._keyId` in verifyDigest.
    // If verifyDigest were invoked without the correct `this` context it would
    // throw (or read undefined fields), causing verifyBatch to return false.
    const signer = new AuditEvidenceSigner(new StatefulRsaSigner());
    const commitment = makeBatchCommitment();
    const signed = await signer.signBatch(commitment);

    expect(signed.signature).toBeTruthy();
    expect(signed.keyId).toBe('stateful-key-1');
    expect(await signer.verifyBatch(signed)).toBe(true);
  });

  it('rejects a tampered batch commitment', async () => {
    const signer = new AuditEvidenceSigner(new StatefulRsaSigner());
    const signed = await signer.signBatch(makeBatchCommitment());
    expect(await signer.verifyBatch({ ...signed, recordCount: signed.recordCount + 1 })).toBe(false);
  });

  it('rejects a batch commitment with a mismatched keyId', async () => {
    const signer = new AuditEvidenceSigner(new StatefulRsaSigner());
    const signed = await signer.signBatch(makeBatchCommitment());
    expect(await signer.verifyBatch({ ...signed, keyId: 'wrong-key' })).toBe(false);
  });

  it('rejects a batch commitment with a corrupted signature', async () => {
    const signer = new AuditEvidenceSigner(new StatefulRsaSigner());
    const signed = await signer.signBatch(makeBatchCommitment());
    expect(await signer.verifyBatch({ ...signed, signature: Buffer.from('not-a-sig').toString('base64') })).toBe(false);
  });

  it('rejects a batch commitment missing required fields', async () => {
    const signer = new AuditEvidenceSigner(new StatefulRsaSigner());
    const signed = await signer.signBatch(makeBatchCommitment());
    expect(await signer.verifyBatch({ ...signed, signature: '' })).toBe(false);
    expect(await signer.verifyBatch({ ...signed, keyId: '' })).toBe(false);
    expect(await signer.verifyBatch({ ...signed, algorithm: '' })).toBe(false);
  });

  it('fails closed when the signer has no verifyDigest method', async () => {
    // A sign-only signer: no verifyDigest property at all.
    const signOnly: CryptoSigner = {
      async signDigest() { return Buffer.from('fake'); },
      async getKeyId() { return 'sign-only'; },
      getAlgorithm() { return 'RS256'; },
    };
    const signer = new AuditEvidenceSigner(signOnly);
    const signed = await signer.signBatch(makeBatchCommitment());
    expect(await signer.verifyBatch(signed)).toBe(false);
  });

  it('hashBatchCommitment produces a stable hex digest', async () => {
    const signer = new AuditEvidenceSigner(new StatefulRsaSigner());
    const signed = await signer.signBatch(makeBatchCommitment());
    const h1 = hashBatchCommitment(signed);
    const h2 = hashBatchCommitment(signed);
    expect(h1).toBe(h2);
    expect(h1).toMatch(/^[0-9a-f]{64}$/);
  });
});
