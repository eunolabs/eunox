/**
 * Evidence Signer Implementation
 * Creates cryptographically signed audit evidence for tamper-evident records
 */

import * as crypto from 'crypto';
import { AuditEvidence, SignedAuditEvidence, AuditBatchCommitment, SignedBatchCommitment, GENESIS_HASH } from './wire';
import { EvidenceSigner } from './runtime';
import { sha256String, canonicalize, canonicalSha256, generateId } from './utils';

// Re-export GENESIS_HASH so consumers can import it from this module without
// needing to know about the wire/types split.
export { GENESIS_HASH } from './types';

/**
 * Interface for cryptographic signing operations.
 *
 * `verifyDigest` is OPTIONAL.  When provided, {@link AuditEvidenceSigner.verifyEvidence}
 * uses it to perform full cryptographic verification of signed evidence.
 * When absent, verification fails closed: signed records cannot be verified
 * and `verifyEvidence` returns `false`.
 */
export interface CryptoSigner {
  signDigest(digest: Buffer): Promise<Buffer>;
  /**
   * Verify a signature over the supplied digest.  Implementations should
   * resolve the public key for `keyId` (or use the configured key when the
   * signer is bound to a single key) and return `true` only when the signature
   * is valid AND was produced under `algorithm`.  Implementations MUST NOT
   * throw on signature mismatch; throw only on configuration / I/O errors.
   */
  verifyDigest?(digest: Buffer, signature: Buffer, keyId: string, algorithm: string): Promise<boolean>;
  getKeyId(): Promise<string>;
  getAlgorithm(): string;
  /**
   * Return the public key in SPKI PEM format, if available locally.
   *
   * Optional — software signers implement this; KMS-backed signers may leave
   * it `undefined` because the public key must be fetched from the KMS
   * asynchronously. Callers MUST check for `undefined` before use.
   */
  getPublicKeyPem?(): string;
}

/**
 * Evidence signer that creates tamper-evident audit records with per-record
 * hash-chain linkage and Merkle batch commitment support.
 *
 * ### Hash chain
 *
 * Each `signEvidence` call stamps two chain fields onto the record before
 * signing:
 *   - `previousHash` — `canonicalSha256` of the preceding `SignedAuditEvidence`
 *     (or {@link GENESIS_HASH} for the very first record).
 *   - `seq`          — monotonically increasing (1-based) sequence number.
 *
 * Both fields are included in the canonical form that is signed, so tampering
 * with them invalidates the signature. Tampering with any earlier record
 * changes its `canonicalSha256`, which propagates forward through `previousHash`
 * fields and breaks every subsequent signature in the chain.
 *
 * ### Concurrent safety
 *
 * `signEvidence` calls are serialised through an internal promise chain so that
 * the `previousHash`/`seq` state is consistent even when multiple `AuditPipeline`
 * workers call the signer concurrently.
 *
 * ### Batch commitments
 *
 * `signBatch` signs an {@link AuditBatchCommitment} using the same key. The
 * pipeline calls this once per drain cycle, after all per-record signs in that
 * cycle are complete. The resulting {@link SignedBatchCommitment} can be
 * published to an external anchor (object store, SIEM, transparency log).
 *
 * ### Chain seeding across restarts
 *
 * Supply `chainSeed` at construction to resume from the last known chain state
 * (e.g. read from a persistent store after a process restart). Without seeding,
 * each process instance starts a new chain segment beginning at seq=1 with
 * `previousHash=GENESIS_HASH`. Seeding ensures continuity of the hash chain
 * across rolling restarts. The `getChainState()` accessor exposes the current
 * state so operators can persist it.
 *
 * ### Following the Azure security pattern
 * "Logs help you debug. Evidence helps you prove."
 */

// ── Exported canonical-form helpers ──────────────────────────────────────────
//
// These are factored out of AuditEvidenceSigner so that LedgerAuditEvidenceSigner
// (and any other implementation) can produce identical signed records without
// sub-classing or duplicating the canonical-form logic.

/**
 * Produce the canonical pipe-delimited string for a piece of evidence.
 *
 * Fields are ordered deterministically. `keyId`, `algorithm`, `previousHash`,
 * and `seq` are appended so they are **covered by the signature** — any
 * tampering with those fields invalidates the signature.
 *
 * Field positions are stable across versions. Adding new fields would require
 * bumping a schema version; existing signed records would fail under the new
 * canonical form. The current set was chosen to capture all audit-relevant
 * dimensions.
 */
export function canonicalizeEvidenceFields(
  evidence: Partial<AuditEvidence>,
  keyId?: string,
  algorithm?: string,
  previousHash?: string,
  seq?: number,
): string {
  const fields = [
    evidence.id || '',
    evidence.sessionId || '',
    evidence.userId || '',
    evidence.promptHash || '',
    evidence.documentsHash || '',
    evidence.tool || '',
    evidence.argsHash || '',
    evidence.nonce || '',
    evidence.ts || '',
    evidence.policyVersion || '',
    evidence.agentId || '',
    evidence.resource || '',
    evidence.action || '',
    evidence.capabilityId || '',
    evidence.decision || '',
    keyId || '',
    algorithm || '',
    previousHash || '',
    String(seq ?? 0),
  ];
  return fields.join('|');
}

/**
 * Sign a single {@link AuditEvidence} record given an explicit chain state.
 *
 * This is the core signing primitive shared by both {@link AuditEvidenceSigner}
 * (which manages chain state in-process) and {@link LedgerAuditEvidenceSigner}
 * (which reads chain state from an external ledger). Extracting it here
 * avoids duplicating the canonicalization + digest + sign logic.
 *
 * @param evidence      Unsigned evidence record.
 * @param cryptoSigner  Signing primitive.
 * @param previousHash  SHA-256 hex of the preceding signed record (or GENESIS_HASH).
 * @param seq           1-based sequence number assigned by the caller.
 */
export async function signEvidenceWithChain(
  evidence: AuditEvidence,
  cryptoSigner: CryptoSigner,
  previousHash: string,
  seq: number,
): Promise<SignedAuditEvidence> {
  const keyId = await cryptoSigner.getKeyId();
  const algorithm = cryptoSigner.getAlgorithm();
  const canonical = canonicalizeEvidenceFields(evidence, keyId, algorithm, previousHash, seq);
  const digest = crypto.createHash('sha256').update(canonical, 'utf8').digest();
  const signatureBuffer = await cryptoSigner.signDigest(digest);
  return {
    ...evidence,
    signature: signatureBuffer.toString('base64'),
    keyId,
    algorithm,
    previousHash,
    seq,
  };
}

export class AuditEvidenceSigner implements EvidenceSigner {


  private cryptoSigner: CryptoSigner;

  // ── Chain state ─────────────────────────────────────────────────────────
  private chainPreviousHash: string;
  private chainSeq: number;
  /**
   * Serial queue for `signEvidence`. All signing calls are chained on this
   * promise so that chain-state updates (`previousHash`, `seq`) are
   * consistent even when multiple callers invoke `signEvidence` concurrently.
   * The promise always resolves (never rejects) so a failure in one signing
   * call does not prevent subsequent calls from running.
   */
  private chainTail: Promise<unknown> = Promise.resolve();

  /**
   * @param cryptoSigner  Underlying signing primitive.
   * @param chainSeed     Optional chain state to resume from (e.g. persisted
   *                      after a graceful shutdown).  When omitted the chain
   *                      starts fresh: `previousHash=GENESIS_HASH`, `seq=0`.
   */
  constructor(
    cryptoSigner: CryptoSigner,
    chainSeed?: { previousHash: string; seq: number },
  ) {
    this.cryptoSigner = cryptoSigner;
    this.chainPreviousHash = chainSeed?.previousHash ?? GENESIS_HASH;
    this.chainSeq = chainSeed?.seq ?? 0;
  }

  /**
   * Return a snapshot of the current chain state.
   *
   * Operators should persist this on graceful shutdown and supply it as
   * `chainSeed` on the next start to maintain hash-chain continuity across
   * process restarts.
   */
  getChainState(): { previousHash: string; seq: number } {
    return { previousHash: this.chainPreviousHash, seq: this.chainSeq };
  }

  /**
   * Expose the underlying {@link CryptoSigner} so the ledger wiring in
   * `bootstrap.ts` can wrap it in a `LedgerAuditEvidenceSigner` without
   * accessing private fields via unsafe casts.
   */
  getCryptoSigner(): CryptoSigner {
    return this.cryptoSigner;
  }

  /**
   * Sign audit evidence to create a tamper-evident record.
   *
   * The method is concurrency-safe: concurrent calls are serialised through an
   * internal promise chain so `previousHash` and `seq` are always consistent.
   * keyId and algorithm are fetched BEFORE canonicalisation so they are
   * covered by the signature and cannot be modified without detection.
   */
  async signEvidence(evidence: AuditEvidence): Promise<SignedAuditEvidence> {
    // Enqueue this signing operation so chain-state updates are serialised.
    // The wrapper promise captures the resolve/reject pair and chains onto
    // `this.chainTail`.  The tail itself is kept as a never-rejecting
    // promise so a failure here doesn't prevent later calls from running.
    return new Promise<SignedAuditEvidence>((resolve, reject) => {
      this.chainTail = this.chainTail.then(() =>
        this.doSignEvidence(evidence).then(resolve, reject),
      ).catch(() => {
        // Swallow errors from the tail itself so the queue keeps draining.
      });
    });
  }

  /**
   * Internal signing implementation, called exclusively from the serial queue.
   */
  private async doSignEvidence(evidence: AuditEvidence): Promise<SignedAuditEvidence> {
    // Capture and advance the chain state atomically (this method is never
    // called concurrently — all calls are serialised through `chainTail`).
    const previousHash = this.chainPreviousHash;
    const seq = this.chainSeq + 1;

    // Delegate to the exported helper so the canonical form is shared with
    // LedgerAuditEvidenceSigner and any other future implementations.
    const signed = await signEvidenceWithChain(evidence, this.cryptoSigner, previousHash, seq);

    // Advance the chain state: the hash of this signed record becomes the
    // `previousHash` of the next one.
    this.chainPreviousHash = hashSignedRecord(signed);
    this.chainSeq = seq;

    return signed;
  }

  /**
   * Verify a signed evidence record.
   *
   * Performs full cryptographic verification when the underlying
   * {@link CryptoSigner} exposes a `verifyDigest` method:
   *   1. Re-canonicalises the evidence using the signed `keyId`,
   *      `algorithm`, `previousHash`, and `seq` (so any tampering with
   *      those fields invalidates the signature).
   *   2. Hashes the canonical bytes with SHA-256.
   *   3. Asks the signer to verify the supplied signature against the digest.
   *
   * When the signer does NOT implement `verifyDigest` this method fails
   * closed (returns `false`) so callers cannot mistake "verification not
   * possible" for "signature valid".
   *
   * **Note:** this method verifies only the cryptographic signature. To
   * verify hash-chain continuity across a sequence of records (i.e. that
   * each `previousHash` equals the `canonicalSha256` of the preceding
   * record), use {@link verifyChain}.
   */
  async verifyEvidence(signedEvidence: SignedAuditEvidence): Promise<boolean> {
    // Reject malformed signed evidence records early
    const { signature, keyId, algorithm, previousHash, seq, ...evidence } = signedEvidence;
    if (!signature || !keyId || !algorithm) {
      return false;
    }
    // previousHash and seq are required on every signed record produced by
    // this signer. Reject records that lack them so old (pre-chain) records
    // cannot pass verification — they are intentionally not forward-compatible.
    if (!previousHash || typeof seq !== 'number') {
      return false;
    }

    // Ensure a canonical form can be produced
    const canonical = this.canonicalizeEvidence(evidence, keyId, algorithm, previousHash, seq);
    if (!canonical) {
      return false;
    }

    // If the signer cannot verify, fail closed.  The `verifyDigest` capability
    // is optional so existing CryptoSigner implementations remain valid; the
    // tradeoff is that they cannot cryptographically verify their own
    // signatures, only produce them.
    if (typeof this.cryptoSigner.verifyDigest !== 'function') {
      return false;
    }

    let signatureBuffer: Buffer;
    try {
      signatureBuffer = Buffer.from(signature, 'base64');
    } catch {
      return false;
    }

    // Reject obviously-malformed signatures rather than handing them to the
    // crypto provider (which may throw).
    if (signatureBuffer.length === 0) {
      return false;
    }

    const digest = crypto.createHash('sha256').update(canonical, 'utf8').digest();

    try {
      return await this.cryptoSigner.verifyDigest(digest, signatureBuffer, keyId, algorithm);
    } catch {
      // Defensive: any thrown error from the signer is treated as a
      // verification failure rather than propagated, so callers always get a
      // boolean answer and audit pipelines remain robust.
      return false;
    }
  }

  /**
   * Create a canonical pipe-delimited string representation of evidence for signing.
   *
   * Delegates to the exported {@link canonicalizeEvidenceFields} function so
   * both `AuditEvidenceSigner` and external implementations (e.g. the ledger
   * signer) share an identical canonical form.
   */
  private canonicalizeEvidence(
    evidence: Partial<AuditEvidence>,
    keyId?: string,
    algorithm?: string,
    previousHash?: string,
    seq?: number,
  ): string {
    return canonicalizeEvidenceFields(evidence, keyId, algorithm, previousHash, seq);
  }

  /**
   * Sign an {@link AuditBatchCommitment} to produce a {@link SignedBatchCommitment}.
   *
   * The canonical JSON form of the commitment (all fields, sorted keys) is
   * hashed with SHA-256 and signed with the same key used for
   * `signEvidence`. The resulting `SignedBatchCommitment` can be published
   * to an external anchor.
   *
   * Unlike `signEvidence`, `signBatch` does NOT participate in the record
   * chain. The batch commitment chain is maintained by the pipeline
   * (`batchSeq`, `previousBatchHash`), not by the signer.
   */
  async signBatch(commitment: AuditBatchCommitment): Promise<SignedBatchCommitment> {
    const keyId = await this.cryptoSigner.getKeyId();
    const algorithm = this.cryptoSigner.getAlgorithm();

    // Use canonical JSON (sorted keys) so the digest is deterministic across
    // runtimes and cannot be influenced by key-insertion order.
    const canonical = canonicalize(commitment);
    const digest = crypto.createHash('sha256').update(canonical, 'utf8').digest();
    const signatureBuffer = await this.cryptoSigner.signDigest(digest);

    return {
      ...commitment,
      signature: signatureBuffer.toString('base64'),
      keyId,
      algorithm,
    };
  }

  /**
   * Verify a {@link SignedBatchCommitment}.
   *
   * Re-canonicalises the commitment fields (without `signature`, `keyId`,
   * `algorithm`) and verifies the signature. Fails closed when the signer
   * does not implement `verifyDigest`.
   */
  async verifyBatch(signed: SignedBatchCommitment): Promise<boolean> {
    const { signature, keyId, algorithm, ...commitment } = signed;
    if (!signature || !keyId || !algorithm) {
      return false;
    }
    if (typeof this.cryptoSigner.verifyDigest !== 'function') {
      return false;
    }
    let signatureBuffer: Buffer;
    try {
      signatureBuffer = Buffer.from(signature, 'base64');
    } catch {
      return false;
    }
    if (signatureBuffer.length === 0) {
      return false;
    }
    const canonical = canonicalize(commitment);
    const digest = crypto.createHash('sha256').update(canonical, 'utf8').digest();
    try {
      return await this.cryptoSigner.verifyDigest(digest, signatureBuffer, keyId, algorithm);
    } catch {
      return false;
    }
  }
}

/**
 * Compute the canonical SHA-256 hex digest of a `SignedAuditEvidence` record.
 *
 * This is the value stored in the next record's `previousHash` field, forming
 * the tamper-evident hash chain. It is also used as the leaf hash when building
 * the Merkle tree for a batch commitment.
 *
 * Using `canonicalSha256` (sorted-key canonical JSON) ensures the digest is
 * deterministic regardless of property-insertion order.
 */
export function hashSignedRecord(signed: SignedAuditEvidence): string {
  return canonicalSha256(signed);
}

/**
 * Compute the canonical SHA-256 hex digest of a `SignedBatchCommitment`.
 *
 * This is the value stored in the next batch commitment's `previousBatchHash`
 * field, forming the tamper-evident batch chain.
 */
export function hashBatchCommitment(signed: SignedBatchCommitment): string {
  return canonicalSha256(signed);
}

/**
 * Verify that a sequence of `SignedAuditEvidence` records forms a valid
 * hash chain: each record's `previousHash` must equal the `hashSignedRecord`
 * of the preceding record, and `seq` values must be consecutive integers
 * starting from `records[0].seq`.
 *
 * This complements per-record signature verification (which proves each
 * individual record was not tampered with) by proving no records were
 * inserted, deleted, or reordered within the sequence.
 *
 * @param records   Ordered array of signed evidence records. May be empty
 *                  (returns `true`).
 * @param seedHash  Expected `previousHash` of the first record. Pass
 *                  `GENESIS_HASH` when verifying from the start of the chain,
 *                  or the `canonicalSha256` of the last known-good record when
 *                  verifying a tail segment.
 * @returns         `true` if every link is intact; `false` on the first broken link.
 */
export function verifyChain(
  records: SignedAuditEvidence[],
  seedHash: string = GENESIS_HASH,
): boolean {
  if (records.length === 0) {
    return true;
  }
  let expectedPreviousHash = seedHash;
  let expectedSeq = records[0]!.seq;

  for (const record of records) {
    if (record.previousHash !== expectedPreviousHash) {
      return false;
    }
    if (record.seq !== expectedSeq) {
      return false;
    }
    expectedPreviousHash = hashSignedRecord(record);
    expectedSeq += 1;
  }
  return true;
}

/**
 * Verify that a sequence of `SignedBatchCommitment` records forms a valid
 * batch chain: each commitment's `previousBatchHash` must equal the
 * `hashBatchCommitment` of the preceding commitment, and `batchSeq` values
 * must be consecutive integers starting from `batches[0].batchSeq`.
 */
export function verifyBatchChain(
  batches: SignedBatchCommitment[],
  seedHash: string = GENESIS_HASH,
): boolean {
  if (batches.length === 0) {
    return true;
  }
  let expectedPreviousHash = seedHash;
  let expectedSeq = batches[0]!.batchSeq;

  for (const batch of batches) {
    if (batch.previousBatchHash !== expectedPreviousHash) {
      return false;
    }
    if (batch.batchSeq !== expectedSeq) {
      return false;
    }
    expectedPreviousHash = hashBatchCommitment(batch);
    expectedSeq += 1;
  }
  return true;
}

/**
 * Create audit evidence from an action validation event
 */
export function createAuditEvidence(params: {
  sessionId: string;
  userId: string;
  prompt?: string;
  documents?: unknown;
  tool: string;
  args: unknown;
  agentId: string;
  resource: string;
  action: string;
  capabilityId: string;
  decision: 'allow' | 'deny';
  policyVersion: string;
  tenantId?: string;
  conditionType?: string;
  denialCode?: string;
}): AuditEvidence {
  const nonce = generateId();
  const ts = new Date().toISOString();

  return {
    id: generateId(),
    sessionId: params.sessionId,
    userId: params.userId,
    promptHash: params.prompt !== undefined ? sha256String(params.prompt) : sha256String(''),
    documentsHash: params.documents !== undefined ? sha256String(canonicalize(params.documents)) : undefined,
    tool: params.tool,
    argsHash: sha256String(canonicalize(params.args)),
    nonce,
    ts,
    policyVersion: params.policyVersion,
    agentId: params.agentId,
    resource: params.resource,
    action: params.action,
    capabilityId: params.capabilityId,
    decision: params.decision,
    ...(params.tenantId !== undefined ? { tenantId: params.tenantId } : {}),
    ...(params.conditionType !== undefined ? { conditionType: params.conditionType } : {}),
    ...(params.denialCode !== undefined ? { denialCode: params.denialCode } : {}),
  };
}

/**
 * Algorithms supported by the software evidence signer.
 *
 * {@link AuditEvidenceSigner} always pre-computes a SHA-256 digest of the
 * canonical evidence and passes it to {@link CryptoSigner.signDigest}. The
 * software signer therefore restricts itself to JWS algorithms whose
 * underlying hash is SHA-256, plus EdDSA which signs the message bytes
 * directly. RS/PS/ES384/512 would require a different digest size and are
 * rejected at construction so misconfigured deployments fail fast rather
 * than silently producing signatures that no JWS verifier accepts.
 */
const SUPPORTED_ALGORITHMS: ReadonlySet<string> = new Set([
  'RS256',
  'PS256',
  'ES256',
  'EDDSA',
]);

/**
 * Configuration for {@link createSoftwareEvidenceSigner}.
 *
 * Exactly one of `privateKeyPem` / `privateKeyPath` must be supplied;
 * supplying both throws at construction. The matching public key is
 * derived from the private key automatically (used by `verifyEvidence`)
 * but a `publicKeyPem` (or `publicKeyPath`, again mutually exclusive)
 * may be supplied explicitly when, for example, the private key lives in
 * an HSM-backed PEM container with a separate public certificate.
 *
 * The resulting signer keeps signing material strictly in-process — it is
 * suitable for development, CI, and lightweight production deployments
 * where a KMS-backed signer is not available. KMS-backed signers should
 * be supplied directly to `EnforcementEngine` instead.
 */
export interface SoftwareEvidenceSignerConfig {
  privateKeyPem?: string;
  privateKeyPath?: string;
  publicKeyPem?: string;
  publicKeyPath?: string;
  /**
   * Logical key identifier recorded in every signed evidence record.
   * Defaults to `software-key`.
   */
  keyId?: string;
  /**
   * JWS-style algorithm name. Defaults to `RS256`. Must be one of:
   * `RS256`, `PS256`, `ES256`, `EdDSA`. The `*384` / `*512` variants
   * are intentionally unsupported because the audit signer's digest is
   * always SHA-256.
   */
  algorithm?: string;
  /**
   * Optional chain seed to resume from a previous chain segment (e.g. after
   * a process restart). When omitted the signer starts a fresh chain
   * segment: `previousHash=GENESIS_HASH`, `seq=0`.
   */
  chainSeed?: { previousHash: string; seq: number };
}

/**
 * Build an {@link EvidenceSigner} backed by an in-process Node.js
 * `crypto.KeyObject`. This is the default fallback used by the tool
 * gateway when `ENABLE_CRYPTOGRAPHIC_AUDIT=true` is set without a
 * KMS-backed signer being supplied programmatically. It guarantees that
 * enabling cryptographic audit always produces real signatures rather
 * than silently no-op'ing.
 *
 * The implementation reads the private (and optional public) key once at
 * construction time so each `signEvidence` call performs only the
 * digest-and-sign operation. Throws synchronously if the key material
 * cannot be loaded or the algorithm is unsupported, so misconfiguration
 * surfaces at startup.
 */
export function createSoftwareEvidenceSigner(config: SoftwareEvidenceSignerConfig): AuditEvidenceSigner {
  // Preserve the canonical JWS casing for the algorithm in the signed
  // record (`EdDSA`, `RS256`, `ES256`, `PS256`) so downstream verifiers
  // that compare against the JWS spec see the expected value. Internally
  // we normalise to upper-case for control-flow comparisons only.
  const rawAlgorithm = config.algorithm ?? 'RS256';
  const algorithmUpper = rawAlgorithm.toUpperCase();
  const CANONICAL_ALGORITHMS: Record<string, string> = {
    RS256: 'RS256',
    PS256: 'PS256',
    ES256: 'ES256',
    EDDSA: 'EdDSA',
  };
  const canonicalAlgorithm = CANONICAL_ALGORITHMS[algorithmUpper];
  const keyId = config.keyId ?? 'software-key';

  // Enforce mutual exclusivity of inline PEM and PEM file path so
  // operators do not get silent "which one wins?" precedence behaviour
  // when both are accidentally configured.
  if (config.privateKeyPem !== undefined && config.privateKeyPath !== undefined) {
    throw new Error(
      'createSoftwareEvidenceSigner: privateKeyPem and privateKeyPath are mutually exclusive — supply exactly one',
    );
  }
  if (config.publicKeyPem !== undefined && config.publicKeyPath !== undefined) {
    throw new Error(
      'createSoftwareEvidenceSigner: publicKeyPem and publicKeyPath are mutually exclusive — supply exactly one',
    );
  }

  const privatePem = config.privateKeyPem
    ?? (config.privateKeyPath ? require('fs').readFileSync(config.privateKeyPath, 'utf8') : undefined);
  if (!privatePem || privatePem.trim().length === 0) {
    throw new Error(
      'createSoftwareEvidenceSigner: privateKeyPem or privateKeyPath must be supplied with PEM-encoded key material',
    );
  }

  let privateKey: crypto.KeyObject;
  try {
    privateKey = crypto.createPrivateKey(privatePem);
  } catch (err) {
    throw new Error(
      'createSoftwareEvidenceSigner: failed to parse private key PEM: ' +
        (err instanceof Error ? err.message : String(err)),
    );
  }

  let publicKey: crypto.KeyObject;
  const publicPem = config.publicKeyPem
    ?? (config.publicKeyPath ? require('fs').readFileSync(config.publicKeyPath, 'utf8') : undefined);
  if (publicPem) {
    try {
      publicKey = crypto.createPublicKey(publicPem);
    } catch (err) {
      throw new Error(
        'createSoftwareEvidenceSigner: failed to parse public key PEM: ' +
          (err instanceof Error ? err.message : String(err)),
      );
    }
  } else {
    publicKey = crypto.createPublicKey(privateKey);
  }

  const isEdDsa = algorithmUpper === 'EDDSA';
  const isPss = algorithmUpper === 'PS256';
  const isEcdsa = algorithmUpper === 'ES256';
  const isRsaPkcs1 = algorithmUpper === 'RS256';
  if (!canonicalAlgorithm || !SUPPORTED_ALGORITHMS.has(algorithmUpper)) {
    throw new Error(
      `createSoftwareEvidenceSigner: unsupported algorithm '${rawAlgorithm}'. ` +
        'Supported: RS256, PS256, ES256, EdDSA. ' +
        'RS/PS/ES384/512 are intentionally rejected because AuditEvidenceSigner ' +
        'always pre-computes a SHA-256 digest before calling signDigest.',
    );
  }

  // Validate the key type is compatible with the requested algorithm so
  // misconfigurations surface at startup rather than at first signing.
  const keyType = privateKey.asymmetricKeyType;
  if (isRsaPkcs1 || isPss) {
    if (keyType !== 'rsa') {
      throw new Error(
        `createSoftwareEvidenceSigner: algorithm '${canonicalAlgorithm}' requires an RSA key, got '${keyType}'`,
      );
    }
  } else if (isEcdsa) {
    if (keyType !== 'ec') {
      throw new Error(
        `createSoftwareEvidenceSigner: algorithm '${canonicalAlgorithm}' requires an EC key, got '${keyType}'`,
      );
    }
  } else if (isEdDsa) {
    if (keyType !== 'ed25519' && keyType !== 'ed448') {
      throw new Error(
        `createSoftwareEvidenceSigner: algorithm 'EdDSA' requires an Ed25519/Ed448 key, got '${keyType}'`,
      );
    }
  }

  const cryptoSigner: CryptoSigner = {
    async signDigest(digest: Buffer): Promise<Buffer> {
      // The CryptoSigner contract receives a precomputed SHA-256 digest
      // from AuditEvidenceSigner; pass `null` as the algorithm so Node
      // signs the digest bytes directly rather than re-hashing them. For
      // EdDSA, Node's signer expects the message and signs it without an
      // intermediate hash step, which is the correct interpretation of
      // the digest bytes as a fixed-length message.
      if (isEdDsa) {
        return crypto.sign(null, digest, privateKey);
      }
      const signOptions: crypto.SignKeyObjectInput = { key: privateKey };
      if (isPss) {
        signOptions.padding = crypto.constants.RSA_PKCS1_PSS_PADDING;
        signOptions.saltLength = crypto.constants.RSA_PSS_SALTLEN_DIGEST;
      }
      if (isEcdsa) {
        // JWS-compatible (P1363 / r||s) ECDSA signatures.
        (signOptions as crypto.SignKeyObjectInput & { dsaEncoding?: 'ieee-p1363' | 'der' }).dsaEncoding = 'ieee-p1363';
      }
      return crypto.sign(null, digest, signOptions);
    },
    async verifyDigest(digest: Buffer, signature: Buffer, _keyId: string, alg: string): Promise<boolean> {
      // Reject algorithm mismatches: a record signed under one algorithm
      // must not be verifiable under another, even with the same key.
      if (alg.toUpperCase() !== algorithmUpper) {
        return false;
      }
      if (isEdDsa) {
        return crypto.verify(null, digest, publicKey, signature);
      }
      const verifyOptions: crypto.VerifyKeyObjectInput = { key: publicKey };
      if (isPss) {
        verifyOptions.padding = crypto.constants.RSA_PKCS1_PSS_PADDING;
        verifyOptions.saltLength = crypto.constants.RSA_PSS_SALTLEN_DIGEST;
      }
      if (isEcdsa) {
        (verifyOptions as crypto.VerifyKeyObjectInput & { dsaEncoding?: 'ieee-p1363' | 'der' }).dsaEncoding = 'ieee-p1363';
      }
      return crypto.verify(null, digest, verifyOptions, signature);
    },
    async getKeyId(): Promise<string> {
      return keyId;
    },
    getAlgorithm(): string {
      return canonicalAlgorithm;
    },
    getPublicKeyPem(): string {
      return publicKey.export({ type: 'spki', format: 'pem' }) as string;
    },
  };

  return new AuditEvidenceSigner(cryptoSigner, config.chainSeed);
}

/**
 * Build a software evidence signer from environment variables. Returns
 * `undefined` when no relevant env vars are present so callers can decide
 * whether to fail fast or continue.
 *
 * Recognised variables:
 *   * `EVIDENCE_SIGNING_KEY_PEM`  — inline PEM string (preferred for
 *      Kubernetes secret mounts that project keys via env var).
 *   * `EVIDENCE_SIGNING_KEY_FILE` — path to a PEM file on disk.
 *   * `EVIDENCE_SIGNING_PUBLIC_KEY_PEM` / `EVIDENCE_SIGNING_PUBLIC_KEY_FILE`
 *      — optional explicit public key (otherwise derived from the private key).
 *   * `EVIDENCE_SIGNING_ALGORITHM` — defaults to `RS256`.
 *   * `EVIDENCE_SIGNING_KEY_ID`   — defaults to `software-key`.
 */
export function createSoftwareEvidenceSignerFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): AuditEvidenceSigner | undefined {
  const privateKeyPem = env.EVIDENCE_SIGNING_KEY_PEM;
  const privateKeyPath = env.EVIDENCE_SIGNING_KEY_FILE;
  if (!privateKeyPem && !privateKeyPath) {
    return undefined;
  }
  return createSoftwareEvidenceSigner({
    privateKeyPem,
    privateKeyPath,
    publicKeyPem: env.EVIDENCE_SIGNING_PUBLIC_KEY_PEM,
    publicKeyPath: env.EVIDENCE_SIGNING_PUBLIC_KEY_FILE,
    keyId: env.EVIDENCE_SIGNING_KEY_ID,
    algorithm: env.EVIDENCE_SIGNING_ALGORITHM,
  });
}

/**
 * Configuration for {@link createSoftwareEvidenceVerifier}.
 *
 * A verifier holds only the public key so it can be deployed to a
 * verification job (for example, the F-9 continuous evidence-chain
 * verification cron) without granting that job the ability to mint new
 * signatures. Exactly one of `publicKeyPem` / `publicKeyPath` must be
 * supplied.
 */
export interface SoftwareEvidenceVerifierConfig {
  publicKeyPem?: string;
  publicKeyPath?: string;
  /**
   * Logical key identifier the verifier will accept. When supplied, the
   * verifier rejects records whose `keyId` does not match — this lets a
   * scheduled job pin verification to a specific signing key and detect
   * unexpected key rotations as failures rather than silently accepting
   * them. When omitted, the verifier accepts any `keyId` that the bound
   * public key successfully verifies.
   */
  keyId?: string;
  /**
   * JWS-style algorithm name. Defaults to `RS256`. Must be one of
   * `RS256`, `PS256`, `ES256`, `EdDSA` — matching {@link createSoftwareEvidenceSigner}.
   */
  algorithm?: string;
}

/**
 * Build an {@link AuditEvidenceSigner} that can ONLY verify, never sign.
 *
 * This is the primitive used by the F-9 continuous evidence-chain
 * verification job: the job holds only the public key, walks a batch of
 * `SignedAuditEvidence` records emitted by issuer/gateway, and calls
 * `verifyEvidence` on each one. Calling `signEvidence` on the returned
 * instance throws — preventing a misconfigured verification host from
 * accidentally minting new evidence.
 */
export function createSoftwareEvidenceVerifier(
  config: SoftwareEvidenceVerifierConfig,
): AuditEvidenceSigner {
  const rawAlgorithm = config.algorithm ?? 'RS256';
  const algorithmUpper = rawAlgorithm.toUpperCase();
  const CANONICAL_ALGORITHMS: Record<string, string> = {
    RS256: 'RS256',
    PS256: 'PS256',
    ES256: 'ES256',
    EDDSA: 'EdDSA',
  };
  const canonicalAlgorithm = CANONICAL_ALGORITHMS[algorithmUpper];
  if (!canonicalAlgorithm || !SUPPORTED_ALGORITHMS.has(algorithmUpper)) {
    throw new Error(
      `createSoftwareEvidenceVerifier: unsupported algorithm '${rawAlgorithm}'. ` +
        'Supported: RS256, PS256, ES256, EdDSA.',
    );
  }

  if (config.publicKeyPem !== undefined && config.publicKeyPath !== undefined) {
    throw new Error(
      'createSoftwareEvidenceVerifier: publicKeyPem and publicKeyPath are mutually exclusive — supply exactly one',
    );
  }
  const publicPem = config.publicKeyPem
    ?? (config.publicKeyPath ? require('fs').readFileSync(config.publicKeyPath, 'utf8') : undefined);
  if (!publicPem || publicPem.trim().length === 0) {
    throw new Error(
      'createSoftwareEvidenceVerifier: publicKeyPem or publicKeyPath must be supplied with PEM-encoded key material',
    );
  }

  let publicKey: crypto.KeyObject;
  try {
    publicKey = crypto.createPublicKey(publicPem);
  } catch (err) {
    throw new Error(
      'createSoftwareEvidenceVerifier: failed to parse public key PEM: ' +
        (err instanceof Error ? err.message : String(err)),
    );
  }

  const isEdDsa = algorithmUpper === 'EDDSA';
  const isPss = algorithmUpper === 'PS256';
  const isEcdsa = algorithmUpper === 'ES256';
  const isRsa = algorithmUpper === 'RS256' || isPss;

  const keyType = publicKey.asymmetricKeyType;
  if (isRsa && keyType !== 'rsa') {
    throw new Error(
      `createSoftwareEvidenceVerifier: algorithm '${canonicalAlgorithm}' requires an RSA public key, got '${keyType}'`,
    );
  }
  if (isEcdsa && keyType !== 'ec') {
    throw new Error(
      `createSoftwareEvidenceVerifier: algorithm '${canonicalAlgorithm}' requires an EC public key, got '${keyType}'`,
    );
  }
  if (isEdDsa && keyType !== 'ed25519' && keyType !== 'ed448') {
    throw new Error(
      `createSoftwareEvidenceVerifier: algorithm 'EdDSA' requires an Ed25519/Ed448 public key, got '${keyType}'`,
    );
  }

  const expectedKeyId = config.keyId;

  const cryptoSigner: CryptoSigner = {
    async signDigest(): Promise<Buffer> {
      throw new Error(
        'createSoftwareEvidenceVerifier: this signer is verify-only and cannot mint signatures. ' +
          'Use createSoftwareEvidenceSigner for signing.',
      );
    },
    async verifyDigest(digest: Buffer, signature: Buffer, keyId: string, alg: string): Promise<boolean> {
      // Reject algorithm mismatches: a record signed under one algorithm
      // must not be verifiable under another, even with the same key.
      if (alg.toUpperCase() !== algorithmUpper) {
        return false;
      }
      // When the verifier was pinned to a specific keyId, a record
      // claiming a different keyId is a signal of unexpected rotation
      // (or tampering) and must fail closed rather than falling through
      // to the cryptographic check.
      if (expectedKeyId !== undefined && keyId !== expectedKeyId) {
        return false;
      }
      if (isEdDsa) {
        return crypto.verify(null, digest, publicKey, signature);
      }
      const verifyOptions: crypto.VerifyKeyObjectInput = { key: publicKey };
      if (isPss) {
        verifyOptions.padding = crypto.constants.RSA_PKCS1_PSS_PADDING;
        verifyOptions.saltLength = crypto.constants.RSA_PSS_SALTLEN_DIGEST;
      }
      if (isEcdsa) {
        (verifyOptions as crypto.VerifyKeyObjectInput & { dsaEncoding?: 'ieee-p1363' | 'der' }).dsaEncoding = 'ieee-p1363';
      }
      return crypto.verify(null, digest, verifyOptions, signature);
    },
    async getKeyId(): Promise<string> {
      // The verifier never signs, but `getKeyId` is part of the contract.
      // Return the pinned keyId when configured, else a sentinel that
      // makes accidental signing attempts identifiable in logs.
      return expectedKeyId ?? 'verify-only';
    },
    getAlgorithm(): string {
      return canonicalAlgorithm;
    },
  };

  return new AuditEvidenceSigner(cryptoSigner);
}

/**
 * Build a software evidence verifier from environment variables. Returns
 * `undefined` when no relevant env vars are present so callers can decide
 * whether to fail fast or continue.
 *
 * Recognised variables (in priority order — first match wins, later
 * vars are ignored entirely so adding a `VERIFY` var to a host that
 * already exports `SIGNING` fallbacks is always safe):
 *   1. `EVIDENCE_VERIFY_PUBLIC_KEY_PEM`  — inline PEM string for the
 *      verification job. Preferred when the job runs in an environment
 *      where the signing key MUST NOT be present.
 *   2. `EVIDENCE_VERIFY_PUBLIC_KEY_FILE` — path to a PEM file on disk.
 *   3. `EVIDENCE_SIGNING_PUBLIC_KEY_PEM` — fallback for hosts that already
 *      configure the signing-side public key.
 *   4. `EVIDENCE_SIGNING_PUBLIC_KEY_FILE` — same, file form.
 *
 * `EVIDENCE_VERIFY_ALGORITHM` (or `EVIDENCE_SIGNING_ALGORITHM`) defaults to `RS256`.
 * `EVIDENCE_VERIFY_KEY_ID` (or `EVIDENCE_SIGNING_KEY_ID`), when set, pins
 * verification to that key id.
 */
export function createSoftwareEvidenceVerifierFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): AuditEvidenceSigner | undefined {
  // Strict precedence: pick exactly one of (PEM, PATH) so mixing
  // VERIFY-* with SIGNING-* fallbacks during a migration cannot trip
  // the mutually-exclusive guard in createSoftwareEvidenceVerifier.
  let publicKeyPem: string | undefined;
  let publicKeyPath: string | undefined;
  if (env.EVIDENCE_VERIFY_PUBLIC_KEY_PEM) {
    publicKeyPem = env.EVIDENCE_VERIFY_PUBLIC_KEY_PEM;
  } else if (env.EVIDENCE_VERIFY_PUBLIC_KEY_FILE) {
    publicKeyPath = env.EVIDENCE_VERIFY_PUBLIC_KEY_FILE;
  } else if (env.EVIDENCE_SIGNING_PUBLIC_KEY_PEM) {
    publicKeyPem = env.EVIDENCE_SIGNING_PUBLIC_KEY_PEM;
  } else if (env.EVIDENCE_SIGNING_PUBLIC_KEY_FILE) {
    publicKeyPath = env.EVIDENCE_SIGNING_PUBLIC_KEY_FILE;
  }
  if (!publicKeyPem && !publicKeyPath) {
    return undefined;
  }
  return createSoftwareEvidenceVerifier({
    publicKeyPem,
    publicKeyPath,
    keyId: env.EVIDENCE_VERIFY_KEY_ID ?? env.EVIDENCE_SIGNING_KEY_ID,
    algorithm: env.EVIDENCE_VERIFY_ALGORITHM ?? env.EVIDENCE_SIGNING_ALGORITHM,
  });
}
