/**
 * Evidence Signer Implementation
 * Creates cryptographically signed audit evidence for tamper-evident records
 */

import * as crypto from 'crypto';
import { AuditEvidence, SignedAuditEvidence, EvidenceSigner } from './types';
import { sha256String, safeSerialize, generateId } from './utils';

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
}

/**
 * Evidence signer that creates tamper-evident audit records
 * Following the Azure security pattern: hash locally, sign with Key Vault
 */
export class AuditEvidenceSigner implements EvidenceSigner {
  private cryptoSigner: CryptoSigner;

  constructor(cryptoSigner: CryptoSigner) {
    this.cryptoSigner = cryptoSigner;
  }

  /**
   * Sign audit evidence to create a tamper-evident record.
   * keyId and algorithm are fetched BEFORE canonicalisation so they are
   * covered by the signature and cannot be modified without detection.
   */
  async signEvidence(evidence: AuditEvidence): Promise<SignedAuditEvidence> {
    // Fetch signing metadata FIRST so it is included in the signed content
    const keyId = await this.cryptoSigner.getKeyId();
    const algorithm = this.cryptoSigner.getAlgorithm();

    // Create a canonical representation that includes keyId and algorithm
    const canonical = this.canonicalizeEvidence(evidence, keyId, algorithm);

    // Hash the canonical UTF-8 bytes directly – no JSON.stringify wrapping
    const digest = crypto.createHash('sha256').update(canonical, 'utf8').digest();

    // Sign the digest
    const signatureBuffer = await this.cryptoSigner.signDigest(digest);
    const signature = signatureBuffer.toString('base64');

    return {
      ...evidence,
      signature,
      keyId,
      algorithm,
    };
  }

  /**
   * Verify a signed evidence record.
   *
   * Performs full cryptographic verification when the underlying
   * {@link CryptoSigner} exposes a `verifyDigest` method:
   *   1. Re-canonicalises the evidence using the signed `keyId` and
   *      `algorithm` (so any tampering with those fields invalidates the
   *      signature).
   *   2. Hashes the canonical bytes with SHA-256.
   *   3. Asks the signer to verify the supplied signature against the digest.
   *
   * When the signer does NOT implement `verifyDigest` this method fails
   * closed (returns `false`) so callers cannot mistake "verification not
   * possible" for "signature valid".
   */
  async verifyEvidence(signedEvidence: SignedAuditEvidence): Promise<boolean> {
    // Reject malformed signed evidence records early
    const { signature, keyId, algorithm, ...evidence } = signedEvidence;
    if (!signature || !keyId || !algorithm) {
      return false;
    }

    // Ensure a canonical form can be produced
    const canonical = this.canonicalizeEvidence(evidence, keyId, algorithm);
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
   * Fields are ordered deterministically. keyId and algorithm are appended so they
   * are covered by the signature and cannot be tampered with undetected.
   */
  private canonicalizeEvidence(evidence: Partial<AuditEvidence>, keyId?: string, algorithm?: string): string {
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
    ];

    return fields.join('|');
  }
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
}): AuditEvidence {
  const nonce = generateId();
  const ts = new Date().toISOString();

  return {
    id: generateId(),
    sessionId: params.sessionId,
    userId: params.userId,
    promptHash: params.prompt !== undefined ? sha256String(params.prompt) : sha256String(''),
    documentsHash: params.documents !== undefined ? sha256String(safeSerialize(params.documents)) : undefined,
    tool: params.tool,
    argsHash: sha256String(safeSerialize(params.args)),
    nonce,
    ts,
    policyVersion: params.policyVersion,
    agentId: params.agentId,
    resource: params.resource,
    action: params.action,
    capabilityId: params.capabilityId,
    decision: params.decision,
  };
}
