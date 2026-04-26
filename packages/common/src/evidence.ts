/**
 * Evidence Signer Implementation
 * Creates cryptographically signed audit evidence for tamper-evident records
 */

import * as crypto from 'crypto';
import { AuditEvidence, SignedAuditEvidence, EvidenceSigner } from './types';
import { sha256String, safeSerialize, generateId } from './utils';

/**
 * Interface for cryptographic signing operations
 */
export interface CryptoSigner {
  signDigest(digest: Buffer): Promise<Buffer>;
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
   * Note: Full cryptographic verification is not implemented yet.
   * This method fails closed so callers cannot treat unsigned or unverifiable
   * evidence as successfully verified.
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

    // Full verification would require:
    // 1. Resolving the public key using keyId
    // 2. Decoding and verifying the signature against sha256(canonical bytes)
    // Until that is implemented, fail closed rather than returning a
    // misleading success value based only on metadata presence.
    return false;
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
