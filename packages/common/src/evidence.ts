/**
 * Evidence Signer Implementation
 * Creates cryptographically signed audit evidence for tamper-evident records
 */

import { AuditEvidence, SignedAuditEvidence, EvidenceSigner } from './types';
import { sha256, generateId } from './utils';

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
   * Sign audit evidence to create a tamper-evident record
   * The signature covers all fields of the evidence, ensuring any modification will be detected
   */
  async signEvidence(evidence: AuditEvidence): Promise<SignedAuditEvidence> {
    // Create a canonical representation of the evidence for signing
    const canonical = this.canonicalizeEvidence(evidence);

    // Hash the canonical representation
    const digest = Buffer.from(sha256(canonical), 'hex');

    // Sign the digest
    const signatureBuffer = await this.cryptoSigner.signDigest(digest);
    const signature = signatureBuffer.toString('base64');

    // Get signing metadata
    const keyId = await this.cryptoSigner.getKeyId();
    const algorithm = this.cryptoSigner.getAlgorithm();

    return {
      ...evidence,
      signature,
      keyId,
      algorithm,
    };
  }

  /**
   * Verify a signed evidence record
   * Note: This is a placeholder. Full verification would require access to the public key
   */
  async verifyEvidence(signedEvidence: SignedAuditEvidence): Promise<boolean> {
    // Extract the evidence without signature
    const { signature, keyId, algorithm, ...evidence } = signedEvidence;

    // Create canonical representation
    const canonical = this.canonicalizeEvidence(evidence);

    // Hash it for future verification
    // In a full implementation, we would:
    // 1. Fetch the public key using keyId
    // 2. Verify the signature against the digest: sha256(canonical)
    // For now, we just check that the signature exists
    return signature.length > 0 && keyId.length > 0 && algorithm.length > 0 && canonical.length > 0;
  }

  /**
   * Create a canonical string representation of evidence for signing
   * Fields are sorted and formatted consistently to ensure the same input always produces the same signature
   */
  private canonicalizeEvidence(evidence: Partial<AuditEvidence>): string {
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
    promptHash: params.prompt ? sha256(params.prompt) : sha256(''),
    documentsHash: params.documents ? sha256(params.documents) : undefined,
    tool: params.tool,
    argsHash: sha256(params.args),
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
