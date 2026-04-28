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

/**
 * Hash algorithm names accepted by Node.js' `crypto` module for the
 * supported JWS-style signing algorithms.
 */
const HASH_ALGORITHMS: Record<string, string> = {
  RS256: 'sha256',
  RS384: 'sha384',
  RS512: 'sha512',
  ES256: 'sha256',
  ES384: 'sha384',
  ES512: 'sha512',
  PS256: 'sha256',
  PS384: 'sha384',
  PS512: 'sha512',
};

/**
 * Configuration for {@link createSoftwareEvidenceSigner}.
 *
 * Exactly one of `privateKeyPem` / `privateKeyPath` must be supplied. The
 * matching public key is derived from the private key automatically (used
 * by `verifyEvidence`) but a `publicKeyPem` may be supplied explicitly
 * when, for example, the private key lives in an HSM-backed PEM container
 * with a separate public certificate.
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
   * RS256/384/512, PS256/384/512, ES256/384/512, EdDSA.
   */
  algorithm?: string;
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
  const algorithm = (config.algorithm ?? 'RS256').toUpperCase();
  const keyId = config.keyId ?? 'software-key';

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

  const isEdDsa = algorithm === 'EDDSA';
  const isPss = algorithm.startsWith('PS');
  const isEcdsa = algorithm.startsWith('ES');
  const hashAlgorithm = HASH_ALGORITHMS[algorithm];
  if (!isEdDsa && !hashAlgorithm) {
    throw new Error(
      `createSoftwareEvidenceSigner: unsupported algorithm '${algorithm}'. ` +
        'Supported: RS256/RS384/RS512, PS256/PS384/PS512, ES256/ES384/ES512, EdDSA.',
    );
  }

  // Validate the key type is compatible with the requested algorithm so
  // misconfigurations surface at startup rather than at first signing.
  const keyType = privateKey.asymmetricKeyType;
  if (algorithm.startsWith('RS') || isPss) {
    if (keyType !== 'rsa') {
      throw new Error(
        `createSoftwareEvidenceSigner: algorithm '${algorithm}' requires an RSA key, got '${keyType}'`,
      );
    }
  } else if (isEcdsa) {
    if (keyType !== 'ec') {
      throw new Error(
        `createSoftwareEvidenceSigner: algorithm '${algorithm}' requires an EC key, got '${keyType}'`,
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
      if (isEdDsa) {
        // Node's EdDSA signer takes the message, not a precomputed digest;
        // AuditEvidenceSigner already produced the SHA-256 digest of the
        // canonical evidence so we sign that 32-byte value directly.
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
      return crypto.sign(hashAlgorithm, digest, signOptions);
    },
    async verifyDigest(digest: Buffer, signature: Buffer, _keyId: string, alg: string): Promise<boolean> {
      // Reject algorithm mismatches: a record signed under one algorithm
      // must not be verifiable under another, even with the same key.
      if (alg.toUpperCase() !== algorithm) {
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
      return crypto.verify(hashAlgorithm, digest, verifyOptions, signature);
    },
    async getKeyId(): Promise<string> {
      return keyId;
    },
    getAlgorithm(): string {
      return algorithm;
    },
  };

  return new AuditEvidenceSigner(cryptoSigner);
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
