/**
 * Evidence Signer Implementation
 * Creates cryptographically signed audit evidence for tamper-evident records
 */

import * as crypto from 'crypto';
import { AuditEvidence, SignedAuditEvidence, EvidenceSigner } from './types';
import { sha256String, canonicalize, generateId } from './utils';

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
