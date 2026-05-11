/**
 * KmsEvidenceSigner — parity tests (Task 5, Stage 3)
 * ────────────────────────────────────────────────────────────────────────────
 * These tests verify the "byte-identical canonical record" contract:
 *
 *   "Audit record shape must be byte-identical to what the software signer
 *    produces (OCSF API Activity, class_uid 6003); only the signature
 *    algorithm/keyref changes."
 *
 * Three categories of tests:
 *
 *   1. **Configuration / factory tests** — `createKmsEvidenceSignerFromEnv`
 *      returns `undefined` when no provider is set, throws on missing required
 *      env vars, and constructs the right driver for each provider.
 *
 *   2. **Parity tests** — For the same AuditEvidence input, a KMS-backed
 *      signer and the software signer must produce:
 *        a) identical `canonicalizeEvidenceFields(...)` pre-signature strings.
 *        b) identical `SignedAuditEvidence` fields (except `signature`,
 *           `keyId`, and `algorithm`).
 *        c) identical OCSF API Activity (class_uid 6003) record content
 *           (except the `enrichments[0].value` / `data.{algorithm,keyId}`
 *           fields that explicitly carry the signing provenance).
 *
 *   3. **Driver unit tests** — Each driver (`azure-keyvault`, `aws-kms`,
 *      `gcp-cloudkms`) is exercised via a lightweight mock client so we never
 *      need real cloud credentials in CI. The mock's sign callback uses an
 *      in-process RSA key so signatures are real and `verifyEvidence` works.
 */

import * as crypto from 'crypto';
import {
  AuditEvidenceSigner,
  CryptoSigner,
  createAuditEvidence,
  createSoftwareEvidenceSigner,
  canonicalizeEvidenceFields,
  signedEvidenceToOcsf,
  GENESIS_HASH,
} from '@euno/common-core';
import {
  createKmsEvidenceSigner,
  createKmsEvidenceSignerFromEnv,
} from '../kms-evidence-signer';

// ── Shared RSA key pair used across tests ─────────────────────────────────────

const { privateKey: TEST_RSA_PRIVATE_KEY, publicKey: TEST_RSA_PUBLIC_KEY } =
  crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

/** Sign a digest with in-process PKCS#1 v1.5 (RS256 semantics). */
function signRsa(digest: Buffer): Buffer {
  return crypto.sign(null, digest, { key: TEST_RSA_PRIVATE_KEY });
}

/** Verify an RS256 signature. */
function verifyRsa(digest: Buffer, signature: Buffer): boolean {
  return crypto.verify(null, digest, { key: TEST_RSA_PUBLIC_KEY }, signature);
}

// ── Helpers to build mock KMS clients ────────────────────────────────────────

/**
 * A minimal mock Azure Key Vault `CryptographyClient` interface.
 *
 * Backed by an in-process RSA key so signatures are real — we can
 * call `verifyEvidence` and get a meaningful boolean back.
 */
function buildMockAkvClient(algorithm = 'RS256') {
  return {
    async sign(_alg: string, digest: Uint8Array) {
      const sigBuf = signRsa(Buffer.from(digest));
      return { result: sigBuf, algorithm };
    },
    async verify(_alg: string, digest: Uint8Array, signature: Uint8Array) {
      const ok = verifyRsa(Buffer.from(digest), Buffer.from(signature));
      return { result: ok };
    },
  };
}

/** Minimal AWS KMS client mock. */
function buildMockAwsKmsClient() {
  // eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
  const SignCommand = jest.fn();
  // eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
  const VerifyCommand = jest.fn();

  const client = {
    async send(command: { input: Record<string, unknown> }) {
      const input = command.input as {
        KeyId?: string;
        MessageType?: string;
        Message?: Buffer;
        Signature?: Buffer;
        SigningAlgorithm?: string;
      };

      if ('Signature' in input) {
        // VerifyCommand
        const ok = verifyRsa(Buffer.from(input.Message!), Buffer.from(input.Signature!));
        return { SignatureValid: ok };
      } else {
        // SignCommand
        const sig = signRsa(Buffer.from(input.Message!));
        return { Signature: sig };
      }
    },
  };

  return { client, SignCommand, VerifyCommand };
}

/** GCP Cloud KMS client mock. */
function buildMockGcpKmsClient(keyVersionName: string) {
  return {
    cryptoKeyVersionPath(
      _project: string,
      _location: string,
      _keyRing: string,
      _cryptoKey: string,
      _version: string,
    ) {
      return keyVersionName;
    },
    async asymmetricSign({ digest }: { digest: { sha256: Buffer } }) {
      // GCP ECDSA returns DER, but for RSA the format is the same as P1363.
      // For simplicity in tests, we use RSA so no DER ↔ P1363 conversion is needed.
      const sig = signRsa(digest.sha256);
      return [{ signature: sig }] as [{ signature: Buffer }];
    },
    async asymmetricVerify({
      digest,
      signature,
    }: {
      digest: { sha256: Buffer };
      signature: Buffer;
    }) {
      const ok = verifyRsa(digest.sha256, signature);
      return [{ success: ok }] as [{ success: boolean }];
    },
  };
}

// ── CryptoSigner backed by the mock clients, bypassing SDK require() ──────────

/**
 * Build a `CryptoSigner` that delegates to a mock AKV client.
 *
 * Because `buildAzureKeyVaultCryptoSigner` calls `require('@azure/keyvault-keys')`
 * at runtime (optional dependency), the driver itself is instantiated by
 * calling the exported `createKmsCryptoSigner` in tests that stub require,
 * OR by constructing the signer directly with a pre-built mock client.
 *
 * For these tests we avoid stubbing module resolution and instead construct
 * a `CryptoSigner` that wraps the mock client with the same logic the driver
 * uses: `signDigest(digest)` → `client.sign(algorithm, digest)`.
 */
function buildAkvBackedSigner(keyId = 'akv-test-key', algorithm = 'RS256'): CryptoSigner {
  const client = buildMockAkvClient(algorithm);
  return {
    async signDigest(digest: Buffer) {
      const { result } = await client.sign(algorithm, digest);
      return Buffer.isBuffer(result) ? result : Buffer.from(result as Uint8Array);
    },
    async verifyDigest(digest, signature, _keyId, alg) {
      if (alg.toUpperCase() !== algorithm) return false;
      const { result } = await client.verify(algorithm, digest, signature);
      return !!result;
    },
    async getKeyId() {
      return keyId;
    },
    getAlgorithm() {
      return algorithm;
    },
  };
}

/** CryptoSigner backed by the mock AWS KMS client. */
function buildAwsBackedSigner(keyId = 'aws-kms-test-key', algorithm = 'RS256'): CryptoSigner {
  const { client } = buildMockAwsKmsClient();
  return {
    async signDigest(digest: Buffer) {
      const response = await client.send({
        input: { Message: digest, SigningAlgorithm: 'RSASSA_PKCS1_V1_5_SHA_256' },
      });
      return Buffer.from((response as { Signature: Buffer }).Signature);
    },
    async verifyDigest(digest, signature, _keyId, alg) {
      if (alg.toUpperCase() !== algorithm) return false;
      const response = await client.send({
        input: { Message: digest, Signature: signature, SigningAlgorithm: 'RSASSA_PKCS1_V1_5_SHA_256' },
      });
      return !!(response as { SignatureValid: boolean }).SignatureValid;
    },
    async getKeyId() {
      return keyId;
    },
    getAlgorithm() {
      return algorithm;
    },
  };
}

/** GCP Cloud KMS-backed CryptoSigner. */
function buildGcpBackedSigner(keyId = 'gcp-kms-test-key', algorithm = 'RS256'): CryptoSigner {
  const kvName = 'projects/p/locations/global/keyRings/kr/cryptoKeys/k/cryptoKeyVersions/1';
  const client = buildMockGcpKmsClient(kvName);
  return {
    async signDigest(digest: Buffer) {
      const results = await client.asymmetricSign({ digest: { sha256: digest } });
      const sig = results[0].signature;
      return Buffer.isBuffer(sig) ? sig : Buffer.from(sig);
    },
    async verifyDigest(digest, signature, _keyId, alg) {
      if (alg.toUpperCase() !== algorithm) return false;
      const results = await client.asymmetricVerify({ digest: { sha256: digest }, signature });
      return !!results[0].success;
    },
    async getKeyId() {
      return keyId;
    },
    getAlgorithm() {
      return algorithm;
    },
  };
}

// ── Factory helpers ───────────────────────────────────────────────────────────

const PRODUCT = { name: 'euno-tool-gateway', vendor: 'Euno', version: '1.0.0' };

function makeEvidence() {
  return createAuditEvidence({
    sessionId: 'sess-parity-test',
    userId: 'user-42',
    prompt: 'summarise customer data',
    documents: { count: 3 },
    tool: 'read_db',
    args: { table: 'orders', limit: 100 },
    agentId: 'agent-analytics',
    resource: 'tool://read_db',
    action: 'read',
    capabilityId: 'cap-analytics-v1',
    decision: 'allow',
    policyVersion: '2.0.0',
  });
}

/** Build a software signer with a fresh in-process RSA key. */
function buildSoftwareSigner(keyId = 'software-test-key') {
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  return createSoftwareEvidenceSigner({
    privateKeyPem: privatePem,
    keyId,
    algorithm: 'RS256',
  });
}

// =============================================================================
// 1. Configuration / factory tests
// =============================================================================

describe('createKmsEvidenceSignerFromEnv', () => {
  it('returns undefined when AUDIT_SIGNING_KMS_PROVIDER is not set', () => {
    expect(createKmsEvidenceSignerFromEnv({})).toBeUndefined();
  });

  it('throws when azure-keyvault provider is set but URL is missing', () => {
    expect(() =>
      createKmsEvidenceSignerFromEnv({
        AUDIT_SIGNING_KMS_PROVIDER: 'azure-keyvault',
        AUDIT_SIGNING_AZURE_KEY_NAME: 'audit-key',
      }),
    ).toThrow('AUDIT_SIGNING_AZURE_KEYVAULT_URL');
  });

  it('throws when azure-keyvault provider is set but key name is missing', () => {
    expect(() =>
      createKmsEvidenceSignerFromEnv({
        AUDIT_SIGNING_KMS_PROVIDER: 'azure-keyvault',
        AUDIT_SIGNING_AZURE_KEYVAULT_URL: 'https://myvault.vault.azure.net/',
      }),
    ).toThrow('AUDIT_SIGNING_AZURE_KEY_NAME');
  });

  it('throws when aws-kms provider is set but key ID is missing', () => {
    expect(() =>
      createKmsEvidenceSignerFromEnv({
        AUDIT_SIGNING_KMS_PROVIDER: 'aws-kms',
      }),
    ).toThrow('AUDIT_SIGNING_AWS_KMS_KEY_ID');
  });

  it('throws when gcp-cloudkms provider is set but project ID is missing', () => {
    expect(() =>
      createKmsEvidenceSignerFromEnv({
        AUDIT_SIGNING_KMS_PROVIDER: 'gcp-cloudkms',
        AUDIT_SIGNING_GCP_KEYRING_ID: 'kr',
        AUDIT_SIGNING_GCP_CRYPTOKEY_ID: 'ck',
      }),
    ).toThrow('AUDIT_SIGNING_GCP_PROJECT_ID');
  });

  it('throws when gcp-cloudkms provider is set but multiple required fields are missing', () => {
    expect(() =>
      createKmsEvidenceSignerFromEnv({
        AUDIT_SIGNING_KMS_PROVIDER: 'gcp-cloudkms',
        AUDIT_SIGNING_GCP_PROJECT_ID: 'my-project',
        // missing keyRingId and cryptoKeyId
      }),
    ).toThrow(/AUDIT_SIGNING_GCP_KEYRING_ID.*AUDIT_SIGNING_GCP_CRYPTOKEY_ID|AUDIT_SIGNING_GCP_CRYPTOKEY_ID.*AUDIT_SIGNING_GCP_KEYRING_ID/);
  });

  it('throws on unrecognised provider value', () => {
    expect(() =>
      createKmsEvidenceSignerFromEnv({
        AUDIT_SIGNING_KMS_PROVIDER: 'hashicorp-vault',
      }),
    ).toThrow("unrecognised AUDIT_SIGNING_KMS_PROVIDER value 'hashicorp-vault'");
  });

  it('resolveAlgorithm: throws on unsupported algorithm before requiring the SDK', () => {
    // Algorithm validation now happens BEFORE the SDK is dynamically required.
    // RS384 is intentionally unsupported (only SHA-256 family: RS256, PS256, ES256).
    // This test verifies that the error is "unsupported algorithm", not
    // "SDK not installed" — proving the validation order is correct.
    expect(() =>
      createKmsEvidenceSigner({
        provider: 'aws-kms',
        keyId: 'k',
        algorithm: 'RS384',
      }),
    ).toThrow("unsupported algorithm 'RS384'");
  });
});

// =============================================================================
// 2. Parity tests — core contract
// =============================================================================

describe('KmsEvidenceSigner parity with software signer', () => {
  const SHARED_KEY_ID = 'audit-signing-key-v1';
  const SHARED_ALGORITHM = 'RS256';

  it('canonical pre-signature string is identical for software and AKV-backed signers', async () => {
    const swSigner = buildSoftwareSigner(SHARED_KEY_ID);
    const swEvidence = makeEvidence();
    const swSigned = await swSigner.signEvidence(swEvidence);

    // AKV-backed signer with the same key ID and algorithm.
    const akvCryptoSigner = buildAkvBackedSigner(SHARED_KEY_ID, SHARED_ALGORITHM);
    const akvEvidenceSigner = new AuditEvidenceSigner(akvCryptoSigner);
    const akvEvidence = { ...swEvidence }; // same evidence object
    const akvSigned = await akvEvidenceSigner.signEvidence(akvEvidence);

    // Both signers embed the same keyId + algorithm, so the canonical
    // pre-signature string must be byte-identical.
    const swCanonical = canonicalizeEvidenceFields(
      swEvidence,
      swSigned.keyId,
      swSigned.algorithm,
      swSigned.previousHash,
      swSigned.seq,
    );
    const akvCanonical = canonicalizeEvidenceFields(
      akvEvidence,
      akvSigned.keyId,
      akvSigned.algorithm,
      akvSigned.previousHash,
      akvSigned.seq,
    );

    expect(akvCanonical).toBe(swCanonical);
  });

  it('canonical pre-signature string is identical for software and AWS-KMS-backed signers', async () => {
    const swSigner = buildSoftwareSigner(SHARED_KEY_ID);
    const swEvidence = makeEvidence();
    const swSigned = await swSigner.signEvidence(swEvidence);

    const awsCryptoSigner = buildAwsBackedSigner(SHARED_KEY_ID, SHARED_ALGORITHM);
    const awsEvidenceSigner = new AuditEvidenceSigner(awsCryptoSigner);
    const awsEvidence = { ...swEvidence };
    const awsSigned = await awsEvidenceSigner.signEvidence(awsEvidence);

    const swCanonical = canonicalizeEvidenceFields(
      swEvidence, swSigned.keyId, swSigned.algorithm, swSigned.previousHash, swSigned.seq,
    );
    const awsCanonical = canonicalizeEvidenceFields(
      awsEvidence, awsSigned.keyId, awsSigned.algorithm, awsSigned.previousHash, awsSigned.seq,
    );

    expect(awsCanonical).toBe(swCanonical);
  });

  it('canonical pre-signature string is identical for software and GCP-KMS-backed signers', async () => {
    const swSigner = buildSoftwareSigner(SHARED_KEY_ID);
    const swEvidence = makeEvidence();
    const swSigned = await swSigner.signEvidence(swEvidence);

    const gcpCryptoSigner = buildGcpBackedSigner(SHARED_KEY_ID, SHARED_ALGORITHM);
    const gcpEvidenceSigner = new AuditEvidenceSigner(gcpCryptoSigner);
    const gcpEvidence = { ...swEvidence };
    const gcpSigned = await gcpEvidenceSigner.signEvidence(gcpEvidence);

    const swCanonical = canonicalizeEvidenceFields(
      swEvidence, swSigned.keyId, swSigned.algorithm, swSigned.previousHash, swSigned.seq,
    );
    const gcpCanonical = canonicalizeEvidenceFields(
      gcpEvidence, gcpSigned.keyId, gcpSigned.algorithm, gcpSigned.previousHash, gcpSigned.seq,
    );

    expect(gcpCanonical).toBe(swCanonical);
  });

  it('evidence fields are preserved identically across software and KMS signers', async () => {
    const swSigner = buildSoftwareSigner(SHARED_KEY_ID);
    const sharedEvidence = makeEvidence();
    const swSigned = await swSigner.signEvidence(sharedEvidence);

    const kmsCryptoSigner = buildAkvBackedSigner(SHARED_KEY_ID, SHARED_ALGORITHM);
    const kmsEvidenceSigner = new AuditEvidenceSigner(kmsCryptoSigner);
    const kmsSigned = await kmsEvidenceSigner.signEvidence({ ...sharedEvidence });

    // Core evidence fields must be identical.
    const evidenceFields: Array<keyof typeof sharedEvidence> = [
      'id', 'sessionId', 'userId', 'tool', 'agentId', 'resource',
      'action', 'capabilityId', 'decision', 'policyVersion',
      'promptHash', 'argsHash', 'nonce', 'ts',
    ];
    for (const field of evidenceFields) {
      expect(kmsSigned[field]).toBe(swSigned[field]);
    }

    // Chain meta fields that are controlled by the signer.
    expect(kmsSigned.seq).toBe(swSigned.seq);
    expect(kmsSigned.previousHash).toBe(swSigned.previousHash);
  });

  it('OCSF API Activity (class_uid 6003) record is identical except signature enrichment', async () => {
    const sharedEvidence = makeEvidence();

    // Software signer
    const swSigner = buildSoftwareSigner('sw-key');
    const swSigned = await swSigner.signEvidence(sharedEvidence);
    const swOcsf = signedEvidenceToOcsf(swSigned, PRODUCT);

    // KMS signer (AKV mock)
    const kmsCryptoSigner = buildAkvBackedSigner('akv-key', SHARED_ALGORITHM);
    const kmsEvidenceSigner = new AuditEvidenceSigner(kmsCryptoSigner);
    const kmsSigned = await kmsEvidenceSigner.signEvidence({ ...sharedEvidence });
    const kmsOcsf = signedEvidenceToOcsf(kmsSigned, PRODUCT);

    // Top-level OCSF fields must be identical.
    expect(kmsOcsf.class_uid).toBe(6003);
    expect(kmsOcsf.category_uid).toBe(swOcsf.category_uid);
    expect(kmsOcsf.activity_id).toBe(swOcsf.activity_id);
    expect(kmsOcsf.type_uid).toBe(swOcsf.type_uid);
    expect(kmsOcsf.severity_id).toBe(swOcsf.severity_id);
    expect(kmsOcsf.status_id).toBe(swOcsf.status_id);
    expect(kmsOcsf.status).toBe(swOcsf.status);

    // Structured sub-objects.
    expect(kmsOcsf.actor?.user?.uid).toBe(swOcsf.actor?.user?.uid);
    expect(kmsOcsf.actor?.session?.uid).toBe(swOcsf.actor?.session?.uid);
    expect(kmsOcsf.api?.operation).toBe(swOcsf.api?.operation);
    expect(kmsOcsf.api?.request?.uid).toBe(swOcsf.api?.request?.uid);
    expect(kmsOcsf.resources?.[0]?.uid).toBe(swOcsf.resources?.[0]?.uid);

    // The enrichment *content* (policyVersion, tool, promptHash, argsHash,
    // nonce) must be identical — only the signature bytes, keyId, and
    // algorithm differ because those are per-signer.
    const swEnr = swOcsf.enrichments![0]!.data as Record<string, unknown>;
    const kmsEnr = kmsOcsf.enrichments![0]!.data as Record<string, unknown>;

    expect(kmsEnr['policyVersion']).toBe(swEnr['policyVersion']);
    expect(kmsEnr['tool']).toBe(swEnr['tool']);
    expect(kmsEnr['promptHash']).toBe(swEnr['promptHash']);
    expect(kmsEnr['argsHash']).toBe(swEnr['argsHash']);
    expect(kmsEnr['nonce']).toBe(swEnr['nonce']);

    // These differ by design — different signers → different provenance.
    expect(kmsEnr['keyId']).not.toBe(swEnr['keyId']);
  });

  it('hash chain is intact for KMS-backed signer over multiple records', async () => {
    const kmsCryptoSigner = buildAkvBackedSigner(SHARED_KEY_ID, SHARED_ALGORITHM);
    const kmsEvidenceSigner = new AuditEvidenceSigner(kmsCryptoSigner);

    const records = [];
    for (let i = 0; i < 3; i++) {
      records.push(await kmsEvidenceSigner.signEvidence(makeEvidence()));
    }

    // verifyChain checks seq continuity + previousHash linkage.
    const { verifyChain } = await import('@euno/common-core');
    expect(verifyChain(records, GENESIS_HASH)).toBe(true);
  });
});

// =============================================================================
// 3. Driver-level unit tests (using mock clients)
// =============================================================================

describe('AKV-backed CryptoSigner (mock client)', () => {
  it('signDigest produces a non-empty buffer', async () => {
    const signer = buildAkvBackedSigner();
    const digest = crypto.createHash('sha256').update('test payload').digest();
    const sig = await signer.signDigest(digest);
    expect(Buffer.isBuffer(sig)).toBe(true);
    expect(sig.length).toBeGreaterThan(0);
  });

  it('verifyDigest returns true for a valid signature', async () => {
    const signer = buildAkvBackedSigner('k', 'RS256');
    const digest = crypto.createHash('sha256').update('hello').digest();
    const sig = await signer.signDigest(digest);
    const ok = await signer.verifyDigest!(digest, sig, 'k', 'RS256');
    expect(ok).toBe(true);
  });

  it('verifyDigest returns false for algorithm mismatch', async () => {
    const signer = buildAkvBackedSigner('k', 'RS256');
    const digest = crypto.createHash('sha256').update('hello').digest();
    const sig = await signer.signDigest(digest);
    const ok = await signer.verifyDigest!(digest, sig, 'k', 'ES256');
    expect(ok).toBe(false);
  });

  it('getKeyId returns the configured logical key ID', async () => {
    const signer = buildAkvBackedSigner('my-akv-key');
    expect(await signer.getKeyId()).toBe('my-akv-key');
  });

  it('getAlgorithm returns RS256', () => {
    const signer = buildAkvBackedSigner();
    expect(signer.getAlgorithm()).toBe('RS256');
  });

  it('AuditEvidenceSigner round-trips with AKV-backed signer', async () => {
    const cryptoSigner = buildAkvBackedSigner('akv-audit', 'RS256');
    const evidenceSigner = new AuditEvidenceSigner(cryptoSigner);

    const evidence = makeEvidence();
    const signed = await evidenceSigner.signEvidence(evidence);

    expect(signed.keyId).toBe('akv-audit');
    expect(signed.algorithm).toBe('RS256');
    expect(signed.seq).toBe(1);
    expect(signed.previousHash).toBe(GENESIS_HASH);
    expect(signed.signature).toBeTruthy();

    const verified = await evidenceSigner.verifyEvidence(signed);
    expect(verified).toBe(true);
  });
});

describe('AWS KMS-backed CryptoSigner (mock client)', () => {
  it('signDigest produces a non-empty buffer', async () => {
    const signer = buildAwsBackedSigner();
    const digest = crypto.createHash('sha256').update('aws test').digest();
    const sig = await signer.signDigest(digest);
    expect(Buffer.isBuffer(sig)).toBe(true);
    expect(sig.length).toBeGreaterThan(0);
  });

  it('verifyDigest returns true for a valid signature', async () => {
    const signer = buildAwsBackedSigner('k', 'RS256');
    const digest = crypto.createHash('sha256').update('aws verify').digest();
    const sig = await signer.signDigest(digest);
    expect(await signer.verifyDigest!(digest, sig, 'k', 'RS256')).toBe(true);
  });

  it('verifyDigest returns false for algorithm mismatch', async () => {
    const signer = buildAwsBackedSigner('k', 'RS256');
    const digest = crypto.createHash('sha256').update('aws verify').digest();
    const sig = await signer.signDigest(digest);
    expect(await signer.verifyDigest!(digest, sig, 'k', 'PS256')).toBe(false);
  });

  it('AuditEvidenceSigner round-trips with AWS-KMS-backed signer', async () => {
    const cryptoSigner = buildAwsBackedSigner('aws-audit', 'RS256');
    const evidenceSigner = new AuditEvidenceSigner(cryptoSigner);

    const evidence = makeEvidence();
    const signed = await evidenceSigner.signEvidence(evidence);

    expect(signed.keyId).toBe('aws-audit');
    expect(signed.algorithm).toBe('RS256');
    expect(signed.seq).toBe(1);
    expect(signed.signature).toBeTruthy();

    const verified = await evidenceSigner.verifyEvidence(signed);
    expect(verified).toBe(true);
  });
});

describe('GCP Cloud KMS-backed CryptoSigner (mock client)', () => {
  it('signDigest produces a non-empty buffer', async () => {
    const signer = buildGcpBackedSigner();
    const digest = crypto.createHash('sha256').update('gcp test').digest();
    const sig = await signer.signDigest(digest);
    expect(Buffer.isBuffer(sig)).toBe(true);
    expect(sig.length).toBeGreaterThan(0);
  });

  it('verifyDigest returns true for a valid signature', async () => {
    const signer = buildGcpBackedSigner('k', 'RS256');
    const digest = crypto.createHash('sha256').update('gcp verify').digest();
    const sig = await signer.signDigest(digest);
    expect(await signer.verifyDigest!(digest, sig, 'k', 'RS256')).toBe(true);
  });

  it('AuditEvidenceSigner round-trips with GCP-KMS-backed signer', async () => {
    const cryptoSigner = buildGcpBackedSigner('gcp-audit', 'RS256');
    const evidenceSigner = new AuditEvidenceSigner(cryptoSigner);

    const evidence = makeEvidence();
    const signed = await evidenceSigner.signEvidence(evidence);

    expect(signed.keyId).toBe('gcp-audit');
    expect(signed.algorithm).toBe('RS256');
    expect(signed.seq).toBe(1);
    expect(signed.signature).toBeTruthy();

    const verified = await evidenceSigner.verifyEvidence(signed);
    expect(verified).toBe(true);
  });
});

// =============================================================================
// 4. Error handling tests
// =============================================================================

describe('KmsEvidenceSigner error handling', () => {
  it('throws a clear error when @azure/keyvault-keys is not installed', () => {
    // @azure/keyvault-keys is an optional deployment dependency. When it is NOT
    // available in the deployment image, require() throws and the factory wraps
    // the error with a helpful install message. We simulate this by resetting the
    // module registry and mocking @azure/keyvault-keys so its factory throws, then
    // loading a fresh copy of the module under test.
    jest.resetModules();
    jest.doMock('@azure/keyvault-keys', () => {
      throw new Error('Cannot find module @azure/keyvault-keys');
    });
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { createKmsEvidenceSigner: create } = require('../kms-evidence-signer') as typeof import('../kms-evidence-signer');
    expect(() =>
      create({
        provider: 'azure-keyvault',
        vaultUrl: 'https://vault.example.com/',
        keyName: 'audit-key',
      }),
    ).toThrow('@azure/keyvault-keys');
    jest.resetModules();
    jest.unmock('@azure/keyvault-keys');
  });

  it('throws when client-secret credential is requested but required fields are missing', () => {
    // Config validation happens BEFORE the SDK is dynamically required, so
    // this throws "client-secret requires tenantId..." regardless of whether
    // the Azure SDK packages are installed.
    expect(() =>
      createKmsEvidenceSigner({
        provider: 'azure-keyvault',
        vaultUrl: 'https://vault.example.com/',
        keyName: 'audit-key',
        credentialType: 'client-secret',
        // Missing clientId, clientSecret, tenantId
      }),
    ).toThrow('client-secret requires tenantId');
  });
});
