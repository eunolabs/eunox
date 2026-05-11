/**
 * KMS-backed EvidenceSigner — Task 5 (Stage 3)
 * ────────────────────────────────────────────────────────────────────────────
 * Implements {@link EvidenceSigner} via three pluggable cloud-KMS drivers:
 *
 *   • Azure Key Vault (`provider: 'azure-keyvault'`)
 *   • AWS KMS          (`provider: 'aws-kms'`)
 *   • GCP Cloud KMS    (`provider: 'gcp-cloudkms'`)
 *
 * All drivers implement the {@link CryptoSigner} interface so they slot
 * directly into the existing {@link AuditEvidenceSigner}. The canonical
 * evidence form and chain semantics are therefore **identical** to those
 * produced by the software signer — only the `signature` bytes, `keyId`,
 * and `algorithm` fields differ.
 *
 * ### Pre-computed digest contract
 *
 * {@link AuditEvidenceSigner} always pre-hashes the canonical evidence string
 * with SHA-256 before calling {@link CryptoSigner.signDigest}. Each driver
 * therefore calls the KMS "sign digest" API (not the "sign message" API) so
 * the digest bytes are transmitted as-is and the KMS does NOT re-hash them.
 * Concretely:
 *   • Azure Key Vault — `CryptographyClient.sign(algorithm, digest)` where
 *     `digest` is the 32-byte SHA-256 output.
 *   • AWS KMS — `SignCommand({ MessageType: 'DIGEST', Message: digest, ... })`.
 *   • GCP Cloud KMS — `asymmetricSign({ digest: { sha256: digest }, ... })`.
 *
 * ### Optional SDK dependencies
 *
 * The cloud SDKs are **not** hard dependencies of `@euno/common-infra` — they
 * are dynamically `require()`d at driver construction time. Callers are
 * responsible for installing whichever SDK they actually use in their
 * deployment image. A clear error message is thrown if the SDK is absent.
 *
 * ### Usage
 *
 * ```typescript
 * import { createKmsEvidenceSigner } from '@euno/common-infra';
 *
 * const signer = createKmsEvidenceSigner({
 *   provider: 'aws-kms',
 *   keyId: 'arn:aws:kms:us-east-1:123456789012:key/…',
 *   region: 'us-east-1',
 *   algorithm: 'RS256',
 *   logicalKeyId: 'audit-signing-key-v1',
 * });
 * ```
 *
 * Or from environment variables in the gateway bootstrap:
 *
 * ```typescript
 * import { createKmsEvidenceSignerFromEnv } from '@euno/common-infra';
 *
 * const signer = createKmsEvidenceSignerFromEnv(process.env);
 * // undefined when AUDIT_SIGNING_KMS_PROVIDER is not set
 * ```
 */

import {
  AuditEvidenceSigner,
  CryptoSigner,
} from '@euno/common-core';

// ── Algorithm maps ────────────────────────────────────────────────────────────

/**
 * Canonical JWS algorithm names the gateway embeds in every signed record.
 * The evidence signer always pre-computes a SHA-256 digest, so only
 * SHA-256-family algorithms are supported.
 *
 * Additional algorithms can be added here when a deployment requires
 * SHA-384 / SHA-512 (e.g. specific GCP/AWS key types) — add the mapping and
 * update the `SUPPORTED_KMS_ALGORITHMS` guard accordingly.
 */
const CANONICAL_ALGORITHM: Record<string, string> = {
  RS256: 'RS256',
  PS256: 'PS256',
  ES256: 'ES256',
};

/** All algorithms the KMS drivers support (upper-cased for comparisons). */
const SUPPORTED_KMS_ALGORITHMS = new Set(['RS256', 'PS256', 'ES256']);

/** Mapping from canonical JWS name → Azure Key Vault algorithm name. */
const AKV_ALGORITHM: Record<string, string> = {
  RS256: 'RS256',
  PS256: 'PS256',
  ES256: 'ES256',
};

/** Mapping from canonical JWS name → AWS KMS `SigningAlgorithm` string. */
const AWS_SIGNING_ALGORITHM: Record<string, string> = {
  RS256: 'RSASSA_PKCS1_V1_5_SHA_256',
  PS256: 'RSASSA_PSS_SHA_256',
  ES256: 'ECDSA_SHA_256',
};

// ── Config types ──────────────────────────────────────────────────────────────

/**
 * Common fields shared by all KMS provider configs.
 */
interface KmsCommonConfig {
  /**
   * Logical key identifier recorded in every signed evidence record.
   *
   * This is the stable, human-readable name that appears in `SignedAuditEvidence.keyId`
   * and in OCSF enrichment fields. It does NOT need to match the provider's
   * internal key ARN/name — it should be a short, meaningful label that
   * operators can recognise in the audit log (e.g. `audit-signing-key-v2`).
   *
   * When omitted, the implementation derives a default from the provider-
   * specific key reference (e.g. the last segment of an ARN or the key name).
   */
  logicalKeyId?: string;
  /**
   * JWS canonical algorithm name. Defaults to `RS256`.
   * Supported: `RS256`, `PS256`, `ES256`.
   *
   * The evidence signer always pre-hashes with SHA-256; all supported
   * algorithms apply RSA-PKCS1v1.5, RSA-PSS, or ECDSA over that digest.
   */
  algorithm?: string;
  /**
   * Optional chain seed for resuming a chain after process restart.
   * Passed directly to {@link AuditEvidenceSigner}.
   */
  chainSeed?: { previousHash: string; seq: number };
}

/**
 * Azure Key Vault driver configuration.
 *
 * Authentication uses one of:
 *   - `credentialType: 'default'` (recommended): `DefaultAzureCredential` from
 *     `@azure/identity` — workload identity, managed identity, or the standard
 *     `AZURE_*` env vars (client secret, certificate, etc.) are tried in order.
 *   - `credentialType: 'managed-identity'`: `ManagedIdentityCredential` with
 *     an optional `clientId` for user-assigned identities.
 *   - `credentialType: 'client-secret'`: `ClientSecretCredential` — requires
 *     `tenantId`, `clientId`, and `clientSecret`.
 *
 * The `@azure/keyvault-keys` and `@azure/identity` packages MUST be installed
 * in the deployment image.
 */
export interface AzureKeyVaultKmsConfig extends KmsCommonConfig {
  provider: 'azure-keyvault';
  /** Key Vault base URL. Example: `https://my-vault.vault.azure.net/`. */
  vaultUrl: string;
  /** Key name within the vault. Example: `audit-signing-key`. */
  keyName: string;
  /**
   * Optional specific key version. Omit to always use the latest version
   * (recommended so key rotations take effect on the next process restart
   * without a config change).
   */
  keyVersion?: string;
  /** Credential strategy. Defaults to `'default'` (DefaultAzureCredential). */
  credentialType?: 'default' | 'managed-identity' | 'client-secret';
  /** Required when `credentialType === 'managed-identity'` (user-assigned identity). */
  clientId?: string;
  /** Required when `credentialType === 'client-secret'`. */
  clientSecret?: string;
  /** Required when `credentialType === 'client-secret'`. */
  tenantId?: string;
}

/**
 * AWS KMS driver configuration.
 *
 * Authentication uses the standard AWS credential provider chain
 * (`@aws-sdk/credential-providers`) — IAM role, IRSA, EC2 instance profile,
 * `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` env vars, or a shared
 * credentials file. Explicit credentials can be supplied via `accessKeyId`,
 * `secretAccessKey`, and `sessionToken` to override the chain.
 *
 * The `@aws-sdk/client-kms` package MUST be installed in the deployment image.
 */
export interface AwsKmsConfig extends KmsCommonConfig {
  provider: 'aws-kms';
  /**
   * Key ARN, key ID, or alias ARN.
   * Example: `arn:aws:kms:us-east-1:123456789012:key/mrk-…` or `alias/audit-key`.
   */
  keyId: string;
  /** AWS region. Defaults to the SDK default (e.g. `AWS_REGION` env var). */
  region?: string;
  /** Optional explicit AWS access key ID (overrides credential chain). */
  accessKeyId?: string;
  /** Optional explicit AWS secret access key (overrides credential chain). */
  secretAccessKey?: string;
  /** Optional AWS STS session token (for temporary credentials). */
  sessionToken?: string;
}

/**
 * GCP Cloud KMS driver configuration.
 *
 * Authentication uses Application Default Credentials (ADC) — Workload
 * Identity, service account key file (`GOOGLE_APPLICATION_CREDENTIALS`), or
 * `gcloud auth application-default login` in development. An explicit key
 * file path can be supplied via `keyFilePath`.
 *
 * The `@google-cloud/kms` package MUST be installed in the deployment image.
 */
export interface GcpCloudKmsConfig extends KmsCommonConfig {
  provider: 'gcp-cloudkms';
  /** GCP project ID. */
  projectId: string;
  /** KMS location (region or `global`). Defaults to `global`. */
  locationId?: string;
  /** Key ring ID. */
  keyRingId: string;
  /** Crypto key ID. */
  cryptoKeyId: string;
  /**
   * Crypto key version number. Defaults to `'1'` when omitted.
   *
   * GCP Cloud KMS `asymmetricSign` requires an explicit `CryptoKeyVersion`
   * resource name — there is no automatic "primary version" resolution for
   * asymmetric keys (unlike symmetric keys). When omitted, the driver pins
   * to version `1`. Update this field (or `AUDIT_SIGNING_GCP_CRYPTOKEY_VERSION`)
   * when rotating to a new key version.
   */
  cryptoKeyVersion?: string;
  /**
   * Optional path to a GCP service account key file. When set, this overrides
   * Application Default Credentials for this client only.
   */
  keyFilePath?: string;
}

/** Union of all supported KMS provider configs. */
export type KmsEvidenceSignerConfig =
  | AzureKeyVaultKmsConfig
  | AwsKmsConfig
  | GcpCloudKmsConfig;

// ── Validation ────────────────────────────────────────────────────────────────

function resolveAlgorithm(raw: string | undefined): string {
  const upper = (raw ?? 'RS256').toUpperCase();
  const canonical = CANONICAL_ALGORITHM[upper];
  if (!canonical || !SUPPORTED_KMS_ALGORITHMS.has(upper)) {
    throw new Error(
      `KmsEvidenceSigner: unsupported algorithm '${raw}'. ` +
        'Supported: RS256, PS256, ES256.',
    );
  }
  return canonical;
}

// ── Azure Key Vault CryptoSigner ──────────────────────────────────────────────

/**
 * {@link CryptoSigner} backed by Azure Key Vault.
 *
 * Calls `CryptographyClient.sign(algorithm, digest)` with the pre-computed
 * SHA-256 digest so the vault never re-hashes the message. The call happens
 * inside the HSM boundary — the raw private key material is never exported.
 *
 * @internal
 */
class AzureKeyVaultCryptoSigner implements CryptoSigner {
  private readonly algorithm: string;
  private readonly akvAlgorithm: string;
  private readonly keyId: string;
  // The SDK types are not available at module load time (dynamic require).
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private readonly cryptoClient: any;

  constructor(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    cryptoClient: any,
    algorithm: string,
    keyId: string,
  ) {
    this.cryptoClient = cryptoClient;
    this.algorithm = algorithm;
    this.akvAlgorithm = AKV_ALGORITHM[algorithm]!;
    this.keyId = keyId;
  }

  async signDigest(digest: Buffer): Promise<Buffer> {
    // AKV's sign() accepts a Uint8Array digest when the algorithm implies
    // a pre-computed hash.  The SDK converts between KV API response types
    // and Uint8Array automatically.
    const result = await this.cryptoClient.sign(this.akvAlgorithm, digest);
    const sig = result.result as Uint8Array | Buffer;
    return Buffer.isBuffer(sig) ? sig : Buffer.from(sig);
  }

  async verifyDigest(
    digest: Buffer,
    signature: Buffer,
    _keyId: string,
    algorithm: string,
  ): Promise<boolean> {
    if (algorithm.toUpperCase() !== this.algorithm) {
      return false;
    }
    const result = await this.cryptoClient.verify(
      this.akvAlgorithm,
      digest,
      signature,
    );
    return !!result.result;
  }

  async getKeyId(): Promise<string> {
    return this.keyId;
  }

  getAlgorithm(): string {
    return this.algorithm;
  }
}

/**
 * Build an Azure Key Vault {@link CryptoSigner}.
 *
 * Dynamically requires `@azure/keyvault-keys` and `@azure/identity` so the
 * `@euno/common-infra` package does not declare them as hard dependencies.
 */
function buildAzureKeyVaultCryptoSigner(config: AzureKeyVaultKmsConfig): CryptoSigner {
  // Validate config BEFORE dynamically requiring SDKs so that invalid
  // configuration surfaces as a clear config error rather than an opaque
  // "SDK not installed" message.
  const credType = config.credentialType ?? 'default';
  if (credType === 'client-secret') {
    if (!config.tenantId || !config.clientId || !config.clientSecret) {
      throw new Error(
        'KmsEvidenceSigner (azure-keyvault): credentialType=client-secret requires tenantId, clientId, and clientSecret.',
      );
    }
  }
  const algorithm = resolveAlgorithm(config.algorithm);

  let AzureKeyVaultModule: {
    CryptographyClient: new (
      keyId: string,
      credential: unknown,
      options?: unknown,
    ) => unknown;
  };
  let AzureIdentityModule: {
    DefaultAzureCredential: new () => unknown;
    ManagedIdentityCredential: new (clientId?: string) => unknown;
    ClientSecretCredential: new (
      tenantId: string,
      clientId: string,
      clientSecret: string,
    ) => unknown;
  };

  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
    AzureKeyVaultModule = require('@azure/keyvault-keys');
  } catch {
    throw new Error(
      'KmsEvidenceSigner (azure-keyvault): the @azure/keyvault-keys package is not installed. ' +
        'Add it to your deployment image: npm install @azure/keyvault-keys',
    );
  }

  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
    AzureIdentityModule = require('@azure/identity');
  } catch {
    throw new Error(
      'KmsEvidenceSigner (azure-keyvault): the @azure/identity package is not installed. ' +
        'Add it to your deployment image: npm install @azure/identity',
    );
  }

  // Build the Azure credential.
  let credential: unknown;
  if (credType === 'managed-identity') {
    credential = new AzureIdentityModule.ManagedIdentityCredential(config.clientId);
  } else if (credType === 'client-secret') {
    // Already validated above: tenantId, clientId, clientSecret are present.
    credential = new AzureIdentityModule.ClientSecretCredential(
      config.tenantId!,
      config.clientId!,
      config.clientSecret!,
    );
  } else {
    // 'default' — tries workload identity, managed identity, env vars, etc.
    credential = new AzureIdentityModule.DefaultAzureCredential();
  }

  // Build the key identifier — `https://<vault>.vault.azure.net/keys/<name>[/<version>]`.
  const keyRef = config.keyVersion
    ? `${config.vaultUrl.replace(/\/$/, '')}/keys/${config.keyName}/${config.keyVersion}`
    : `${config.vaultUrl.replace(/\/$/, '')}/keys/${config.keyName}`;

  const cryptoClient = new AzureKeyVaultModule.CryptographyClient(
    keyRef,
    credential,
  );

  const keyId = config.logicalKeyId ?? `akv:${config.vaultUrl.replace(/^https?:\/\//, '')}:${config.keyName}`;

  return new AzureKeyVaultCryptoSigner(cryptoClient, algorithm, keyId);
}

// ── AWS KMS CryptoSigner ──────────────────────────────────────────────────────

/**
 * {@link CryptoSigner} backed by AWS KMS.
 *
 * Uses `SignCommand` with `MessageType: 'DIGEST'` so AWS KMS receives the
 * pre-hashed SHA-256 bytes and applies the configured signing algorithm
 * without re-hashing. The private key never leaves the KMS HSM boundary.
 *
 * @internal
 */
class AwsKmsCryptoSigner implements CryptoSigner {
  private readonly algorithm: string;
  private readonly awsSigningAlgorithm: string;
  private readonly awsKeyId: string;
  private readonly logicalKeyId: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private readonly kmsClient: any;

  constructor(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    kmsClient: any,
    awsKeyId: string,
    algorithm: string,
    logicalKeyId: string,
  ) {
    this.kmsClient = kmsClient;
    this.awsKeyId = awsKeyId;
    this.algorithm = algorithm;
    this.awsSigningAlgorithm = AWS_SIGNING_ALGORITHM[algorithm]!;
    this.logicalKeyId = logicalKeyId;
  }

  async signDigest(digest: Buffer): Promise<Buffer> {
    // eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
    const { SignCommand } = require('@aws-sdk/client-kms');
    const response = await this.kmsClient.send(
      new SignCommand({
        KeyId: this.awsKeyId,
        // 'DIGEST' tells KMS the caller has already hashed the message.
        MessageType: 'DIGEST',
        Message: digest,
        SigningAlgorithm: this.awsSigningAlgorithm,
      }),
    );
    if (!response.Signature) {
      throw new Error('KmsEvidenceSigner (aws-kms): SignCommand returned no Signature');
    }
    const sig = response.Signature as Uint8Array | Buffer;
    return Buffer.isBuffer(sig) ? sig : Buffer.from(sig);
  }

  async verifyDigest(
    digest: Buffer,
    signature: Buffer,
    _keyId: string,
    algorithm: string,
  ): Promise<boolean> {
    if (algorithm.toUpperCase() !== this.algorithm) {
      return false;
    }
    // eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
    const { VerifyCommand } = require('@aws-sdk/client-kms');
    try {
      const response = await this.kmsClient.send(
        new VerifyCommand({
          KeyId: this.awsKeyId,
          MessageType: 'DIGEST',
          Message: digest,
          Signature: signature,
          SigningAlgorithm: this.awsSigningAlgorithm,
        }),
      );
      return !!response.SignatureValid;
    } catch {
      // KMS throws `KMSInvalidSignatureException` on mismatch; return false.
      return false;
    }
  }

  async getKeyId(): Promise<string> {
    return this.logicalKeyId;
  }

  getAlgorithm(): string {
    return this.algorithm;
  }
}

/**
 * Build an AWS KMS {@link CryptoSigner}.
 *
 * Dynamically requires `@aws-sdk/client-kms` so the package is not a hard
 * dependency of `@euno/common-infra`.
 */
function buildAwsKmsCryptoSigner(config: AwsKmsConfig): CryptoSigner {
  // Validate algorithm BEFORE dynamically requiring the SDK so that an
  // unsupported algorithm surfaces as a clear config error.
  const algorithm = resolveAlgorithm(config.algorithm);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let kmsClientModule: { KMSClient: new (cfg: Record<string, unknown>) => any };
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
    kmsClientModule = require('@aws-sdk/client-kms');
  } catch {
    throw new Error(
      'KmsEvidenceSigner (aws-kms): the @aws-sdk/client-kms package is not installed. ' +
        'Add it to your deployment image: npm install @aws-sdk/client-kms',
    );
  }

  // Build the KMSClient config.  Omitting properties that are `undefined`
  // keeps the SDK from overriding its internal credential-provider chain.
  const clientCfg: Record<string, unknown> = {};
  if (config.region) clientCfg.region = config.region;
  if (config.accessKeyId && config.secretAccessKey) {
    clientCfg.credentials = {
      accessKeyId: config.accessKeyId,
      secretAccessKey: config.secretAccessKey,
      ...(config.sessionToken ? { sessionToken: config.sessionToken } : {}),
    };
  }

  const kmsClient = new kmsClientModule.KMSClient(clientCfg);
  // Default logical key ID: derive a concise label from the ARN or alias.
  const defaultKeyId = config.keyId.startsWith('arn:')
    ? config.keyId.split('/').pop() ?? config.keyId
    : config.keyId;
  const logicalKeyId = config.logicalKeyId ?? `aws-kms:${defaultKeyId}`;

  return new AwsKmsCryptoSigner(kmsClient, config.keyId, algorithm, logicalKeyId);
}

// ── GCP Cloud KMS CryptoSigner ────────────────────────────────────────────────

/**
 * {@link CryptoSigner} backed by GCP Cloud KMS.
 *
 * Uses `asymmetricSign` with a `digest.sha256` field so GCP KMS receives the
 * pre-hashed SHA-256 bytes. For ECDSA keys, GCP returns the DER-encoded
 * signature — this is converted to IEEE P1363 (r‖s) format for consistency
 * with the software signer (JWS ES256 convention).
 *
 * @internal
 */
class GcpCloudKmsCryptoSigner implements CryptoSigner {
  private readonly algorithm: string;
  private readonly keyVersionName: string;
  private readonly logicalKeyId: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private readonly kmsClient: any;

  constructor(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    kmsClient: any,
    keyVersionName: string,
    algorithm: string,
    logicalKeyId: string,
  ) {
    this.kmsClient = kmsClient;
    this.keyVersionName = keyVersionName;
    this.algorithm = algorithm;
    this.logicalKeyId = logicalKeyId;
  }

  async signDigest(digest: Buffer): Promise<Buffer> {
    const [response] = await this.kmsClient.asymmetricSign({
      name: this.keyVersionName,
      digest: { sha256: digest },
    });

    if (!response.signature) {
      throw new Error('KmsEvidenceSigner (gcp-cloudkms): asymmetricSign returned no signature');
    }

    const rawSig = response.signature as Uint8Array | Buffer;
    const sigBuf = Buffer.isBuffer(rawSig) ? rawSig : Buffer.from(rawSig);

    // GCP returns ECDSA signatures in DER format.  The software signer uses
    // IEEE P1363 (r‖s) for JWS ES256 compliance; convert if necessary.
    if (this.algorithm === 'ES256') {
      return derToIeeeP1363(sigBuf, 32);
    }
    return sigBuf;
  }

  async verifyDigest(
    digest: Buffer,
    signature: Buffer,
    _keyId: string,
    algorithm: string,
  ): Promise<boolean> {
    if (algorithm.toUpperCase() !== this.algorithm) {
      return false;
    }
    try {
      // For verification, GCP also accepts DER-encoded ECDSA signatures.
      // Convert from P1363 back to DER if we stored a P1363 signature.
      const sigForVerify = this.algorithm === 'ES256'
        ? ieeeP1363ToDer(signature, 32)
        : signature;

      const [response] = await this.kmsClient.asymmetricVerify({
        name: this.keyVersionName,
        digest: { sha256: digest },
        signature: sigForVerify,
      });
      return !!response.success;
    } catch {
      return false;
    }
  }

  async getKeyId(): Promise<string> {
    return this.logicalKeyId;
  }

  getAlgorithm(): string {
    return this.algorithm;
  }
}

/**
 * Build a GCP Cloud KMS {@link CryptoSigner}.
 *
 * Dynamically requires `@google-cloud/kms`.
 */
function buildGcpCloudKmsCryptoSigner(config: GcpCloudKmsConfig): CryptoSigner {
  // Validate algorithm BEFORE dynamically requiring the SDK.
  const algorithm = resolveAlgorithm(config.algorithm);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let kmsModule: { KeyManagementServiceClient: new (cfg?: Record<string, unknown>) => any };
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
    kmsModule = require('@google-cloud/kms');
  } catch {
    throw new Error(
      'KmsEvidenceSigner (gcp-cloudkms): the @google-cloud/kms package is not installed. ' +
        'Add it to your deployment image: npm install @google-cloud/kms',
    );
  }

  const clientCfg: Record<string, unknown> = {};
  if (config.keyFilePath) {
    clientCfg.keyFilename = config.keyFilePath;
  }

  const kmsClient = new kmsModule.KeyManagementServiceClient(
    Object.keys(clientCfg).length > 0 ? clientCfg : undefined,
  );

  const locationId = config.locationId ?? 'global';
  // GCP Cloud KMS `asymmetricSign` requires an explicit CryptoKeyVersion path;
  // there is no automatic "primary version" resolution for asymmetric keys.
  // When the caller omits `cryptoKeyVersion`, we default to version 1.
  // Operators must update this value (or `AUDIT_SIGNING_GCP_CRYPTOKEY_VERSION`)
  // when rotating to a new key version.
  const versionId = config.cryptoKeyVersion ?? '1';

  // CryptoKeyVersion resource name format:
  // projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}/cryptoKeyVersions/{version}
  const keyVersionName = kmsClient.cryptoKeyVersionPath(
    config.projectId,
    locationId,
    config.keyRingId,
    config.cryptoKeyId,
    versionId,
  );

  const logicalKeyId =
    config.logicalKeyId ??
    `gcp-kms:${config.projectId}/${config.keyRingId}/${config.cryptoKeyId}`;

  return new GcpCloudKmsCryptoSigner(kmsClient, keyVersionName, algorithm, logicalKeyId);
}

// ── ECDSA DER ↔ IEEE P1363 helpers ───────────────────────────────────────────

/**
 * Convert an ECDSA signature from DER (ASN.1 SEQUENCE { INTEGER r, INTEGER s })
 * to IEEE P1363 (r‖s raw bytes, each zero-padded to `coordBytes` bytes).
 *
 * GCP Cloud KMS returns DER-encoded ECDSA signatures.  The software signer
 * uses P1363 (JWS / IEEE P1363 §5.2 format) so we normalise to P1363 for
 * consistency with existing signed records.
 */
function derToIeeeP1363(der: Buffer, coordBytes: number): Buffer {
  // DER structure: 0x30 <len> 0x02 <rLen> <r bytes> 0x02 <sLen> <s bytes>
  if (der[0] !== 0x30) {
    // Already non-DER, return as-is.
    return der;
  }
  let offset = 2; // Skip SEQUENCE tag + length.
  if (der[1] === 0x81) {
    offset = 3; // Extended length encoding.
  }

  if (der[offset] !== 0x02) {
    throw new Error('KmsEvidenceSigner: malformed DER ECDSA signature (expected INTEGER tag for r)');
  }
  const rLen = der[offset + 1]!;
  let rStart = offset + 2;
  let r = der.slice(rStart, rStart + rLen);
  // Strip leading zero byte (DER uses it to keep r positive).
  if (r[0] === 0x00) r = r.slice(1);

  const sTagOffset = rStart + rLen;
  if (der[sTagOffset] !== 0x02) {
    throw new Error('KmsEvidenceSigner: malformed DER ECDSA signature (expected INTEGER tag for s)');
  }
  const sLen = der[sTagOffset + 1]!;
  let sStart = sTagOffset + 2;
  let s = der.slice(sStart, sStart + sLen);
  if (s[0] === 0x00) s = s.slice(1);

  const result = Buffer.alloc(coordBytes * 2, 0);
  r.copy(result, coordBytes - r.length);
  s.copy(result, coordBytes * 2 - s.length);
  return result;
}

/**
 * Convert an ECDSA signature from IEEE P1363 (r‖s) to DER encoding.
 *
 * Used when calling GCP's `asymmetricVerify` which expects DER-encoded
 * signatures.
 */
function ieeeP1363ToDer(p1363: Buffer, coordBytes: number): Buffer {
  let r = p1363.slice(0, coordBytes);
  let s = p1363.slice(coordBytes);

  // Prepend 0x00 if the high bit is set (DER INTEGER is signed big-endian).
  if (r[0]! & 0x80) r = Buffer.concat([Buffer.from([0x00]), r]);
  if (s[0]! & 0x80) s = Buffer.concat([Buffer.from([0x00]), s]);

  const seqContent = Buffer.concat([
    Buffer.from([0x02, r.length]),
    r,
    Buffer.from([0x02, s.length]),
    s,
  ]);
  return Buffer.concat([Buffer.from([0x30, seqContent.length]), seqContent]);
}

// ── Public factories ──────────────────────────────────────────────────────────

/**
 * Build a {@link CryptoSigner} backed by the KMS provider in `config`.
 *
 * This is the low-level primitive — use {@link createKmsEvidenceSigner} for
 * a fully wrapped {@link AuditEvidenceSigner} with chain-state management.
 */
export function createKmsCryptoSigner(config: KmsEvidenceSignerConfig): CryptoSigner {
  switch (config.provider) {
    case 'azure-keyvault':
      return buildAzureKeyVaultCryptoSigner(config);
    case 'aws-kms':
      return buildAwsKmsCryptoSigner(config);
    case 'gcp-cloudkms':
      return buildGcpCloudKmsCryptoSigner(config);
    default: {
      // TypeScript exhaustiveness — this branch is unreachable at runtime.
      const _exhaustive: never = config;
      throw new Error(`KmsEvidenceSigner: unknown provider '${(_exhaustive as KmsEvidenceSignerConfig).provider}'`);
    }
  }
}

/**
 * Build an {@link AuditEvidenceSigner} backed by the configured KMS provider.
 *
 * The returned signer is functionally identical to one built by
 * {@link createSoftwareEvidenceSigner}: it implements the same
 * {@link EvidenceSigner} and {@link AuditBatchSigner} seams, uses the same
 * canonical evidence form and hash-chain linkage, and its `SignedAuditEvidence`
 * records are byte-identical to those the software signer would produce for
 * the same input — only `signature`, `keyId`, and `algorithm` differ.
 *
 * ### Chain continuity across restarts
 *
 * Supply `config.chainSeed` (the output of a previous `getChainState()` call)
 * to maintain hash-chain continuity across process restarts. Without seeding,
 * each restart begins a fresh chain segment starting at seq=1 with
 * `previousHash=GENESIS_HASH`.
 */
export function createKmsEvidenceSigner(config: KmsEvidenceSignerConfig): AuditEvidenceSigner {
  const cryptoSigner = createKmsCryptoSigner(config);
  return new AuditEvidenceSigner(cryptoSigner, config.chainSeed);
}

// ── Environment-variable factory ──────────────────────────────────────────────

/**
 * Build a KMS-backed {@link AuditEvidenceSigner} from environment variables.
 *
 * Returns `undefined` when `AUDIT_SIGNING_KMS_PROVIDER` is not set, allowing
 * the caller to fall back to the software signer (see
 * {@link createSoftwareEvidenceSignerFromEnv}).
 *
 * ### Environment variables
 *
 * | Variable | Description |
 * |---|---|
 * | `AUDIT_SIGNING_KMS_PROVIDER` | Required. One of `azure-keyvault`, `aws-kms`, `gcp-cloudkms`. |
 * | `AUDIT_SIGNING_KEY_ID` | Logical key ID stamped on each record. Provider-derived when omitted. |
 * | `AUDIT_SIGNING_ALGORITHM` | JWS algorithm. Defaults to `RS256`. Supported: `RS256`, `PS256`, `ES256`. |
 * | **Azure Key Vault** | |
 * | `AUDIT_SIGNING_AZURE_KEYVAULT_URL` | Required when provider=`azure-keyvault`. |
 * | `AUDIT_SIGNING_AZURE_KEY_NAME` | Required when provider=`azure-keyvault`. |
 * | `AUDIT_SIGNING_AZURE_KEY_VERSION` | Optional. Defaults to latest. |
 * | `AUDIT_SIGNING_AZURE_CREDENTIAL_TYPE` | `default` (default), `managed-identity`, or `client-secret`. |
 * | `AUDIT_SIGNING_AZURE_CLIENT_ID` | Required when `AUDIT_SIGNING_AZURE_CREDENTIAL_TYPE=client-secret`. |
 * | `AUDIT_SIGNING_AZURE_CLIENT_SECRET` | Required when `AUDIT_SIGNING_AZURE_CREDENTIAL_TYPE=client-secret`. |
 * | `AUDIT_SIGNING_AZURE_TENANT_ID` | Required when `AUDIT_SIGNING_AZURE_CREDENTIAL_TYPE=client-secret`. |
 * | **AWS KMS** | |
 * | `AUDIT_SIGNING_AWS_KMS_KEY_ID` | Required when provider=`aws-kms`. |
 * | `AUDIT_SIGNING_AWS_KMS_REGION` | Optional. Defaults to SDK default (`AWS_REGION` env var). |
 * | **GCP Cloud KMS** | |
 * | `AUDIT_SIGNING_GCP_PROJECT_ID` | Required when provider=`gcp-cloudkms`. |
 * | `AUDIT_SIGNING_GCP_LOCATION_ID` | Optional. Defaults to `global`. |
 * | `AUDIT_SIGNING_GCP_KEYRING_ID` | Required when provider=`gcp-cloudkms`. |
 * | `AUDIT_SIGNING_GCP_CRYPTOKEY_ID` | Required when provider=`gcp-cloudkms`. |
 * | `AUDIT_SIGNING_GCP_CRYPTOKEY_VERSION` | Optional. Defaults to `1`. Update on key rotation (asymmetric keys require an explicit version). |
 * | `AUDIT_SIGNING_GCP_KEY_FILE_PATH` | Optional. Path to GCP service account key file. |
 */
export function createKmsEvidenceSignerFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): AuditEvidenceSigner | undefined {
  const provider = env.AUDIT_SIGNING_KMS_PROVIDER;
  if (!provider) {
    return undefined;
  }

  const logicalKeyId = env.AUDIT_SIGNING_KEY_ID || undefined;
  const algorithm = env.AUDIT_SIGNING_ALGORITHM || undefined;

  switch (provider) {
    case 'azure-keyvault': {
      const vaultUrl = env.AUDIT_SIGNING_AZURE_KEYVAULT_URL;
      const keyName = env.AUDIT_SIGNING_AZURE_KEY_NAME;
      if (!vaultUrl) {
        throw new Error(
          'KmsEvidenceSigner: AUDIT_SIGNING_AZURE_KEYVAULT_URL is required when ' +
            'AUDIT_SIGNING_KMS_PROVIDER=azure-keyvault.',
        );
      }
      if (!keyName) {
        throw new Error(
          'KmsEvidenceSigner: AUDIT_SIGNING_AZURE_KEY_NAME is required when ' +
            'AUDIT_SIGNING_KMS_PROVIDER=azure-keyvault.',
        );
      }
      const credType = (env.AUDIT_SIGNING_AZURE_CREDENTIAL_TYPE ?? 'default') as
        | 'default'
        | 'managed-identity'
        | 'client-secret';
      return createKmsEvidenceSigner({
        provider: 'azure-keyvault',
        vaultUrl,
        keyName,
        keyVersion: env.AUDIT_SIGNING_AZURE_KEY_VERSION || undefined,
        credentialType: credType,
        clientId: env.AUDIT_SIGNING_AZURE_CLIENT_ID || undefined,
        clientSecret: env.AUDIT_SIGNING_AZURE_CLIENT_SECRET || undefined,
        tenantId: env.AUDIT_SIGNING_AZURE_TENANT_ID || undefined,
        logicalKeyId,
        algorithm,
      });
    }

    case 'aws-kms': {
      const keyId = env.AUDIT_SIGNING_AWS_KMS_KEY_ID;
      if (!keyId) {
        throw new Error(
          'KmsEvidenceSigner: AUDIT_SIGNING_AWS_KMS_KEY_ID is required when ' +
            'AUDIT_SIGNING_KMS_PROVIDER=aws-kms.',
        );
      }
      return createKmsEvidenceSigner({
        provider: 'aws-kms',
        keyId,
        region: env.AUDIT_SIGNING_AWS_KMS_REGION || undefined,
        logicalKeyId,
        algorithm,
      });
    }

    case 'gcp-cloudkms': {
      const projectId = env.AUDIT_SIGNING_GCP_PROJECT_ID;
      const keyRingId = env.AUDIT_SIGNING_GCP_KEYRING_ID;
      const cryptoKeyId = env.AUDIT_SIGNING_GCP_CRYPTOKEY_ID;
      const missing: string[] = [];
      if (!projectId) missing.push('AUDIT_SIGNING_GCP_PROJECT_ID');
      if (!keyRingId) missing.push('AUDIT_SIGNING_GCP_KEYRING_ID');
      if (!cryptoKeyId) missing.push('AUDIT_SIGNING_GCP_CRYPTOKEY_ID');
      if (missing.length > 0) {
        throw new Error(
          `KmsEvidenceSigner: ${missing.join(', ')} ${missing.length > 1 ? 'are' : 'is'} required ` +
            'when AUDIT_SIGNING_KMS_PROVIDER=gcp-cloudkms.',
        );
      }
      // TypeScript cannot narrow after the compound missing-check above; the
      // branches above guarantee these strings are defined at this point.
      const gcpConfig: GcpCloudKmsConfig = {
        provider: 'gcp-cloudkms',
        projectId: projectId as string,
        locationId: env.AUDIT_SIGNING_GCP_LOCATION_ID || undefined,
        keyRingId: keyRingId as string,
        cryptoKeyId: cryptoKeyId as string,
        cryptoKeyVersion: env.AUDIT_SIGNING_GCP_CRYPTOKEY_VERSION || undefined,
        keyFilePath: env.AUDIT_SIGNING_GCP_KEY_FILE_PATH || undefined,
        logicalKeyId,
        algorithm,
      };
      return createKmsEvidenceSigner(gcpConfig);
    }

    default:
      throw new Error(
        `KmsEvidenceSigner: unrecognised AUDIT_SIGNING_KMS_PROVIDER value '${provider}'. ` +
          "Valid values: 'azure-keyvault', 'aws-kms', 'gcp-cloudkms'.",
      );
  }
}
