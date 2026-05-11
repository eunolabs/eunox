/**
 * KMS-backed TokenSigner — Task 11 (Stage 3)
 * ────────────────────────────────────────────────────────────────────────────
 * Implements {@link TokenSigner} via the same three cloud-KMS drivers used
 * by {@link KmsEvidenceSigner}:
 *
 *   • Azure Key Vault (`provider: 'azure-keyvault'`)
 *   • AWS KMS          (`provider: 'aws-kms'`)
 *   • GCP Cloud KMS    (`provider: 'gcp-cloudkms'`)
 *
 * ### Per-tenant key isolation
 *
 * The hosted gateway uses one HSM key per tenant (per the threat model in
 * docs/security/minter-threat-model.md §1 and §4).  {@link KmsTokenSigner}
 * supports this via an optional `tenantKeyMap: Record<string, string>` in the
 * config.  When supplied, the signer looks up the tenant's key ID from the
 * map using the `IssuanceContext.audience` value as the key (audience
 * corresponds to the gateway tenant identifier).  If no mapping is found, the
 * signer falls back to the default key configured for the provider.
 *
 * For more fine-grained isolation (per-policy or per-tenant + per-policy),
 * pass `policyKeyMap: Record<string, string>` whose keys are
 * `"${tenantId}:${policyHash}"` or plain `policyHash` strings (the same
 * composite-key convention used by the capability-issuer signers).
 *
 * ### JWT encoding
 *
 * The minter signs capability JWTs whose structure must be identical to those
 * produced by `@euno/capability-issuer`.  The JWT is assembled manually
 * (without `jose.SignJWT`) so the SHA-256 digest of the signing input can be
 * forwarded to the KMS "sign digest" API — identical to the evidence-signer
 * contract.  KMS never sees the raw signing input; it only receives the 32-byte
 * SHA-256 digest.
 *
 * ### Public-key retrieval
 *
 * `getPublicKey()` is required by `TokenSigner` so gateway verifiers can cache
 * the SPKI PEM and build JWKS responses.  Each driver calls the KMS
 * "get public key" API once and caches the result; subsequent calls are free.
 *
 * ### Optional SDK dependencies
 *
 * The cloud SDKs are **not** hard dependencies of `@euno/common-infra` — they
 * are dynamically `require()`d at initialisation time.  Callers are responsible
 * for installing whichever SDK they use.  A clear error is thrown if absent.
 *
 * ### Usage
 *
 * ```typescript
 * import { createKmsTokenSigner } from '@euno/common-infra';
 *
 * const signer = createKmsTokenSigner({
 *   provider: 'aws-kms',
 *   keyId: 'arn:aws:kms:…',
 *   region: 'us-east-1',
 *   algorithm: 'ES256',
 *   tenantKeyMap: {
 *     'tenant-acme': 'arn:aws:kms:…:key/tenant-acme-signing-key',
 *   },
 * });
 *
 * // In bootstrap, from env vars:
 * const signer = createKmsTokenSignerFromEnv(process.env);
 * ```
 */

import * as crypto from 'crypto';
import {
  TokenSigner,
  CapabilityTokenPayload,
  IssuanceContext,
} from '@euno/common-core';

// ── Supported algorithms ──────────────────────────────────────────────────────

/** JWS algorithms supported by all three KMS drivers. */
const SUPPORTED_KMS_ALGORITHMS = new Set(['RS256', 'PS256', 'ES256']);

/** Canonical JWS algorithm strings (upper-cased input → canonical form). */
const CANONICAL_ALGORITHM: Record<string, string> = {
  RS256: 'RS256',
  PS256: 'PS256',
  ES256: 'ES256',
};

/** AWS KMS `SigningAlgorithm` strings mapped from JWS names. */
const AWS_SIGNING_ALGORITHM: Record<string, string> = {
  RS256: 'RSASSA_PKCS1_V1_5_SHA_256',
  PS256: 'RSASSA_PSS_SHA_256',
  ES256: 'ECDSA_SHA_256',
};

/** Azure Key Vault algorithm names (same as JWS for these three). */
const AKV_ALGORITHM: Record<string, string> = {
  RS256: 'RS256',
  PS256: 'PS256',
  ES256: 'ES256',
};

function resolveAlgorithm(raw: string | undefined): string {
  const upper = (raw ?? 'ES256').toUpperCase();
  const canonical = CANONICAL_ALGORITHM[upper];
  if (!canonical || !SUPPORTED_KMS_ALGORITHMS.has(upper)) {
    throw new Error(
      `KmsTokenSigner: unsupported algorithm '${raw}'. Supported: RS256, PS256, ES256.`,
    );
  }
  return canonical;
}

// ── Config types ──────────────────────────────────────────────────────────────

/**
 * Fields shared by all three KMS provider configs.
 */
interface KmsTokenCommonConfig {
  /**
   * JWS algorithm. Defaults to `ES256` (recommended for HSM keys; threat
   * model §1 specifies EC P-256 / ES256 for the hosted offering).
   * Supported: `RS256`, `PS256`, `ES256`.
   */
  algorithm?: string;
  /**
   * Logical key identifier embedded in every JWT `kid` header.
   * When omitted, the driver derives a default from the provider-specific
   * key reference (e.g. last segment of an ARN, key name).
   */
  logicalKeyId?: string;
  /**
   * Per-tenant key map.  Keys are tenant identifiers (matching
   * `IssuanceContext.audience`) or composite `policyHash:audience` strings;
   * values are provider-specific key references.  When a mint request carries
   * an `IssuanceContext`, the signer resolves the tenant-specific key using
   * the same composite-key convention as `resolveIssuanceContextKey` in
   * `@euno/common-core`, giving each tenant its own HSM key boundary.
   *
   * Key format:
   * - `<policyHash>:<audience>` — combined policy + tenant isolation (exact match)
   * - `<audience>`              — tenant-level isolation (fallback)
   * - `<policyHash>`            — policy-level isolation (fallback)
   */
  tenantKeyMap?: Record<string, string>;
}

/** Azure Key Vault configuration for the token signer. */
export interface AzureKeyVaultTokenSignerConfig extends KmsTokenCommonConfig {
  provider: 'azure-keyvault';
  /** Key Vault base URL. Example: `https://my-vault.vault.azure.net/`. */
  vaultUrl: string;
  /** Default key name within the vault (used when no tenant mapping matches). */
  keyName: string;
  /** Optional specific key version. Omit to use the latest version. */
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

/** AWS KMS configuration for the token signer. */
export interface AwsKmsTokenSignerConfig extends KmsTokenCommonConfig {
  provider: 'aws-kms';
  /**
   * Default key ARN, key ID, or alias ARN (used when no tenant mapping matches).
   * Example: `arn:aws:kms:us-east-1:123456789012:key/mrk-…` or `alias/minter-key`.
   */
  keyId: string;
  /** AWS region. Defaults to `AWS_REGION` env var. */
  region?: string;
  /** Optional explicit access key (overrides credential chain). */
  accessKeyId?: string;
  /** Optional explicit secret access key. */
  secretAccessKey?: string;
  /** Optional STS session token (temporary credentials). */
  sessionToken?: string;
}

/** GCP Cloud KMS configuration for the token signer. */
export interface GcpCloudKmsTokenSignerConfig extends KmsTokenCommonConfig {
  provider: 'gcp-cloudkms';
  /** GCP project ID. */
  projectId: string;
  /** KMS location (HSM-capable region, e.g. `us-east1`). NOT `global` for HSM keys. */
  locationId: string;
  /** Key ring ID. */
  keyRingId: string;
  /** Default crypto key ID (used when no tenant mapping matches). */
  cryptoKeyId: string;
  /** Default crypto key version. Defaults to `'1'`. Must be updated on rotation. */
  cryptoKeyVersion?: string;
  /** Optional path to GCP service account key file. */
  keyFilePath?: string;
}

/** Union of all supported KMS provider configs for the token signer. */
export type KmsTokenSignerConfig =
  | AzureKeyVaultTokenSignerConfig
  | AwsKmsTokenSignerConfig
  | GcpCloudKmsTokenSignerConfig;

// ── Internal signing key abstraction ─────────────────────────────────────────

/**
 * Internal interface implemented by each KMS provider driver.
 *
 * NOT exported — callers use `KmsTokenSigner` through the `TokenSigner` seam.
 * The design mirrors `CryptoSigner` from `@euno/common-core` but adds
 * `getPublicKeyPem()` which is required for JWT verification path.
 */
interface KmsSigningDriver {
  /**
   * Sign the SHA-256 `digest` of `header.payload` and return the raw
   * signature bytes.  For ES256 the caller converts DER → P1363 if needed.
   */
  signDigest(digest: Buffer): Promise<Buffer>;
  /**
   * Return the SPKI PEM public key for this driver instance.
   * Used by `getPublicKey()` and JWKS endpoint construction.
   */
  getPublicKeyPem(): Promise<string>;
  /** Logical key ID embedded in the JWT `kid` header. */
  getKeyId(): string;
  /** JWS algorithm string (e.g. `ES256`). */
  getAlgorithm(): string;
}

// ── Azure Key Vault driver ────────────────────────────────────────────────────

class AzureKeyVaultSigningDriver implements KmsSigningDriver {
  private readonly algorithm: string;
  private readonly akvAlgorithm: string;
  private readonly keyId: string;
  private publicKeyPemCache: string | null = null;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private readonly cryptoClient: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private readonly keyClient: any;
  private readonly keyName: string;
  private readonly keyVersion?: string;

  constructor(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    cryptoClient: any,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    keyClient: any,
    algorithm: string,
    keyId: string,
    keyName: string,
    keyVersion?: string,
  ) {
    this.cryptoClient = cryptoClient;
    this.keyClient = keyClient;
    this.algorithm = algorithm;
    this.akvAlgorithm = AKV_ALGORITHM[algorithm]!;
    this.keyId = keyId;
    this.keyName = keyName;
    this.keyVersion = keyVersion;
  }

  async signDigest(digest: Buffer): Promise<Buffer> {
    const result = await this.cryptoClient.sign(this.akvAlgorithm, digest);
    const sig = result.result as Uint8Array | Buffer;
    return Buffer.isBuffer(sig) ? sig : Buffer.from(sig);
  }

  async getPublicKeyPem(): Promise<string> {
    if (this.publicKeyPemCache) {
      return this.publicKeyPemCache;
    }
    // Fetch key material from Key Vault to extract the public key.
    const key = await this.keyClient.getKey(
      this.keyName,
      this.keyVersion ? { version: this.keyVersion } : undefined,
    );
    if (!key.key) {
      throw new Error('KmsTokenSigner (azure-keyvault): key material not available from getKey()');
    }
    this.publicKeyPemCache = await buildSpkiPemFromAkvKey(key, this.algorithm);
    return this.publicKeyPemCache;
  }

  getKeyId(): string {
    return this.keyId;
  }

  getAlgorithm(): string {
    return this.algorithm;
  }
}

/**
 * Build an SPKI PEM public key string from an Azure Key Vault `KeyVaultKey`
 * object using `crypto.createPublicKey()` with a JWK input.  This avoids
 * a hard `jose` dependency in `@euno/common-infra`.
 *
 * Node.js v16.15+ supports `crypto.createPublicKey({ key: jwk, format: 'jwk' })`.
 */
async function buildSpkiPemFromAkvKey(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  key: any,
  algorithm: string,
): Promise<string> {
  const rawKey = key.key as Record<string, Uint8Array | Buffer | undefined>;

  let jwkForNode: crypto.JsonWebKey;

  if (rawKey.n && rawKey.e) {
    // RSA public key
    jwkForNode = {
      kty: 'RSA',
      n: Buffer.from(rawKey.n).toString('base64url'),
      e: Buffer.from(rawKey.e).toString('base64url'),
      alg: algorithm,
      use: 'sig',
    };
  } else if (rawKey.x && rawKey.y && (key.key.crv as string | undefined)) {
    // EC public key
    jwkForNode = {
      kty: 'EC',
      crv: key.key.crv as string,
      x: Buffer.from(rawKey.x).toString('base64url'),
      y: Buffer.from(rawKey.y).toString('base64url'),
      alg: algorithm,
      use: 'sig',
    };
  } else {
    throw new Error(
      'KmsTokenSigner (azure-keyvault): unrecognised key material; expected RSA (n,e) or EC (x,y,crv) fields.',
    );
  }

  const pubKey = crypto.createPublicKey({ key: jwkForNode, format: 'jwk' });
  return pubKey.export({ type: 'spki', format: 'pem' }) as string;
}

function buildAzureKeyVaultDriver(config: AzureKeyVaultTokenSignerConfig): KmsSigningDriver {
  const credType = config.credentialType ?? 'default';
  if (credType === 'client-secret') {
    if (!config.tenantId || !config.clientId || !config.clientSecret) {
      throw new Error(
        'KmsTokenSigner (azure-keyvault): credentialType=client-secret requires tenantId, clientId, and clientSecret.',
      );
    }
  }
  const algorithm = resolveAlgorithm(config.algorithm);

  let AzureKeyVaultModule: {
    CryptographyClient: new (keyId: string, credential: unknown) => unknown;
    KeyClient: new (vaultUrl: string, credential: unknown) => unknown;
  };
  let AzureIdentityModule: {
    DefaultAzureCredential: new () => unknown;
    ManagedIdentityCredential: new (clientId?: string) => unknown;
    ClientSecretCredential: new (tenantId: string, clientId: string, clientSecret: string) => unknown;
  };

  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
    AzureKeyVaultModule = require('@azure/keyvault-keys');
  } catch {
    throw new Error(
      'KmsTokenSigner (azure-keyvault): the @azure/keyvault-keys package is not installed. ' +
        'Add it to your deployment image: npm install @azure/keyvault-keys',
    );
  }

  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
    AzureIdentityModule = require('@azure/identity');
  } catch {
    throw new Error(
      'KmsTokenSigner (azure-keyvault): the @azure/identity package is not installed. ' +
        'Add it to your deployment image: npm install @azure/identity',
    );
  }

  let credential: unknown;
  if (credType === 'managed-identity') {
    credential = new AzureIdentityModule.ManagedIdentityCredential(config.clientId);
  } else if (credType === 'client-secret') {
    credential = new AzureIdentityModule.ClientSecretCredential(
      config.tenantId!,
      config.clientId!,
      config.clientSecret!,
    );
  } else {
    credential = new AzureIdentityModule.DefaultAzureCredential();
  }

  const keyRef = config.keyVersion
    ? `${config.vaultUrl.replace(/\/$/, '')}/keys/${config.keyName}/${config.keyVersion}`
    : `${config.vaultUrl.replace(/\/$/, '')}/keys/${config.keyName}`;

  const cryptoClient = new AzureKeyVaultModule.CryptographyClient(keyRef, credential);
  const keyClient = new AzureKeyVaultModule.KeyClient(config.vaultUrl, credential);

  const keyId =
    config.logicalKeyId ?? `akv:${config.vaultUrl.replace(/^https?:\/\//, '')}:${config.keyName}`;

  return new AzureKeyVaultSigningDriver(
    cryptoClient,
    keyClient,
    algorithm,
    keyId,
    config.keyName,
    config.keyVersion,
  );
}

// ── AWS KMS driver ────────────────────────────────────────────────────────────

class AwsKmsSigningDriver implements KmsSigningDriver {
  private readonly algorithm: string;
  private readonly awsSigningAlgorithm: string;
  private readonly awsKeyId: string;
  private readonly logicalKeyId: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private readonly kmsClient: any;
  private publicKeyPemCache: string | null = null;

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
        MessageType: 'DIGEST',
        Message: digest,
        SigningAlgorithm: this.awsSigningAlgorithm,
      }),
    );
    if (!response.Signature) {
      throw new Error('KmsTokenSigner (aws-kms): SignCommand returned no Signature');
    }
    const sig = response.Signature as Uint8Array | Buffer;
    return Buffer.isBuffer(sig) ? sig : Buffer.from(sig);
  }

  async getPublicKeyPem(): Promise<string> {
    if (this.publicKeyPemCache) {
      return this.publicKeyPemCache;
    }
    // eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
    const { GetPublicKeyCommand } = require('@aws-sdk/client-kms');
    const response = await this.kmsClient.send(
      new GetPublicKeyCommand({ KeyId: this.awsKeyId }),
    );
    if (!response.PublicKey) {
      throw new Error('KmsTokenSigner (aws-kms): GetPublicKeyCommand returned no PublicKey');
    }
    const der = Buffer.from(response.PublicKey as Uint8Array);
    // DER → PEM (SPKI)
    const b64 = der.toString('base64');
    this.publicKeyPemCache =
      `-----BEGIN PUBLIC KEY-----\n` +
      (b64.match(/.{1,64}/g) ?? []).join('\n') +
      `\n-----END PUBLIC KEY-----`;
    return this.publicKeyPemCache;
  }

  getKeyId(): string {
    return this.logicalKeyId;
  }

  getAlgorithm(): string {
    return this.algorithm;
  }
}

function buildAwsKmsDriver(config: AwsKmsTokenSignerConfig): KmsSigningDriver {
  const algorithm = resolveAlgorithm(config.algorithm);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let kmsClientModule: { KMSClient: new (cfg: Record<string, unknown>) => any };
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
    kmsClientModule = require('@aws-sdk/client-kms');
  } catch {
    throw new Error(
      'KmsTokenSigner (aws-kms): the @aws-sdk/client-kms package is not installed. ' +
        'Add it to your deployment image: npm install @aws-sdk/client-kms',
    );
  }

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
  const defaultKeyId = config.keyId.startsWith('arn:')
    ? config.keyId.split('/').pop() ?? config.keyId
    : config.keyId;
  const logicalKeyId = config.logicalKeyId ?? `aws-kms:${defaultKeyId}`;

  return new AwsKmsSigningDriver(kmsClient, config.keyId, algorithm, logicalKeyId);
}

// ── GCP Cloud KMS driver ──────────────────────────────────────────────────────

class GcpCloudKmsSigningDriver implements KmsSigningDriver {
  private readonly algorithm: string;
  private readonly keyVersionName: string;
  private readonly logicalKeyId: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private readonly kmsClient: any;
  private publicKeyPemCache: string | null = null;

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
      throw new Error(
        'KmsTokenSigner (gcp-cloudkms): asymmetricSign returned no signature',
      );
    }
    const rawSig = response.signature as Uint8Array | Buffer;
    const sigBuf = Buffer.isBuffer(rawSig) ? rawSig : Buffer.from(rawSig);
    // GCP returns DER-encoded ECDSA; convert to IEEE P1363 for JWS ES256.
    if (this.algorithm === 'ES256') {
      return derToIeeeP1363(sigBuf, 32);
    }
    return sigBuf;
  }

  async getPublicKeyPem(): Promise<string> {
    if (this.publicKeyPemCache) {
      return this.publicKeyPemCache;
    }
    const [response] = await this.kmsClient.getPublicKey({
      name: this.keyVersionName,
    });
    if (!response.pem) {
      throw new Error(
        'KmsTokenSigner (gcp-cloudkms): getPublicKey returned no pem field',
      );
    }
    this.publicKeyPemCache = response.pem as string;
    return this.publicKeyPemCache;
  }

  getKeyId(): string {
    return this.logicalKeyId;
  }

  getAlgorithm(): string {
    return this.algorithm;
  }
}

function buildGcpCloudKmsDriver(config: GcpCloudKmsTokenSignerConfig): KmsSigningDriver {
  const algorithm = resolveAlgorithm(config.algorithm);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let kmsModule: { KeyManagementServiceClient: new (cfg?: Record<string, unknown>) => any };
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/no-var-requires
    kmsModule = require('@google-cloud/kms');
  } catch {
    throw new Error(
      'KmsTokenSigner (gcp-cloudkms): the @google-cloud/kms package is not installed. ' +
        'Add it to your deployment image: npm install @google-cloud/kms',
    );
  }

  const clientCfg: Record<string, unknown> = {};
  if (config.keyFilePath) clientCfg.keyFilename = config.keyFilePath;

  const kmsClient = new kmsModule.KeyManagementServiceClient(
    Object.keys(clientCfg).length > 0 ? clientCfg : undefined,
  );

  const versionId = config.cryptoKeyVersion ?? '1';
  const keyVersionName = kmsClient.cryptoKeyVersionPath(
    config.projectId,
    config.locationId,
    config.keyRingId,
    config.cryptoKeyId,
    versionId,
  );

  const logicalKeyId =
    config.logicalKeyId ??
    `gcp-kms:${config.projectId}/${config.keyRingId}/${config.cryptoKeyId}`;

  return new GcpCloudKmsSigningDriver(kmsClient, keyVersionName, algorithm, logicalKeyId);
}

// ── DER ↔ IEEE P1363 helpers (shared with kms-evidence-signer) ───────────────

/** Convert DER ECDSA → IEEE P1363 (r‖s). Identical to kms-evidence-signer impl. */
function derToIeeeP1363(der: Buffer, coordBytes: number): Buffer {
  if (der[0] !== 0x30) return der;
  let offset = 2;
  if (der[1] === 0x81) offset = 3;
  if (der[offset] !== 0x02) {
    throw new Error('KmsTokenSigner: malformed DER ECDSA signature (expected INTEGER tag for r)');
  }
  const rLen = der[offset + 1]!;
  const rStart = offset + 2;
  let r = der.slice(rStart, rStart + rLen);
  if (r[0] === 0x00) r = r.slice(1);
  const sTagOffset = rStart + rLen;
  if (der[sTagOffset] !== 0x02) {
    throw new Error('KmsTokenSigner: malformed DER ECDSA signature (expected INTEGER tag for s)');
  }
  const sLen = der[sTagOffset + 1]!;
  const sStart = sTagOffset + 2;
  let s = der.slice(sStart, sStart + sLen);
  if (s[0] === 0x00) s = s.slice(1);
  const result = Buffer.alloc(coordBytes * 2, 0);
  r.copy(result, coordBytes - r.length);
  s.copy(result, coordBytes * 2 - s.length);
  return result;
}

// ── Base64URL helper ──────────────────────────────────────────────────────────

function base64UrlEncode(data: string | Buffer): string {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  return buf.toString('base64url');
}

// ── Per-tenant key resolver ───────────────────────────────────────────────────

/**
 * Resolves the KMS key reference for a given issuance context.
 *
 * Lookup order (first match wins), mirroring the composite-key convention
 * in `resolveIssuanceContextKey` from `@euno/common-core`:
 * 1. `tenantKeyMap["${policyHash}:${audience}"]`  — policy + tenant isolation
 * 2. `tenantKeyMap["${audience}"]`                — tenant-level isolation
 * 3. `tenantKeyMap["${policyHash}"]`              — policy-level isolation
 * 4. Default key (the driver's built-in key reference)
 *
 * Returns `undefined` when no entry matches (use default key).
 */
function resolveContextKey(
  tenantKeyMap: Record<string, string> | undefined,
  context: IssuanceContext | undefined,
): string | undefined {
  if (!tenantKeyMap || !context) return undefined;
  const composite = `${context.policyHash}:${context.audience}`;
  return (
    tenantKeyMap[composite] ??
    tenantKeyMap[context.audience] ??
    tenantKeyMap[context.policyHash] ??
    undefined
  );
}

// ── KmsTokenSigner ────────────────────────────────────────────────────────────

/**
 * KMS-backed implementation of the `TokenSigner` seam from `@euno/common-core`.
 *
 * Supports per-tenant key isolation via `config.tenantKeyMap`.  The default
 * driver instance is used for all mints that do not match a tenant-specific
 * entry; per-tenant drivers are created lazily on first use and cached.
 */
export class KmsTokenSigner implements TokenSigner {
  private readonly config: KmsTokenSignerConfig;
  private readonly defaultDriver: KmsSigningDriver;
  /**
   * Cache of per-tenant drivers keyed by the resolved key reference string.
   * Entries are created lazily on first use to avoid KMS API calls at startup
   * for tenants that have never minted a token.
   */
  private readonly driverCache = new Map<string, KmsSigningDriver>();

  constructor(config: KmsTokenSignerConfig) {
    this.config = config;
    this.defaultDriver = buildDriver(config);
  }

  // ── TokenSigner interface ──────────────────────────────────────────────────

  /**
   * Sign a capability token payload.
   *
   * When `context` is supplied and `config.tenantKeyMap` contains a matching
   * entry, the tenant-specific HSM key is used.  Otherwise the default key
   * signs the token.  The JWT `kid` header always reflects the key that
   * actually signed the token.
   */
  async sign(payload: CapabilityTokenPayload, context?: IssuanceContext): Promise<string> {
    const driver = await this.resolveDriver(context);
    return signJwt(payload, driver);
  }

  async getPublicKey(): Promise<string> {
    return this.defaultDriver.getPublicKeyPem();
  }

  async getKeyId(): Promise<string> {
    return this.defaultDriver.getKeyId();
  }

  getAlgorithm(): string {
    return this.defaultDriver.getAlgorithm();
  }

  // ── Internal helpers ──────────────────────────────────────────────────────

  private async resolveDriver(context: IssuanceContext | undefined): Promise<KmsSigningDriver> {
    const keyRef = resolveContextKey(this.config.tenantKeyMap, context);
    if (!keyRef) return this.defaultDriver;

    const cached = this.driverCache.get(keyRef);
    if (cached) return cached;

    // Build a new driver for this tenant key.  We clone the base config and
    // override the key reference so all other settings (credentials, region,
    // algorithm) are inherited.
    const tenantDriver = buildDriverForKeyRef(this.config, keyRef);
    this.driverCache.set(keyRef, tenantDriver);
    return tenantDriver;
  }
}

// ── JWT construction ──────────────────────────────────────────────────────────

/**
 * Build and sign a JWT manually so we can forward the pre-computed SHA-256
 * digest to the KMS "sign digest" API (identical to the evidence-signer
 * contract).  This avoids giving the KMS driver the full signing input.
 */
async function signJwt(
  payload: CapabilityTokenPayload,
  driver: KmsSigningDriver,
): Promise<string> {
  const header = {
    alg: driver.getAlgorithm(),
    typ: 'JWT',
    kid: driver.getKeyId(),
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  // Pre-hash with SHA-256 (all three KMS drivers use the "sign digest" API —
  // this is a JWT signing digest, NOT a password hash; the payload is the
  // base64url-encoded JWT header and claims, not a secret credential).
  const digest = crypto.createHash('sha256').update(signingInput).digest();
  const rawSig = await driver.signDigest(digest);
  const encodedSignature = base64UrlEncode(rawSig);

  return `${signingInput}.${encodedSignature}`;
}

// ── Driver factories ──────────────────────────────────────────────────────────

function buildDriver(config: KmsTokenSignerConfig): KmsSigningDriver {
  switch (config.provider) {
    case 'azure-keyvault':
      return buildAzureKeyVaultDriver(config);
    case 'aws-kms':
      return buildAwsKmsDriver(config);
    case 'gcp-cloudkms':
      return buildGcpCloudKmsDriver(config);
    default: {
      const _exhaustive: never = config;
      throw new Error(
        `KmsTokenSigner: unknown provider '${(_exhaustive as KmsTokenSignerConfig).provider}'`,
      );
    }
  }
}

/**
 * Build a driver for a specific `keyRef` string, inheriting all other config
 * fields (credentials, region, algorithm) from the base config.  This is how
 * per-tenant key isolation is implemented without repeating credential config
 * for every tenant.
 */
function buildDriverForKeyRef(
  base: KmsTokenSignerConfig,
  keyRef: string,
): KmsSigningDriver {
  switch (base.provider) {
    case 'azure-keyvault':
      return buildAzureKeyVaultDriver({ ...base, keyName: keyRef, keyVersion: undefined });
    case 'aws-kms':
      return buildAwsKmsDriver({ ...base, keyId: keyRef });
    case 'gcp-cloudkms': {
      // keyRef for GCP is expected to be a full cryptoKeyVersionPath or a
      // `cryptoKeyId` value.  We treat it as a cryptoKeyId with version '1'
      // unless it contains '/cryptoKeyVersions/' (full path).
      if (keyRef.includes('/cryptoKeyVersions/')) {
        // Full version path — parse out the relevant segments.
        const parts = keyRef.split('/');
        const versionIdx = parts.indexOf('cryptoKeyVersions');
        const cryptoKeyVersion: string = versionIdx >= 0 ? (parts[versionIdx + 1] ?? '1') : '1';
        const cryptoKeyId: string = versionIdx >= 1 ? (parts[versionIdx - 1] ?? base.cryptoKeyId) : base.cryptoKeyId;
        return buildGcpCloudKmsDriver({ ...base, cryptoKeyId, cryptoKeyVersion });
      }
      return buildGcpCloudKmsDriver({ ...base, cryptoKeyId: keyRef, cryptoKeyVersion: '1' });
    }
    default: {
      const _exhaustive: never = base;
      throw new Error(
        `KmsTokenSigner: unknown provider '${(_exhaustive as KmsTokenSignerConfig).provider}'`,
      );
    }
  }
}

// ── Public factory ────────────────────────────────────────────────────────────

/**
 * Create a KMS-backed {@link TokenSigner}.
 *
 * ```typescript
 * const signer = createKmsTokenSigner({ provider: 'aws-kms', keyId: '...', algorithm: 'ES256' });
 * ```
 */
export function createKmsTokenSigner(config: KmsTokenSignerConfig): KmsTokenSigner {
  return new KmsTokenSigner(config);
}

// ── Environment-variable factory ──────────────────────────────────────────────

/**
 * Build a KMS-backed {@link TokenSigner} from environment variables.
 *
 * Returns `undefined` when `MINTER_KMS_PROVIDER` is not set, allowing the
 * caller to fall back to the local software signer (dev mode).
 *
 * ### Environment variables
 *
 * | Variable | Description |
 * |---|---|
 * | `MINTER_KMS_PROVIDER` | Required. One of `azure-keyvault`, `aws-kms`, `gcp-cloudkms`. |
 * | `MINTER_SIGNING_ALGORITHM` | JWS algorithm. Defaults to `ES256`. Supported: `RS256`, `PS256`, `ES256`. |
 * | `MINTER_SIGNING_KEY_ID` | Logical key ID stamped on each JWT `kid`. Provider-derived when omitted. |
 * | `MINTER_TENANT_KEY_MAP` | Optional JSON object mapping tenant audience values to KMS key references. |
 * | **Azure Key Vault** | |
 * | `MINTER_SIGNING_AZURE_KEYVAULT_URL` | Required when provider=`azure-keyvault`. |
 * | `MINTER_SIGNING_AZURE_KEY_NAME` | Required when provider=`azure-keyvault`. |
 * | `MINTER_SIGNING_AZURE_KEY_VERSION` | Optional. Defaults to latest. |
 * | `MINTER_SIGNING_AZURE_CREDENTIAL_TYPE` | `default` (default), `managed-identity`, or `client-secret`. |
 * | `MINTER_SIGNING_AZURE_CLIENT_ID` | Required when `MINTER_SIGNING_AZURE_CREDENTIAL_TYPE=client-secret`. |
 * | `MINTER_SIGNING_AZURE_CLIENT_SECRET` | Required when `MINTER_SIGNING_AZURE_CREDENTIAL_TYPE=client-secret`. |
 * | `MINTER_SIGNING_AZURE_TENANT_ID` | Required when `MINTER_SIGNING_AZURE_CREDENTIAL_TYPE=client-secret`. |
 * | **AWS KMS** | |
 * | `MINTER_SIGNING_AWS_KMS_KEY_ID` | Required when provider=`aws-kms`. |
 * | `MINTER_SIGNING_AWS_KMS_REGION` | Optional. Defaults to SDK default (`AWS_REGION` env var). |
 * | **GCP Cloud KMS** | |
 * | `MINTER_SIGNING_GCP_PROJECT_ID` | Required when provider=`gcp-cloudkms`. |
 * | `MINTER_SIGNING_GCP_LOCATION_ID` | Required when provider=`gcp-cloudkms`. Must be an HSM-capable region (not `global`). |
 * | `MINTER_SIGNING_GCP_KEYRING_ID` | Required when provider=`gcp-cloudkms`. |
 * | `MINTER_SIGNING_GCP_CRYPTOKEY_ID` | Required when provider=`gcp-cloudkms`. |
 * | `MINTER_SIGNING_GCP_CRYPTOKEY_VERSION` | Optional. Defaults to `1`. Update on key rotation. |
 * | `MINTER_SIGNING_GCP_KEY_FILE_PATH` | Optional. Path to GCP service account key file. |
 */
export function createKmsTokenSignerFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): KmsTokenSigner | undefined {
  const provider = env.MINTER_KMS_PROVIDER;
  if (!provider) return undefined;

  const algorithm = env.MINTER_SIGNING_ALGORITHM || undefined;
  const logicalKeyId = env.MINTER_SIGNING_KEY_ID || undefined;

  let tenantKeyMap: Record<string, string> | undefined;
  if (env.MINTER_TENANT_KEY_MAP) {
    try {
      tenantKeyMap = JSON.parse(env.MINTER_TENANT_KEY_MAP) as Record<string, string>;
    } catch {
      throw new Error(
        'KmsTokenSigner: MINTER_TENANT_KEY_MAP must be valid JSON (an object mapping tenant IDs to key references).',
      );
    }
  }

  switch (provider) {
    case 'azure-keyvault': {
      const vaultUrl = env.MINTER_SIGNING_AZURE_KEYVAULT_URL;
      const keyName = env.MINTER_SIGNING_AZURE_KEY_NAME;
      if (!vaultUrl) {
        throw new Error(
          'KmsTokenSigner: MINTER_SIGNING_AZURE_KEYVAULT_URL is required when MINTER_KMS_PROVIDER=azure-keyvault.',
        );
      }
      if (!keyName) {
        throw new Error(
          'KmsTokenSigner: MINTER_SIGNING_AZURE_KEY_NAME is required when MINTER_KMS_PROVIDER=azure-keyvault.',
        );
      }
      const credType = (env.MINTER_SIGNING_AZURE_CREDENTIAL_TYPE ?? 'default') as
        | 'default'
        | 'managed-identity'
        | 'client-secret';
      return createKmsTokenSigner({
        provider: 'azure-keyvault',
        vaultUrl,
        keyName,
        keyVersion: env.MINTER_SIGNING_AZURE_KEY_VERSION || undefined,
        credentialType: credType,
        clientId: env.MINTER_SIGNING_AZURE_CLIENT_ID || undefined,
        clientSecret: env.MINTER_SIGNING_AZURE_CLIENT_SECRET || undefined,
        tenantId: env.MINTER_SIGNING_AZURE_TENANT_ID || undefined,
        algorithm,
        logicalKeyId,
        tenantKeyMap,
      });
    }

    case 'aws-kms': {
      const keyId = env.MINTER_SIGNING_AWS_KMS_KEY_ID;
      if (!keyId) {
        throw new Error(
          'KmsTokenSigner: MINTER_SIGNING_AWS_KMS_KEY_ID is required when MINTER_KMS_PROVIDER=aws-kms.',
        );
      }
      return createKmsTokenSigner({
        provider: 'aws-kms',
        keyId,
        region: env.MINTER_SIGNING_AWS_KMS_REGION || undefined,
        algorithm,
        logicalKeyId,
        tenantKeyMap,
      });
    }

    case 'gcp-cloudkms': {
      const projectId = env.MINTER_SIGNING_GCP_PROJECT_ID;
      const locationId = env.MINTER_SIGNING_GCP_LOCATION_ID;
      const keyRingId = env.MINTER_SIGNING_GCP_KEYRING_ID;
      const cryptoKeyId = env.MINTER_SIGNING_GCP_CRYPTOKEY_ID;
      const missing: string[] = [];
      if (!projectId) missing.push('MINTER_SIGNING_GCP_PROJECT_ID');
      if (!locationId) missing.push('MINTER_SIGNING_GCP_LOCATION_ID');
      if (!keyRingId) missing.push('MINTER_SIGNING_GCP_KEYRING_ID');
      if (!cryptoKeyId) missing.push('MINTER_SIGNING_GCP_CRYPTOKEY_ID');
      if (missing.length > 0) {
        throw new Error(
          `KmsTokenSigner: the following env vars are required when MINTER_KMS_PROVIDER=gcp-cloudkms: ${missing.join(', ')}.`,
        );
      }
      return createKmsTokenSigner({
        provider: 'gcp-cloudkms',
        projectId: projectId!,
        locationId: locationId!,
        keyRingId: keyRingId!,
        cryptoKeyId: cryptoKeyId!,
        cryptoKeyVersion: env.MINTER_SIGNING_GCP_CRYPTOKEY_VERSION || undefined,
        keyFilePath: env.MINTER_SIGNING_GCP_KEY_FILE_PATH || undefined,
        algorithm,
        logicalKeyId,
        tenantKeyMap,
      });
    }

    default:
      throw new Error(
        `KmsTokenSigner: unknown MINTER_KMS_PROVIDER '${provider}'. Supported: azure-keyvault, aws-kms, gcp-cloudkms.`,
      );
  }
}
