/**
 * Azure Key Vault Token Signer
 * Implements cryptographic signing using Azure Key Vault
 */

import { CryptographyClient, SignResult, KeyVaultKey } from '@azure/keyvault-keys';
import { DefaultAzureCredential, ClientSecretCredential } from '@azure/identity';
import { SigningAdapter, SigningAdapterConfig, SigningAlgorithm, CapabilityTokenPayload, AzureKeyVaultConfig, IssuanceContext, resolveIssuanceContextKey } from '@euno/common';
import { KeyClient } from '@azure/keyvault-keys';
import * as crypto from 'crypto';
import * as jose from 'jose';

/**
 * Azure Key Vault specific configuration extending the base adapter config
 */
export interface AzureKeyVaultAdapterConfig extends SigningAdapterConfig {
  type: 'azure-keyvault';
  keyVault: AzureKeyVaultConfig;
}

/**
 * Determine the signing algorithm from Azure Key Vault key type and size
 */
function detectAlgorithmFromKey(key: KeyVaultKey): SigningAlgorithm {
  const keyType = key.keyType;

  if (keyType === 'RSA' || keyType === 'RSA-HSM') {
    // Default to RS256 for RSA keys, but could be RS384 or RS512
    // based on key size or configuration preference
    return 'RS256';
  } else if (keyType === 'EC' || keyType === 'EC-HSM') {
    // Determine ES algorithm from curve
    const curveName = key.key?.crv;
    if (curveName === 'P-256') {
      return 'ES256';
    } else if (curveName === 'P-256K') {
      throw new Error('Unsupported EC curve P-256K: ES256K is not supported by this signer');
    } else if (curveName === 'P-384') {
      return 'ES384';
    } else if (curveName === 'P-521') {
      return 'ES512';
    }
    return 'ES256'; // Default for EC
  }

  // Default to RS256 if unable to determine
  return 'RS256';
}

export class AzureKeyVaultSigner extends SigningAdapter {
  private cryptoClient: CryptographyClient;
  private keyClient: KeyClient;
  private keyVaultConfig: AzureKeyVaultConfig;
  private keyId?: string;
  private publicKeyCache?: string;
  /**
   * Per-policyHash `CryptographyClient` cache.
   * Lazily populated on the first `sign()` call that references a given
   * `policyHash` so key-vault round-trips are amortised across requests.
   */
  private cryptoClientsByPolicyHash: Map<string, CryptographyClient> = new Map();
  /**
   * Per-policyHash signing algorithm detected from the mapped key.
   * A policy-specific key may use a different algorithm than the default key
   * (e.g. the default key is RSA-2048/RS256 but the high-security policy uses
   * an EC P-256 key/ES256).  Storing the algorithm alongside the client avoids
   * calling Key Vault on every sign operation just to re-derive the algorithm.
   */
  private algorithmByPolicyHash: Map<string, string> = new Map();

  constructor(config: AzureKeyVaultAdapterConfig) {
    super(config);
    this.keyVaultConfig = config.keyVault;

    // Create credential based on configuration
    const credential = this.createCredential();

    // Initialize Key Vault clients
    this.keyClient = new KeyClient(this.keyVaultConfig.vaultUrl, credential);

    // The CryptographyClient will be initialized when we get the key
    this.cryptoClient = null as any; // Will be set in initialize()
  }

  private createCredential() {
    if (this.keyVaultConfig.credentialType === 'client-secret' && this.keyVaultConfig.clientId && this.keyVaultConfig.clientSecret && this.keyVaultConfig.tenantId) {
      return new ClientSecretCredential(
        this.keyVaultConfig.tenantId,
        this.keyVaultConfig.clientId,
        this.keyVaultConfig.clientSecret
      );
    }
    // Default to managed identity or default credential chain
    return new DefaultAzureCredential();
  }

  /**
   * Initialize the cryptography client with the key
   * Override from base SigningAdapter
   */
  async initialize(): Promise<void> {
    if (this.cryptoClient) {
      return;
    }

    const key = await this.keyClient.getKey(
      this.keyVaultConfig.keyName,
      this.keyVaultConfig.keyVersion ? { version: this.keyVaultConfig.keyVersion } : undefined
    );

    this.keyId = key.id;
    this.cryptoClient = new CryptographyClient(key, this.createCredential());

    // Auto-detect algorithm from key type if not explicitly configured
    if (!this.config.algorithm) {
      this.algorithm = detectAlgorithmFromKey(key);
    }

    // Cache the public key
    if (key.key) {
      await this.cachePublicKey(key);
    }
  }

  /**
   * Cache the public key in PEM format for verification
   */
  private async cachePublicKey(key: KeyVaultKey): Promise<void> {
    if (!key.key) {
      return;
    }

    if (key.key.n && key.key.e) {
      // RSA public key
      const nBase64 = Buffer.from(key.key.n).toString('base64url');
      const eBase64 = Buffer.from(key.key.e).toString('base64url');

      const publicKeyObj = await jose.importJWK({
        kty: 'RSA',
        n: nBase64,
        e: eBase64,
        alg: this.algorithm,
        use: 'sig',
      }, this.algorithm) as jose.KeyLike;
      this.publicKeyCache = await jose.exportSPKI(publicKeyObj);
    } else if (key.key.x && key.key.y && key.key.crv) {
      // EC public key
      const xBase64 = Buffer.from(key.key.x).toString('base64url');
      const yBase64 = Buffer.from(key.key.y).toString('base64url');

      const publicKeyObj = await jose.importJWK({
        kty: 'EC',
        crv: key.key.crv,
        x: xBase64,
        y: yBase64,
        alg: this.algorithm,
        use: 'sig',
      }, this.algorithm) as jose.KeyLike;
      this.publicKeyCache = await jose.exportSPKI(publicKeyObj);
    }
  }

  /**
   * Get the hash algorithm name for a given signing algorithm.
   * Accepts the algorithm as a parameter so it can be used for both the
   * default key and any policy-specific mapped key.
   */
  private getHashAlgorithmFor(algorithm: string): string {
    switch (algorithm) {
      case 'RS256':
      case 'ES256':
        return 'sha256';
      case 'RS384':
      case 'ES384':
        return 'sha384';
      case 'RS512':
      case 'ES512':
        return 'sha512';
      case 'EdDSA':
        // EdDSA doesn't use a separate hash step for Azure Key Vault
        throw new Error('EdDSA is not currently supported with Azure Key Vault');
      default:
        return 'sha256';
    }
  }

  /**
   * Sign a capability token payload.
   *
   * When an {@link IssuanceContext} is supplied and the `policyHash` matches
   * an entry in {@link AzureKeyVaultConfig.keysByPolicyHash}, the signer uses
   * the mapped key name instead of the default {@link AzureKeyVaultConfig.keyName}.
   * The per-policy key is fetched once and its `CryptographyClient` is cached
   * so subsequent calls for the same policy hash skip the Key Vault metadata
   * round-trip.  If the mapped key is not yet cached, it is resolved
   * synchronously during the sign operation — the overall signing latency is
   * therefore bounded by at most one additional `getKey` call per distinct
   * policy hash seen at runtime.
   *
   * Falls back to the default key when no `context` is supplied or the
   * `policyHash` is not mapped in `keysByPolicyHash`.
   */
  async sign(payload: CapabilityTokenPayload, context?: IssuanceContext): Promise<string> {
    await this.initialize();

    // Resolve the CryptographyClient and effective algorithm for this signing
    // operation.  When an IssuanceContext maps to a policy-specific key, both
    // the client and that key's algorithm are selected; otherwise the defaults
    // (set during initialize()) are used.
    const { client: activeCryptoClient, algorithm: activeAlgorithm } =
      await this.resolveSigningResources(context);

    // Create JWT header using the resolved algorithm so the header's `alg`
    // always matches the key that will actually sign it.
    const header = {
      alg: activeAlgorithm,
      typ: 'JWT',
      kid: await this.getKeyId(),
    };

    // Encode header and payload
    const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
    const encodedPayload = this.base64UrlEncode(JSON.stringify(payload));
    const signingInput = `${encodedHeader}.${encodedPayload}`;

    // Hash the signing input locally (as per Azure Key Vault best practice).
    // Use the hash algorithm that matches the resolved signing algorithm.
    const hashAlgorithm = this.getHashAlgorithmFor(activeAlgorithm);
    const digest = crypto
      .createHash(hashAlgorithm)
      .update(signingInput)
      .digest();

    // Sign the digest with Key Vault using the resolved client and algorithm.
    const signResult: SignResult = await activeCryptoClient.sign(activeAlgorithm, digest);

    // Encode the signature
    const encodedSignature = this.base64UrlEncode(Buffer.from(signResult.result));

    // Return the complete JWT
    return `${signingInput}.${encodedSignature}`;
  }

  /**
   * Resolve the `CryptographyClient` and signing algorithm for a given signing
   * operation.
   *
   * When an {@link IssuanceContext} is supplied and its `policyHash` maps to
   * an entry in {@link AzureKeyVaultConfig.keysByPolicyHash}, returns (creating
   * on first use) a `CryptographyClient` for that key, together with the
   * algorithm detected from that key.  Falls back to the default client and
   * algorithm when no context / mapping is present.
   *
   * The cache is keyed on `policyHash` rather than the resolved key name so
   * that each policy boundary has its own client entry and cache invalidation
   * is straightforward: each distinct hash maps to exactly one client.
   */
  private async resolveSigningResources(
    context?: IssuanceContext,
  ): Promise<{ client: CryptographyClient; algorithm: string }> {
    // Try composite key "${policyHash}:${audience}" first so operators can
    // assign different keys to different tenants even when they share the same
    // policy document.  Fall back to plain policyHash for single-tenant
    // deployments where audience differentiation is not needed.
    const mappedKeyName =
      context !== undefined && this.keyVaultConfig.keysByPolicyHash !== undefined
        ? (this.keyVaultConfig.keysByPolicyHash[resolveIssuanceContextKey(context)] ??
           this.keyVaultConfig.keysByPolicyHash[context.policyHash])
        : undefined;

    if (mappedKeyName === undefined) {
      return { client: this.cryptoClient, algorithm: this.algorithm };
    }

    const policyHash = context!.policyHash;
    const cached = this.cryptoClientsByPolicyHash.get(policyHash);
    if (cached !== undefined) {
      // Algorithm was stored when the client was created — safe to assert.
      return { client: cached, algorithm: this.algorithmByPolicyHash.get(policyHash)! };
    }

    // Fetch the policy-specific key from Key Vault, detect its algorithm, and
    // cache both the client and the algorithm keyed by policyHash.
    const key = await this.keyClient.getKey(mappedKeyName);
    const detectedAlgorithm = detectAlgorithmFromKey(key);
    const client = new CryptographyClient(key, this.createCredential());
    this.cryptoClientsByPolicyHash.set(policyHash, client);
    this.algorithmByPolicyHash.set(policyHash, detectedAlgorithm);
    return { client, algorithm: detectedAlgorithm };
  }

  /**
   * Get the public key for verification
   */
  async getPublicKey(): Promise<string> {
    await this.initialize();

    if (!this.publicKeyCache) {
      throw new Error('Public key not available');
    }

    return this.publicKeyCache;
  }

  /**
   * Get the key ID used for signing
   */
  async getKeyId(): Promise<string> {
    await this.initialize();

    if (!this.keyId) {
      throw new Error('Key ID not available');
    }

    return this.keyId;
  }

  /**
   * Base64 URL encode (without padding)
   */
  private base64UrlEncode(input: string | Buffer): string {
    const buffer = typeof input === 'string' ? Buffer.from(input, 'utf-8') : input;
    return buffer
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }
}
