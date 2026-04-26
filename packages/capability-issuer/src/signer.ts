/**
 * Azure Key Vault Token Signer
 * Implements cryptographic signing using Azure Key Vault
 */

import { CryptographyClient, SignResult, KeyVaultKey } from '@azure/keyvault-keys';
import { DefaultAzureCredential, ClientSecretCredential } from '@azure/identity';
import { SigningAdapter, SigningAdapterConfig, SigningAlgorithm, CapabilityTokenPayload, AzureKeyVaultConfig } from '@euno/common';
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
    if (curveName === 'P-256' || curveName === 'P-256K') {
      return 'ES256';
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
   * Get the hash algorithm name for the signing algorithm
   */
  private getHashAlgorithm(): string {
    switch (this.algorithm) {
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
   * Sign a capability token payload
   * Follows the Azure pattern: hash locally, then sign the digest with Key Vault
   */
  async sign(payload: CapabilityTokenPayload): Promise<string> {
    await this.initialize();

    // Create JWT header
    const header = {
      alg: this.algorithm,
      typ: 'JWT',
      kid: await this.getKeyId(),
    };

    // Encode header and payload
    const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
    const encodedPayload = this.base64UrlEncode(JSON.stringify(payload));
    const signingInput = `${encodedHeader}.${encodedPayload}`;

    // Hash the signing input locally (as per Azure Key Vault best practice)
    const hashAlgorithm = this.getHashAlgorithm();
    const digest = crypto
      .createHash(hashAlgorithm)
      .update(signingInput)
      .digest();

    // Sign the digest with Key Vault
    const signResult: SignResult = await this.cryptoClient.sign(this.algorithm, digest);

    // Encode the signature
    const encodedSignature = this.base64UrlEncode(Buffer.from(signResult.result));

    // Return the complete JWT
    return `${signingInput}.${encodedSignature}`;
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
