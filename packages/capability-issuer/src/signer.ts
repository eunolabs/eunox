/**
 * Azure Key Vault Token Signer
 * Implements cryptographic signing using Azure Key Vault
 */

import { CryptographyClient, SignResult } from '@azure/keyvault-keys';
import { DefaultAzureCredential, ClientSecretCredential } from '@azure/identity';
import { SigningAdapter, SigningAdapterConfig, CapabilityTokenPayload, AzureKeyVaultConfig } from '@euno/common';
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

    // Cache the public key
    if (key.key && key.key.n && key.key.e) {
      // RSA public key - convert to base64url strings
      const nBase64 = Buffer.from(key.key.n).toString('base64url');
      const eBase64 = Buffer.from(key.key.e).toString('base64url');

      const publicKeyObj = await jose.importJWK({
        kty: 'RSA',
        n: nBase64,
        e: eBase64,
        alg: 'RS256',
        use: 'sig',
      }, 'RS256') as jose.KeyLike;
      this.publicKeyCache = await jose.exportSPKI(publicKeyObj);
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
      alg: 'RS256',
      typ: 'JWT',
      kid: await this.getKeyId(),
    };

    // Encode header and payload
    const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
    const encodedPayload = this.base64UrlEncode(JSON.stringify(payload));
    const signingInput = `${encodedHeader}.${encodedPayload}`;

    // Hash the signing input locally (as per Azure Key Vault best practice)
    const digest = crypto
      .createHash('sha256')
      .update(signingInput)
      .digest();

    // Sign the digest with Key Vault
    const signResult: SignResult = await this.cryptoClient.sign('RS256', digest);

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
