/**
 * GCP Cloud KMS Token Signer
 * Implements cryptographic signing using Google Cloud Key Management Service
 */

import { KeyManagementServiceClient } from '@google-cloud/kms';
import { SigningAdapter, SigningAdapterConfig, SigningAlgorithm, CapabilityTokenPayload, GCPCloudKMSConfig } from '@euno/common';
import * as crypto from 'crypto';

/**
 * GCP Cloud KMS specific configuration extending the base adapter config
 */
export interface GCPCloudKMSAdapterConfig extends SigningAdapterConfig {
  type: 'gcp-cloudkms';
  gcpKMS: GCPCloudKMSConfig;
}

/**
 * Detect signing algorithm from GCP KMS key algorithm name
 */
function detectAlgorithmFromGCPKey(algorithm: string): SigningAlgorithm {
  if (algorithm.includes('RSA_SIGN_PKCS1_2048_SHA256') || algorithm.includes('RSA_SIGN_PKCS1_3072_SHA256') || algorithm.includes('RSA_SIGN_PKCS1_4096_SHA256')) {
    return 'RS256';
  } else if (algorithm.includes('RSA_SIGN_PKCS1_4096_SHA512')) {
    return 'RS512';
  } else if (algorithm.includes('EC_SIGN_P256_SHA256')) {
    return 'ES256';
  } else if (algorithm.includes('EC_SIGN_P384_SHA384')) {
    return 'ES384';
  }
  // Default to RS256
  return 'RS256';
}

/**
 * Get the hash algorithm name for the signing algorithm
 */
function getHashAlgorithm(algorithm: SigningAlgorithm): string {
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
    default:
      return 'sha256';
  }
}

/**
 * Convert GCP public key PEM to standard format
 */
function convertGCPPublicKeyToPEM(pem: string): string {
  // GCP returns the key in PEM format, but we may need to ensure proper formatting
  if (!pem.includes('-----BEGIN')) {
    // If not in PEM format, wrap it
    const base64Key = pem.replace(/\s/g, '');
    return `-----BEGIN PUBLIC KEY-----\n${base64Key.match(/.{1,64}/g)?.join('\n')}\n-----END PUBLIC KEY-----`;
  }
  return pem;
}

export class GCPCloudKMSSigner extends SigningAdapter {
  private kmsClient: KeyManagementServiceClient;
  private gcpConfig: GCPCloudKMSConfig;
  private versionName?: string;
  private publicKeyCache?: string;

  constructor(config: GCPCloudKMSAdapterConfig) {
    super(config);
    this.gcpConfig = config.gcpKMS;

    // Initialize GCP KMS client
    const clientConfig: any = {};

    // If a key file path is provided, use it for authentication
    if (this.gcpConfig.keyFilePath) {
      clientConfig.keyFilename = this.gcpConfig.keyFilePath;
    }

    this.kmsClient = new KeyManagementServiceClient(clientConfig);
  }

  /**
   * Initialize the KMS client and cache public key
   * Override from base SigningAdapter
   */
  async initialize(): Promise<void> {
    if (this.publicKeyCache) {
      return;
    }

    // Build the crypto key version name
    const keyRingName = `projects/${this.gcpConfig.projectId}/locations/${this.gcpConfig.locationId}/keyRings/${this.gcpConfig.keyRingId}`;
    const cryptoKeyName = `${keyRingName}/cryptoKeys/${this.gcpConfig.cryptoKeyId}`;

    if (this.gcpConfig.cryptoKeyVersion) {
      this.versionName = `${cryptoKeyName}/cryptoKeyVersions/${this.gcpConfig.cryptoKeyVersion}`;
    } else {
      // Get the primary version
      const [cryptoKey] = await this.kmsClient.getCryptoKey({ name: cryptoKeyName });
      if (!cryptoKey.primary?.name) {
        throw new Error('Failed to get primary crypto key version from GCP Cloud KMS');
      }
      this.versionName = cryptoKey.primary.name;
    }

    // Fetch the public key
    const [publicKey] = await this.kmsClient.getPublicKey({
      name: this.versionName,
    });

    if (!publicKey.pem) {
      throw new Error('Failed to retrieve public key from GCP Cloud KMS');
    }

    // Cache the public key
    this.publicKeyCache = convertGCPPublicKeyToPEM(publicKey.pem);

    // Auto-detect algorithm from key if not explicitly configured
    if (!this.config.algorithm && publicKey.algorithm) {
      this.algorithm = detectAlgorithmFromGCPKey(String(publicKey.algorithm));
    }
  }

  /**
   * Sign a capability token payload
   * GCP Cloud KMS asymmetricSign expects the full message or digest
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

    // Hash the signing input locally
    const hashAlgorithm = getHashAlgorithm(this.algorithm);
    const digest = crypto
      .createHash(hashAlgorithm)
      .update(signingInput)
      .digest();

    // Sign the digest with GCP Cloud KMS
    const [signResponse] = await this.kmsClient.asymmetricSign({
      name: this.versionName,
      digest: {
        sha256: this.algorithm === 'RS256' || this.algorithm === 'ES256' ? digest : undefined,
        sha384: this.algorithm === 'RS384' || this.algorithm === 'ES384' ? digest : undefined,
        sha512: this.algorithm === 'RS512' || this.algorithm === 'ES512' ? digest : undefined,
      },
    });

    if (!signResponse.signature) {
      throw new Error('Failed to sign with GCP Cloud KMS');
    }

    // Encode the signature
    const signature = Buffer.from(signResponse.signature as Uint8Array);
    const encodedSignature = this.base64UrlEncode(signature);

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

    if (!this.versionName) {
      throw new Error('Key version name not available');
    }

    return this.versionName;
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

  /**
   * Cleanup resources
   */
  async dispose(): Promise<void> {
    // GCP client cleanup
    await this.kmsClient.close();
    this.publicKeyCache = undefined;
    this.versionName = undefined;
  }
}
