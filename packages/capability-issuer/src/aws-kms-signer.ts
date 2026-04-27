/**
 * AWS KMS Token Signer
 * Implements cryptographic signing using AWS Key Management Service
 */

import { KMSClient, SignCommand, GetPublicKeyCommand, SigningAlgorithmSpec } from '@aws-sdk/client-kms';
import { SigningAdapter, SigningAdapterConfig, SigningAlgorithm, CapabilityTokenPayload, AWSKMSConfig } from '@euno/common';
import * as crypto from 'crypto';

/**
 * AWS KMS specific configuration extending the base adapter config
 */
export interface AWSKMSAdapterConfig extends SigningAdapterConfig {
  type: 'aws-kms';
  awsKMS: AWSKMSConfig;
}

/**
 * Map JWT signing algorithms to AWS KMS signing algorithms
 */
function getAWSSigningAlgorithm(algorithm: SigningAlgorithm): SigningAlgorithmSpec {
  switch (algorithm) {
    case 'RS256':
      return 'RSASSA_PKCS1_V1_5_SHA_256';
    case 'RS384':
      return 'RSASSA_PKCS1_V1_5_SHA_384';
    case 'RS512':
      return 'RSASSA_PKCS1_V1_5_SHA_512';
    case 'ES256':
      return 'ECDSA_SHA_256';
    case 'ES384':
      return 'ECDSA_SHA_384';
    case 'ES512':
      return 'ECDSA_SHA_512';
    default:
      throw new Error(`Unsupported signing algorithm for AWS KMS: ${algorithm}`);
  }
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

export class AWSKMSSigner extends SigningAdapter {
  private kmsClient: KMSClient;
  private awsConfig: AWSKMSConfig;
  private publicKeyCache?: string;

  constructor(config: AWSKMSAdapterConfig) {
    super(config);
    this.awsConfig = config.awsKMS;

    // Initialize AWS KMS client
    const clientConfig: any = {
      region: this.awsConfig.region,
    };

    // Add explicit credentials if provided
    if (this.awsConfig.accessKeyId && this.awsConfig.secretAccessKey) {
      clientConfig.credentials = {
        accessKeyId: this.awsConfig.accessKeyId,
        secretAccessKey: this.awsConfig.secretAccessKey,
        sessionToken: this.awsConfig.sessionToken,
      };
    }

    this.kmsClient = new KMSClient(clientConfig);
  }

  /**
   * Initialize the KMS client and cache public key
   * Override from base SigningAdapter
   */
  async initialize(): Promise<void> {
    if (this.publicKeyCache) {
      return;
    }

    // Fetch and cache the public key
    const command = new GetPublicKeyCommand({
      KeyId: this.awsConfig.keyId,
    });

    const response = await this.kmsClient.send(command);

    if (!response.PublicKey) {
      throw new Error('Failed to retrieve public key from AWS KMS');
    }

    // Convert DER format to PEM
    const publicKeyDer = Buffer.from(response.PublicKey);
    const publicKeyBase64 = publicKeyDer.toString('base64');
    this.publicKeyCache = `-----BEGIN PUBLIC KEY-----\n${publicKeyBase64.match(/.{1,64}/g)?.join('\n')}\n-----END PUBLIC KEY-----`;
  }

  /**
   * Sign a capability token payload
   * Follows the AWS KMS pattern: hash locally, then sign the digest with KMS
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

    // Hash the signing input locally (as per AWS KMS best practice)
    const hashAlgorithm = getHashAlgorithm(this.algorithm);
    const digest = crypto
      .createHash(hashAlgorithm)
      .update(signingInput)
      .digest();

    // Sign the digest with AWS KMS
    const signCommand = new SignCommand({
      KeyId: this.awsConfig.keyId,
      Message: digest,
      MessageType: 'DIGEST',
      SigningAlgorithm: getAWSSigningAlgorithm(this.algorithm),
    });

    const signResult = await this.kmsClient.send(signCommand);

    if (!signResult.Signature) {
      throw new Error('Failed to sign with AWS KMS');
    }

    // Encode the signature
    const signature = Buffer.from(signResult.Signature);
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
    return this.awsConfig.keyId;
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
    // AWS SDK v3 clients don't need explicit cleanup
    this.publicKeyCache = undefined;
  }
}
