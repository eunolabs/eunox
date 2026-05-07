/**
 * AWS KMS Token Signer
 * Implements cryptographic signing using AWS Key Management Service
 */

import { KMSClient, SignCommand, GetPublicKeyCommand, SigningAlgorithmSpec } from '@aws-sdk/client-kms';
import { SigningAdapter, SigningAdapterConfig, SigningAlgorithm, CapabilityTokenPayload, AWSKMSConfig, IssuanceContext, resolveIssuanceContextKey } from '@euno/common';
import * as crypto from 'crypto';

/**
 * Convert a DER-encoded ECDSA signature to the JOSE (r||s) format required by JWS/JWT.
 * AWS KMS returns DER-encoded ECDSA signatures; JWT expects the raw concatenated (r||s) bytes.
 */
export function derEcdsaToJose(derBuffer: Buffer, algorithm: SigningAlgorithm): Buffer {
  const coordinateSize = algorithm === 'ES512' ? 66 : algorithm === 'ES384' ? 48 : 32;

  let offset = 0;

  // SEQUENCE tag
  if ((derBuffer[offset++] ?? 0) !== 0x30) {
    throw new Error('Invalid DER signature: missing SEQUENCE tag');
  }

  // SEQUENCE length (short or long form)
  if ((derBuffer[offset] ?? 0) & 0x80) {
    offset += ((derBuffer[offset] ?? 0) & 0x7f) + 1;
  } else {
    offset++;
  }

  // INTEGER tag for r
  if ((derBuffer[offset++] ?? 0) !== 0x02) {
    throw new Error('Invalid DER signature: missing INTEGER tag for r');
  }
  const rLen = derBuffer[offset++] ?? 0;
  let r = derBuffer.slice(offset, offset + rLen);
  offset += rLen;

  // INTEGER tag for s
  if ((derBuffer[offset++] ?? 0) !== 0x02) {
    throw new Error('Invalid DER signature: missing INTEGER tag for s');
  }
  const sLen = derBuffer[offset++] ?? 0;
  let s = derBuffer.slice(offset, offset + sLen);

  // Strip all leading zero bytes. DER uses leading zeros to indicate positive integers
  // when the MSB is set; we strip them all here and re-pad to the exact coordinate size below.
  while (r.length > 0 && r[0] === 0x00) r = r.slice(1);
  while (s.length > 0 && s[0] === 0x00) s = s.slice(1);

  if (r.length > coordinateSize || s.length > coordinateSize) {
    throw new Error('Invalid DER signature: r or s value exceeds expected coordinate size');
  }

  // Pad each component to the required coordinate size
  const rPadded = Buffer.alloc(coordinateSize);
  r.copy(rPadded, coordinateSize - r.length);

  const sPadded = Buffer.alloc(coordinateSize);
  s.copy(sPadded, coordinateSize - s.length);

  return Buffer.concat([rPadded, sPadded]);
}

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
   * Initialize the KMS client and cache public key.
   * Also auto-detects the signing algorithm from the key spec when config.algorithm is not set.
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

    // Auto-detect signing algorithm from key spec when not explicitly configured
    if (!this.config.algorithm) {
      const keySpec = response.KeySpec;
      if (keySpec?.includes('ECC_NIST_P256')) {
        this.algorithm = 'ES256';
      } else if (keySpec?.includes('ECC_NIST_P384')) {
        this.algorithm = 'ES384';
      } else if (keySpec?.includes('ECC_NIST_P521')) {
        this.algorithm = 'ES512';
      } else if (keySpec?.startsWith('RSA_')) {
        // Pick the best available RSA signing algorithm
        const algos = response.SigningAlgorithms || [];
        if (algos.includes('RSASSA_PKCS1_V1_5_SHA_512')) {
          this.algorithm = 'RS512';
        } else if (algos.includes('RSASSA_PKCS1_V1_5_SHA_384')) {
          this.algorithm = 'RS384';
        } else {
          this.algorithm = 'RS256';
        }
      } else if (keySpec) {
        throw new Error(`Unsupported AWS KMS key spec: ${keySpec}`);
      }
      // If keySpec is undefined, keep the default algorithm (RS256)
    }
  }

  /**
   * Sign a capability token payload.
   *
   * When an {@link IssuanceContext} is supplied and the `policyHash` maps to
   * an entry in {@link AWSKMSConfig.grantTokensByPolicyHash}, the matching
   * grant token is included in the `SignCommand.GrantTokens` array.  AWS KMS
   * then validates that the caller holds a grant scoped to this policy hash,
   * bringing the policy boundary into the cryptographic boundary without
   * requiring a broad `kms:Sign` IAM allow-all statement.
   *
   * When no `context` is supplied (or the `policyHash` is unmapped), the call
   * proceeds with no `GrantTokens`; the operation is authorised by whatever
   * IAM policy or grant the caller holds — full backward compatibility.
   */
  async sign(payload: CapabilityTokenPayload, context?: IssuanceContext): Promise<string> {
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

    // Sign the digest with AWS KMS.
    // When the caller supplied an IssuanceContext, look up the grant token
    // using a composite key "${policyHash}:${audience}" first, then fall back
    // to plain policyHash.  Composite keys let operators assign different grants
    // to different tenants even when they share the same policy document.
    // Omitting GrantTokens is always safe: KMS falls back to IAM policy
    // evaluation, preserving full back-compat.
    const grantToken =
      context !== undefined && this.awsConfig.grantTokensByPolicyHash !== undefined
        ? (this.awsConfig.grantTokensByPolicyHash[resolveIssuanceContextKey(context)] ??
           this.awsConfig.grantTokensByPolicyHash[context.policyHash])
        : undefined;

    const signCommand = new SignCommand({
      KeyId: this.awsConfig.keyId,
      Message: digest,
      MessageType: 'DIGEST',
      SigningAlgorithm: getAWSSigningAlgorithm(this.algorithm),
      ...(grantToken !== undefined ? { GrantTokens: [grantToken] } : {}),
    });

    const signResult = await this.kmsClient.send(signCommand);

    if (!signResult.Signature) {
      throw new Error('Failed to sign with AWS KMS');
    }

    // For ECDSA algorithms, convert the DER-encoded signature to the JOSE (r||s) format
    // required by JWT/JWS. RSA signatures are used as-is.
    let signatureBuffer: Buffer = Buffer.from(signResult.Signature as Uint8Array);
    if (this.algorithm === 'ES256' || this.algorithm === 'ES384' || this.algorithm === 'ES512') {
      signatureBuffer = derEcdsaToJose(signatureBuffer, this.algorithm);
    }

    // Encode the signature
    const encodedSignature = this.base64UrlEncode(signatureBuffer);

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
    this.kmsClient.destroy();
    this.publicKeyCache = undefined;
  }
}
