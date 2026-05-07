/**
 * DID-based Token Signer
 *
 * Implements DID-based signing for capability tokens using keys from DID Documents.
 * Supports did:web method with full resolution and signing capabilities.
 *
 * Reference: https://www.w3.org/TR/did-core/#verification-methods
 */

import {
  SigningAdapter,
  SigningAdapterConfig,
  CapabilityTokenPayload,
  CapabilityError,
  ErrorCode,
  IssuanceContext,
} from '@euno/common';
import * as jose from 'jose';
import {
  resolveDID,
  findVerificationMethod,
  extractPublicKeyPem,
  determineSigningAlgorithm,
  type DIDDocument,
  type VerificationMethod,
} from './did-resolver';

/**
 * DID signing configuration
 */
export interface DIDSigningAdapterConfig extends SigningAdapterConfig {
  type: 'did';
  /** DID of the issuer */
  issuerDID: string;
  /** Key ID within the DID Document to use for signing */
  keyId?: string;
  /** Private key material (in production, use HSM or secure key storage) */
  privateKey: string;
  /** Private key format (e.g., 'jwk', 'pem') */
  privateKeyFormat?: 'jwk' | 'pem';
}

/**
 * DID-based Token Signer
 *
 * Implements DID-based signing:
 * - Resolves issuer DID to get DID Document
 * - Uses verification method from DID Document for signing
 * - Signs tokens with key referenced in DID Document
 * - Supports multiple key types (RSA, EC, Ed25519)
 * - Enables verifiers to validate signatures using DID resolution
 */
export class DIDSigner extends SigningAdapter {
  private didConfig: DIDSigningAdapterConfig;
  private didDocument: DIDDocument | null = null;
  private verificationMethod: VerificationMethod | null = null;
  private privateKeyObj: jose.KeyLike | Uint8Array | null = null;

  constructor(config: DIDSigningAdapterConfig) {
    super(config);
    this.didConfig = config;
  }

  /**
   * Sign a capability token using DID-referenced key
   */
  async sign(payload: CapabilityTokenPayload, _context?: IssuanceContext): Promise<string> {
    await this.ensureInitialized();

    if (!this.privateKeyObj || !this.verificationMethod) {
      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        'DID signer not properly initialized',
        500
      );
    }

    const kid = this.verificationMethod.id;
    const alg = determineSigningAlgorithm(this.verificationMethod);

    // Sign the JWT using jose
    const jwt = await new jose.SignJWT(payload as unknown as jose.JWTPayload)
      .setProtectedHeader({
        alg,
        typ: 'JWT',
        kid,
      })
      .setIssuedAt()
      .setExpirationTime(payload.exp)
      .sign(this.privateKeyObj);

    return jwt;
  }

  /**
   * Get the public key for verification
   */
  async getPublicKey(): Promise<string> {
    await this.ensureInitialized();

    if (!this.verificationMethod) {
      throw new CapabilityError(
        ErrorCode.INTERNAL_ERROR,
        'DID signer not properly initialized',
        500
      );
    }

    return await extractPublicKeyPem(this.verificationMethod);
  }

  /**
   * Get the key ID used for signing
   *
   * Returns the full DID URL (e.g., "did:ion:abc123#key-1")
   */
  async getKeyId(): Promise<string> {
    if (this.didConfig.keyId) {
      return `${this.didConfig.issuerDID}#${this.didConfig.keyId}`;
    }
    return `${this.didConfig.issuerDID}#key-1`;
  }

  /**
   * Initialize the signer with key material
   */
  async initialize(): Promise<void> {
    // Resolve DID Document to get public key and algorithm
    this.didDocument = await resolveDID(this.didConfig.issuerDID);

    // Find the verification method for signing
    this.verificationMethod = findVerificationMethod(this.didDocument, this.didConfig.keyId);

    if (!this.verificationMethod) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        `No verification method found in DID Document for ${this.didConfig.issuerDID}`,
        400
      );
    }

    // Load private key from configuration
    if (!this.didConfig.privateKey) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        'Private key is required for DID signing. Set privateKey in configuration.',
        400
      );
    }

    // Import private key based on format
    const format = this.didConfig.privateKeyFormat || 'pem';
    const alg = determineSigningAlgorithm(this.verificationMethod);

    try {
      if (format === 'pem') {
        this.privateKeyObj = await jose.importPKCS8(this.didConfig.privateKey, alg);
      } else if (format === 'jwk') {
        this.privateKeyObj = await jose.importJWK(JSON.parse(this.didConfig.privateKey), alg);
      } else {
        throw new CapabilityError(
          ErrorCode.INVALID_REQUEST,
          `Unsupported private key format: ${format}`,
          400
        );
      }
    } catch (error) {
      throw new CapabilityError(
        ErrorCode.INVALID_REQUEST,
        `Failed to import private key: ${error instanceof Error ? error.message : 'Unknown error'}`,
        400
      );
    }

    // Update algorithm from verification method
    this.algorithm = alg as any;
  }

  /**
   * Ensure the signer is initialized before use
   */
  private async ensureInitialized(): Promise<void> {
    if (!this.didDocument || !this.verificationMethod || !this.privateKeyObj) {
      await this.initialize();
    }
  }
}
