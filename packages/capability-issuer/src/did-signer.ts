/**
 * DID-based Token Signer Stub
 *
 * This is a placeholder implementation for future DID-based signing support.
 * When implemented, this will sign capability tokens using keys from DID Documents.
 *
 * Reference: https://www.w3.org/TR/did-core/#verification-methods
 */

import {
  SigningAdapter,
  SigningAdapterConfig,
  SigningAlgorithm,
  CapabilityTokenPayload,
  CapabilityError,
  ErrorCode,
} from '@euno/common';

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
  privateKey?: string;
  /** Private key format (e.g., 'jwk', 'pem') */
  privateKeyFormat?: 'jwk' | 'pem';
}

/**
 * DID-based Token Signer
 *
 * Future implementation will:
 * - Resolve issuer DID to get DID Document
 * - Use verification method from DID Document for signing
 * - Sign tokens with key referenced in DID Document
 * - Support multiple key types (RSA, EC, Ed25519)
 * - Enable verifiers to validate signatures using DID resolution
 */
export class DIDSigner extends SigningAdapter {
  private didConfig: DIDSigningAdapterConfig;

  constructor(config: DIDSigningAdapterConfig) {
    super(config);
    this.didConfig = config;
  }

  /**
   * Sign a capability token using DID-referenced key
   *
   * TODO: Implement DID-based signing:
   * 1. Load private key from secure storage (HSM, Key Vault, local wallet)
   * 2. Create JWT header with 'kid' pointing to DID#key-id
   * 3. Sign token using key algorithm from DID Document
   * 4. Return signed JWT
   */
  async sign(_payload: CapabilityTokenPayload): Promise<string> {
    throw new CapabilityError(
      ErrorCode.NOT_IMPLEMENTED,
      'DID signer not yet implemented. This is a placeholder for future DID-based signing support.',
      501
    );

    // Future implementation pseudocode:
    // await this.initialize();
    //
    // const kid = this.didConfig.keyId
    //   ? `${this.didConfig.issuerDID}#${this.didConfig.keyId}`
    //   : `${this.didConfig.issuerDID}#key-1`;
    //
    // const header = {
    //   alg: this.determineAlgorithm(),
    //   typ: 'JWT',
    //   kid
    // };
    //
    // const token = await this.signJWT(header, payload, this.privateKeyCache);
    // return token;
  }

  /**
   * Get the public key for verification
   *
   * TODO: Extract public key from DID Document
   */
  async getPublicKey(): Promise<string> {
    throw new CapabilityError(
      ErrorCode.NOT_IMPLEMENTED,
      'DID signer not yet implemented.',
      501
    );

    // Future implementation:
    // const didDocument = await this.resolveDID(this.didConfig.issuerDID);
    // const verificationMethod = this.findVerificationMethod(didDocument, this.didConfig.keyId);
    // const publicKey = this.extractPublicKey(verificationMethod);
    // return publicKey; // Return in PEM format
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
    // TODO: Load private key from configuration or secure storage
    // TODO: Resolve DID Document to get public key and algorithm
    // TODO: Validate key pair matches

    // if (this.didConfig.privateKey) {
    //   if (this.didConfig.privateKeyFormat === 'jwk') {
    //     this.privateKeyCache = await jose.importJWK(JSON.parse(this.didConfig.privateKey));
    //   } else if (this.didConfig.privateKeyFormat === 'pem') {
    //     this.privateKeyCache = await jose.importPKCS8(this.didConfig.privateKey, 'RS256');
    //   }
    // }

    // For now, this is a no-op
  }

  /**
   * Resolve DID Document for the issuer
   */
  // @ts-expect-error - Stub method for future implementation
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  private async _resolveDID(_did: string): Promise<any> {
    // TODO: Implement using DID resolver
    throw new Error('Not implemented');
  }

  /**
   * Find the verification method in DID Document
   */
  // @ts-expect-error - Stub method for future implementation
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  private _findVerificationMethod(_didDocument: any, _keyId?: string): any {
    // TODO: Search verificationMethod array in DID Document
    // If keyId provided, find matching method
    // Otherwise, use first available signing key
    throw new Error('Not implemented');
  }

  /**
   * Extract public key from verification method
   */
  // @ts-expect-error - Stub method for future implementation
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  private _extractPublicKey(_verificationMethod: any): string {
    // TODO: Convert verification method to PEM format
    // Handle different key types (RSA, EC, Ed25519)
    throw new Error('Not implemented');
  }

  /**
   * Determine signing algorithm from key type
   */
  // @ts-expect-error - Stub method for future implementation
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  private _determineAlgorithm(): SigningAlgorithm {
    // Use configured algorithm if available
    if (this.config.algorithm) {
      return this.config.algorithm;
    }

    // TODO: Detect from DID Document verification method key type
    // For now, return the default from base class
    return this.algorithm;
  }
}
