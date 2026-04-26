/**
 * Token Verifier for Tool Gateway
 * Verifies and validates capability tokens
 */

import * as jose from 'jose';
import {
  TokenVerifier,
  CapabilityTokenPayload,
  CapabilityError,
  ErrorCode,
  SigningAlgorithm,
} from '@euno/common';

export class JWTTokenVerifier implements TokenVerifier {
  private publicKey: string;
  private cachedKeyObject: jose.KeyLike | Uint8Array | null = null;
  private revokedTokens: Set<string> = new Set();
  private algorithms: SigningAlgorithm[];

  constructor(publicKey: string, algorithms?: SigningAlgorithm[]) {
    this.publicKey = publicKey;
    // Default to RS256 for backward compatibility, but allow multiple algorithms
    this.algorithms = algorithms || ['RS256'];
  }

  /**
   * Verify and decode a capability token
   */
  async verify(token: string): Promise<CapabilityTokenPayload> {
    try {
      // Import the public key (cached for performance; invalidated on key rotation)
      if (!this.cachedKeyObject) {
        // Use the first configured algorithm for key import
        const algorithm = this.algorithms[0] || 'RS256';
        this.cachedKeyObject = await jose.importSPKI(this.publicKey, algorithm);
      }

      // Verify the token signature and decode
      const { payload } = await jose.jwtVerify(token, this.cachedKeyObject, {
        algorithms: this.algorithms,
      });

      // Check if token is revoked
      const tokenId = payload.jti as string;
      if (tokenId && await this.isRevoked(tokenId)) {
        throw new CapabilityError(
          ErrorCode.TOKEN_REVOKED,
          'Token has been revoked',
          401
        );
      }

      // Cast payload to CapabilityTokenPayload
      return payload as unknown as CapabilityTokenPayload;
    } catch (error) {
      if (error instanceof CapabilityError) {
        throw error;
      }

      // Map jose JWTExpired to EXPIRED_TOKEN so callers get the correct error code
      if (error instanceof Error && (error as any).code === 'ERR_JWT_EXPIRED') {
        throw new CapabilityError(
          ErrorCode.EXPIRED_TOKEN,
          'Token has expired',
          401
        );
      }

      throw new CapabilityError(
        ErrorCode.INVALID_TOKEN,
        `Token verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        401
      );
    }
  }

  /**
   * Check if a token is revoked
   */
  async isRevoked(tokenId: string): Promise<boolean> {
    return this.revokedTokens.has(tokenId);
  }

  /**
   * Revoke a token (for admin operations)
   */
  revokeToken(tokenId: string): void {
    this.revokedTokens.add(tokenId);
  }

  /**
   * Update the public key (for key rotation)
   */
  updatePublicKey(publicKey: string): void {
    this.publicKey = publicKey;
    this.cachedKeyObject = null; // Invalidate cache on key rotation
  }
}
