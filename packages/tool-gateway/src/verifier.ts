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
  isExpired,
} from '@euno/common';

export class JWTTokenVerifier implements TokenVerifier {
  private publicKey: string;
  private revokedTokens: Set<string> = new Set();

  constructor(publicKey: string) {
    this.publicKey = publicKey;
  }

  /**
   * Verify and decode a capability token
   */
  async verify(token: string): Promise<CapabilityTokenPayload> {
    try {
      // Import the public key
      const publicKeyObj = await jose.importSPKI(this.publicKey, 'RS256');

      // Verify the token signature and decode
      const { payload } = await jose.jwtVerify(token, publicKeyObj, {
        algorithms: ['RS256'],
      });

      // Check expiration
      if (payload.exp && isExpired(payload.exp as number)) {
        throw new CapabilityError(
          ErrorCode.EXPIRED_TOKEN,
          'Token has expired',
          401
        );
      }

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
  }
}
