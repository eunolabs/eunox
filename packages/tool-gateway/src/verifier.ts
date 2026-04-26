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
  private cachedKeyObjects: Map<string, jose.KeyLike | Uint8Array> = new Map();
  // Maps revoked JTI → token expiry (Unix seconds).  isRevoked() prunes only
  // the queried entry when it has expired (O(1)), while revokeToken() bulk-prunes
  // all stale entries before inserting so the map stays bounded to the active-
  // token window and does not grow without bound.
  // NOTE: this is an in-process store. In a multi-instance deployment each
  // replica holds its own copy, so a revocation issued to one instance will
  // not be seen by others.  For distributed deployments replace this with a
  // shared store (e.g. Redis) by overriding isRevoked / revokeToken.
  private revokedTokens: Map<string, number> = new Map();
  private algorithms: SigningAlgorithm[];

  /** Default revocation TTL used when the caller does not supply an expiry. */
  private static readonly DEFAULT_REVOCATION_TTL_SECONDS = 86400; // 24 hours

  constructor(publicKey: string, algorithms?: SigningAlgorithm[]) {
    this.publicKey = publicKey;
    // Default to RS256 for backward compatibility, but allow multiple algorithms.
    // Normalize so that an explicitly passed empty array also falls back to RS256.
    this.algorithms = algorithms?.length ? algorithms : ['RS256'];
  }

  /**
   * Verify and decode a capability token
   */
  async verify(token: string): Promise<CapabilityTokenPayload> {
    try {
      // Read the algorithm from the token header so we import the key with the
      // correct alg parameter (jose constrains key usage to the import alg).
      const { alg } = jose.decodeProtectedHeader(token);
      const algorithm = alg ?? this.algorithms[0] ?? 'RS256';

      // Reject tokens whose algorithm is not in the configured allow-list before
      // importing the key, so we fail fast rather than letting jose handle it.
      if (!this.algorithms.includes(algorithm as SigningAlgorithm)) {
        throw new CapabilityError(
          ErrorCode.INVALID_TOKEN,
          `Token uses disallowed algorithm: ${algorithm}`,
          401
        );
      }

      // Import the public key per algorithm (cached for performance; invalidated on key rotation)
      if (!this.cachedKeyObjects.has(algorithm)) {
        const keyObject = await jose.importSPKI(this.publicKey, algorithm);
        this.cachedKeyObjects.set(algorithm, keyObject);
      }
      const keyObject = this.cachedKeyObjects.get(algorithm)!;

      // Verify the token signature and decode
      const { payload } = await jose.jwtVerify(token, keyObject, {
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
   * Check if a token is revoked.
   * Performs an O(1) lookup; the entry is considered absent if its associated
   * token has already expired (so an expired revocation is never reported as
   * active, and the entry will be cleaned up the next time revokeToken runs).
   */
  async isRevoked(tokenId: string): Promise<boolean> {
    const expiry = this.revokedTokens.get(tokenId);
    if (expiry === undefined) {
      return false;
    }
    if (expiry <= Math.floor(Date.now() / 1000)) {
      this.revokedTokens.delete(tokenId);
      return false;
    }
    return true;
  }

  /**
   * Revoke a token (for admin operations).
   * @param tokenId - The JWT ID (jti) of the token to revoke.
   * @param expiresAt - Unix timestamp (seconds) when the token expires.
   *   Provide the token's own `exp` value so the revocation entry can be
   *   automatically pruned once the token is no longer valid anyway.
   *   Defaults to {@link JWTTokenVerifier.DEFAULT_REVOCATION_TTL_SECONDS} from now when omitted.
   */
  revokeToken(tokenId: string, expiresAt?: number): void {
    // Prune all expired entries before adding the new one so the map does
    // not grow indefinitely. This is amortized over revokeToken calls, which
    // are far less frequent than isRevoked calls.
    const now = Math.floor(Date.now() / 1000);
    for (const [jti, expiry] of this.revokedTokens) {
      if (expiry <= now) {
        this.revokedTokens.delete(jti);
      }
    }
    const expiry = expiresAt ?? (now + JWTTokenVerifier.DEFAULT_REVOCATION_TTL_SECONDS);
    this.revokedTokens.set(tokenId, expiry);
  }

  /**
   * Update the public key (for key rotation)
   */
  updatePublicKey(publicKey: string): void {
    this.publicKey = publicKey;
    this.cachedKeyObjects.clear(); // Invalidate cache on key rotation
  }
}
