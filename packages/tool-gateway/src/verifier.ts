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
  SUPPORTED_SCHEMA_VERSIONS,
} from '@euno/common';
import { InMemoryRevocationStore, RevocationStore } from './revocation-store';

export class JWTTokenVerifier implements TokenVerifier {
  private publicKey: string;
  private cachedKeyObjects: Map<string, jose.KeyLike | Uint8Array> = new Map();
  // Pluggable revocation backend.  Defaults to an in-process store; production
  // multi-instance deployments should inject a shared store (e.g.
  // RedisRevocationStore) so revocations are visible across replicas.
  // See `docs/DISTRIBUTED_REVOCATION.md` for the operational architecture.
  private revocationStore: RevocationStore;
  private algorithms: SigningAlgorithm[];

  /** Default revocation TTL used when the caller does not supply an expiry. */
  private static readonly DEFAULT_REVOCATION_TTL_SECONDS = 86400; // 24 hours

  constructor(
    publicKey: string,
    algorithms?: SigningAlgorithm[],
    revocationStore?: RevocationStore
  ) {
    this.publicKey = publicKey;
    // Default to RS256 for backward compatibility, but allow multiple algorithms.
    // Normalize so that an explicitly passed empty array also falls back to RS256.
    this.algorithms = algorithms?.length ? algorithms : ['RS256'];
    this.revocationStore = revocationStore ?? new InMemoryRevocationStore();
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
      const capabilityPayload = payload as unknown as CapabilityTokenPayload;

      // Validate schema version (fail-closed on unknown versions)
      const schemaVersion = capabilityPayload.schemaVersion;
      if (!schemaVersion) {
        throw new CapabilityError(
          ErrorCode.INVALID_TOKEN,
          'Token missing required schemaVersion field',
          401
        );
      }
      if (!SUPPORTED_SCHEMA_VERSIONS.has(schemaVersion)) {
        throw new CapabilityError(
          ErrorCode.INVALID_TOKEN,
          `Unsupported token schema version: ${schemaVersion}. Supported versions: ${Array.from(SUPPORTED_SCHEMA_VERSIONS).join(', ')}`,
          401
        );
      }

      return capabilityPayload;
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
   *
   * Delegates to the configured {@link RevocationStore}.  The default
   * in-memory store performs an O(1) lookup; alternative backends (Redis,
   * etc.) may add network latency but are required for correctness across
   * multiple gateway instances.
   */
  async isRevoked(tokenId: string): Promise<boolean> {
    return this.revocationStore.isRevoked(tokenId);
  }

  /**
   * Revoke a token (for admin operations).
   * @param tokenId - The JWT ID (jti) of the token to revoke.
   * @param expiresAt - Unix timestamp (seconds) when the token expires.
   *   Provide the token's own `exp` value so the revocation entry can be
   *   automatically pruned once the token is no longer valid anyway.
   *   Defaults to {@link JWTTokenVerifier.DEFAULT_REVOCATION_TTL_SECONDS} from now when omitted.
   *
   * Returns a Promise so distributed (e.g. Redis-backed) stores can perform
   * I/O.  Callers that previously treated this as fire-and-forget should
   * `await` it to surface backend failures.
   */
  async revokeToken(tokenId: string, expiresAt?: number): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    const expiry = expiresAt ?? (now + JWTTokenVerifier.DEFAULT_REVOCATION_TTL_SECONDS);
    await this.revocationStore.revoke(tokenId, expiry);
  }

  /**
   * Replace the revocation backend (e.g. to swap an in-memory store for a
   * Redis-backed one once the connection is established).  Closes the
   * previous store on a best-effort basis.
   */
  async setRevocationStore(store: RevocationStore): Promise<void> {
    const previous = this.revocationStore;
    this.revocationStore = store;
    if (previous && previous !== store) {
      try {
        await previous.close();
      } catch {
        // best-effort close; the new store is already in place
      }
    }
  }

  /**
   * Update the public key (for key rotation)
   */
  updatePublicKey(publicKey: string): void {
    this.publicKey = publicKey;
    this.cachedKeyObjects.clear(); // Invalidate cache on key rotation
  }
}
