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
import { PartnerIssuerResolver } from './partner-issuer-resolver';

export class JWTTokenVerifier implements TokenVerifier {
  private publicKey: string;
  private cachedKeyObjects: Map<string, jose.KeyLike | Uint8Array> = new Map();
  // Pluggable revocation backend.  Defaults to an in-process store; production
  // multi-instance deployments should inject a shared store (e.g.
  // RedisRevocationStore) so revocations are visible across replicas.
  // See `docs/DISTRIBUTED_REVOCATION.md` for the operational architecture.
  private revocationStore: RevocationStore;
  private algorithms: SigningAlgorithm[];
  /**
   * Optional cross-org partner-issuer trust resolver.  When configured,
   * tokens whose `iss` claim matches a trusted partner DID are verified
   * against the public key advertised in the partner's DID document
   * instead of the gateway's local SPKI key.  Tokens from untrusted
   * issuers continue to be rejected by the local-key path.
   *
   * See `docs/sprint-3-4-gaps/05-cross-org-trust-harness.md`.
   */
  private partnerResolver?: PartnerIssuerResolver;
  /**
   * Optional list of issuer DIDs/strings the local SPKI key is allowed
   * to sign for.  When the partner resolver is configured AND the token's
   * `iss` claim is a trusted partner DID, verification routes through the
   * partner resolver; otherwise it falls back to the local SPKI path.
   * Empty / undefined means the local-key path accepts any `iss`
   * (preserves Sprint-1/2 behaviour).
   */
  private localIssuers?: Set<string>;

  /** Default revocation TTL used when the caller does not supply an expiry. */
  private static readonly DEFAULT_REVOCATION_TTL_SECONDS = 86400; // 24 hours

  constructor(
    publicKey: string,
    algorithms?: SigningAlgorithm[],
    revocationStore?: RevocationStore,
    partnerResolver?: PartnerIssuerResolver,
    localIssuers?: string[]
  ) {
    this.publicKey = publicKey;
    // Default to RS256 for backward compatibility, but allow multiple algorithms.
    // Normalize so that an explicitly passed empty array also falls back to RS256.
    this.algorithms = algorithms?.length ? algorithms : ['RS256'];
    this.revocationStore = revocationStore ?? new InMemoryRevocationStore();
    this.partnerResolver = partnerResolver;
    if (localIssuers && localIssuers.length > 0) {
      this.localIssuers = new Set(localIssuers);
    }
  }

  /**
   * Verify and decode a capability token
   */
  async verify(token: string): Promise<CapabilityTokenPayload> {
    try {
      // Read the algorithm from the token header so we import the key with the
      // correct alg parameter (jose constrains key usage to the import alg).
      const header = jose.decodeProtectedHeader(token);
      const alg = header.alg;
      const algorithm = alg ?? this.algorithms[0] ?? 'RS256';

      // Reject tokens whose algorithm is not in the configured allow-list before
      // importing the key, so we fail fast rather than letting jose handle it.
      // Partner DIDs may legitimately use algorithms (e.g. EdDSA) the local
      // signer does not, so when the token's `iss` is a trusted partner DID
      // we defer the algorithm check to the algorithm declared in the
      // partner's DID document instead of `this.algorithms`.
      let payload: CapabilityTokenPayload;
      let iss: string | undefined;
      try {
        const decoded = jose.decodeJwt(token);
        iss = typeof decoded.iss === 'string' ? decoded.iss : undefined;
      } catch {
        // The signature step below will produce a clearer error.
      }

      const useResolver = this.partnerResolver && iss && this.partnerResolver.trusts(iss);

      if (useResolver) {
        // Cross-org path: resolve the partner DID's verification key and use
        // the algorithm declared in its DID document.  The local algorithm
        // allow-list is intentionally bypassed because partner DIDs commonly
        // use EdDSA / ES256 even when the local signer is RS256.
        const kid = typeof header.kid === 'string' ? header.kid : undefined;
        const { key: partnerKey, alg: partnerAlg } = await this.partnerResolver!.getKey(iss!, kid);
        try {
          const result = await jose.jwtVerify(token, partnerKey, {
            algorithms: [partnerAlg],
            issuer: iss!,
          });
          payload = result.payload as unknown as CapabilityTokenPayload;
        } catch (err) {
          // Drop the cached key on failure so the next attempt re-resolves
          // the DID document (handles out-of-band key rotation cleanly).
          this.partnerResolver!.invalidate(iss!, kid);
          throw err;
        }
      } else {
        // Local path: verify against the gateway's bootstrapped SPKI key.
        if (!this.algorithms.includes(algorithm as SigningAlgorithm)) {
          throw new CapabilityError(
            ErrorCode.INVALID_TOKEN,
            `Token uses disallowed algorithm: ${algorithm}`,
            401
          );
        }

        // If a partner resolver is configured AND a local-issuer allow-list
        // exists, reject tokens whose issuer is neither a trusted partner
        // nor a recognised local issuer (defence in depth: stops a token
        // signed by the local key from impersonating a partner DID).
        if (this.partnerResolver && this.localIssuers && iss && !this.localIssuers.has(iss)) {
          throw new CapabilityError(
            ErrorCode.INVALID_TOKEN,
            `Token issuer ${iss} is neither a trusted partner DID nor a known local issuer`,
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
        const result = await jose.jwtVerify(token, keyObject, {
          algorithms: this.algorithms,
        });
        payload = result.payload as unknown as CapabilityTokenPayload;
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

      // Validate schema version (fail-closed on unknown versions)
      const schemaVersion = payload.schemaVersion;
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

      return payload;
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
