/**
 * Distributed ID (DID) Identity Provider
 *
 * Implements DID-based identity support with W3C Decentralized Identifiers and
 * Verifiable Credentials for cross-domain agent authentication.
 *
 * Reference: https://www.w3.org/TR/did-core/
 * Reference: https://www.w3.org/TR/vc-data-model/
 */

import {
  IdentityAdapter,
  IdentityAdapterConfig,
  UserContext,
  CapabilityError,
  ErrorCode,
} from '@euno/common';
import * as jose from 'jose';
import {
  resolveDID,
  findVerificationMethod,
  extractPublicKeyPem,
  determineSigningAlgorithm,
  type DIDDocument,
} from './did-resolver';

/**
 * DID-specific configuration
 */
export interface DIDIdentityAdapterConfig extends IdentityAdapterConfig {
  type: 'did';
  /** DID method (e.g., 'ion', 'web', 'key') */
  didMethod?: string;
  /** DID resolver endpoint */
  resolverEndpoint?: string;
  /** Supported DID methods */
  supportedMethods?: string[];
  /** Cache TTL for resolved DID Documents in seconds (default: 300 = 5 minutes) */
  documentCacheTtlSeconds?: number;
}

/** Cached DID Document entry */
interface CachedDIDDocument {
  document: DIDDocument;
  expiresAt: number;
}

/**
 * Distributed ID Identity Provider
 *
 * Implements DID-based identity:
 * - Validates JWT tokens signed with DID keys
 * - Resolves DIDs to DID Documents using universal DID resolver
 * - Supports multiple DID methods (did:ion, did:web, did:key)
 * - Extracts user context from JWT claims
 * - Caches resolved DID Documents to reduce latency and resolver load
 *
 * Note: Full W3C Verifiable Presentation/Credential support requires additional
 * libraries like @digitalbazaar/vc and is not yet implemented.
 */
export class DIDIdentityProvider extends IdentityAdapter {
  public readonly name = 'did';
  private didConfig: DIDIdentityAdapterConfig;
  private documentCache = new Map<string, CachedDIDDocument>();
  private readonly cacheTtlMs: number;
  /** Maximum number of DID Documents held in the cache at one time. */
  private static readonly MAX_CACHE_SIZE = 256;

  constructor(config: DIDIdentityAdapterConfig) {
    super(config);
    this.didConfig = config;
    this.cacheTtlMs = (config.documentCacheTtlSeconds ?? 300) * 1000;
  }

  /**
   * Resolve a DID Document, using the in-memory cache when available.
   *
   * The cache is bounded to MAX_CACHE_SIZE entries.  When the limit is reached
   * the oldest (insertion-order) entry is evicted before adding a new one.
   * Expired entries are also evicted eagerly on each cache miss.
   */
  private async resolveDIDCached(did: string): Promise<DIDDocument> {
    const now = Date.now();
    const cached = this.documentCache.get(did);
    if (cached && cached.expiresAt > now) {
      return cached.document;
    }

    // Evict the stale entry (if any) before fetching a fresh one
    if (cached) {
      this.documentCache.delete(did);
    }

    const document = await resolveDID(did);

    // Enforce maximum cache size: evict the oldest entry (Map preserves insertion order)
    if (this.documentCache.size >= DIDIdentityProvider.MAX_CACHE_SIZE) {
      const oldestKey = this.documentCache.keys().next().value;
      if (oldestKey !== undefined) {
        this.documentCache.delete(oldestKey);
      }
    }

    this.documentCache.set(did, { document, expiresAt: now + this.cacheTtlMs });
    return document;
  }

  /**
   * Validate a JWT token signed with a DID key and extract user context
   *
   * This implementation validates JWT tokens where:
   * - The token is signed by a key from a DID Document
   * - The 'iss' claim contains the issuer DID
   * - The 'sub' claim contains the subject (user) DID
   *
   * Note: Full W3C Verifiable Presentation validation is not yet implemented.
   * For full VC/VP support, use a library like @digitalbazaar/vc.
   */
  async validateToken(token: string): Promise<UserContext> {
    try {
      // Decode header to get key ID and algorithm
      const header = jose.decodeProtectedHeader(token);
      const kid = header.kid;

      if (!kid) {
        throw new CapabilityError(
          ErrorCode.INVALID_TOKEN,
          'Token missing kid (key ID) in header',
          401
        );
      }

      // Extract DID from kid (format: did:method:identifier#key-id)
      const didMatch = kid.match(/^(did:[^#]+)/);
      if (!didMatch) {
        throw new CapabilityError(
          ErrorCode.INVALID_TOKEN,
          `Invalid kid format: ${kid}. Expected DID format (did:method:identifier#key-id)`,
          401
        );
      }

      const issuerDID = didMatch[1];

      if (!issuerDID) {
        throw new CapabilityError(
          ErrorCode.INVALID_TOKEN,
          `Invalid kid format: could not extract DID from ${kid}`,
          401
        );
      }

      // Check if this DID method is supported
      if (this.didConfig.supportedMethods && this.didConfig.supportedMethods.length > 0) {
        const methodMatch = issuerDID.split(':');
        if (methodMatch.length < 2 || !methodMatch[1]) {
          throw new CapabilityError(
            ErrorCode.INVALID_TOKEN,
            `Invalid DID format: ${issuerDID}`,
            401
          );
        }
        const method = methodMatch[1];
        if (!this.didConfig.supportedMethods.includes(method)) {
          throw new CapabilityError(
            ErrorCode.INVALID_TOKEN,
            `DID method '${method}' is not supported. Supported methods: ${this.didConfig.supportedMethods.join(', ')}`,
            401
          );
        }
      }

      // Resolve the issuer DID to get the public key (cached)
      const didDocument = await this.resolveDIDCached(issuerDID);

      // Find the verification method for this key ID
      const keyIdParts = kid.split('#');
      if (keyIdParts.length < 2) {
        throw new CapabilityError(
          ErrorCode.INVALID_TOKEN,
          `Invalid kid format: missing key fragment in ${kid}`,
          401
        );
      }
      const keyId = keyIdParts[1];
      const verificationMethod = findVerificationMethod(didDocument, keyId);

      if (!verificationMethod) {
        throw new CapabilityError(
          ErrorCode.INVALID_TOKEN,
          `Verification method not found for key ID: ${kid}`,
          401
        );
      }

      // Get the public key and algorithm
      const publicKeyPem = extractPublicKeyPem(verificationMethod);
      const algorithm = determineSigningAlgorithm(verificationMethod);

      // Import the public key
      const publicKey = await jose.importSPKI(publicKeyPem, algorithm);

      // Verify the JWT
      const { payload } = await jose.jwtVerify(token, publicKey, {
        algorithms: [algorithm],
        issuer: issuerDID,
      });

      // Enforce that the iss claim matches the DID extracted from kid
      if (payload.iss !== issuerDID) {
        throw new CapabilityError(
          ErrorCode.INVALID_TOKEN,
          `Token issuer mismatch: expected ${issuerDID}, got ${payload.iss}`,
          401
        );
      }

      // Require a subject claim
      if (!payload.sub) {
        throw new CapabilityError(
          ErrorCode.INVALID_TOKEN,
          'Token missing required sub (subject) claim',
          401
        );
      }

      // Extract user context from JWT claims
      const userId = payload.sub as string;
      const email = payload.email as string | undefined;
      const roles = (payload.roles as string[]) || [];

      // Extract additional claims
      const claims: Record<string, unknown> = {
        did: issuerDID,
        kid: kid,
      };

      // Copy all JWT claims to user context
      for (const [key, value] of Object.entries(payload)) {
        if (!['sub', 'iss', 'aud', 'exp', 'iat', 'email', 'roles'].includes(key)) {
          claims[key] = value;
        }
      }

      const userContext: UserContext = {
        userId,
        roles,
        claims,
      };

      if (email) {
        userContext.email = email;
      }

      return userContext;
    } catch (error) {
      if (error instanceof CapabilityError) {
        throw error;
      }

      // Map jose JWT errors
      if (error instanceof Error) {
        if ((error as any).code === 'ERR_JWT_EXPIRED') {
          throw new CapabilityError(
            ErrorCode.EXPIRED_TOKEN,
            'Token has expired',
            401
          );
        }

        if (
          (error as any).code === 'ERR_JWS_INVALID' ||
          (error as any).code === 'ERR_JWT_CLAIM_VALIDATION_FAILED' ||
          (error as any).code === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED'
        ) {
          throw new CapabilityError(
            ErrorCode.INVALID_TOKEN,
            `Invalid token: ${error.message}`,
            401
          );
        }
      }

      throw new CapabilityError(
        ErrorCode.INVALID_TOKEN,
        `Failed to validate DID token: ${error instanceof Error ? error.message : 'Unknown error'}`,
        401
      );
    }
  }

  /**
   * Get user roles from JWT claims
   *
   * Note: This is a simplified implementation. Full VC-based role extraction
   * would query a credential registry or parse embedded VCs.
   */
  async getUserRoles(_userId: string): Promise<string[]> {
    // For DID-based identity, roles are typically embedded in the JWT token
    // and extracted during validateToken(). This method would need additional
    // context or a credential registry to fetch roles independently.
    //
    // For now, return empty array. Roles should be obtained from validateToken().
    return [];
  }

  /**
   * Check if a DID holder has a specific permission
   *
   * Note: This is a simplified implementation using the base class logic.
   * Full VC-based permission checking would query for specific capability credentials.
   */
  async hasPermission(userId: string, permission: string): Promise<boolean> {
    const roles = await this.getUserRoles(userId);
    return roles.includes(permission);
  }

  /**
   * Initialize the DID resolver
   */
  async initialize(): Promise<void> {
    // Validate supported methods if specified
    if (this.didConfig.supportedMethods) {
      const validMethods = ['web', 'ion', 'key'];
      for (const method of this.didConfig.supportedMethods) {
        if (!validMethods.includes(method)) {
          throw new CapabilityError(
            ErrorCode.INVALID_REQUEST,
            `Unsupported DID method: ${method}. Valid methods: ${validMethods.join(', ')}`,
            400
          );
        }
      }
    }

    // Initialization complete
  }
}
