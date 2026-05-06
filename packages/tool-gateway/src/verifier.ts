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
  JwksKeySource,
  pickJwkByKid,
} from '@euno/common';
import { InMemoryRevocationStore, RevocationStore, RevocationEpochStore } from './revocation-store';
import { PartnerIssuerResolver } from './partner-issuer-resolver';
import { JwksClient } from './jwks-client';
import { ProofsVerifier } from './proofs-verifier';

/**
 * Constructor options for {@link JWTTokenVerifier} (and its
 * {@link JwksTokenVerifier} subclass).
 *
 * The options bag is the documented constructor form. The legacy
 * positional signature is still accepted by {@link JWTTokenVerifier}
 * for in-tree back-compat, but new call sites — and especially any
 * external embedder — should use this object so security-sensitive
 * defaults like {@link requireKid} are explicit at the call site.
 */
export interface JWTTokenVerifierOptions {
  /** JWT signing algorithms the verifier will accept (default `['RS256']`). */
  algorithms?: SigningAlgorithm[];
  /** Revocation store backend (default: in-process `InMemoryRevocationStore`). */
  revocationStore?: RevocationStore;
  /** Cross-org partner-issuer trust resolver. */
  partnerResolver?: PartnerIssuerResolver;
  /** Issuer IDs (DIDs or plain strings) the local SPKI key is allowed to sign for. */
  localIssuers?: string[];
  /** JWKS-based key source (R-6). When set, tokens carrying a `kid` are routed here. */
  jwksKeySource?: JwksKeySource;
  /**
   * Whether to require a `kid` in every JWT protected header.
   *
   * Defaults to `true` so embedders that omit the option get the same
   * strict behaviour as the production gateway (`EUNO_REQUIRE_KID`
   * also defaults to `true`).  Set to `false` only during a rolling
   * deploy while tokens that pre-date the JWKS migration are still
   * in circulation.
   */
  requireKid?: boolean;
  /** Optional cosignature + transparency-log proofs verifier. */
  proofsVerifier?: ProofsVerifier;
  /**
   * Optional per-issuer epoch store (revoke-all-before-T mechanism).
   * When supplied, tokens whose `iat` is strictly before the epoch
   * recorded for their `iss` are rejected.
   */
  epochStore?: RevocationEpochStore;
}

export class JWTTokenVerifier implements TokenVerifier {
  private publicKey: string;
  private cachedKeyObjects: Map<string, jose.KeyLike | Uint8Array> = new Map();
  // Pluggable revocation backend.  Defaults to an in-process store; production
  // multi-instance deployments should inject a shared store (e.g.
  // RedisRevocationStore) so revocations are visible across replicas.
  // See `docs/DISTRIBUTED_REVOCATION.md` for the operational architecture.
  private revocationStore: RevocationStore;
  /**
   * Optional per-issuer epoch store.  When configured, `performPostVerificationChecks`
   * rejects any token whose `iat` is strictly before the epoch recorded for
   * its `iss` claim.  This gives incident responders a single-knob cut-off
   * for a compromised signing key without enumerating every outstanding JTI.
   */
  protected epochStore?: RevocationEpochStore;
  /** Protected so subclasses (e.g. JwksTokenVerifier) can access in verify(). */
  protected algorithms: SigningAlgorithm[];
  /**
   * Optional cross-org partner-issuer trust resolver.  When configured,
   * tokens whose `iss` claim matches a trusted partner DID are verified
   * against the public key advertised in the partner's DID document
   * instead of the gateway's local SPKI key.  Tokens from untrusted
   * issuers continue to be rejected by the local-key path.
   *
   * See `docs/sprint-3-4-gaps/05-cross-org-trust-harness.md`.
   */
  protected partnerResolver?: PartnerIssuerResolver;
  /**
   * Optional list of issuer DIDs/strings the local SPKI key is allowed
   * to sign for.  When the partner resolver is configured AND the token's
   * `iss` claim is a trusted partner DID, verification routes through the
   * partner resolver; otherwise it falls back to the local SPKI path.
   * Empty / undefined means the local-key path accepts any `iss`
   * (preserves Sprint-1/2 behaviour).
   */
  protected localIssuers?: Set<string>;

  /**
   * Optional JWKS key source (R-6).  When provided, the local key path
   * uses JWKS-based key selection by `kid` instead of the single SPKI
   * (`publicKey`).  If both are present the JWKS source takes precedence
   * for any token that carries a `kid` header.
   */
  private jwksKeySource?: JwksKeySource;

  /**
   * Whether to require a `kid` in the JWT protected header (R-6).
   * Defaults to `true` so embedders that omit the option get the same
   * strict behaviour as the production gateway (`EUNO_REQUIRE_KID`
   * also defaults to `true`).  Set to `false` only during a rolling
   * deploy while tokens that pre-date the JWKS migration are still
   * in circulation.
   */
  protected requireKid: boolean;

  /**
   * Optional cosignature + transparency-log proofs verifier (multi-issuer
   * trust hardening). When configured with strict-mode requirements, runs
   * after the primary signature succeeds and rejects tokens that do not
   * carry the required proofs. Defaults to a no-op verifier so existing
   * deployments are unchanged. See {@link ProofsVerifier}.
   */
  protected proofsVerifier?: ProofsVerifier;

  /** Default revocation TTL used when the caller does not supply an expiry. */
  private static readonly DEFAULT_REVOCATION_TTL_SECONDS = 86400; // 24 hours

  // Two supported constructor forms. The overloads make it a *compile-time*
  // error to mix them (e.g. supplying both an options bag and a legacy
  // positional `revocationStore`), so misconfigurations like passing
  // `revocationStore` as the 3rd arg while also passing `{ algorithms }`
  // as the 2nd are caught by tsc rather than silently dropped.
  constructor(publicKey: string, options?: JWTTokenVerifierOptions);
  constructor(
    publicKey: string,
    algorithms: SigningAlgorithm[],
    revocationStore?: RevocationStore,
    partnerResolver?: PartnerIssuerResolver,
    localIssuers?: string[],
    jwksKeySource?: JwksKeySource,
    requireKid?: boolean,
    proofsVerifier?: ProofsVerifier,
  );
  constructor(
    publicKey: string,
    optionsOrAlgorithms?: JWTTokenVerifierOptions | SigningAlgorithm[],
    revocationStore?: RevocationStore,
    partnerResolver?: PartnerIssuerResolver,
    localIssuers?: string[],
    jwksKeySource?: JwksKeySource,
    requireKid?: boolean,
    proofsVerifier?: ProofsVerifier,
  ) {
    // Accept either an options bag (preferred) or the historical
    // positional signature for back-compat with existing call sites.
    // The options-bag form is the only one documented going forward
    // because it makes per-field defaults — particularly the
    // security-sensitive `requireKid` — explicit at the call site.
    const usingOptionsBag =
      optionsOrAlgorithms !== undefined && !Array.isArray(optionsOrAlgorithms);
    if (usingOptionsBag) {
      // Defence in depth against callers that bypass the typed overloads
      // (e.g. `.ts` files with `@ts-ignore`, or transpiled JS): if any
      // legacy positional argument is supplied alongside the options
      // bag, fail fast rather than silently drop the extra args.
      if (
        revocationStore !== undefined ||
        partnerResolver !== undefined ||
        localIssuers !== undefined ||
        jwksKeySource !== undefined ||
        requireKid !== undefined ||
        proofsVerifier !== undefined
      ) {
        throw new Error(
          'JWTTokenVerifier: mixing the options-bag and legacy positional ' +
            'constructor forms is not supported. Pass all configuration ' +
            'inside the JWTTokenVerifierOptions object (the second argument).',
        );
      }
    }
    const opts: JWTTokenVerifierOptions = Array.isArray(optionsOrAlgorithms)
      ? {
          algorithms: optionsOrAlgorithms,
          revocationStore,
          partnerResolver,
          localIssuers,
          jwksKeySource,
          requireKid,
          proofsVerifier,
        }
      : optionsOrAlgorithms ?? {};

    this.publicKey = publicKey;
    // Default to RS256 for backward compatibility, but allow multiple algorithms.
    // Normalize so that an explicitly passed empty array also falls back to RS256.
    this.algorithms = opts.algorithms?.length ? opts.algorithms : ['RS256'];
    this.revocationStore = opts.revocationStore ?? new InMemoryRevocationStore();
    this.partnerResolver = opts.partnerResolver;
    if (opts.localIssuers && opts.localIssuers.length > 0) {
      this.localIssuers = new Set(opts.localIssuers);
    }
    this.jwksKeySource = opts.jwksKeySource;
    // Default to `true` so this matches the production gateway and the
    // `EUNO_REQUIRE_KID` env-var default.  Tests / embedders that
    // intentionally exercise the legacy "no kid" path must opt out
    // explicitly with `{ requireKid: false }`.
    this.requireKid = opts.requireKid ?? true;
    this.proofsVerifier = opts.proofsVerifier;
    if (opts.epochStore) {
      this.epochStore = opts.epochStore;
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
      const kid = typeof header.kid === 'string' ? header.kid : undefined;

      // Enforce kid requirement (R-6).  Default is now `true` (matches
      // the `EUNO_REQUIRE_KID` env-var default); pass `requireKid: false`
      // to the constructor to allow legacy tokens without a `kid` while
      // a rolling deploy completes.
      if (this.requireKid && !kid) {
        throw new CapabilityError(
          ErrorCode.INVALID_TOKEN,
          'Token missing required kid (key ID) in protected header',
          401,
        );
      }

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
        const { key: partnerKey, alg: partnerAlg } = await this.partnerResolver!.getKey(iss!, kid);
        try {
          const result = await jose.jwtVerify(token, partnerKey, {
            algorithms: [partnerAlg],
            issuer: iss!,
          });
          payload = result.payload as unknown as CapabilityTokenPayload;
        } catch (err) {
          // Only drop the cached key on actual signature verification
          // failures.  Other jose errors (expiration, claim validation,
          // malformed JWT) do not indicate stale resolver data — invalidating
          // for them would (a) cause repeated DID fetches for benign cases
          // like expired tokens and (b) become a DoS amplifier where any
          // attacker holding a single partner DID could force unbounded
          // network resolution by replaying invalid tokens.
          if (err instanceof jose.errors.JWSSignatureVerificationFailed) {
            this.partnerResolver!.invalidate(iss!, kid);
          }
          throw err;
        }
      } else if (this.jwksKeySource && kid) {
        // JWKS path (R-6): select the key by kid from the JWKS source.
        // This path is used when a JwksClient (or any JwksKeySource impl)
        // was injected at construction time AND the token carries a kid.
        if (!this.algorithms.includes(algorithm as SigningAlgorithm)) {
          throw new CapabilityError(
            ErrorCode.INVALID_TOKEN,
            `Token uses disallowed algorithm: ${algorithm}`,
            401,
          );
        }

        // Retrieve the matching JWK.  JwksClient.getKeyByKid handles the
        // forced-refresh-on-miss logic (one network round-trip to pick up a
        // freshly-rotated key) and is fail-closed when the kid is not found
        // even after the refresh.  For generic JwksKeySource implementations,
        // do a single lookup and throw on miss.
        // Note: tokens from non-local issuers (e.g. untrusted partner DIDs)
        // will naturally fail here because their kid won't be in the local
        // JWKS cache — no explicit issuer check is needed.
        let jwkEntry: import('@euno/common').JwkKey;
        if (this.jwksKeySource instanceof JwksClient) {
          jwkEntry = await (this.jwksKeySource as JwksClient).getKeyByKid(kid);
        } else {
          const jwks = await this.jwksKeySource.getJwks();
          const found = pickJwkByKid(jwks, kid);
          if (!found) {
            throw new CapabilityError(
              ErrorCode.INVALID_TOKEN,
              `No public key found for kid="${kid}"`,
              401,
            );
          }
          jwkEntry = found;
        }

        const keyObject = await jose.importJWK(jwkEntry as jose.JWK, algorithm);
        const result = await jose.jwtVerify(token, keyObject as jose.KeyLike, {
          algorithms: this.algorithms,
        });
        payload = result.payload as unknown as CapabilityTokenPayload;
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

      return this.performPostVerificationChecks(payload);
    } catch (error) {
      if (error instanceof CapabilityError) {
        throw error;
      }

      // Map jose JWTExpired to EXPIRED_TOKEN so callers get the correct error code
      if (error instanceof Error && (error as NodeJS.ErrnoException).code === 'ERR_JWT_EXPIRED') {
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
   * Attach (or replace) the per-issuer epoch store.  When set, every
   * successfully-verified token is additionally checked against its issuer's
   * epoch: tokens with `iat` strictly before the recorded epoch are rejected
   * as if they were individually revoked.  Closes the previous store on a
   * best-effort basis.
   */
  async setEpochStore(store: RevocationEpochStore): Promise<void> {
    const previous = this.epochStore;
    this.epochStore = store;
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

  /**
   * Shared post-signature checks: revocation + epoch + schema version.
   * Protected so {@link JwksTokenVerifier} can call it without duplicating
   * the logic.
   */
  protected async performPostVerificationChecks(
    payload: CapabilityTokenPayload,
  ): Promise<CapabilityTokenPayload> {
    const tokenId = payload.jti as string;
    if (tokenId && (await this.isRevoked(tokenId))) {
      throw new CapabilityError(ErrorCode.TOKEN_REVOKED, 'Token has been revoked', 401);
    }

    // Per-issuer epoch check: reject tokens whose iat predates the cut-off.
    // getEpoch() is fail-closed by default — a Redis outage returns
    // nowSeconds()+1 as the epoch, blocking all tokens from that issuer until
    // the store is reachable again (prevents an outage from bypassing an
    // active epoch).  Operators may set REVOCATION_EPOCH_FAIL_OPEN=true to
    // swap to fail-open behaviour.
    if (this.epochStore && payload.iss) {
      const epoch = await this.epochStore.getEpoch(payload.iss);
      if (epoch !== null) {
        // CapabilityTokenPayload requires iat to be a number, but at runtime
        // a crafted/malformed token could omit it entirely. Tokens without a
        // valid numeric iat cannot be placed on the timeline relative to the
        // epoch, so we treat them as pre-epoch and reject them rather than
        // silently bypassing the cut-off.
        if (typeof payload.iat !== 'number') {
          throw new CapabilityError(
            ErrorCode.INVALID_TOKEN,
            'Token is missing a required numeric iat claim and cannot be validated against the issuer epoch',
            401,
          );
        }
        if (payload.iat < epoch) {
          throw new CapabilityError(
            ErrorCode.TOKEN_REVOKED,
            'Token predates the revocation epoch for its issuer',
            401,
          );
        }
      }
    }

    const schemaVersion = payload.schemaVersion;
    if (!schemaVersion) {
      throw new CapabilityError(
        ErrorCode.INVALID_TOKEN,
        'Token missing required schemaVersion field',
        401,
      );
    }
    if (!SUPPORTED_SCHEMA_VERSIONS.has(schemaVersion)) {
      throw new CapabilityError(
        ErrorCode.INVALID_TOKEN,
        `Unsupported token schema version: ${schemaVersion}. Supported versions: ${Array.from(SUPPORTED_SCHEMA_VERSIONS).join(', ')}`,
        401,
      );
    }
    // Multi-issuer trust hardening: verify cosignatures and SCTs (when
    // configured). No-op when neither is required and the token carries
    // no proofs. Strict-mode rejections raise CapabilityError.
    if (this.proofsVerifier) {
      await this.proofsVerifier.verify(payload);
    }
    return payload;
  }
}

// ── JwksTokenVerifier ──────────────────────────────────────────────────────

/**
 * Constructor options for {@link JwksTokenVerifier}.
 *
 * Extends {@link JWTTokenVerifierOptions} so the JWKS verifier accepts
 * the same fields as its base class (no field is JWKS-only). The
 * `jwksKeySource` field is intentionally omitted because the JWKS
 * verifier takes the key source as its first positional argument.
 */
export type JwksTokenVerifierOptions = Omit<JWTTokenVerifierOptions, 'jwksKeySource'>;

/**
 * A JWKS-backed token verifier.
 *
 * Extends {@link JWTTokenVerifier} to inherit the revocation infrastructure
 * (`isRevoked`, `revokeToken`, `setRevocationStore`) and enforcement-engine
 * compatibility, while substituting a JWK Set key source for the single SPKI.
 *
 * Differences from the base class:
 * - No SPKI key — all key material is fetched from the issuer's
 *   `/.well-known/jwks.json` via the injected {@link JwksKeySource}.
 * - `requireKid` defaults to `true`.  When `true`, a missing `kid` header
 *   is immediately rejected.  When `false`, all JWKS keys are tried in turn
 *   to support tokens minted before the JWKS migration.
 *
 * @example
 * ```ts
 * const verifier = new JwksTokenVerifier(jwksClient, {
 *   algorithms: ['RS256'],
 *   revocationStore: redisRevocationStore,
 * });
 * const payload = await verifier.verify(token);
 * await verifier.revokeToken(payload.jti!);
 * ```
 */
export class JwksTokenVerifier extends JWTTokenVerifier {
  private readonly jwksSource: JwksKeySource;

  constructor(jwksKeySource: JwksKeySource, options: JwksTokenVerifierOptions = {}) {
    super('', {
      ...options,
      jwksKeySource,
      // `requireKid` defaults to `true` for both the base class and the
      // JWKS verifier; pass it through unchanged so explicit `false`
      // (rolling deploys) still works.
    });
    this.jwksSource = jwksKeySource;
  }

  /**
   * Verify a capability token using JWKS key selection.
   *
   * Overrides the parent to:
   * 1. When `requireKid=true` (default): reject tokens without a `kid`
   *    header immediately.  When `requireKid=false`: try every key in the
   *    JWKS in turn, which supports tokens minted before the JWKS migration.
   * 2. Apply the same `localIssuers` allow-list that the SPKI path enforces
   *    when a partner resolver is configured (prevents an arbitrary `iss`
   *    claim from bypassing the local-issuer allow-list).
   * 3. Route all local-issuer tokens through the JWKS source; cross-org
   *    partner-DID tokens are still handled via the inherited partner resolver.
   *
   * Revocation and schema-version checks are performed by the inherited
   * {@link JWTTokenVerifier.performPostVerificationChecks} helper.
   */
  override async verify(token: string): Promise<CapabilityTokenPayload> {
    try {
      const header = jose.decodeProtectedHeader(token);
      const algorithm = (header.alg ?? this.algorithms[0] ?? 'RS256') as string;
      const kid = typeof header.kid === 'string' ? header.kid : undefined;

      // Enforce kid requirement: reject immediately when requireKid=true.
      // When requireKid=false, proceed to the "try all keys" path below.
      if (!kid && this.requireKid) {
        throw new CapabilityError(
          ErrorCode.INVALID_TOKEN,
          'Token is missing required kid in protected header',
          401,
        );
      }

      // Resolve the issuer for partner-resolver routing.
      let iss: string | undefined;
      try {
        const decoded = jose.decodeJwt(token);
        iss = typeof decoded.iss === 'string' ? decoded.iss : undefined;
      } catch {
        // The signature step below will produce a clearer error.
      }

      const useResolver = this.partnerResolver && iss && this.partnerResolver.trusts(iss);

      if (useResolver) {
        // Cross-org path: partner DID document supplies the public key.
        // kid is required when routing via the partner resolver.
        if (!kid) {
          throw new CapabilityError(
            ErrorCode.INVALID_TOKEN,
            'Token is missing required kid in protected header for partner-issuer verification',
            401,
          );
        }
        const { key: partnerKey, alg: partnerAlg } = await this.partnerResolver!.getKey(iss!, kid);
        let partnerPayload: CapabilityTokenPayload;
        try {
          const result = await jose.jwtVerify(token, partnerKey, {
            algorithms: [partnerAlg],
            issuer: iss!,
          });
          partnerPayload = result.payload as unknown as CapabilityTokenPayload;
        } catch (err) {
          if (err instanceof jose.errors.JWSSignatureVerificationFailed) {
            this.partnerResolver!.invalidate(iss!, kid);
          }
          throw err;
        }
        return this.performPostVerificationChecks(partnerPayload);
      } else {
        // Local-issuer path: look up the key by kid from the JWKS source.
        if (!this.algorithms.includes(algorithm as SigningAlgorithm)) {
          throw new CapabilityError(
            ErrorCode.INVALID_TOKEN,
            `Token uses disallowed algorithm: ${algorithm}`,
            401,
          );
        }

        // Apply the same localIssuers allow-list that the SPKI path enforces
        // when a partner resolver is configured, to prevent tokens carrying
        // an arbitrary iss from bypassing the local-issuer constraint.
        if (this.partnerResolver && this.localIssuers && iss && !this.localIssuers.has(iss)) {
          throw new CapabilityError(
            ErrorCode.INVALID_TOKEN,
            `Token issuer ${iss} is neither a trusted partner DID nor a known local issuer`,
            401,
          );
        }

        if (kid) {
          // Fast path: token carries a kid — look up the specific key.
          // JwksClient supports forced-refresh-on-miss; generic JwksKeySource
          // implementations do a single lookup.
          let jwkEntry: import('@euno/common').JwkKey;
          if (this.jwksSource instanceof JwksClient) {
            jwkEntry = await this.jwksSource.getKeyByKid(kid);
          } else {
            const jwks = await this.jwksSource.getJwks();
            const found = pickJwkByKid(jwks, kid);
            if (!found) {
              throw new CapabilityError(
                ErrorCode.INVALID_TOKEN,
                `No public key found for kid="${kid}"`,
                401,
              );
            }
            jwkEntry = found;
          }

          const keyObject = await jose.importJWK(jwkEntry as jose.JWK, algorithm);
          const result = await jose.jwtVerify(token, keyObject as jose.KeyLike, {
            algorithms: this.algorithms,
          });
          return this.performPostVerificationChecks(
            result.payload as unknown as CapabilityTokenPayload,
          );
        }

        // Slow path (requireKid=false): no kid — try all keys in the JWKS.
        // This supports a rolling-deploy transition while pre-JWKS tokens
        // are still in circulation.  Less efficient; enforce requireKid=true
        // once all issuers include kid.
        const jwks = await this.jwksSource.getJwks();
        let lastError: unknown;

        for (const jwkEntry of jwks.keys) {
          try {
            const keyObject = await jose.importJWK(jwkEntry as jose.JWK, algorithm);
            const result = await jose.jwtVerify(token, keyObject as jose.KeyLike, {
              algorithms: this.algorithms,
            });
            return this.performPostVerificationChecks(
              result.payload as unknown as CapabilityTokenPayload,
            );
          } catch (err) {
            lastError = err;
          }
        }

        throw new CapabilityError(
          ErrorCode.INVALID_TOKEN,
          `Token signature did not match any key in the JWKS: ${lastError instanceof Error ? lastError.message : 'Unknown error'}`,
          401,
        );
      }
    } catch (error) {
      if (error instanceof CapabilityError) {
        throw error;
      }
      if (error instanceof Error && (error as NodeJS.ErrnoException).code === 'ERR_JWT_EXPIRED') {
        throw new CapabilityError(ErrorCode.EXPIRED_TOKEN, 'Token has expired', 401);
      }
      throw new CapabilityError(
        ErrorCode.INVALID_TOKEN,
        `Token verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        401,
      );
    }
  }
}
