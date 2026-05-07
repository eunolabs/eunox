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
} from '@euno/common';
import { InMemoryRevocationStore, RevocationStore, RevocationEpochStore } from './revocation-store';
import { PartnerIssuerResolver } from './partner-issuer-resolver';
import { ProofsVerifier } from './proofs-verifier';
import {
  TrustAnchor,
  TrustAnchorContext,
  SpkiTrustAnchor,
  buildTrustChain,
} from './trust-anchor';

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
  /**
   * The raw SPKI PEM kept so `updatePublicKey` can update it and flush the
   * `SpkiTrustAnchor` cache.  Not used directly for verification — that is
   * delegated to the trust-anchor chain.
   */
  private publicKey: string;

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

  /**
   * Ordered trust-anchor chain.  The verifier delegates key selection to
   * the first anchor whose `owns()` returns `true`.  Built from constructor
   * options; subclasses may supply their own chain.
   *
   * Protected so subclasses (e.g. `JwksTokenVerifier`) can inspect or extend
   * the chain without re-implementing the full `verify()` loop.
   */
  protected trustChain: TrustAnchor[];

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
    // Default to `true` so this matches the production gateway and the
    // `EUNO_REQUIRE_KID` env-var default.  Tests / embedders that
    // intentionally exercise the legacy "no kid" path must opt out
    // explicitly with `{ requireKid: false }`.
    this.requireKid = opts.requireKid ?? true;
    this.proofsVerifier = opts.proofsVerifier;
    if (opts.epochStore) {
      this.epochStore = opts.epochStore;
    }

    // Resolve the localIssuers set once so it can be passed to the anchor.
    const localIssuersSet =
      opts.localIssuers && opts.localIssuers.length > 0
        ? new Set(opts.localIssuers)
        : undefined;

    // Build the trust-anchor chain from the supplied options.
    this.trustChain = buildTrustChain({
      publicKey: this.publicKey,
      algorithms: this.algorithms,
      localIssuers: localIssuersSet,
      jwksKeySource: opts.jwksKeySource,
      partnerResolver: opts.partnerResolver,
    });
  }

  /**
   * Verify and decode a capability token.
   *
   * The verification pipeline is:
   * 1. Decode the JWT protected header (alg, kid).
   * 2. Enforce the `requireKid` constraint.
   * 3. Decode the `iss` claim from the payload (unsigned at this stage).
   * 4. Walk the {@link trustChain}: find the first anchor whose `owns()`
   *    returns `true` and delegate key selection to it.
   * 5. Call `jose.jwtVerify` with the resolved key + algorithm constraints.
   *    On `JWSSignatureVerificationFailed`, call `anchor.invalidate()` so
   *    the anchor can flush any cached key material before the next attempt.
   * 6. Run `performPostVerificationChecks` (revocation, epoch, schema version,
   *    proofs).
   */
  async verify(token: string): Promise<CapabilityTokenPayload> {
    try {
      // Step 1: decode header.
      const header = jose.decodeProtectedHeader(token);
      const alg = (header.alg ?? this.algorithms[0] ?? 'RS256') as string;
      const kid = typeof header.kid === 'string' ? header.kid : undefined;

      // Step 2: enforce kid requirement (R-6).
      if (this.requireKid && !kid) {
        throw new CapabilityError(
          ErrorCode.INVALID_TOKEN,
          'Token missing required kid (key ID) in protected header',
          401,
        );
      }

      // Step 3: decode iss (unsigned; anchor.resolveKey performs the full
      // check after the key is fetched).
      let iss: string | undefined;
      try {
        const decoded = jose.decodeJwt(token);
        iss = typeof decoded.iss === 'string' ? decoded.iss : undefined;
      } catch {
        // The signature step below will produce a clearer error.
      }

      const ctx: TrustAnchorContext = { iss, kid, alg };

      // Step 4: find the responsible anchor.
      const anchor = this.trustChain.find((a) => a.owns(ctx));
      if (!anchor) {
        throw new CapabilityError(
          ErrorCode.INVALID_TOKEN,
          iss
            ? `No trust anchor found for issuer "${iss}" with algorithm "${alg}"`
            : `No trust anchor accepts this token (algorithm "${alg}")`,
          401,
        );
      }

      // Step 5: resolve key and verify signature.
      const resolution = await anchor.resolveKey(ctx);
      const jwtVerifyOpts: jose.JWTVerifyOptions = {
        algorithms: resolution.algorithms,
        ...(resolution.issuer ? { issuer: resolution.issuer } : {}),
      };

      let payload: CapabilityTokenPayload | undefined;

      if (resolution.keys) {
        // Rolling-deploy try-all path: no kid — try each key in order.
        let lastError: unknown;
        for (const key of resolution.keys) {
          try {
            const result = await jose.jwtVerify(token, key, jwtVerifyOpts);
            payload = result.payload as unknown as CapabilityTokenPayload;
            break;
          } catch (err) {
            lastError = err;
          }
        }
        if (payload === undefined) {
          // Mirror the single-key path: flush the anchor's key cache when
          // every key in the set rejected the signature — the JWKS may have
          // been rotated between the cache population and this request.
          if (lastError instanceof jose.errors.JWSSignatureVerificationFailed) {
            anchor.invalidate?.(ctx);
          }
          throw new CapabilityError(
            ErrorCode.INVALID_TOKEN,
            `Token signature did not match any key in the JWKS: ${lastError instanceof Error ? lastError.message : 'Unknown error'}`,
            401,
          );
        }
      } else {
        // Normal path: single key.  TypeScript narrows `resolution` to the
        // `key`-bearing variant of the discriminated union in this `else`
        // branch (because `resolution.keys` is falsy), so `resolution.key`
        // is typed as non-optional and requires no non-null assertion.
        try {
          const result = await jose.jwtVerify(token, resolution.key, jwtVerifyOpts);
          payload = result.payload as unknown as CapabilityTokenPayload;
        } catch (err) {
          // Invalidate cached key material on signature failure so the next
          // request re-fetches (handles an out-of-band key rotation).
          if (err instanceof jose.errors.JWSSignatureVerificationFailed) {
            anchor.invalidate?.(ctx);
          }
          throw err;
        }
      }

      // Step 6: revocation, epoch, schema, proofs.
      return this.performPostVerificationChecks(payload);
    } catch (error) {
      if (error instanceof CapabilityError) {
        throw error;
      }

      // Map jose JWTExpired to EXPIRED_TOKEN so callers get the correct error code
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
   * Update the public key (for key rotation).
   * Flushes the {@link SpkiTrustAnchor} key cache so the next verification
   * imports the new key.
   */
  updatePublicKey(publicKey: string): void {
    this.publicKey = publicKey;
    // Update the SpkiTrustAnchor in the chain (if present).
    for (const anchor of this.trustChain) {
      if (anchor instanceof SpkiTrustAnchor) {
        anchor.updatePublicKey(publicKey);
        break;
      }
    }
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
 * - `verify()` is inherited from the base class; the {@link JwksTrustAnchor}
 *   in the trust chain handles key selection for both the kid-present and
 *   the try-all paths.
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
  constructor(jwksKeySource: JwksKeySource, options: JwksTokenVerifierOptions = {}) {
    super('', {
      ...options,
      jwksKeySource,
      // `requireKid` defaults to `true` for both the base class and the
      // JWKS verifier; pass it through unchanged so explicit `false`
      // (rolling deploys) still works.
    });
  }

  /**
   * Not supported on a JWKS-backed verifier — there is no single SPKI key
   * to rotate.  Call sites that manage key rotation should instead replace
   * the underlying {@link JwksKeySource} or allow the JWKS cache to expire.
   */
  override updatePublicKey(_publicKey: string): never {
    throw new Error(
      'JwksTokenVerifier.updatePublicKey() is not supported: key material ' +
        'is managed by the JWKS key source, not a static SPKI PEM.',
    );
  }
}
