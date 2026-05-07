/**
 * TrustAnchor chain-of-responsibility for JWTTokenVerifier.
 * ---------------------------------------------------------------------------
 * Each trust anchor encapsulates one key source and its acceptance criteria.
 * The verifier walks an ordered list of anchors; the first anchor whose
 * `owns()` returns `true` is responsible for supplying the key material.
 *
 * Adding a new key source (hardware-attested keys, federation tokens,
 * workload-identity attestations, …) is a matter of implementing this
 * interface and inserting the anchor at the appropriate priority in the
 * chain — no changes to the `JWTTokenVerifier` core are required.
 *
 * Anchor order matters: higher-priority anchors must be placed before
 * lower-priority ones.  In particular, `PartnerDidTrustAnchor` must
 * precede `SpkiTrustAnchor` / `JwksTrustAnchor` so that a locally-signed
 * token can never impersonate a partner DID (structural fix for the
 * local-key-signs-a-partner-DID footgun — replaces the defensive `if`
 * in the old `JWTTokenVerifier.verify()`).
 */

import * as jose from 'jose';
import {
  CapabilityError,
  ErrorCode,
  JwksKeySource,
  SigningAlgorithm,
  pickJwkByKid,
} from '@euno/common';
import { PartnerIssuerResolver } from './partner-issuer-resolver';

/** Minimal logger interface accepted by {@link buildTrustChain}. */
type WarnLogger = { warn: (msg: string, meta?: Record<string, unknown>) => void };

// ── Context & Resolution ─────────────────────────────────────────────────────

/**
 * Token identity decoded from the protected header and payload *before* any
 * signature check.  Passed to {@link TrustAnchor.owns} and
 * {@link TrustAnchor.resolveKey}.
 */
export interface TrustAnchorContext {
  /** `iss` claim from the JWT payload, or `undefined` when absent. */
  iss: string | undefined;
  /** `kid` from the JWT protected header, or `undefined` when absent. */
  kid: string | undefined;
  /** Signing algorithm from the protected header (falls back to verifier default). */
  alg: string;
}

/**
 * Key material and constraints returned by {@link TrustAnchor.resolveKey}.
 *
 * Exactly one of `key` or `keys` is populated — the type is a discriminated
 * union so TypeScript enforces this invariant at compile time:
 * - **`key`** — normal path: the verifier calls `jose.jwtVerify` once.
 * - **`keys`** — rolling-deploy try-all path (no `kid`, `requireKid=false`):
 *   the verifier tries each key in order, succeeding on the first match.
 *
 * Custom anchor implementations MUST populate exactly one of the two; an
 * anchor that returns neither will be caught by TypeScript's type checker
 * rather than producing a cryptic `TypeError` at runtime.
 */
export type TrustAnchorResolution =
  | {
      /** Single key for the normal, kid-present verification path. */
      key: jose.KeyLike | Uint8Array;
      keys?: never;
      /** Algorithm allow-list passed as `algorithms` to `jose.jwtVerify`. */
      algorithms: string[];
      /**
       * When present, `jose.jwtVerify` enforces `issuer === this value`.
       * Used by `PartnerDidTrustAnchor` to bind verification to the token's
       * declared `iss` claim.
       */
      issuer?: string;
    }
  | {
      /**
       * Multiple keys for the try-all path (JWKS without `kid`).
       * The verifier iterates these in order, returning after the first success.
       */
      keys: Array<jose.KeyLike | Uint8Array>;
      key?: never;
      /** Algorithm allow-list passed as `algorithms` to `jose.jwtVerify`. */
      algorithms: string[];
      /** When present, `jose.jwtVerify` enforces `issuer === this value`. */
      issuer?: string;
    };

// ── Interface ────────────────────────────────────────────────────────────────

/**
 * A trust anchor decides whether it is responsible for a given token and,
 * if so, resolves the key material needed to verify the signature.
 *
 * The verifier walks an ordered chain of anchors and delegates to the first
 * one that claims ownership.
 *
 * @example
 * ```ts
 * // Custom hardware-attested key source:
 * class HsmTrustAnchor implements TrustAnchor {
 *   owns(ctx) { return ctx.kid?.startsWith('hsm:') ?? false; }
 *   async resolveKey(ctx) { const k = await hsm.getKey(ctx.kid!); return { key: k, algorithms: ['ES256'] }; }
 * }
 * ```
 */
export interface TrustAnchor {
  /**
   * Synchronously decide whether this anchor is responsible for the token.
   *
   * Only the pre-decoded `iss`, `kid`, and `alg` are available here — no
   * network I/O should occur.  Return `false` to pass the decision to the
   * next anchor in the chain.
   */
  owns(ctx: TrustAnchorContext): boolean;

  /**
   * Resolve the key material for this token.
   * Called only when `owns()` returned `true`.
   *
   * Implementations may perform async I/O (JWKS fetch, DID resolution,
   * KMS call).  Throw {@link CapabilityError} to hard-reject the token.
   */
  resolveKey(ctx: TrustAnchorContext): Promise<TrustAnchorResolution>;

  /**
   * Optional hook: called when `jose.jwtVerify` throws
   * `JWSSignatureVerificationFailed` against the key returned by
   * `resolveKey`.  Implementations should evict any cached key material so
   * the next request picks up a freshly-rotated key.
   */
  invalidate?(ctx: TrustAnchorContext): void;
}

// ── SpkiTrustAnchor ──────────────────────────────────────────────────────────

/**
 * Trust anchor backed by a single SPKI public key.
 *
 * Owns tokens whose `iss` is a member of the configured `localIssuers` set
 * (or all tokens when no issuer restriction is configured — preserving the
 * pre-JWKS single-key behaviour).  The algorithm allow-list is enforced
 * inside `owns()` so a mis-matched algorithm is rejected before any crypto
 * operation is attempted.
 *
 * Key objects are cached per algorithm to avoid re-importing on every
 * request; the cache is flushed by {@link updatePublicKey} on rotation.
 *
 * @example
 * ```ts
 * new SpkiTrustAnchor({
 *   publicKey: spkiPem,
 *   algorithms: ['RS256'],
 *   localIssuers: new Set(['did:web:issuer.example.com']),
 * });
 * ```
 */
export class SpkiTrustAnchor implements TrustAnchor {
  private spkiPem: string;
  private readonly allowedAlgorithms: SigningAlgorithm[];
  private readonly localIssuers?: Set<string>;
  /** Key objects cached by algorithm to avoid re-importing on every request. */
  private readonly cachedKeys = new Map<string, jose.KeyLike | Uint8Array>();

  constructor(opts: {
    publicKey: string;
    algorithms: SigningAlgorithm[];
    localIssuers?: Set<string>;
  }) {
    this.spkiPem = opts.publicKey;
    this.allowedAlgorithms = opts.algorithms;
    this.localIssuers = opts.localIssuers;
  }

  owns(ctx: TrustAnchorContext): boolean {
    // Reject algorithms outside the allow-list immediately.
    if (!this.allowedAlgorithms.includes(ctx.alg as SigningAlgorithm)) {
      return false;
    }
    // When a localIssuers restriction is configured, only own tokens from
    // known local issuers.  Tokens with an unknown `iss` are passed through
    // so legacy tokens without an `iss` claim continue to work.
    if (this.localIssuers !== undefined && ctx.iss !== undefined) {
      return this.localIssuers.has(ctx.iss);
    }
    return true;
  }

  async resolveKey(ctx: TrustAnchorContext): Promise<TrustAnchorResolution> {
    if (!this.cachedKeys.has(ctx.alg)) {
      const keyObject = await jose.importSPKI(this.spkiPem, ctx.alg);
      this.cachedKeys.set(ctx.alg, keyObject);
    }
    return {
      key: this.cachedKeys.get(ctx.alg)!,
      algorithms: [...this.allowedAlgorithms],
    };
  }

  /**
   * Replace the SPKI PEM and flush the key cache.  Called by
   * {@link JWTTokenVerifier.updatePublicKey} on key rotation.
   */
  updatePublicKey(newPem: string): void {
    this.spkiPem = newPem;
    this.cachedKeys.clear();
  }
}

// ── JwksTrustAnchor ──────────────────────────────────────────────────────────

/**
 * Trust anchor backed by a JWKS endpoint.
 *
 * **Normal path** (`kid` present): retrieves the matching JWK from the key
 * source and returns it in `TrustAnchorResolution.key`.
 *
 * **Rolling-deploy path** (`kid` absent, `requireKid=false`): imports all
 * keys in the JWKS and returns them in `TrustAnchorResolution.keys` so the
 * verifier can try each one in turn.  This path supports a graceful migration
 * while pre-JWKS tokens are still in circulation; disable it (set
 * `requireKid: true`) once all issuers include a `kid` header.
 *
 * @example
 * ```ts
 * new JwksTrustAnchor({
 *   keySource: new JwksClient({ jwksUrl: '…/.well-known/jwks.json' }),
 *   algorithms: ['RS256'],
 *   localIssuers: new Set(['did:web:issuer.example.com']),
 * });
 * ```
 */
export class JwksTrustAnchor implements TrustAnchor {
  private readonly keySource: JwksKeySource;
  private readonly allowedAlgorithms: SigningAlgorithm[];
  private readonly localIssuers?: Set<string>;

  constructor(opts: {
    keySource: JwksKeySource;
    algorithms: SigningAlgorithm[];
    localIssuers?: Set<string>;
  }) {
    this.keySource = opts.keySource;
    this.allowedAlgorithms = opts.algorithms;
    this.localIssuers = opts.localIssuers;
  }

  owns(ctx: TrustAnchorContext): boolean {
    // Enforce algorithm allow-list for the local JWKS path.
    if (!this.allowedAlgorithms.includes(ctx.alg as SigningAlgorithm)) {
      return false;
    }
    // When a localIssuers restriction is configured, only own tokens from
    // known local issuers.
    if (this.localIssuers !== undefined && ctx.iss !== undefined) {
      return this.localIssuers.has(ctx.iss);
    }
    return true;
  }

  async resolveKey(ctx: TrustAnchorContext): Promise<TrustAnchorResolution> {
    if (ctx.kid) {
      // Fast path: resolve the single key matching the kid.
      // Use getKeyByKid() when the key source supports it (e.g. JwksClient
      // applies forced-refresh-on-miss semantics); fall back to a plain
      // getJwks() + pickJwkByKid() for sources that don't implement it.
      let jwkEntry: import('@euno/common').JwkKey;
      if (this.keySource.getKeyByKid) {
        jwkEntry = await this.keySource.getKeyByKid(ctx.kid);
      } else {
        const jwks = await this.keySource.getJwks();
        const found = pickJwkByKid(jwks, ctx.kid);
        if (!found) {
          throw new CapabilityError(
            ErrorCode.INVALID_TOKEN,
            `No public key found for kid="${ctx.kid}"`,
            401,
          );
        }
        jwkEntry = found;
      }
      const keyObject = await jose.importJWK(jwkEntry as jose.JWK, ctx.alg);
      return {
        key: keyObject as jose.KeyLike,
        algorithms: [...this.allowedAlgorithms],
      };
    }

    // Rolling-deploy slow path: no kid — try all keys in the JWKS.
    // Keys that cannot be imported for the requested algorithm are skipped
    // silently (e.g. EC keys when the token declares RS256).
    const jwks = await this.keySource.getJwks();
    const keys: Array<jose.KeyLike | Uint8Array> = [];
    for (const entry of jwks.keys) {
      try {
        const k = await jose.importJWK(entry as jose.JWK, ctx.alg);
        keys.push(k as jose.KeyLike);
      } catch {
        // Key type mismatch or unsupported parameters — skip.
      }
    }
    if (keys.length === 0) {
      throw new CapabilityError(
        ErrorCode.INVALID_TOKEN,
        'No usable keys found in the JWKS for the token algorithm',
        401,
      );
    }
    return {
      keys,
      algorithms: [...this.allowedAlgorithms],
    };
  }
}

// ── PartnerDidTrustAnchor ────────────────────────────────────────────────────

/**
 * Trust anchor backed by partner DID documents.
 *
 * Owns tokens whose `iss` is a DID trusted by the injected
 * {@link PartnerIssuerResolver} (legacy env-var allow-list or live registry).
 * The algorithm allow-list is intentionally **not** enforced in `owns()` —
 * partner DIDs may use algorithms (e.g. EdDSA, ES256) that differ from the
 * local signing algorithm.  The algorithm is taken from the DID document.
 *
 * A `kid` is required for partner-DID tokens; `resolveKey` rejects tokens
 * that omit it before any network resolution is attempted.
 *
 * Because this anchor is inserted **before** `SpkiTrustAnchor` /
 * `JwksTrustAnchor` in the chain, a locally-signed token cannot
 * accidentally match a partner DID issuer — the ownership check is
 * structural, not a defensive `if`.
 *
 * @example
 * ```ts
 * new PartnerDidTrustAnchor({ resolver: partnerIssuerResolver });
 * ```
 */
export class PartnerDidTrustAnchor implements TrustAnchor {
  private readonly resolver: PartnerIssuerResolver;

  constructor(opts: { resolver: PartnerIssuerResolver }) {
    this.resolver = opts.resolver;
  }

  owns(ctx: TrustAnchorContext): boolean {
    if (!ctx.iss) return false;
    // mightTrust() returns true for env-var-trusted DIDs immediately, and
    // also for any non-empty DID when a registry is wired — the definitive
    // async registry check is deferred to resolveKey() → getKey() →
    // trustsAsync().  This ensures registry-backed partner DIDs are not
    // silently dropped at the synchronous owns() gate.
    return this.resolver.mightTrust(ctx.iss);
  }

  async resolveKey(ctx: TrustAnchorContext): Promise<TrustAnchorResolution> {
    if (!ctx.iss) {
      throw new CapabilityError(
        ErrorCode.INVALID_TOKEN,
        'Partner-DID anchor requires an iss claim',
        401,
      );
    }
    if (!ctx.kid) {
      throw new CapabilityError(
        ErrorCode.INVALID_TOKEN,
        'Token is missing required kid in protected header for partner-issuer verification',
        401,
      );
    }
    const { key, alg } = await this.resolver.getKey(ctx.iss, ctx.kid);
    return {
      key,
      algorithms: [alg],
      issuer: ctx.iss,
    };
  }

  invalidate(ctx: TrustAnchorContext): void {
    if (ctx.iss) {
      this.resolver.invalidate(ctx.iss, ctx.kid);
    }
  }
}

// ── Factory helper ───────────────────────────────────────────────────────────

/**
 * Build the default trust-anchor chain for {@link JWTTokenVerifier}.
 *
 * Chain order:
 * 1. {@link PartnerDidTrustAnchor} — partner DID tokens first, so the local
 *    key can never be used to verify a token whose `iss` is a partner DID.
 * 2. {@link JwksTrustAnchor} or {@link SpkiTrustAnchor} — local-issuer tokens,
 *    keyed by whichever source was injected.
 *
 * The chain is intentionally simple — operators who need custom ordering
 * (e.g. a hardware-attested anchor that takes priority over JWKS) should
 * construct the array directly.
 */
export function buildTrustChain(opts: {
  publicKey: string;
  algorithms: SigningAlgorithm[];
  localIssuers?: Set<string>;
  jwksKeySource?: JwksKeySource;
  partnerResolver?: PartnerIssuerResolver;
  /** Optional logger for operator warnings emitted during chain construction. */
  logger?: WarnLogger;
}): TrustAnchor[] {
  const chain: TrustAnchor[] = [];

  // 1. Partner DID anchor — must be first.
  if (opts.partnerResolver) {
    chain.push(new PartnerDidTrustAnchor({ resolver: opts.partnerResolver }));
  }

  // 2. Local-key anchor: JWKS-backed or single SPKI.
  // Note: when jwksKeySource is provided, publicKey is unused — all key
  // material comes from the JWKS endpoint.  A warning is emitted when both
  // are configured so operators are alerted during startup (see below).
  if (opts.jwksKeySource) {
    if (opts.publicKey) {
      opts.logger?.warn(
        'buildTrustChain: both jwksKeySource and publicKey were provided; ' +
          'publicKey is ignored — the JWKS source is the only local-key anchor.',
      );
    }
    chain.push(
      new JwksTrustAnchor({
        keySource: opts.jwksKeySource,
        algorithms: opts.algorithms,
        localIssuers: opts.localIssuers,
      }),
    );
  } else {
    chain.push(
      new SpkiTrustAnchor({
        publicKey: opts.publicKey,
        algorithms: opts.algorithms,
        localIssuers: opts.localIssuers,
      }),
    );
  }

  return chain;
}
