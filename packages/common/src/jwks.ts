/**
 * JWKS (JSON Web Key Set) types, interface, and helpers — R-6.
 *
 * These are shared by:
 *  - `packages/capability-issuer` — exposes `/.well-known/jwks.json`
 *  - `packages/tool-gateway` — fetches + caches the JWKS for verification
 *
 * The `JwksKeySource` interface provides a unified abstraction that
 * covers both the local-issuer JWKS client and the partner-DID
 * resolver path, as described in `docs/IMPROVEMENTS_AND_REFACTORING.md`
 * § R-6.
 */

/**
 * A single JSON Web Key, per RFC 7517 / RFC 7518.
 * Index signature (`[key: string]: unknown`) preserves forward-compat
 * for algorithm-specific parameters without a type update.
 */
export interface JwkKey {
  /** Key type: `RSA`, `EC`, `OKP`. */
  kty: string;
  /** Key ID — must match the `kid` placed in every signed JWT header. */
  kid: string;
  /** Intended key use: always `sig` for capability tokens. */
  use?: string;
  /** Algorithm (e.g. `RS256`, `ES256`, `EdDSA`). */
  alg?: string;
  // RSA public-key fields
  n?: string;
  e?: string;
  // EC / OKP public-key fields
  crv?: string;
  x?: string;
  y?: string;
  [key: string]: unknown;
}

/**
 * A JSON Web Key Set, per RFC 7517 §5.
 */
export interface JwkSet {
  keys: JwkKey[];
}

/**
 * Abstraction over any key source that can return a JWK Set.
 *
 * Both the local-issuer JWKS client and the partner-DID resolver
 * should be expressible as implementations of this interface so the
 * gateway's verification code shares a single code path.
 */
export interface JwksKeySource {
  /**
   * Return the current JWK Set.  Implementations are expected to
   * cache the result and refresh on a configurable TTL.
   */
  getJwks(): Promise<JwkSet>;
}

/**
 * Find the JWK whose `kid` matches the given string.
 *
 * Returns `undefined` when no matching key exists — callers are
 * responsible for deciding whether to re-fetch or reject.
 */
export function pickJwkByKid(jwks: JwkSet, kid: string): JwkKey | undefined {
  return jwks.keys.find((k) => k.kid === kid);
}
