/**
 * AdminJwtVerifier — lightweight JWKS-backed verifier for operator JWTs
 * presented to the minter admin API.
 *
 * Design goals
 * ─────────────
 * 1. Primary authentication path: `Authorization: Bearer <jwt>`.
 *    The gateway already uses `jose` for capability-token verification; this
 *    module reuses the same library to verify operator identity tokens issued
 *    by an IdP (e.g. Azure AD, Okta, Auth0).
 *
 * 2. The shared admin key (`X-Admin-Key`) remains operational as an explicit
 *    temporary fallback.  When a verifier instance is provided and the caller
 *    presents a valid Bearer token, the shared key is NOT consulted.
 *
 * 3. Operator identity is extracted from the `sub` claim of the verified
 *    JWT and surfaced via `AdminPrincipal.operatorId` for use in audit logs.
 *
 * 4. Optional scope enforcement: if `requiredScope` is supplied, the token's
 *    `scp` or `scope` claim must include that value.
 *
 * Environment variables (consumed by `createAdminJwtVerifierFromEnv`):
 *
 *   MINTER_ADMIN_JWKS_URI      — URL of the IdP JWKS endpoint (required to
 *                                 activate JWT auth)
 *   MINTER_ADMIN_JWT_AUDIENCE  — expected `aud` value in the token (required
 *                                 when MINTER_ADMIN_JWKS_URI is set)
 *   MINTER_ADMIN_JWT_ISSUER    — expected `iss` value (optional; omit to skip
 *                                 issuer validation)
 *   MINTER_ADMIN_JWT_REQUIRED_SCOPE — required scope value (optional)
 */

import * as jose from 'jose';

/** Resolved identity from a successfully verified operator JWT. */
export interface AdminPrincipal {
  /** JWT `sub` claim — the operator's stable user identifier. */
  operatorId: string;
  /** Raw extracted scopes (from `scp` or `scope` claim), if present. */
  scopes: string[];
}

export interface AdminJwtVerifierOptions {
  /**
   * URL of the IdP JWKS endpoint.  The verifier fetches and caches the key
   * set using `jose.createRemoteJWKSet` (which handles key rotation).
   */
  jwksUri: string;
  /**
   * Expected `aud` value.  Tokens that do not include this audience string
   * are rejected.
   */
  audience: string;
  /**
   * Expected `iss` value.  When supplied, tokens whose issuer does not match
   * are rejected.  Omit to skip issuer validation (useful during migration
   * from multiple issuers).
   */
  issuer?: string;
  /**
   * If set, the token's `scp` or `scope` claim must include this value.
   * Use `'admin:keys'` for key-management endpoints and `'admin:policies'`
   * for policy-management endpoints.
   */
  requiredScope?: string;
}

export class AdminJwtVerifier {
  private readonly keySet: ReturnType<typeof jose.createRemoteJWKSet>;
  private readonly audience: string;
  private readonly issuer: string | undefined;
  private readonly requiredScope: string | undefined;

  constructor(opts: AdminJwtVerifierOptions) {
    this.keySet = jose.createRemoteJWKSet(new URL(opts.jwksUri));
    this.audience = opts.audience;
    this.issuer = opts.issuer;
    this.requiredScope = opts.requiredScope;
  }

  /**
   * Verify a raw JWT string.  Throws on any verification failure (expired,
   * wrong audience, missing scope, invalid signature, …).  Returns the
   * resolved `AdminPrincipal` on success.
   */
  async verify(token: string): Promise<AdminPrincipal> {
    const verifyOptions: jose.JWTVerifyOptions = {
      audience: this.audience,
    };
    if (this.issuer) {
      verifyOptions.issuer = this.issuer;
    }

    const { payload } = await jose.jwtVerify(token, this.keySet, verifyOptions);

    const operatorId = typeof payload.sub === 'string' && payload.sub.length > 0
      ? payload.sub
      : undefined;
    if (!operatorId) {
      throw new Error('JWT is missing the `sub` claim required to identify the operator');
    }

    // Extract scopes from `scp` (Azure AD style) or `scope` (standard).
    const rawScp = payload['scp'] ?? payload['scope'];
    const scopes = typeof rawScp === 'string'
      ? rawScp.split(/\s+/).filter(Boolean)
      : [];

    if (this.requiredScope && !scopes.includes(this.requiredScope)) {
      throw new Error(
        `Operator JWT is missing required scope "${this.requiredScope}". ` +
        `Present scopes: [${scopes.join(', ')}]`,
      );
    }

    return { operatorId, scopes };
  }
}

/**
 * Factory that reads `MINTER_ADMIN_JWKS_URI` and `MINTER_ADMIN_JWT_AUDIENCE`
 * from the environment and returns an `AdminJwtVerifier` instance when both are
 * present, or `undefined` when JWT auth is not configured.
 *
 * The returned verifier is designed to be injected into
 * `AdminKeysRouterOptions.jwtVerifier` and
 * `AdminPoliciesRouterOptions.jwtVerifier`.
 */
export function createAdminJwtVerifierFromEnv(
  env: Record<string, string | undefined> = process.env,
  opts?: { requiredScope?: string },
): AdminJwtVerifier | undefined {
  const jwksUri = env['MINTER_ADMIN_JWKS_URI'];
  const audience = env['MINTER_ADMIN_JWT_AUDIENCE'];

  if (!jwksUri || !audience) {
    return undefined;
  }

  return new AdminJwtVerifier({
    jwksUri,
    audience,
    issuer: env['MINTER_ADMIN_JWT_ISSUER'],
    requiredScope: opts?.requiredScope,
  });
}
