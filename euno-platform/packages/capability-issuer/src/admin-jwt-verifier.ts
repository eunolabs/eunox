/**
 * AdminJwtVerifier — lightweight JWKS-backed verifier for operator JWTs
 * presented to the issuer admin API.
 *
 * Design mirrors the equivalent class in `@euno/api-key-minter`
 * (`admin-jwt-verifier.ts`). Both use the same authentication contract:
 *
 * 1. PRIMARY — `Authorization: Bearer <jwt>` verified against the JWKS
 *    endpoint configured by `ISSUER_ADMIN_JWKS_URI`.  Operator identity
 *    is extracted from the JWT `sub` claim and surfaced via
 *    `AdminPrincipal.operatorId` for use in audit logs.
 *
 * 2. FALLBACK — `X-Admin-Key: <secret>` shared-secret.  Accepted while
 *    teams migrate to operator JWT tokens; emits a deprecation warning on
 *    every use.
 *
 * Environment variables consumed by `createAdminJwtVerifierFromEnv`:
 *
 *   ISSUER_ADMIN_JWKS_URI        — URL of the IdP JWKS endpoint (activates JWT auth)
 *   ISSUER_ADMIN_JWT_AUDIENCE    — expected `aud` value (required when JWKS_URI is set)
 *   ISSUER_ADMIN_JWT_ISSUER      — expected `iss` value (optional)
 *   ISSUER_ADMIN_JWT_REQUIRED_SCOPE — required scope value (optional)
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
   * are rejected.  Omit to skip issuer validation.
   */
  issuer?: string;
  /**
   * If set, the token's `scp` or `scope` claim must include this value.
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
 * Factory that reads `ISSUER_ADMIN_JWKS_URI` and `ISSUER_ADMIN_JWT_AUDIENCE`
 * from the environment and returns an `AdminJwtVerifier` instance when both
 * are present, or `undefined` when JWT auth is not configured.
 */
export function createAdminJwtVerifierFromEnv(
  env: Record<string, string | undefined> = process.env,
  opts?: { requiredScope?: string },
): AdminJwtVerifier | undefined {
  const jwksUri = env['ISSUER_ADMIN_JWKS_URI'];
  const audience = env['ISSUER_ADMIN_JWT_AUDIENCE'];

  if (!jwksUri || !audience) {
    return undefined;
  }

  return new AdminJwtVerifier({
    jwksUri,
    audience,
    issuer: env['ISSUER_ADMIN_JWT_ISSUER'],
    requiredScope: opts?.requiredScope,
  });
}
