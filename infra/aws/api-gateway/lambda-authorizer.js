/**
 * Euno Capability Authorizer — AWS API Gateway custom Lambda authorizer.
 *
 * This file is the AWS-side parity of the Azure APIM `validate-jwt` policy
 * referenced by Sprint 1 of the execution plan and by the multi-cloud
 * parity matrix in `docs/SPRINT_1_2_SUMMARY.md`. It performs the same
 * edge-level capability-token verification that the in-cluster Tool
 * Gateway performs in `packages/tool-gateway/src/verifier.ts`:
 *
 *   1. Signature verification against the issuer's published JWKS.
 *   2. Algorithm allow-list (defence in depth against `alg` substitution).
 *   3. Issuer (`iss`) check.
 *   4. Audience (`aud`) check.
 *   5. Expiration (`exp`) check (handled by `jose.jwtVerify`).
 *   6. Required-claim presence (`sub`, `jti`, `schemaVersion`).
 *   7. Schema-version allow-list (fail-closed on unknown versions).
 *
 * Scope-based payload validation (per-tool action / resource constraints)
 * deliberately stays inside the Tool Gateway pod so the policy lives in
 * exactly one place — the authorizer's job is to filter out clearly bad
 * requests at the edge, not to duplicate the constraint engine.
 *
 * On success the authorizer returns an IAM allow policy for the requested
 * method ARN and exposes the decoded claims via `context.*` (stringified
 * per AWS contract) so the upstream Tool Gateway and CloudWatch access
 * logs can correlate the request with the issued capability.
 *
 * On failure it throws `'Unauthorized'`, which API Gateway maps to a
 * 401 response. (Returning a deny policy would surface as 403, which we
 * reserve for "valid token but insufficient scope" — that decision is
 * made by the Tool Gateway pod after the authorizer has succeeded.)
 *
 * Configuration (environment variables):
 *
 *   ISSUER_JWKS_URL      Required. URL of the issuer's JWKS endpoint
 *                        (e.g. https://issuer.euno.example/.well-known/jwks.json).
 *   EXPECTED_AUDIENCE    Required. Expected `aud` claim value
 *                        (typically `tool-gateway`).
 *   EXPECTED_ISSUER      Required. Expected `iss` claim value.
 *   ALLOWED_ALGORITHMS   Optional. Comma-separated JWS `alg` allow-list.
 *                        Defaults to `RS256`. Must match the algorithms
 *                        the Capability Issuer is configured to mint.
 *   SUPPORTED_SCHEMA_VERSIONS
 *                        Optional. Comma-separated list of accepted
 *                        `schemaVersion` values. Defaults to `1.0`,
 *                        matching `SUPPORTED_SCHEMA_VERSIONS` in
 *                        `packages/common/src/types.ts`.
 *   JWKS_CACHE_MAX_AGE_MS
 *                        Optional. JWKS cache lifetime. Defaults to
 *                        600000 (10 minutes). Lower values shorten the
 *                        window during which a rotated-out key remains
 *                        accepted; higher values reduce JWKS HTTP load.
 *
 * Packaging: see `infra/aws/api-gateway/README.md` — bundle with `jose@5`
 * in `node_modules` and deploy as a Node.js 20.x Lambda.
 */

'use strict';

const { createRemoteJWKSet, jwtVerify } = require('jose');

const ISSUER_JWKS_URL = process.env.ISSUER_JWKS_URL;
const EXPECTED_AUDIENCE = process.env.EXPECTED_AUDIENCE;
const EXPECTED_ISSUER = process.env.EXPECTED_ISSUER;
const parsedAllowedAlgorithms = (process.env.ALLOWED_ALGORITHMS || 'RS256')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
// Fall back to RS256 when the env var was set to an empty/whitespace
// value: passing an empty allow-list to `jwtVerify` would silently
// reject every token, which is a confusing misconfiguration mode.
const ALLOWED_ALGORITHMS =
  parsedAllowedAlgorithms.length > 0 ? parsedAllowedAlgorithms : ['RS256'];
const SUPPORTED_SCHEMA_VERSIONS = new Set(
  (process.env.SUPPORTED_SCHEMA_VERSIONS || '1.0')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
);
const RAW_JWKS_CACHE_MAX_AGE_MS = process.env.JWKS_CACHE_MAX_AGE_MS;
const JWKS_CACHE_MAX_AGE_MS =
  RAW_JWKS_CACHE_MAX_AGE_MS === undefined || RAW_JWKS_CACHE_MAX_AGE_MS === ''
    ? 600000
    : Number(RAW_JWKS_CACHE_MAX_AGE_MS);
if (!Number.isFinite(JWKS_CACHE_MAX_AGE_MS) || JWKS_CACHE_MAX_AGE_MS < 0) {
  // Surface bad numeric config at module-load time rather than passing
  // NaN / negative values into `createRemoteJWKSet`, where they would
  // either disable caching entirely or produce confusing runtime errors.
  throw new Error(
    `[euno-authorizer] Invalid JWKS_CACHE_MAX_AGE_MS=${String(RAW_JWKS_CACHE_MAX_AGE_MS)}; must be a finite, non-negative number of milliseconds.`
  );
}

if (!ISSUER_JWKS_URL || !EXPECTED_AUDIENCE || !EXPECTED_ISSUER) {
  // Surface misconfiguration at module-load time so a misconfigured
  // Lambda fails CloudWatch-visibly with a clear error rather than
  // silently 401-ing every request.
  const missing = [
    !ISSUER_JWKS_URL && 'ISSUER_JWKS_URL',
    !EXPECTED_AUDIENCE && 'EXPECTED_AUDIENCE',
    !EXPECTED_ISSUER && 'EXPECTED_ISSUER',
  ]
    .filter(Boolean)
    .join(', ');
  throw new Error(
    `[euno-authorizer] Missing required env vars: ${missing}. ` +
      'Configure them on the Lambda before invocation.'
  );
}

// Module-level JWKS so warm Lambda invocations reuse the cached keys.
const JWKS = createRemoteJWKSet(new URL(ISSUER_JWKS_URL), {
  cacheMaxAge: JWKS_CACHE_MAX_AGE_MS,
  // Cooldown prevents a flood of JWKS fetches when an unknown `kid`
  // arrives (e.g. during key rotation): jose will refetch at most
  // once every 30s by default, which is fine for our use case.
});

/**
 * Strict JWT shape: three base64url-encoded segments separated by dots.
 * Used as a defence-in-depth pre-check before handing the token to
 * `jose.jwtVerify`, so obviously-malformed input (control characters,
 * arbitrary garbage prefixed with "Bearer ") is rejected before the
 * crypto layer is touched.
 */
const JWT_SHAPE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

/**
 * Pull the bearer token out of the API Gateway authorizer event.
 * Supports both REQUEST authorizers (Authorization header) and TOKEN
 * authorizers (event.authorizationToken).
 *
 * @param {object} event API Gateway authorizer event
 * @returns {string} The raw JWT (no `Bearer ` prefix)
 * @throws {Error} 'Unauthorized' if no token is present
 */
function extractToken(event) {
  let raw;
  if (event && typeof event.authorizationToken === 'string') {
    raw = event.authorizationToken;
  } else if (event && (event.headers || event.multiValueHeaders)) {
    // Header names are case-insensitive per RFC 7230; API Gateway
    // preserves case, so accept the common variants explicitly.
    const headers = event.headers || {};
    const mv = event.multiValueHeaders || {};
    const mvAuth = mv.Authorization || mv.authorization;
    raw =
      headers.Authorization ||
      headers.authorization ||
      (Array.isArray(mvAuth) && mvAuth.length ? mvAuth[0] : undefined);
  }

  if (!raw || typeof raw !== 'string') {
    throw new Error('Unauthorized');
  }

  const match = /^Bearer\s+(\S+)$/i.exec(raw.trim());
  if (!match) {
    throw new Error('Unauthorized');
  }
  const token = match[1].trim();
  // Defence-in-depth: validate the token shape before calling jose. This
  // rejects obviously malformed input (control chars, wrong segment
  // count, base64-incompatible chars) without involving the crypto path.
  if (!JWT_SHAPE.test(token)) {
    throw new Error('Unauthorized');
  }
  return token;
}

/**
 * Build an IAM policy document scoped to a single method ARN.
 *
 * We intentionally do NOT widen the resource to `arn:aws:execute-api:.../*\/*`
 * because authorizer responses are cached: a wildcard would let one
 * caller's authorization decision apply to a different method on a
 * subsequent request. `authorizerResultTtlInSeconds` is set to 0 in the
 * OpenAPI document, so per-method scoping costs us nothing.
 *
 * @param {string} principalId Subject identifier surfaced to API Gateway.
 * @param {'Allow'|'Deny'} effect
 * @param {string} resource The exact methodArn from the authorizer event.
 * @param {object} context Extra fields exposed to the integration as `$context.authorizer.*`.
 *                         All values must be string/number/boolean per AWS contract.
 * @returns {object}
 */
function buildPolicy(principalId, effect, resource, context) {
  return {
    principalId,
    policyDocument: {
      Version: '2012-10-17',
      Statement: [
        {
          Action: 'execute-api:Invoke',
          Effect: effect,
          Resource: resource,
        },
      ],
    },
    context: context || {},
  };
}

/**
 * Lambda handler. Exported as `handler` per AWS convention; the OpenAPI
 * authorizerUri references `/2015-03-31/functions/${ARN}/invocations`,
 * which calls the function's default export — wiring is handled by the
 * `handler: index.handler` setting on the deployed Lambda (see README).
 */
exports.handler = async (event) => {
  const token = extractToken(event);

  let payload;
  try {
    const result = await jwtVerify(token, JWKS, {
      algorithms: ALLOWED_ALGORITHMS,
      issuer: EXPECTED_ISSUER,
      audience: EXPECTED_AUDIENCE,
      // jose enforces `exp` automatically; `iat` and `nbf` are also
      // enforced when present.
    });
    payload = result.payload;
  } catch (err) {
    // Log the structured failure for CloudWatch (the access-log
    // destination defined in the API Gateway stage), but always surface
    // the same opaque "Unauthorized" to the client so we don't leak
    // verification-failure detail to attackers.
    // eslint-disable-next-line no-console
    console.warn(
      '[euno-authorizer] token verification failed:',
      err && err.code ? err.code : err && err.message ? err.message : 'unknown'
    );
    throw new Error('Unauthorized');
  }

  // Required-claim checks beyond what `jwtVerify` enforces.
  if (typeof payload.sub !== 'string' || !payload.sub) {
    // eslint-disable-next-line no-console
    console.warn('[euno-authorizer] token missing required sub claim');
    throw new Error('Unauthorized');
  }
  if (typeof payload.jti !== 'string' || !payload.jti) {
    // eslint-disable-next-line no-console
    console.warn('[euno-authorizer] token missing required jti claim');
    throw new Error('Unauthorized');
  }
  if (
    typeof payload.schemaVersion !== 'string' ||
    !SUPPORTED_SCHEMA_VERSIONS.has(payload.schemaVersion)
  ) {
    // eslint-disable-next-line no-console
    console.warn(
      '[euno-authorizer] unsupported schemaVersion:',
      payload.schemaVersion
    );
    throw new Error('Unauthorized');
  }

  // Surface select claims to the upstream integration. AWS requires every
  // authorizer-context value to be a string/number/boolean — arrays and
  // nested objects must be JSON-stringified.
  const context = {
    sub: payload.sub,
    iss: typeof payload.iss === 'string' ? payload.iss : '',
    jti: payload.jti,
    schemaVersion: payload.schemaVersion,
    exp: typeof payload.exp === 'number' ? payload.exp : 0,
  };
  if (Array.isArray(payload.capabilities)) {
    // The Tool Gateway re-derives capabilities from the token itself, but
    // exposing the count here makes CloudWatch log analysis easier.
    context.capabilityCount = payload.capabilities.length;
  }

  return buildPolicy(payload.sub, 'Allow', event.methodArn, context);
};

// Exported for unit testing only; not part of the public Lambda contract.
exports._internals = {
  extractToken,
  buildPolicy,
};
