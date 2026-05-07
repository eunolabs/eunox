/**
 * Unit tests for the AWS Lambda authorizer's pure helpers
 * (`extractToken` and `buildPolicy`). Verifying the full `handler`
 * requires either a live JWKS endpoint or substantial mocking of
 * `jose.createRemoteJWKSet`; both are out of scope for this package's
 * test suite. The integration path is exercised in `infra/aws/api-gateway/`
 * deployment runbooks.
 *
 * We import via `require` because the authorizer is pure CommonJS to
 * match the AWS Lambda Node.js 20.x runtime convention.
 */

// eslint-disable-next-line @typescript-eslint/no-var-requires
const path = require('path');

// Resolve from the repo root so the test runs regardless of cwd.
const authorizerPath = path.resolve(
  __dirname,
  '../../../../infra/aws/api-gateway/lambda-authorizer.js'
);

// Set required env vars BEFORE requiring the module — its module-level
// init reads them once.
process.env.ISSUER_JWKS_URL = 'https://issuer.test/.well-known/jwks.json';
process.env.EXPECTED_AUDIENCE = 'tool-gateway';
process.env.EXPECTED_ISSUER = 'https://issuer.test';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const authorizer = require(authorizerPath);
const { extractToken, buildPolicy } = authorizer._internals;

describe('AWS Lambda authorizer — extractToken', () => {
  // A syntactically-valid JWT shape (3 base64url segments). Signature
  // validity is not exercised here — that's the handler's job.
  const SAMPLE_JWT = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0.sig';

  it('extracts a Bearer token from a TOKEN-authorizer event', () => {
    expect(extractToken({ authorizationToken: `Bearer ${SAMPLE_JWT}` })).toBe(SAMPLE_JWT);
  });

  it('extracts a Bearer token from a REQUEST-authorizer event headers', () => {
    expect(extractToken({ headers: { Authorization: `Bearer ${SAMPLE_JWT}` } })).toBe(SAMPLE_JWT);
    expect(extractToken({ headers: { authorization: `bearer ${SAMPLE_JWT}` } })).toBe(SAMPLE_JWT);
  });

  it('extracts a Bearer token from multiValueHeaders', () => {
    expect(
      extractToken({ multiValueHeaders: { Authorization: [`Bearer ${SAMPLE_JWT}`] } })
    ).toBe(SAMPLE_JWT);
  });

  it('rejects missing tokens with Unauthorized', () => {
    expect(() => extractToken({})).toThrow('Unauthorized');
    expect(() => extractToken({ headers: {} })).toThrow('Unauthorized');
  });

  it('rejects non-Bearer schemes with Unauthorized', () => {
    expect(() => extractToken({ authorizationToken: 'Basic abc' })).toThrow('Unauthorized');
    expect(() => extractToken({ authorizationToken: SAMPLE_JWT })).toThrow('Unauthorized');
  });

  it('rejects malformed JWT shapes with Unauthorized (defence in depth)', () => {
    // Wrong segment count
    expect(() => extractToken({ authorizationToken: 'Bearer onlyone' })).toThrow('Unauthorized');
    expect(() => extractToken({ authorizationToken: 'Bearer one.two' })).toThrow('Unauthorized');
    // Disallowed characters (spaces / control chars in the token body)
    expect(() => extractToken({ authorizationToken: 'Bearer abc.def.gh i' })).toThrow(
      'Unauthorized'
    );
    expect(() =>
      extractToken({ authorizationToken: `Bearer abc.def.${String.fromCharCode(0x07)}` })
    ).toThrow('Unauthorized');
  });
});

describe('AWS Lambda authorizer — buildPolicy', () => {
  it('produces a method-scoped Allow policy', () => {
    const policy = buildPolicy(
      'agent-123',
      'Allow',
      'arn:aws:execute-api:us-east-1:111:abc/prod/POST/api/v1/tools/invoke',
      { sub: 'agent-123' }
    );
    expect(policy).toEqual({
      principalId: 'agent-123',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: 'arn:aws:execute-api:us-east-1:111:abc/prod/POST/api/v1/tools/invoke',
          },
        ],
      },
      context: { sub: 'agent-123' },
    });
  });

  it('does not widen the resource (per-method scoping is intentional)', () => {
    const policy = buildPolicy('p', 'Allow', 'arn:aws:execute-api:r:a:id/stage/GET/x', {});
    expect(policy.policyDocument.Statement[0].Resource).not.toContain('*');
  });
});
