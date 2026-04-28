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
  '../../../infra/aws/api-gateway/lambda-authorizer.js'
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
  it('extracts a Bearer token from a TOKEN-authorizer event', () => {
    expect(extractToken({ authorizationToken: 'Bearer abc.def.ghi' })).toBe('abc.def.ghi');
  });

  it('extracts a Bearer token from a REQUEST-authorizer event headers', () => {
    expect(extractToken({ headers: { Authorization: 'Bearer xyz' } })).toBe('xyz');
    expect(extractToken({ headers: { authorization: 'bearer XYZ' } })).toBe('XYZ');
  });

  it('extracts a Bearer token from multiValueHeaders', () => {
    expect(
      extractToken({ multiValueHeaders: { Authorization: ['Bearer multi'] } })
    ).toBe('multi');
  });

  it('rejects missing tokens with Unauthorized', () => {
    expect(() => extractToken({})).toThrow('Unauthorized');
    expect(() => extractToken({ headers: {} })).toThrow('Unauthorized');
  });

  it('rejects non-Bearer schemes with Unauthorized', () => {
    expect(() => extractToken({ authorizationToken: 'Basic abc' })).toThrow('Unauthorized');
    expect(() => extractToken({ authorizationToken: 'just-a-token' })).toThrow('Unauthorized');
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
