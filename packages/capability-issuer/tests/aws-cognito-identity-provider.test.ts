/**
 * Unit tests for AWSCognitoIdentityProvider.
 *
 * Mocks `jose.createRemoteJWKSet` so tests can verify against a locally
 * generated key pair without making real network calls to Cognito.
 */

import * as jose from 'jose';
import { AWSCognitoIdentityProvider } from '../src/aws-cognito-identity-provider';

// Spy on createRemoteJWKSet so we can return a local verifier
const createRemoteJWKSetSpy = jest.spyOn(jose, 'createRemoteJWKSet');

describe('AWSCognitoIdentityProvider', () => {
  const REGION = 'us-east-1';
  const USER_POOL_ID = 'us-east-1_AbCdEfGhI';
  const CLIENT_ID = 'test-client-id';
  const EXPECTED_ISSUER = `https://cognito-idp.${REGION}.amazonaws.com/${USER_POOL_ID}`;

  let privateKey: jose.KeyLike;
  let publicKey: jose.KeyLike;

  beforeAll(async () => {
    const keys = await jose.generateKeyPair('RS256');
    privateKey = keys.privateKey;
    publicKey = keys.publicKey;
  });

  beforeEach(() => {
    createRemoteJWKSetSpy.mockReset();
    // Return a local key resolver that always returns our test public key
    createRemoteJWKSetSpy.mockReturnValue((async () => publicKey) as any);
  });

  afterAll(() => {
    createRemoteJWKSetSpy.mockRestore();
  });

  function makeProvider(overrides: Partial<{ tokenUse: 'id' | 'access'; issuer: string; jwksUri: string }> = {}) {
    return new AWSCognitoIdentityProvider({
      type: 'aws-cognito',
      name: 'test',
      awsCognito: {
        region: REGION,
        userPoolId: USER_POOL_ID,
        clientId: CLIENT_ID,
        ...overrides,
      },
    });
  }

  async function signCognitoToken(payload: Record<string, unknown>) {
    return new jose.SignJWT(payload)
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuer(EXPECTED_ISSUER)
      .setAudience(CLIENT_ID)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);
  }

  it('extracts userId, email, and roles from cognito:groups for an ID token', async () => {
    const provider = makeProvider();
    const token = await signCognitoToken({
      sub: 'user-123',
      email: 'alice@example.com',
      'cognito:groups': ['SalesManager', 'Viewer'],
      token_use: 'id',
    });

    const ctx = await provider.validateToken(token);

    expect(ctx.userId).toBe('user-123');
    expect(ctx.email).toBe('alice@example.com');
    expect(ctx.roles).toEqual(['SalesManager', 'Viewer']);
  });

  it('rejects tokens with mismatched token_use claim', async () => {
    const provider = makeProvider({ tokenUse: 'id' });
    const token = await signCognitoToken({
      sub: 'user-123',
      'cognito:groups': ['Viewer'],
      token_use: 'access', // mismatch
    });

    await expect(provider.validateToken(token)).rejects.toMatchObject({
      statusCode: 401,
    });
  });

  it('validates access tokens by client_id claim instead of audience', async () => {
    const provider = makeProvider({ tokenUse: 'access' });
    // Access tokens do NOT carry `aud` — sign without it
    const token = await new jose.SignJWT({
      sub: 'user-456',
      'cognito:groups': ['Administrator'],
      token_use: 'access',
      client_id: CLIENT_ID,
      username: 'alice',
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuer(EXPECTED_ISSUER)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);

    const ctx = await provider.validateToken(token);
    expect(ctx.userId).toBe('user-456');
    expect(ctx.roles).toEqual(['Administrator']);
  });

  it('rejects access tokens whose client_id does not match', async () => {
    const provider = makeProvider({ tokenUse: 'access' });
    const token = await new jose.SignJWT({
      sub: 'user-456',
      token_use: 'access',
      client_id: 'wrong-client',
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuer(EXPECTED_ISSUER)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);

    await expect(provider.validateToken(token)).rejects.toMatchObject({
      statusCode: 401,
    });
  });

  it('rejects tokens with the wrong issuer', async () => {
    const provider = makeProvider();
    const token = await new jose.SignJWT({ sub: 'user-1', 'cognito:groups': [] })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuer('https://evil.example.com')
      .setAudience(CLIENT_ID)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);

    await expect(provider.validateToken(token)).rejects.toMatchObject({
      statusCode: 401,
    });
  });

  it('falls back to the `groups` claim for IAM Identity Center tokens', async () => {
    const ICENTER_ISSUER = 'https://identitycenter.amazonaws.com/ssoins-test';
    const provider = makeProvider({ issuer: ICENTER_ISSUER, jwksUri: `${ICENTER_ISSUER}/.well-known/jwks.json` });
    const token = await new jose.SignJWT({
      sub: 'sso-user-1',
      email: 'bob@corp.example',
      groups: ['DataScientist'],
      identitystore_id: 'd-1234567890',
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuer(ICENTER_ISSUER)
      .setAudience(CLIENT_ID)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);

    const ctx = await provider.validateToken(token);
    expect(ctx.userId).toBe('sso-user-1');
    expect(ctx.roles).toEqual(['DataScientist']);
    expect(ctx.tenantId).toBe('d-1234567890');
  });

  it('caches the JWKS function across calls (does not re-create on every validate)', async () => {
    const provider = makeProvider();
    const token = await signCognitoToken({ sub: 'user-1', 'cognito:groups': [] });

    await provider.validateToken(token);
    await provider.validateToken(token);
    await provider.validateToken(token);

    // createRemoteJWKSet must be called exactly once for the lifetime of the provider
    expect(createRemoteJWKSetSpy).toHaveBeenCalledTimes(1);
  });

  it('exposes its name as `aws-cognito` for registry lookup', () => {
    expect(makeProvider().name).toBe('aws-cognito');
  });

  it('throws a 501 from getUserRoles directing callers to validateToken', async () => {
    const provider = makeProvider();
    await expect(provider.getUserRoles('any')).rejects.toMatchObject({
      statusCode: 501,
    });
  });
});
