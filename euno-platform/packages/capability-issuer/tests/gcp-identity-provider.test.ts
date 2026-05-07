/**
 * Unit tests for GCPIdentityProvider.
 *
 * Mocks `jose.createRemoteJWKSet` so tests can verify against a locally
 * generated key pair without making real network calls to Google's OAuth
 * certs endpoint.
 */

import * as jose from 'jose';
import { GCPIdentityProvider } from '../src/gcp-identity-provider';

const createRemoteJWKSetSpy = jest.spyOn(jose, 'createRemoteJWKSet');

describe('GCPIdentityProvider', () => {
  const AUDIENCE = 'oauth-client.apps.googleusercontent.com';

  let privateKey: jose.KeyLike;
  let publicKey: jose.KeyLike;

  beforeAll(async () => {
    const keys = await jose.generateKeyPair('RS256');
    privateKey = keys.privateKey;
    publicKey = keys.publicKey;
  });

  beforeEach(() => {
    createRemoteJWKSetSpy.mockReset();
    createRemoteJWKSetSpy.mockReturnValue((async () => publicKey) as any);
  });

  afterAll(() => {
    createRemoteJWKSetSpy.mockRestore();
  });

  function makeProvider(opts: Partial<{ issuer: string; jwksUri: string; projectId: string; rolesClaim: string }> = {}) {
    return new GCPIdentityProvider({
      type: 'gcp-identity',
      name: 'test',
      gcpIdentity: {
        audience: AUDIENCE,
        ...opts,
      },
    });
  }

  async function signGoogleToken(
    payload: Record<string, unknown>,
    issuer = 'https://accounts.google.com',
    audience = AUDIENCE,
  ) {
    return new jose.SignJWT(payload)
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuer(issuer)
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);
  }

  it('extracts userId, email, hd (tenantId), and roles from a Google ID token', async () => {
    const provider = makeProvider();
    const token = await signGoogleToken({
      sub: 'google-user-1',
      email: 'alice@corp.example',
      hd: 'corp.example',
      groups: ['SalesManager'],
    });

    const ctx = await provider.validateToken(token);

    expect(ctx.userId).toBe('google-user-1');
    expect(ctx.email).toBe('alice@corp.example');
    expect(ctx.tenantId).toBe('corp.example');
    expect(ctx.roles).toEqual(['SalesManager']);
  });

  it('uses the configured `rolesClaim` to read roles from a custom claim', async () => {
    const provider = makeProvider({ rolesClaim: 'roles' });
    const token = await signGoogleToken({
      sub: 'google-user-2',
      roles: ['Administrator', 'DataScientist'],
    });

    const ctx = await provider.validateToken(token);
    expect(ctx.roles).toEqual(['Administrator', 'DataScientist']);
  });

  it('returns an empty roles list when the claim is missing or not an array', async () => {
    const provider = makeProvider();
    const token = await signGoogleToken({
      sub: 'google-user-3',
      groups: 'not-an-array', // wrong shape
    });

    const ctx = await provider.validateToken(token);
    expect(ctx.roles).toEqual([]);
  });

  it('rejects tokens with the wrong audience', async () => {
    const provider = makeProvider();
    const token = await signGoogleToken(
      { sub: 'u' },
      'https://accounts.google.com',
      'wrong-audience',
    );

    await expect(provider.validateToken(token)).rejects.toMatchObject({ statusCode: 401 });
  });

  it('derives the Identity Platform issuer from projectId when no issuer is supplied', async () => {
    const PROJECT_ID = 'my-firebase-project';
    const provider = makeProvider({ projectId: PROJECT_ID });
    const token = await signGoogleToken(
      { sub: 'firebase-user-1', user_id: 'firebase-user-1' },
      `https://securetoken.google.com/${PROJECT_ID}`,
      AUDIENCE,
    );

    const ctx = await provider.validateToken(token);
    expect(ctx.userId).toBe('firebase-user-1');
    // tenantId falls back to projectId when no `hd` claim is present
    expect(ctx.tenantId).toBe(PROJECT_ID);
  });

  it('rejects an Identity Platform token whose issuer does not match the configured project', async () => {
    const provider = makeProvider({ projectId: 'project-a' });
    const token = await signGoogleToken(
      { sub: 'u' },
      'https://securetoken.google.com/project-b',
      AUDIENCE,
    );

    await expect(provider.validateToken(token)).rejects.toMatchObject({ statusCode: 401 });
  });

  it('honours an explicit issuer override (Workforce / Workload Identity Federation)', async () => {
    const POOL_ISSUER = 'https://iam.googleapis.com/projects/123/locations/global/workforcePools/pool-1/providers/oidc-1';
    const provider = makeProvider({
      issuer: POOL_ISSUER,
      jwksUri: 'https://example.com/jwks.json',
    });
    const token = await signGoogleToken({ sub: 'federated-user' }, POOL_ISSUER, AUDIENCE);

    const ctx = await provider.validateToken(token);
    expect(ctx.userId).toBe('federated-user');
  });

  it('caches the JWKS function across calls', async () => {
    const provider = makeProvider();
    const token = await signGoogleToken({ sub: 'u' });

    await provider.validateToken(token);
    await provider.validateToken(token);
    expect(createRemoteJWKSetSpy).toHaveBeenCalledTimes(1);
  });

  it('exposes its name as `gcp-identity` for registry lookup', () => {
    expect(makeProvider().name).toBe('gcp-identity');
  });

  it('throws a 501 from getUserRoles directing callers to validateToken', async () => {
    const provider = makeProvider();
    await expect(provider.getUserRoles('any')).rejects.toMatchObject({ statusCode: 501 });
  });

  it('rejects tokens that lack any subject claim (sub or user_id)', async () => {
    const provider = makeProvider();
    // Sign a token with no `sub` claim
    const token = await new jose.SignJWT({ email: 'nobody@example.com' })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuer('https://accounts.google.com')
      .setAudience(AUDIENCE)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);

    await expect(provider.validateToken(token)).rejects.toMatchObject({
      statusCode: 401,
      message: expect.stringMatching(/missing subject claim/),
    });
  });
});
