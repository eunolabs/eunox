import * as jose from 'jose';
import { TokenMinter, MINTER_MAX_TTL_SECONDS } from '../src/token-minter';
import { LocalTokenSigner } from '../src/local-token-signer';
import { CAPABILITY_TOKEN_SCHEMA_VERSION } from '@euno/common';

async function makeMinter(ttlSeconds?: number): Promise<{ minter: TokenMinter; signer: LocalTokenSigner }> {
  const signer = await LocalTokenSigner.generate('RS256');
  const minter = new TokenMinter({
    signer,
    issuerDid: 'did:web:minter.test',
    gatewayAudience: 'tool-gateway',
    ttlSeconds,
  });
  return { minter, signer };
}

describe('TokenMinter', () => {
  it('mintToken returns a JWT string', async () => {
    const { minter } = await makeMinter();
    const result = await minter.mintToken({
      tenantId: 'tenant-1',
      agentId: 'agent-1',
      sessionId: 'session-1',
      capabilities: [],
      apiKeyPrefix: 'prefix12',
      scopes: ['enforce'],
      policyId: 'policy-1',
    });
    expect(typeof result.capabilityToken).toBe('string');
    expect(result.capabilityToken.split('.').length).toBe(3);
  });

  it('minted JWT has correct claims', async () => {
    const { minter, signer } = await makeMinter(300);
    const result = await minter.mintToken({
      tenantId: 'tenant-1',
      agentId: 'agent-abc',
      sessionId: 'session-abc',
      capabilities: [],
      apiKeyPrefix: 'myprefix',
      scopes: ['enforce'],
      policyId: 'policy-1',
    });

    const publicKeyPem = await signer.getPublicKey();
    const pubKey = await jose.importSPKI(publicKeyPem, 'RS256');
    const { payload } = await jose.jwtVerify(result.capabilityToken, pubKey);

    expect(payload['iss']).toBe('did:web:minter.test');
    expect(payload['sub']).toBe('agent-abc');
    expect(payload['aud']).toBe('tool-gateway');
    expect(payload['jti']).toBe(result.jti);
    expect(payload['schemaVersion']).toBe(CAPABILITY_TOKEN_SCHEMA_VERSION);
    expect(payload['exp']).toBe(result.expiresAt);
  });

  it('TTL is enforced at max 300 seconds', async () => {
    // Request 600s, should be capped at 300s
    const { minter } = await makeMinter(600);
    const before = Math.floor(Date.now() / 1000);
    const result = await minter.mintToken({
      tenantId: 't',
      agentId: 'a',
      sessionId: 's',
      capabilities: [],
      apiKeyPrefix: 'pref',
      scopes: [],
      policyId: 'p',
    });
    const after = Math.floor(Date.now() / 1000);
    const actualTtl = result.expiresAt - before;
    expect(actualTtl).toBeLessThanOrEqual(MINTER_MAX_TTL_SECONDS + (after - before));
    expect(actualTtl).toBeGreaterThan(0);
  });

  it('vc envelope is present with correct shape', async () => {
    const { minter, signer } = await makeMinter();
    const result = await minter.mintToken({
      tenantId: 'tenant-1',
      agentId: 'agent-1',
      sessionId: 'sess-1',
      capabilities: [],
      apiKeyPrefix: 'prefix12',
      scopes: ['enforce'],
      policyId: 'pol-1',
    });

    const publicKeyPem = await signer.getPublicKey();
    const pubKey = await jose.importSPKI(publicKeyPem, 'RS256');
    const { payload } = await jose.jwtVerify(result.capabilityToken, pubKey);
    const vc = payload['vc'] as Record<string, unknown>;
    expect(vc).toBeDefined();
    expect(Array.isArray(vc['type'])).toBe(true);
    expect((vc['type'] as string[]).includes('CapabilityCredential')).toBe(true);
    expect(vc['id']).toBe(`urn:uuid:${result.jti}`);
  });

  it('authorizedBy fields are set correctly', async () => {
    const { minter, signer } = await makeMinter();
    const result = await minter.mintToken({
      tenantId: 'my-tenant',
      agentId: 'my-agent',
      sessionId: 'my-session',
      capabilities: [],
      apiKeyPrefix: 'myprefix',
      scopes: ['admin'],
      policyId: 'p1',
    });

    const publicKeyPem = await signer.getPublicKey();
    const pubKey = await jose.importSPKI(publicKeyPem, 'RS256');
    const { payload } = await jose.jwtVerify(result.capabilityToken, pubKey);
    const authorizedBy = payload['authorizedBy'] as Record<string, unknown>;
    expect(authorizedBy['userId']).toBe('myprefix');
    expect(authorizedBy['tenantId']).toBe('my-tenant');
    expect(authorizedBy['roles']).toEqual(['admin']);
  });

  it('returns unique jti for each mint', async () => {
    const { minter } = await makeMinter();
    const input = {
      tenantId: 't',
      agentId: 'a',
      sessionId: 's',
      capabilities: [],
      apiKeyPrefix: 'p',
      scopes: [],
      policyId: 'pol',
    };
    const r1 = await minter.mintToken(input);
    const r2 = await minter.mintToken(input);
    expect(r1.jti).not.toBe(r2.jti);
  });
});
