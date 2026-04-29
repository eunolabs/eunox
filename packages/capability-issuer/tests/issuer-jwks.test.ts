/**
 * Tests for the JWKS endpoint on the capability issuer (R-6).
 *
 * Verifies:
 *  - getJwks() returns a valid JWK Set
 *  - The JWK has correct kty/alg/use/kid fields
 *  - getPublicKey() still works (backward compat)
 *  - The kid in signed JWTs matches a kid in the JWK Set
 */

import * as jose from 'jose';
import {
  IdentityAdapter,
  IdentityAdapterConfig,
  JwkKey,
  UserContext,
  createLogger,
} from '@euno/common';
import { CapabilityIssuerService } from '../src/issuer-service';
import { SigningAdapter } from '../src/signer';

// ── Stubs ─────────────────────────────────────────────────────────────────

class StubIdentityProvider extends IdentityAdapter {
  public readonly name = 'stub';
  constructor(private ctx: UserContext) {
    super({ type: 'stub', name: 'stub' } as IdentityAdapterConfig);
  }
  async validateToken(_token: string): Promise<UserContext> {
    return this.ctx;
  }
  async getUserRoles(_userId: string): Promise<string[]> {
    return this.ctx.roles;
  }
}

// ── Minimal in-process signer using jose ──────────────────────────────────

const SIGNING_ALG = 'RS256' as const;

class JoseRsaSigner extends SigningAdapter {
  private readonly _privateKey: jose.KeyLike;
  private readonly _publicKeyPem: string;
  private readonly _kid: string;

  constructor(privateKey: jose.KeyLike, publicKeyPem: string, kid: string) {
    super({ type: 'stub-rsa', name: 'stub-rsa', algorithm: SIGNING_ALG } as import('@euno/common').SigningAdapterConfig);
    this._privateKey = privateKey;
    this._publicKeyPem = publicKeyPem;
    this._kid = kid;
  }

  async sign(payload: import('@euno/common').CapabilityTokenPayload): Promise<string> {
    return new jose.SignJWT(payload as unknown as jose.JWTPayload)
      .setProtectedHeader({ alg: SIGNING_ALG, kid: this._kid })
      .sign(this._privateKey);
  }

  async getPublicKey(): Promise<string> {
    return this._publicKeyPem;
  }

  async getKeyId(): Promise<string> {
    return this._kid;
  }
}

async function createSigner(): Promise<JoseRsaSigner> {
  const { privateKey, publicKey } = await jose.generateKeyPair(SIGNING_ALG, { extractable: true });
  const publicKeyPem = await jose.exportSPKI(publicKey);
  return new JoseRsaSigner(privateKey, publicKeyPem, 'test-kid-1');
}

const ISSUER_DID = 'did:web:test.issuer.example.com';
const logger = createLogger('issuer-jwks-test', 'test');

// ── Helpers ───────────────────────────────────────────────────────────────

async function buildService(): Promise<{
  signer: JoseRsaSigner;
  service: CapabilityIssuerService;
}> {
  const signer = await createSigner();
  const identity = new StubIdentityProvider({
    userId: 'user-1',
    email: 'user@example.com',
    roles: ['Administrator'],
    tenantId: 'tenant-1',
    claims: {},
  });
  const service = new CapabilityIssuerService(
    signer,
    identity,
    ISSUER_DID,
    900,
    logger,
  );
  return { signer, service };
}

// ── Tests ─────────────────────────────────────────────────────────────────

describe('CapabilityIssuerService.getJwks() — R-6', () => {
  it('returns a JWK Set with at least one key', async () => {
    const { service } = await buildService();

    const jwks = await service.getJwks();

    expect(jwks).toHaveProperty('keys');
    expect(Array.isArray(jwks.keys)).toBe(true);
    expect(jwks.keys.length).toBeGreaterThanOrEqual(1);
  });

  it('the JWK has the required fields: kty, kid, use="sig", alg', async () => {
    const { service } = await buildService();

    const jwks = await service.getJwks();
    const key = jwks.keys[0]!;

    expect(typeof key.kty).toBe('string');
    expect(key.kty.length).toBeGreaterThan(0);
    expect(key.kid).toBe('test-kid-1');
    expect(key.use).toBe('sig');
    expect(key.alg).toBe(SIGNING_ALG);
  });

  it('the JWK kty is RSA for an RS256 key and includes n/e fields', async () => {
    const { service } = await buildService();

    const jwks = await service.getJwks();
    const key = jwks.keys[0]!;

    expect(key.kty).toBe('RSA');
    expect(typeof key.n).toBe('string');
    expect(typeof key.e).toBe('string');
  });

  it('kid in the JWK matches the signer kid', async () => {
    const { signer, service } = await buildService();

    const jwks = await service.getJwks();
    const signerKid = await signer.getKeyId();

    expect(jwks.keys[0]!.kid).toBe(signerKid);
  });

  it('a token signed by the signer can be verified using the JWK from getJwks()', async () => {
    const { service } = await buildService();

    // Issue a real token
    const result = await service.issueCapability({
      authToken: 'user-bearer-token',
      agentId: 'test-agent',
    });
    const token = result.token;

    // Decode the header to confirm kid is present
    const header = jose.decodeProtectedHeader(token);
    expect(typeof header.kid).toBe('string');

    // Fetch the JWKS and find the matching key
    const jwks = await service.getJwks();
    const matchingJwk = jwks.keys.find((k: JwkKey) => k.kid === header.kid);
    expect(matchingJwk).toBeDefined();

    // Verify the token using the matching JWK
    const keyObject = await jose.importJWK(matchingJwk as jose.JWK, header.alg as string);
    const { payload } = await jose.jwtVerify(token, keyObject as jose.KeyLike);

    expect(payload.iss).toBe(ISSUER_DID);
    expect(payload.sub).toBe('test-agent');
  });

  it('kid in the JWT header matches a kid in the published JWK Set', async () => {
    const { service } = await buildService();

    const result = await service.issueCapability({
      authToken: 'user-bearer-token',
      agentId: 'test-agent',
    });

    const header = jose.decodeProtectedHeader(result.token);
    const jwks = await service.getJwks();
    const kidSet = new Set(jwks.keys.map((k: JwkKey) => k.kid));

    expect(kidSet.has(header.kid!)).toBe(true);
  });
});

describe('CapabilityIssuerService.getJwks() — alg inference', () => {
  it('omits alg when getAlgorithm() is absent and key material is RSA (ambiguous algorithm family)', async () => {
    // Build a TokenSigner that does NOT have getAlgorithm() to test the
    // fallback path that infers alg from JWK key material.
    const { privateKey: privKey, publicKey: pubKey } = await jose.generateKeyPair('RS256', {
      extractable: true,
    });
    const publicKeyPem = await jose.exportSPKI(pubKey);

    // Minimal TokenSigner without getAlgorithm
    const minimalSigner: import('@euno/common').TokenSigner = {
      async sign(payload) {
        return new jose.SignJWT(payload as unknown as jose.JWTPayload)
          .setProtectedHeader({ alg: 'RS256' })
          .sign(privKey);
      },
      async getPublicKey() { return publicKeyPem; },
      async getKeyId() { return 'no-alg-kid'; },
      // getAlgorithm intentionally omitted
    };

    const identity = new StubIdentityProvider({
      userId: 'u', email: 'u@x.com', roles: ['Administrator'], tenantId: 't', claims: {},
    });
    const service = new CapabilityIssuerService(minimalSigner, identity, ISSUER_DID, 900, logger);

    const jwks = await service.getJwks();
    const key = jwks.keys[0]!;

    // RSA is ambiguous — alg should be omitted rather than guessing
    expect(key['alg']).toBeUndefined();
    expect(key.kty).toBe('RSA');
    expect(key.use).toBe('sig');
    expect(key.kid).toBe('no-alg-kid');
  });

  it('infers alg=ES256 from JWK key material for P-256 EC keys without getAlgorithm()', async () => {
    const { privateKey: privKey, publicKey: pubKey } = await jose.generateKeyPair('ES256', {
      extractable: true,
    });
    const publicKeyPem = await jose.exportSPKI(pubKey);

    const ecSigner: import('@euno/common').TokenSigner = {
      async sign(payload) {
        return new jose.SignJWT(payload as unknown as jose.JWTPayload)
          .setProtectedHeader({ alg: 'ES256' })
          .sign(privKey);
      },
      async getPublicKey() { return publicKeyPem; },
      async getKeyId() { return 'ec-kid'; },
    };

    const identity = new StubIdentityProvider({
      userId: 'u', email: 'u@x.com', roles: ['Administrator'], tenantId: 't', claims: {},
    });
    const service = new CapabilityIssuerService(ecSigner, identity, ISSUER_DID, 900, logger);

    const jwks = await service.getJwks();
    const key = jwks.keys[0]!;

    expect(key.kty).toBe('EC');
    expect(key['alg']).toBe('ES256');
    expect(key.use).toBe('sig');
    expect(key.kid).toBe('ec-kid');
  });
});

describe('CapabilityIssuerService.getPublicKey() backward compat', () => {
  it('returns the SPKI string in the publicKey field', async () => {
    const { signer, service } = await buildService();
    const expectedSpki = await signer.getPublicKey();

    const publicKey = await service.getPublicKey();

    expect(publicKey).toBe(expectedSpki);
    expect(typeof publicKey).toBe('string');
    expect(publicKey).toMatch(/-----BEGIN PUBLIC KEY-----/);
  });
});
