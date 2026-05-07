/**
 * Tests for the TrustAnchor chain-of-responsibility.
 *
 * Covers:
 *  - SpkiTrustAnchor: owns() algorithm + localIssuers filtering; resolveKey()
 *    key import + caching; updatePublicKey() cache flush.
 *  - JwksTrustAnchor: owns() algorithm + localIssuers filtering; resolveKey()
 *    kid fast-path (via optional getKeyByKid); resolveKey() try-all slow-path
 *    (requireKid=false); kid-miss error handling.
 *  - PartnerDidTrustAnchor: owns() routing (env-var + registry path);
 *    resolveKey() key forwarding; invalidate() delegation to the resolver.
 *  - buildTrustChain(): produces the correct anchor types and order for all
 *    three configuration scenarios (SPKI only, JWKS only, partner + local).
 *  - JWTTokenVerifier + JwksTokenVerifier integration with the chain (verify()
 *    routes tokens correctly through each anchor; invalidate() called on
 *    try-all exhaustion; updatePublicKey() throws on JwksTokenVerifier).
 */

import * as jose from 'jose';
import {
  TrustAnchorContext,
  SpkiTrustAnchor,
  JwksTrustAnchor,
  PartnerDidTrustAnchor,
  buildTrustChain,
} from '../src/trust-anchor';
import { PartnerIssuerResolver } from '../src/partner-issuer-resolver';
import { JWTTokenVerifier, JwksTokenVerifier } from '../src/verifier';
import {
  CapabilityTokenPayload,
  JwkSet,
  getCurrentTimestamp,
  getExpirationTimestamp,
  CAPABILITY_TOKEN_SCHEMA_VERSION,
} from '@euno/common';

// ── Key generation helpers ──────────────────────────────────────────────────

async function makeRsaKeyPair() {
  const { publicKey, privateKey } = await jose.generateKeyPair('RS256');
  const spkiPem = await jose.exportSPKI(publicKey);
  return { publicKey, privateKey, spkiPem };
}

function makeMinimalPayload(overrides: Partial<CapabilityTokenPayload> = {}): Record<string, unknown> {
  return {
    iss: 'did:web:issuer.example.com',
    sub: 'test-agent',
    aud: 'tool-gateway',
    iat: getCurrentTimestamp(),
    exp: getExpirationTimestamp(900),
    jti: `jti-${Math.random()}`,
    schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
    capabilities: [],
    ...overrides,
  } as Record<string, unknown>;
}

// ── SpkiTrustAnchor ─────────────────────────────────────────────────────────

describe('SpkiTrustAnchor', () => {
  let spkiPem: string;
  let privateKey: jose.KeyLike;

  beforeAll(async () => {
    const kp = await makeRsaKeyPair();
    spkiPem = kp.spkiPem;
    privateKey = kp.privateKey;
  });

  describe('owns()', () => {
    it('accepts a token when no algorithm or issuer restriction is configured', () => {
      const anchor = new SpkiTrustAnchor({ publicKey: spkiPem, algorithms: ['RS256'] });
      expect(anchor.owns({ iss: 'did:web:any.example.com', kid: undefined, alg: 'RS256' })).toBe(true);
    });

    it('rejects a token whose algorithm is outside the allow-list', () => {
      const anchor = new SpkiTrustAnchor({ publicKey: spkiPem, algorithms: ['RS256'] });
      expect(anchor.owns({ iss: undefined, kid: undefined, alg: 'ES256' })).toBe(false);
    });

    it('accepts a token whose iss is in the localIssuers set', () => {
      const anchor = new SpkiTrustAnchor({
        publicKey: spkiPem,
        algorithms: ['RS256'],
        localIssuers: new Set(['did:web:issuer.example.com']),
      });
      expect(
        anchor.owns({ iss: 'did:web:issuer.example.com', kid: undefined, alg: 'RS256' }),
      ).toBe(true);
    });

    it('rejects a token whose iss is NOT in the localIssuers set', () => {
      const anchor = new SpkiTrustAnchor({
        publicKey: spkiPem,
        algorithms: ['RS256'],
        localIssuers: new Set(['did:web:issuer.example.com']),
      });
      expect(
        anchor.owns({ iss: 'did:web:stranger.example.com', kid: undefined, alg: 'RS256' }),
      ).toBe(false);
    });

    it('passes through tokens with no iss even when localIssuers is set', () => {
      // Preserves backward-compat: legacy tokens may omit the iss claim.
      const anchor = new SpkiTrustAnchor({
        publicKey: spkiPem,
        algorithms: ['RS256'],
        localIssuers: new Set(['did:web:issuer.example.com']),
      });
      expect(anchor.owns({ iss: undefined, kid: undefined, alg: 'RS256' })).toBe(true);
    });
  });

  describe('resolveKey()', () => {
    it('returns a key that successfully verifies a matching token', async () => {
      const anchor = new SpkiTrustAnchor({ publicKey: spkiPem, algorithms: ['RS256'] });
      const ctx: TrustAnchorContext = { iss: undefined, kid: undefined, alg: 'RS256' };
      const resolution = await anchor.resolveKey(ctx);
      expect(resolution.key).toBeDefined();
      expect(resolution.keys).toBeUndefined();
      expect(resolution.algorithms).toContain('RS256');

      const token = await new jose.SignJWT(makeMinimalPayload())
        .setProtectedHeader({ alg: 'RS256' })
        .sign(privateKey);
      await expect(
        jose.jwtVerify(token, resolution.key!, { algorithms: resolution.algorithms }),
      ).resolves.toBeDefined();
    });

    it('caches the key object (resolveKey called twice returns the same reference)', async () => {
      const anchor = new SpkiTrustAnchor({ publicKey: spkiPem, algorithms: ['RS256'] });
      const ctx: TrustAnchorContext = { iss: undefined, kid: undefined, alg: 'RS256' };
      const r1 = await anchor.resolveKey(ctx);
      const r2 = await anchor.resolveKey(ctx);
      expect(r1.key).toBe(r2.key);
    });

    it('flushes the key cache on updatePublicKey()', async () => {
      const anchor = new SpkiTrustAnchor({ publicKey: spkiPem, algorithms: ['RS256'] });
      const ctx: TrustAnchorContext = { iss: undefined, kid: undefined, alg: 'RS256' };
      const r1 = await anchor.resolveKey(ctx);

      // Rotate key — use a fresh key pair.
      const { spkiPem: newPem, privateKey: newPrivKey } = await makeRsaKeyPair();
      anchor.updatePublicKey(newPem);

      const r2 = await anchor.resolveKey(ctx);
      // Different key object after rotation.
      expect(r2.key).not.toBe(r1.key);

      // The new key should verify tokens signed with newPrivKey.
      const token = await new jose.SignJWT(makeMinimalPayload())
        .setProtectedHeader({ alg: 'RS256' })
        .sign(newPrivKey);
      await expect(
        jose.jwtVerify(token, r2.key!, { algorithms: ['RS256'] }),
      ).resolves.toBeDefined();
    });
  });
});

// ── JwksTrustAnchor ─────────────────────────────────────────────────────────

describe('JwksTrustAnchor', () => {
  let publicKey: jose.KeyLike;

  beforeAll(async () => {
    const kp = await makeRsaKeyPair();
    publicKey = kp.publicKey;
  });

  function makeJwksSource(kid = 'key-1'): {
    source: import('@euno/common').JwksKeySource;
    jwk: import('@euno/common').JwkKey;
  } {
    // Build a minimal JWKS from the in-scope RSA public key using
    // the n/e modulus components.  For testing purposes we embed
    // them as placeholder strings; the actual verification is
    // exercised via JwksClient integration in the verifier tests.
    const jwk: import('@euno/common').JwkKey = {
      kty: 'RSA',
      kid,
      use: 'sig',
      alg: 'RS256',
      n: 'placeholder',
      e: 'AQAB',
    };
    const source: import('@euno/common').JwksKeySource = {
      getJwks: jest.fn().mockResolvedValue({ keys: [jwk] } as JwkSet),
    };
    return { source, jwk };
  }

  describe('owns()', () => {
    it('returns true for a token with an allowed algorithm', () => {
      const { source } = makeJwksSource();
      const anchor = new JwksTrustAnchor({ keySource: source, algorithms: ['RS256'] });
      expect(anchor.owns({ iss: undefined, kid: 'key-1', alg: 'RS256' })).toBe(true);
    });

    it('returns false for a disallowed algorithm', () => {
      const { source } = makeJwksSource();
      const anchor = new JwksTrustAnchor({ keySource: source, algorithms: ['RS256'] });
      expect(anchor.owns({ iss: undefined, kid: 'key-1', alg: 'EdDSA' })).toBe(false);
    });

    it('returns true when iss is in localIssuers', () => {
      const { source } = makeJwksSource();
      const anchor = new JwksTrustAnchor({
        keySource: source,
        algorithms: ['RS256'],
        localIssuers: new Set(['did:web:issuer.example.com']),
      });
      expect(
        anchor.owns({ iss: 'did:web:issuer.example.com', kid: 'key-1', alg: 'RS256' }),
      ).toBe(true);
    });

    it('returns false when iss is NOT in localIssuers', () => {
      const { source } = makeJwksSource();
      const anchor = new JwksTrustAnchor({
        keySource: source,
        algorithms: ['RS256'],
        localIssuers: new Set(['did:web:issuer.example.com']),
      });
      expect(
        anchor.owns({ iss: 'did:web:other.example.com', kid: 'key-1', alg: 'RS256' }),
      ).toBe(false);
    });

    it('passes through tokens with no iss even when localIssuers is set', () => {
      const { source } = makeJwksSource();
      const anchor = new JwksTrustAnchor({
        keySource: source,
        algorithms: ['RS256'],
        localIssuers: new Set(['did:web:issuer.example.com']),
      });
      expect(anchor.owns({ iss: undefined, kid: 'key-1', alg: 'RS256' })).toBe(true);
    });
  });

  describe('resolveKey() — kid fast-path', () => {
    it('returns TrustAnchorResolution.key (not keys) when kid is present', async () => {
      // Build a real JwksClient-backed anchor using a fresh key pair.
      const jwk = await jose.exportJWK(publicKey);
      const jwkEntry = { ...jwk, kid: 'k1', use: 'sig', alg: 'RS256' };
      // Use a generic JwksKeySource stub so the test stays self-contained.
      const source: import('@euno/common').JwksKeySource = {
        getJwks: jest.fn().mockResolvedValue({ keys: [jwkEntry] }),
      };
      const anchor = new JwksTrustAnchor({ keySource: source, algorithms: ['RS256'] });
      const ctx: TrustAnchorContext = { iss: undefined, kid: 'k1', alg: 'RS256' };
      const resolution = await anchor.resolveKey(ctx);
      expect(resolution.key).toBeDefined();
      expect(resolution.keys).toBeUndefined();
      expect(resolution.algorithms).toContain('RS256');
    });

    it('throws when the kid is absent from the JWKS (generic source)', async () => {
      const source: import('@euno/common').JwksKeySource = {
        getJwks: jest.fn().mockResolvedValue({ keys: [] }),
      };
      const anchor = new JwksTrustAnchor({ keySource: source, algorithms: ['RS256'] });
      const ctx: TrustAnchorContext = { iss: undefined, kid: 'missing-kid', alg: 'RS256' };
      await expect(anchor.resolveKey(ctx)).rejects.toMatchObject({ code: 'INVALID_TOKEN' });
    });
  });

  describe('resolveKey() — try-all slow-path (no kid)', () => {
    it('returns TrustAnchorResolution.keys when no kid is provided', async () => {
      const jwk = await jose.exportJWK(publicKey);
      const jwkEntry = { ...jwk, kid: 'k1', use: 'sig', alg: 'RS256' };
      const source: import('@euno/common').JwksKeySource = {
        getJwks: jest.fn().mockResolvedValue({ keys: [jwkEntry] }),
      };
      const anchor = new JwksTrustAnchor({ keySource: source, algorithms: ['RS256'] });
      const ctx: TrustAnchorContext = { iss: undefined, kid: undefined, alg: 'RS256' };
      const resolution = await anchor.resolveKey(ctx);
      expect(resolution.keys).toBeDefined();
      expect(resolution.key).toBeUndefined();
      expect(Array.isArray(resolution.keys)).toBe(true);
      expect(resolution.keys!.length).toBeGreaterThan(0);
    });

    it('throws when the JWKS is empty (no keys to try)', async () => {
      const source: import('@euno/common').JwksKeySource = {
        getJwks: jest.fn().mockResolvedValue({ keys: [] }),
      };
      const anchor = new JwksTrustAnchor({ keySource: source, algorithms: ['RS256'] });
      const ctx: TrustAnchorContext = { iss: undefined, kid: undefined, alg: 'RS256' };
      await expect(anchor.resolveKey(ctx)).rejects.toMatchObject({ code: 'INVALID_TOKEN' });
    });
  });
});

// ── PartnerDidTrustAnchor ────────────────────────────────────────────────────

describe('PartnerDidTrustAnchor', () => {
  function makeResolver(trustedDid: string, key?: jose.KeyLike | Uint8Array) {
    const resolver: jest.Mocked<Pick<PartnerIssuerResolver, 'mightTrust' | 'getKey' | 'invalidate'>> = {
      mightTrust: jest.fn((did) => did === trustedDid),
      getKey: jest.fn().mockResolvedValue({ key, alg: 'RS256' }),
      invalidate: jest.fn(),
    };
    return resolver;
  }

  describe('owns()', () => {
    it('returns true for a trusted partner DID', () => {
      const resolver = makeResolver('did:web:partner.example.com');
      const anchor = new PartnerDidTrustAnchor({ resolver: resolver as unknown as PartnerIssuerResolver });
      expect(
        anchor.owns({ iss: 'did:web:partner.example.com', kid: 'k1', alg: 'EdDSA' }),
      ).toBe(true);
    });

    it('returns false for an untrusted DID', () => {
      const resolver = makeResolver('did:web:partner.example.com');
      const anchor = new PartnerDidTrustAnchor({ resolver: resolver as unknown as PartnerIssuerResolver });
      expect(
        anchor.owns({ iss: 'did:web:stranger.example.com', kid: 'k1', alg: 'EdDSA' }),
      ).toBe(false);
    });

    it('returns false when iss is undefined', () => {
      const resolver = makeResolver('did:web:partner.example.com');
      const anchor = new PartnerDidTrustAnchor({ resolver: resolver as unknown as PartnerIssuerResolver });
      expect(anchor.owns({ iss: undefined, kid: 'k1', alg: 'RS256' })).toBe(false);
    });

    it('is not gated on algorithm — partners can use any alg', () => {
      const resolver = makeResolver('did:web:partner.example.com');
      const anchor = new PartnerDidTrustAnchor({ resolver: resolver as unknown as PartnerIssuerResolver });
      // EdDSA, ES256, RS256 — all accepted as long as the DID is trusted.
      for (const alg of ['EdDSA', 'ES256', 'RS256']) {
        expect(
          anchor.owns({ iss: 'did:web:partner.example.com', kid: 'k1', alg }),
        ).toBe(true);
      }
    });

    it('returns true for a registry-backed DID (not in env-var set)', () => {
      // Simulate a resolver that has a registry wired: mightTrust returns true
      // for any non-empty DID even if it's not in the in-memory set, deferring
      // the definitive trust decision to the async getKey() call.
      const resolver: jest.Mocked<Pick<PartnerIssuerResolver, 'mightTrust' | 'getKey' | 'invalidate'>> = {
        mightTrust: jest.fn((_did: string) => true), // registry path: all non-empty DIDs pass owns()
        getKey: jest.fn(),
        invalidate: jest.fn(),
      };
      const anchor = new PartnerDidTrustAnchor({ resolver: resolver as unknown as PartnerIssuerResolver });
      expect(
        anchor.owns({ iss: 'did:web:registry-partner.example.com', kid: 'k1', alg: 'EdDSA' }),
      ).toBe(true);
      expect(resolver.mightTrust).toHaveBeenCalledWith('did:web:registry-partner.example.com');
    });
  });

  describe('resolveKey()', () => {
    it('delegates to resolver.getKey() and forwards key + alg', async () => {
      const { publicKey: partnerPub } = await jose.generateKeyPair('ES256');
      const resolver = makeResolver('did:web:partner.example.com', partnerPub);
      const anchor = new PartnerDidTrustAnchor({ resolver: resolver as unknown as PartnerIssuerResolver });
      const ctx: TrustAnchorContext = { iss: 'did:web:partner.example.com', kid: 'k1', alg: 'ES256' };
      const resolution = await anchor.resolveKey(ctx);
      expect(resolution.key).toBe(partnerPub);
      expect(resolution.algorithms).toEqual(['RS256']); // forwarded from getKey mock
      expect(resolution.issuer).toBe('did:web:partner.example.com');
      expect(resolver.getKey).toHaveBeenCalledWith('did:web:partner.example.com', 'k1');
    });

    it('throws INVALID_TOKEN when iss is undefined', async () => {
      const resolver = makeResolver('did:web:partner.example.com');
      const anchor = new PartnerDidTrustAnchor({ resolver: resolver as unknown as PartnerIssuerResolver });
      await expect(
        anchor.resolveKey({ iss: undefined, kid: 'k1', alg: 'EdDSA' }),
      ).rejects.toMatchObject({ code: 'INVALID_TOKEN' });
    });

    it('throws INVALID_TOKEN when kid is undefined', async () => {
      const resolver = makeResolver('did:web:partner.example.com');
      const anchor = new PartnerDidTrustAnchor({ resolver: resolver as unknown as PartnerIssuerResolver });
      await expect(
        anchor.resolveKey({ iss: 'did:web:partner.example.com', kid: undefined, alg: 'EdDSA' }),
      ).rejects.toMatchObject({ code: 'INVALID_TOKEN' });
    });
  });

  describe('invalidate()', () => {
    it('calls resolver.invalidate() with the correct did and kid', () => {
      const resolver = makeResolver('did:web:partner.example.com');
      const anchor = new PartnerDidTrustAnchor({ resolver: resolver as unknown as PartnerIssuerResolver });
      anchor.invalidate({ iss: 'did:web:partner.example.com', kid: 'k1', alg: 'EdDSA' });
      expect(resolver.invalidate).toHaveBeenCalledWith('did:web:partner.example.com', 'k1');
    });

    it('does nothing when iss is undefined', () => {
      const resolver = makeResolver('did:web:partner.example.com');
      const anchor = new PartnerDidTrustAnchor({ resolver: resolver as unknown as PartnerIssuerResolver });
      expect(() =>
        anchor.invalidate({ iss: undefined, kid: 'k1', alg: 'EdDSA' }),
      ).not.toThrow();
      expect(resolver.invalidate).not.toHaveBeenCalled();
    });
  });
});

// ── buildTrustChain() ────────────────────────────────────────────────────────

describe('buildTrustChain()', () => {
  it('produces [SpkiTrustAnchor] when only a public key is supplied', () => {
    const chain = buildTrustChain({ publicKey: 'pem', algorithms: ['RS256'] });
    expect(chain).toHaveLength(1);
    expect(chain[0]).toBeInstanceOf(SpkiTrustAnchor);
  });

  it('produces [JwksTrustAnchor] when a JWKS key source is supplied', () => {
    const source: import('@euno/common').JwksKeySource = {
      getJwks: jest.fn(),
    };
    const chain = buildTrustChain({ publicKey: '', algorithms: ['RS256'], jwksKeySource: source });
    expect(chain).toHaveLength(1);
    expect(chain[0]).toBeInstanceOf(JwksTrustAnchor);
  });

  it('produces [PartnerDidTrustAnchor, SpkiTrustAnchor] when a partner resolver is supplied', () => {
    const resolver = { mightTrust: jest.fn(), getKey: jest.fn(), invalidate: jest.fn() };
    const chain = buildTrustChain({
      publicKey: 'pem',
      algorithms: ['RS256'],
      partnerResolver: resolver as unknown as PartnerIssuerResolver,
    });
    expect(chain).toHaveLength(2);
    expect(chain[0]).toBeInstanceOf(PartnerDidTrustAnchor);
    expect(chain[1]).toBeInstanceOf(SpkiTrustAnchor);
  });

  it('produces [PartnerDidTrustAnchor, JwksTrustAnchor] when both resolver and JWKS source are supplied', () => {
    const resolver = { mightTrust: jest.fn(), getKey: jest.fn(), invalidate: jest.fn() };
    const source: import('@euno/common').JwksKeySource = { getJwks: jest.fn() };
    const chain = buildTrustChain({
      publicKey: '',
      algorithms: ['RS256'],
      partnerResolver: resolver as unknown as PartnerIssuerResolver,
      jwksKeySource: source,
    });
    expect(chain).toHaveLength(2);
    expect(chain[0]).toBeInstanceOf(PartnerDidTrustAnchor);
    expect(chain[1]).toBeInstanceOf(JwksTrustAnchor);
  });
});

// ── Integration: JWTTokenVerifier chain routing ──────────────────────────────

describe('JWTTokenVerifier — trust-anchor chain routing', () => {
  let spkiPem: string;
  let privateKey: jose.KeyLike;

  beforeAll(async () => {
    const kp = await makeRsaKeyPair();
    spkiPem = kp.spkiPem;
    privateKey = kp.privateKey;
  });

  it('routes a local token through SpkiTrustAnchor (no JWKS, no partner resolver)', async () => {
    const verifier = new JWTTokenVerifier(spkiPem, { requireKid: false });
    const token = await new jose.SignJWT(makeMinimalPayload())
      .setProtectedHeader({ alg: 'RS256' })
      .sign(privateKey);
    await expect(verifier.verify(token)).resolves.toBeDefined();
  });

  it('rejects a token when no anchor in the chain matches the algorithm', async () => {
    const verifier = new JWTTokenVerifier(spkiPem, {
      requireKid: false,
      algorithms: ['RS256'],
    });
    // Token signed with an EC key (ES256) — the RS256-only anchor won't own it.
    const { privateKey: ecPriv } = await jose.generateKeyPair('ES256');
    const token = await new jose.SignJWT(makeMinimalPayload())
      .setProtectedHeader({ alg: 'ES256' })
      .sign(ecPriv);
    await expect(verifier.verify(token)).rejects.toMatchObject({ code: 'INVALID_TOKEN' });
  });

  it('does NOT verify a local-key token whose iss matches no anchor when localIssuers is set', async () => {
    const verifier = new JWTTokenVerifier(spkiPem, {
      requireKid: false,
      localIssuers: ['did:web:issuer.example.com'],
    });
    // Signed with the local key but iss is not in localIssuers.
    const token = await new jose.SignJWT(
      makeMinimalPayload({ iss: 'did:web:stranger.example.com' }),
    )
      .setProtectedHeader({ alg: 'RS256' })
      .sign(privateKey);
    await expect(verifier.verify(token)).rejects.toMatchObject({ code: 'INVALID_TOKEN' });
  });

  it('verifies a local-key token whose iss is in localIssuers', async () => {
    const verifier = new JWTTokenVerifier(spkiPem, {
      requireKid: false,
      localIssuers: ['did:web:issuer.example.com'],
    });
    const token = await new jose.SignJWT(makeMinimalPayload())
      .setProtectedHeader({ alg: 'RS256' })
      .sign(privateKey);
    await expect(verifier.verify(token)).resolves.toBeDefined();
  });
});

// ── Integration: JwksTokenVerifier chain routing ─────────────────────────────

describe('JwksTokenVerifier — trust-anchor chain routing', () => {
  let privateKey: jose.KeyLike;
  let publicKey: jose.KeyLike;

  beforeAll(async () => {
    const kp = await makeRsaKeyPair();
    privateKey = kp.privateKey;
    publicKey = kp.publicKey;
  });

  async function makeJwksVerifier(kid: string, opts: { requireKid?: boolean } = {}) {
    const jwk = { ...(await jose.exportJWK(publicKey)), kid, use: 'sig', alg: 'RS256' };
    const source: import('@euno/common').JwksKeySource = {
      getJwks: jest.fn().mockResolvedValue({ keys: [jwk] }),
    };
    const verifier = new JwksTokenVerifier(source, {
      algorithms: ['RS256'],
      requireKid: opts.requireKid ?? true,
    });
    return { verifier, source };
  }

  it('verifies a token with kid via JwksTrustAnchor', async () => {
    const { verifier } = await makeJwksVerifier('k1');
    const token = await new jose.SignJWT(makeMinimalPayload())
      .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
      .sign(privateKey);
    await expect(verifier.verify(token)).resolves.toBeDefined();
  });

  it('verifies a token without kid via the try-all path (requireKid=false)', async () => {
    const { verifier } = await makeJwksVerifier('k1', { requireKid: false });
    const token = await new jose.SignJWT(makeMinimalPayload())
      .setProtectedHeader({ alg: 'RS256' })
      .sign(privateKey);
    await expect(verifier.verify(token)).resolves.toBeDefined();
  });

  it('rejects a token without kid when requireKid=true (default)', async () => {
    const { verifier } = await makeJwksVerifier('k1', { requireKid: true });
    const token = await new jose.SignJWT(makeMinimalPayload())
      .setProtectedHeader({ alg: 'RS256' })
      .sign(privateKey);
    await expect(verifier.verify(token)).rejects.toMatchObject({ code: 'INVALID_TOKEN' });
  });
});

// ── JwksTrustAnchor: optional getKeyByKid() ──────────────────────────────────

describe('JwksTrustAnchor — optional getKeyByKid() on JwksKeySource', () => {
  it('uses getKeyByKid() when the key source provides it', async () => {
    const kp = await makeRsaKeyPair();
    const jwk = { ...(await jose.exportJWK(kp.publicKey)), kid: 'k1', use: 'sig', alg: 'RS256' };
    const getKeyByKid = jest.fn().mockResolvedValue(jwk);
    const source: import('@euno/common').JwksKeySource = {
      getJwks: jest.fn(),
      getKeyByKid,
    };
    const anchor = new JwksTrustAnchor({ keySource: source, algorithms: ['RS256'] });
    const ctx: TrustAnchorContext = { iss: undefined, kid: 'k1', alg: 'RS256' };
    const resolution = await anchor.resolveKey(ctx);
    expect(getKeyByKid).toHaveBeenCalledWith('k1');
    expect(source.getJwks).not.toHaveBeenCalled();
    expect(resolution.key).toBeDefined();
  });

  it('falls back to getJwks() + pickJwkByKid when getKeyByKid is absent', async () => {
    const kp = await makeRsaKeyPair();
    const jwk = { ...(await jose.exportJWK(kp.publicKey)), kid: 'k1', use: 'sig', alg: 'RS256' };
    const source: import('@euno/common').JwksKeySource = {
      getJwks: jest.fn().mockResolvedValue({ keys: [jwk] }),
      // getKeyByKid intentionally omitted
    };
    const anchor = new JwksTrustAnchor({ keySource: source, algorithms: ['RS256'] });
    const ctx: TrustAnchorContext = { iss: undefined, kid: 'k1', alg: 'RS256' };
    const resolution = await anchor.resolveKey(ctx);
    expect(source.getJwks).toHaveBeenCalled();
    expect(resolution.key).toBeDefined();
  });
});

// ── JWTTokenVerifier: try-all path calls invalidate() ────────────────────────

describe('JWTTokenVerifier — try-all path invalidation', () => {
  it('calls anchor.invalidate() when all keys exhaust with JWSSignatureVerificationFailed', async () => {
    // Token is signed with signerKey but the anchor returns wrongKey, so
    // every try in the try-all loop fails with JWSSignatureVerificationFailed.
    const { privateKey: signerKey, spkiPem } = await makeRsaKeyPair();
    const { publicKey: wrongKey } = await jose.generateKeyPair('RS256');

    const invalidate = jest.fn();
    const customAnchor = {
      owns: jest.fn().mockReturnValue(true),
      resolveKey: jest.fn().mockResolvedValue({
        keys: [wrongKey],
        algorithms: ['RS256'],
      }),
      invalidate,
    };

    const verifier = new JWTTokenVerifier(spkiPem, { requireKid: false });
    // Inject the custom anchor directly (bypasses buildTrustChain).
    (verifier as unknown as { trustChain: typeof customAnchor[] }).trustChain = [customAnchor];

    const token = await new jose.SignJWT(makeMinimalPayload())
      .setProtectedHeader({ alg: 'RS256' })
      .sign(signerKey);

    await expect(verifier.verify(token)).rejects.toMatchObject({ code: 'INVALID_TOKEN' });
    expect(invalidate).toHaveBeenCalled();
  });
});

// ── JwksTokenVerifier: updatePublicKey() throws ───────────────────────────────

describe('JwksTokenVerifier — updatePublicKey() is unsupported', () => {
  it('throws when updatePublicKey() is called', async () => {
    const kp = await makeRsaKeyPair();
    const source: import('@euno/common').JwksKeySource = { getJwks: jest.fn() };
    const verifier = new JwksTokenVerifier(source);
    expect(() => verifier.updatePublicKey(kp.spkiPem)).toThrow(
      /JwksTokenVerifier\.updatePublicKey\(\) is not supported/,
    );
  });
});
