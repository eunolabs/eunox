/**
 * Tests for the cross-org partner-issuer trust resolver and the
 * multi-issuer verifier path (Sprint 3-4 gap #5).
 */

import * as crypto from 'crypto';
import * as jose from 'jose';
import { CAPABILITY_TOKEN_SCHEMA_VERSION, ErrorCode } from '@euno/common';
import {
  PartnerIssuerResolver,
  createPartnerIssuerResolverFromEnv,
} from '../src/partner-issuer-resolver';
import { JWTTokenVerifier } from '../src/verifier';
import {
  InMemoryPartnerDidRegistry,
  jcsSha256,
  createPinAttestation,
} from '../src/partner-did-registry';

const PARTNER_DID = 'did:web:partner-sim.local%3A4001';

interface PartnerKeys {
  privateKey: jose.KeyLike;
  publicJwk: jose.JWK;
  didDoc: Record<string, unknown>;
}

async function makePartnerKeys(did = PARTNER_DID): Promise<PartnerKeys> {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicJwk = publicKey.export({ format: 'jwk' }) as jose.JWK;
  publicJwk.alg = 'EdDSA';
  publicJwk.use = 'sig';
  const privateJose = (await jose.importPKCS8(
    privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    'EdDSA'
  )) as jose.KeyLike;
  const vmId = `${did}#key-1`;
  return {
    privateKey: privateJose,
    publicJwk,
    didDoc: {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: did,
      verificationMethod: [
        { id: vmId, type: 'JsonWebKey2020', controller: did, publicKeyJwk: publicJwk },
      ],
      authentication: [vmId],
      assertionMethod: [vmId],
    },
  };
}

async function mintPartnerJWT(privateKey: jose.KeyLike, did: string, overrides: Record<string, unknown> = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: did,
    sub: 'partner-agent',
    aud: 'tool-gateway',
    iat: now,
    exp: now + 600,
    jti: `jti-${crypto.randomUUID()}`,
    schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
    capabilities: [{ resource: 'storage://shared/**', actions: ['read'] }],
    ...overrides,
  };
  return new jose.SignJWT(payload)
    .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: `${did}#key-1` })
    .sign(privateKey);
}

function mockFetchForDid(didDoc: Record<string, unknown>): jest.Mock {
  return jest.fn().mockResolvedValue({
    ok: true,
    json: async () => didDoc,
  } as unknown as Response);
}

describe('createPartnerIssuerResolverFromEnv', () => {
  it('returns undefined when TRUSTED_PARTNER_DIDS is unset', () => {
    expect(createPartnerIssuerResolverFromEnv({})).toBeUndefined();
  });

  it('returns undefined when TRUSTED_PARTNER_DIDS is empty', () => {
    expect(createPartnerIssuerResolverFromEnv({ TRUSTED_PARTNER_DIDS: '' })).toBeUndefined();
    expect(createPartnerIssuerResolverFromEnv({ TRUSTED_PARTNER_DIDS: '   , ,  ' })).toBeUndefined();
  });

  it('parses a comma-separated list and trims whitespace', () => {
    const r = createPartnerIssuerResolverFromEnv({
      TRUSTED_PARTNER_DIDS: ' did:web:a , did:web:b ',
    });
    expect(r).toBeDefined();
    expect(r!.trusts('did:web:a')).toBe(true);
    expect(r!.trusts('did:web:b')).toBe(true);
    expect(r!.trusts('did:web:c')).toBe(false);
  });
});

describe('PartnerIssuerResolver.getKey', () => {
  let originalFetch: typeof global.fetch;

  beforeEach(() => {
    originalFetch = global.fetch;
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('throws AUTHENTICATION_FAILED for an untrusted DID', async () => {
    const r = new PartnerIssuerResolver({ trustedIssuerDids: [PARTNER_DID] });
    await expect(r.getKey('did:web:other')).rejects.toMatchObject({
      code: ErrorCode.AUTHENTICATION_FAILED,
      statusCode: 401,
    });
  });

  it('resolves and caches the partner key', async () => {
    const { didDoc } = await makePartnerKeys();
    const fetchMock = mockFetchForDid(didDoc);
    global.fetch = fetchMock;
    const r = new PartnerIssuerResolver({ trustedIssuerDids: [PARTNER_DID] });

    const r1 = await r.getKey(PARTNER_DID, `${PARTNER_DID}#key-1`);
    const r2 = await r.getKey(PARTNER_DID, `${PARTNER_DID}#key-1`);
    expect(r1.alg).toBe('EdDSA');
    expect(r2.key).toBe(r1.key);
    // Only resolved once thanks to the cache.
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('invalidate() drops the cached key so the next call re-resolves', async () => {
    const { didDoc } = await makePartnerKeys();
    const fetchMock = mockFetchForDid(didDoc);
    global.fetch = fetchMock;
    const r = new PartnerIssuerResolver({ trustedIssuerDids: [PARTNER_DID] });

    await r.getKey(PARTNER_DID);
    r.invalidate(PARTNER_DID);
    await r.getKey(PARTNER_DID);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});

describe('JWTTokenVerifier — cross-org partner verification', () => {
  // A throw-away local SPKI key so the verifier constructs successfully;
  // we never actually exercise the local-key path with this DID.
  let localPublicKeyPem: string;
  let originalFetch: typeof global.fetch;

  beforeAll(async () => {
    const { publicKey } = await jose.generateKeyPair('RS256', { extractable: true });
    localPublicKeyPem = await jose.exportSPKI(publicKey);
  });

  beforeEach(() => {
    originalFetch = global.fetch;
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('accepts a partner-signed token when the partner DID is trusted', async () => {
    const partner = await makePartnerKeys();
    global.fetch = mockFetchForDid(partner.didDoc);
    const resolver = new PartnerIssuerResolver({ trustedIssuerDids: [PARTNER_DID] });
    const verifier = new JWTTokenVerifier(localPublicKeyPem, { requireKid: false, algorithms: ['RS256'], partnerResolver: resolver });

    const token = await mintPartnerJWT(partner.privateKey, PARTNER_DID);
    const payload = await verifier.verify(token);
    expect(payload.iss).toBe(PARTNER_DID);
    expect(payload.sub).toBe('partner-agent');
  });

  it('rejects a partner-signed token when the partner DID is NOT in the trust list', async () => {
    const partner = await makePartnerKeys();
    global.fetch = mockFetchForDid(partner.didDoc);
    // Resolver trusts a different DID.
    const resolver = new PartnerIssuerResolver({ trustedIssuerDids: ['did:web:other'] });
    const verifier = new JWTTokenVerifier(localPublicKeyPem, { requireKid: false, algorithms: ['RS256'], partnerResolver: resolver });

    const token = await mintPartnerJWT(partner.privateKey, PARTNER_DID);
    // The token is EdDSA-signed but routes through the local-key path because
    // its issuer is not in the trust set.  The local path has alg=RS256 only,
    // so verification must fail with INVALID_TOKEN.
    await expect(verifier.verify(token)).rejects.toMatchObject({
      code: ErrorCode.INVALID_TOKEN,
    });
  });

  it('rejects a tampered partner-signed token (signature failure invalidates cache)', async () => {
    const partner = await makePartnerKeys();
    global.fetch = mockFetchForDid(partner.didDoc);
    const resolver = new PartnerIssuerResolver({ trustedIssuerDids: [PARTNER_DID] });
    const verifier = new JWTTokenVerifier(localPublicKeyPem, { requireKid: false, algorithms: ['RS256'], partnerResolver: resolver });

    const token = await mintPartnerJWT(partner.privateKey, PARTNER_DID);
    // Flip a byte in the signature segment.
    const parts = token.split('.');
    expect(parts).toHaveLength(3);
    const sig = Buffer.from(parts[2]!, 'base64url');
    sig[0] = sig[0]! ^ 0xff;
    parts[2] = sig.toString('base64url');
    const tampered = parts.join('.');

    await expect(verifier.verify(tampered)).rejects.toMatchObject({
      code: ErrorCode.INVALID_TOKEN,
    });
  });

  it('still verifies legacy single-issuer (local-key) tokens when partner resolver is configured', async () => {
    // Generate a local RS256 key and use it as both issuer and verifier key.
    const { publicKey, privateKey } = await jose.generateKeyPair('RS256', { extractable: true });
    const spki = await jose.exportSPKI(publicKey);
    const resolver = new PartnerIssuerResolver({ trustedIssuerDids: [PARTNER_DID] });
    const verifier = new JWTTokenVerifier(spki, { requireKid: false, algorithms: ['RS256'], partnerResolver: resolver });

    const now = Math.floor(Date.now() / 1000);
    const localToken = await new jose.SignJWT({
      iss: 'local-issuer',
      sub: 'agent-1',
      aud: 'tool-gateway',
      iat: now,
      exp: now + 600,
      jti: 'local-jti-1',
      schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
      capabilities: [{ resource: 'tool://x', actions: ['read'] }],
    })
      .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
      .sign(privateKey);

    const payload = await verifier.verify(localToken);
    expect(payload.iss).toBe('local-issuer');
  });

  it('with localIssuers allow-list, rejects local-signed tokens whose iss is unknown', async () => {
    const { publicKey, privateKey } = await jose.generateKeyPair('RS256', { extractable: true });
    const spki = await jose.exportSPKI(publicKey);
    const resolver = new PartnerIssuerResolver({ trustedIssuerDids: [PARTNER_DID] });
    const verifier = new JWTTokenVerifier(spki, { requireKid: false, algorithms: ['RS256'], partnerResolver: resolver, localIssuers: ['known-local-issuer'] });

    const now = Math.floor(Date.now() / 1000);
    const token = await new jose.SignJWT({
      iss: 'spoofed-issuer',
      sub: 'agent-1',
      aud: 'tool-gateway',
      iat: now,
      exp: now + 600,
      jti: 'spoof-jti',
      schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
      capabilities: [{ resource: 'tool://x', actions: ['read'] }],
    })
      .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
      .sign(privateKey);

    await expect(verifier.verify(token)).rejects.toMatchObject({
      code: ErrorCode.INVALID_TOKEN,
      statusCode: 401,
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// PartnerIssuerResolver — pin attestation verification
// ─────────────────────────────────────────────────────────────────────────────

describe('PartnerIssuerResolver — pin attestation verification', () => {
  const DID = 'did:web:partner.example.com';
  const SECRET = 'test-secret-32-bytes-padding!!';

  async function makeKeys(did = DID) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const publicJwk = publicKey.export({ format: 'jwk' }) as jose.JWK;
    publicJwk.alg = 'EdDSA';
    publicJwk.use = 'sig';
    const privateJose = await jose.importPKCS8(
      privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(), 'EdDSA',
    ) as jose.KeyLike;
    const vmId = `${did}#key-1`;
    const didDoc = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: did,
      verificationMethod: [{ id: vmId, type: 'JsonWebKey2020', controller: did, publicKeyJwk: publicJwk }],
      authentication: [vmId],
      assertionMethod: [vmId],
    };
    return { privateKey: privateJose, publicJwk, didDoc };
  }

  let originalFetch: typeof global.fetch;
  beforeEach(() => { originalFetch = global.fetch; });
  afterEach(() => { global.fetch = originalFetch; });

  it('accepts a resolution when attestation is valid', async () => {
    const { didDoc } = await makeKeys();
    global.fetch = jest.fn().mockResolvedValue({ ok: true, json: async () => didDoc } as unknown as Response);

    const reg = new InMemoryPartnerDidRegistry();
    const docHash = jcsSha256(didDoc);
    const activatedAt = Date.now();
    await reg.propose({ did: DID, proposer: 'alice', pinnedDocSha256: docHash });
    const att = createPinAttestation({ did: DID, pinnedDocSha256: docHash, approver: 'bob', activatedAt }, SECRET);
    await reg.approve(DID, 'bob', { pinnedDocSha256: docHash, pinAttestation: att });

    const resolver = new PartnerIssuerResolver({
      trustedIssuerDids: [DID],
      registry: reg,
      pinAttestationSecret: SECRET,
    });
    // Should not throw.
    const result = await resolver.getKey(DID, `${DID}#key-1`);
    expect(result.alg).toBe('EdDSA');
  });

  it('rejects with INVALID_TOKEN when attestation HMAC is tampered', async () => {
    const { didDoc } = await makeKeys();
    global.fetch = jest.fn().mockResolvedValue({ ok: true, json: async () => didDoc } as unknown as Response);

    const reg = new InMemoryPartnerDidRegistry();
    const docHash = jcsSha256(didDoc);
    const activatedAt = Date.now();
    await reg.propose({ did: DID, proposer: 'alice', pinnedDocSha256: docHash });
    const att = createPinAttestation({ did: DID, pinnedDocSha256: docHash, approver: 'bob', activatedAt }, SECRET);
    // Tamper the HMAC before storing.
    const tamperedAtt = { ...att, hmac: 'ff'.repeat(32) };
    await reg.approve(DID, 'bob', { pinnedDocSha256: docHash, pinAttestation: tamperedAtt });

    const resolver = new PartnerIssuerResolver({
      trustedIssuerDids: [DID],
      registry: reg,
      pinAttestationSecret: SECRET,
    });
    await expect(resolver.getKey(DID, `${DID}#key-1`)).rejects.toMatchObject({
      code: ErrorCode.INVALID_TOKEN,
    });
  });

  it('rejects when attestation DID field does not match entry DID', async () => {
    const { didDoc } = await makeKeys();
    global.fetch = jest.fn().mockResolvedValue({ ok: true, json: async () => didDoc } as unknown as Response);

    const reg = new InMemoryPartnerDidRegistry();
    const docHash = jcsSha256(didDoc);
    const activatedAt = Date.now();
    await reg.propose({ did: DID, proposer: 'alice', pinnedDocSha256: docHash });
    // Attestation signed for a different DID.
    const att = createPinAttestation({
      did: 'did:web:evil.example.com',
      pinnedDocSha256: docHash,
      approver: 'bob',
      activatedAt,
    }, SECRET);
    await reg.approve(DID, 'bob', { pinnedDocSha256: docHash, pinAttestation: att });

    const resolver = new PartnerIssuerResolver({
      trustedIssuerDids: [DID],
      registry: reg,
      pinAttestationSecret: SECRET,
    });
    await expect(resolver.getKey(DID, `${DID}#key-1`)).rejects.toMatchObject({
      code: ErrorCode.INVALID_TOKEN,
    });
  });

  it('warns but succeeds (hash-only) when secret is set but no attestation exists (legacy entry)', async () => {
    const { didDoc } = await makeKeys();
    global.fetch = jest.fn().mockResolvedValue({ ok: true, json: async () => didDoc } as unknown as Response);

    const reg = new InMemoryPartnerDidRegistry();
    const docHash = jcsSha256(didDoc);
    // Approve without attestation (legacy path).
    await reg.propose({ did: DID, proposer: 'alice', pinnedDocSha256: docHash });
    await reg.approve(DID, 'bob');

    const resolver = new PartnerIssuerResolver({
      trustedIssuerDids: [DID],
      registry: reg,
      pinAttestationSecret: SECRET,
    });
    // Should succeed with hash-only verification (warning is logged, not thrown).
    const result = await resolver.getKey(DID, `${DID}#key-1`);
    expect(result.alg).toBe('EdDSA');
  });
});
