/**
 * Tests for JwksClient (R-6) — caching, forced refresh, fail-closed.
 *
 * Covers:
 *  - Cache hit: no HTTP fetch within TTL
 *  - Cache miss: fetches on first call
 *  - Stale-while-revalidate: returns cached value when stale
 *  - getKeyByKid: forced refresh on kid miss
 *  - Fail-closed: throws when no cache and fetch fails
 *  - Fail-soft: keeps stale cache when refresh fails (logs warning)
 *
 * All HTTP calls are mocked via jest.mock('axios').
 */

import axios from 'axios';
import { JwksClient } from '../src/jwks-client';
import { JwkSet } from '@euno/common';

jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

const JWKS_URL = 'http://issuer.test/.well-known/jwks.json';

const KEY1: JwkSet['keys'][number] = {
  kty: 'RSA',
  kid: 'key-1',
  use: 'sig',
  alg: 'RS256',
  n: 'mod1',
  e: 'AQAB',
};

const KEY2: JwkSet['keys'][number] = {
  kty: 'RSA',
  kid: 'key-2',
  use: 'sig',
  alg: 'RS256',
  n: 'mod2',
  e: 'AQAB',
};

function makeJwks(keys: JwkSet['keys']): JwkSet {
  return { keys };
}

describe('JwksClient (R-6)', () => {
  let client: JwksClient;
  const warnSpy = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
    client = new JwksClient({
      jwksUrl: JWKS_URL,
      cacheTtlMs: 5_000, // 5 s for tests
      logger: { warn: warnSpy },
    });
  });

  // ── Cache behaviour ─────────────────────────────────────────────────────

  it('fetches JWKS on first call and caches the result', async () => {
    mockedAxios.get.mockResolvedValueOnce({ data: makeJwks([KEY1]) });

    const jwks = await client.getJwks();

    expect(mockedAxios.get).toHaveBeenCalledTimes(1);
    expect(mockedAxios.get).toHaveBeenCalledWith(JWKS_URL, expect.any(Object));
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]!.kid).toBe('key-1');
  });

  it('does NOT re-fetch within the cache TTL (cache hit)', async () => {
    mockedAxios.get.mockResolvedValue({ data: makeJwks([KEY1]) });

    await client.getJwks(); // first fetch
    const jwks = await client.getJwks(); // cache hit

    expect(mockedAxios.get).toHaveBeenCalledTimes(1); // still only one fetch
    expect(jwks.keys[0]!.kid).toBe('key-1');
  });

  it('re-fetches after the TTL expires (stale-while-revalidate returns stale immediately)', async () => {
    // Short TTL client — 50 ms is short enough to expire quickly but long enough
    // that the refreshed cache stays valid for the final assertion.
    const shortTtlClient = new JwksClient({
      jwksUrl: JWKS_URL,
      cacheTtlMs: 50,
      logger: { warn: warnSpy },
    });

    mockedAxios.get
      .mockResolvedValueOnce({ data: makeJwks([KEY1]) }) // first fetch
      .mockResolvedValueOnce({ data: makeJwks([KEY2]) }); // second fetch

    // First call — populates cache
    const first = await shortTtlClient.getJwks();
    expect(first.keys[0]!.kid).toBe('key-1');

    // Wait for TTL to expire
    await new Promise((r) => setTimeout(r, 60));

    // Second call — cache is stale; stale-while-revalidate returns stale immediately
    // and schedules background refresh
    const second = await shortTtlClient.getJwks();
    expect(second.keys[0]!.kid).toBe('key-1'); // still returns stale value

    // Allow the background refresh to resolve (flush macrotasks)
    await new Promise((r) => setTimeout(r, 20));

    // Third call — fresh cache (the refreshed cache TTL of 50ms has not expired yet)
    const third = await shortTtlClient.getJwks();
    expect(third.keys[0]!.kid).toBe('key-2');

    expect(mockedAxios.get).toHaveBeenCalledTimes(2);
  });

  // ── getKeyByKid ─────────────────────────────────────────────────────────

  it('getKeyByKid returns the matching key when in cache', async () => {
    mockedAxios.get.mockResolvedValueOnce({ data: makeJwks([KEY1, KEY2]) });

    const key = await client.getKeyByKid('key-2');

    expect(key.kid).toBe('key-2');
    expect(mockedAxios.get).toHaveBeenCalledTimes(1);
  });

  it('getKeyByKid does a forced refresh when kid is not in cache', async () => {
    // Initial fetch returns only key-1
    mockedAxios.get
      .mockResolvedValueOnce({ data: makeJwks([KEY1]) })
      // Forced refresh returns key-1 + key-2
      .mockResolvedValueOnce({ data: makeJwks([KEY1, KEY2]) });

    // Prime the cache
    await client.getJwks();

    // Now ask for key-2 — should trigger forced refresh
    const key = await client.getKeyByKid('key-2');

    expect(key.kid).toBe('key-2');
    expect(mockedAxios.get).toHaveBeenCalledTimes(2); // initial + forced refresh
  });

  it('getKeyByKid throws (fail-closed) when kid is not found even after forced refresh', async () => {
    mockedAxios.get
      .mockResolvedValueOnce({ data: makeJwks([KEY1]) }) // initial
      .mockResolvedValueOnce({ data: makeJwks([KEY1]) }); // forced refresh — still no key-2

    await client.getJwks(); // prime cache

    await expect(client.getKeyByKid('key-2')).rejects.toMatchObject({
      code: 'INVALID_TOKEN',
    });
  });

  // ── Fail-closed ─────────────────────────────────────────────────────────

  it('throws (fail-closed) when the initial fetch fails with no cached value', async () => {
    mockedAxios.get.mockRejectedValueOnce(new Error('Network error'));

    await expect(client.getJwks()).rejects.toMatchObject({
      code: 'INTERNAL_ERROR',
    });
  });

  // ── Fail-soft (stale cache preserved on refresh failure) ────────────────

  it('keeps serving stale cached keys when a refresh fails and logs a warning', async () => {
    const shortTtlClient = new JwksClient({
      jwksUrl: JWKS_URL,
      cacheTtlMs: 50,
      logger: { warn: warnSpy },
    });

    mockedAxios.get
      .mockResolvedValueOnce({ data: makeJwks([KEY1]) }) // initial
      .mockRejectedValueOnce(new Error('Refresh failed')); // stale-while-revalidate refresh fails

    // Populate cache
    await shortTtlClient.getJwks();

    // Expire cache
    await new Promise((r) => setTimeout(r, 60));

    // Should still return stale keys (background refresh will fail)
    const stale = await shortTtlClient.getJwks();
    expect(stale.keys[0]!.kid).toBe('key-1');

    // Let background refresh run (and fail)
    await new Promise((r) => setTimeout(r, 20));

    // Warning should have been logged
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('JWKS refresh failed'),
      expect.any(Object),
    );
  });

  // ── Input validation ─────────────────────────────────────────────────────

  it('throws when the JWKS response does not have a keys array', async () => {
    mockedAxios.get.mockResolvedValueOnce({ data: { notKeys: [] } });

    await expect(client.getJwks()).rejects.toThrow();
  });
});

// ── JwksTokenVerifier ─────────────────────────────────────────────────────

import * as jose from 'jose';
import { JwksTokenVerifier, JWTTokenVerifier as BaseJWTTokenVerifier } from '../src/verifier';
import { JwkSet as JwkSetType, CAPABILITY_TOKEN_SCHEMA_VERSION } from '@euno/common';

describe('JwksTokenVerifier (R-6)', () => {
  const SIGNING_ALG = 'RS256';
  let privateKey: jose.KeyLike;
  let publicKey: jose.KeyLike;
  let publicKeyJwk: jose.JWK;
  let jwksClient: JwksClient;
  const KID = 'test-kid-42';

  beforeEach(async () => {
    jest.clearAllMocks();
    const pair = await jose.generateKeyPair(SIGNING_ALG, { extractable: true });
    privateKey = pair.privateKey;
    publicKey = pair.publicKey;
    publicKeyJwk = await jose.exportJWK(publicKey);

    const jwks: JwkSetType = {
      keys: [{ ...publicKeyJwk, kid: KID, use: 'sig', alg: SIGNING_ALG, kty: publicKeyJwk.kty! }],
    };
    mockedAxios.get.mockResolvedValue({ data: jwks });

    jwksClient = new JwksClient({ jwksUrl: JWKS_URL, cacheTtlMs: 60_000 });
    // Pre-warm cache
    await jwksClient.getJwks();
  });

  async function mintToken(kid?: string): Promise<string> {
    const jwtBuilder = new jose.SignJWT({
      sub: 'agent-1',
      iss: 'did:web:test.example.com',
      aud: 'euno-gateway',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 300,
      jti: 'test-jti-1',
      schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
      capabilities: [{ resource: 'api://service', actions: ['read'] }],
    }).setProtectedHeader({ alg: SIGNING_ALG, ...(kid ? { kid } : {}) });
    return jwtBuilder.sign(privateKey);
  }

  it('verifies a token using JWKS key selection by kid', async () => {
    const token = await mintToken(KID);
    const verifier = new JwksTokenVerifier(jwksClient);

    const payload = await verifier.verify(token);

    expect(payload.sub).toBe('agent-1');
  });

  it('inherits revokeToken and isRevoked from JWTTokenVerifier', async () => {
    const token = await mintToken(KID);
    const verifier = new JwksTokenVerifier(jwksClient);

    // Verify successfully first
    await verifier.verify(token);

    // Revoke by jti
    await verifier.revokeToken('test-jti-1');

    // Should now be rejected as revoked
    await expect(verifier.verify(token)).rejects.toMatchObject({
      code: 'TOKEN_REVOKED',
    });
  });

  it('rejects a token whose kid is not in the JWKS (fail-closed)', async () => {
    // After the miss, a forced refresh is done — but the kid is still absent
    mockedAxios.get.mockResolvedValue({
      data: { keys: [{ ...publicKeyJwk, kid: KID, use: 'sig', alg: SIGNING_ALG, kty: publicKeyJwk.kty! }] },
    });

    const token = await mintToken('unknown-kid');
    const verifier = new JwksTokenVerifier(jwksClient);

    await expect(verifier.verify(token)).rejects.toMatchObject({
      code: 'INVALID_TOKEN',
    });
  });

  it('rejects a token with no kid when requireKid=true (default)', async () => {
    const token = await mintToken(undefined); // no kid in header
    const verifier = new JwksTokenVerifier(jwksClient); // requireKid defaults to true

    await expect(verifier.verify(token)).rejects.toMatchObject({
      code: 'INVALID_TOKEN',
    });
  });

  it('verifies a token with no kid when requireKid=false (tries all JWKS keys)', async () => {
    const token = await mintToken(undefined); // no kid in header
    const verifier = new JwksTokenVerifier(jwksClient, { requireKid: false });

    const payload = await verifier.verify(token);
    expect(payload.sub).toBe('agent-1');
  });

  it('falls back to SPKI path when kid is absent and requireKid=false (base class only)', async () => {
    // Confirm backward compat: base class with SPKI still works without kid
    const spki = await jose.exportSPKI(publicKey);
    const token = await mintToken(undefined); // no kid
    const baseVerifier = new BaseJWTTokenVerifier(spki, [SIGNING_ALG]);

    const payload = await baseVerifier.verify(token);
    expect(payload.sub).toBe('agent-1');
  });
});
