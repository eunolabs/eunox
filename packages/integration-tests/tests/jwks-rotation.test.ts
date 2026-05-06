/**
 * Integration test: JWKS key-rotation scenario (R-6).
 *
 * Proves that the gateway can verify tokens from a freshly-rotated
 * key WITHOUT a restart, satisfying the core requirement:
 *
 *   "No synchronised restart required for rotation."
 *
 * Test outline
 * ─────────────
 * 1. Issuer publishes JWKS with key-1.  Gateway caches it.
 * 2. Issuer adds key-2 to JWKS (rotation in progress).
 * 3. Issuer switches signing to key-2.
 * 4. Gateway receives a token signed with key-2.
 *    - kid=key-2 is not in the cache → forced refresh
 *    - Gateway fetches updated JWKS ([key-1, key-2]) and verifies.
 * 5. Issuer eventually removes key-1 (cleanup).
 * 6. Gateway fetches JWKS with only key-2.
 * 7. Tokens signed with key-1 are now rejected (old key gone).
 *
 * The HTTP layer is fully mocked — no live servers required.
 */

import * as jose from 'jose';
import axios from 'axios';
import { JwksClient } from '../../tool-gateway/src/jwks-client';
import { JWTTokenVerifier } from '../../tool-gateway/src/verifier';
import {
  CAPABILITY_TOKEN_SCHEMA_VERSION,
  JwkSet,
  JwkKey,
} from '@euno/common';

jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

const JWKS_URL = 'http://issuer.local/.well-known/jwks.json';
const SIGNING_ALG = 'RS256' as const;

// ── Key-pair helpers ────────────────────────────────────────────────────────

interface KeyPair {
  kid: string;
  privateKey: jose.KeyLike;
  jwk: JwkKey;
}

async function generateKeyPair(kid: string): Promise<KeyPair> {
  const { privateKey, publicKey } = await jose.generateKeyPair(SIGNING_ALG, { extractable: true });
  const exported = await jose.exportJWK(publicKey);
  return {
    kid,
    privateKey,
    jwk: { ...exported, kid, use: 'sig', alg: SIGNING_ALG, kty: exported.kty! },
  };
}

async function mintToken(pair: KeyPair): Promise<string> {
  return new jose.SignJWT({
    sub: 'test-agent',
    iss: 'did:web:rotation.test',
    aud: 'euno-gateway',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 300,
    jti: `jti-${Math.random()}`,
    schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
    capabilities: [{ resource: 'api://svc', actions: ['read'] }],
  })
    .setProtectedHeader({ alg: SIGNING_ALG, kid: pair.kid })
    .sign(pair.privateKey);
}

function makeJwksResponse(keys: JwkKey[]): { data: JwkSet } {
  return { data: { keys } };
}

// ── Test ────────────────────────────────────────────────────────────────────

describe('JWKS key-rotation — end-to-end (R-6)', () => {
  let key1: KeyPair;
  let key2: KeyPair;
  let client: JwksClient;
  let verifier: JWTTokenVerifier;

  beforeEach(async () => {
    jest.clearAllMocks();
    key1 = await generateKeyPair('key-1');
    key2 = await generateKeyPair('key-2');

    client = new JwksClient({ jwksUrl: JWKS_URL, cacheTtlMs: 60_000 });
    verifier = new JWTTokenVerifier('', {
      // no SPKI — JWKS path
      requireKid: false, // false so we can test without kid as well
      algorithms: [SIGNING_ALG],
      jwksKeySource: client,
    });
  });

  it('Step 1 → 3: gateway verifies token signed with key-1 (single-key JWKS)', async () => {
    // Issuer publishes [key-1]
    mockedAxios.get.mockResolvedValue(makeJwksResponse([key1.jwk]));

    // Pre-warm cache
    await client.getJwks();

    const token = await mintToken(key1);
    const payload = await verifier.verify(token);

    expect(payload.sub).toBe('test-agent');
    expect(mockedAxios.get).toHaveBeenCalledTimes(1);
  });

  it('Step 4: gateway performs a forced refresh when it encounters kid=key-2', async () => {
    // Initial state: issuer only has key-1
    mockedAxios.get
      .mockResolvedValueOnce(makeJwksResponse([key1.jwk]))
      // After rotation: issuer has both key-1 and key-2
      .mockResolvedValueOnce(makeJwksResponse([key1.jwk, key2.jwk]));

    // Gateway boots with key-1 in cache
    await client.getJwks();
    expect(mockedAxios.get).toHaveBeenCalledTimes(1);

    // Issuer rotates: now signs with key-2.  The gateway cache still only has key-1.
    const tokenSignedWithKey2 = await mintToken(key2);

    // Gateway verifies: kid=key-2 not in cache → forced refresh → finds key-2
    const payload = await verifier.verify(tokenSignedWithKey2);

    expect(payload.sub).toBe('test-agent');
    // Exactly two HTTP calls: initial boot + forced refresh
    expect(mockedAxios.get).toHaveBeenCalledTimes(2);
  });

  it('Step 4 (no restart): gateway verifies key-2 token without restart', async () => {
    // Simulate already-running gateway that has only cached key-1
    mockedAxios.get
      .mockResolvedValueOnce(makeJwksResponse([key1.jwk]))
      .mockResolvedValueOnce(makeJwksResponse([key1.jwk, key2.jwk]));

    await client.getJwks();

    // Old tokens signed with key-1 still work
    const oldToken = await mintToken(key1);
    await expect(verifier.verify(oldToken)).resolves.toMatchObject({ sub: 'test-agent' });

    // New token signed with key-2 — gateway must refresh and succeed
    const newToken = await mintToken(key2);
    await expect(verifier.verify(newToken)).resolves.toMatchObject({ sub: 'test-agent' });
  });

  it('Step 7: token signed with removed key-1 is rejected after cache expires (fail-closed)', async () => {
    // Short TTL so we can simulate expiry in the test
    const shortTtlClient = new JwksClient({ jwksUrl: JWKS_URL, cacheTtlMs: 1 });
    const shortTtlVerifier = new JWTTokenVerifier('', {
      requireKid: false,
      algorithms: [SIGNING_ALG],
      jwksKeySource: shortTtlClient,
    });

    // Stage 1: Issuer publishes [key-1, key-2], gateway boots
    mockedAxios.get
      .mockResolvedValueOnce(makeJwksResponse([key1.jwk, key2.jwk]))
      // Stage 2: key-1 removed — any subsequent fetch returns only key-2
      .mockResolvedValue(makeJwksResponse([key2.jwk]));

    await shortTtlClient.getJwks();

    // Expire the cache
    await new Promise((r) => setTimeout(r, 5));

    // Token signed with old key-1 — cache has expired, refresh returns [key-2] only
    // kid=key-1 is in the stale cache but after forced refresh it's gone
    const oldToken = await mintToken(key1);

    // getKeyByKid('key-1'):
    //  - getJwks() returns stale [key1, key2] immediately (stale-while-revalidate)
    //  - picks key-1 from stale — BUT the stale key has the real key-1 JWK
    //  - so it actually verifies! This is the expected behavior during the TTL window.
    //
    // To truly reject key-1, we need it to NOT be in the cache at all.
    // We achieve this by forcing a manual refresh first.
    await shortTtlClient.getJwks(); // trigger background refresh via stale-while-revalidate

    // Wait for background refresh to complete (now cache has [key-2] only)
    await new Promise((r) => setTimeout(r, 20));

    // Now the cache only has key-2.  A token with kid=key-1:
    //  - getKeyByKid('key-1') → not in cache → forced refresh → still not there → reject
    await expect(shortTtlVerifier.verify(oldToken)).rejects.toMatchObject({
      code: 'INVALID_TOKEN',
    });
  });

  it('gateway rejects token with kid not in JWKS even after forced refresh (fail-closed)', async () => {
    const phantom = await generateKeyPair('phantom-key');

    // Both initial fetch and forced-refresh only return key-1
    mockedAxios.get
      .mockResolvedValueOnce(makeJwksResponse([key1.jwk]))
      .mockResolvedValueOnce(makeJwksResponse([key1.jwk]));

    await client.getJwks();

    const token = await mintToken(phantom);

    await expect(verifier.verify(token)).rejects.toMatchObject({
      code: 'INVALID_TOKEN',
    });
    // Exactly two fetches: initial + forced refresh
    expect(mockedAxios.get).toHaveBeenCalledTimes(2);
  });
});
