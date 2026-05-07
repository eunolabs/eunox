/**
 * Tests for the DPoP (RFC 9449) verifier and proof builder used by
 * F-2 (`docs/IMPROVEMENTS_AND_REFACTORING.md`).
 *
 * Covers the happy path plus every documented failure mode of
 * `verifyDpopProof` so that the gateway's deny-by-default semantics
 * stay intact across refactors.
 */

import * as jose from 'jose';
import {
  computeJwkThumbprint,
  createDpopProof,
  DPOP_SUPPORTED_ALGORITHMS,
  extractHtu,
  InMemoryDpopReplayStore,
  jwkToJkt,
  verifyDpopProof,
} from '../src/dpop';
import { CapabilityError, ErrorCode } from '../src/utils';

interface KeyPairFixture {
  privateKey: jose.KeyLike;
  publicJwk: jose.JWK;
  jkt: string;
}

async function generateP256Fixture(): Promise<KeyPairFixture> {
  const { privateKey, publicKey } = await jose.generateKeyPair('ES256', {
    extractable: true,
  });
  const publicJwk = await jose.exportJWK(publicKey);
  const jkt = await computeJwkThumbprint(publicJwk);
  return { privateKey: privateKey as jose.KeyLike, publicJwk, jkt };
}

describe('extractHtu', () => {
  it('strips query and fragment', () => {
    expect(extractHtu('https://gw.example.com/proxy/api?x=1&y=2#frag')).toBe(
      'https://gw.example.com/proxy/api',
    );
  });

  it('lower-cases scheme and host', () => {
    expect(extractHtu('HTTPS://Example.COM/Path')).toBe('https://example.com/Path');
  });

  it('preserves explicit non-default port', () => {
    expect(extractHtu('http://api.example.com:8080/x')).toBe('http://api.example.com:8080/x');
  });
});

describe('computeJwkThumbprint / jwkToJkt', () => {
  it('produces a stable RFC 7638 thumbprint', async () => {
    const fixture = await generateP256Fixture();
    const recomputed = await jwkToJkt(fixture.publicJwk as unknown as Record<string, unknown>);
    expect(recomputed).toBe(fixture.jkt);
    // Thumbprints are base64url and 43 chars long for SHA-256.
    expect(fixture.jkt).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('produces different thumbprints for different keys', async () => {
    const a = await generateP256Fixture();
    const b = await generateP256Fixture();
    expect(a.jkt).not.toBe(b.jkt);
  });
});

describe('InMemoryDpopReplayStore', () => {
  it('accepts a fresh jti and rejects a replay within TTL', async () => {
    const store = new InMemoryDpopReplayStore();
    const exp = Math.floor(Date.now() / 1000) + 300;
    expect(await store.checkAndRemember('jti-1', exp)).toBe(true);
    expect(await store.checkAndRemember('jti-1', exp)).toBe(false);
  });

  it('treats an expired entry as novel', async () => {
    const store = new InMemoryDpopReplayStore();
    const past = Math.floor(Date.now() / 1000) - 10;
    expect(await store.checkAndRemember('jti-2', past)).toBe(true);
    // Past-TTL entry should be treated as gone on the next lookup.
    expect(await store.checkAndRemember('jti-2', Math.floor(Date.now() / 1000) + 60)).toBe(true);
  });

  it('caps memory growth at maxEntries', async () => {
    const store = new InMemoryDpopReplayStore({ maxEntries: 1024 });
    const exp = Math.floor(Date.now() / 1000) + 600;
    for (let i = 0; i < 1500; i += 1) {
      await store.checkAndRemember(`jti-${i}`, exp);
    }
    expect(store.size()).toBeLessThanOrEqual(1024);
  });

  it('JTI reuse is accepted after the original entry expires (lazy-deletion path)', async () => {
    const store = new InMemoryDpopReplayStore();
    const past = Math.floor(Date.now() / 1000) - 10;
    // First admit: the entry is stored but immediately in the past.
    expect(await store.checkAndRemember('jti-reuse', past)).toBe(true);
    // The map entry is stale. checkAndRemember should treat the JTI as novel
    // and the stale heap node must be silently skipped via lazy deletion.
    const future = Math.floor(Date.now() / 1000) + 300;
    expect(await store.checkAndRemember('jti-reuse', future)).toBe(true);
    // Now it is live — a genuine replay must be rejected.
    expect(await store.checkAndRemember('jti-reuse', future)).toBe(false);
    expect(store.size()).toBe(1);
  });

  it('heap rebuild after FIFO eviction keeps the store consistent', async () => {
    // Use a tiny cap to exercise the FIFO-eviction + rebuild path cheaply.
    const max = 1024;
    const store = new InMemoryDpopReplayStore({ maxEntries: max });
    const future = Math.floor(Date.now() / 1000) + 600;
    // Fill to capacity with live entries.
    for (let i = 0; i < max; i++) {
      await store.checkAndRemember(`live-${i}`, future);
    }
    expect(store.size()).toBe(max);
    // Exceed capacity: FIFO eviction + heap rebuild fires.
    for (let i = 0; i < Math.ceil(max * 0.1) + 5; i++) {
      await store.checkAndRemember(`overflow-${i}`, future);
    }
    // Map size must be ≤ max after FIFO eviction kicks in.
    expect(store.size()).toBeLessThanOrEqual(max);
    // Evicted JTIs (live-0 … live-N) must be re-admissible as novel.
    expect(await store.checkAndRemember('live-0', future)).toBe(true);
    // A non-evicted recent entry must still be rejected as a replay.
    expect(await store.checkAndRemember(`overflow-0`, future)).toBe(false);
  });
});

describe('verifyDpopProof', () => {
  let fixture: KeyPairFixture;
  let store: InMemoryDpopReplayStore;

  beforeAll(async () => {
    fixture = await generateP256Fixture();
  });

  beforeEach(() => {
    store = new InMemoryDpopReplayStore();
  });

  function baseProof(overrides: Partial<Parameters<typeof createDpopProof>[0]> = {}) {
    return createDpopProof({
      privateKey: fixture.privateKey,
      publicJwk: fixture.publicJwk,
      algorithm: 'ES256',
      httpMethod: 'POST',
      httpUrl: 'https://gw.example.com/proxy/api/v1/x',
      ...overrides,
    });
  }

  it('accepts a valid proof and returns the thumbprint', async () => {
    const proof = await baseProof();
    const result = await verifyDpopProof({
      proof,
      httpMethod: 'POST',
      httpUrl: 'https://gw.example.com/proxy/api/v1/x?ignored=1',
      replayStore: store,
      expectedJkt: fixture.jkt,
    });
    expect(result.jkt).toBe(fixture.jkt);
    expect(result.claims.htm).toBe('POST');
    expect(result.header.alg).toBe('ES256');
  });

  it('rejects a proof signed with the wrong key (thumbprint mismatch)', async () => {
    const other = await generateP256Fixture();
    const proof = await createDpopProof({
      privateKey: other.privateKey,
      publicJwk: other.publicJwk,
      algorithm: 'ES256',
      httpMethod: 'POST',
      httpUrl: 'https://gw.example.com/proxy/api/v1/x',
    });
    await expect(
      verifyDpopProof({
        proof,
        httpMethod: 'POST',
        httpUrl: 'https://gw.example.com/proxy/api/v1/x',
        replayStore: store,
        expectedJkt: fixture.jkt,
      }),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_TOKEN });
  });

  it('rejects an htm mismatch', async () => {
    const proof = await baseProof();
    await expect(
      verifyDpopProof({
        proof,
        httpMethod: 'GET', // wrong method
        httpUrl: 'https://gw.example.com/proxy/api/v1/x',
        replayStore: store,
        expectedJkt: fixture.jkt,
      }),
    ).rejects.toThrow(/htm mismatch/);
  });

  it('rejects an htu mismatch', async () => {
    const proof = await baseProof();
    await expect(
      verifyDpopProof({
        proof,
        httpMethod: 'POST',
        httpUrl: 'https://gw.example.com/proxy/api/v1/y', // wrong path
        replayStore: store,
        expectedJkt: fixture.jkt,
      }),
    ).rejects.toThrow(/htu mismatch/);
  });

  it('rejects a proof older than maxAgeSeconds', async () => {
    const past = Math.floor(Date.now() / 1000) - 600;
    const proof = await baseProof({ iat: past });
    await expect(
      verifyDpopProof({
        proof,
        httpMethod: 'POST',
        httpUrl: 'https://gw.example.com/proxy/api/v1/x',
        replayStore: store,
        expectedJkt: fixture.jkt,
        maxAgeSeconds: 300,
      }),
    ).rejects.toThrow(/too old/);
  });

  it('rejects a proof with iat in the future beyond skew', async () => {
    const future = Math.floor(Date.now() / 1000) + 3600;
    const proof = await baseProof({ iat: future });
    await expect(
      verifyDpopProof({
        proof,
        httpMethod: 'POST',
        httpUrl: 'https://gw.example.com/proxy/api/v1/x',
        replayStore: store,
        expectedJkt: fixture.jkt,
      }),
    ).rejects.toThrow(/in the future/);
  });

  it('rejects a replayed proof', async () => {
    const proof = await baseProof({ jti: 'replay-test' });
    await verifyDpopProof({
      proof,
      httpMethod: 'POST',
      httpUrl: 'https://gw.example.com/proxy/api/v1/x',
      replayStore: store,
      expectedJkt: fixture.jkt,
    });
    await expect(
      verifyDpopProof({
        proof,
        httpMethod: 'POST',
        httpUrl: 'https://gw.example.com/proxy/api/v1/x',
        replayStore: store,
        expectedJkt: fixture.jkt,
      }),
    ).rejects.toThrow(/already been used/);
  });

  it('rejects a proof with no DPoP typ', async () => {
    // Hand-craft a JWT with the wrong typ.
    const proof = await new jose.SignJWT({
      htm: 'POST',
      htu: 'https://gw.example.com/proxy/api/v1/x',
      jti: 'wrong-typ',
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'JWT', jwk: fixture.publicJwk })
      .setIssuedAt()
      .sign(fixture.privateKey);
    await expect(
      verifyDpopProof({
        proof,
        httpMethod: 'POST',
        httpUrl: 'https://gw.example.com/proxy/api/v1/x',
        replayStore: store,
        expectedJkt: fixture.jkt,
      }),
    ).rejects.toThrow(/wrong typ/);
  });

  it('rejects a symmetric algorithm even when present in allow-list', async () => {
    // Build a proof signed by an HS256 key — it should be rejected
    // before the allow-list lookup.
    const secret = new TextEncoder().encode('not-a-real-secret-just-for-test');
    const proof = await new jose.SignJWT({
      htm: 'POST',
      htu: 'https://gw.example.com/proxy/api/v1/x',
      jti: 'sym-1',
    })
      .setProtectedHeader({ alg: 'HS256', typ: 'dpop+jwt', jwk: fixture.publicJwk })
      .setIssuedAt()
      .sign(secret);
    await expect(
      verifyDpopProof({
        proof,
        httpMethod: 'POST',
        httpUrl: 'https://gw.example.com/proxy/api/v1/x',
        replayStore: store,
        expectedJkt: fixture.jkt,
        // Even if a buggy operator passes HS256 here, we still reject.
        allowedAlgorithms: ['HS256', ...DPOP_SUPPORTED_ALGORITHMS],
      }),
    ).rejects.toThrow(/symmetric algorithm/);
  });

  it('rejects a malformed proof', async () => {
    await expect(
      verifyDpopProof({
        proof: 'not.a.jwt',
        httpMethod: 'POST',
        httpUrl: 'https://gw.example.com/proxy/api/v1/x',
        replayStore: store,
      }),
    ).rejects.toBeInstanceOf(CapabilityError);
  });

  it('rejects a missing proof', async () => {
    await expect(
      verifyDpopProof({
        proof: '',
        httpMethod: 'POST',
        httpUrl: 'https://gw.example.com/proxy/api/v1/x',
        replayStore: store,
      }),
    ).rejects.toThrow(/required/);
  });
});

describe('RedisDpopReplayStore', () => {
  // Mirrors the `RedisCallCounterClient` testing pattern: stub the
  // tiny `ioredis` surface the store depends on so we can verify
  // the `SET ... NX EX` semantics without a real Redis server.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { RedisDpopReplayStore } = require('../src/dpop');

  function makeFakeClient(): {
    set: jest.Mock;
    quit: jest.Mock;
    on: jest.Mock;
  } {
    return {
      set: jest.fn(),
      quit: jest.fn().mockResolvedValue('OK'),
      on: jest.fn(),
    };
  }

  it('returns true for a novel jti (SET NX returned OK)', async () => {
    const client = makeFakeClient();
    client.set.mockResolvedValue('OK');
    const store = new RedisDpopReplayStore(client);
    const ok = await store.checkAndRemember('jti-1', Math.floor(Date.now() / 1000) + 60);
    expect(ok).toBe(true);
    expect(client.set).toHaveBeenCalledWith('dpopjti:jti-1', '1', 'EX', expect.any(Number), 'NX');
  });

  it('returns false for a replay (SET NX returned null)', async () => {
    const client = makeFakeClient();
    client.set.mockResolvedValue(null);
    const store = new RedisDpopReplayStore(client);
    expect(
      await store.checkAndRemember('jti-2', Math.floor(Date.now() / 1000) + 60),
    ).toBe(false);
  });

  it('uses at least 1s TTL even when the proof has already expired', async () => {
    const client = makeFakeClient();
    client.set.mockResolvedValue('OK');
    const store = new RedisDpopReplayStore(client);
    await store.checkAndRemember('jti-3', Math.floor(Date.now() / 1000) - 10);
    const ttl = client.set.mock.calls[0]![3];
    expect(ttl).toBeGreaterThanOrEqual(1);
  });

  it('honours a custom keyPrefix', async () => {
    const client = makeFakeClient();
    client.set.mockResolvedValue('OK');
    const store = new RedisDpopReplayStore(client, { keyPrefix: 'custom:' });
    await store.checkAndRemember('jti-4', Math.floor(Date.now() / 1000) + 60);
    expect(client.set).toHaveBeenCalledWith('custom:jti-4', '1', 'EX', expect.any(Number), 'NX');
  });

  it('fails closed by default on Redis errors (returns false → request denied)', async () => {
    const client = makeFakeClient();
    client.set.mockRejectedValue(new Error('redis down'));
    const store = new RedisDpopReplayStore(client);
    expect(
      await store.checkAndRemember('jti-5', Math.floor(Date.now() / 1000) + 60),
    ).toBe(false);
  });

  it('fails open when failClosedOnError=false (returns true → request allowed)', async () => {
    const client = makeFakeClient();
    client.set.mockRejectedValue(new Error('redis down'));
    const store = new RedisDpopReplayStore(client, { failClosedOnError: false });
    expect(
      await store.checkAndRemember('jti-6', Math.floor(Date.now() / 1000) + 60),
    ).toBe(true);
  });

  it('close() releases the underlying client', async () => {
    const client = makeFakeClient();
    const store = new RedisDpopReplayStore(client);
    await store.close();
    expect(client.quit).toHaveBeenCalledTimes(1);
  });
});

describe('createDpopReplayStoreFromEnv', () => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { createDpopReplayStoreFromEnv, InMemoryDpopReplayStore } = require('../src/dpop');

  it('returns an in-memory store when REDIS_URL is unset', async () => {
    const s = await createDpopReplayStoreFromEnv({});
    expect(s).toBeInstanceOf(InMemoryDpopReplayStore);
  });

  it('throws when ioredis is missing and NODE_ENV=production', async () => {
    jest.resetModules();
    try {
      jest.doMock('ioredis', () => { throw new Error("Cannot find module 'ioredis'"); }, { virtual: true });

      await jest.isolateModulesAsync(async () => {
        const { createDpopReplayStoreFromEnv: factory } = require('../src/dpop');
        await expect(
          factory({ REDIS_URL: 'redis://localhost:6379', NODE_ENV: 'production' }),
        ).rejects.toThrow(/Refusing to fall back/);
      });
    } finally {
      jest.dontMock('ioredis');
      jest.resetModules();
    }
  });

  it('throws when ioredis is missing and EUNO_DEPLOYMENT_TIER=multi-replica', async () => {
    jest.resetModules();
    try {
      jest.doMock('ioredis', () => { throw new Error("Cannot find module 'ioredis'"); }, { virtual: true });

      await jest.isolateModulesAsync(async () => {
        const { createDpopReplayStoreFromEnv: factory } = require('../src/dpop');
        await expect(
          factory({ REDIS_URL: 'redis://localhost:6379', EUNO_DEPLOYMENT_TIER: 'multi-replica' }),
        ).rejects.toThrow(/Refusing to fall back/);
      });
    } finally {
      jest.dontMock('ioredis');
      jest.resetModules();
    }
  });

  it('falls back to in-memory (non-production) when ioredis is missing', async () => {
    jest.resetModules();
    try {
      jest.doMock('ioredis', () => { throw new Error("Cannot find module 'ioredis'"); }, { virtual: true });

      await jest.isolateModulesAsync(async () => {
        const { createDpopReplayStoreFromEnv: factory, InMemoryDpopReplayStore: InMem } = require('../src/dpop');
        const store = await factory({ REDIS_URL: 'redis://localhost:6379' });
        expect(store).toBeInstanceOf(InMem);
      });
    } finally {
      jest.dontMock('ioredis');
      jest.resetModules();
    }
  });
});
