/**
 * Tests for RevocationStore implementations.
 */

import { createLogger } from '@euno/common';
import {
  InMemoryRevocationStore,
  RedisRevocationStore,
  RedisLikeClient,
  createRevocationStoreFromEnv,
  InMemoryRevocationEpochStore,
  RedisRevocationEpochStore,
  createRevocationEpochStoreFromEnv,
} from '../src/revocation-store';

const logger = createLogger('test', 'test');

describe('InMemoryRevocationStore', () => {
  it('reports unknown ids as not revoked', async () => {
    const store = new InMemoryRevocationStore();
    expect(await store.isRevoked('nope')).toBe(false);
  });

  it('reports a revoked id with future expiry as revoked', async () => {
    const store = new InMemoryRevocationStore();
    const future = Math.floor(Date.now() / 1000) + 3600;
    await store.revoke('tok-1', future);
    expect(await store.isRevoked('tok-1')).toBe(true);
  });

  it('treats expired entries as not revoked and prunes them', async () => {
    const store = new InMemoryRevocationStore();
    const past = Math.floor(Date.now() / 1000) - 1;
    await store.revoke('tok-old', past);
    expect(await store.isRevoked('tok-old')).toBe(false);
    expect(store.size()).toBe(0);
  });

  it('eagerly prunes other expired entries on revoke', async () => {
    const store = new InMemoryRevocationStore();
    const past = Math.floor(Date.now() / 1000) - 1;
    await store.revoke('a', past);
    await store.revoke('b', past);
    const future = Math.floor(Date.now() / 1000) + 3600;
    await store.revoke('c', future);
    expect(store.size()).toBe(1);
  });

  it('close() empties the store', async () => {
    const store = new InMemoryRevocationStore();
    const future = Math.floor(Date.now() / 1000) + 3600;
    await store.revoke('x', future);
    await store.close();
    expect(store.size()).toBe(0);
  });
});

describe('RedisRevocationStore', () => {
  function makeClient(overrides: Partial<RedisLikeClient> = {}): RedisLikeClient & {
    calls: { method: string; args: unknown[] }[];
  } {
    const calls: { method: string; args: unknown[] }[] = [];
    const client: any = {
      calls,
      get: async (key: string) => {
        calls.push({ method: 'get', args: [key] });
        return null;
      },
      exists: async (key: string) => {
        calls.push({ method: 'exists', args: [key] });
        return 0;
      },
      set: async (...args: unknown[]) => {
        calls.push({ method: 'set', args });
        return 'OK';
      },
      quit: async () => {
        calls.push({ method: 'quit', args: [] });
        return 'OK';
      },
      on: (_event: string, _listener: (...args: unknown[]) => void) => undefined,
      ...overrides,
    };
    return client;
  }

  it('stores revocations with the configured prefix and TTL', async () => {
    const client = makeClient();
    const store = new RedisRevocationStore(client, logger, { keyPrefix: 'rl:' });
    const future = Math.floor(Date.now() / 1000) + 600;
    await store.revoke('jti-1', future);
    const setCall = client.calls.find(c => c.method === 'set');
    expect(setCall).toBeDefined();
    expect(setCall!.args[0]).toBe('rl:jti-1');
    expect(setCall!.args[1]).toBe('1');
    expect(setCall!.args[2]).toBe('EX');
    expect(setCall!.args[3] as number).toBeGreaterThan(0);
    expect(setCall!.args[3] as number).toBeLessThanOrEqual(600);
  });

  it('skips revocation for already-expired tokens', async () => {
    const client = makeClient();
    const store = new RedisRevocationStore(client, logger);
    const past = Math.floor(Date.now() / 1000) - 10;
    await store.revoke('expired', past);
    expect(client.calls.find(c => c.method === 'set')).toBeUndefined();
  });

  it('returns true when redis reports the key exists', async () => {
    const client = makeClient({
      exists: async () => 1,
    });
    const store = new RedisRevocationStore(client, logger);
    expect(await store.isRevoked('any')).toBe(true);
  });

  it('fails closed (treats as revoked) on redis error by default', async () => {
    const client = makeClient({
      exists: async () => {
        throw new Error('redis down');
      },
    });
    const store = new RedisRevocationStore(client, logger);
    expect(await store.isRevoked('any')).toBe(true);
  });

  it('fails open when explicitly configured', async () => {
    const client = makeClient({
      exists: async () => {
        throw new Error('redis down');
      },
    });
    const store = new RedisRevocationStore(client, logger, { failOpen: true });
    expect(await store.isRevoked('any')).toBe(false);
  });

  it('close() calls quit() on the underlying client', async () => {
    const client = makeClient();
    const store = new RedisRevocationStore(client, logger);
    await store.close();
    expect(client.calls.find(c => c.method === 'quit')).toBeDefined();
  });

  it('close() swallows quit errors', async () => {
    const client = makeClient({
      quit: async () => {
        throw new Error('already closed');
      },
    });
    const store = new RedisRevocationStore(client, logger);
    await expect(store.close()).resolves.toBeUndefined();
  });
});

describe('createRevocationStoreFromEnv', () => {
  it('returns an in-memory store when REDIS_URL is unset', async () => {
    const store = await createRevocationStoreFromEnv({} as NodeJS.ProcessEnv, logger);
    expect(store).toBeInstanceOf(InMemoryRevocationStore);
    await store.close();
  });

  it('falls back to in-memory when ioredis cannot be loaded', async () => {
    // Force the `require('ioredis')` lookup inside the factory to fail so
    // the test exercises the missing-dependency fallback deterministically,
    // regardless of whether ioredis happens to be hoisted into the workspace.
    jest.resetModules();
    try {
      jest.doMock(
        'ioredis',
        () => {
          throw new Error("Cannot find module 'ioredis'");
        },
        { virtual: true }
      );

      await jest.isolateModulesAsync(async () => {
        const mod = await import('../src/revocation-store');
        const store = await mod.createRevocationStoreFromEnv(
          { REDIS_URL: 'redis://localhost:6379' } as unknown as NodeJS.ProcessEnv,
          logger
        );
        expect(store).toBeInstanceOf(mod.InMemoryRevocationStore);
        await store.close();
      });
    } finally {
      jest.dontMock('ioredis');
      jest.resetModules();
    }
  });

  it('throws when ioredis is missing and NODE_ENV=production', async () => {
    jest.resetModules();
    try {
      jest.doMock('ioredis', () => { throw new Error("Cannot find module 'ioredis'"); }, { virtual: true });

      await jest.isolateModulesAsync(async () => {
        const mod = await import('../src/revocation-store');
        await expect(
          mod.createRevocationStoreFromEnv(
            { REDIS_URL: 'redis://localhost:6379', NODE_ENV: 'production' } as unknown as NodeJS.ProcessEnv,
            logger,
          ),
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
        const mod = await import('../src/revocation-store');
        await expect(
          mod.createRevocationStoreFromEnv(
            {
              REDIS_URL: 'redis://localhost:6379',
              EUNO_DEPLOYMENT_TIER: 'multi-replica',
            } as unknown as NodeJS.ProcessEnv,
            logger,
          ),
        ).rejects.toThrow(/Refusing to fall back/);
      });
    } finally {
      jest.dontMock('ioredis');
      jest.resetModules();
    }
  });
});

// ── RevocationEpochStore ───────────────────────────────────────────────────

describe('InMemoryRevocationEpochStore', () => {
  it('returns null for issuers with no epoch set', async () => {
    const store = new InMemoryRevocationEpochStore();
    expect(await store.getEpoch('did:example:issuer')).toBeNull();
  });

  it('returns the epoch after setEpoch', async () => {
    const store = new InMemoryRevocationEpochStore();
    const epoch = Math.floor(Date.now() / 1000);
    await store.setEpoch('did:example:issuer', epoch);
    expect(await store.getEpoch('did:example:issuer')).toBe(epoch);
  });

  it('replaces the epoch when called twice', async () => {
    const store = new InMemoryRevocationEpochStore();
    const first = Math.floor(Date.now() / 1000) - 3600;
    const second = Math.floor(Date.now() / 1000);
    await store.setEpoch('did:example:issuer', first);
    await store.setEpoch('did:example:issuer', second);
    expect(await store.getEpoch('did:example:issuer')).toBe(second);
  });

  it('isolates epochs per issuer', async () => {
    const store = new InMemoryRevocationEpochStore();
    const epochA = Math.floor(Date.now() / 1000) - 600;
    const epochB = Math.floor(Date.now() / 1000) - 300;
    await store.setEpoch('did:example:issuerA', epochA);
    await store.setEpoch('did:example:issuerB', epochB);
    expect(await store.getEpoch('did:example:issuerA')).toBe(epochA);
    expect(await store.getEpoch('did:example:issuerB')).toBe(epochB);
    expect(await store.getEpoch('did:example:issuerC')).toBeNull();
  });

  it('close() empties the store', async () => {
    const store = new InMemoryRevocationEpochStore();
    await store.setEpoch('did:example:issuer', Math.floor(Date.now() / 1000));
    expect(store.size()).toBe(1);
    await store.close();
    expect(store.size()).toBe(0);
  });
});

describe('RedisRevocationEpochStore', () => {
  function makeEpochClient(overrides: Partial<RedisLikeClient> = {}): RedisLikeClient & {
    calls: { method: string; args: unknown[] }[];
  } {
    const calls: { method: string; args: unknown[] }[] = [];
    const client: any = {
      calls,
      get: async (key: string) => {
        calls.push({ method: 'get', args: [key] });
        return null;
      },
      exists: async (key: string) => {
        calls.push({ method: 'exists', args: [key] });
        return 0;
      },
      set: async (...args: unknown[]) => {
        calls.push({ method: 'set', args });
        return 'OK';
      },
      quit: async () => {
        calls.push({ method: 'quit', args: [] });
        return 'OK';
      },
      on: (_event: string, _listener: (...args: unknown[]) => void) => undefined,
      ...overrides,
    };
    return client;
  }

  it('returns null when the key does not exist in Redis', async () => {
    const client = makeEpochClient({ get: async () => null });
    const store = new RedisRevocationEpochStore(client, logger);
    expect(await store.getEpoch('did:example:issuer')).toBeNull();
  });

  it('returns the parsed epoch when the key exists', async () => {
    const epoch = Math.floor(Date.now() / 1000) - 100;
    const client = makeEpochClient({ get: async () => String(epoch) });
    const store = new RedisRevocationEpochStore(client, logger);
    expect(await store.getEpoch('did:example:issuer')).toBe(epoch);
  });

  it('returns null for non-numeric stored values', async () => {
    const client = makeEpochClient({ get: async () => 'not-a-number' });
    const store = new RedisRevocationEpochStore(client, logger);
    expect(await store.getEpoch('did:example:issuer')).toBeNull();
  });

  it('uses the configured key prefix', async () => {
    const client = makeEpochClient();
    const store = new RedisRevocationEpochStore(client, logger, { keyPrefix: 'ep:' });
    await store.getEpoch('did:example:issuer');
    const getCall = client.calls.find(c => c.method === 'get');
    expect(getCall?.args[0]).toBe('ep:did:example:issuer');
  });

  it('stores the epoch with setEpoch', async () => {
    const client = makeEpochClient();
    const store = new RedisRevocationEpochStore(client, logger, { keyPrefix: 'ep:' });
    const epoch = Math.floor(Date.now() / 1000);
    await store.setEpoch('did:example:issuer', epoch);
    const setCall = client.calls.find(c => c.method === 'set');
    expect(setCall).toBeDefined();
    expect(setCall!.args[0]).toBe('ep:did:example:issuer');
    expect(setCall!.args[1]).toBe(String(epoch));
  });

  it('fails closed (returns nowSeconds()+1 as epoch) on redis error by default', async () => {
    const before = Math.floor(Date.now() / 1000);
    const client = makeEpochClient({
      get: async () => { throw new Error('redis down'); },
    });
    const store = new RedisRevocationEpochStore(client, logger);
    const result = await store.getEpoch('did:example:issuer');
    const after = Math.floor(Date.now() / 1000);
    // Fail-closed: result should be nowSeconds()+1, meaning any token with
    // iat <= now is also blocked (iat < epoch holds for iat === now too).
    expect(result).not.toBeNull();
    expect(result!).toBeGreaterThanOrEqual(before + 1);
    expect(result!).toBeLessThanOrEqual(after + 2);
  });

  it('fails open (returns null) when failOpen=true on redis error', async () => {
    const client = makeEpochClient({
      get: async () => { throw new Error('redis down'); },
    });
    const store = new RedisRevocationEpochStore(client, logger, { failOpen: true });
    expect(await store.getEpoch('did:example:issuer')).toBeNull();
  });

  it('invokes onError callback on redis error', async () => {
    const client = makeEpochClient({
      get: async () => { throw new Error('redis down'); },
    });
    const onError = jest.fn();
    const store = new RedisRevocationEpochStore(client, logger, { onError });
    await store.getEpoch('did:example:issuer');
    expect(onError).toHaveBeenCalledTimes(1);
  });

  it('throws when setEpoch fails', async () => {
    const client = makeEpochClient({
      set: async () => { throw new Error('redis write error'); },
    });
    const store = new RedisRevocationEpochStore(client, logger);
    await expect(store.setEpoch('did:example:issuer', 12345)).rejects.toThrow('redis write error');
  });

  it('close() calls quit() on the underlying client', async () => {
    const client = makeEpochClient();
    const store = new RedisRevocationEpochStore(client, logger);
    await store.close();
    expect(client.calls.find(c => c.method === 'quit')).toBeDefined();
  });

  it('close() swallows quit errors', async () => {
    const client = makeEpochClient({
      quit: async () => { throw new Error('already closed'); },
    });
    const store = new RedisRevocationEpochStore(client, logger);
    await expect(store.close()).resolves.toBeUndefined();
  });
});

describe('createRevocationEpochStoreFromEnv', () => {
  it('returns an in-memory store when REDIS_URL is unset', async () => {
    const store = await createRevocationEpochStoreFromEnv({} as NodeJS.ProcessEnv, logger);
    expect(store).toBeInstanceOf(InMemoryRevocationEpochStore);
    await store.close();
  });

  it('falls back to in-memory when ioredis cannot be loaded (dev)', async () => {
    jest.resetModules();
    try {
      jest.doMock('ioredis', () => { throw new Error("Cannot find module 'ioredis'"); }, { virtual: true });

      await jest.isolateModulesAsync(async () => {
        const mod = await import('../src/revocation-store');
        const store = await mod.createRevocationEpochStoreFromEnv(
          { REDIS_URL: 'redis://localhost:6379' } as unknown as NodeJS.ProcessEnv,
          logger
        );
        expect(store).toBeInstanceOf(mod.InMemoryRevocationEpochStore);
        await store.close();
      });
    } finally {
      jest.dontMock('ioredis');
      jest.resetModules();
    }
  });

  it('throws when ioredis is missing and NODE_ENV=production', async () => {
    jest.resetModules();
    try {
      jest.doMock('ioredis', () => { throw new Error("Cannot find module 'ioredis'"); }, { virtual: true });

      await jest.isolateModulesAsync(async () => {
        const mod = await import('../src/revocation-store');
        await expect(
          mod.createRevocationEpochStoreFromEnv(
            { REDIS_URL: 'redis://localhost:6379', NODE_ENV: 'production' } as unknown as NodeJS.ProcessEnv,
            logger,
          ),
        ).rejects.toThrow(/Refusing to fall back/);
      });
    } finally {
      jest.dontMock('ioredis');
      jest.resetModules();
    }
  });
});
