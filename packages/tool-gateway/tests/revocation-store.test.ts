/**
 * Tests for RevocationStore implementations.
 */

import { createLogger } from '@euno/common';
import {
  InMemoryRevocationStore,
  RedisRevocationStore,
  RedisLikeClient,
  createRevocationStoreFromEnv,
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
