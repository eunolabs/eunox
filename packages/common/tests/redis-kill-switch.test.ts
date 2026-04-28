/**
 * Tests for RedisKillSwitchManager and createKillSwitchManagerFromEnv.
 */

import { createLogger } from '../src/logger';
import { DefaultKillSwitchManager } from '../src/kill-switch';
import {
  RedisKillSwitchClient,
  RedisKillSwitchManager,
  createKillSwitchManagerFromEnv,
} from '../src/redis-kill-switch';

const logger = createLogger('test', 'test');

interface FakeClient extends RedisKillSwitchClient {
  store: {
    strings: Map<string, string>;
    sets: Map<string, Set<string>>;
  };
  calls: { method: string; args: unknown[] }[];
  triggerError: (event: string, err: unknown) => void;
}

function makeFakeClient(overrides: Partial<RedisKillSwitchClient> = {}): FakeClient {
  const strings = new Map<string, string>();
  const sets = new Map<string, Set<string>>();
  const calls: { method: string; args: unknown[] }[] = [];
  const errorListeners: Array<(...args: unknown[]) => void> = [];
  const ensureSet = (key: string): Set<string> => {
    let s = sets.get(key);
    if (!s) {
      s = new Set<string>();
      sets.set(key, s);
    }
    return s;
  };
  const client: FakeClient = {
    store: { strings, sets },
    calls,
    triggerError(event, err) {
      if (event === 'error') {
        for (const l of errorListeners) {
          l(err);
        }
      }
    },
    async get(key: string): Promise<string | null> {
      calls.push({ method: 'get', args: [key] });
      return strings.has(key) ? strings.get(key)! : null;
    },
    async set(key: string, value: string): Promise<unknown> {
      calls.push({ method: 'set', args: [key, value] });
      strings.set(key, value);
      return 'OK';
    },
    async del(key: string): Promise<unknown> {
      calls.push({ method: 'del', args: [key] });
      const had = strings.delete(key) ? 1 : 0;
      const hadSet = sets.delete(key) ? 1 : 0;
      return had + hadSet;
    },
    async sadd(key: string, member: string): Promise<unknown> {
      calls.push({ method: 'sadd', args: [key, member] });
      const before = ensureSet(key).size;
      ensureSet(key).add(member);
      return ensureSet(key).size - before;
    },
    async srem(key: string, member: string): Promise<unknown> {
      calls.push({ method: 'srem', args: [key, member] });
      const s = sets.get(key);
      if (!s) return 0;
      return s.delete(member) ? 1 : 0;
    },
    async smembers(key: string): Promise<string[]> {
      calls.push({ method: 'smembers', args: [key] });
      return Array.from(sets.get(key) ?? []);
    },
    async quit(): Promise<unknown> {
      calls.push({ method: 'quit', args: [] });
      return 'OK';
    },
    on(event: string, listener: (...args: unknown[]) => void): unknown {
      if (event === 'error') {
        errorListeners.push(listener);
      }
      return undefined;
    },
    ...overrides,
  };
  return client;
}

/**
 * Wait one event-loop turn so the fire-and-forget Redis writes inside
 * `runWrite` settle before assertions run.
 */
async function flushMicrotasks(): Promise<void> {
  await new Promise((r) => setImmediate(r));
}

describe('RedisKillSwitchManager', () => {
  it('seeds the local cache from Redis on start()', async () => {
    const client = makeFakeClient();
    client.store.strings.set('killswitch:global', '1');
    client.store.sets.set('killswitch:killed_sessions', new Set(['s1']));
    client.store.sets.set('killswitch:killed_agents', new Set(['a1']));

    const mgr = new RedisKillSwitchManager(client, logger, { refreshIntervalMs: 0 });
    await mgr.start();

    expect(mgr.isGlobalKillActive()).toBe(true);
    expect(mgr.isSessionKilled('s1')).toBe(true);
    expect(mgr.isAgentKilled('a1')).toBe(true);
    expect(mgr.shouldBlock('s1')).toBe(true);
    expect(mgr.shouldBlock('s2')).toBe(true); // global blocks everything
    expect(mgr.getStatus()).toEqual({
      globalKill: true,
      killedSessionCount: 1,
      killedAgentCount: 1,
    });

    await mgr.close();
  });

  it('starts with an empty cache when initial refresh fails', async () => {
    const client = makeFakeClient({
      get: async () => {
        throw new Error('boom');
      },
    });
    const mgr = new RedisKillSwitchManager(client, logger, { refreshIntervalMs: 0 });
    await mgr.start(); // must not throw
    expect(mgr.isGlobalKillActive()).toBe(false);
    expect(mgr.getStatus()).toEqual({
      globalKill: false,
      killedSessionCount: 0,
      killedAgentCount: 0,
    });
    await mgr.close();
  });

  it('write-throughs activateGlobalKill / deactivateGlobalKill to Redis', async () => {
    const client = makeFakeClient();
    const mgr = new RedisKillSwitchManager(client, logger, { refreshIntervalMs: 0 });
    await mgr.start();

    mgr.activateGlobalKill();
    await flushMicrotasks();
    expect(mgr.isGlobalKillActive()).toBe(true);
    expect(client.store.strings.get('killswitch:global')).toBe('1');

    mgr.deactivateGlobalKill();
    await flushMicrotasks();
    expect(mgr.isGlobalKillActive()).toBe(false);
    expect(client.store.strings.has('killswitch:global')).toBe(false);

    await mgr.close();
  });

  it('write-throughs killSession / reviveSession to Redis', async () => {
    const client = makeFakeClient();
    const mgr = new RedisKillSwitchManager(client, logger, { refreshIntervalMs: 0 });
    await mgr.start();

    mgr.killSession('sess-A');
    await flushMicrotasks();
    expect(mgr.isSessionKilled('sess-A')).toBe(true);
    expect(client.store.sets.get('killswitch:killed_sessions')?.has('sess-A')).toBe(true);

    mgr.reviveSession('sess-A');
    await flushMicrotasks();
    expect(mgr.isSessionKilled('sess-A')).toBe(false);
    expect(client.store.sets.get('killswitch:killed_sessions')?.has('sess-A')).toBe(false);

    await mgr.close();
  });

  it('write-throughs killAgent / reviveAgent to Redis', async () => {
    const client = makeFakeClient();
    const mgr = new RedisKillSwitchManager(client, logger, { refreshIntervalMs: 0 });
    await mgr.start();

    mgr.killAgent('agent-1');
    await flushMicrotasks();
    expect(mgr.isAgentKilled('agent-1')).toBe(true);
    expect(mgr.shouldBlock(undefined, 'agent-1')).toBe(true);
    expect(client.store.sets.get('killswitch:killed_agents')?.has('agent-1')).toBe(true);

    mgr.reviveAgent('agent-1');
    await flushMicrotasks();
    expect(mgr.isAgentKilled('agent-1')).toBe(false);

    await mgr.close();
  });

  it('resetAll clears every kill key in Redis and the local cache', async () => {
    const client = makeFakeClient();
    client.store.strings.set('killswitch:global', '1');
    client.store.sets.set('killswitch:killed_sessions', new Set(['s1', 's2']));
    client.store.sets.set('killswitch:killed_agents', new Set(['a1']));

    const mgr = new RedisKillSwitchManager(client, logger, { refreshIntervalMs: 0 });
    await mgr.start();
    expect(mgr.getStatus().killedSessionCount).toBe(2);

    mgr.resetAll();
    await flushMicrotasks();
    expect(mgr.getStatus()).toEqual({
      globalKill: false,
      killedSessionCount: 0,
      killedAgentCount: 0,
    });
    expect(client.store.strings.has('killswitch:global')).toBe(false);
    expect(client.store.sets.has('killswitch:killed_sessions')).toBe(false);
    expect(client.store.sets.has('killswitch:killed_agents')).toBe(false);

    await mgr.close();
  });

  it('does NOT update the local cache when a write fails (default fail-closed)', async () => {
    const client = makeFakeClient({
      sadd: async () => {
        throw new Error('redis down');
      },
    });
    const mgr = new RedisKillSwitchManager(client, logger, { refreshIntervalMs: 0 });
    await mgr.start();

    mgr.killSession('sess-broken');
    await flushMicrotasks();

    // Cache must NOT reflect the failed write – otherwise this pod would
    // silently disagree with every other replica.
    expect(mgr.isSessionKilled('sess-broken')).toBe(false);

    await mgr.close();
  });

  it('updates the local cache when a write fails and failOpenOnWrite=true', async () => {
    const client = makeFakeClient({
      sadd: async () => {
        throw new Error('redis down');
      },
    });
    const mgr = new RedisKillSwitchManager(client, logger, {
      refreshIntervalMs: 0,
      failOpenOnWrite: true,
    });
    await mgr.start();

    mgr.killSession('sess-best-effort');
    await flushMicrotasks();

    // Best-effort: local pod still honours the operator's intent.
    expect(mgr.isSessionKilled('sess-best-effort')).toBe(true);

    await mgr.close();
  });

  it('refresh() pulls remote changes made by other pods into the local cache', async () => {
    const client = makeFakeClient();
    const mgr = new RedisKillSwitchManager(client, logger, { refreshIntervalMs: 0 });
    await mgr.start();
    expect(mgr.isSessionKilled('remote-sess')).toBe(false);

    // Simulate another pod writing directly to Redis.
    client.store.sets.set('killswitch:killed_sessions', new Set(['remote-sess']));
    client.store.strings.set('killswitch:global', '1');

    await mgr.refresh();
    expect(mgr.isSessionKilled('remote-sess')).toBe(true);
    expect(mgr.isGlobalKillActive()).toBe(true);

    await mgr.close();
  });

  it('respects a custom keyPrefix', async () => {
    const client = makeFakeClient();
    const mgr = new RedisKillSwitchManager(client, logger, {
      refreshIntervalMs: 0,
      keyPrefix: 'myenv:ks:',
    });
    await mgr.start();

    mgr.killAgent('agent-prefix');
    await flushMicrotasks();
    expect(client.store.sets.get('myenv:ks:killed_agents')?.has('agent-prefix')).toBe(true);

    await mgr.close();
  });

  it('shouldBlock matches sessionId, agentId, and global independently', async () => {
    const client = makeFakeClient();
    const mgr = new RedisKillSwitchManager(client, logger, { refreshIntervalMs: 0 });
    await mgr.start();

    mgr.killSession('sX');
    mgr.killAgent('aX');
    await flushMicrotasks();

    expect(mgr.shouldBlock('sX')).toBe(true);
    expect(mgr.shouldBlock(undefined, 'aX')).toBe(true);
    expect(mgr.shouldBlock('sY', 'aY')).toBe(false);

    mgr.activateGlobalKill();
    await flushMicrotasks();
    expect(mgr.shouldBlock('sY', 'aY')).toBe(true);

    await mgr.close();
  });

  it('close() is idempotent and stops the refresh timer', async () => {
    const client = makeFakeClient();
    const mgr = new RedisKillSwitchManager(client, logger, { refreshIntervalMs: 50 });
    await mgr.start();
    await mgr.close();
    await mgr.close(); // must not throw

    const quitCalls = client.calls.filter((c) => c.method === 'quit');
    expect(quitCalls.length).toBeGreaterThanOrEqual(1);
  });

  it('close() swallows quit() errors', async () => {
    const client = makeFakeClient({
      quit: async () => {
        throw new Error('already closed');
      },
    });
    const mgr = new RedisKillSwitchManager(client, logger, { refreshIntervalMs: 0 });
    await mgr.start();
    await expect(mgr.close()).resolves.toBeUndefined();
  });

  it('logs but does not throw when the Redis client emits an error event', async () => {
    const client = makeFakeClient();
    const mgr = new RedisKillSwitchManager(client, logger, { refreshIntervalMs: 0 });
    await mgr.start();
    expect(() => client.triggerError('error', new Error('boom'))).not.toThrow();
    await mgr.close();
  });
});

describe('createKillSwitchManagerFromEnv', () => {
  it('returns the in-process default when REDIS_URL is unset', async () => {
    const mgr = await createKillSwitchManagerFromEnv({} as NodeJS.ProcessEnv, logger);
    expect(mgr).toBeInstanceOf(DefaultKillSwitchManager);
  });

  it('falls back to the in-process default when ioredis cannot be loaded', async () => {
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
        const mod = await import('../src/redis-kill-switch');
        const fallbackMod = await import('../src/kill-switch');
        const mgr = await mod.createKillSwitchManagerFromEnv(
          { REDIS_URL: 'redis://localhost:6379' } as unknown as NodeJS.ProcessEnv,
          logger
        );
        expect(mgr).toBeInstanceOf(fallbackMod.DefaultKillSwitchManager);
      });
    } finally {
      jest.dontMock('ioredis');
      jest.resetModules();
    }
  });
});
