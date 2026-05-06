/**
 * Tests for RedisKillSwitchManager and createKillSwitchManagerFromEnv.
 */

import { createLogger } from '../src/logger';
import { DefaultKillSwitchManager } from '../src/kill-switch';
import {
  RedisKillSwitchClient,
  RedisKillSwitchManager,
  RedisKillSwitchSubscriber,
  PostgresKillSwitchBackend,
  KillSwitchPersistenceBackend,
  createKillSwitchManagerFromEnv,
} from '../src/redis-kill-switch';
import type { KillSwitchConfig } from '../src/types';

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
    async publish(channel: string, message: string): Promise<unknown> {
      calls.push({ method: 'publish', args: [channel, message] });
      return 0;
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

  it('reverts the local cache when a write fails (default fail-closed)', async () => {
    const client = makeFakeClient({
      sadd: async () => {
        throw new Error('redis down');
      },
    });
    const mgr = new RedisKillSwitchManager(client, logger, { refreshIntervalMs: 0 });
    await mgr.start();

    mgr.killSession('sess-broken');
    // Synchronously the cache reflects the kill so the issuing pod
    // honours it immediately – there is no race window.
    expect(mgr.isSessionKilled('sess-broken')).toBe(true);

    await flushMicrotasks();

    // Once the failed Redis write settles the cache is rolled back so
    // this pod does not silently disagree with every other replica.
    expect(mgr.isSessionKilled('sess-broken')).toBe(false);

    await mgr.close();
  });

  it('keeps the optimistic cache update when a write fails and failOpenOnWrite=true', async () => {
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
    // Cache reflects the kill synchronously…
    expect(mgr.isSessionKilled('sess-best-effort')).toBe(true);

    await flushMicrotasks();

    // …and is preserved as best-effort local state when Redis fails.
    expect(mgr.isSessionKilled('sess-best-effort')).toBe(true);

    await mgr.close();
  });

  it('reverts a failed killAgent without removing pre-existing kills', async () => {
    let firstCall = true;
    const client = makeFakeClient({
      sadd: async () => {
        if (firstCall) {
          firstCall = false;
          return 1;
        }
        throw new Error('redis down');
      },
    });
    const mgr = new RedisKillSwitchManager(client, logger, { refreshIntervalMs: 0 });
    await mgr.start();

    // First kill succeeds.
    mgr.killAgent('agent-1');
    await flushMicrotasks();
    expect(mgr.isAgentKilled('agent-1')).toBe(true);

    // Second kill (different agent) fails on Redis – cache must roll
    // back the new entry without disturbing agent-1.
    mgr.killAgent('agent-2');
    expect(mgr.isAgentKilled('agent-2')).toBe(true); // applied optimistically
    await flushMicrotasks();
    expect(mgr.isAgentKilled('agent-2')).toBe(false); // rolled back
    expect(mgr.isAgentKilled('agent-1')).toBe(true); // unaffected

    await mgr.close();
  });

  it('reverts a failed resetAll back to the previous full state', async () => {
    const client = makeFakeClient();
    client.store.strings.set('killswitch:global', '1');
    client.store.sets.set('killswitch:killed_sessions', new Set(['s1', 's2']));
    client.store.sets.set('killswitch:killed_agents', new Set(['a1']));

    const mgr = new RedisKillSwitchManager(client, logger, { refreshIntervalMs: 0 });
    await mgr.start();
    expect(mgr.getStatus()).toEqual({
      globalKill: true,
      killedSessionCount: 2,
      killedAgentCount: 1,
    });

    // Make the next del() round fail.
    client.del = async () => {
      throw new Error('redis down');
    };

    mgr.resetAll();
    // Optimistically cleared synchronously…
    expect(mgr.getStatus()).toEqual({
      globalKill: false,
      killedSessionCount: 0,
      killedAgentCount: 0,
    });
    await flushMicrotasks();
    // …then rolled back to the full prior state.
    expect(mgr.getStatus()).toEqual({
      globalKill: true,
      killedSessionCount: 2,
      killedAgentCount: 1,
    });
    expect(mgr.isSessionKilled('s1')).toBe(true);
    expect(mgr.isSessionKilled('s2')).toBe(true);
    expect(mgr.isAgentKilled('a1')).toBe(true);

    await mgr.close();
  });

  it('start() is idempotent even when refreshIntervalMs=0', async () => {
    const client = makeFakeClient();
    const mgr = new RedisKillSwitchManager(client, logger, { refreshIntervalMs: 0 });

    await mgr.start();
    const callsAfterFirst = client.calls.length;
    await mgr.start();
    await mgr.start();

    // Repeated start() must not re-run the initial refresh – without a
    // dedicated `started` guard the timer-disabled code path would
    // re-issue GET + 2x SMEMBERS on every call.
    expect(client.calls.length).toBe(callsAfterFirst);

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

  describe('pub/sub propagation', () => {
    interface FakeSubscriber extends RedisKillSwitchSubscriber {
      subscribed: Set<string>;
      emitMessage: (channel: string, message: string) => void;
      emitError: (err: unknown) => void;
    }

    function makeFakeSubscriber(
      overrides: Partial<RedisKillSwitchSubscriber> = {},
    ): FakeSubscriber {
      const subscribed = new Set<string>();
      const messageListeners: Array<(channel: string, message: string) => void> = [];
      const errorListeners: Array<(err: unknown) => void> = [];
      const sub: FakeSubscriber = {
        subscribed,
        emitMessage(channel, message) {
          for (const l of messageListeners) l(channel, message);
        },
        emitError(err) {
          for (const l of errorListeners) l(err);
        },
        async subscribe(channel: string) {
          subscribed.add(channel);
          return undefined;
        },
        async unsubscribe(channel?: string) {
          if (channel) subscribed.delete(channel);
          else subscribed.clear();
          return undefined;
        },
        async quit() {
          return 'OK';
        },
        on(event: string, listener: (...args: unknown[]) => void) {
          if (event === 'message') {
            messageListeners.push(listener as (channel: string, message: string) => void);
          } else if (event === 'error') {
            errorListeners.push(listener as (err: unknown) => void);
          }
          return undefined;
        },
        ...overrides,
      };
      return sub;
    }

    it('publishes a granular event to <prefix>events on every successful write', async () => {
      const client = makeFakeClient();
      const subscriber = makeFakeSubscriber();
      const mgr = new RedisKillSwitchManager(client, logger, {
        refreshIntervalMs: 0,
        subscriber,
        instanceId: 'pod-A',
      });
      await mgr.start();

      mgr.killSession('sess-1');
      mgr.killAgent('agent-1');
      mgr.activateGlobalKill();
      mgr.deactivateGlobalKill();
      mgr.reviveSession('sess-1');
      mgr.reviveAgent('agent-1');
      mgr.resetAll();

      await flushMicrotasks();
      await flushMicrotasks();

      const publishes = client.calls.filter((c) => c.method === 'publish');
      expect(publishes).toHaveLength(7);
      const ops = publishes.map((c) => JSON.parse(String(c.args[1])).op);
      expect(ops).toEqual([
        'kill_session',
        'kill_agent',
        'activate_global',
        'deactivate_global',
        'revive_session',
        'revive_agent',
        'reset_all',
      ]);
      // All publishes target the events channel and carry the
      // originator instanceId so receivers can ignore self-echoes.
      for (const c of publishes) {
        expect(c.args[0]).toBe('killswitch:events');
        const payload = JSON.parse(String(c.args[1]));
        expect(payload.src).toBe('pod-A');
        expect(payload.v).toBe(1);
      }

      await mgr.close();
    });

    it('does NOT publish when the Redis write fails (fail-closed)', async () => {
      const client = makeFakeClient({
        sadd: async () => {
          throw new Error('redis down');
        },
      });
      const subscriber = makeFakeSubscriber();
      const mgr = new RedisKillSwitchManager(client, logger, {
        refreshIntervalMs: 0,
        subscriber,
        instanceId: 'pod-A',
      });
      await mgr.start();

      mgr.killSession('sess-x');
      await flushMicrotasks();
      await flushMicrotasks();

      const publishes = client.calls.filter((c) => c.method === 'publish');
      expect(publishes).toHaveLength(0);

      await mgr.close();
    });

    it('subscribes to the events channel on start() and unsubscribes on close()', async () => {
      const client = makeFakeClient();
      const subscriber = makeFakeSubscriber();
      const mgr = new RedisKillSwitchManager(client, logger, {
        refreshIntervalMs: 0,
        subscriber,
      });
      await mgr.start();
      expect(subscriber.subscribed.has('killswitch:events')).toBe(true);

      await mgr.close();
      expect(subscriber.subscribed.has('killswitch:events')).toBe(false);
    });

    it('applies remote kill_session events from another replica synchronously', async () => {
      const client = makeFakeClient();
      const subscriber = makeFakeSubscriber();
      const mgr = new RedisKillSwitchManager(client, logger, {
        refreshIntervalMs: 0,
        subscriber,
        instanceId: 'pod-B',
      });
      await mgr.start();
      expect(mgr.isSessionKilled('remote-sess')).toBe(false);

      // Simulate pod-A publishing a kill_session on the events channel.
      subscriber.emitMessage(
        'killswitch:events',
        JSON.stringify({ v: 1, src: 'pod-A', op: 'kill_session', id: 'remote-sess' }),
      );

      // The cache update happens synchronously inside the message
      // handler – no Redis round-trip, no waiting for the periodic
      // refresh.  shouldBlock() reflects the remote kill immediately.
      expect(mgr.isSessionKilled('remote-sess')).toBe(true);
      expect(mgr.shouldBlock('remote-sess')).toBe(true);

      await mgr.close();
    });

    it('applies every event op from remote replicas to the local cache', async () => {
      const client = makeFakeClient();
      const subscriber = makeFakeSubscriber();
      const mgr = new RedisKillSwitchManager(client, logger, {
        refreshIntervalMs: 0,
        subscriber,
        instanceId: 'pod-B',
      });
      await mgr.start();

      const send = (op: string, id?: string) =>
        subscriber.emitMessage(
          'killswitch:events',
          JSON.stringify({ v: 1, src: 'pod-A', op, ...(id ? { id } : {}) }),
        );

      send('activate_global');
      expect(mgr.isGlobalKillActive()).toBe(true);
      send('deactivate_global');
      expect(mgr.isGlobalKillActive()).toBe(false);

      send('kill_session', 's1');
      send('kill_agent', 'a1');
      expect(mgr.isSessionKilled('s1')).toBe(true);
      expect(mgr.isAgentKilled('a1')).toBe(true);

      send('revive_session', 's1');
      send('revive_agent', 'a1');
      expect(mgr.isSessionKilled('s1')).toBe(false);
      expect(mgr.isAgentKilled('a1')).toBe(false);

      send('kill_session', 's2');
      send('activate_global');
      send('reset_all');
      expect(mgr.isGlobalKillActive()).toBe(false);
      expect(mgr.isSessionKilled('s2')).toBe(false);
      expect(mgr.getStatus()).toEqual({
        globalKill: false,
        killedSessionCount: 0,
        killedAgentCount: 0,
      });

      await mgr.close();
    });

    it('ignores echoes of its own published events (deduplication by instanceId)', async () => {
      const client = makeFakeClient();
      const subscriber = makeFakeSubscriber();
      const mgr = new RedisKillSwitchManager(client, logger, {
        refreshIntervalMs: 0,
        subscriber,
        instanceId: 'pod-self',
      });
      await mgr.start();

      // Echo of a "kill" we issued ourselves – cache should not double-apply
      // any state, and a subsequent revive must clear it (i.e. the echo
      // didn't somehow re-add the entry after the local revive).
      mgr.killSession('echoed');
      await flushMicrotasks();
      mgr.reviveSession('echoed');
      await flushMicrotasks();
      subscriber.emitMessage(
        'killswitch:events',
        JSON.stringify({ v: 1, src: 'pod-self', op: 'kill_session', id: 'echoed' }),
      );
      expect(mgr.isSessionKilled('echoed')).toBe(false);

      await mgr.close();
    });

    it('ignores messages on unrelated channels', async () => {
      const client = makeFakeClient();
      const subscriber = makeFakeSubscriber();
      const mgr = new RedisKillSwitchManager(client, logger, {
        refreshIntervalMs: 0,
        subscriber,
      });
      await mgr.start();

      subscriber.emitMessage(
        'some:other:channel',
        JSON.stringify({ v: 1, src: 'x', op: 'activate_global' }),
      );
      expect(mgr.isGlobalKillActive()).toBe(false);

      await mgr.close();
    });

    it('drops malformed event payloads without throwing', async () => {
      const client = makeFakeClient();
      const subscriber = makeFakeSubscriber();
      const mgr = new RedisKillSwitchManager(client, logger, {
        refreshIntervalMs: 0,
        subscriber,
      });
      await mgr.start();

      expect(() =>
        subscriber.emitMessage('killswitch:events', 'not-json{{{'),
      ).not.toThrow();
      expect(() =>
        subscriber.emitMessage('killswitch:events', JSON.stringify({ v: 99, op: 'unknown' })),
      ).not.toThrow();
      expect(() =>
        subscriber.emitMessage('killswitch:events', JSON.stringify(null)),
      ).not.toThrow();
      expect(mgr.isGlobalKillActive()).toBe(false);

      await mgr.close();
    });

    it('drops id-bearing ops when the id field is absent or not a string', async () => {
      const client = makeFakeClient();
      const subscriber = makeFakeSubscriber();
      const mgr = new RedisKillSwitchManager(client, logger, {
        refreshIntervalMs: 0,
        subscriber,
        instanceId: 'pod-B',
      });
      await mgr.start();

      // Missing id — must not insert undefined into the set
      expect(() =>
        subscriber.emitMessage(
          'killswitch:events',
          JSON.stringify({ v: 1, src: 'pod-A', op: 'kill_session' }),
        ),
      ).not.toThrow();
      expect(mgr.getStatus().killedSessionCount).toBe(0);

      // Non-string id — also must not corrupt the set
      expect(() =>
        subscriber.emitMessage(
          'killswitch:events',
          JSON.stringify({ v: 1, src: 'pod-A', op: 'kill_agent', id: 42 }),
        ),
      ).not.toThrow();
      expect(mgr.getStatus().killedAgentCount).toBe(0);

      // A valid event still works after the invalid ones
      subscriber.emitMessage(
        'killswitch:events',
        JSON.stringify({ v: 1, src: 'pod-A', op: 'kill_session', id: 'sess-valid' }),
      );
      expect(mgr.isSessionKilled('sess-valid')).toBe(true);

      await mgr.close();
    });

    it('does NOT publish when subscriber is absent (KILL_SWITCH_PUBSUB_ENABLED=false)', async () => {
      // Without a subscriber, publish() should never be called even on
      // successful writes — the whole point of KILL_SWITCH_PUBSUB_ENABLED=false
      // is to fall back to periodic-refresh-only propagation without any
      // pub/sub round-trips.
      const client = makeFakeClient();
      // No subscriber passed — mirrors what createKillSwitchManagerFromEnv
      // does when KILL_SWITCH_PUBSUB_ENABLED=false.
      const mgr = new RedisKillSwitchManager(client, logger, {
        refreshIntervalMs: 0,
        // subscriber intentionally omitted
      });
      await mgr.start();

      mgr.killSession('sess-nopub');
      mgr.killAgent('agent-nopub');
      mgr.activateGlobalKill();
      mgr.resetAll();

      await flushMicrotasks();
      await flushMicrotasks();

      const publishes = client.calls.filter((c) => c.method === 'publish');
      expect(publishes).toHaveLength(0);

      await mgr.close();
    });

    it('uses the configured keyPrefix for the events channel', async () => {
      const client = makeFakeClient();
      const subscriber = makeFakeSubscriber();
      const mgr = new RedisKillSwitchManager(client, logger, {
        refreshIntervalMs: 0,
        subscriber,
        keyPrefix: 'tenantA:ks:',
        instanceId: 'pod-A',
      });
      await mgr.start();
      expect(subscriber.subscribed.has('tenantA:ks:events')).toBe(true);

      mgr.activateGlobalKill();
      await flushMicrotasks();
      const publishes = client.calls.filter((c) => c.method === 'publish');
      expect(publishes).toHaveLength(1);
      expect(publishes[0]?.args[0]).toBe('tenantA:ks:events');

      await mgr.close();
    });

    it('still works (falls back to periodic refresh) when subscribe() fails', async () => {
      const client = makeFakeClient();
      const subscriber = makeFakeSubscriber({
        subscribe: async () => {
          throw new Error('SUBSCRIBE failed');
        },
      });
      const mgr = new RedisKillSwitchManager(client, logger, {
        refreshIntervalMs: 0,
        subscriber,
      });
      await expect(mgr.start()).resolves.toBeUndefined();
      // Writes still work even though pub/sub failed to wire up.
      mgr.killSession('s1');
      await flushMicrotasks();
      expect(mgr.isSessionKilled('s1')).toBe(true);
      await mgr.close();
    });

    it('logs but does not throw when the subscriber emits an error event', async () => {
      const client = makeFakeClient();
      const subscriber = makeFakeSubscriber();
      const mgr = new RedisKillSwitchManager(client, logger, {
        refreshIntervalMs: 0,
        subscriber,
      });
      await mgr.start();
      expect(() => subscriber.emitError(new Error('boom'))).not.toThrow();
      await mgr.close();
    });

    it('a publish failure does not cause unhandledRejection or break the write', async () => {
      const client = makeFakeClient({
        publish: async () => {
          throw new Error('publish failed');
        },
      });
      const subscriber = makeFakeSubscriber();
      const mgr = new RedisKillSwitchManager(client, logger, {
        refreshIntervalMs: 0,
        subscriber,
      });
      await mgr.start();

      mgr.killAgent('a1');
      await flushMicrotasks();
      await flushMicrotasks();
      // Write still landed in Redis and in the local cache.
      expect(client.store.sets.get('killswitch:killed_agents')?.has('a1')).toBe(true);
      expect(mgr.isAgentKilled('a1')).toBe(true);

      await mgr.close();
    });
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

  it('does NOT call duplicate() when KILL_SWITCH_PUBSUB_ENABLED=false', async () => {
    let duplicateCalled = false;
    jest.resetModules();
    try {
      jest.doMock(
        'ioredis',
        () => {
          return class FakeRedis {
            get() { return Promise.resolve(null); }
            set() { return Promise.resolve('OK'); }
            del() { return Promise.resolve(0); }
            sadd() { return Promise.resolve(0); }
            srem() { return Promise.resolve(0); }
            smembers() { return Promise.resolve([]); }
            publish() { return Promise.resolve(0); }
            quit() { return Promise.resolve('OK'); }
            on() {}
            duplicate() {
              duplicateCalled = true;
              return new (this.constructor as new () => unknown)();
            }
          };
        },
        { virtual: true },
      );

      await jest.isolateModulesAsync(async () => {
        const mod = await import('../src/redis-kill-switch');
        const mgr = await mod.createKillSwitchManagerFromEnv(
          {
            REDIS_URL: 'redis://localhost:6379',
            KILL_SWITCH_PUBSUB_ENABLED: 'false',
          } as unknown as NodeJS.ProcessEnv,
          logger,
        );
        expect(duplicateCalled).toBe(false);
        await (mgr as { close?(): Promise<void> }).close?.();
      });
    } finally {
      jest.dontMock('ioredis');
      jest.resetModules();
    }
  });

  it('warns and disables pub/sub when the Redis client does not support duplicate()', async () => {
    jest.resetModules();
    try {
      jest.doMock(
        'ioredis',
        () => {
          return class FakeRedisNoDuplicate {
            get() { return Promise.resolve(null); }
            set() { return Promise.resolve('OK'); }
            del() { return Promise.resolve(0); }
            sadd() { return Promise.resolve(0); }
            srem() { return Promise.resolve(0); }
            smembers() { return Promise.resolve([]); }
            publish() { return Promise.resolve(0); }
            quit() { return Promise.resolve('OK'); }
            on() {}
            // No duplicate() method — intentionally omitted
          };
        },
        { virtual: true },
      );

      await jest.isolateModulesAsync(async () => {
        const mod = await import('../src/redis-kill-switch');
        const { DefaultKillSwitchManager: Default } = await import('../src/kill-switch');
        const mgr = await mod.createKillSwitchManagerFromEnv(
          { REDIS_URL: 'redis://localhost:6379' } as unknown as NodeJS.ProcessEnv,
          logger,
        );
        // Should still return a Redis-backed manager (not the in-memory fallback)
        expect(mgr).not.toBeInstanceOf(Default);
        // Writes must still work (pub/sub is disabled but periodic refresh works)
        expect(() => (mgr as { killSession?(s: string): void }).killSession?.('sess-noduplicate')).not.toThrow();
        await (mgr as { close?(): Promise<void> }).close?.();
      });
    } finally {
      jest.dontMock('ioredis');
      jest.resetModules();
    }
  });

  it('throws (fail-fast) when KILL_SWITCH_POSTGRES_URL is set but pg cannot be loaded', async () => {
    jest.resetModules();
    try {
      jest.doMock('ioredis', () => {
        return class FakeRedis {
          get() { return Promise.resolve(null); }
          set() { return Promise.resolve('OK'); }
          del() { return Promise.resolve(0); }
          sadd() { return Promise.resolve(0); }
          srem() { return Promise.resolve(0); }
          smembers() { return Promise.resolve([]); }
          publish() { return Promise.resolve(0); }
          quit() { return Promise.resolve('OK'); }
          on() {}
          duplicate() { return new (this.constructor as new () => unknown)(); }
        };
      }, { virtual: true });
      jest.doMock('pg', () => {
        throw new Error("Cannot find module 'pg'");
      }, { virtual: true });

      await jest.isolateModulesAsync(async () => {
        const mod = await import('../src/redis-kill-switch');
        await expect(
          mod.createKillSwitchManagerFromEnv(
            {
              REDIS_URL: 'redis://localhost:6379',
              KILL_SWITCH_POSTGRES_URL: 'postgres://localhost/killswitch',
              KILL_SWITCH_PUBSUB_ENABLED: 'false',
            } as unknown as NodeJS.ProcessEnv,
            logger,
          ),
        ).rejects.toThrow();
      });
    } finally {
      jest.dontMock('ioredis');
      jest.dontMock('pg');
      jest.resetModules();
    }
  });

  it('throws (fail-fast) when KILL_SWITCH_POSTGRES_URL set and KILL_SWITCH_PG_TABLE has invalid name', async () => {
    jest.resetModules();
    try {
      jest.doMock('ioredis', () => {
        return class FakeRedis {
          get() { return Promise.resolve(null); }
          set() { return Promise.resolve('OK'); }
          del() { return Promise.resolve(0); }
          sadd() { return Promise.resolve(0); }
          srem() { return Promise.resolve(0); }
          smembers() { return Promise.resolve([]); }
          publish() { return Promise.resolve(0); }
          quit() { return Promise.resolve('OK'); }
          on() {}
          duplicate() { return new (this.constructor as new () => unknown)(); }
        };
      }, { virtual: true });
      jest.doMock('pg', () => ({
        Pool: class FakePg {
          connect() { return Promise.resolve({ query: () => Promise.resolve({ rows: [] }), release: () => {} }); }
          end() { return Promise.resolve(); }
        },
      }), { virtual: true });

      await jest.isolateModulesAsync(async () => {
        const mod = await import('../src/redis-kill-switch');
        await expect(
          mod.createKillSwitchManagerFromEnv(
            {
              REDIS_URL: 'redis://localhost:6379',
              KILL_SWITCH_POSTGRES_URL: 'postgres://localhost/killswitch',
              // invalid table name with SQL injection attempt
              KILL_SWITCH_PG_TABLE: "euno_ks; DROP TABLE euno_ks--",
              KILL_SWITCH_PUBSUB_ENABLED: 'false',
            } as unknown as NodeJS.ProcessEnv,
            logger,
          ),
        ).rejects.toThrow(/invalid table name/);
      });
    } finally {
      jest.dontMock('ioredis');
      jest.dontMock('pg');
      jest.resetModules();
    }
  });
});

// ── PostgresKillSwitchBackend ─────────────────────────────────────────────────

describe('PostgresKillSwitchBackend', () => {
  function makeFakePgPool(opts: {
    rows?: { entry_type: string; entry_id: string }[];
    throwOn?: 'query';
  } = {}) {
    const queries: { sql: string; params?: unknown[] }[] = [];
    const storedRows: { entry_type: string; entry_id: string }[] = [...(opts.rows ?? [])];

    const pool = {
      queries,
      storedRows,
      ended: false,
      connect() {
        const client = {
          async query(sql: string, values?: unknown[]) {
            queries.push({ sql, params: values });
            if (opts.throwOn === 'query') throw new Error('db-error');
            if (/INSERT/.test(sql) && values && values.length >= 2) {
              const [type, id] = values as [string, string];
              if (!storedRows.find((r) => r.entry_type === type && r.entry_id === id)) {
                storedRows.push({ entry_type: type, entry_id: id });
              }
            }
            if (/DELETE FROM/.test(sql) && values && values.length >= 2) {
              const [type, id] = values as [string, string];
              const idx = storedRows.findIndex((r) => r.entry_type === type && r.entry_id === id);
              if (idx !== -1) storedRows.splice(idx, 1);
            }
            if (/DELETE FROM/.test(sql) && (!values || values.length === 0)) {
              storedRows.splice(0, storedRows.length);
            }
            return { rows: storedRows, rowCount: storedRows.length };
          },
          release() {},
        };
        return Promise.resolve(client);
      },
      async end() {
        this.ended = true;
      },
    };
    return pool;
  }

  it('load() returns empty state when table is empty', async () => {
    const pool = makeFakePgPool({ rows: [] });
    const backend = new PostgresKillSwitchBackend(pool as never);
    const state = await backend.load();
    expect(state.globalKillSwitch).toBe(false);
    expect(state.killedSessions.size).toBe(0);
    expect(state.killedAgents.size).toBe(0);
    await backend.close();
  });

  it('load() reconstructs full state from DB rows', async () => {
    const pool = makeFakePgPool({
      rows: [
        { entry_type: 'global', entry_id: '' },
        { entry_type: 'session', entry_id: 'sess-1' },
        { entry_type: 'session', entry_id: 'sess-2' },
        { entry_type: 'agent', entry_id: 'agent-1' },
      ],
    });
    const backend = new PostgresKillSwitchBackend(pool as never);
    const state = await backend.load();
    expect(state.globalKillSwitch).toBe(true);
    expect(state.killedSessions.has('sess-1')).toBe(true);
    expect(state.killedSessions.has('sess-2')).toBe(true);
    expect(state.killedAgents.has('agent-1')).toBe(true);
    await backend.close();
  });

  it('activateGlobalKill() inserts a global row', async () => {
    const pool = makeFakePgPool();
    const backend = new PostgresKillSwitchBackend(pool as never);
    await backend.activateGlobalKill();
    expect(pool.storedRows.some((r) => r.entry_type === 'global' && r.entry_id === '')).toBe(true);
    await backend.close();
  });

  it('deactivateGlobalKill() removes the global row', async () => {
    const pool = makeFakePgPool({ rows: [{ entry_type: 'global', entry_id: '' }] });
    const backend = new PostgresKillSwitchBackend(pool as never);
    await backend.deactivateGlobalKill();
    expect(pool.storedRows.some((r) => r.entry_type === 'global')).toBe(false);
    await backend.close();
  });

  it('killSession() inserts a session row; reviveSession() removes it', async () => {
    const pool = makeFakePgPool();
    const backend = new PostgresKillSwitchBackend(pool as never);
    await backend.killSession('sess-x');
    expect(pool.storedRows.some((r) => r.entry_type === 'session' && r.entry_id === 'sess-x')).toBe(true);
    await backend.reviveSession('sess-x');
    expect(pool.storedRows.some((r) => r.entry_type === 'session')).toBe(false);
    await backend.close();
  });

  it('killAgent() inserts an agent row; reviveAgent() removes it', async () => {
    const pool = makeFakePgPool();
    const backend = new PostgresKillSwitchBackend(pool as never);
    await backend.killAgent('agent-z');
    expect(pool.storedRows.some((r) => r.entry_type === 'agent' && r.entry_id === 'agent-z')).toBe(true);
    await backend.reviveAgent('agent-z');
    expect(pool.storedRows.some((r) => r.entry_type === 'agent')).toBe(false);
    await backend.close();
  });

  it('resetAll() clears all rows', async () => {
    const pool = makeFakePgPool({
      rows: [
        { entry_type: 'global', entry_id: '' },
        { entry_type: 'session', entry_id: 'sess-1' },
        { entry_type: 'agent', entry_id: 'agent-1' },
      ],
    });
    const backend = new PostgresKillSwitchBackend(pool as never);
    await backend.resetAll();
    expect(pool.storedRows.length).toBe(0);
    await backend.close();
  });

  it('migrate() issues CREATE TABLE IF NOT EXISTS with the configured table name', async () => {
    const pool = makeFakePgPool();
    const backend = new PostgresKillSwitchBackend(pool as never, { table: 'my_ks' });
    await backend.migrate!();
    const ddl = pool.queries.find((q) => /CREATE TABLE IF NOT EXISTS/.test(q.sql));
    expect(ddl).toBeDefined();
    expect(ddl!.sql).toContain('my_ks');
    await backend.close();
  });

  it('close() calls pool.end()', async () => {
    const pool = makeFakePgPool();
    const backend = new PostgresKillSwitchBackend(pool as never);
    await backend.close();
    expect(pool.ended).toBe(true);
  });
});

// ── Kill-switch persistence fallback ─────────────────────────────────────────

describe('RedisKillSwitchManager persistence backend', () => {
  function makeFakePersistence(
    initialState: KillSwitchConfig = {
      globalKillSwitch: false,
      killedSessions: new Set<string>(),
      killedAgents: new Set<string>(),
    }
  ): KillSwitchPersistenceBackend & {
    writeLog: string[];
    state: KillSwitchConfig;
    failLoad: boolean;
  } {
    const state: KillSwitchConfig = {
      globalKillSwitch: initialState.globalKillSwitch,
      killedSessions: new Set(initialState.killedSessions),
      killedAgents: new Set(initialState.killedAgents),
    };
    const writeLog: string[] = [];

    return {
      state,
      writeLog,
      failLoad: false,
      async load() {
        if (this.failLoad) throw new Error('pg-load-error');
        return {
          globalKillSwitch: state.globalKillSwitch,
          killedSessions: new Set(state.killedSessions),
          killedAgents: new Set(state.killedAgents),
        };
      },
      async activateGlobalKill() {
        writeLog.push('activateGlobalKill');
        state.globalKillSwitch = true;
      },
      async deactivateGlobalKill() {
        writeLog.push('deactivateGlobalKill');
        state.globalKillSwitch = false;
      },
      async killSession(id: string) {
        writeLog.push(`killSession:${id}`);
        state.killedSessions.add(id);
      },
      async reviveSession(id: string) {
        writeLog.push(`reviveSession:${id}`);
        state.killedSessions.delete(id);
      },
      async killAgent(id: string) {
        writeLog.push(`killAgent:${id}`);
        state.killedAgents.add(id);
      },
      async reviveAgent(id: string) {
        writeLog.push(`reviveAgent:${id}`);
        state.killedAgents.delete(id);
      },
      async resetAll() {
        writeLog.push('resetAll');
        state.globalKillSwitch = false;
        state.killedSessions.clear();
        state.killedAgents.clear();
      },
      async close() {
        writeLog.push('close');
      },
    };
  }

  it('seeds from persistence backend when initial Redis refresh fails', async () => {
    const client = makeFakeClient({
      get: async () => { throw new Error('redis down'); },
    });
    const pg = makeFakePersistence({
      globalKillSwitch: true,
      killedSessions: new Set(['pg-sess']),
      killedAgents: new Set(['pg-agent']),
    });
    const mgr = new RedisKillSwitchManager(client, logger, {
      refreshIntervalMs: 0,
      persistenceBackend: pg,
    });
    await mgr.start();

    expect(mgr.isGlobalKillActive()).toBe(true);
    expect(mgr.isSessionKilled('pg-sess')).toBe(true);
    expect(mgr.isAgentKilled('pg-agent')).toBe(true);

    await mgr.close();
  });

  it('starts with empty cache when both Redis and persistence fail at startup', async () => {
    const client = makeFakeClient({
      get: async () => { throw new Error('redis down'); },
    });
    const pg = makeFakePersistence();
    pg.failLoad = true;

    const mgr = new RedisKillSwitchManager(client, logger, {
      refreshIntervalMs: 0,
      persistenceBackend: pg,
    });
    await mgr.start();
    expect(mgr.isGlobalKillActive()).toBe(false);
    await mgr.close();
  });

  it('refresh() falls back to persistence when Redis is unavailable', async () => {
    const client = makeFakeClient();
    const pg = makeFakePersistence();
    const mgr = new RedisKillSwitchManager(client, logger, {
      refreshIntervalMs: 0,
      persistenceBackend: pg,
    });
    await mgr.start();
    expect(mgr.isGlobalKillActive()).toBe(false);

    client.get = async () => { throw new Error('redis down'); };
    pg.state.globalKillSwitch = true;
    pg.state.killedSessions.add('emergency-sess');

    await mgr.refresh();

    expect(mgr.isGlobalKillActive()).toBe(true);
    expect(mgr.isSessionKilled('emergency-sess')).toBe(true);

    await mgr.close();
  });

  it('refresh() propagates error when Redis fails and no persistence is configured', async () => {
    const client = makeFakeClient({
      get: async () => { throw new Error('redis down'); },
    });
    const mgr = new RedisKillSwitchManager(client, logger, { refreshIntervalMs: 0 });
    await mgr.start().catch(() => {});
    await expect(mgr.refresh()).rejects.toThrow('redis down');
    await mgr.close();
  });

  it('dual-writes to persistence backend after successful Redis writes', async () => {
    const client = makeFakeClient();
    const pg = makeFakePersistence();
    const mgr = new RedisKillSwitchManager(client, logger, {
      refreshIntervalMs: 0,
      persistenceBackend: pg,
    });
    await mgr.start();

    mgr.activateGlobalKill();
    mgr.killSession('s1');
    mgr.killAgent('a1');
    mgr.deactivateGlobalKill();
    mgr.reviveSession('s1');
    mgr.reviveAgent('a1');
    mgr.resetAll();

    await flushMicrotasks();
    await flushMicrotasks();

    expect(pg.writeLog).toContain('activateGlobalKill');
    expect(pg.writeLog).toContain('killSession:s1');
    expect(pg.writeLog).toContain('killAgent:a1');
    expect(pg.writeLog).toContain('deactivateGlobalKill');
    expect(pg.writeLog).toContain('reviveSession:s1');
    expect(pg.writeLog).toContain('reviveAgent:a1');
    expect(pg.writeLog).toContain('resetAll');

    await mgr.close();
  });

  it('does NOT dual-write when the Redis write fails (fail-closed)', async () => {
    const client = makeFakeClient({
      sadd: async () => { throw new Error('redis down'); },
    });
    const pg = makeFakePersistence();
    const mgr = new RedisKillSwitchManager(client, logger, {
      refreshIntervalMs: 0,
      persistenceBackend: pg,
    });
    await mgr.start();

    mgr.killSession('sess-broken');
    await flushMicrotasks();

    expect(pg.writeLog).not.toContain('killSession:sess-broken');
    expect(mgr.isSessionKilled('sess-broken')).toBe(false);

    await mgr.close();
  });

  it('persistence write failure does not fail the overall kill operation', async () => {
    const client = makeFakeClient();
    const pg = makeFakePersistence();
    pg.killSession = async () => { throw new Error('pg-error'); };

    const mgr = new RedisKillSwitchManager(client, logger, {
      refreshIntervalMs: 0,
      persistenceBackend: pg,
    });
    await mgr.start();

    mgr.killSession('sess-pg-fail');
    await flushMicrotasks();

    expect(mgr.isSessionKilled('sess-pg-fail')).toBe(true);
    expect(client.store.sets.get('killswitch:killed_sessions')?.has('sess-pg-fail')).toBe(true);

    await mgr.close();
  });

  it('close() also closes the persistence backend', async () => {
    const client = makeFakeClient();
    const pg = makeFakePersistence();
    const mgr = new RedisKillSwitchManager(client, logger, {
      refreshIntervalMs: 0,
      persistenceBackend: pg,
    });
    await mgr.start();
    await mgr.close();
    expect(pg.writeLog).toContain('close');
  });
});

// ── PostgresKillSwitchBackend table name validation ───────────────────────────

describe('PostgresKillSwitchBackend table name validation', () => {
  function makeFakePgPool() {
    return {
      connect() {
        return Promise.resolve({
          query: () => Promise.resolve({ rows: [], rowCount: 0 }),
          release() {},
        });
      },
      async end() {},
    };
  }

  it('accepts valid simple identifiers and schema-qualified names', () => {
    expect(() => new PostgresKillSwitchBackend(makeFakePgPool() as never, { table: 'euno_kill_switch_entries' })).not.toThrow();
    expect(() => new PostgresKillSwitchBackend(makeFakePgPool() as never, { table: 'ks' })).not.toThrow();
    expect(() => new PostgresKillSwitchBackend(makeFakePgPool() as never, { table: 'public.euno_kill_switch_entries' })).not.toThrow();
  });

  it('throws on table names that would allow SQL injection', () => {
    expect(() => new PostgresKillSwitchBackend(makeFakePgPool() as never, { table: 'ks; DROP TABLE ks--' })).toThrow(/invalid table name/);
    expect(() => new PostgresKillSwitchBackend(makeFakePgPool() as never, { table: '' })).toThrow(/invalid table name/);
    expect(() => new PostgresKillSwitchBackend(makeFakePgPool() as never, { table: '1invalid' })).toThrow(/invalid table name/);
    expect(() => new PostgresKillSwitchBackend(makeFakePgPool() as never, { table: 'ks-with-dashes' })).toThrow(/invalid table name/);
  });
});

// ── Persistence write ordering ────────────────────────────────────────────────

describe('RedisKillSwitchManager persistence write ordering', () => {
  it('applies Postgres writes in the same order as Redis writes even when I/O durations differ', async () => {
    const client = makeFakeClient();
    const writeOrder: string[] = [];

    // Construct a persistence backend where the first write is slow and
    // the second write is instant.  Without the `persistenceTail`
    // serialization chain, the second write would overtake the first.
    const pg: KillSwitchPersistenceBackend = {
      load: async () => ({
        globalKillSwitch: false,
        killedSessions: new Set<string>(),
        killedAgents: new Set<string>(),
      }),
      activateGlobalKill: async () => {},
      deactivateGlobalKill: async () => {},
      killSession: async (id: string) => {
        // Deliberately slow to create the overtaking window
        await new Promise<void>((r) => setTimeout(r, 20));
        writeOrder.push(`kill:${id}`);
      },
      reviveSession: async (id: string) => {
        // Instant write — overtakes killSession without serialization
        writeOrder.push(`revive:${id}`);
      },
      killAgent: async () => {},
      reviveAgent: async () => {},
      resetAll: async () => {},
      close: async () => {},
    };

    const mgr = new RedisKillSwitchManager(client, logger, {
      refreshIntervalMs: 0,
      persistenceBackend: pg,
    });
    await mgr.start();

    mgr.killSession('target');
    mgr.reviveSession('target');

    // Wait long enough for both writes to settle (kill takes 20 ms)
    await new Promise<void>((r) => setTimeout(r, 100));

    // With serialization: kill arrives in Postgres before revive.
    // Without serialization: revive would arrive first, leaving a
    // stale kill row after revive completes.
    const killIdx = writeOrder.indexOf('kill:target');
    const reviveIdx = writeOrder.indexOf('revive:target');
    expect(killIdx).toBeGreaterThanOrEqual(0);
    expect(reviveIdx).toBeGreaterThanOrEqual(0);
    expect(killIdx).toBeLessThan(reviveIdx);

    await mgr.close();
  });
});
