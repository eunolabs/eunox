/**
 * Tests for RedisKillSwitchManager and createKillSwitchManagerFromEnv.
 */

import { createLogger } from '../src/logger';
import { DefaultKillSwitchManager } from '../src/kill-switch';
import {
  RedisKillSwitchClient,
  RedisKillSwitchManager,
  RedisKillSwitchSubscriber,
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
});
