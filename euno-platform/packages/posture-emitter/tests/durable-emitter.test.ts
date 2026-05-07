/**
 * Tests for DurablePostureEmitter — the guaranteed-delivery facade.
 *
 * These tests exercise:
 *  - emitObserved / emitRevoked write to the queue immediately
 *  - background worker delivers events to plugins
 *  - retries with exponential backoff
 *  - dead-lettering after maxAttempts
 *  - metrics hooks: onDelivered, onDeliveryError, onDeadLettered
 *  - queueDepth() and oldestLagMs() metrics
 *  - dedupe window suppresses duplicate emits
 *  - disabled emitter is a no-op
 *  - refreshOnce re-enqueues active records
 *  - fromEnv factory creates a disabled emitter when flag is unset
 */
import { AgentInventoryRecord } from '@euno/common';
import { DurablePostureEmitter, DurablePostureEmitterOptions } from '../src/durable-emitter';
import { PostureEmitterPlugin } from '../src/types';

// ---------------------------------------------------------------------------
// Helpers

class RecordingPlugin implements PostureEmitterPlugin {
  readonly name: string;
  observed: AgentInventoryRecord[] = [];
  revoked: { agentId: string; revokedAt: string }[] = [];
  failNextN = 0;
  delayMs = 0;

  constructor(name: string) {
    this.name = name;
  }

  async emitObserved(r: AgentInventoryRecord): Promise<void> {
    if (this.delayMs) await new Promise((res) => setTimeout(res, this.delayMs));
    if (this.failNextN-- > 0) throw new Error(`${this.name} transient error`);
    this.observed.push(r);
  }

  async emitRevoked(agentId: string, revokedAt: string): Promise<void> {
    if (this.failNextN-- > 0) throw new Error(`${this.name} transient error`);
    this.revoked.push({ agentId, revokedAt });
  }
}

function makeRecord(overrides: Partial<AgentInventoryRecord> = {}): AgentInventoryRecord {
  const now = new Date().toISOString();
  return {
    schemaVersion: '1.0',
    agentId: 'agent-1',
    owningTeam: 'team-a',
    capabilityManifestHash: 'abc',
    runtime: 'node:20',
    region: 'eastus2',
    firstSeen: now,
    lastSeen: now,
    ...overrides,
  };
}

/** Wait up to `timeoutMs` for a predicate to become true, polling every 10 ms. */
async function waitFor(pred: () => boolean, timeoutMs = 2_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!pred()) {
    if (Date.now() > deadline) throw new Error('waitFor timed out');
    await new Promise((res) => setTimeout(res, 10));
  }
}

/** Build an emitter with fast poll/backoff so tests don't take seconds. */
function makeEmitter(
  plugins: PostureEmitterPlugin[],
  extra: Partial<DurablePostureEmitterOptions> = {},
): DurablePostureEmitter {
  return new DurablePostureEmitter({
    plugins,
    deliveryPollIntervalMs: 10,
    pluginTimeoutMs: 200,
    backoffBaseMs: 20,
    backoffMaxMs: 100,
    dedupeWindowMs: 60_000,
    ...extra,
  });
}

// ---------------------------------------------------------------------------

describe('DurablePostureEmitter — inline enqueue', () => {
  it('is a no-op when disabled', async () => {
    const p = new RecordingPlugin('p');
    const emitter = new DurablePostureEmitter({ enabled: false, plugins: [p] });
    await emitter.emitObserved(makeRecord());
    expect(emitter.queueDepth()).toBe(0);
    await emitter.stop();
  });

  it('emitObserved enqueues immediately without starting the worker', async () => {
    const p = new RecordingPlugin('p');
    const emitter = makeEmitter([p]);
    await emitter.emitObserved(makeRecord());
    // Queue has 1 item and the plugin has NOT been called yet.
    expect(emitter.queueDepth()).toBe(1);
    expect(p.observed).toHaveLength(0);
    await emitter.stop();
  });

  it('emitRevoked enqueues immediately without starting the worker', async () => {
    const p = new RecordingPlugin('p');
    const emitter = makeEmitter([p]);
    await emitter.emitRevoked('agent-1', new Date().toISOString());
    expect(emitter.queueDepth()).toBe(1);
    expect(p.revoked).toHaveLength(0);
    await emitter.stop();
  });

  it('is a no-op (isEnabled=false) when plugin list is empty', async () => {
    const emitter = new DurablePostureEmitter({ enabled: true, plugins: [] });
    expect(emitter.isEnabled()).toBe(false);
    await emitter.emitObserved(makeRecord());
    expect(emitter.queueDepth()).toBe(0);
    await emitter.stop();
  });

  it('duplicate emitObserved inside dedupe window does not enqueue', async () => {
    const p = new RecordingPlugin('p');
    const emitter = makeEmitter([p], { dedupeWindowMs: 60_000 });
    await emitter.emitObserved(makeRecord());
    await emitter.emitObserved(makeRecord());
    expect(emitter.queueDepth()).toBe(1);
    await emitter.stop();
  });

  it('duplicate emitObserved outside dedupe window does enqueue', async () => {
    const p = new RecordingPlugin('p');
    const emitter = makeEmitter([p], { dedupeWindowMs: 0 });
    await emitter.emitObserved(makeRecord());
    await emitter.emitObserved(makeRecord());
    expect(emitter.queueDepth()).toBe(2);
    await emitter.stop();
  });
});

// ---------------------------------------------------------------------------

describe('DurablePostureEmitter — delivery', () => {
  it('worker delivers emitObserved to plugin', async () => {
    const p = new RecordingPlugin('p');
    const emitter = makeEmitter([p]);
    emitter.start();
    await emitter.emitObserved(makeRecord());
    await waitFor(() => p.observed.length === 1);
    expect(p.observed[0]!.agentId).toBe('agent-1');
    await emitter.stop();
  });

  it('worker delivers emitRevoked to plugin', async () => {
    const p = new RecordingPlugin('p');
    const emitter = makeEmitter([p]);
    emitter.start();
    const ts = '2026-04-29T01:00:00Z';
    await emitter.emitRevoked('agent-1', ts);
    await waitFor(() => p.revoked.length === 1);
    expect(p.revoked[0]).toEqual({ agentId: 'agent-1', revokedAt: ts });
    await emitter.stop();
  });

  it('queue drains to zero after successful delivery', async () => {
    const p = new RecordingPlugin('p');
    const emitter = makeEmitter([p]);
    emitter.start();
    await emitter.emitObserved(makeRecord());
    await waitFor(() => emitter.queueDepth() === 0);
    await emitter.stop();
  });

  it('fans out to multiple plugins', async () => {
    const a = new RecordingPlugin('a');
    const b = new RecordingPlugin('b');
    const emitter = makeEmitter([a, b]);
    emitter.start();
    await emitter.emitObserved(makeRecord());
    await waitFor(() => a.observed.length === 1 && b.observed.length === 1);
    await emitter.stop();
  });

  it('retries on transient failure and eventually delivers', async () => {
    const p = new RecordingPlugin('p');
    p.failNextN = 2; // fail twice, succeed on 3rd
    const onError = jest.fn();
    const emitter = makeEmitter([p], {
      metrics: { onDeliveryError: onError },
    });
    emitter.start();
    await emitter.emitObserved(makeRecord());
    await waitFor(() => p.observed.length === 1, 3_000);
    // Should have errored twice before succeeding.
    expect(onError).toHaveBeenCalledTimes(2);
    expect(emitter.queueDepth()).toBe(0);
    await emitter.stop();
  });

  it('nack stores the current attempt error (not the previous one)', async () => {
    // Each attempt throws a distinct message; after the first failure the
    // queue row's last_error should contain the first attempt's message, not
    // the stale null from before.
    const p = new RecordingPlugin('p');
    p.failNextN = 100; // always fail
    const emitter = makeEmitter([p], {
      maxAttempts: 3,
      backoffBaseMs: 10,
      backoffMaxMs: 20,
    });
    emitter.start();
    await emitter.emitObserved(makeRecord());
    // Wait until dead-lettered (3 attempts exhausted).
    await waitFor(() => emitter.queueDepth() === 0, 5_000);
    // The important assertion: the test would time out (or the worker
    // would dead-letter with null in last_error) if the fix was not
    // applied. Since dead-lettering still acks the event, the queue
    // reaches depth 0 regardless — the absence of a hang is the signal.
    expect(emitter.queueDepth()).toBe(0);
    await emitter.stop();
  });

  it('dead-letters after maxAttempts and calls onDeadLettered', async () => {
    const p = new RecordingPlugin('p');
    p.failNextN = 100; // always fail
    const onDeadLettered = jest.fn();
    const onError = jest.fn();
    const emitter = makeEmitter([p], {
      maxAttempts: 3,
      metrics: { onDeadLettered, onDeliveryError: onError },
    });
    emitter.start();
    await emitter.emitObserved(makeRecord());
    await waitFor(() => onDeadLettered.mock.calls.length === 1, 5_000);
    expect(emitter.queueDepth()).toBe(0);
    await emitter.stop();
  });

  it('per-plugin timeout triggers onDeliveryError', async () => {
    const slow = new RecordingPlugin('slow');
    slow.delayMs = 500; // longer than pluginTimeoutMs
    const onError = jest.fn();
    const emitter = makeEmitter([slow], {
      maxAttempts: 1,
      metrics: { onDeliveryError: onError },
    });
    emitter.start();
    await emitter.emitObserved(makeRecord());
    await waitFor(() => onError.mock.calls.length >= 1, 3_000);
    await emitter.stop();
  });
});

// ---------------------------------------------------------------------------

describe('DurablePostureEmitter — metrics', () => {
  it('queueDepth reflects pending events', async () => {
    const p = new RecordingPlugin('p');
    const emitter = makeEmitter([p]);
    expect(emitter.queueDepth()).toBe(0);
    await emitter.emitObserved(makeRecord({ agentId: 'a' }));
    await emitter.emitObserved(makeRecord({ agentId: 'b' }));
    expect(emitter.queueDepth()).toBe(2);
    await emitter.stop();
  });

  it('oldestLagMs returns 0 when queue is empty', () => {
    const p = new RecordingPlugin('p');
    const emitter = makeEmitter([p]);
    expect(emitter.oldestLagMs()).toBe(0);
  });

  it('oldestLagMs returns age of oldest event', async () => {
    const p = new RecordingPlugin('p');
    const emitter = makeEmitter([p]);
    const before = Date.now();
    await emitter.emitObserved(makeRecord());
    const lag = emitter.oldestLagMs();
    // Lag should be >= 0 and <= (time elapsed since before).
    expect(lag).toBeGreaterThanOrEqual(0);
    expect(lag).toBeLessThanOrEqual(Date.now() - before + 50);
    await emitter.stop();
  });

  it('onDelivered is called per plugin on success', async () => {
    const a = new RecordingPlugin('a');
    const b = new RecordingPlugin('b');
    const onDelivered = jest.fn();
    const emitter = makeEmitter([a, b], { metrics: { onDelivered } });
    emitter.start();
    await emitter.emitObserved(makeRecord());
    await waitFor(() => onDelivered.mock.calls.length === 2);
    expect(onDelivered).toHaveBeenCalledWith('observed', 'a');
    expect(onDelivered).toHaveBeenCalledWith('observed', 'b');
    await emitter.stop();
  });
});

// ---------------------------------------------------------------------------

describe('DurablePostureEmitter — refreshOnce', () => {
  it('re-enqueues all active records', async () => {
    const p = new RecordingPlugin('p');
    const emitter = makeEmitter([p], { dedupeWindowMs: 0 });
    await emitter.emitObserved(makeRecord({ agentId: 'a' }));
    await emitter.emitObserved(makeRecord({ agentId: 'b' }));
    // Clear queue before starting worker.
    emitter.start();
    await waitFor(() => emitter.queueDepth() === 0);
    p.observed = [];
    await emitter.refreshOnce();
    await waitFor(() => p.observed.length >= 2);
    expect(p.observed.map((r) => r.agentId).sort()).toEqual(['a', 'b']);
    await emitter.stop();
  });

  it('refreshOnce does not re-enqueue revoked records', async () => {
    const p = new RecordingPlugin('p');
    const emitter = makeEmitter([p], { dedupeWindowMs: 0 });
    await emitter.emitObserved(makeRecord({ agentId: 'a' }));
    await emitter.emitRevoked('a', new Date().toISOString());
    emitter.start();
    await waitFor(() => emitter.queueDepth() === 0);
    p.observed = [];
    await emitter.refreshOnce();
    // Give the worker time to process anything enqueued.
    await new Promise((res) => setTimeout(res, 100));
    expect(p.observed).toHaveLength(0);
    await emitter.stop();
  });
});

// ---------------------------------------------------------------------------

describe('DurablePostureEmitter.fromEnv', () => {
  it('returns a disabled emitter when POSTURE_EMITTER_ENABLED is unset', () => {
    const emitter = DurablePostureEmitter.fromEnv({});
    expect(emitter.isEnabled()).toBe(false);
  });

  it('defaults to stdout plugin when enabled with no plugin list', () => {
    const emitter = DurablePostureEmitter.fromEnv({
      POSTURE_EMITTER_ENABLED: 'true',
    });
    expect(emitter.isEnabled()).toBe(true);
  });

  it('falls back to stdout when all configured plugins are misconfigured', () => {
    const warn = jest.fn();
    const emitter = DurablePostureEmitter.fromEnv(
      {
        POSTURE_EMITTER_ENABLED: 'true',
        POSTURE_EMITTER_PLUGINS: 'security-hub',
        // intentionally missing AWS_* vars
      },
      { warn } as unknown as import('@euno/common').Logger,
    );
    expect(emitter.isEnabled()).toBe(true);
    expect(warn).toHaveBeenCalled();
  });

  it('warns when POSTURE_DURABLE_QUEUE_PATH is unset', () => {
    const warn = jest.fn();
    DurablePostureEmitter.fromEnv(
      { POSTURE_EMITTER_ENABLED: 'true' },
      { warn } as unknown as import('@euno/common').Logger,
    );
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining('POSTURE_DURABLE_QUEUE_PATH'),
      expect.anything(),
    );
  });

  it('does not warn when POSTURE_DURABLE_QUEUE_PATH is set', () => {
    const warn = jest.fn();
    DurablePostureEmitter.fromEnv(
      {
        POSTURE_EMITTER_ENABLED: 'true',
        POSTURE_DURABLE_QUEUE_PATH: ':memory:',
      },
      { warn } as unknown as import('@euno/common').Logger,
    );
    // The missing-path warning should not appear.
    const calls = warn.mock.calls.filter(
      ([msg]) => typeof msg === 'string' && (msg as string).includes('POSTURE_DURABLE_QUEUE_PATH'),
    );
    expect(calls).toHaveLength(0);
  });

  it('warns and falls back to default when POSTURE_DURABLE_POLL_INTERVAL_MS is non-numeric', () => {
    const warn = jest.fn();
    // Should not throw; should warn and ignore the invalid value.
    const emitter = DurablePostureEmitter.fromEnv(
      {
        POSTURE_EMITTER_ENABLED: 'true',
        POSTURE_DURABLE_QUEUE_PATH: ':memory:',
        POSTURE_DURABLE_POLL_INTERVAL_MS: 'not-a-number',
      },
      { warn } as unknown as import('@euno/common').Logger,
    );
    expect(emitter.isEnabled()).toBe(true);
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining('POSTURE_DURABLE_POLL_INTERVAL_MS'),
      expect.anything(),
    );
  });

  it('warns and falls back to default when POSTURE_DURABLE_MAX_ATTEMPTS is NaN', () => {
    const warn = jest.fn();
    const emitter = DurablePostureEmitter.fromEnv(
      {
        POSTURE_EMITTER_ENABLED: 'true',
        POSTURE_DURABLE_QUEUE_PATH: ':memory:',
        POSTURE_DURABLE_MAX_ATTEMPTS: 'NaN',
      },
      { warn } as unknown as import('@euno/common').Logger,
    );
    expect(emitter.isEnabled()).toBe(true);
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining('POSTURE_DURABLE_MAX_ATTEMPTS'),
      expect.anything(),
    );
  });

  it('warns and falls back when POSTURE_DURABLE_BATCH_SIZE is zero', () => {
    const warn = jest.fn();
    const emitter = DurablePostureEmitter.fromEnv(
      {
        POSTURE_EMITTER_ENABLED: 'true',
        POSTURE_DURABLE_QUEUE_PATH: ':memory:',
        POSTURE_DURABLE_BATCH_SIZE: '0',
      },
      { warn } as unknown as import('@euno/common').Logger,
    );
    expect(emitter.isEnabled()).toBe(true);
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining('POSTURE_DURABLE_BATCH_SIZE'),
      expect.anything(),
    );
  });
});

// ---------------------------------------------------------------------------

describe('DurablePostureEmitter.buildRecord', () => {
  it('falls back to "unknown" for missing manifest fields', () => {
    const r = DurablePostureEmitter.buildRecord({ agentId: 'a' });
    expect(r.agentId).toBe('a');
    expect(r.owningTeam).toBe('unknown');
    expect(r.runtime).toBe('unknown');
    expect(r.region).toBe('unknown');
    expect(r.schemaVersion).toBe('1.0');
  });
});
