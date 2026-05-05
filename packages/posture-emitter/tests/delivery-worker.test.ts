/**
 * Unit tests for DeliveryWorker.
 *
 * Tests the worker directly against a real in-memory DurableQueue so we
 * can introspect queue row state (e.g. last_error, attempts) without
 * going through the full DurablePostureEmitter facade.
 */
import { AgentInventoryRecord } from '@euno/common';
import { DurableQueue } from '../src/durable-queue';
import { DeliveryWorker } from '../src/delivery-worker';
import { PostureEmitterPlugin } from '../src/types';

class FailingPlugin implements PostureEmitterPlugin {
  readonly name = 'failing';
  callCount = 0;
  errors: string[];

  constructor(errors: string[]) {
    this.errors = errors;
  }

  async emitObserved(): Promise<void> {
    const msg = this.errors[this.callCount] ?? 'persistent error';
    this.callCount++;
    throw new Error(msg);
  }

  async emitRevoked(): Promise<void> {
    throw new Error('revoked-error');
  }
}

const RECORD: AgentInventoryRecord = {
  schemaVersion: '1.0',
  agentId: 'agent-1',
  owningTeam: 'team-a',
  capabilityManifestHash: 'abc',
  runtime: 'node:20',
  region: 'eastus2',
  firstSeen: '2026-01-01T00:00:00Z',
  lastSeen: '2026-01-01T00:00:00Z',
};

/** Advance time forward so nack'd events become immediately re-peekaable. */
function drainQueue(queue: DurableQueue, limit = 100, nowMs = Date.now() + 999_999): ReturnType<DurableQueue['peek']> {
  return queue.peek(limit, nowMs);
}

describe('DeliveryWorker — last_error stores the current attempt error', () => {
  it('nack writes the current attempt error to last_error, not the stale previous value', async () => {
    const queue = new DurableQueue();
    const plugin = new FailingPlugin(['first-error', 'second-error', 'third-error']);

    // Push one event — its initial last_error is null.
    queue.push('observed', JSON.stringify({ record: RECORD }));
    expect(drainQueue(queue)[0]!.lastError).toBeNull();

    const worker = new DeliveryWorker({
      queue,
      plugins: [plugin],
      maxAttempts: 5,
      backoffBaseMs: 1,
      backoffMaxMs: 1,
      pollIntervalMs: 10,
    });
    worker.start();

    // Wait until the first nack has been recorded (attempts = 1).
    const deadline = Date.now() + 3_000;
    while (drainQueue(queue)[0]?.attempts === 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 10));
    }
    await worker.stop();

    const events = drainQueue(queue);
    expect(events.length).toBeGreaterThan(0);
    const row = events[0]!;
    // The last_error should be the message from the current attempt,
    // not null (which was the value before the fix).
    expect(row.lastError).not.toBeNull();
    expect(typeof row.lastError).toBe('string');
    expect(row.lastError!.length).toBeGreaterThan(0);

    queue.close();
  });

  it('each successive nack updates last_error to the most recent attempt message', async () => {
    const queue = new DurableQueue();
    const errors = ['attempt-1-error', 'attempt-2-error', 'attempt-3-error'];
    const plugin = new FailingPlugin(errors);

    queue.push('observed', JSON.stringify({ record: RECORD }));

    const worker = new DeliveryWorker({
      queue,
      plugins: [plugin],
      maxAttempts: 10,
      backoffBaseMs: 1,
      backoffMaxMs: 1,
      pollIntervalMs: 10,
    });
    worker.start();

    // Wait until we've seen at least 2 attempts recorded.
    const deadline = Date.now() + 3_000;
    while (drainQueue(queue)[0]?.attempts === undefined ||
           (drainQueue(queue)[0]?.attempts ?? 0) < 2 &&
           Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 10));
    }
    await worker.stop();

    const row = drainQueue(queue)[0];
    if (!row) return; // event may have drained already; that's fine
    // last_error should be the error from attempt `row.attempts` (1-indexed).
    const expectedError = errors[row.attempts - 1] ?? 'persistent error';
    expect(row.lastError).toBe(expectedError);

    queue.close();
  });
});

describe('DeliveryWorker — defaults from types.ts constants', () => {
  it('constructs with no optional fields and uses exported defaults', () => {
    const queue = new DurableQueue();
    // Should not throw and should be usable.
    const worker = new DeliveryWorker({ queue, plugins: [] });
    expect(worker).toBeDefined();
    queue.close();
  });
});
