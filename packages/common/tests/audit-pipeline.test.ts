/**
 * Tests for AuditPipeline (R-9, addresses I-21).
 */

import { AuditPipeline, createAuditPipeline, DropReason } from '../src/audit-pipeline';
import { createAuditEvidence } from '../src/evidence';
import { EvidenceSigner } from '../src/runtime';
import { AuditEvidence, SignedAuditEvidence } from '../src/types';

function makeEvidence(i: number): AuditEvidence {
  // Build through the canonical helper so test data matches what
  // `EnforcementEngine` actually feeds into the pipeline at runtime.
  const ev = createAuditEvidence({
    sessionId: 'sess-1',
    userId: 'user-1',
    tool: 'tool-1',
    args: { i },
    agentId: 'agent-1',
    resource: 'tool://demo',
    action: 'read',
    capabilityId: `cap-${i}`,
    decision: 'allow',
    policyVersion: '1.0.0',
  });
  // Force a deterministic id so tests can assert ordering by id.
  return { ...ev, id: `ev-${i}` };
}

/** Signer that records every call and resolves with a deterministic signature. */
class RecordingSigner implements EvidenceSigner {
  public readonly seen: AuditEvidence[] = [];
  public delayMs = 0;
  public failOnIds = new Set<string>();

  async signEvidence(evidence: AuditEvidence): Promise<SignedAuditEvidence> {
    if (this.delayMs > 0) {
      await new Promise((r) => setTimeout(r, this.delayMs));
    }
    if (this.failOnIds.has(evidence.id)) {
      throw new Error(`signer fail on ${evidence.id}`);
    }
    this.seen.push(evidence);
    return {
      ...evidence,
      signature: 'sig-' + evidence.id,
      keyId: 'k1',
      algorithm: 'RS256',
    };
  }

  async verifyEvidence(): Promise<boolean> {
    return true;
  }
}

/** Wait until predicate returns true, polling on the microtask queue. */
async function waitFor(pred: () => boolean, timeoutMs = 1000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!pred()) {
    if (Date.now() > deadline) {
      throw new Error('waitFor timed out');
    }
    await new Promise((r) => setTimeout(r, 5));
  }
}

describe('AuditPipeline', () => {
  it('signs enqueued evidence asynchronously without blocking the producer', async () => {
    const signer = new RecordingSigner();
    signer.delayMs = 25;
    const pipeline = createAuditPipeline({ signer, workers: 2 });

    // The enqueue promise must resolve essentially immediately even when
    // the signer is slow — the contract that backs the R-9 latency claim.
    const start = Date.now();
    await pipeline.enqueue(makeEvidence(1));
    await pipeline.enqueue(makeEvidence(2));
    const enqueueElapsed = Date.now() - start;
    expect(enqueueElapsed).toBeLessThan(20);

    await waitFor(() => signer.seen.length === 2);
    expect(signer.seen.map((e) => e.id).sort()).toEqual(['ev-1', 'ev-2']);

    await pipeline.drain();
    expect(pipeline.signedCount()).toBe(2);
    expect(pipeline.droppedCount()).toBe(0);
  });

  it('drops oldest with metric when buffer is full under drop_oldest_with_metric policy', async () => {
    const signer = new RecordingSigner();
    // Hold the worker hostage so the buffer can actually fill before
    // anything drains.
    signer.delayMs = 1000;
    const drops: Array<{ count: number; reason: DropReason }> = [];
    const pipeline = new AuditPipeline({
      signer,
      maxSize: 2,
      workers: 1,
      maxBatchSize: 1,
      backpressure: 'drop_oldest_with_metric',
      onDropped: (count, reason) => drops.push({ count, reason }),
    });
    pipeline.start();

    await pipeline.enqueue(makeEvidence(1)); // becomes in-flight (worker grabs it)
    // Give the worker a tick to pull the first item.
    await new Promise((r) => setTimeout(r, 5));
    await pipeline.enqueue(makeEvidence(2)); // goes in queue
    await pipeline.enqueue(makeEvidence(3)); // goes in queue (queue depth 2)
    await pipeline.enqueue(makeEvidence(4)); // queue full -> drop ev-2 (oldest)

    expect(pipeline.droppedCount()).toBe(1);
    expect(drops).toEqual([{ count: 1, reason: 'queue_full' }]);

    // Speed up the signer for a clean shutdown.
    signer.delayMs = 0;
    await pipeline.drain(2000);
  });

  it('blocks the producer when policy=block and buffer is full', async () => {
    const signer = new RecordingSigner();
    signer.delayMs = 30;
    const pipeline = new AuditPipeline({
      signer,
      maxSize: 1,
      workers: 1,
      maxBatchSize: 1,
      backpressure: 'block',
    });
    pipeline.start();

    // ev-1 goes to the worker immediately (queue empty after pull).
    await pipeline.enqueue(makeEvidence(1));
    // Wait until the worker has actually pulled ev-1 so the queue is empty
    // again, then fill it with ev-2.
    await waitFor(() => pipeline.queueDepth() === 0, 200);
    await pipeline.enqueue(makeEvidence(2));
    expect(pipeline.queueDepth()).toBe(1);

    // ev-3 must block until ev-1 finishes signing and the worker pulls
    // ev-2, freeing the slot.
    const start = Date.now();
    let resolved = false;
    const p = pipeline.enqueue(makeEvidence(3)).then(() => {
      resolved = true;
    });
    // Give the event loop a tick — the producer must STILL be parked.
    await new Promise((r) => setTimeout(r, 5));
    expect(resolved).toBe(false);

    await p;
    const elapsed = Date.now() - start;
    expect(elapsed).toBeGreaterThanOrEqual(20);
    expect(pipeline.droppedCount()).toBe(0);

    await pipeline.drain(2000);
    expect(signer.seen.map((e) => e.id).sort()).toEqual(['ev-1', 'ev-2', 'ev-3']);
  });

  it('drops items that exceed maxAgeMs while waiting in the queue', async () => {
    const signer = new RecordingSigner();
    signer.delayMs = 50;
    const drops: Array<{ count: number; reason: DropReason }> = [];
    const pipeline = new AuditPipeline({
      signer,
      maxSize: 16,
      workers: 1,
      maxBatchSize: 4,
      maxAgeMs: 10,
      onDropped: (count, reason) => drops.push({ count, reason }),
    });
    pipeline.start();

    await pipeline.enqueue(makeEvidence(1)); // grabbed immediately
    await pipeline.enqueue(makeEvidence(2)); // sits in queue
    await pipeline.enqueue(makeEvidence(3)); // sits in queue
    // Wait long enough for ev-2/ev-3 to age out before the worker is free.
    await new Promise((r) => setTimeout(r, 80));
    await pipeline.drain(2000);

    expect(signer.seen.map((e) => e.id)).toEqual(['ev-1']);
    const aged = drops.filter((d) => d.reason === 'aged_out').reduce((a, b) => a + b.count, 0);
    expect(aged).toBe(2);
  });

  it('isolates signEvidence rejections via onSignError and keeps draining', async () => {
    const signer = new RecordingSigner();
    signer.failOnIds.add('ev-2');
    const errors: string[] = [];
    const pipeline = createAuditPipeline({
      signer,
      workers: 1,
      onSignError: (err, ev) => errors.push(`${ev.id}:${(err as Error).message}`),
    });

    await pipeline.enqueue(makeEvidence(1));
    await pipeline.enqueue(makeEvidence(2));
    await pipeline.enqueue(makeEvidence(3));
    await pipeline.drain(2000);

    expect(signer.seen.map((e) => e.id)).toEqual(['ev-1', 'ev-3']);
    expect(errors).toEqual(['ev-2:signer fail on ev-2']);
    expect(pipeline.signErrorCount()).toBe(1);
    expect(pipeline.signedCount()).toBe(2);
  });

  it('drops new evidence after drain() and counts it', async () => {
    const signer = new RecordingSigner();
    const pipeline = createAuditPipeline({ signer });
    await pipeline.enqueue(makeEvidence(1));
    await pipeline.drain();
    await pipeline.enqueue(makeEvidence(2));
    expect(pipeline.droppedCount()).toBe(1);
    expect(signer.seen.map((e) => e.id)).toEqual(['ev-1']);
  });

  it('counts queued items as drops when drain() times out', async () => {
    const signer = new RecordingSigner();
    signer.delayMs = 200;
    const drops: Array<{ count: number; reason: DropReason }> = [];
    const pipeline = createAuditPipeline({
      signer,
      workers: 1,
      maxBatchSize: 1,
      onDropped: (count, reason) => drops.push({ count, reason }),
    });

    await pipeline.enqueue(makeEvidence(1));
    await pipeline.enqueue(makeEvidence(2));
    await pipeline.enqueue(makeEvidence(3));
    // Tight deadline — only ev-1 has time to sign.
    await pipeline.drain(20);

    const totalDropped = drops.reduce((a, b) => a + b.count, 0);
    expect(totalDropped).toBeGreaterThan(0);
    expect(pipeline.droppedCount()).toBe(totalDropped);
  });

  it('start() is idempotent', () => {
    const signer = new RecordingSigner();
    const pipeline = new AuditPipeline({ signer });
    pipeline.start();
    pipeline.start(); // must not spawn extra workers / throw
    return pipeline.drain();
  });

  it('caps parked waiters under block policy and drops beyond maxWaiters', async () => {
    // Hold the worker hostage so the buffer fills and the next two
    // producers must park as waiters. With maxWaiters=2 the third
    // parked producer must be dropped instead of growing the list.
    const signer = new RecordingSigner();
    signer.delayMs = 1000;
    const drops: Array<{ count: number; reason: DropReason }> = [];
    const pipeline = new AuditPipeline({
      signer,
      maxSize: 1,
      workers: 1,
      maxBatchSize: 1,
      backpressure: 'block',
      maxWaiters: 2,
      onDropped: (count, reason) => drops.push({ count, reason }),
    });
    pipeline.start();

    // ev-1 grabbed by the worker (in-flight under the slow signer).
    await pipeline.enqueue(makeEvidence(1));
    // Wait for the worker to actually pull ev-1 so the buffer is empty
    // again, then refill it with ev-2.
    await new Promise((r) => setTimeout(r, 5));
    await pipeline.enqueue(makeEvidence(2));

    // ev-3 and ev-4 must park (buffer full + 2 waiter slots).
    let p3Resolved = false;
    let p4Resolved = false;
    const p3 = pipeline.enqueue(makeEvidence(3)).then(() => (p3Resolved = true));
    const p4 = pipeline.enqueue(makeEvidence(4)).then(() => (p4Resolved = true));
    await new Promise((r) => setTimeout(r, 5));
    expect(p3Resolved).toBe(false);
    expect(p4Resolved).toBe(false);

    // ev-5 must be dropped immediately (waiter cap reached).
    await pipeline.enqueue(makeEvidence(5));
    expect(pipeline.droppedCount()).toBe(1);
    expect(drops).toEqual([{ count: 1, reason: 'queue_full' }]);

    // Speed up the signer for clean shutdown so the parked producers
    // resolve through the drain path.
    signer.delayMs = 0;
    await pipeline.drain(2000);
    await Promise.all([p3, p4]);
  });

  it('drain(timeoutMs) returns even when a worker is stuck in signEvidence', async () => {
    // Signer that never resolves — the previous implementation awaited
    // Promise.allSettled(workers) unconditionally and would hang here.
    const signer: EvidenceSigner = {
      async signEvidence() {
        await new Promise(() => {
          /* never */
        });
        throw new Error('unreachable');
      },
      async verifyEvidence() {
        return false;
      },
    };
    const pipeline = createAuditPipeline({ signer, workers: 1, maxBatchSize: 1 });
    await pipeline.enqueue(makeEvidence(1));
    // Give the worker a tick to pick up ev-1.
    await new Promise((r) => setTimeout(r, 10));

    const start = Date.now();
    await pipeline.drain(50);
    const elapsed = Date.now() - start;
    // Drain MUST honour the deadline regardless of the hung worker.
    expect(elapsed).toBeLessThan(500);
  });

  it('handles wrap-around correctly in the ring buffer', async () => {
    // Stress the head/tail wrap by repeatedly filling and draining a
    // small buffer. A naive (non-circular) array would still work;
    // this test guards specifically against off-by-one bugs in the
    // modulo arithmetic that backs the O(1) enqueue/dequeue.
    const signer = new RecordingSigner();
    const pipeline = createAuditPipeline({
      signer,
      maxSize: 4,
      workers: 1,
      maxBatchSize: 2,
    });
    for (let i = 0; i < 20; i++) {
      await pipeline.enqueue(makeEvidence(i));
    }
    await pipeline.drain(2000);
    // All 20 must have been signed (no drops since enqueue rate <=
    // signer rate when delayMs=0).
    expect(pipeline.signedCount()).toBe(20);
    expect(pipeline.droppedCount()).toBe(0);
    expect(pipeline.queueDepth()).toBe(0);
    expect(signer.seen).toHaveLength(20);
  });

  it('exposes the active backpressurePolicy', () => {
    const signer = new RecordingSigner();
    const defaultPipe = new AuditPipeline({ signer });
    const blockPipe = new AuditPipeline({ signer, backpressure: 'block' });
    const dropPipe = new AuditPipeline({ signer, backpressure: 'drop_oldest_with_metric' });
    expect(defaultPipe.backpressurePolicy).toBe('drop_oldest_with_metric');
    expect(blockPipe.backpressurePolicy).toBe('block');
    expect(dropPipe.backpressurePolicy).toBe('drop_oldest_with_metric');
  });
});
