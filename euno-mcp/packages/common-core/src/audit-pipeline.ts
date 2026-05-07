/**
 * Async batched audit pipeline (R-9, addresses I-21)
 * ---------------------------------------------------------------------------
 * Wraps an {@link EvidenceSigner} behind a bounded in-memory ring buffer
 * drained by N background worker loops, so producers (most importantly the
 * tool-gateway `EnforcementEngine`) never pay signing latency on the request
 * critical path.
 *
 * Design (from `docs/IMPROVEMENTS_AND_REFACTORING.md` § R-9):
 *
 *   - Bounded ring buffer (`maxSize` + optional per-item `maxAgeMs`).
 *   - `workers` background loops, each pulling up to `maxBatchSize` items per
 *     cycle and calling {@link EvidenceSigner.signEvidence} once per item.
 *     Batching is a wake-up amortisation: the underlying single-record
 *     signer interface is unchanged, so existing signers (software, KMS)
 *     work without modification.
 *   - **Merkle batch commitment** (addresses audit-chain integrity): after
 *     each drain cycle a worker computes the Merkle root of the batch's
 *     signed-record hashes, signs an {@link AuditBatchCommitment}, and calls
 *     the registered {@link AuditAnchor}s. This anchors the batch externally
 *     so a compromised replica cannot retroactively rewrite records without
 *     breaking the commitment chain visible to the anchors.
 *   - Backpressure policy when the buffer is full:
 *       * `drop_oldest_with_metric` (default) — pop the oldest item, count
 *         it as dropped, then accept the new one. Producers are never
 *         blocked. The `onDropped` callback and the Prometheus counter are
 *         the operator's signal that evidence was shed; monitoring that
 *         counter is the contract for best-effort audit durability.
 *       * `block`                              — `enqueue()` returns a
 *         promise that resolves once a slot opens. Suitable for regulated
 *         workloads that require audit completeness, but note that during
 *         a signer stall the request path will block until the signer
 *         recovers or a client/server timeout fires. Records are still
 *         dropped once the `maxWaiters` cap is reached.
 *   - Always emits an `onDropped(count, reason)` callback so a Prometheus
 *     counter (or any other sink) can be wired in by the host service —
 *     the counter cannot live inside `@euno/common` itself because the
 *     gateway and issuer each own their own `Registry` (F-5).
 *   - Graceful `drain(timeoutMs)` for shutdown so a `SIGTERM` flushes
 *     anything still in the buffer before the process exits.
 *
 * The pipeline owns nothing but the queue and the workers; it does not
 * persist. A crash loses anything still buffered — the same guarantee
 * the synchronous in-process signer offered before R-9 (the gateway audit
 * trail is best-effort tamper-evidence, not durable storage).
 */

import { EvidenceSigner, AuditBatchSigner, AuditAnchor } from './runtime';
import { AuditEvidence, SignedAuditEvidence, AuditBatchCommitment, SignedBatchCommitment, GENESIS_HASH } from './types';
import { computeMerkleRoot, generateId } from './utils';
import { hashSignedRecord, hashBatchCommitment } from './evidence';

/**
 * Backpressure policy applied when the ring buffer is full.
 *
 *   - `drop_oldest_with_metric` (default) — drop the oldest queued item,
 *     increment a dropped counter, and accept the new one. Producers are
 *     never blocked; this is the default because it preserves request-path
 *     p99 and avoids blocking the request during signer outages.
 *   - `block`                              — make `enqueue()` await until a
 *     slot is free. Producers pay backpressure but no evidence is dropped
 *     due to a full buffer. **Note:** during a signer stall the request path
 *     blocks until the signer recovers or a client/server timeout fires.
 *     Records are still dropped once the `maxWaiters` cap is reached.
 *     Recommended only when the operator's compliance posture requires
 *     audit completeness and the signer is reliably low-latency.
 */
export const BACKPRESSURE_POLICIES = ['drop_oldest_with_metric', 'block'] as const;
export type BackpressurePolicy = (typeof BACKPRESSURE_POLICIES)[number];

/**
 * Reason an evidence record was dropped, surfaced to the metrics sink so
 * operators can tell capacity drops apart from age-eviction drops.
 */
export type DropReason =
  | 'queue_full'    // backpressure policy = drop_oldest_with_metric, ring full
  | 'aged_out';     // item exceeded `maxAgeMs` while waiting in the queue

/**
 * Configuration for {@link AuditPipeline}.
 */
export interface AuditPipelineOptions {
  /**
   * Underlying signer the workers call. The pipeline owns the call to
   * `signEvidence` so producers can hand off and return immediately.
   */
  signer: EvidenceSigner;
  /**
   * Maximum number of unsigned `AuditEvidence` records buffered in memory.
   * Beyond this, the {@link backpressure} policy decides what happens.
   * Must be >= 1. Default 1024 — sized for a small gateway under burst.
   */
  maxSize?: number;
  /**
   * Number of concurrent worker loops draining the queue. Each worker
   * holds at most one in-flight `signEvidence` call; total concurrency
   * against the signer is therefore bounded by `workers`. Must be >= 1.
   * Default 2.
   */
  workers?: number;
  /**
   * Maximum number of records a single worker pulls per wake-up. Larger
   * values amortise event-loop wake-ups under heavy load; smaller values
   * keep tail latency between enqueue and sign tighter. Must be >= 1.
   * Default 16.
   */
  maxBatchSize?: number;
  /**
   * Maximum age (ms) a record may sit in the queue before it is dropped
   * as `aged_out`. Defends against unbounded queue residency when the
   * signer is slow or down. `undefined` (default) disables age-based
   * eviction.
   */
  maxAgeMs?: number;
  /** Backpressure policy. Default `'drop_oldest_with_metric'`. */
  backpressure?: BackpressurePolicy;
  /**
   * Hard cap on the number of producers parked under the `block`
   * policy. Defends against an unbounded waiter list (and the
   * associated promise-resolver memory) when the signer is slower
   * than the producer rate for long stretches. Defaults to `maxSize`
   * — i.e. the parked-waiters list cannot exceed the buffer size.
   * Records that arrive when this cap is reached are dropped with
   * `reason='queue_full'`. Ignored under the drop policy.
   */
  maxWaiters?: number;
  /**
   * Invoked when one or more records are dropped. `count` is always >= 1.
   * `reason` lets the sink split the metric into capacity vs. age drops.
   * Errors thrown by the sink are swallowed — the pipeline must never
   * crash a producer.
   */
  onDropped?: (count: number, reason: DropReason) => void;
  /**
   * Invoked after a record is successfully signed. Optional; mainly
   * useful for downstream sinks that persist or stream signed evidence.
   * Errors thrown here are swallowed.
   */
  onSigned?: (signed: SignedAuditEvidence) => void;
  /**
   * Invoked when `signEvidence` rejects. The pipeline does NOT retry —
   * a failed sign just emits this callback and moves on (the decision
   * was already logged unsigned by the producer). Errors thrown by the
   * sink are swallowed.
   */
  onSignError?: (err: unknown, evidence: AuditEvidence) => void;
  // ── Merkle batch commitment options ─────────────────────────────────────
  /**
   * Replica/pod identifier stamped on every {@link AuditBatchCommitment}.
   * Operators should set this to the Kubernetes Pod name (e.g. via the
   * downward API: `$(POD_NAME)`) so batch commitments can be attributed to
   * a specific replica in multi-replica deployments. Defaults to
   * `'unknown-replica'` when not supplied.
   */
  replicaId?: string;
  /**
   * Signer used to produce {@link SignedBatchCommitment} records. When
   * absent, batch commitments are computed but NOT signed — they are still
   * passed to `onBatch` as an `AuditBatchCommitment` (typed as
   * `SignedBatchCommitment` with empty signature/keyId/algorithm fields).
   * For full tamper-evidence, supply the same {@link AuditEvidenceSigner}
   * instance used for per-record signing.
   */
  batchSigner?: AuditBatchSigner;
  /**
   * List of external anchors to publish each {@link SignedBatchCommitment}
   * to after each pipeline drain cycle. Errors from individual anchors are
   * swallowed so one failing anchor cannot break the pipeline. When empty
   * or absent, batch commitments are not published externally.
   *
   * Bootstrap wires at least a logging anchor (always on when `batchSigner`
   * is set) and optionally an HTTP anchor when `AUDIT_ANCHOR_URL` is
   * configured.
   */
  anchors?: AuditAnchor[];
  /**
   * Called after a batch commitment is signed and published. Fires once per
   * drain cycle when at least one record was signed. Errors are swallowed.
   */
  onBatch?: (commitment: SignedBatchCommitment) => void;
  /**
   * Called when batch commitment signing fails. Errors thrown by the sink
   * are swallowed.
   */
  onBatchError?: (err: unknown) => void;
}

/**
 * Internal queue node — pairs the unsigned evidence with the timestamp
 * it entered the buffer (used for `maxAgeMs` enforcement). The block-
 * policy waiter list stores its own resolver objects separately from
 * the buffered queue (see `waiters` field).
 */
interface QueueNode {
  evidence: AuditEvidence;
  enqueuedAt: number;
}

/**
 * Bounded async pipeline that drains `AuditEvidence` records into an
 * `EvidenceSigner` from N background worker loops. See module header.
 */
export class AuditPipeline {
  private readonly signer: EvidenceSigner;
  private readonly maxSize: number;
  private readonly workerCount: number;
  private readonly maxBatchSize: number;
  private readonly maxAgeMs: number | undefined;
  private readonly backpressure: BackpressurePolicy;
  private readonly maxWaiters: number;
  private readonly onDropped?: (count: number, reason: DropReason) => void;
  private readonly onSigned?: (signed: SignedAuditEvidence) => void;
  private readonly onSignError?: (err: unknown, evidence: AuditEvidence) => void;
  // ── Merkle batch commitment ─────────────────────────────────────────────
  private readonly replicaId: string;
  private readonly batchSigner?: AuditBatchSigner;
  private readonly anchors: AuditAnchor[];
  private readonly onBatch?: (commitment: SignedBatchCommitment) => void;
  private readonly onBatchError?: (err: unknown) => void;
  /** Monotonically increasing (1-based) batch sequence number for this replica. */
  private batchSeq = 0;
  /**
   * SHA-256 hex of the previous {@link SignedBatchCommitment}, or
   * {@link GENESIS_HASH} before the first batch.
   */
  private previousBatchHash: string = GENESIS_HASH;
  /**
   * Tail of the batch-commitment serialisation chain.
   *
   * `emitBatchCommitment` chains each new batch onto this tail so that
   * `batchSeq` / `previousBatchHash` assignments are always serialised,
   * even when multiple workers call `emitBatchCommitment` concurrently
   * (they interleave at `await` points inside `doEmitBatchCommitment`).
   * The chaining assignment is synchronous, so it is always ordered
   * correctly by the event loop.
   */
  private batchChainTail: Promise<void> = Promise.resolve();

  /**
   * Fixed-size circular buffer (true ring buffer): enqueue / dequeue /
   * drop-oldest are all O(1) regardless of `maxSize`. Backed by a
   * pre-allocated `Array` indexed via `head` / `tail` modulo
   * `maxSize`. The earlier implementation used `Array.shift()`, which
   * is O(n) and added measurable overhead under sustained load with a
   * larger buffer.
   */
  private readonly buffer: Array<QueueNode | undefined>;
  private head = 0;
  private tail = 0;
  private count = 0;
  /**
   * Producers parked under the `block` policy. Each entry is a
   * resolver: it is invoked once a worker frees a slot (FIFO, so
   * producers unblock in arrival order), and the woken producer
   * re-enters the queue from `enqueue`. Bounded by `maxWaiters` to
   * defend against unbounded promise-list growth.
   */
  private readonly waiters: Array<() => void> = [];
  private readonly workers: Promise<void>[] = [];
  /** Resolvers registered by workers waiting for new work. */
  private readonly workerWakers: Array<() => void> = [];
  private stopped = false;
  private droppedTotal = 0;
  private signedTotal = 0;
  private signErrorTotal = 0;

  constructor(options: AuditPipelineOptions) {
    this.signer = options.signer;
    this.maxSize = Math.max(1, options.maxSize ?? 1024);
    this.workerCount = Math.max(1, options.workers ?? 2);
    this.maxBatchSize = Math.max(1, options.maxBatchSize ?? 16);
    this.maxAgeMs = options.maxAgeMs;
    this.backpressure = options.backpressure ?? 'drop_oldest_with_metric';
    this.maxWaiters = Math.max(1, options.maxWaiters ?? this.maxSize);
    this.onDropped = options.onDropped;
    this.onSigned = options.onSigned;
    this.onSignError = options.onSignError;
    this.replicaId = options.replicaId ?? 'unknown-replica';
    this.batchSigner = options.batchSigner;
    this.anchors = options.anchors ?? [];
    this.onBatch = options.onBatch;
    this.onBatchError = options.onBatchError;
    this.buffer = new Array<QueueNode | undefined>(this.maxSize);
  }

  /** Push a node onto the tail of the ring buffer (caller must check capacity). */
  private pushTail(node: QueueNode): void {
    this.buffer[this.tail] = node;
    this.tail = (this.tail + 1) % this.maxSize;
    this.count += 1;
  }

  /** Pop the oldest node from the head of the ring buffer, or undefined when empty. */
  private popHead(): QueueNode | undefined {
    if (this.count === 0) return undefined;
    const node = this.buffer[this.head];
    this.buffer[this.head] = undefined;
    this.head = (this.head + 1) % this.maxSize;
    this.count -= 1;
    return node;
  }

  /**
   * Start the worker loops. Idempotent — calling start() twice has no
   * effect after the first invocation.
   */
  start(): void {
    if (this.workers.length > 0) {
      return;
    }
    for (let i = 0; i < this.workerCount; i++) {
      this.workers.push(this.runWorker());
    }
  }

  /**
   * Hand an unsigned evidence record to the pipeline.
   *
   * Under the default `drop_oldest_with_metric` policy, the returned
   * promise resolves immediately (synchronously, microtask-only) so
   * producers on the request critical path pay zero awaited latency.
   * If the buffer is full, the oldest queued item is evicted and the
   * `onDropped` callback fires with `reason='queue_full'`.
   *
   * Under the `block` policy, the returned promise resolves only once a
   * slot becomes free (i.e. a worker has dequeued enough items). This
   * backpressures the producer so evidence is not dropped due to a full
   * buffer. **Caveat:** during a signer stall the request path blocks
   * until the signer recovers or a client/server timeout fires. When
   * the parked-waiter list reaches `maxWaiters` (default = `maxSize`)
   * the new record is dropped with `reason='queue_full'` instead of
   * growing the waiter list unboundedly.
   *
   * Callers should NOT `await` this on the critical path under the
   * drop policy unless they want a yield point — fire-and-forget is
   * the intended usage.
   */
  enqueue(evidence: AuditEvidence): Promise<void> {
    if (this.stopped) {
      // After drain/stop we no longer accept new evidence; treat this
      // as a drop so the metric reflects the loss. Returning a resolved
      // promise lets producers continue without unhandled rejections.
      this.recordDrops(1, 'queue_full');
      return Promise.resolve();
    }

    if (this.count < this.maxSize) {
      this.pushTail({ evidence, enqueuedAt: Date.now() });
      this.wakeWorker();
      return Promise.resolve();
    }

    // Buffer full — apply backpressure policy.
    if (this.backpressure === 'drop_oldest_with_metric') {
      // Evict the oldest record so the newest survives. The freshest
      // evidence usually has the most diagnostic value (it relates to
      // the most recent traffic); evicting the oldest preserves that
      // bias while still bounding memory.
      this.popHead();
      this.recordDrops(1, 'queue_full');
      this.pushTail({ evidence, enqueuedAt: Date.now() });
      this.wakeWorker();
      return Promise.resolve();
    }

    // `block`: park the producer until a slot frees up. The waiter is
    // resolved by the worker that dequeues the slot (in `pullBatch`).
    if (this.waiters.length >= this.maxWaiters) {
      // Hard cap reached. Drop instead of growing the waiter list
      // forever — important when producers fire-and-forget enqueue()
      // (no awaiter means promise resolvers would otherwise pin
      // memory indefinitely).
      this.recordDrops(1, 'queue_full');
      return Promise.resolve();
    }
    return new Promise<void>((resolve) => {
      // We can't push the node into the buffer yet (it's full). Park
      // a callback that re-runs the enqueue once a slot frees up.
      this.waiters.push(() => {
        // Check stopped state again — drain may have happened between
        // the producer parking and a slot becoming free.
        if (this.stopped) {
          this.recordDrops(1, 'queue_full');
          resolve();
          return;
        }
        this.pushTail({ evidence, enqueuedAt: Date.now() });
        this.wakeWorker();
        resolve();
      });
    });
  }

  /**
   * Stop accepting new work and wait for the queue to drain.
   *
   *   - `timeoutMs` (default `Infinity`) — if the workers can't drain in
   *     time the remaining queued items are counted as `queue_full`
   *     drops so the metric still surfaces them, and the promise
   *     resolves. Workers themselves continue running until their
   *     current `signEvidence` settles, but `drain()` will not wait
   *     past the deadline for them — a hung signer therefore cannot
   *     hang shutdown.
   *
   * After `drain()` resolves, `enqueue()` calls drop their argument and
   * `start()` is a no-op. Construct a fresh pipeline to resume.
   */
  async drain(timeoutMs: number = Infinity): Promise<void> {
    this.stopped = true;
    // Wake any parked producers so their promises resolve (they will
    // observe `stopped` and count themselves as drops).
    while (this.waiters.length > 0) {
      const w = this.waiters.shift();
      if (w) w();
    }
    // Wake every worker so they re-check `stopped` and exit once empty.
    this.wakeAllWorkers();

    const deadline = timeoutMs === Infinity ? Infinity : Date.now() + timeoutMs;
    // Poll until the queue is empty AND every worker has settled, or the
    // deadline expires. Polling is fine here: drain runs on shutdown,
    // not on the hot path.
    while (this.count > 0 && Date.now() < deadline) {
      await new Promise<void>((r) => setTimeout(r, 5));
    }

    if (this.count > 0) {
      // Timed out — count what's left as drops so the operator sees it.
      const lost = this.count;
      while (this.popHead() !== undefined) {
        // popHead clears the slot; loop empties the buffer in O(n).
      }
      this.recordDrops(lost, 'queue_full');
    }

    // Wait for in-flight worker calls to settle, but never past the
    // overall deadline — a hung `signEvidence` must not be able to
    // hang shutdown. Workers exit naturally once the queue is empty
    // and `stopped === true`; this race is the safety net.
    if (deadline === Infinity) {
      await Promise.allSettled(this.workers);
      return;
    }
    const remaining = Math.max(0, deadline - Date.now());
    await Promise.race([
      Promise.allSettled(this.workers),
      new Promise<void>((r) => setTimeout(r, remaining)),
    ]);
  }

  /** Number of records currently buffered awaiting signature. */
  queueDepth(): number {
    return this.count;
  }

  /**
   * Active backpressure policy (`drop_oldest_with_metric` | `block`).
   * Exposed so producers (e.g. the gateway `EnforcementEngine`) can
   * decide whether to await `enqueue()` — under `block` they MUST
   * await it to honour the documented backpressure contract; under
   * `drop_oldest_with_metric` they MUST NOT, or the request critical
   * path re-incurs the signing latency R-9 removed.
   */
  get backpressurePolicy(): BackpressurePolicy {
    return this.backpressure;
  }

  /** Total records dropped over the lifetime of the pipeline. */
  droppedCount(): number {
    return this.droppedTotal;
  }

  /** Total records successfully signed. */
  signedCount(): number {
    return this.signedTotal;
  }

  /** Total `signEvidence` rejections. */
  signErrorCount(): number {
    return this.signErrorTotal;
  }

  /**
   * Internal: record `n` dropped items and notify the metrics sink.
   * Sink errors are swallowed so a misbehaving collector cannot crash
   * the pipeline.
   */
  private recordDrops(n: number, reason: DropReason): void {
    this.droppedTotal += n;
    if (this.onDropped) {
      try {
        this.onDropped(n, reason);
      } catch {
        // Metric sinks must never destabilise the pipeline.
      }
    }
  }

  /**
   * Park a worker until either new work arrives or the pipeline is
   * stopped. Resolved by `wakeWorker` / `wakeAllWorkers`.
   */
  private waitForWork(): Promise<void> {
    return new Promise<void>((resolve) => {
      this.workerWakers.push(resolve);
    });
  }

  private wakeWorker(): void {
    const r = this.workerWakers.shift();
    if (r) r();
  }

  private wakeAllWorkers(): void {
    while (this.workerWakers.length > 0) {
      const r = this.workerWakers.shift();
      if (r) r();
    }
  }

  /**
   * Pull up to `maxBatchSize` records from the queue, dropping any that
   * have exceeded `maxAgeMs`. Each removed slot frees a parked
   * `block`-policy waiter (FIFO) so producers unblock in arrival order.
   */
  private pullBatch(): AuditEvidence[] {
    const batch: AuditEvidence[] = [];
    const now = Date.now();
    let agedOut = 0;
    while (batch.length < this.maxBatchSize && this.count > 0) {
      const node = this.popHead();
      if (!node) break;
      // Free a parked block-policy producer for this consumed slot.
      const waiter = this.waiters.shift();
      if (waiter) waiter();

      if (this.maxAgeMs !== undefined && now - node.enqueuedAt > this.maxAgeMs) {
        agedOut += 1;
        continue;
      }
      batch.push(node.evidence);
    }
    if (agedOut > 0) {
      this.recordDrops(agedOut, 'aged_out');
    }
    return batch;
  }

  /**
   * Worker loop: pull a batch, sign each record, emit a Merkle batch
   * commitment, then repeat until stopped and queue empty. Per-item
   * rejections are isolated so one bad record cannot stall the worker.
   */
  private async runWorker(): Promise<void> {
    // Fresh promise loop. The worker terminates when it observes
    // `stopped === true` AND the queue is empty.
    // eslint-disable-next-line no-constant-condition
    while (true) {
      if (this.count === 0) {
        if (this.stopped) {
          return;
        }
        await this.waitForWork();
        continue;
      }
      const batch = this.pullBatch();
      const signedBatch: SignedAuditEvidence[] = [];
      for (const evidence of batch) {
        try {
          const signed = await this.signer.signEvidence(evidence);
          this.signedTotal += 1;
          signedBatch.push(signed);
          if (this.onSigned) {
            try {
              this.onSigned(signed);
            } catch {
              // Sink failure is not pipeline failure.
            }
          }
        } catch (err) {
          this.signErrorTotal += 1;
          if (this.onSignError) {
            try {
              this.onSignError(err, evidence);
            } catch {
              // Sink failure is not pipeline failure.
            }
          }
        }
      }
      // Emit a Merkle batch commitment when there is at least one consumer:
      //   - a batchSigner (produces signed commitments)
      //   - an external anchor (receives the commitment for external anchoring)
      //   - an onBatch callback (e.g. structured logging)
      // Without any consumer, skipping the commitment avoids useless work.
      const hasBatchConsumer = !!this.batchSigner || this.anchors.length > 0 || !!this.onBatch;
      if (signedBatch.length > 0 && hasBatchConsumer) {
        await this.emitBatchCommitment(signedBatch);
      }
    }
  }

  /**
   * Compute a Merkle batch commitment for `signedRecords`, sign it (when a
   * `batchSigner` is configured), publish it to all registered anchors, and
   * fire `onBatch`. Any error is reported via `onBatchError`; the worker
   * loop is never interrupted.
   *
   * **Serialisation guarantee**: batches are always committed in the order
   * workers call this method, regardless of how many workers are running.
   * The returned promise resolves only after the previous batch commitment
   * has fully completed, so `batchSeq` and `previousBatchHash` are always
   * assigned in the correct order.
   */
  private emitBatchCommitment(signedRecords: SignedAuditEvidence[]): Promise<void> {
    // Chain onto the current tail synchronously (no await) so that two
    // workers that reach this line concurrently always form a linear chain
    // in the order they arrived.
    const next = this.batchChainTail.then(() =>
      this.doEmitBatchCommitment(signedRecords),
    );
    // Suppress rejection on the tail so a previous failure (already
    // routed to onBatchError inside doEmitBatchCommitment) never blocks
    // future batches. The no-op handler intentionally swallows the error
    // because it has already been reported.
    this.batchChainTail = next.then(undefined, () => { /* swallow — already reported */ });
    return next;
  }

  /**
   * Inner implementation of batch commitment, always called serially by
   * `emitBatchCommitment`.
   */
  private async doEmitBatchCommitment(signedRecords: SignedAuditEvidence[]): Promise<void> {
    try {
      const leafHashes = signedRecords.map(hashSignedRecord);
      const merkleRoot = computeMerkleRoot(leafHashes);
      const batchSeq = ++this.batchSeq;
      const firstSeq = signedRecords[0]!.seq;
      const lastSeq = signedRecords[signedRecords.length - 1]!.seq;

      const commitment: AuditBatchCommitment = {
        batchId: generateId(),
        replicaId: this.replicaId,
        batchSeq,
        previousBatchHash: this.previousBatchHash,
        merkleRoot,
        recordCount: signedRecords.length,
        firstSeq,
        lastSeq,
        ts: new Date().toISOString(),
      };

      let signed: SignedBatchCommitment;
      if (this.batchSigner) {
        signed = await this.batchSigner.signBatch(commitment);
      } else {
        // No batch signer configured: emit an unsigned commitment so
        // `onBatch` and anchors still receive the Merkle root (useful for
        // development and staging environments where key management is not
        // yet set up). The absence of a signature is obvious from the empty
        // fields.
        signed = { ...commitment, signature: '', keyId: '', algorithm: '' };
      }

      // Advance the batch chain before notifying callbacks so the state is
      // consistent even if a callback throws.
      this.previousBatchHash = hashBatchCommitment(signed);

      // Fan out to all external anchors concurrently so one slow anchor
      // does not block others. Per-anchor failures are isolated: a
      // rejection is caught, reported via onBatchError (with the anchor
      // name included), and the remaining anchors are unaffected.
      if (this.anchors.length > 0) {
        const results = await Promise.allSettled(
          this.anchors.map((anchor) => anchor.anchorBatch(signed)),
        );
        for (let i = 0; i < results.length; i++) {
          const result = results[i]!;
          if (result.status === 'rejected') {
            const anchorName = this.anchors[i]!.name;
            this.reportBatchError(
              new Error(
                `Anchor '${anchorName}' failed: ${
                  result.reason instanceof Error
                    ? result.reason.message
                    : String(result.reason)
                }`,
              ),
            );
          }
        }
      }

      if (this.onBatch) {
        try {
          this.onBatch(signed);
        } catch {
          // Sink failure must not break the pipeline.
        }
      }
    } catch (err) {
      this.reportBatchError(err);
    }
  }

  /**
   * Route a batch-level error to `onBatchError` while swallowing any
   * exception thrown by the sink itself.
   */
  private reportBatchError(err: unknown): void {
    if (this.onBatchError) {
      try {
        this.onBatchError(err);
      } catch {
        // Sink failure must not break the pipeline.
      }
    }
  }

  /** Number of Merkle batch commitments emitted over the lifetime of this pipeline. */
  batchCommitmentCount(): number {
    return this.batchSeq;
  }
}

/**
 * Convenience factory mirroring `createSoftwareEvidenceSigner` etc. so
 * `bootstrap.ts` can construct + start in one call.
 */
export function createAuditPipeline(options: AuditPipelineOptions): AuditPipeline {
  const pipeline = new AuditPipeline(options);
  pipeline.start();
  return pipeline;
}
