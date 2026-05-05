/**
 * SQLite WAL-backed durable queue for posture events.
 *
 * ## Guaranteed-delivery contract
 *
 * Every call to {@link DurableQueue.push} completes a synchronous
 * SQLite write before returning, so the caller's in-process risk
 * window is just the time between the event occurring and the
 * `push()` call completing — typically sub-millisecond. After that
 * the event is on disk and survives a process crash.
 *
 * The companion {@link DeliveryWorker} drives the read side:
 *
 *   1. `peek(n)` — returns at most `n` events whose `next_attempt_at`
 *      is in the past.
 *   2. `ack(id)` — deletes the event after successful delivery.
 *   3. `nack(id, nextMs, error)` — increments the attempt counter and
 *      sets a future `next_attempt_at` so exponential backoff is
 *      respected across restarts.
 *
 * ## WAL mode
 *
 * The database is opened in WAL journal mode with `synchronous=NORMAL`
 * so writes flush to the WAL file (crash-safe) without fsync on every
 * commit (which would make push() noticeably slow).  The tradeoff:
 * a power loss between WAL checkpoint and the main database file can
 * lose the last few events, but WAL recovery on next open restores
 * them.  This matches the semantics implied by the problem statement
 * ("local durable queue … SQLite WAL").
 *
 * ## In-memory mode
 *
 * When `path` is `':memory:'` the database lives entirely in RAM.
 * This is the default when no path is supplied, and it is safe for
 * tests.  Durability guarantees do not apply.
 */
import Database, { Database as DatabaseType } from 'better-sqlite3';

/** The two posture event types the queue understands. */
export type QueuedEventType = 'observed' | 'revoked';

/** A single row returned by {@link DurableQueue.peek}. */
export interface QueuedEvent {
  /** SQLite row-id; opaque to callers outside this module. */
  id: number;
  /** Event type — drives which plugin method is called. */
  type: QueuedEventType;
  /**
   * JSON-serialised payload.
   * For `observed`: `AgentInventoryRecord`.
   * For `revoked`: `{ agentId: string; revokedAt: string }`.
   */
  payload: string;
  /** Unix timestamp (ms) when the event was first pushed. */
  insertedAt: number;
  /** Number of delivery attempts so far (0 on first peek). */
  attempts: number;
  /** Unix timestamp (ms) before which the event should not be retried. */
  nextAttemptAt: number;
  /** Error message from the most recent failed attempt, or null. */
  lastError: string | null;
}

export interface DurableQueueOptions {
  /**
   * File path for the SQLite database.
   * Use `':memory:'` (default) for tests or transient in-process queues.
   * In production, set this to a writable path on a persistent volume so
   * events survive process restarts.
   */
  path?: string;
}

/**
 * SQLite WAL-backed durable queue.
 *
 * Thread safety: `better-sqlite3` is synchronous; the single-threaded
 * Node.js event loop serialises all calls naturally.
 */
export class DurableQueue {
  private readonly db: DatabaseType;
  private readonly stmtPush: ReturnType<DatabaseType['prepare']>;
  private readonly stmtPeek: ReturnType<DatabaseType['prepare']>;
  private readonly stmtAck: ReturnType<DatabaseType['prepare']>;
  private readonly stmtNack: ReturnType<DatabaseType['prepare']>;
  private readonly stmtDepth: ReturnType<DatabaseType['prepare']>;
  private readonly stmtOldest: ReturnType<DatabaseType['prepare']>;

  constructor(opts: DurableQueueOptions = {}) {
    const filePath = opts.path ?? ':memory:';
    this.db = new Database(filePath);

    // Enable WAL mode for crash-safe writes without per-commit fsyncs.
    // `synchronous=NORMAL` is sufficient with WAL: the WAL file is
    // flushed before the write returns, but the main DB is only
    // checkpointed periodically.
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('synchronous = NORMAL');

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS posture_queue (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        type            TEXT    NOT NULL CHECK(type IN ('observed','revoked')),
        payload         TEXT    NOT NULL,
        inserted_at     INTEGER NOT NULL,
        attempts        INTEGER NOT NULL DEFAULT 0,
        next_attempt_at INTEGER NOT NULL DEFAULT 0,
        last_error      TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_pq_next_attempt
        ON posture_queue (next_attempt_at);
    `);

    this.stmtPush = this.db.prepare(`
      INSERT INTO posture_queue (type, payload, inserted_at, attempts, next_attempt_at)
      VALUES (@type, @payload, @insertedAt, 0, 0)
    `);

    this.stmtPeek = this.db.prepare(`
      SELECT id, type, payload, inserted_at AS insertedAt,
             attempts, next_attempt_at AS nextAttemptAt, last_error AS lastError
      FROM   posture_queue
      WHERE  next_attempt_at <= @nowMs
      ORDER  BY next_attempt_at ASC, id ASC
      LIMIT  @limit
    `);

    this.stmtAck = this.db.prepare(`
      DELETE FROM posture_queue WHERE id = @id
    `);

    this.stmtNack = this.db.prepare(`
      UPDATE posture_queue
      SET    attempts        = attempts + 1,
             next_attempt_at = @nextAttemptAt,
             last_error      = @lastError
      WHERE  id = @id
    `);

    this.stmtDepth = this.db.prepare(`
      SELECT COUNT(*) AS n FROM posture_queue
    `);

    this.stmtOldest = this.db.prepare(`
      SELECT MIN(inserted_at) AS minInsertedAt FROM posture_queue
    `);
  }

  /**
   * Synchronously write an event to the queue.
   * Returns the assigned row-id (useful for tests).
   */
  push(type: QueuedEventType, payload: string, nowMs: number = Date.now()): number {
    const result = this.stmtPush.run({ type, payload, insertedAt: nowMs });
    return result.lastInsertRowid as number;
  }

  /**
   * Return at most `limit` events whose `next_attempt_at` is ≤ `nowMs`.
   * Events are returned oldest-first so the worker does not starve
   * recently-enqueued events.
   */
  peek(limit: number, nowMs: number = Date.now()): QueuedEvent[] {
    return this.stmtPeek.all({ nowMs, limit }) as QueuedEvent[];
  }

  /**
   * Permanently delete a successfully-delivered event.
   */
  ack(id: number): void {
    this.stmtAck.run({ id });
  }

  /**
   * Record a delivery failure and schedule a retry.
   *
   * @param id            Row-id of the event.
   * @param nextAttemptAt Unix ms before which the event should not be retried.
   * @param error         Human-readable error message stored for diagnostics.
   */
  nack(id: number, nextAttemptAt: number, error: string): void {
    this.stmtNack.run({ id, nextAttemptAt, lastError: error });
  }

  /** Number of events currently in the queue. */
  depth(): number {
    const row = this.stmtDepth.get({}) as { n: number };
    return row.n;
  }

  /**
   * Unix ms of the oldest event still in the queue, or `null` when
   * the queue is empty.  Subtract from `Date.now()` to get lag in ms.
   */
  oldestInsertedAt(): number | null {
    const row = this.stmtOldest.get({}) as { minInsertedAt: number | null };
    return row.minInsertedAt;
  }

  /**
   * Close the underlying SQLite connection.
   * After this call all methods will throw.
   */
  close(): void {
    this.db.close();
  }
}
