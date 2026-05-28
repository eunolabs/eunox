// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package posture

import (
"context"
"database/sql"
"fmt"
"time"

// SQLite driver for durable queue.
_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS posture_queue (
id             INTEGER PRIMARY KEY AUTOINCREMENT,
event_type     TEXT    NOT NULL CHECK(event_type IN ('observed','revoked')),
payload        BLOB   NOT NULL,
inserted_at    INTEGER NOT NULL,
attempts       INTEGER NOT NULL DEFAULT 0,
next_attempt_at INTEGER NOT NULL DEFAULT 0,
last_error     TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_posture_queue_next_attempt ON posture_queue(next_attempt_at);

CREATE TABLE IF NOT EXISTS posture_dead_letter (
id             INTEGER PRIMARY KEY AUTOINCREMENT,
original_id    INTEGER NOT NULL,
event_type     TEXT    NOT NULL CHECK(event_type IN ('observed','revoked')),
payload        BLOB   NOT NULL,
inserted_at    INTEGER NOT NULL,
attempts       INTEGER NOT NULL,
last_error     TEXT    NOT NULL DEFAULT '',
dead_lettered_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_posture_dlq_dead_lettered_at ON posture_dead_letter(dead_lettered_at);
`

// SQLiteQueue is a durable event queue backed by SQLite in WAL mode.
// It enforces a single-writer invariant via an exclusive lock on open.
//
// # Throughput Limitations
//
// The queue serializes all operations (Push, Peek, Ack, Nack, DeadLetter) through
// a single semaphore-guarded database connection with EXCLUSIVE locking mode. This
// design provides strong data-integrity guarantees and simple crash recovery but
// imposes the following throughput constraints:
//
//   - Maximum sustained throughput: ~100–500 events/s (hardware-dependent)
//   - Under burst load, enqueue callers contend with the delivery worker's Ack/Nack
//     writes; the semaphore honours context deadlines so Push callers shed load
//     gracefully rather than blocking indefinitely
//   - The exclusive lock prevents concurrent readers, including diagnostic queries
//
// # When to Use PostgreSQL
//
// For deployments exceeding ~100 events/s sustained posture throughput, switch to a
// PostgreSQL-backed queue implementation (see docs/posture-scaling.md). PostgreSQL
// provides row-level locking, connection pooling, and horizontal read scaling.
//
// # Read/Write Split Evaluation
//
// A potential optimization is splitting the read path (Peek) to a separate read-only
// connection under WAL mode (removing _locking_mode=EXCLUSIVE). This would allow
// concurrent diagnostic reads but adds complexity (coordinating two connections,
// potential snapshot isolation issues). This optimization is deferred until
// profiling demonstrates it as the bottleneck vs. write contention.
type SQLiteQueue struct {
// sem is a capacity-1 channel used as a context-aware mutex.
// Acquire: send a token (sem <- struct{}{}); release: receive (<-sem).
// Using a channel instead of sync.Mutex allows Push callers to respect
// context cancellation when the delivery worker holds the lock (F-4 fix).
sem chan struct{}
db  *sql.DB
}

// NewSQLiteQueue opens (or creates) a SQLite database at the given path and
// initializes the queue schema. The database is configured in WAL mode for
// single-writer, multi-reader concurrency. If path is ":memory:", an in-memory
// database is used (useful for testing).
func NewSQLiteQueue(path string) (*SQLiteQueue, error) {
dsn := path
if path != ":memory:" {
// WAL mode + exclusive locking for single-writer guarantee.
dsn = fmt.Sprintf("%s?_journal_mode=WAL&_locking_mode=EXCLUSIVE&_busy_timeout=5000", path)
}

db, err := sql.Open("sqlite", dsn)
if err != nil {
return nil, fmt.Errorf("posture queue: open database: %w", err)
}

// Enforce single connection for single-writer invariant.
db.SetMaxOpenConns(1)
db.SetMaxIdleConns(1)

ctx := context.Background()

// Verify connectivity and set pragmas.
if _, err := db.ExecContext(ctx, "PRAGMA journal_mode=WAL"); err != nil {
_ = db.Close()
return nil, fmt.Errorf("posture queue: set WAL mode: %w", err)
}

if _, err := db.ExecContext(ctx, schema); err != nil {
_ = db.Close()
return nil, fmt.Errorf("posture queue: create schema: %w", err)
}

return &SQLiteQueue{sem: make(chan struct{}, 1), db: db}, nil
}

// acquire waits until the semaphore is available or ctx is cancelled.
// All methods call acquire before touching the database so that context
// cancellation is respected even while another goroutine holds the lock.
func (q *SQLiteQueue) acquire(ctx context.Context) error {
select {
case q.sem <- struct{}{}:
return nil
case <-ctx.Done():
return ctx.Err()
}
}

// release returns the semaphore token, unblocking the next waiter.
func (q *SQLiteQueue) release() {
<-q.sem
}

// Push enqueues a new event. Returns the assigned event ID.
func (q *SQLiteQueue) Push(ctx context.Context, eventType EventType, payload []byte) (int64, error) {
if err := ctx.Err(); err != nil {
return 0, fmt.Errorf("posture queue: push: %w", err)
}
if err := q.acquire(ctx); err != nil {
return 0, fmt.Errorf("posture queue: push: %w", err)
}
defer q.release()

if err := ctx.Err(); err != nil {
return 0, fmt.Errorf("posture queue: push: %w", err)
}

nowMs := time.Now().UnixMilli()
result, err := q.db.ExecContext(ctx,
`INSERT INTO posture_queue (event_type, payload, inserted_at, next_attempt_at) VALUES (?, ?, ?, ?)`,
string(eventType), payload, nowMs, nowMs,
)
if err != nil {
return 0, fmt.Errorf("posture queue: push: %w", err)
}

id, err := result.LastInsertId()
if err != nil {
return 0, fmt.Errorf("posture queue: last insert id: %w", err)
}

return id, nil
}

// Peek returns up to limit events that are ready for delivery (next_attempt_at <= now).
func (q *SQLiteQueue) Peek(ctx context.Context, limit int) ([]QueuedEvent, error) {
if err := ctx.Err(); err != nil {
return nil, fmt.Errorf("posture queue: peek: %w", err)
}
if err := q.acquire(ctx); err != nil {
return nil, fmt.Errorf("posture queue: peek: %w", err)
}
defer q.release()

if err := ctx.Err(); err != nil {
return nil, fmt.Errorf("posture queue: peek: %w", err)
}

nowMs := time.Now().UnixMilli()
rows, err := q.db.QueryContext(ctx,
`SELECT id, event_type, payload, inserted_at, attempts, next_attempt_at, last_error
 FROM posture_queue
 WHERE next_attempt_at <= ?
 ORDER BY next_attempt_at ASC
 LIMIT ?`,
nowMs, limit,
)
if err != nil {
return nil, fmt.Errorf("posture queue: peek: %w", err)
}
defer func() { _ = rows.Close() }()

var events []QueuedEvent
for rows.Next() {
var e QueuedEvent
var eventType string
if err := rows.Scan(&e.ID, &eventType, &e.Payload, &e.InsertedAt, &e.Attempts, &e.NextAttemptAt, &e.LastError); err != nil {
return nil, fmt.Errorf("posture queue: scan row: %w", err)
}
e.Type = EventType(eventType)
events = append(events, e)
}

return events, rows.Err()
}

// Ack removes a successfully delivered event from the queue.
func (q *SQLiteQueue) Ack(ctx context.Context, id int64) error {
if err := ctx.Err(); err != nil {
return fmt.Errorf("posture queue: ack: %w", err)
}
if err := q.acquire(ctx); err != nil {
return fmt.Errorf("posture queue: ack: %w", err)
}
defer q.release()

if err := ctx.Err(); err != nil {
return fmt.Errorf("posture queue: ack: %w", err)
}

_, err := q.db.ExecContext(ctx, `DELETE FROM posture_queue WHERE id = ?`, id)
if err != nil {
return fmt.Errorf("posture queue: ack: %w", err)
}
return nil
}

// Nack reschedules a failed event for later retry.
func (q *SQLiteQueue) Nack(ctx context.Context, id, nextAttemptAt int64, errMsg string) error {
if err := ctx.Err(); err != nil {
return fmt.Errorf("posture queue: nack: %w", err)
}
if err := q.acquire(ctx); err != nil {
return fmt.Errorf("posture queue: nack: %w", err)
}
defer q.release()

if err := ctx.Err(); err != nil {
return fmt.Errorf("posture queue: nack: %w", err)
}

_, err := q.db.ExecContext(ctx,
`UPDATE posture_queue SET attempts = attempts + 1, next_attempt_at = ?, last_error = ? WHERE id = ?`,
nextAttemptAt, errMsg, id,
)
if err != nil {
return fmt.Errorf("posture queue: nack: %w", err)
}
return nil
}

// Depth returns the total number of events in the queue.
func (q *SQLiteQueue) Depth(ctx context.Context) (int64, error) {
if err := ctx.Err(); err != nil {
return 0, fmt.Errorf("posture queue: depth: %w", err)
}
if err := q.acquire(ctx); err != nil {
return 0, fmt.Errorf("posture queue: depth: %w", err)
}
defer q.release()

if err := ctx.Err(); err != nil {
return 0, fmt.Errorf("posture queue: depth: %w", err)
}

var count int64
err := q.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM posture_queue`).Scan(&count)
if err != nil {
return 0, fmt.Errorf("posture queue: depth: %w", err)
}
return count, nil
}

// DeadLetter moves an event from the active queue to the dead-letter table.
func (q *SQLiteQueue) DeadLetter(ctx context.Context, event *QueuedEvent) error {
if err := ctx.Err(); err != nil {
return fmt.Errorf("posture queue: dead-letter: %w", err)
}
if err := q.acquire(ctx); err != nil {
return fmt.Errorf("posture queue: dead-letter: %w", err)
}
defer q.release()

if err := ctx.Err(); err != nil {
return fmt.Errorf("posture queue: dead-letter: %w", err)
}

tx, err := q.db.BeginTx(ctx, nil)
if err != nil {
return fmt.Errorf("posture queue: dead-letter begin tx: %w", err)
}
defer func() { _ = tx.Rollback() }()

nowMs := time.Now().UnixMilli()
_, err = tx.ExecContext(ctx,
`INSERT INTO posture_dead_letter (original_id, event_type, payload, inserted_at, attempts, last_error, dead_lettered_at)
 VALUES (?, ?, ?, ?, ?, ?, ?)`,
event.ID, string(event.Type), event.Payload, event.InsertedAt, event.Attempts, event.LastError, nowMs,
)
if err != nil {
return fmt.Errorf("posture queue: dead-letter insert: %w", err)
}

res, err := tx.ExecContext(ctx, `DELETE FROM posture_queue WHERE id = ?`, event.ID)
if err != nil {
return fmt.Errorf("posture queue: dead-letter delete: %w", err)
}
n, err := res.RowsAffected()
if err != nil {
return fmt.Errorf("posture queue: dead-letter rows affected: %w", err)
}
if n == 0 {
return fmt.Errorf("posture queue: dead-letter: event %d not found in queue", event.ID)
}

if err := tx.Commit(); err != nil {
return fmt.Errorf("posture queue: dead-letter commit: %w", err)
}
return nil
}

// ListDeadLetters returns up to limit dead-lettered events, ordered by dead-letter time descending.
func (q *SQLiteQueue) ListDeadLetters(ctx context.Context, limit int) ([]DeadLetteredEvent, error) {
if err := ctx.Err(); err != nil {
return nil, fmt.Errorf("posture queue: list dead letters: %w", err)
}
if err := q.acquire(ctx); err != nil {
return nil, fmt.Errorf("posture queue: list dead letters: %w", err)
}
defer q.release()

if err := ctx.Err(); err != nil {
return nil, fmt.Errorf("posture queue: list dead letters: %w", err)
}

rows, err := q.db.QueryContext(ctx,
`SELECT id, original_id, event_type, payload, inserted_at, attempts, last_error, dead_lettered_at
 FROM posture_dead_letter
 ORDER BY dead_lettered_at DESC
 LIMIT ?`,
limit,
)
if err != nil {
return nil, fmt.Errorf("posture queue: list dead letters: %w", err)
}
defer func() { _ = rows.Close() }()

var events []DeadLetteredEvent
for rows.Next() {
var e DeadLetteredEvent
var eventType string
if err := rows.Scan(&e.ID, &e.OriginalID, &eventType, &e.Payload, &e.InsertedAt, &e.Attempts, &e.LastError, &e.DeadLetteredAt); err != nil {
return nil, fmt.Errorf("posture queue: scan dead letter row: %w", err)
}
e.Type = EventType(eventType)
events = append(events, e)
}
return events, rows.Err()
}

// DeadLetterDepth returns the total number of dead-lettered events.
func (q *SQLiteQueue) DeadLetterDepth(ctx context.Context) (int64, error) {
if err := ctx.Err(); err != nil {
return 0, fmt.Errorf("posture queue: dead letter depth: %w", err)
}
if err := q.acquire(ctx); err != nil {
return 0, fmt.Errorf("posture queue: dead letter depth: %w", err)
}
defer q.release()

if err := ctx.Err(); err != nil {
return 0, fmt.Errorf("posture queue: dead letter depth: %w", err)
}

var count int64
err := q.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM posture_dead_letter`).Scan(&count)
if err != nil {
return 0, fmt.Errorf("posture queue: dead letter depth: %w", err)
}
return count, nil
}

// Close releases the database connection. Waits for any in-flight operation to
// complete before closing, using a background context.
func (q *SQLiteQueue) Close() error {
if err := q.acquire(context.Background()); err != nil {
return fmt.Errorf("posture queue: close: %w", err)
}
defer q.release()

return q.db.Close()
}

// Compile-time interface check.
var _ Queue = (*SQLiteQueue)(nil)
