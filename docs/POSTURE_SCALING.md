# Posture Queue Scaling Guide

## Overview

The posture emitter uses a local SQLite database as a durable event queue for
agent inventory observations and revocation events. This design provides:

- **Zero external dependencies** — no separate message broker required
- **Crash durability** — WAL mode ensures committed events survive process restart
- **Exactly-once delivery semantics** — events are ACKed only after successful plugin delivery
- **Dead-letter support** — permanently failing events are quarantined for manual inspection

## SQLite Throughput Constraints

The queue enforces a single-writer invariant:

| Constraint | Value |
|---|---|
| Max open connections | 1 |
| Locking mode | EXCLUSIVE |
| Journal mode | WAL |
| Busy timeout | 5000 ms |

### Performance Characteristics

| Metric | Approximate Value |
|---|---|
| Sustained write throughput (SSD) | 100–500 events/s |
| P99 enqueue latency (idle) | < 1 ms |
| P99 enqueue latency (under delivery contention) | 5–50 ms |
| Maximum queue depth (practical) | 1M+ events |

### Contention Model

All queue operations serialize through a `sync.Mutex`. Under sustained burst:

1. **Enqueue callers** compete with the delivery worker's read (Peek) and write (Ack/Nack) operations
2. Latency spikes manifest as increased P99 rather than explicit back-pressure
3. The delivery worker polls every 1s (configurable via `DeliveryWorkerConfig.PollInterval`)

## When to Switch to PostgreSQL

Consider a PostgreSQL-backed queue implementation when:

- Sustained posture event rate exceeds **100 events/second**
- P99 enqueue latency exceeds acceptable thresholds (>50 ms)
- Multiple posture emitter replicas need to share a queue (horizontal scaling)
- Operators require concurrent read access for diagnostics without affecting write performance

## PostgreSQL Migration Path

A PostgreSQL queue implementation would provide:

- Row-level locking (no global mutex contention)
- Connection pooling for concurrent readers/writers
- Native support for `SELECT ... FOR UPDATE SKIP LOCKED` work-queue pattern
- Horizontal read scaling via read replicas

### Recommended Schema

```sql
CREATE TABLE posture_queue (
    id             BIGSERIAL PRIMARY KEY,
    event_type     TEXT NOT NULL CHECK (event_type IN ('observed', 'revoked')),
    payload        BYTEA NOT NULL,
    inserted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attempts       INT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_error     TEXT NOT NULL DEFAULT '',
    locked_until   TIMESTAMPTZ
);

CREATE INDEX idx_posture_queue_deliverable
    ON posture_queue (next_attempt_at)
    WHERE locked_until IS NULL OR locked_until < NOW();

CREATE TABLE posture_dead_letter (
    id               BIGSERIAL PRIMARY KEY,
    original_id      BIGINT NOT NULL,
    event_type       TEXT NOT NULL,
    payload          BYTEA NOT NULL,
    inserted_at      TIMESTAMPTZ NOT NULL,
    attempts         INT NOT NULL,
    last_error       TEXT NOT NULL DEFAULT '',
    dead_lettered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

## Read/Write Split Evaluation (SQLite)

An intermediate optimization for the SQLite implementation is splitting the read
path to a separate read-only connection. This requires:

1. Removing `_locking_mode=EXCLUSIVE` from the DSN
2. Opening a second `*sql.DB` for read operations (Peek, Depth, ListDeadLetters)
3. Coordinating the read connection's lifecycle with the write connection

**Trade-offs:**

| Benefit | Cost |
|---|---|
| Diagnostic queries don't block writes | Two connections to manage |
| Lower P99 for read operations | Potential snapshot isolation edge cases |
| Simpler monitoring tooling | Additional testing surface |

This optimization is deferred until profiling identifies read contention as the
primary bottleneck (vs. write serialization).

## Configuration

The delivery worker's behaviour is configurable via `DeliveryWorkerConfig`:

| Parameter | Default | Description |
|---|---|---|
| `MaxAttempts` | 10 | Attempts before dead-lettering |
| `BackoffBase` | 1s | Base for exponential backoff |
| `BackoffMax` | 5m | Maximum backoff duration |
| `BatchSize` | 50 | Events fetched per poll tick |
| `PollInterval` | 1s | Interval between delivery ticks |
| `PluginTimeout` | 5s | Per-plugin delivery timeout |

## Monitoring

The posture emitter exposes Prometheus metrics:

- `posture_queue_depth` — current queue size
- `posture_delivery_errors_total` — delivery failures by plugin
- `posture_dead_letter_total` — events moved to dead-letter table

Alert when `posture_queue_depth` consistently grows (delivery throughput < arrival rate).
