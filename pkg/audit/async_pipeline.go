// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// ErrAsyncPipelineClosed is returned by AsyncPipeline.Append when the
// pipeline has been shut down.
var ErrAsyncPipelineClosed = errors.New("audit: async pipeline is closed")

// ErrAsyncPipelineBufferFull is returned by AsyncPipeline.Append when the
// write-ahead buffer is full and the drop-on-full policy is active.
var ErrAsyncPipelineBufferFull = errors.New("audit: async pipeline buffer full, entry dropped")

// AsyncPipelineConfig configures the write-ahead buffer wrapper.
type AsyncPipelineConfig struct {
	// BufferSize is the capacity of the bounded write-ahead channel.
	// When the buffer is full, new Append calls return ErrAsyncPipelineBufferFull
	// immediately (drop-on-full). This prevents enforcement-path latency from
	// being coupled to slow downstream I/O. Default: 4096.
	BufferSize int

	// FlushInterval is the maximum time between background flush attempts.
	// Entries that accumulate between flushes are written in a single Append
	// call sequence to the inner pipeline. Default: 1 s.
	FlushInterval time.Duration

	// WriteTimeout caps how long a single inner-pipeline Append call may
	// block during the background drain. This prevents a slow or stalled
	// downstream backend from blocking the graceful-shutdown drain forever.
	// Default: 30 s.
	WriteTimeout time.Duration

	// Logger receives operational log messages. Defaults to slog.Default().
	Logger *slog.Logger
}

// AsyncPipeline wraps any Pipeline with a bounded write-ahead buffer so that
// calls to Append from the enforcement hot path return immediately without
// blocking on ledger I/O.
//
// # Consistency guarantee
//
// Audit entries enqueued via Append are durable within one FlushInterval or
// on graceful shutdown (Close). If the process is killed between an Append
// call and the next flush, entries buffered in memory are lost. For
// high-assurance deployments that require guaranteed delivery, operators
// should combine AsyncPipeline with a write-ahead disk queue upstream (e.g.,
// the HTTPTransport buffer in pkg/audit).
//
// # Drop-on-full policy
//
// When BufferSize entries are already buffered, Append returns
// ErrAsyncPipelineBufferFull and the entry is permanently lost from this
// pipeline's perspective. The caller SHOULD log the error with enough context
// (record ID, timestamp) to allow manual reconciliation from the upstream
// audit chain.
//
// Call Start() before use and Close() on shutdown.
type AsyncPipeline struct {
	cfg    AsyncPipelineConfig
	inner  Pipeline
	buffer chan *LogEntry
	wg     sync.WaitGroup
	once   sync.Once
	stopCh chan struct{}

	// closeErr stores the error from inner.Close so concurrent Close calls all
	// return the same value after the once.Do completes.
	closeErr error

	mu     sync.Mutex
	closed bool
}

// NewAsyncPipeline creates a new AsyncPipeline wrapping inner. Call Start()
// before appending entries.
func NewAsyncPipeline(inner Pipeline, cfg AsyncPipelineConfig) *AsyncPipeline {
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 4096
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 1 * time.Second
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 30 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &AsyncPipeline{
		cfg:    cfg,
		inner:  inner,
		buffer: make(chan *LogEntry, cfg.BufferSize),
		stopCh: make(chan struct{}),
	}
}

// Start launches the background drain goroutine. It must be called once
// before Append. ctx cancellation is an alternative to Close().
func (p *AsyncPipeline) Start(ctx context.Context) {
	p.wg.Add(1)
	go p.drainLoop(ctx)
}

// Append enqueues entry for asynchronous delivery to the inner pipeline.
// It returns immediately without blocking on ledger I/O, satisfying the
// enforcement-path latency requirement (P2-3).
//
// Returns:
//   - nil on successful enqueue.
//   - ErrNilEntry if entry is nil.
//   - ErrAsyncPipelineClosed if Close() has been called.
//   - ErrAsyncPipelineBufferFull if the buffer is full (entry dropped).
func (p *AsyncPipeline) Append(_ context.Context, entry *LogEntry) error {
	if entry == nil {
		return ErrNilEntry
	}

	// Hold the lock across the non-blocking send so that the closed check and
	// the channel send are atomic with respect to Close(). Without this, Close()
	// could set closed=true and drain the goroutine between the check and the
	// send, leaving an orphaned entry that is never drained.
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return ErrAsyncPipelineClosed
	}

	select {
	case p.buffer <- entry:
		return nil
	default:
		p.cfg.Logger.Warn("audit: async pipeline buffer full, dropping entry",
			slog.String("event_type", entry.EventType),
			slog.String("tenant_id", entry.TenantID),
		)
		return ErrAsyncPipelineBufferFull
	}
}

// Close signals the drain goroutine to flush all buffered entries and stop.
// It blocks until all in-flight writes complete. Close is idempotent: all
// concurrent and subsequent callers block until the first invocation finishes
// and then return the same error.
//
// The inner pipeline's Close is called exactly once, after all buffered
// entries have been drained, so that resources are released in the correct
// order and double-close of the inner pipeline is prevented.
func (p *AsyncPipeline) Close() error {
	p.once.Do(func() {
		p.mu.Lock()
		p.closed = true
		p.mu.Unlock()
		close(p.stopCh)
		// Wait for the drain goroutine to finish inside once.Do so that
		// concurrent Close callers block here rather than racing to call
		// inner.Close multiple times after wg.Wait returns.
		p.wg.Wait()
		p.closeErr = p.inner.Close()
	})
	return p.closeErr
}

// drainLoop reads from the write-ahead buffer and writes to the inner
// pipeline. It exits when the stop channel is closed after draining all
// remaining buffered entries.
func (p *AsyncPipeline) drainLoop(ctx context.Context) {
	defer p.wg.Done()
	ticker := time.NewTicker(p.cfg.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case entry := <-p.buffer:
			p.writeEntry(entry)

		case <-ticker.C:
			// Flush everything buffered so far without blocking on new arrivals.
			p.drainAvailable()

		case <-ctx.Done():
			// Context cancelled: drain remaining buffer entries then return.
			p.drainAvailable()
			return

		case <-p.stopCh:
			// Graceful shutdown: drain all remaining buffered entries.
			p.drainAvailable()
			return
		}
	}
}

// drainAvailable processes all entries currently in the buffer without
// blocking. It is called on ticker ticks and on shutdown.
func (p *AsyncPipeline) drainAvailable() {
	for {
		select {
		case entry := <-p.buffer:
			p.writeEntry(entry)
		default:
			return
		}
	}
}

// writeEntry forwards a single entry to the inner pipeline, logging errors.
// Errors from the inner pipeline do NOT propagate back to callers because
// Append was already acknowledged as non-blocking.
//
// WriteTimeout is always applied to cap how long a single inner-pipeline
// Append call may block, preventing a slow or stalled backend from blocking
// the graceful-shutdown drain indefinitely.
//
// I-5 fix: if the entry carries a valid TraceSpanContext (populated by the
// caller via audit.WithTraceContext), the write context is linked to that span
// so that audit-write spans appear as children of the originating enforcement
// span in distributed traces rather than as unlinked root spans.
func (p *AsyncPipeline) writeEntry(entry *LogEntry) {
	base := context.Background()
	if entry.TraceSpanContext.IsValid() {
		base = trace.ContextWithRemoteSpanContext(base, entry.TraceSpanContext)
	}
	writeCtx, cancel := context.WithTimeout(base, p.cfg.WriteTimeout)
	defer cancel()
	if err := p.inner.Append(writeCtx, entry); err != nil {
		p.cfg.Logger.Error("audit: async pipeline write failed",
			slog.String("event_type", entry.EventType),
			slog.String("tenant_id", entry.TenantID),
			slog.String("error", err.Error()),
		)
	}
}

// WithTraceContext stamps entry.TraceSpanContext with the active span from ctx
// so that the async drain goroutine can link its write spans to the caller's
// trace. Call this before passing an entry to Append:
//
//	audit.WithTraceContext(ctx, entry)
//	pipeline.Append(ctx, entry)
func WithTraceContext(ctx context.Context, entry *LogEntry) {
	if entry != nil {
		entry.TraceSpanContext = trace.SpanFromContext(ctx).SpanContext()
	}
}
