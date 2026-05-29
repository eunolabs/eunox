// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPipeline is a synchronous Pipeline for testing. Append is optionally
// slow to simulate I/O latency.
type mockPipeline struct {
	mu      sync.Mutex
	entries []*LogEntry
	delay   time.Duration
	err     error
	closed  bool
}

func (m *mockPipeline) Append(_ context.Context, entry *LogEntry) error {
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	cp := *entry
	m.entries = append(m.entries, &cp)
	return nil
}

func (m *mockPipeline) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockPipeline) len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

func TestAsyncPipeline_AppendAndFlush(t *testing.T) {
	inner := &mockPipeline{}
	p := NewAsyncPipeline(inner, AsyncPipelineConfig{
		BufferSize:    64,
		FlushInterval: 50 * time.Millisecond,
	})
	p.Start(context.Background())

	entry := &LogEntry{EventType: "test.event", TenantID: "tenant-1"}
	err := p.Append(context.Background(), entry)
	require.NoError(t, err)

	// Close flushes all buffered entries before returning.
	require.NoError(t, p.Close())

	assert.Equal(t, 1, inner.len())
	assert.True(t, inner.closed)
}

func TestAsyncPipeline_NonBlocking(t *testing.T) {
	// The inner pipeline has a 200 ms delay per write. Append should return
	// immediately regardless.
	inner := &mockPipeline{delay: 200 * time.Millisecond}
	p := NewAsyncPipeline(inner, AsyncPipelineConfig{
		BufferSize:    64,
		FlushInterval: 500 * time.Millisecond,
	})
	p.Start(context.Background())
	t.Cleanup(func() { _ = p.Close() })

	entry := &LogEntry{EventType: "slow.event"}

	start := time.Now()
	err := p.Append(context.Background(), entry)
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.Less(t, elapsed, 50*time.Millisecond, "Append must return before the inner pipeline write completes")
}

func TestAsyncPipeline_BufferFull(t *testing.T) {
	// Inner pipeline blocks indefinitely to fill the buffer.
	blocked := make(chan struct{})
	inner := &mockPipeline{}
	// Override Append with a blocking version via a wrapper.
	blocking := &blockingPipeline{inner: inner, block: blocked}
	p := NewAsyncPipeline(blocking, AsyncPipelineConfig{
		BufferSize:    2,
		FlushInterval: time.Hour, // prevent timer-based drain
	})
	p.Start(context.Background())
	t.Cleanup(func() {
		close(blocked)
		_ = p.Close()
	})

	entry := &LogEntry{EventType: "test"}

	// Fill the buffer (2 entries) + 1 in-flight in drain goroutine.
	var dropErr error
	for i := 0; i < 10; i++ {
		err := p.Append(context.Background(), entry)
		if errors.Is(err, ErrAsyncPipelineBufferFull) {
			dropErr = err
			break
		}
	}
	assert.ErrorIs(t, dropErr, ErrAsyncPipelineBufferFull)
}

func TestAsyncPipeline_ClosedReturnError(t *testing.T) {
	inner := &mockPipeline{}
	p := NewAsyncPipeline(inner, AsyncPipelineConfig{})
	p.Start(context.Background())
	require.NoError(t, p.Close())

	err := p.Append(context.Background(), &LogEntry{})
	assert.ErrorIs(t, err, ErrAsyncPipelineClosed)
}

func TestAsyncPipeline_CloseIdempotent(t *testing.T) {
	inner := &mockPipeline{}
	p := NewAsyncPipeline(inner, AsyncPipelineConfig{})
	p.Start(context.Background())
	require.NoError(t, p.Close())
	require.NoError(t, p.Close()) // must not panic or deadlock
}

func TestAsyncPipeline_FlushInterval(t *testing.T) {
	// Entries should be flushed even without calling Close when the ticker fires.
	var received atomic.Int64
	inner := &countingPipeline{count: &received}

	p := NewAsyncPipeline(inner, AsyncPipelineConfig{
		BufferSize:    64,
		FlushInterval: 50 * time.Millisecond,
	})
	p.Start(context.Background())
	t.Cleanup(func() { _ = p.Close() })

	for i := 0; i < 5; i++ {
		_ = p.Append(context.Background(), &LogEntry{EventType: "tick"})
	}

	require.Eventually(t, func() bool {
		return received.Load() == 5
	}, 500*time.Millisecond, 10*time.Millisecond)
}

func TestAsyncPipeline_InnerWriteError_Logged(t *testing.T) {
	// Inner pipeline errors must not propagate to Append callers — they must
	// only be logged.
	logs := &logCapture{}
	inner := &mockPipeline{err: errors.New("db write failed")}
	p := NewAsyncPipeline(inner, AsyncPipelineConfig{
		Logger: slog.New(logs),
	})
	p.Start(context.Background())

	err := p.Append(context.Background(), &LogEntry{EventType: "e"})
	require.NoError(t, err, "Append must not return the inner pipeline error")

	require.NoError(t, p.Close())
	assert.True(t, logs.hasMsg("audit: async pipeline write failed"),
		"expected error log from inner pipeline failure")
}

func TestAsyncPipeline_ContextCancel(t *testing.T) {
	// Cancelling the context passed to Start should drain the buffer and stop.
	inner := &mockPipeline{}
	p := NewAsyncPipeline(inner, AsyncPipelineConfig{
		BufferSize:    64,
		FlushInterval: time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	p.Start(ctx)

	for i := 0; i < 3; i++ {
		_ = p.Append(context.Background(), &LogEntry{EventType: "ctx"})
	}

	cancel()
	// Close must return without deadlocking even when context was cancelled.
	require.NoError(t, p.Close())
	// Inner pipeline should be closed.
	assert.True(t, inner.closed)
}

func TestAsyncPipeline_ConcurrentCloseCallsInnerOnlyOnce(t *testing.T) {
	// Before the fix, concurrent Close calls would each call inner.Close()
	// after the once.Do barrier, resulting in multiple close calls.
	var closeCount atomic.Int64
	inner := &countedClosePipeline{count: &closeCount}
	p := NewAsyncPipeline(inner, AsyncPipelineConfig{})
	p.Start(context.Background())

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_ = p.Close()
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(1), closeCount.Load(),
		"inner.Close must be called exactly once regardless of concurrent Close calls")
}

// --- test helpers ---

type blockingPipeline struct {
	inner Pipeline
	block chan struct{}
}

func (b *blockingPipeline) Append(ctx context.Context, entry *LogEntry) error {
	select {
	case <-b.block:
	case <-ctx.Done():
	}
	return b.inner.Append(ctx, entry)
}

func (b *blockingPipeline) Close() error { return b.inner.Close() }

type countingPipeline struct {
	count *atomic.Int64
}

func (c *countingPipeline) Append(_ context.Context, _ *LogEntry) error {
	c.count.Add(1)
	return nil
}

func (c *countingPipeline) Close() error { return nil }

// countedClosePipeline counts how many times Close is called.
type countedClosePipeline struct {
	count *atomic.Int64
}

func (c *countedClosePipeline) Append(_ context.Context, _ *LogEntry) error { return nil }
func (c *countedClosePipeline) Close() error {
	c.count.Add(1)
	return nil
}

// logCapture implements slog.Handler and captures log messages.
type logCapture struct {
	mu   sync.Mutex
	msgs []string
}

func (l *logCapture) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (l *logCapture) Handle(_ context.Context, r slog.Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.msgs = append(l.msgs, r.Message)
	return nil
}

func (l *logCapture) WithAttrs(_ []slog.Attr) slog.Handler { return l }
func (l *logCapture) WithGroup(_ string) slog.Handler      { return l }

func (l *logCapture) hasMsg(msg string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, m := range l.msgs {
		if m == msg {
			return true
		}
	}
	return false
}
