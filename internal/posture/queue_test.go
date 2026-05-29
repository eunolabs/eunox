// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package posture

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSQLiteQueue_PushAndPeek(t *testing.T) {
	q, err := NewSQLiteQueue(":memory:")
	require.NoError(t, err)
	defer func() { _ = q.Close() }()

	// Push an event.
	id, err := q.Push(context.Background(), EventObserved, []byte(`{"agentId":"agent-1"}`))
	require.NoError(t, err)
	assert.Greater(t, id, int64(0))

	// Peek should return the event.
	events, err := q.Peek(context.Background(), 10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, id, events[0].ID)
	assert.Equal(t, EventObserved, events[0].Type)
	assert.Equal(t, `{"agentId":"agent-1"}`, string(events[0].Payload))
	assert.Equal(t, 0, events[0].Attempts)
}

func TestSQLiteQueue_Ack(t *testing.T) {
	q, err := NewSQLiteQueue(":memory:")
	require.NoError(t, err)
	defer func() { _ = q.Close() }()

	id, err := q.Push(context.Background(), EventObserved, []byte(`{}`))
	require.NoError(t, err)

	// Ack removes the event.
	err = q.Ack(context.Background(), id)
	require.NoError(t, err)

	events, err := q.Peek(context.Background(), 10)
	require.NoError(t, err)
	assert.Empty(t, events)
}

func TestSQLiteQueue_Nack(t *testing.T) {
	q, err := NewSQLiteQueue(":memory:")
	require.NoError(t, err)
	defer func() { _ = q.Close() }()

	id, err := q.Push(context.Background(), EventObserved, []byte(`{}`))
	require.NoError(t, err)

	// Nack with a far-future next attempt.
	futureMs := int64(99999999999999)
	err = q.Nack(context.Background(), id, futureMs, "transient failure")
	require.NoError(t, err)

	// Peek should return nothing (not yet ready).
	events, err := q.Peek(context.Background(), 10)
	require.NoError(t, err)
	assert.Empty(t, events)
}

func TestSQLiteQueue_Depth(t *testing.T) {
	q, err := NewSQLiteQueue(":memory:")
	require.NoError(t, err)
	defer func() { _ = q.Close() }()

	depth, err := q.Depth(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(0), depth)

	_, err = q.Push(context.Background(), EventObserved, []byte(`{}`))
	require.NoError(t, err)
	_, err = q.Push(context.Background(), EventRevoked, []byte(`{}`))
	require.NoError(t, err)

	depth, err = q.Depth(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(2), depth)
}

func TestSQLiteQueue_MultiplePushAndOrdering(t *testing.T) {
	q, err := NewSQLiteQueue(":memory:")
	require.NoError(t, err)
	defer func() { _ = q.Close() }()

	id1, err := q.Push(context.Background(), EventObserved, []byte(`{"n":1}`))
	require.NoError(t, err)
	id2, err := q.Push(context.Background(), EventObserved, []byte(`{"n":2}`))
	require.NoError(t, err)
	id3, err := q.Push(context.Background(), EventRevoked, []byte(`{"n":3}`))
	require.NoError(t, err)

	events, err := q.Peek(context.Background(), 2)
	require.NoError(t, err)
	require.Len(t, events, 2)
	assert.Equal(t, id1, events[0].ID)
	assert.Equal(t, id2, events[1].ID)

	// Ack first, peek again.
	require.NoError(t, q.Ack(context.Background(), id1))
	require.NoError(t, q.Ack(context.Background(), id2))

	events, err = q.Peek(context.Background(), 10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, id3, events[0].ID)
	assert.Equal(t, EventRevoked, events[0].Type)
}

func TestSQLiteQueue_NackIncrementsAttempts(t *testing.T) {
	q, err := NewSQLiteQueue(":memory:")
	require.NoError(t, err)
	defer func() { _ = q.Close() }()

	id, _ := q.Push(context.Background(), EventObserved, []byte(`{}`))

	// Nack with immediate retry (nextAttemptAt = 0).
	require.NoError(t, q.Nack(context.Background(), id, 0, "fail 1"))

	events, err := q.Peek(context.Background(), 10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, 1, events[0].Attempts)
	assert.Equal(t, "fail 1", events[0].LastError)

	// Nack again.
	require.NoError(t, q.Nack(context.Background(), id, 0, "fail 2"))

	events, err = q.Peek(context.Background(), 10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, 2, events[0].Attempts)
	assert.Equal(t, "fail 2", events[0].LastError)
}

func TestSQLiteQueue_DurabilityAfterReopen(t *testing.T) {
	// Use a temp file to test durability.
	path := t.TempDir() + "/test-queue.db"

	q, err := NewSQLiteQueue(path)
	require.NoError(t, err)

	_, err = q.Push(context.Background(), EventObserved, []byte(`{"durable":true}`))
	require.NoError(t, err)

	// Close and reopen.
	require.NoError(t, q.Close())

	q2, err := NewSQLiteQueue(path)
	require.NoError(t, err)
	defer func() { _ = q2.Close() }()

	events, err := q2.Peek(context.Background(), 10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, `{"durable":true}`, string(events[0].Payload))
}

func TestSQLiteQueue_DeadLetter(t *testing.T) {
	q, err := NewSQLiteQueue(":memory:")
	require.NoError(t, err)
	defer func() { _ = q.Close() }()

	ctx := context.Background()

	// Push an event and dead-letter it.
	id, err := q.Push(ctx, EventObserved, []byte(`{"agent":"a1"}`))
	require.NoError(t, err)

	events, err := q.Peek(ctx, 1)
	require.NoError(t, err)
	require.Len(t, events, 1)

	err = q.DeadLetter(ctx, &events[0])
	require.NoError(t, err)

	// Queue should be empty.
	depth, err := q.Depth(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), depth)

	// Dead-letter queue should have 1 item.
	dlDepth, err := q.DeadLetterDepth(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), dlDepth)

	// List dead letters.
	dls, err := q.ListDeadLetters(ctx, 10)
	require.NoError(t, err)
	require.Len(t, dls, 1)
	assert.Equal(t, id, dls[0].OriginalID)
	assert.Equal(t, EventObserved, dls[0].Type)
	assert.Equal(t, `{"agent":"a1"}`, string(dls[0].Payload))
	assert.Greater(t, dls[0].DeadLetteredAt, int64(0))
}

func TestSQLiteQueue_DeadLetter_NotFound(t *testing.T) {
	q, err := NewSQLiteQueue(":memory:")
	require.NoError(t, err)
	defer func() { _ = q.Close() }()

	ctx := context.Background()

	// Dead-lettering a non-existent event should return an error.
	err = q.DeadLetter(ctx, &QueuedEvent{ID: 9999, Type: EventObserved, Payload: []byte(`{}`)})
	assert.Error(t, err)
}

func TestSQLiteQueue_DeadLetterDepth_Empty(t *testing.T) {
	q, err := NewSQLiteQueue(":memory:")
	require.NoError(t, err)
	defer func() { _ = q.Close() }()

	ctx := context.Background()

	depth, err := q.DeadLetterDepth(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), depth)
}

func TestSQLiteQueue_ContextCancelled(t *testing.T) {
	q, err := NewSQLiteQueue(":memory:")
	require.NoError(t, err)
	defer func() { _ = q.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err = q.Push(ctx, EventObserved, []byte(`{}`))
	assert.ErrorIs(t, err, context.Canceled)

	_, err = q.Peek(ctx, 10)
	assert.ErrorIs(t, err, context.Canceled)

	_, err = q.Depth(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}

// TestSQLiteQueue_Push_RespectsContextCancellation verifies that a Push
// blocked on the semaphore returns context.Canceled when its context is
// cancelled while waiting (backpressure / T-6).
func TestSQLiteQueue_Push_RespectsContextCancellation(t *testing.T) {
	t.Parallel()

	q, err := NewSQLiteQueue(":memory:")
	require.NoError(t, err)
	defer func() { _ = q.Close() }()

	// Manually hold the semaphore to simulate the delivery worker owning the lock.
	q.sem <- struct{}{}
	defer func() { <-q.sem }()

	ctx, cancel := context.WithCancel(context.Background())

	// Push in background — it will block waiting for the semaphore.
	done := make(chan error, 1)
	go func() {
		_, pushErr := q.Push(ctx, EventObserved, []byte(`{}`))
		done <- pushErr
	}()

	// Give the goroutine time to enter the acquire select.
	time.Sleep(20 * time.Millisecond)

	// Cancel the context — Push must unblock and return context.Canceled.
	cancel()

	select {
	case pushErr := <-done:
		assert.ErrorIs(t, pushErr, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("Push did not unblock after context cancellation")
	}
}

// TestSQLiteQueue_Push_AbortsWhenContextExpires verifies that a Push
// blocked on the semaphore returns context.DeadlineExceeded when its
// deadline expires while waiting (backpressure / T-6).
func TestSQLiteQueue_Push_AbortsWhenContextExpires(t *testing.T) {
	t.Parallel()

	q, err := NewSQLiteQueue(":memory:")
	require.NoError(t, err)
	defer func() { _ = q.Close() }()

	// Manually hold the semaphore.
	q.sem <- struct{}{}
	defer func() { <-q.sem }()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, pushErr := q.Push(ctx, EventObserved, []byte(`{}`))
	assert.ErrorIs(t, pushErr, context.DeadlineExceeded)
}
