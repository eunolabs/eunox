// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package posture

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSQLiteQueue_PushAndPeek(t *testing.T) {
	q, err := NewSQLiteQueue(":memory:")
	require.NoError(t, err)
	defer func() { _ = q.Close() }()

	// Push an event.
	id, err := q.Push(EventObserved, []byte(`{"agentId":"agent-1"}`))
	require.NoError(t, err)
	assert.Greater(t, id, int64(0))

	// Peek should return the event.
	events, err := q.Peek(10)
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

	id, err := q.Push(EventObserved, []byte(`{}`))
	require.NoError(t, err)

	// Ack removes the event.
	err = q.Ack(id)
	require.NoError(t, err)

	events, err := q.Peek(10)
	require.NoError(t, err)
	assert.Empty(t, events)
}

func TestSQLiteQueue_Nack(t *testing.T) {
	q, err := NewSQLiteQueue(":memory:")
	require.NoError(t, err)
	defer func() { _ = q.Close() }()

	id, err := q.Push(EventObserved, []byte(`{}`))
	require.NoError(t, err)

	// Nack with a far-future next attempt.
	futureMs := int64(99999999999999)
	err = q.Nack(id, futureMs, "transient failure")
	require.NoError(t, err)

	// Peek should return nothing (not yet ready).
	events, err := q.Peek(10)
	require.NoError(t, err)
	assert.Empty(t, events)
}

func TestSQLiteQueue_Depth(t *testing.T) {
	q, err := NewSQLiteQueue(":memory:")
	require.NoError(t, err)
	defer func() { _ = q.Close() }()

	depth, err := q.Depth()
	require.NoError(t, err)
	assert.Equal(t, int64(0), depth)

	_, err = q.Push(EventObserved, []byte(`{}`))
	require.NoError(t, err)
	_, err = q.Push(EventRevoked, []byte(`{}`))
	require.NoError(t, err)

	depth, err = q.Depth()
	require.NoError(t, err)
	assert.Equal(t, int64(2), depth)
}

func TestSQLiteQueue_MultiplePushAndOrdering(t *testing.T) {
	q, err := NewSQLiteQueue(":memory:")
	require.NoError(t, err)
	defer func() { _ = q.Close() }()

	id1, _ := q.Push(EventObserved, []byte(`{"n":1}`))
	id2, _ := q.Push(EventObserved, []byte(`{"n":2}`))
	id3, _ := q.Push(EventRevoked, []byte(`{"n":3}`))

	events, err := q.Peek(2)
	require.NoError(t, err)
	require.Len(t, events, 2)
	assert.Equal(t, id1, events[0].ID)
	assert.Equal(t, id2, events[1].ID)

	// Ack first, peek again.
	require.NoError(t, q.Ack(id1))
	require.NoError(t, q.Ack(id2))

	events, err = q.Peek(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, id3, events[0].ID)
	assert.Equal(t, EventRevoked, events[0].Type)
}

func TestSQLiteQueue_NackIncrementsAttempts(t *testing.T) {
	q, err := NewSQLiteQueue(":memory:")
	require.NoError(t, err)
	defer func() { _ = q.Close() }()

	id, _ := q.Push(EventObserved, []byte(`{}`))

	// Nack with immediate retry (nextAttemptAt = 0).
	require.NoError(t, q.Nack(id, 0, "fail 1"))

	events, err := q.Peek(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, 1, events[0].Attempts)
	assert.Equal(t, "fail 1", events[0].LastError)

	// Nack again.
	require.NoError(t, q.Nack(id, 0, "fail 2"))

	events, err = q.Peek(10)
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

	_, err = q.Push(EventObserved, []byte(`{"durable":true}`))
	require.NoError(t, err)

	// Close and reopen.
	require.NoError(t, q.Close())

	q2, err := NewSQLiteQueue(path)
	require.NoError(t, err)
	defer func() { _ = q2.Close() }()

	events, err := q2.Peek(10)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, `{"durable":true}`, string(events[0].Payload))
}
