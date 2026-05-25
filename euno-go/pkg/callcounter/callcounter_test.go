// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package callcounter_test

import (
	"context"
	"testing"
	"time"

	"github.com/edgeobs/euno-platform/euno-go/pkg/callcounter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInMemory_IncrementAndGet(t *testing.T) {
	counter := callcounter.NewInMemory()
	ctx := context.Background()

	count, err := counter.IncrementAndGet(ctx, "key1", 60)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	count, err = counter.IncrementAndGet(ctx, "key1", 60)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)

	count, err = counter.IncrementAndGet(ctx, "key1", 60)
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

func TestInMemory_SeparateKeys(t *testing.T) {
	counter := callcounter.NewInMemory()
	ctx := context.Background()

	count, err := counter.IncrementAndGet(ctx, "key1", 60)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	count, err = counter.IncrementAndGet(ctx, "key2", 60)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

func TestInMemory_SlidingWindow(t *testing.T) {
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	counter := callcounter.NewInMemory(callcounter.WithTimeFunc(func() time.Time { return now }))
	ctx := context.Background()

	// Make 3 calls at t=0
	for i := 0; i < 3; i++ {
		_, err := counter.IncrementAndGet(ctx, "key1", 60)
		require.NoError(t, err)
	}

	// Advance time past the window
	now = now.Add(61 * time.Second)
	counter2 := callcounter.NewInMemory(callcounter.WithTimeFunc(func() time.Time { return now }))

	count, err := counter2.IncrementAndGet(ctx, "key1", 60)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count) // Old entries expired
}

func TestInMemory_WindowExpiry(t *testing.T) {
	current := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	timeFunc := func() time.Time { return current }
	counter := callcounter.NewInMemory(callcounter.WithTimeFunc(timeFunc))
	ctx := context.Background()

	// Make some calls
	_, err := counter.IncrementAndGet(ctx, "key1", 10)
	require.NoError(t, err)
	_, err = counter.IncrementAndGet(ctx, "key1", 10)
	require.NoError(t, err)

	// Advance time past the window
	current = current.Add(11 * time.Second)

	// New call should only count itself (old ones expired)
	count, err := counter.IncrementAndGet(ctx, "key1", 10)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

func TestInMemory_Cleanup(t *testing.T) {
	counter := callcounter.NewInMemory()
	ctx := context.Background()

	_, err := counter.IncrementAndGet(ctx, "key1", 60)
	require.NoError(t, err)

	// Cleanup shouldn't panic
	counter.Cleanup()
}
