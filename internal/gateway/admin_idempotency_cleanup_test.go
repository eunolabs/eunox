// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdempotencyStore_Start_CleansUpExpiredEntries(t *testing.T) {
	t.Parallel()

	now := time.Now()
	var mu sync.Mutex
	nowFn := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	setNow := func(n time.Time) {
		mu.Lock()
		defer mu.Unlock()
		now = n
	}

	store := NewIdempotencyStore(
		WithIdempotencyTTL(1*time.Minute),
		WithIdempotencyCleanupInterval(20*time.Millisecond),
		WithIdempotencyTimeFunc(nowFn),
	)

	// Insert an entry.
	store.Set("k1", []byte(`{}`), 200, nil)
	require.Equal(t, 1, store.Len())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store.Start(ctx)

	// Advance fake clock past the TTL.
	setNow(now.Add(2 * time.Minute))

	// Wait for the background goroutine to evict the expired entry.
	require.Eventually(t, func() bool {
		return store.Len() == 0
	}, 2*time.Second, 10*time.Millisecond, "background cleanup must evict expired entries")
}

func TestIdempotencyStore_Start_StopsOnContextCancel(t *testing.T) {
	t.Parallel()

	store := NewIdempotencyStore(
		WithIdempotencyCleanupInterval(10 * time.Millisecond),
	)

	ctx, cancel := context.WithCancel(context.Background())
	store.Start(ctx)

	// Cancel context and ensure no panic / data race after goroutine exits.
	cancel()
	time.Sleep(50 * time.Millisecond)
}

func TestIdempotencyStore_Start_KeepsNonExpiredEntries(t *testing.T) {
	t.Parallel()

	now := time.Now()
	store := NewIdempotencyStore(
		WithIdempotencyTTL(1*time.Hour),
		WithIdempotencyCleanupInterval(20*time.Millisecond),
		WithIdempotencyTimeFunc(func() time.Time { return now }),
	)

	store.Set("fresh", []byte(`{}`), 200, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store.Start(ctx)

	// Even after several cleanup cycles the non-expired entry must survive.
	time.Sleep(60 * time.Millisecond)
	assert.Equal(t, 1, store.Len(), "non-expired entries must not be evicted")
}
