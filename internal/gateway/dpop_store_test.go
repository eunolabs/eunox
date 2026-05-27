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

func TestInMemoryDPoPStore_MarkUsed_ReturnsNotSeenFirst(t *testing.T) {
	store := NewInMemoryDPoPStore(5 * time.Minute)
	seen, err := store.MarkUsed(context.Background(), "jti-1")
	require.NoError(t, err)
	assert.False(t, seen, "first use should not be detected as replay")
}

func TestInMemoryDPoPStore_MarkUsed_DetectsReplay(t *testing.T) {
	store := NewInMemoryDPoPStore(5 * time.Minute)
	_, _ = store.MarkUsed(context.Background(), "jti-1")
	seen, err := store.MarkUsed(context.Background(), "jti-1")
	require.NoError(t, err)
	assert.True(t, seen, "second use of same JTI within TTL must be detected as replay")
}

func TestInMemoryDPoPStore_MarkUsed_AllowsAfterExpiry(t *testing.T) {
	now := time.Now()
	store := &InMemoryDPoPStore{
		seen:            make(map[string]time.Time),
		ttl:             5 * time.Minute,
		cleanupInterval: defaultDPoPCleanupInterval,
		now:             func() time.Time { return now },
	}

	// Mark as used.
	seen, err := store.MarkUsed(context.Background(), "jti-exp")
	require.NoError(t, err)
	assert.False(t, seen)

	// Advance time past the TTL.
	now = now.Add(6 * time.Minute)
	seen, err = store.MarkUsed(context.Background(), "jti-exp")
	require.NoError(t, err)
	assert.False(t, seen, "JTI should be accepted again after TTL expiry")
}

// background cleanup goroutine test.

func TestInMemoryDPoPStore_Start_CleansUpExpiredEntries(t *testing.T) {
	now := time.Now()
	var mu sync.Mutex
	nowFn := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	setNow := func(t time.Time) {
		mu.Lock()
		defer mu.Unlock()
		now = t
	}

	store := &InMemoryDPoPStore{
		seen:            make(map[string]time.Time),
		ttl:             1 * time.Minute,
		cleanupInterval: 50 * time.Millisecond, // fast for testing
		now:             nowFn,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store.Start(ctx)

	// Insert an entry.
	_, err := store.MarkUsed(context.Background(), "jti-cleanup")
	require.NoError(t, err)

	// Advance fake clock past TTL.
	setNow(time.Now().Add(2 * time.Minute))

	// Wait for the cleanup goroutine to evict the expired entry.
	require.Eventually(t, func() bool {
		store.mu.Lock()
		defer store.mu.Unlock()
		_, exists := store.seen["jti-cleanup"]
		return !exists
	}, 2*time.Second, 10*time.Millisecond, "cleanup goroutine should have removed the expired entry")
}

func TestInMemoryDPoPStore_Start_StopsOnContextCancel(t *testing.T) {
	store := NewInMemoryDPoPStore(5 * time.Minute)
	store.cleanupInterval = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	store.Start(ctx)

	// Cancel and ensure no panic or data race.
	cancel()
	time.Sleep(50 * time.Millisecond) // let goroutine exit
}
