// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/eunolabs/eunox/pkg/redisfailover"
	"github.com/redis/go-redis/v9"
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

// --- RedisDPoPStore tests ---

func TestRedisDPoPStore_MarkUsed_FirstUseNotReplay(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	store := NewRedisDPoPStore(client, 5*time.Minute)
	seen, err := store.MarkUsed(context.Background(), "jti-redis-1")
	require.NoError(t, err)
	assert.False(t, seen, "first use must not be reported as replay")
}

func TestRedisDPoPStore_MarkUsed_DetectsReplay(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	store := NewRedisDPoPStore(client, 5*time.Minute)

	_, err := store.MarkUsed(context.Background(), "jti-replay")
	require.NoError(t, err)

	seen, err := store.MarkUsed(context.Background(), "jti-replay")
	require.NoError(t, err)
	assert.True(t, seen, "second use of same JTI within TTL must be reported as replay")
}

func TestRedisDPoPStore_MarkUsed_AllowsAfterTTLExpiry(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	ttl := 1 * time.Second
	store := NewRedisDPoPStore(client, ttl)

	_, err := store.MarkUsed(context.Background(), "jti-expire")
	require.NoError(t, err)

	// Advance miniredis clock past the TTL.
	mr.FastForward(2 * time.Second)

	seen, err := store.MarkUsed(context.Background(), "jti-expire")
	require.NoError(t, err)
	assert.False(t, seen, "JTI must be re-accepted after Redis TTL expiry")
}

func TestRedisDPoPStore_MarkUsed_DifferentJTIsAreIndependent(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	store := NewRedisDPoPStore(client, 5*time.Minute)

	seen1, err := store.MarkUsed(context.Background(), "jti-a")
	require.NoError(t, err)
	seen2, err := store.MarkUsed(context.Background(), "jti-b")
	require.NoError(t, err)

	assert.False(t, seen1)
	assert.False(t, seen2, "different JTIs must be independently tracked")
}

// --- ResilientRedisDPoPStore tests ---

func TestResilientRedisDPoPStore_FailClosedOnRedisError(t *testing.T) {
	t.Parallel()

	// Start then immediately stop miniredis to simulate a broken connection.
	mr, err := miniredis.Run()
	require.NoError(t, err)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Close() // break the connection
	t.Cleanup(func() { _ = client.Close() })

	monitor := redisfailover.NewMonitor()
	reporter := monitor.Register("dpop-test")
	inner := NewRedisDPoPStore(client, 5*time.Minute)
	store := NewResilientRedisDPoPStore(inner, reporter, slog.Default())

	seen, err := store.MarkUsed(context.Background(), "jti-fail-closed")
	require.NoError(t, err, "resilient store must absorb the Redis error")
	assert.True(t, seen, "when Redis is down, store must fail closed (treat as replay)")
	assert.Equal(t, redisfailover.Degraded, reporter.State())
}

func TestResilientRedisDPoPStore_HealthyWhenRedisAvailable(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	monitor := redisfailover.NewMonitor()
	reporter := monitor.Register("dpop-healthy")
	inner := NewRedisDPoPStore(client, 5*time.Minute)
	store := NewResilientRedisDPoPStore(inner, reporter, slog.Default())

	seen, err := store.MarkUsed(context.Background(), "jti-healthy")
	require.NoError(t, err)
	assert.False(t, seen)
	assert.Equal(t, redisfailover.Healthy, reporter.State())
}

func TestResilientRedisDPoPStore_ReplayDetectedWhileHealthy(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	monitor := redisfailover.NewMonitor()
	reporter := monitor.Register("dpop-replay")
	inner := NewRedisDPoPStore(client, 5*time.Minute)
	store := NewResilientRedisDPoPStore(inner, reporter, slog.Default())

	_, _ = store.MarkUsed(context.Background(), "jti-resilient")

	seen, err := store.MarkUsed(context.Background(), "jti-resilient")
	require.NoError(t, err)
	assert.True(t, seen, "replay must be detected when Redis is healthy")
}
