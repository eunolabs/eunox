// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInMemoryLimiterAllowsUpToRateWithinWindow(t *testing.T) {
	current := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	limiter := NewInMemory(Config{Rate: 3, Window: time.Minute})
	limiter.now = func() time.Time { return current }
	t.Cleanup(limiter.Close)

	for i := 0; i < 3; i++ {
		allowed, err := limiter.Allow(context.Background(), "issuer")
		require.NoError(t, err)
		assert.True(t, allowed)
	}
}

func TestInMemoryLimiterDeniesOverRate(t *testing.T) {
	current := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	limiter := NewInMemory(Config{Rate: 2, Window: time.Minute})
	limiter.now = func() time.Time { return current }
	t.Cleanup(limiter.Close)

	for i := 0; i < 2; i++ {
		allowed, err := limiter.Allow(context.Background(), "issuer")
		require.NoError(t, err)
		assert.True(t, allowed)
	}

	allowed, err := limiter.Allow(context.Background(), "issuer")
	require.NoError(t, err)
	assert.False(t, allowed)
}

func TestInMemoryLimiterResetsAfterWindow(t *testing.T) {
	current := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	limiter := NewInMemory(Config{Rate: 2, Window: 10 * time.Second})
	limiter.now = func() time.Time { return current }
	t.Cleanup(limiter.Close)

	for i := 0; i < 2; i++ {
		allowed, err := limiter.Allow(context.Background(), "issuer")
		require.NoError(t, err)
		assert.True(t, allowed)
	}

	current = current.Add(10 * time.Second)

	allowed, err := limiter.Allow(context.Background(), "issuer")
	require.NoError(t, err)
	assert.True(t, allowed)
}

func TestInMemoryLimiterDetailedResult(t *testing.T) {
	current := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	limiter := NewInMemory(Config{Rate: 2, Window: 10 * time.Second})
	limiter.now = func() time.Time { return current }
	t.Cleanup(limiter.Close)

	result, err := limiter.Check(context.Background(), "issuer")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, 1, result.Remaining)
	assert.Equal(t, 10*time.Second, result.ResetAfter)
	assert.Zero(t, result.RetryAfter)

	current = current.Add(2 * time.Second)
	result, err = limiter.Check(context.Background(), "issuer")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, 0, result.Remaining)
	assert.Equal(t, 8*time.Second, result.ResetAfter)
	assert.Zero(t, result.RetryAfter)

	result, err = limiter.Check(context.Background(), "issuer")
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Equal(t, 0, result.Remaining)
	assert.Equal(t, 8*time.Second, result.ResetAfter)
	assert.Equal(t, 8*time.Second, result.RetryAfter)
}

func TestInMemoryLimiterConcurrentAccess(t *testing.T) {
	limiter := NewInMemory(Config{Rate: 50, Window: time.Minute})
	t.Cleanup(limiter.Close)

	var allowed atomic.Int64
	var failures atomic.Int64
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := limiter.Allow(context.Background(), "issuer")
			if err != nil {
				failures.Add(1)
				return
			}
			if ok {
				allowed.Add(1)
			}
		}()
	}

	wg.Wait()
	assert.Zero(t, failures.Load())
	assert.Equal(t, int64(50), allowed.Load())
}

func TestInMemoryLimiterDifferentKeysAreIndependent(t *testing.T) {
	current := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	limiter := NewInMemory(Config{Rate: 1, Window: time.Minute})
	limiter.now = func() time.Time { return current }
	t.Cleanup(limiter.Close)

	allowed, err := limiter.Allow(context.Background(), "issuer-a")
	require.NoError(t, err)
	assert.True(t, allowed)

	allowed, err = limiter.Allow(context.Background(), "issuer-b")
	require.NoError(t, err)
	assert.True(t, allowed)

	allowed, err = limiter.Allow(context.Background(), "issuer-a")
	require.NoError(t, err)
	assert.False(t, allowed)
}

func TestInMemoryLimiterCleanupRemovesExpiredEntries(t *testing.T) {
	current := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	limiter := NewInMemory(Config{Rate: 1, Window: 5 * time.Second})
	limiter.now = func() time.Time { return current }
	t.Cleanup(limiter.Close)

	allowed, err := limiter.Allow(context.Background(), "issuer")
	require.NoError(t, err)
	assert.True(t, allowed)
	require.Len(t, limiter.entries, 1)

	current = current.Add(6 * time.Second)
	limiter.Cleanup()
	assert.Empty(t, limiter.entries)
}

func TestRedisLimiterCheckWithMock(t *testing.T) {
	current := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	fake := newFakeRedisEvaler()
	limiter := &RedisLimiter{
		client: fake,
		cfg:    Config{Rate: 2, Window: 10 * time.Second},
		now:    func() time.Time { return current },
	}

	result, err := limiter.Check(context.Background(), "issuer")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, 1, result.Remaining)
	assert.Equal(t, 10*time.Second, result.ResetAfter)
	assert.Zero(t, result.RetryAfter)

	current = current.Add(2 * time.Second)
	result, err = limiter.Check(context.Background(), "issuer")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, 0, result.Remaining)
	assert.Equal(t, 8*time.Second, result.ResetAfter)

	result, err = limiter.Check(context.Background(), "issuer")
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Equal(t, 0, result.Remaining)
	assert.Equal(t, 8*time.Second, result.ResetAfter)
	assert.Equal(t, 8*time.Second, result.RetryAfter)
}

func TestRedisLimiterDifferentKeysAreIndependent(t *testing.T) {
	current := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	fake := newFakeRedisEvaler()
	limiter := &RedisLimiter{
		client: fake,
		cfg:    Config{Rate: 1, Window: time.Minute},
		now:    func() time.Time { return current },
	}

	allowed, err := limiter.Allow(context.Background(), "issuer-a")
	require.NoError(t, err)
	assert.True(t, allowed)

	allowed, err = limiter.Allow(context.Background(), "issuer-b")
	require.NoError(t, err)
	assert.True(t, allowed)

	allowed, err = limiter.Allow(context.Background(), "issuer-a")
	require.NoError(t, err)
	assert.False(t, allowed)
}

func TestRedisLimiterPropagatesClientErrors(t *testing.T) {
	limiter := &RedisLimiter{
		client: &fakeRedisEvaler{entries: make(map[string][]int64), err: errors.New("boom")},
		cfg:    Config{Rate: 1, Window: time.Second},
		now:    time.Now,
	}

	_, err := limiter.Check(context.Background(), "issuer")
	require.Error(t, err)
	assert.ErrorContains(t, err, "boom")
}

type fakeRedisEvaler struct {
	mu      sync.Mutex
	entries map[string][]int64
	err     error
}

func newFakeRedisEvaler() *fakeRedisEvaler {
	return &fakeRedisEvaler{entries: make(map[string][]int64)}
}

func (f *fakeRedisEvaler) Eval(_ context.Context, _ string, keys []string, args ...interface{}) ([]interface{}, error) {
	if f.err != nil {
		return nil, f.err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	key := keys[0]
	nowMicros := mustInt64(args[0])
	windowMicros := mustInt64(args[1])
	limit := mustInt64(args[2])
	cutoff := nowMicros - windowMicros

	timestamps := f.entries[key]
	kept := timestamps[:0]
	for _, ts := range timestamps {
		if ts > cutoff {
			kept = append(kept, ts)
		}
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i] < kept[j] })

	allowed := int64(0)
	if int64(len(kept)) < limit {
		kept = append(kept, nowMicros)
		sort.Slice(kept, func(i, j int) bool { return kept[i] < kept[j] })
		allowed = 1
	}
	f.entries[key] = kept

	earliest := int64(0)
	if len(kept) > 0 {
		earliest = kept[0]
	}

	return []interface{}{allowed, int64(len(kept)), earliest}, nil
}

func mustInt64(value interface{}) int64 {
	switch v := value.(type) {
	case int64:
		return v
	case int:
		return int64(v)
	default:
		panic(fmt.Sprintf("unexpected numeric type %T", value))
	}
}
