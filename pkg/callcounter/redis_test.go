// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package callcounter_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedis_IncrementAndGet_Basic(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	counter := callcounter.NewRedis(client)
	ctx := context.Background()

	count, err := counter.IncrementAndGet(ctx, "key1", 60)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	count, err = counter.IncrementAndGet(ctx, "key1", 60)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)
}

// TestRedis_IncrementAndGet_SlidingWindowExpiry verifies that after the key TTL
// elapses, the sorted-set key is evicted by Redis and the counter resets to 1.
//
// Note: miniredis.FastForward only advances Redis's internal TTL clock; it does
// not advance Go's time.Now().  The test therefore relies on key expiry (TTL)
// rather than ZREMRANGEBYSCORE to produce count==1.  After the M-6 fix the key
// TTL is 2×windowSec (4 s for window=2), so the fast-forward must exceed 4 s.
func TestRedis_IncrementAndGet_SlidingWindowExpiry(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	counter := callcounter.NewRedis(client)
	ctx := context.Background()

	// Make 3 calls with a 2-second window (key TTL = 2×2 = 4 s after M-6 fix).
	for i := 0; i < 3; i++ {
		_, err := counter.IncrementAndGet(ctx, "key1", 2)
		require.NoError(t, err)
	}

	// Advance past the 4-second TTL so that miniredis evicts the key.
	mr.FastForward(5 * time.Second)

	// After TTL expiry the sorted-set key is gone; the next call creates a new
	// one with exactly 1 entry.
	count, err := counter.IncrementAndGet(ctx, "key1", 2)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "key must be evicted after TTL expires")
}

func TestRedis_IncrementAndGet_ConcurrentCallsNoDuplicate(t *testing.T) {
	// Before the fix, two calls at the same UnixNano produced the same ZADD
	// member.  ZADD with an existing member updates its score rather than
	// inserting a new entry, so the counter undercounted.  The monotonic
	// sequence suffix added by the fix ensures each call gets a unique member.
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	counter := callcounter.NewRedis(client)
	ctx := context.Background()

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, err := counter.IncrementAndGet(ctx, "concurrent-key", 60)
			require.NoError(t, err)
		}()
	}
	wg.Wait()

	// One final call to read the total.  Expect exactly n+1 distinct entries.
	count, err := counter.IncrementAndGet(ctx, "concurrent-key", 60)
	require.NoError(t, err)
	assert.Equal(t, int64(n+1), count,
		"all concurrent calls must be counted as distinct entries (no nanosecond collision)")
}
