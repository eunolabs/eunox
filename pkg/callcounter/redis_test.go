// Copyright 2026 Eunox Authors
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

func TestRedis_IncrementAndGet_SlidingWindowExpiry(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	counter := callcounter.NewRedis(client)
	ctx := context.Background()

	// Make 3 calls, then fast-forward miniredis past the window.
	for i := 0; i < 3; i++ {
		_, err := counter.IncrementAndGet(ctx, "key1", 2)
		require.NoError(t, err)
	}

	mr.FastForward(3 * time.Second) // advance past the 2-second window

	// Next call should count 1 (old entries are outside the window).
	count, err := counter.IncrementAndGet(ctx, "key1", 2)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "entries past the sliding window must expire")
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
