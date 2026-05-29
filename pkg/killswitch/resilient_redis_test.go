// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package killswitch

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/eunolabs/eunox/pkg/redisfailover"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResilientRedis_FailClosedBeforeStart(t *testing.T) {
	t.Parallel()
	monitor := redisfailover.NewMonitor()
	reporter := monitor.Register("test")
	inner := NewRedis(nil) // nil client is fine; Start is never called
	r := NewResilientRedis(inner, reporter)

	blocked, err := r.ShouldBlock(context.Background(), "agent-1", "sess-1")
	require.NoError(t, err)
	assert.True(t, blocked, "ShouldBlock must be fail-closed before Start is called")
}

// TestResilientRedis_StartedFieldConcurrentAccess verifies that concurrent
// calls to Start and ShouldBlock do not trigger a data race.  Run with
// -race to exercise the race detector.
func TestResilientRedis_StartedFieldConcurrentAccess(t *testing.T) {
	t.Parallel()

	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	t.Cleanup(mr.Close)

	client := redis.NewClient(&redis.Options{
		Addr:        mr.Addr(),
		DialTimeout: 200 * time.Millisecond,
	})
	t.Cleanup(func() { _ = client.Close() })

	monitor := redisfailover.NewMonitor()
	reporter := monitor.Register("resilient-test")
	inner := NewRedis(client)
	r := NewResilientRedis(inner, reporter)

	// Launch 20 concurrent ShouldBlock callers while Start executes.
	// Before the atomic.Bool fix, these concurrent reads/writes on the
	// unprotected bool would have been flagged by the race detector.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = r.ShouldBlock(context.Background(), "agent-x", "sess-x")
		}()
	}
	r.Start(t.Context())
	wg.Wait()
}
