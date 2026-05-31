// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

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
// newResilientSetup starts a miniredis server and returns a wired-up
// ResilientRedis together with a monitor so tests can inspect health state.
func newResilientSetup(t *testing.T) (*ResilientRedis, *redisfailover.Monitor) {
	t.Helper()
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	t.Cleanup(mr.Close)

	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), DialTimeout: 200 * time.Millisecond})
	t.Cleanup(func() { _ = client.Close() })

	monitor := redisfailover.NewMonitor()
	reporter := monitor.Register("rr-test")
	inner := NewRedis(client)
	r := NewResilientRedis(inner, reporter)
	r.Start(t.Context())
	t.Cleanup(r.Stop)
	return r, monitor
}

func TestResilientRedis_Stop(t *testing.T) {
	t.Parallel()
	r, _ := newResilientSetup(t)
	// Stop is idempotent and must not panic.
	r.Stop()
	r.Stop()
}

func TestResilientRedis_ActivateDeactivateGlobal(t *testing.T) {
	t.Parallel()
	r, _ := newResilientSetup(t)
	ctx := context.Background()

	require.NoError(t, r.ActivateGlobal(ctx))

	blocked, err := r.ShouldBlock(ctx, "agent-x", "")
	require.NoError(t, err)
	assert.True(t, blocked, "global kill switch must block all agents")

	require.NoError(t, r.DeactivateGlobal(ctx))

	blocked, err = r.ShouldBlock(ctx, "agent-x", "")
	require.NoError(t, err)
	assert.False(t, blocked, "after deactivation agents must be unblocked")
}

func TestResilientRedis_KillReviveAgent(t *testing.T) {
	t.Parallel()
	r, _ := newResilientSetup(t)
	ctx := context.Background()

	require.NoError(t, r.KillAgent(ctx, "agent-1"))

	blocked, err := r.ShouldBlock(ctx, "agent-1", "")
	require.NoError(t, err)
	assert.True(t, blocked)

	require.NoError(t, r.ReviveAgent(ctx, "agent-1"))

	blocked, err = r.ShouldBlock(ctx, "agent-1", "")
	require.NoError(t, err)
	assert.False(t, blocked)
}

func TestResilientRedis_KillReviveSession(t *testing.T) {
	t.Parallel()
	r, _ := newResilientSetup(t)
	ctx := context.Background()

	require.NoError(t, r.KillSession(ctx, "sess-42"))

	blocked, err := r.ShouldBlock(ctx, "", "sess-42")
	require.NoError(t, err)
	assert.True(t, blocked)

	require.NoError(t, r.ReviveSession(ctx, "sess-42"))

	blocked, err = r.ShouldBlock(ctx, "", "sess-42")
	require.NoError(t, err)
	assert.False(t, blocked)
}

func TestResilientRedis_Reset(t *testing.T) {
	t.Parallel()
	r, _ := newResilientSetup(t)
	ctx := context.Background()

	require.NoError(t, r.KillAgent(ctx, "agent-reset"))
	require.NoError(t, r.KillSession(ctx, "sess-reset"))

	blocked, _ := r.ShouldBlock(ctx, "agent-reset", "")
	require.True(t, blocked)

	require.NoError(t, r.Reset(ctx))

	blocked, err := r.ShouldBlock(ctx, "agent-reset", "")
	require.NoError(t, err)
	assert.False(t, blocked)
}

func TestResilientRedis_Status(t *testing.T) {
	t.Parallel()
	r, _ := newResilientSetup(t)
	ctx := context.Background()

	require.NoError(t, r.KillAgent(ctx, "agent-status"))
	require.NoError(t, r.KillSession(ctx, "sess-status"))

	status, err := r.Status(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.ElementsMatch(t, []string{"agent-status"}, status.KilledAgents)
	assert.ElementsMatch(t, []string{"sess-status"}, status.KilledSessions)
}

func TestResilientRedis_UpdateHealthMarksHealthyOnSuccess(t *testing.T) {
	t.Parallel()
	r, monitor := newResilientSetup(t)
	ctx := context.Background()

	// A successful operation should leave the reporter healthy.
	require.NoError(t, r.ActivateGlobal(ctx))
	require.NoError(t, r.DeactivateGlobal(ctx))
	assert.True(t, monitor.IsReady(), "monitor must be ready after successful operations")
}

func TestResilientRedis_UpdateHealthMarksDegradedOnError(t *testing.T) {
	t.Parallel()
	// Build a resilient wrapper around a dead Redis so that every mutation fails.
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	addr := mr.Addr()
	mr.Close() // kill immediately

	client := redis.NewClient(&redis.Options{Addr: addr, DialTimeout: 100 * time.Millisecond})
	t.Cleanup(func() { _ = client.Close() })

	monitor := redisfailover.NewMonitor()
	reporter := monitor.Register("degraded-test")
	inner := NewRedis(client)
	r := NewResilientRedis(inner, reporter)
	// Don't call Start — we only want to test that mutation errors mark degraded.
	r.started.Store(true) // manually mark started so updateHealth is reached

	ctx := context.Background()
	// KillAgent will fail (Redis is down); updateHealth must mark degraded.
	_ = r.KillAgent(ctx, "agent-fail")
	assert.False(t, monitor.IsReady(), "monitor must be degraded after a Redis error")
}

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

func TestResilientRedis_Start_MarksDegradedWhenRedisDown(t *testing.T) {
	t.Parallel()

	// Start miniredis, grab its address, then close it immediately so that the
	// initial refreshState inside Start returns a connection error.
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	addr := mr.Addr()
	mr.Close() // kill before Start is called

	client := redis.NewClient(&redis.Options{
		Addr:        addr,
		PoolSize:    1,
		DialTimeout: 100 * time.Millisecond,
	})
	t.Cleanup(func() { _ = client.Close() })

	monitor := redisfailover.NewMonitor()
	reporter := monitor.Register("degraded-start-test")
	inner := NewRedis(client)
	r := NewResilientRedis(inner, reporter)

	r.Start(t.Context())
	defer r.Stop()

	assert.False(t, monitor.IsReady(), "monitor must be degraded when Redis is down during Start")
}
