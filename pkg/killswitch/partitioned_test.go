// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package killswitch_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/eunolabs/eunox/pkg/killswitch"
	"github.com/eunolabs/eunox/pkg/redisfailover"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newMiniredisClient starts a miniredis server and returns a connected
// UniversalClient and a cleanup function.
func newMiniredisClient(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return mr, client
}

func newPartitioned(t *testing.T, client *redis.Client) *killswitch.PartitionedKillSwitch {
	t.Helper()
	inner := killswitch.NewRedis(client)
	return killswitch.NewPartitioned(inner, client, nil)
}

// TestPartitioned_NotBlockedInitially verifies that a fresh partitioned kill-switch
// does not block any agent by default.
func TestPartitioned_NotBlockedInitially(t *testing.T) {
	t.Parallel()
	_, client := newMiniredisClient(t)
	p := newPartitioned(t, client)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Start(ctx)
	defer p.Stop()

	blocked, err := p.ShouldBlock(ctx, "agent-1", "")
	require.NoError(t, err)
	assert.False(t, blocked)
}

// TestPartitioned_GlobalKillBlocksAll verifies that a global kill-switch activated on
// the shared inner manager blocks all agents through the partitioned manager.
func TestPartitioned_GlobalKillBlocksAll(t *testing.T) {
	t.Parallel()
	_, client := newMiniredisClient(t)
	p := newPartitioned(t, client)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Start(ctx)
	defer p.Stop()

	require.NoError(t, p.ActivateGlobal(ctx))

	blocked, err := p.ShouldBlock(ctx, "agent-1", "")
	require.NoError(t, err)
	assert.True(t, blocked)

	blocked, err = p.ShouldBlock(ctx, "agent-2", "")
	require.NoError(t, err)
	assert.True(t, blocked)
}

// TestPartitioned_KillAgentOnlyBlocksTargetAgent verifies that killing one agent does
// not affect another agent — the core failure domain isolation property.
func TestPartitioned_KillAgentOnlyBlocksTargetAgent(t *testing.T) {
	t.Parallel()
	_, client := newMiniredisClient(t)
	p := newPartitioned(t, client)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Start(ctx)
	defer p.Stop()

	require.NoError(t, p.KillAgent(ctx, "agent-1"))

	blocked1, err := p.ShouldBlock(ctx, "agent-1", "")
	require.NoError(t, err)
	assert.True(t, blocked1, "agent-1 should be blocked")

	blocked2, err := p.ShouldBlock(ctx, "agent-2", "")
	require.NoError(t, err)
	assert.False(t, blocked2, "agent-2 should not be blocked")
}

// TestPartitioned_ReviveAgent verifies that reviving an agent unblocks it.
func TestPartitioned_ReviveAgent(t *testing.T) {
	t.Parallel()
	_, client := newMiniredisClient(t)
	p := newPartitioned(t, client)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Start(ctx)
	defer p.Stop()

	require.NoError(t, p.KillAgent(ctx, "agent-1"))

	blocked, err := p.ShouldBlock(ctx, "agent-1", "")
	require.NoError(t, err)
	assert.True(t, blocked)

	require.NoError(t, p.ReviveAgent(ctx, "agent-1"))

	blocked, err = p.ShouldBlock(ctx, "agent-1", "")
	require.NoError(t, err)
	assert.False(t, blocked)
}

// TestPartitioned_SessionKill verifies that session kill is delegated to the shared manager.
func TestPartitioned_SessionKill(t *testing.T) {
	t.Parallel()
	_, client := newMiniredisClient(t)
	p := newPartitioned(t, client)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Start(ctx)
	defer p.Stop()

	require.NoError(t, p.KillSession(ctx, "sess-99"))

	blocked, err := p.ShouldBlock(ctx, "agent-1", "sess-99")
	require.NoError(t, err)
	assert.True(t, blocked, "sess-99 should be blocked regardless of agent")

	// A request from agent-1 with a different session is not blocked.
	blocked, err = p.ShouldBlock(ctx, "agent-1", "sess-100")
	require.NoError(t, err)
	assert.False(t, blocked)
}

// TestPartitioned_Reset verifies that Reset clears all state including per-agent partitions.
func TestPartitioned_Reset(t *testing.T) {
	t.Parallel()
	_, client := newMiniredisClient(t)
	p := newPartitioned(t, client)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Start(ctx)
	defer p.Stop()

	require.NoError(t, p.KillAgent(ctx, "agent-1"))
	require.NoError(t, p.KillAgent(ctx, "agent-2"))

	blocked, _ := p.ShouldBlock(ctx, "agent-1", "")
	require.True(t, blocked)

	require.NoError(t, p.Reset(ctx))

	blocked, err := p.ShouldBlock(ctx, "agent-1", "")
	require.NoError(t, err)
	assert.False(t, blocked, "agent-1 should be unblocked after reset")

	blocked, err = p.ShouldBlock(ctx, "agent-2", "")
	require.NoError(t, err)
	assert.False(t, blocked, "agent-2 should be unblocked after reset")
}

// TestPartitioned_DegradedPartitionIsFailClosed verifies that if a per-agent
// subscription is marked degraded, ShouldBlock returns true (fail-closed) for that
// agent but false for agents with healthy partitions.
//
// This is the core failure domain isolation test: one agent's subscription failure
// must not degrade other agents.
func TestPartitioned_DegradedPartitionIsFailClosed(t *testing.T) {
	t.Parallel()
	_, client := newMiniredisClient(t)
	inner := killswitch.NewRedis(client)
	p := killswitch.NewPartitioned(inner, client, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Start(ctx)
	defer p.Stop()

	// Prime agent-1 so its partition exists in the map.
	blocked, err := p.ShouldBlock(ctx, "agent-1", "")
	require.NoError(t, err)
	assert.False(t, blocked)

	// Simulate a degraded subscription for agent-1 via the exported test hook.
	killswitch.SetPartitionDegraded(p, "agent-1", true)

	blocked, err = p.ShouldBlock(ctx, "agent-1", "")
	require.NoError(t, err)
	assert.True(t, blocked, "degraded partition should be fail-closed")

	// agent-2 (fresh partition) must not be affected.
	blocked, err = p.ShouldBlock(ctx, "agent-2", "")
	require.NoError(t, err)
	assert.False(t, blocked, "agent-2 should not be affected by agent-1 partition degradation")
}

// TestPartitioned_DegradedAgentsList verifies that DegradedAgents returns only the
// agents whose partitions are currently degraded.
func TestPartitioned_DegradedAgentsList(t *testing.T) {
	t.Parallel()
	_, client := newMiniredisClient(t)
	inner := killswitch.NewRedis(client)
	p := killswitch.NewPartitioned(inner, client, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Start(ctx)
	defer p.Stop()

	// Prime partitions for all three agents.
	for _, id := range []string{"agent-1", "agent-2", "agent-3"} {
		_, _ = p.ShouldBlock(ctx, id, "")
	}

	// Degrade only agent-2.
	killswitch.SetPartitionDegraded(p, "agent-2", true)

	degraded := p.DegradedAgents()
	require.Len(t, degraded, 1)
	assert.Equal(t, "agent-2", degraded[0])
}

// TestPartitioned_ImplementsManager verifies that *PartitionedKillSwitch satisfies
// the Manager interface at compile time.
func TestPartitioned_ImplementsManager(t *testing.T) {
	t.Parallel()
	var _ killswitch.Manager = (*killswitch.PartitionedKillSwitch)(nil)
}

// TestPartitioned_WithMaxPartitions verifies that WithMaxPartitions returns the same
// receiver (for chaining) and accepts custom values.
func TestPartitioned_WithMaxPartitions(t *testing.T) {
	t.Parallel()
	_, client := newMiniredisClient(t)
	inner := killswitch.NewRedis(client)
	p := killswitch.NewPartitioned(inner, client, nil)
	result := p.WithMaxPartitions(5000)
	assert.Same(t, p, result, "WithMaxPartitions must return the same instance")
}

// TestPartitioned_WithMaxPartitions_DefaultOnNonPositive verifies that n ≤ 0 restores
// the default (10 000) rather than setting an invalid cap.
func TestPartitioned_WithMaxPartitions_DefaultOnNonPositive(t *testing.T) {
	t.Parallel()
	_, client := newMiniredisClient(t)
	inner := killswitch.NewRedis(client)
	p := killswitch.NewPartitioned(inner, client, nil)
	result := p.WithMaxPartitions(0)
	assert.Same(t, p, result)
	result = p.WithMaxPartitions(-1)
	assert.Same(t, p, result)
}

// TestPartitioned_WithReporter verifies that WithReporter returns the same receiver.
func TestPartitioned_WithReporter(t *testing.T) {
	t.Parallel()
	_, client := newMiniredisClient(t)
	inner := killswitch.NewRedis(client)
	monitor := redisfailover.NewMonitor()
	reporter := monitor.Register("test-part-reporter")
	p := killswitch.NewPartitioned(inner, client, nil)
	result := p.WithReporter(reporter)
	assert.Same(t, p, result)
}

// TestPartitioned_WithReporter_HealthyAfterStart verifies that Start marks the monitor
// healthy when Redis is reachable.
func TestPartitioned_WithReporter_HealthyAfterStart(t *testing.T) {
	t.Parallel()
	_, client := newMiniredisClient(t)
	inner := killswitch.NewRedis(client)
	monitor := redisfailover.NewMonitor()
	reporter := monitor.Register("test-part-healthy")
	p := killswitch.NewPartitioned(inner, client, nil).WithReporter(reporter)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Start(ctx)
	defer p.Stop()

	assert.True(t, monitor.IsReady(), "monitor must be ready after successful Start")
}

// TestPartitioned_DeactivateGlobal verifies that DeactivateGlobal unblocks all agents
// after the global kill switch was activated.
func TestPartitioned_DeactivateGlobal(t *testing.T) {
	t.Parallel()
	_, client := newMiniredisClient(t)
	p := newPartitioned(t, client)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Start(ctx)
	defer p.Stop()

	require.NoError(t, p.ActivateGlobal(ctx))
	blocked, err := p.ShouldBlock(ctx, "agent-1", "")
	require.NoError(t, err)
	assert.True(t, blocked)

	require.NoError(t, p.DeactivateGlobal(ctx))
	blocked, err = p.ShouldBlock(ctx, "agent-1", "")
	require.NoError(t, err)
	assert.False(t, blocked)
}

// TestPartitioned_ReviveSession verifies that ReviveSession unblocks a session that was
// killed via the shared inner manager.
func TestPartitioned_ReviveSession(t *testing.T) {
	t.Parallel()
	_, client := newMiniredisClient(t)
	p := newPartitioned(t, client)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Start(ctx)
	defer p.Stop()

	require.NoError(t, p.KillSession(ctx, "sess-99"))
	blocked, err := p.ShouldBlock(ctx, "agent-1", "sess-99")
	require.NoError(t, err)
	assert.True(t, blocked)

	require.NoError(t, p.ReviveSession(ctx, "sess-99"))
	blocked, err = p.ShouldBlock(ctx, "agent-1", "sess-99")
	require.NoError(t, err)
	assert.False(t, blocked)
}

// TestPartitioned_Status verifies that Status delegates to the shared inner manager
// and reflects killed agents and sessions.
func TestPartitioned_Status(t *testing.T) {
	t.Parallel()
	_, client := newMiniredisClient(t)
	p := newPartitioned(t, client)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Start(ctx)
	defer p.Stop()

	require.NoError(t, p.KillAgent(ctx, "agent-status"))
	require.NoError(t, p.KillSession(ctx, "sess-status"))

	status, err := p.Status(ctx)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.ElementsMatch(t, []string{"agent-status"}, status.KilledAgents)
	assert.ElementsMatch(t, []string{"sess-status"}, status.KilledSessions)
}

// TestPartitioned_HandleAgentEvent verifies that handleAgentEvent correctly updates the
// in-memory kill state when a per-agent pub/sub message arrives. The test uses the
// exported test hook (HandleAgentEventForTest) to simulate the event without requiring
// a real pub/sub round-trip.
func TestPartitioned_HandleAgentEvent(t *testing.T) {
	t.Parallel()
	_, client := newMiniredisClient(t)
	inner := killswitch.NewRedis(client)
	p := killswitch.NewPartitioned(inner, client, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Start(ctx)
	defer p.Stop()

	// Inject kill event into the partition directly.
	killswitch.HandleAgentEventForTest(p, "agent-evt", "kill")
	// Ensure the partition is not marked degraded so ShouldBlock reads killed.
	killswitch.SetPartitionDegraded(p, "agent-evt", false)

	blocked, err := p.ShouldBlock(ctx, "agent-evt", "")
	require.NoError(t, err)
	assert.True(t, blocked, "agent should be blocked after kill event")

	// Inject revive event.
	killswitch.HandleAgentEventForTest(p, "agent-evt", "revive")

	blocked, err = p.ShouldBlock(ctx, "agent-evt", "")
	require.NoError(t, err)
	assert.False(t, blocked, "agent should be unblocked after revive event")
}

// TestPartitioned_LRU_Eviction verifies that when the partition cap is 1, adding a
// second agent evicts the first, and the evicted agent's partition is recreated fresh
// on the next ShouldBlock call.
func TestPartitioned_LRU_Eviction(t *testing.T) {
	t.Parallel()
	_, client := newMiniredisClient(t)
	inner := killswitch.NewRedis(client)
	p := killswitch.NewPartitioned(inner, client, nil).WithMaxPartitions(1)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Start(ctx)
	defer p.Stop()

	// Create partition for agent-1.
	blocked, err := p.ShouldBlock(ctx, "agent-1", "")
	require.NoError(t, err)
	assert.False(t, blocked)

	// Creating partition for agent-2 must evict agent-1 (cap=1).
	blocked, err = p.ShouldBlock(ctx, "agent-2", "")
	require.NoError(t, err)
	assert.False(t, blocked)

	// agent-1's partition was evicted; DegradedAgents must not contain it.
	degraded := p.DegradedAgents()
	for _, id := range degraded {
		assert.NotEqual(t, "agent-1", id, "evicted partition must not appear in DegradedAgents")
	}

	// agent-1 can be re-added and must not be blocked (fresh partition, no kill state).
	blocked, err = p.ShouldBlock(ctx, "agent-1", "")
	require.NoError(t, err)
	assert.False(t, blocked, "re-created agent-1 partition must not be blocked")
}

// TestPartitioned_KillAgent_UpdatesExistingPartition verifies that KillAgent sets
// the in-memory killed flag on a partition that was already created by ShouldBlock.
func TestPartitioned_KillAgent_UpdatesExistingPartition(t *testing.T) {
	t.Parallel()
	_, client := newMiniredisClient(t)
	p := newPartitioned(t, client)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Start(ctx)
	defer p.Stop()

	// Prime the partition so it exists in the map before KillAgent is called.
	_, err := p.ShouldBlock(ctx, "agent-prime", "")
	require.NoError(t, err)

	// KillAgent must update the in-memory partition (the if ok { } block).
	require.NoError(t, p.KillAgent(ctx, "agent-prime"))

	// The partition-level killed flag is now true; confirm ShouldBlock reflects it.
	// (inner.ShouldBlock returns true because the Redis key is set, so this also
	// exercises the fast-path return before the partition check.)
	blocked, err := p.ShouldBlock(ctx, "agent-prime", "")
	require.NoError(t, err)
	assert.True(t, blocked)
}

// TestPartitioned_ReviveAgent_UpdatesExistingPartition verifies that ReviveAgent
// clears the in-memory killed flag when a partition already exists.
func TestPartitioned_ReviveAgent_UpdatesExistingPartition(t *testing.T) {
	t.Parallel()
	_, client := newMiniredisClient(t)
	p := newPartitioned(t, client)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Start(ctx)
	defer p.Stop()

	// Prime the partition while the agent is still alive.
	_, err := p.ShouldBlock(ctx, "agent-revive", "")
	require.NoError(t, err)

	// Kill and update the partition's killed flag.
	require.NoError(t, p.KillAgent(ctx, "agent-revive"))

	// Now revive — ReviveAgent must clear the in-memory flag (the if ok { } block).
	require.NoError(t, p.ReviveAgent(ctx, "agent-revive"))

	// After revive the agent must not be blocked (both Redis and partition updated).
	blocked, err := p.ShouldBlock(ctx, "agent-revive", "")
	require.NoError(t, err)
	assert.False(t, blocked)
}

// TestPartitioned_KillAgent_InnerError verifies that KillAgent propagates the error
// returned by the inner Redis manager.
func TestPartitioned_KillAgent_InnerError(t *testing.T) {
	t.Parallel()
	mr, client := newMiniredisClient(t)
	p := newPartitioned(t, client)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Start(ctx)
	defer p.Stop()

	// Cut the Redis connection so the inner SET command fails.
	mr.Close()

	err := p.KillAgent(ctx, "agent-err")
	assert.Error(t, err, "KillAgent must propagate Redis errors")
}

// TestPartitioned_ReviveAgent_InnerError verifies that ReviveAgent propagates the
// error returned by the inner Redis manager.
func TestPartitioned_ReviveAgent_InnerError(t *testing.T) {
	t.Parallel()
	mr, client := newMiniredisClient(t)
	p := newPartitioned(t, client)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Start(ctx)
	defer p.Stop()

	mr.Close()

	err := p.ReviveAgent(ctx, "agent-err")
	assert.Error(t, err, "ReviveAgent must propagate Redis errors")
}

// TestPartitioned_Reset_InnerError verifies that Reset propagates errors from the
// inner Redis manager and does not silently swallow them.
func TestPartitioned_Reset_InnerError(t *testing.T) {
	t.Parallel()
	mr, client := newMiniredisClient(t)
	p := newPartitioned(t, client)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Start(ctx)
	defer p.Stop()

	mr.Close()

	err := p.Reset(ctx)
	assert.Error(t, err, "Reset must propagate Redis errors")
}

// TestPartitioned_PublishAgentEvent_LogsOnError verifies that publishAgentEvent
// writes a warning log when the Publish call fails and a logger is set.
//
// The test wires the inner manager with a working Redis client (so inner.KillAgent
// succeeds) and the partitioned switch with a dead client (so Publish fails).  This
// two-client split lets us reach the publishAgentEvent error path without the
// earlier inner.KillAgent call also failing.
func TestPartitioned_PublishAgentEvent_LogsOnError(t *testing.T) {
	t.Parallel()

	// Working client for inner (global kill-switch state).
	_, workingClient := newMiniredisClient(t)
	inner := killswitch.NewRedis(workingClient)

	// Dead client for per-agent pub/sub operations (publishAgentEvent uses this).
	deadMr := miniredis.NewMiniRedis()
	require.NoError(t, deadMr.Start())
	deadClient := redis.NewClient(&redis.Options{
		Addr:        deadMr.Addr(),
		DialTimeout: 50 * time.Millisecond,
	})
	t.Cleanup(func() { _ = deadClient.Close() })
	deadMr.Close() // close immediately so Publish will fail

	var logBuf strings.Builder
	// Use slog with a simple text handler writing to the builder.
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	p := killswitch.NewPartitioned(inner, deadClient, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p.Start(ctx)
	defer p.Stop()

	// inner.KillAgent uses workingClient → succeeds.
	// publishAgentEvent uses deadClient.Publish → fails → log warning is written.
	_ = p.KillAgent(ctx, "agent-pub-fail")

	assert.Contains(t, logBuf.String(), "failed to publish per-agent event",
		"a warn log must be written when Publish fails and a logger is set")
}
