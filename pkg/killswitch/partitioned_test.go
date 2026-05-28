// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package killswitch_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/edgeobs/eunox/pkg/killswitch"
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
