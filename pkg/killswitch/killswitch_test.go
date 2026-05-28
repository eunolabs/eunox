// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package killswitch_test

import (
	"context"
	"testing"

	"github.com/eunolabs/eunox/pkg/killswitch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInMemory_InitiallyNotBlocked(t *testing.T) {
	ks := killswitch.NewInMemory()
	ctx := context.Background()

	blocked, err := ks.ShouldBlock(ctx, "agent-1", "sess-1")
	require.NoError(t, err)
	assert.False(t, blocked)
}

func TestInMemory_GlobalKillSwitch(t *testing.T) {
	ks := killswitch.NewInMemory()
	ctx := context.Background()

	require.NoError(t, ks.ActivateGlobal(ctx))

	blocked, err := ks.ShouldBlock(ctx, "agent-1", "sess-1")
	require.NoError(t, err)
	assert.True(t, blocked)

	// Any agent/session is blocked
	blocked, err = ks.ShouldBlock(ctx, "agent-2", "sess-2")
	require.NoError(t, err)
	assert.True(t, blocked)

	// Deactivate
	require.NoError(t, ks.DeactivateGlobal(ctx))

	blocked, err = ks.ShouldBlock(ctx, "agent-1", "sess-1")
	require.NoError(t, err)
	assert.False(t, blocked)
}

func TestInMemory_AgentKillSwitch(t *testing.T) {
	ks := killswitch.NewInMemory()
	ctx := context.Background()

	require.NoError(t, ks.KillAgent(ctx, "agent-1"))

	// agent-1 is blocked
	blocked, err := ks.ShouldBlock(ctx, "agent-1", "sess-1")
	require.NoError(t, err)
	assert.True(t, blocked)

	// agent-2 is not blocked
	blocked, err = ks.ShouldBlock(ctx, "agent-2", "sess-1")
	require.NoError(t, err)
	assert.False(t, blocked)

	// Revive agent-1
	require.NoError(t, ks.ReviveAgent(ctx, "agent-1"))

	blocked, err = ks.ShouldBlock(ctx, "agent-1", "sess-1")
	require.NoError(t, err)
	assert.False(t, blocked)
}

func TestInMemory_SessionKillSwitch(t *testing.T) {
	ks := killswitch.NewInMemory()
	ctx := context.Background()

	require.NoError(t, ks.KillSession(ctx, "sess-1"))

	// sess-1 is blocked
	blocked, err := ks.ShouldBlock(ctx, "agent-1", "sess-1")
	require.NoError(t, err)
	assert.True(t, blocked)

	// sess-2 is not blocked
	blocked, err = ks.ShouldBlock(ctx, "agent-1", "sess-2")
	require.NoError(t, err)
	assert.False(t, blocked)

	// Revive sess-1
	require.NoError(t, ks.ReviveSession(ctx, "sess-1"))

	blocked, err = ks.ShouldBlock(ctx, "agent-1", "sess-1")
	require.NoError(t, err)
	assert.False(t, blocked)
}

func TestInMemory_Reset(t *testing.T) {
	ks := killswitch.NewInMemory()
	ctx := context.Background()

	require.NoError(t, ks.ActivateGlobal(ctx))
	require.NoError(t, ks.KillAgent(ctx, "agent-1"))
	require.NoError(t, ks.KillSession(ctx, "sess-1"))

	require.NoError(t, ks.Reset(ctx))

	blocked, err := ks.ShouldBlock(ctx, "agent-1", "sess-1")
	require.NoError(t, err)
	assert.False(t, blocked)
}

func TestInMemory_Status(t *testing.T) {
	ks := killswitch.NewInMemory()
	ctx := context.Background()

	require.NoError(t, ks.ActivateGlobal(ctx))
	require.NoError(t, ks.KillAgent(ctx, "agent-1"))
	require.NoError(t, ks.KillAgent(ctx, "agent-2"))
	require.NoError(t, ks.KillSession(ctx, "sess-1"))

	status, err := ks.Status(ctx)
	require.NoError(t, err)
	assert.True(t, status.GlobalActive)
	assert.Len(t, status.KilledAgents, 2)
	assert.Len(t, status.KilledSessions, 1)
	assert.Contains(t, status.KilledAgents, "agent-1")
	assert.Contains(t, status.KilledAgents, "agent-2")
	assert.Contains(t, status.KilledSessions, "sess-1")
}

func TestInMemory_EmptyAgentOrSession_NotBlocked(t *testing.T) {
	ks := killswitch.NewInMemory()
	ctx := context.Background()

	require.NoError(t, ks.KillAgent(ctx, "agent-1"))
	require.NoError(t, ks.KillSession(ctx, "sess-1"))

	// Empty strings are not evaluated
	blocked, err := ks.ShouldBlock(ctx, "", "")
	require.NoError(t, err)
	assert.False(t, blocked)
}
