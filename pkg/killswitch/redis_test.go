// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package killswitch

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedis_HandlePubSubMessage_GlobalActivate(t *testing.T) {
	t.Parallel()
	r := &Redis{
		killedAgents:   make(map[string]bool),
		killedSessions: make(map[string]bool),
	}

	r.handlePubSubMessage("global:activate")
	assert.True(t, r.globalActive)
}

func TestRedis_HandlePubSubMessage_GlobalDeactivate(t *testing.T) {
	t.Parallel()
	r := &Redis{
		globalActive:   true,
		killedAgents:   make(map[string]bool),
		killedSessions: make(map[string]bool),
	}

	r.handlePubSubMessage("global:deactivate")
	assert.False(t, r.globalActive)
}

func TestRedis_HandlePubSubMessage_AgentKill(t *testing.T) {
	t.Parallel()
	r := &Redis{
		killedAgents:   make(map[string]bool),
		killedSessions: make(map[string]bool),
	}

	r.handlePubSubMessage("agent:kill:agent-123")
	assert.True(t, r.killedAgents["agent-123"])
}

func TestRedis_HandlePubSubMessage_AgentRevive(t *testing.T) {
	t.Parallel()
	r := &Redis{
		killedAgents:   map[string]bool{"agent-123": true},
		killedSessions: make(map[string]bool),
	}

	r.handlePubSubMessage("agent:revive:agent-123")
	assert.False(t, r.killedAgents["agent-123"])
}

func TestRedis_HandlePubSubMessage_SessionKill(t *testing.T) {
	t.Parallel()
	r := &Redis{
		killedAgents:   make(map[string]bool),
		killedSessions: make(map[string]bool),
	}

	r.handlePubSubMessage("session:kill:sess-456")
	assert.True(t, r.killedSessions["sess-456"])
}

func TestRedis_HandlePubSubMessage_SessionRevive(t *testing.T) {
	t.Parallel()
	r := &Redis{
		killedAgents:   make(map[string]bool),
		killedSessions: map[string]bool{"sess-456": true},
	}

	r.handlePubSubMessage("session:revive:sess-456")
	assert.False(t, r.killedSessions["sess-456"])
}

func TestRedis_HandlePubSubMessage_Reset(t *testing.T) {
	t.Parallel()
	r := &Redis{
		globalActive:   true,
		killedAgents:   map[string]bool{"agent-1": true, "agent-2": true},
		killedSessions: map[string]bool{"sess-1": true},
	}

	r.handlePubSubMessage("reset")
	assert.False(t, r.globalActive)
	assert.Empty(t, r.killedAgents)
	assert.Empty(t, r.killedSessions)
}

func TestRedis_HandlePubSubMessage_MultipleEvents(t *testing.T) {
	t.Parallel()
	r := &Redis{
		killedAgents:   make(map[string]bool),
		killedSessions: make(map[string]bool),
	}

	// Simulate a sequence of events that would arrive via pub/sub.
	r.handlePubSubMessage("agent:kill:agent-A")
	r.handlePubSubMessage("agent:kill:agent-B")
	r.handlePubSubMessage("session:kill:sess-X")
	r.handlePubSubMessage("global:activate")

	assert.True(t, r.globalActive)
	assert.True(t, r.killedAgents["agent-A"])
	assert.True(t, r.killedAgents["agent-B"])
	assert.True(t, r.killedSessions["sess-X"])

	// Revive one agent and deactivate global.
	r.handlePubSubMessage("agent:revive:agent-A")
	r.handlePubSubMessage("global:deactivate")

	assert.False(t, r.globalActive)
	assert.False(t, r.killedAgents["agent-A"])
	assert.True(t, r.killedAgents["agent-B"])
}

func TestRedis_HandlePubSubMessage_EmptyPayload(t *testing.T) {
	t.Parallel()
	r := &Redis{
		killedAgents:   make(map[string]bool),
		killedSessions: make(map[string]bool),
	}

	// Empty payload or unknown message should not panic.
	r.handlePubSubMessage("")
	r.handlePubSubMessage("unknown:event")
	assert.False(t, r.globalActive)
}

func TestRedis_HandlePubSubMessage_AgentKillEmptyID(t *testing.T) {
	t.Parallel()
	r := &Redis{
		killedAgents:   make(map[string]bool),
		killedSessions: make(map[string]bool),
	}

	// "agent:kill:" with no ID after prefix falls through to default (no-op).
	r.handlePubSubMessage("agent:kill:")
	assert.Empty(t, r.killedAgents)
}

func TestRedis_WithLogger(t *testing.T) {
	t.Parallel()
	r := NewRedis(nil)
	assert.Nil(t, r.logger)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	r2 := r.WithLogger(logger)

	// WithLogger returns the same receiver for chaining.
	assert.Same(t, r, r2)
	assert.Equal(t, logger, r.logger)
}

func TestRedis_Reset_DelError(t *testing.T) {
	t.Parallel()

	// Start a real miniredis server so we have a valid address to connect to.
	mr := miniredis.NewMiniRedis()
	if err := mr.Start(); err != nil {
		t.Fatalf("miniredis start: %v", err)
	}
	addr := mr.Addr()

	client := redis.NewClient(&redis.Options{
		Addr:        addr,
		PoolSize:    1,
		DialTimeout: 100 * time.Millisecond,
	})
	t.Cleanup(func() { _ = client.Close() })

	r := NewRedis(client)

	// Close the server so that the DEL command will fail with a connection error.
	mr.Close()

	err := r.Reset(t.Context())
	require.Error(t, err, "Reset must return an error when Redis DEL fails")
	assert.Contains(t, err.Error(), "kill switch reset")
}

func TestRedis_Reset_StatePreservedOnError(t *testing.T) {
	t.Parallel()

	// Start miniredis, grab the address, then close it so all Redis commands fail.
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	addr := mr.Addr()
	mr.Close()

	client := redis.NewClient(&redis.Options{
		Addr:        addr,
		PoolSize:    1,
		DialTimeout: 100 * time.Millisecond,
	})
	t.Cleanup(func() { _ = client.Close() })

	r := NewRedis(client)

	// Seed in-memory state to represent pre-existing kills.
	r.mu.Lock()
	r.killedAgents["agent-1"] = true
	r.killedSessions["sess-1"] = true
	r.globalActive = true
	r.mu.Unlock()

	err := r.Reset(t.Context())
	require.Error(t, err, "Reset must return an error when Redis is unavailable")

	// In-memory state must NOT be cleared because the Redis deletion failed.
	r.mu.RLock()
	agentStillKilled := r.killedAgents["agent-1"]
	sessStillKilled := r.killedSessions["sess-1"]
	globalStillActive := r.globalActive
	r.mu.RUnlock()

	assert.True(t, agentStillKilled, "agent kill state must be preserved when Reset fails")
	assert.True(t, sessStillKilled, "session kill state must be preserved when Reset fails")
	assert.True(t, globalStillActive, "global state must be preserved when Reset fails")
}

func TestRedis_DeactivateGlobal(t *testing.T) {
	t.Parallel()
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	r := NewRedis(client)
	ctx := context.Background()

	// Activate then deactivate — ShouldBlock must go false.
	require.NoError(t, r.ActivateGlobal(ctx))
	r.mu.RLock()
	assert.True(t, r.globalActive)
	r.mu.RUnlock()

	require.NoError(t, r.DeactivateGlobal(ctx))
	r.mu.RLock()
	assert.False(t, r.globalActive)
	r.mu.RUnlock()

	blocked, err := r.ShouldBlock(ctx, "", "")
	require.NoError(t, err)
	assert.False(t, blocked)
}

func TestRedis_ReviveSession(t *testing.T) {
	t.Parallel()
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	r := NewRedis(client)
	ctx := context.Background()

	require.NoError(t, r.KillSession(ctx, "sess-abc"))
	r.mu.RLock()
	assert.True(t, r.killedSessions["sess-abc"])
	r.mu.RUnlock()

	require.NoError(t, r.ReviveSession(ctx, "sess-abc"))
	r.mu.RLock()
	assert.False(t, r.killedSessions["sess-abc"])
	r.mu.RUnlock()

	blocked, err := r.ShouldBlock(ctx, "", "sess-abc")
	require.NoError(t, err)
	assert.False(t, blocked)
}

func TestRedis_Status(t *testing.T) {
	t.Parallel()
	r := &Redis{
		globalActive:   true,
		killedAgents:   map[string]bool{"agent-1": true, "agent-2": true},
		killedSessions: map[string]bool{"sess-1": true},
	}

	status, err := r.Status(context.Background())
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.GlobalActive)
	assert.ElementsMatch(t, []string{"agent-1", "agent-2"}, status.KilledAgents)
	assert.Equal(t, []string{"sess-1"}, status.KilledSessions)
}

func TestRedis_WithLogger_LogsRefreshFailure(t *testing.T) {
	t.Parallel()

	// Start a real miniredis server, then close it before Start() so the
	// initial refreshState call returns a real connection error.
	mr := miniredis.NewMiniRedis()
	if err := mr.Start(); err != nil {
		t.Fatalf("miniredis start: %v", err)
	}
	addr := mr.Addr()
	mr.Close() // kill it immediately so the first refresh fails

	client := redis.NewClient(&redis.Options{
		Addr:        addr,
		PoolSize:    1,
		DialTimeout: 100 * time.Millisecond,
	})
	t.Cleanup(func() { _ = client.Close() })

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	r := NewRedis(client).WithLogger(logger)

	r.Start(t.Context())
	defer r.Stop()

	assert.Contains(t, buf.String(), "initial state refresh failed")
}

func TestRedis_HandlePubSubMessage_UnknownPayload_WithClient(t *testing.T) {
	t.Parallel()

	// Create a live miniredis so refreshState succeeds.
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	t.Cleanup(mr.Close)

	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), DialTimeout: 200 * time.Millisecond})
	t.Cleanup(func() { _ = client.Close() })

	r := NewRedis(client)
	r.Start(t.Context())
	defer r.Stop()

	// Unknown payload triggers shouldRefresh = true and calls refreshState with
	// the live client — must complete without panic.
	r.handlePubSubMessage("unknown-xyz")

	// After refresh from empty Redis, globalActive must still be false.
	r.mu.RLock()
	globalActive := r.globalActive
	r.mu.RUnlock()
	assert.False(t, globalActive)
}
