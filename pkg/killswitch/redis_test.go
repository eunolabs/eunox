// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package killswitch

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
