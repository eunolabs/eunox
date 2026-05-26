// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package killswitch provides kill-switch management for blocking agents, sessions, or all traffic.
package killswitch

import "context"

// Manager determines whether a request should be blocked by the kill switch.
type Manager interface {
	// ShouldBlock returns true if the given agent/session combination is killed.
	// An empty agentID or sessionID means the field is not evaluated for that dimension.
	ShouldBlock(ctx context.Context, agentID, sessionID string) (bool, error)

	// ActivateGlobal activates the global kill switch (blocks all requests).
	ActivateGlobal(ctx context.Context) error

	// DeactivateGlobal deactivates the global kill switch.
	DeactivateGlobal(ctx context.Context) error

	// KillAgent blocks all requests from the specified agent.
	KillAgent(ctx context.Context, agentID string) error

	// ReviveAgent removes the kill on the specified agent.
	ReviveAgent(ctx context.Context, agentID string) error

	// KillSession blocks all requests for the specified session.
	KillSession(ctx context.Context, sessionID string) error

	// ReviveSession removes the kill on the specified session.
	ReviveSession(ctx context.Context, sessionID string) error

	// Reset clears all kill-switch state.
	Reset(ctx context.Context) error

	// Status returns the current kill-switch state.
	Status(ctx context.Context) (*Status, error)
}

// Status represents the current state of the kill switch.
type Status struct {
	GlobalActive   bool     `json:"globalActive"`
	KilledAgents   []string `json:"killedAgents"`
	KilledSessions []string `json:"killedSessions"`
}
