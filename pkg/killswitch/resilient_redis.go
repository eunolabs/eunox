// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package killswitch

import (
	"context"

	"github.com/edgeobs/eunox/pkg/redisfailover"
)

// ResilientRedis wraps a Redis kill-switch manager with fail-closed semantics.
// The underlying Redis kill switch already uses a local pub/sub cache. This
// wrapper adds explicit health reporting for readiness probes and ensures
// that ShouldBlock returns true (fail-closed) if the initial state load fails
// and no cached state is available.
//
// Failure policy: FAIL-CLOSED — if Redis state is unknown and no cache exists,
// the kill switch blocks all requests. This prevents potentially revoked agents
// from executing when the system cannot determine their status.
type ResilientRedis struct {
	inner    *Redis
	reporter *redisfailover.Reporter
	started  bool
}

// NewResilientRedis creates a fail-closed resilient kill-switch manager.
func NewResilientRedis(inner *Redis, reporter *redisfailover.Reporter) *ResilientRedis {
	return &ResilientRedis{
		inner:    inner,
		reporter: reporter,
	}
}

// Start initializes the kill switch. Reports degraded if initial state load fails.
func (r *ResilientRedis) Start(ctx context.Context) {
	r.inner.Start(ctx)
	r.started = true

	// Verify that the initial state load succeeded. refreshState now propagates
	// real connectivity errors (distinct from redis.Nil / key-not-found), so a
	// non-nil return here means Redis is unreachable and we must stay degraded.
	if err := r.inner.refreshState(ctx); err != nil {
		r.reporter.MarkDegraded()
	} else {
		r.reporter.MarkHealthy()
	}
}

// Stop terminates the kill switch.
func (r *ResilientRedis) Stop() {
	r.inner.Stop()
}

// ShouldBlock returns true if the request should be blocked. On Redis
// failure with no cached state, returns true (fail-closed).
func (r *ResilientRedis) ShouldBlock(ctx context.Context, agentID, sessionID string) (bool, error) {
	if !r.started {
		// Not yet initialized: fail-closed
		return true, nil
	}
	// The inner Redis impl reads from local cache (populated via pub/sub),
	// so this should not fail. If it somehow errors, fail-closed.
	blocked, err := r.inner.ShouldBlock(ctx, agentID, sessionID)
	if err != nil {
		r.reporter.MarkDegraded()
		return true, nil
	}
	return blocked, nil
}

// ActivateGlobal delegates to the inner implementation.
func (r *ResilientRedis) ActivateGlobal(ctx context.Context) error {
	err := r.inner.ActivateGlobal(ctx)
	r.updateHealth(err)
	return err
}

// DeactivateGlobal delegates to the inner implementation.
func (r *ResilientRedis) DeactivateGlobal(ctx context.Context) error {
	err := r.inner.DeactivateGlobal(ctx)
	r.updateHealth(err)
	return err
}

// KillAgent delegates to the inner implementation.
func (r *ResilientRedis) KillAgent(ctx context.Context, agentID string) error {
	err := r.inner.KillAgent(ctx, agentID)
	r.updateHealth(err)
	return err
}

// ReviveAgent delegates to the inner implementation.
func (r *ResilientRedis) ReviveAgent(ctx context.Context, agentID string) error {
	err := r.inner.ReviveAgent(ctx, agentID)
	r.updateHealth(err)
	return err
}

// KillSession delegates to the inner implementation.
func (r *ResilientRedis) KillSession(ctx context.Context, sessionID string) error {
	err := r.inner.KillSession(ctx, sessionID)
	r.updateHealth(err)
	return err
}

// ReviveSession delegates to the inner implementation.
func (r *ResilientRedis) ReviveSession(ctx context.Context, sessionID string) error {
	err := r.inner.ReviveSession(ctx, sessionID)
	r.updateHealth(err)
	return err
}

// Reset delegates to the inner implementation.
func (r *ResilientRedis) Reset(ctx context.Context) error {
	err := r.inner.Reset(ctx)
	r.updateHealth(err)
	return err
}

// Status delegates to the inner implementation.
func (r *ResilientRedis) Status(ctx context.Context) (*Status, error) {
	return r.inner.Status(ctx)
}

func (r *ResilientRedis) updateHealth(err error) {
	if err != nil {
		r.reporter.MarkDegraded()
	} else {
		r.reporter.MarkHealthy()
	}
}
