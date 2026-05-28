// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package killswitch

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/eunolabs/eunox/pkg/redisfailover"
	"github.com/redis/go-redis/v9"
)

// perAgentChannelPrefix is the Redis pub/sub channel prefix for per-agent kill-switch events.
// Each agent subscribes to "killswitch:agent-events:<agentID>" for its own partition.
// Global and session events are still broadcast on the shared "killswitch:events" channel.
const perAgentChannelPrefix = "killswitch:agent-events:"

// agentPartition holds the per-agent kill state and subscription health for one agent.
type agentPartition struct {
	mu       sync.RWMutex
	killed   bool
	degraded bool // true when the per-agent subscription has failed; causes fail-closed
	cancel   context.CancelFunc
}

// PartitionedKillSwitch wraps [Redis] and provides per-agent failure domain isolation
// (P3-4). In a centralized gateway serving many agents, a Redis subscription failure
// for one agent's partition degrades only that agent (fail-closed) rather than
// blocking or exposing all agents.
//
// Architecture:
//   - Global and session kill-switch state is managed by the embedded [Redis] manager
//     and propagated via the shared "killswitch:events" channel.
//   - Each agent whose agentID is seen in a [ShouldBlock] call gets its own Redis
//     pub/sub subscription on "killswitch:agent-events:<agentID>".
//   - If that per-agent subscription fails, [ShouldBlock] returns (true, nil) for
//     that agent only — all other agents are unaffected.
//
// The per-agent subscriptions carry only agent-level kill events for their specific
// agent. The global Redis manager handles the remaining state (global active, all
// agent kills for status queries). Per-agent kill/revive operations are also published
// on the per-agent channel so that the owning partition receives them without going
// through the global scan.
//
// Use [NewPartitioned] and call [PartitionedKillSwitch.Start] to begin background subscriptions.
type PartitionedKillSwitch struct {
	inner    *Redis // handles global + session + full state refresh
	client   redis.UniversalClient
	logger   *slog.Logger
	reporter *redisfailover.Reporter // optional; used for readiness reporting

	mu           sync.RWMutex
	partitions   map[string]*agentPartition
	lifecycleCtx context.Context // set by Start; controls per-agent subscription lifetimes
	started      bool            // true after Start has completed its initial load
}

// NewPartitioned creates a partitioned kill-switch manager. client must be a
// [redis.UniversalClient] so that per-agent subscriptions can be created.
// inner must be the same Redis client wrapped in [Redis].
func NewPartitioned(inner *Redis, client redis.UniversalClient, logger *slog.Logger) *PartitionedKillSwitch {
	return &PartitionedKillSwitch{
		inner:      inner,
		client:     client,
		logger:     logger,
		partitions: make(map[string]*agentPartition),
	}
}

// WithReporter attaches a [redisfailover.Reporter] to the partitioned kill-switch so
// that it can report readiness state to the health monitor (fail-closed semantics
// identical to [ResilientRedis]).
func (p *PartitionedKillSwitch) WithReporter(reporter *redisfailover.Reporter) *PartitionedKillSwitch {
	p.reporter = reporter
	return p
}

// Start initialises the shared kill-switch state and stores the lifecycle context
// so that per-agent subscriptions (created lazily on first [ShouldBlock] call) are
// tied to the service lifetime rather than individual request contexts. ctx must
// remain live for the duration of the service — canceling it will shut down all
// background pub/sub goroutines.
func (p *PartitionedKillSwitch) Start(ctx context.Context) {
	p.inner.Start(ctx)

	p.mu.Lock()
	p.lifecycleCtx = ctx
	p.started = true
	p.mu.Unlock()

	if p.reporter != nil {
		if err := p.inner.HealthStatus(); err != nil {
			p.reporter.MarkDegraded()
		} else {
			p.reporter.MarkHealthy()
		}
	}
}

// Stop cancels the shared kill-switch and all per-agent subscriptions.
func (p *PartitionedKillSwitch) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, part := range p.partitions {
		if part.cancel != nil {
			part.cancel()
		}
	}
	p.inner.Stop()
}

// ShouldBlock returns true if any kill-switch condition is active for the given agent
// or session. Per-agent failure domain isolation:
//   - If [Start] has not yet been called (initial state not loaded), fail-closed.
//   - If the per-agent subscription for agentID is degraded (connection failed), this
//     agent is treated as fail-closed (blocked) until the subscription recovers.
//   - If the global shared kill-switch is degraded, all agents are affected (same as
//     the existing Redis kill-switch behaviour).
func (p *PartitionedKillSwitch) ShouldBlock(ctx context.Context, agentID, sessionID string) (bool, error) {
	p.mu.RLock()
	started := p.started
	p.mu.RUnlock()
	if !started {
		// Not yet initialised: fail-closed.
		return true, nil
	}

	// Delegate global and session checks to the shared inner manager.
	blocked, err := p.inner.ShouldBlock(ctx, agentID, sessionID)
	if err != nil || blocked {
		if p.reporter != nil && err != nil {
			p.reporter.MarkDegraded()
		}
		return blocked, err
	}

	if agentID == "" {
		return false, nil
	}

	// Ensure a per-agent partition (and subscription) exists for this agentID.
	part := p.getOrCreatePartition(agentID)

	part.mu.RLock()
	defer part.mu.RUnlock()

	// Fail-closed: if the per-agent subscription is degraded, block the agent.
	if part.degraded {
		return true, nil
	}
	return part.killed, nil
}

// ActivateGlobal delegates to the shared manager.
func (p *PartitionedKillSwitch) ActivateGlobal(ctx context.Context) error {
	return p.inner.ActivateGlobal(ctx)
}

// DeactivateGlobal delegates to the shared manager.
func (p *PartitionedKillSwitch) DeactivateGlobal(ctx context.Context) error {
	return p.inner.DeactivateGlobal(ctx)
}

// KillAgent blocks the specified agent via the shared manager and also notifies the
// agent's own partition channel so that any running sidecar for this agent picks up
// the event without waiting for a shared-channel pub/sub round-trip.
func (p *PartitionedKillSwitch) KillAgent(ctx context.Context, agentID string) error {
	if err := p.inner.KillAgent(ctx, agentID); err != nil {
		return err
	}
	// Also update the in-memory partition if it exists (avoids latency on hot path).
	p.mu.RLock()
	part, ok := p.partitions[agentID]
	p.mu.RUnlock()
	if ok {
		part.mu.Lock()
		part.killed = true
		part.mu.Unlock()
	}
	// Publish on the per-agent channel as well.
	p.publishAgentEvent(ctx, agentID, "kill")
	return nil
}

// ReviveAgent removes the kill on the specified agent.
func (p *PartitionedKillSwitch) ReviveAgent(ctx context.Context, agentID string) error {
	if err := p.inner.ReviveAgent(ctx, agentID); err != nil {
		return err
	}
	p.mu.RLock()
	part, ok := p.partitions[agentID]
	p.mu.RUnlock()
	if ok {
		part.mu.Lock()
		part.killed = false
		part.mu.Unlock()
	}
	p.publishAgentEvent(ctx, agentID, "revive")
	return nil
}

// KillSession delegates to the shared manager.
func (p *PartitionedKillSwitch) KillSession(ctx context.Context, sessionID string) error {
	return p.inner.KillSession(ctx, sessionID)
}

// ReviveSession delegates to the shared manager.
func (p *PartitionedKillSwitch) ReviveSession(ctx context.Context, sessionID string) error {
	return p.inner.ReviveSession(ctx, sessionID)
}

// Reset clears all state including per-agent partitions. Active per-agent subscriptions
// are canceled and removed; they will be re-created lazily on the next [ShouldBlock]
// call, seeding fresh state from the shared manager's (now reset) cache.
func (p *PartitionedKillSwitch) Reset(ctx context.Context) error {
	if err := p.inner.Reset(ctx); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, part := range p.partitions {
		if part.cancel != nil {
			part.cancel()
		}
	}
	p.partitions = make(map[string]*agentPartition)
	return nil
}

// Status returns the current kill-switch state from the shared manager.
func (p *PartitionedKillSwitch) Status(ctx context.Context) (*Status, error) {
	return p.inner.Status(ctx)
}

// DegradedAgents returns the list of agent IDs whose per-agent subscriptions are
// currently degraded. This is useful for operational monitoring.
func (p *PartitionedKillSwitch) DegradedAgents() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var degraded []string
	for id, part := range p.partitions {
		part.mu.RLock()
		if part.degraded {
			degraded = append(degraded, id)
		}
		part.mu.RUnlock()
	}
	return degraded
}

// getOrCreatePartition returns the agentPartition for agentID, creating and starting
// a per-agent subscription if one does not yet exist. The subscription goroutine is
// tied to p.lifecycleCtx (set by Start) so that it outlives individual requests.
func (p *PartitionedKillSwitch) getOrCreatePartition(agentID string) *agentPartition {
	p.mu.RLock()
	part, ok := p.partitions[agentID]
	p.mu.RUnlock()
	if ok {
		return part
	}

	p.mu.Lock()
	// Double-check under write lock to avoid duplicate creation.
	if part, ok = p.partitions[agentID]; ok {
		p.mu.Unlock()
		return part
	}

	part = &agentPartition{}
	// Seed initial kill state from the shared manager's cache.
	// The shared Redis manager's ShouldBlock reads from its local cache, so this
	// is fast and does not trigger a Redis round-trip.
	blocked, _ := p.inner.ShouldBlock(p.lifecycleCtx, agentID, "")
	part.killed = blocked

	p.partitions[agentID] = part

	// Start the per-agent subscription tied to the service lifecycle context.
	partCtx, cancel := context.WithCancel(p.lifecycleCtx)
	part.cancel = cancel
	p.mu.Unlock()

	go p.runAgentSubscription(partCtx, agentID, part)

	return part
}

// runAgentSubscription subscribes to the per-agent pub/sub channel and updates the
// partition's kill state. If the subscription fails on startup, the partition is
// marked degraded (fail-closed). On channel closure, the partition is also marked
// degraded until the subscription can be re-established (which does not happen
// automatically; operators should investigate Redis connectivity).
func (p *PartitionedKillSwitch) runAgentSubscription(ctx context.Context, agentID string, part *agentPartition) {
	channel := perAgentChannelPrefix + agentID
	pubsub := p.client.Subscribe(ctx, channel)
	defer func() { _ = pubsub.Close() }()

	// Ping to confirm the subscription was established before we mark healthy.
	if _, err := pubsub.Receive(ctx); err != nil {
		if p.logger != nil {
			p.logger.Warn("kill switch: per-agent subscription failed on startup; marking agent degraded (fail-closed)",
				slog.String("agentID", agentID),
				slog.String("error", err.Error()),
			)
		}
		part.mu.Lock()
		part.degraded = true
		part.mu.Unlock()
		return
	}

	// Subscription is live; mark healthy and start processing events.
	part.mu.Lock()
	part.degraded = false
	part.mu.Unlock()

	ch := pubsub.Channel()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				// Channel closed — mark degraded until operator restores connectivity.
				if p.logger != nil {
					p.logger.Warn("kill switch: per-agent subscription channel closed; marking agent degraded (fail-closed)",
						slog.String("agentID", agentID),
					)
				}
				part.mu.Lock()
				part.degraded = true
				part.mu.Unlock()
				return
			}
			p.handleAgentEvent(part, msg.Payload)
		}
	}
}

// handleAgentEvent processes a per-agent pub/sub message.
func (p *PartitionedKillSwitch) handleAgentEvent(part *agentPartition, payload string) {
	part.mu.Lock()
	defer part.mu.Unlock()
	switch payload {
	case "kill":
		part.killed = true
	case "revive":
		part.killed = false
	}
}

// publishAgentEvent publishes a kill/revive event on the per-agent channel.
func (p *PartitionedKillSwitch) publishAgentEvent(ctx context.Context, agentID, event string) {
	channel := perAgentChannelPrefix + agentID
	if err := p.client.Publish(ctx, channel, event).Err(); err != nil && p.logger != nil {
		p.logger.Warn("kill switch: failed to publish per-agent event",
			slog.String("agentID", agentID),
			slog.String("event", event),
			slog.String("error", err.Error()),
		)
	}
}

// agentChannel returns the per-agent pub/sub channel name for a given agentID.
// Exported for use in tests.
func agentChannel(agentID string) string {
	return fmt.Sprintf("%s%s", perAgentChannelPrefix, agentID)
}
