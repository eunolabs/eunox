// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package posture

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPlugin records all calls for testing.
type mockPlugin struct {
	name      string
	observed  []AgentInventoryRecord
	revoked   []revokedCall
	mu        sync.Mutex
	failsLeft atomic.Int32
}

type revokedCall struct {
	AgentID   string
	RevokedAt time.Time
}

func newMockPlugin(name string) *mockPlugin {
	return &mockPlugin{name: name}
}

func (p *mockPlugin) Name() string { return p.name }

func (p *mockPlugin) EmitObserved(_ context.Context, record *AgentInventoryRecord) error {
	if p.failsLeft.Load() > 0 {
		p.failsLeft.Add(-1)
		return fmt.Errorf("mock transient failure")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.observed = append(p.observed, *record)
	return nil
}

func (p *mockPlugin) EmitRevoked(_ context.Context, agentID string, revokedAt time.Time) error {
	if p.failsLeft.Load() > 0 {
		p.failsLeft.Add(-1)
		return fmt.Errorf("mock transient failure")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.revoked = append(p.revoked, revokedCall{agentID, revokedAt})
	return nil
}

func (p *mockPlugin) observedCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.observed)
}

func (p *mockPlugin) revokedCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.revoked)
}

// mockMetrics tracks delivery metrics for testing.
type mockMetrics struct {
	delivered    atomic.Int32
	errors       atomic.Int32
	deadLettered atomic.Int32
}

func (m *mockMetrics) OnDelivered(_ EventType, _ string)     { m.delivered.Add(1) }
func (m *mockMetrics) OnDeliveryError(_ EventType, _ string) { m.errors.Add(1) }
func (m *mockMetrics) OnDeadLettered(_ EventType)            { m.deadLettered.Add(1) }

func TestDeliveryWorker_DeliversObservedEvent(t *testing.T) {
	q, err := NewSQLiteQueue(":memory:")
	require.NoError(t, err)
	defer func() { _ = q.Close() }()

	plugin := newMockPlugin("test")
	metrics := &mockMetrics{}

	// Enqueue an observed event.
	record := AgentInventoryRecord{
		AgentID:    "agent-1",
		OwningTeam: "team-a",
		FirstSeen:  time.Now().UTC(),
		LastSeen:   time.Now().UTC(),
	}
	payload, _ := json.Marshal(record)
	_, err = q.Push(context.Background(), EventObserved, payload)
	require.NoError(t, err)

	cfg := DeliveryWorkerConfig{
		MaxAttempts:   10,
		BackoffBase:   100 * time.Millisecond,
		BackoffMax:    1 * time.Second,
		BatchSize:     10,
		PollInterval:  50 * time.Millisecond,
		PluginTimeout: 5 * time.Second,
	}

	worker := NewDeliveryWorker(q, []Plugin{plugin}, cfg, nil, metrics)
	worker.Start()

	// Wait for delivery.
	assert.Eventually(t, func() bool {
		return plugin.observedCount() == 1
	}, 2*time.Second, 10*time.Millisecond)

	worker.Stop()

	assert.Equal(t, int32(1), metrics.delivered.Load())
	assert.Equal(t, "agent-1", plugin.observed[0].AgentID)

	// Queue should be empty.
	depth, _ := q.Depth(context.Background())
	assert.Equal(t, int64(0), depth)
}

func TestDeliveryWorker_DeliversRevokedEvent(t *testing.T) {
	q, err := NewSQLiteQueue(":memory:")
	require.NoError(t, err)
	defer func() { _ = q.Close() }()

	plugin := newMockPlugin("test")

	revokedAt := time.Now().UTC().Truncate(time.Second)
	payload, _ := json.Marshal(RevokedPayload{
		AgentID:   "agent-revoke",
		RevokedAt: revokedAt,
	})
	_, err = q.Push(context.Background(), EventRevoked, payload)
	require.NoError(t, err)

	cfg := DeliveryWorkerConfig{
		MaxAttempts:   10,
		BackoffBase:   100 * time.Millisecond,
		BackoffMax:    1 * time.Second,
		BatchSize:     10,
		PollInterval:  50 * time.Millisecond,
		PluginTimeout: 5 * time.Second,
	}

	worker := NewDeliveryWorker(q, []Plugin{plugin}, cfg, nil, nil)
	worker.Start()

	assert.Eventually(t, func() bool {
		return plugin.revokedCount() == 1
	}, 2*time.Second, 10*time.Millisecond)

	worker.Stop()

	assert.Equal(t, "agent-revoke", plugin.revoked[0].AgentID)
	assert.Equal(t, revokedAt, plugin.revoked[0].RevokedAt)
}

func TestDeliveryWorker_RetriesOnFailure(t *testing.T) {
	q, err := NewSQLiteQueue(":memory:")
	require.NoError(t, err)
	defer func() { _ = q.Close() }()

	plugin := newMockPlugin("test")
	plugin.failsLeft.Store(2) // Fail first 2 attempts.
	metrics := &mockMetrics{}

	record := AgentInventoryRecord{AgentID: "agent-retry", FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC()}
	payload, _ := json.Marshal(record)
	_, err = q.Push(context.Background(), EventObserved, payload)
	require.NoError(t, err)

	cfg := DeliveryWorkerConfig{
		MaxAttempts:   10,
		BackoffBase:   10 * time.Millisecond, // Very short for test speed.
		BackoffMax:    50 * time.Millisecond,
		BatchSize:     10,
		PollInterval:  20 * time.Millisecond,
		PluginTimeout: 5 * time.Second,
	}

	worker := NewDeliveryWorker(q, []Plugin{plugin}, cfg, nil, metrics)
	worker.Start()

	// Eventually succeeds after retries.
	assert.Eventually(t, func() bool {
		return plugin.observedCount() == 1
	}, 5*time.Second, 10*time.Millisecond)

	worker.Stop()

	assert.Equal(t, int32(1), metrics.delivered.Load())
	assert.GreaterOrEqual(t, metrics.errors.Load(), int32(2))
}

func TestDeliveryWorker_DeadLettersAfterMaxAttempts(t *testing.T) {
	q, err := NewSQLiteQueue(":memory:")
	require.NoError(t, err)
	defer func() { _ = q.Close() }()

	plugin := newMockPlugin("test")
	plugin.failsLeft.Store(100) // Always fail.
	metrics := &mockMetrics{}

	record := AgentInventoryRecord{AgentID: "agent-dead", FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC()}
	payload, _ := json.Marshal(record)

	// Manually push with enough attempts to trigger dead-letter on next tick.
	id, err := q.Push(context.Background(), EventObserved, payload)
	require.NoError(t, err)

	// Set attempts to maxAttempts to trigger dead-letter immediately.
	q.mu.Lock()
	_, err = q.db.ExecContext(context.Background(), `UPDATE posture_queue SET attempts = ? WHERE id = ?`, 10, id)
	q.mu.Unlock()
	require.NoError(t, err)

	cfg := DeliveryWorkerConfig{
		MaxAttempts:   10,
		BackoffBase:   10 * time.Millisecond,
		BackoffMax:    50 * time.Millisecond,
		BatchSize:     10,
		PollInterval:  20 * time.Millisecond,
		PluginTimeout: 5 * time.Second,
	}

	worker := NewDeliveryWorker(q, []Plugin{plugin}, cfg, nil, metrics)
	worker.Start()

	assert.Eventually(t, func() bool {
		return metrics.deadLettered.Load() == 1
	}, 2*time.Second, 10*time.Millisecond)

	worker.Stop()

	// Plugin should NOT have been called (dead-letter skips delivery).
	assert.Equal(t, 0, plugin.observedCount())
}

func TestDeliveryWorker_MultiplePlugins(t *testing.T) {
	q, err := NewSQLiteQueue(":memory:")
	require.NoError(t, err)
	defer func() { _ = q.Close() }()

	plugin1 := newMockPlugin("plugin-1")
	plugin2 := newMockPlugin("plugin-2")

	record := AgentInventoryRecord{AgentID: "agent-multi", FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC()}
	payload, _ := json.Marshal(record)
	_, err = q.Push(context.Background(), EventObserved, payload)
	require.NoError(t, err)

	cfg := DeliveryWorkerConfig{
		MaxAttempts:   10,
		BackoffBase:   100 * time.Millisecond,
		BackoffMax:    1 * time.Second,
		BatchSize:     10,
		PollInterval:  50 * time.Millisecond,
		PluginTimeout: 5 * time.Second,
	}

	worker := NewDeliveryWorker(q, []Plugin{plugin1, plugin2}, cfg, nil, nil)
	worker.Start()

	assert.Eventually(t, func() bool {
		return plugin1.observedCount() == 1 && plugin2.observedCount() == 1
	}, 2*time.Second, 10*time.Millisecond)

	worker.Stop()
}

func TestDeliveryWorker_StopDrainsInFlight(t *testing.T) {
	q, err := NewSQLiteQueue(":memory:")
	require.NoError(t, err)
	defer func() { _ = q.Close() }()

	plugin := newMockPlugin("test")

	// Push multiple events.
	for i := 0; i < 5; i++ {
		record := AgentInventoryRecord{AgentID: fmt.Sprintf("agent-%d", i), FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC()}
		payload, _ := json.Marshal(record)
		_, _ = q.Push(context.Background(), EventObserved, payload)
	}

	cfg := DeliveryWorkerConfig{
		MaxAttempts:   10,
		BackoffBase:   100 * time.Millisecond,
		BackoffMax:    1 * time.Second,
		BatchSize:     50,
		PollInterval:  1 * time.Hour, // Very long poll interval.
		PluginTimeout: 5 * time.Second,
	}

	worker := NewDeliveryWorker(q, []Plugin{plugin}, cfg, nil, nil)
	worker.Start()

	// Stop should trigger a final drain tick.
	worker.Stop()

	// All 5 events should have been delivered during the drain.
	assert.Equal(t, 5, plugin.observedCount())
}

func TestComputeNextAttempt_LargeAttempts(t *testing.T) {
	cfg := DeliveryWorkerConfig{
		MaxAttempts: 10,
		BackoffBase: 1 * time.Second,
		BackoffMax:  5 * time.Minute,
	}
	worker := &DeliveryWorker{config: cfg}

	largeCases := []int{0, 1, 10, 62, 63, 64, 100, 1000, 1<<30 - 1}
	for _, attempts := range largeCases {
		before := time.Now().UnixMilli()
		result := worker.computeNextAttempt(attempts)
		after := time.Now().Add(cfg.BackoffMax).UnixMilli()

		// Result must be a future timestamp (positive backoff).
		assert.Greater(t, result, before, "attempt=%d: backoff must be positive (result=%d)", attempts, result)
		// Result must not exceed now + BackoffMax.
		assert.LessOrEqual(t, result, after, "attempt=%d: backoff must not exceed BackoffMax (result=%d)", attempts, result)
	}
}
