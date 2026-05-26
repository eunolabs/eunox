// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/edgeobs/eunox/internal/posture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testPlugin is a thread-safe mock plugin for integration tests.
type testPlugin struct {
	name     string
	observed []posture.AgentInventoryRecord
	revoked  []string
	mu       sync.Mutex
	count    atomic.Int32
}

func (p *testPlugin) Name() string { return p.name }

func (p *testPlugin) EmitObserved(_ context.Context, record *posture.AgentInventoryRecord) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.observed = append(p.observed, *record)
	p.count.Add(1)
	return nil
}

func (p *testPlugin) EmitRevoked(_ context.Context, agentID string, _ time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.revoked = append(p.revoked, agentID)
	p.count.Add(1)
	return nil
}

func (p *testPlugin) totalCount() int {
	return int(p.count.Load())
}

// TestPostureEmitter_EndToEnd_EmitAndDelivery verifies the full lifecycle:
// HTTP emit request → durable queue → delivery worker → plugin receives event.
func TestPostureEmitter_EndToEnd_EmitAndDelivery(t *testing.T) {
	plugin := &testPlugin{name: "integration-test"}

	cfg := posture.DefaultConfig()
	cfg.QueuePath = ":memory:"
	cfg.FlushIntervalMS = 50
	cfg.DedupeWindowMS = 0 // Disable dedup for test clarity.

	app, err := posture.New(&cfg, []posture.Plugin{plugin}, &posture.Dependencies{})
	require.NoError(t, err)
	defer app.Stop()

	app.Start()

	// Issue an emit request via HTTP.
	emitBody := posture.EmitRequest{
		AgentID:                "integration-agent-1",
		OwningTeam:             "platform-team",
		CapabilityManifestHash: "sha256:abc123",
		Runtime:                "go/1.25",
		Region:                 "us-east-1",
		Capabilities:           []string{"tool:search", "tool:write"},
	}
	bodyBytes, _ := json.Marshal(emitBody)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/emit", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code)

	// Wait for delivery to the plugin.
	assert.Eventually(t, func() bool {
		return plugin.totalCount() >= 1
	}, 5*time.Second, 10*time.Millisecond)

	// Verify the plugin received the correct record.
	plugin.mu.Lock()
	defer plugin.mu.Unlock()
	require.Len(t, plugin.observed, 1)
	assert.Equal(t, "integration-agent-1", plugin.observed[0].AgentID)
	assert.Equal(t, "platform-team", plugin.observed[0].OwningTeam)
	assert.Equal(t, "sha256:abc123", plugin.observed[0].CapabilityManifestHash)
	assert.Equal(t, "go/1.25", plugin.observed[0].Runtime)
	assert.Equal(t, "us-east-1", plugin.observed[0].Region)
	assert.Equal(t, []string{"tool:search", "tool:write"}, plugin.observed[0].Capabilities)
}

// TestPostureEmitter_EndToEnd_RevokeFlow verifies: emit → revoke → plugin gets both events.
func TestPostureEmitter_EndToEnd_RevokeFlow(t *testing.T) {
	plugin := &testPlugin{name: "revoke-test"}

	cfg := posture.DefaultConfig()
	cfg.QueuePath = ":memory:"
	cfg.FlushIntervalMS = 50
	cfg.DedupeWindowMS = 0

	app, err := posture.New(&cfg, []posture.Plugin{plugin}, &posture.Dependencies{})
	require.NoError(t, err)
	defer app.Stop()

	app.Start()

	// Step 1: Emit an agent observation.
	emitBody, _ := json.Marshal(posture.EmitRequest{
		AgentID:    "agent-to-revoke",
		OwningTeam: "security",
		Runtime:    "python/3.12",
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/emit", bytes.NewReader(emitBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusAccepted, rec.Code)

	// Wait for delivery.
	assert.Eventually(t, func() bool {
		return plugin.totalCount() >= 1
	}, 5*time.Second, 10*time.Millisecond)

	// Step 2: Revoke the agent.
	revokeBody, _ := json.Marshal(posture.RevokeRequest{AgentID: "agent-to-revoke"})
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/revoke", bytes.NewReader(revokeBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusAccepted, rec.Code)

	// Wait for revoke delivery.
	assert.Eventually(t, func() bool {
		return plugin.totalCount() >= 2
	}, 5*time.Second, 10*time.Millisecond)

	// Verify both events received.
	plugin.mu.Lock()
	defer plugin.mu.Unlock()
	require.Len(t, plugin.observed, 1)
	require.Len(t, plugin.revoked, 1)
	assert.Equal(t, "agent-to-revoke", plugin.observed[0].AgentID)
	assert.Equal(t, "agent-to-revoke", plugin.revoked[0])
}

// TestPostureEmitter_EndToEnd_HealthEndpoints verifies health probes work correctly.
func TestPostureEmitter_EndToEnd_HealthEndpoints(t *testing.T) {
	cfg := posture.DefaultConfig()
	cfg.QueuePath = ":memory:"
	cfg.HealthMaxQueueDepth = 100

	app, err := posture.New(&cfg, nil, &posture.Dependencies{})
	require.NoError(t, err)
	defer app.Stop()

	// Liveness.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/health/live", http.NoBody)
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Readiness (healthy - empty queue).
	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/health/ready", http.NoBody)
	rec = httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]interface{}
	_ = json.NewDecoder(rec.Body).Decode(&body)
	assert.Equal(t, "ready", body["status"])
	assert.Equal(t, float64(0), body["queueDepth"])
}

// TestPostureEmitter_EndToEnd_MultiplePlugins ensures all configured plugins receive events.
func TestPostureEmitter_EndToEnd_MultiplePlugins(t *testing.T) {
	plugin1 := &testPlugin{name: "defender"}
	plugin2 := &testPlugin{name: "security-hub"}
	plugin3 := &testPlugin{name: "scc"}

	cfg := posture.DefaultConfig()
	cfg.QueuePath = ":memory:"
	cfg.FlushIntervalMS = 50
	cfg.DedupeWindowMS = 0

	app, err := posture.New(&cfg, []posture.Plugin{plugin1, plugin2, plugin3}, &posture.Dependencies{})
	require.NoError(t, err)
	defer app.Stop()

	app.Start()

	emitBody, _ := json.Marshal(posture.EmitRequest{
		AgentID:    "multi-plugin-agent",
		OwningTeam: "infra",
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/emit", bytes.NewReader(emitBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusAccepted, rec.Code)

	// Wait for all plugins to receive the event.
	assert.Eventually(t, func() bool {
		return plugin1.totalCount() >= 1 && plugin2.totalCount() >= 1 && plugin3.totalCount() >= 1
	}, 5*time.Second, 10*time.Millisecond)

	plugin1.mu.Lock()
	assert.Equal(t, "multi-plugin-agent", plugin1.observed[0].AgentID)
	plugin1.mu.Unlock()

	plugin2.mu.Lock()
	assert.Equal(t, "multi-plugin-agent", plugin2.observed[0].AgentID)
	plugin2.mu.Unlock()

	plugin3.mu.Lock()
	assert.Equal(t, "multi-plugin-agent", plugin3.observed[0].AgentID)
	plugin3.mu.Unlock()
}
