// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package posture

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApp_EmitObserved(t *testing.T) {
	cfg := DefaultConfig()
	cfg.QueuePath = ":memory:"
	cfg.DedupeWindowMS = 0 // Disable deduplication for test clarity.

	plugin := newMockPlugin("test")
	app, err := New(cfg, []Plugin{plugin}, Dependencies{})
	require.NoError(t, err)
	defer app.Stop()

	app.Start()

	record := AgentInventoryRecord{
		AgentID:    "agent-1",
		OwningTeam: "team-a",
		Runtime:    "langchain-go/0.1",
		Region:     "us-east-1",
		FirstSeen:  time.Now().UTC(),
		LastSeen:   time.Now().UTC(),
	}

	err = app.EmitObserved(record)
	require.NoError(t, err)

	// Wait for delivery.
	assert.Eventually(t, func() bool {
		return plugin.observedCount() == 1
	}, 5*time.Second, 10*time.Millisecond)

	assert.Equal(t, "agent-1", plugin.observed[0].AgentID)
	assert.Equal(t, "team-a", plugin.observed[0].OwningTeam)
}

func TestApp_EmitRevoked(t *testing.T) {
	cfg := DefaultConfig()
	cfg.QueuePath = ":memory:"

	plugin := newMockPlugin("test")
	app, err := New(cfg, []Plugin{plugin}, Dependencies{})
	require.NoError(t, err)
	defer app.Stop()

	app.Start()

	revokedAt := time.Now().UTC().Truncate(time.Second)
	err = app.EmitRevoked("agent-revoke", revokedAt)
	require.NoError(t, err)

	assert.Eventually(t, func() bool {
		return plugin.revokedCount() == 1
	}, 5*time.Second, 10*time.Millisecond)

	assert.Equal(t, "agent-revoke", plugin.revoked[0].AgentID)
}

func TestApp_EmitObserved_Disabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.QueuePath = ":memory:"
	cfg.Enabled = false

	app, err := New(cfg, nil, Dependencies{})
	require.NoError(t, err)
	defer app.Stop()

	err = app.EmitObserved(AgentInventoryRecord{AgentID: "agent-1", FirstSeen: time.Now(), LastSeen: time.Now()})
	assert.NoError(t, err)

	depth, err := app.QueueDepth()
	require.NoError(t, err)
	assert.Equal(t, int64(0), depth)
}

func TestApp_EmitObserved_Deduplication(t *testing.T) {
	cfg := DefaultConfig()
	cfg.QueuePath = ":memory:"
	cfg.DedupeWindowMS = 300000 // 5 minutes.
	cfg.FlushIntervalMS = 50    // Fast polling for test.

	plugin := newMockPlugin("test")
	app, err := New(cfg, []Plugin{plugin}, Dependencies{})
	require.NoError(t, err)
	defer app.Stop()

	app.Start()

	now := time.Now().UTC()
	record := AgentInventoryRecord{
		AgentID:   "agent-dup",
		FirstSeen: now,
		LastSeen:  now,
	}

	// First emit should enqueue.
	err = app.EmitObserved(record)
	require.NoError(t, err)

	// Second emit within window should be deduplicated.
	record.LastSeen = now.Add(1 * time.Minute)
	err = app.EmitObserved(record)
	require.NoError(t, err)

	// Wait for delivery of the single event.
	assert.Eventually(t, func() bool {
		return plugin.observedCount() == 1
	}, 5*time.Second, 10*time.Millisecond)

	// Give extra time to ensure no second delivery.
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, 1, plugin.observedCount())
}

func TestApp_QueueDepth(t *testing.T) {
	cfg := DefaultConfig()
	cfg.QueuePath = ":memory:"
	cfg.Enabled = true
	cfg.DedupeWindowMS = 0

	// Don't start the worker so events accumulate.
	app, err := New(cfg, nil, Dependencies{})
	require.NoError(t, err)
	defer app.Stop()

	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		_ = app.EmitObserved(AgentInventoryRecord{
			AgentID:   fmt.Sprintf("agent-%d", i),
			FirstSeen: now,
			LastSeen:  now,
		})
	}

	depth, err := app.QueueDepth()
	require.NoError(t, err)
	assert.Equal(t, int64(3), depth)
}

// --- HTTP Handler Tests ---

func TestApp_HandleLive(t *testing.T) {
	cfg := DefaultConfig()
	cfg.QueuePath = ":memory:"

	app, err := New(cfg, nil, Dependencies{})
	require.NoError(t, err)
	defer app.Stop()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/health/live", nil)
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]string
	_ = json.NewDecoder(rec.Body).Decode(&body)
	assert.Equal(t, "ok", body["status"])
}

func TestApp_HandleReady_Healthy(t *testing.T) {
	cfg := DefaultConfig()
	cfg.QueuePath = ":memory:"

	app, err := New(cfg, nil, Dependencies{})
	require.NoError(t, err)
	defer app.Stop()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/health/ready", nil)
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestApp_HandleReady_Degraded(t *testing.T) {
	cfg := DefaultConfig()
	cfg.QueuePath = ":memory:"
	cfg.HealthMaxQueueDepth = 2
	cfg.DedupeWindowMS = 0

	app, err := New(cfg, nil, Dependencies{})
	require.NoError(t, err)
	defer app.Stop()

	// Push enough events to exceed threshold.
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		_ = app.EmitObserved(AgentInventoryRecord{
			AgentID:   fmt.Sprintf("agent-%d", i),
			FirstSeen: now,
			LastSeen:  now,
		})
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/health/ready", nil)
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestApp_HandleReady_QueueError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.QueuePath = ":memory:"

	app, err := New(cfg, nil, Dependencies{})
	require.NoError(t, err)
	app.Stop()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/health/ready", nil)
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestApp_HandleStatus(t *testing.T) {
	cfg := DefaultConfig()
	cfg.QueuePath = ":memory:"

	plugin := newMockPlugin("test-plugin")
	app, err := New(cfg, []Plugin{plugin}, Dependencies{})
	require.NoError(t, err)
	defer app.Stop()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/status", nil)
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]interface{}
	_ = json.NewDecoder(rec.Body).Decode(&body)
	assert.Equal(t, true, body["enabled"])
	assert.Equal(t, float64(0), body["queueDepth"])

	plugins := body["plugins"].([]interface{})
	assert.Len(t, plugins, 1)
	assert.Equal(t, "test-plugin", plugins[0])
}

func TestApp_HandleStatus_QueueError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.QueuePath = ":memory:"

	app, err := New(cfg, nil, Dependencies{})
	require.NoError(t, err)
	app.Stop()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/status", nil)
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestApp_HandleEmit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.QueuePath = ":memory:"
	cfg.DedupeWindowMS = 0

	plugin := newMockPlugin("test")
	app, err := New(cfg, []Plugin{plugin}, Dependencies{})
	require.NoError(t, err)
	defer app.Stop()
	app.Start()

	body := EmitRequest{
		AgentID:    "http-agent",
		OwningTeam: "platform",
		Runtime:    "go/1.24",
		Region:     "eu-west-1",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/emit", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusAccepted, rec.Code)

	// Wait for delivery.
	assert.Eventually(t, func() bool {
		return plugin.observedCount() == 1
	}, 5*time.Second, 10*time.Millisecond)

	assert.Equal(t, "http-agent", plugin.observed[0].AgentID)
}

func TestApp_HandleEmit_MissingAgentID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.QueuePath = ":memory:"

	app, err := New(cfg, nil, Dependencies{})
	require.NoError(t, err)
	defer app.Stop()

	body := EmitRequest{OwningTeam: "platform"}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/emit", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestApp_HandleEmit_UnknownField(t *testing.T) {
	cfg := DefaultConfig()
	cfg.QueuePath = ":memory:"

	app, err := New(cfg, nil, Dependencies{})
	require.NoError(t, err)
	defer app.Stop()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/emit", bytes.NewBufferString(`{"agentId":"a","unexpected":1}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestApp_HandleRevoke(t *testing.T) {
	cfg := DefaultConfig()
	cfg.QueuePath = ":memory:"

	plugin := newMockPlugin("test")
	app, err := New(cfg, []Plugin{plugin}, Dependencies{})
	require.NoError(t, err)
	defer app.Stop()
	app.Start()

	body := RevokeRequest{AgentID: "revoke-agent"}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/revoke", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusAccepted, rec.Code)

	assert.Eventually(t, func() bool {
		return plugin.revokedCount() == 1
	}, 5*time.Second, 10*time.Millisecond)

	assert.Equal(t, "revoke-agent", plugin.revoked[0].AgentID)
}

func TestApp_HandleRevoke_MissingAgentID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.QueuePath = ":memory:"

	app, err := New(cfg, nil, Dependencies{})
	require.NoError(t, err)
	defer app.Stop()

	body := RevokeRequest{}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/revoke", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestApp_HandleRevoke_UnknownField(t *testing.T) {
	cfg := DefaultConfig()
	cfg.QueuePath = ":memory:"

	app, err := New(cfg, nil, Dependencies{})
	require.NoError(t, err)
	defer app.Stop()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/revoke", bytes.NewBufferString(`{"agentId":"a","unexpected":1}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// --- Plugin Tests ---

func TestDefenderPlugin_EmitObserved(t *testing.T) {
	var capturedAssessment DefenderAssessment
	var capturedResourceID, capturedName string

	client := &mockDefenderClient{
		createOrUpdate: func(_ context.Context, resourceID, name string, a DefenderAssessment) error {
			capturedResourceID = resourceID
			capturedName = name
			capturedAssessment = a
			return nil
		},
	}

	plugin := NewDefenderPlugin(DefenderPluginConfig{
		SubscriptionID: "sub-123",
		ClientFactory:  func() DefenderClient { return client },
	})

	record := AgentInventoryRecord{
		AgentID:                "test-agent",
		OwningTeam:             "team-x",
		CapabilityManifestHash: "sha256-abc",
		Runtime:                "go/1.24",
		Region:                 "westus2",
		FirstSeen:              time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC),
		LastSeen:               time.Date(2024, 6, 2, 0, 0, 0, 0, time.UTC),
	}

	err := plugin.EmitObserved(context.Background(), record)
	require.NoError(t, err)

	assert.Equal(t, "/subscriptions/sub-123", capturedResourceID)
	assert.Equal(t, "euno-agent-test-agent", capturedName)
	assert.Equal(t, "Healthy", capturedAssessment.Status)
	assert.Equal(t, "test-agent", capturedAssessment.AdditionalData["agentId"])
	assert.Equal(t, "team-x", capturedAssessment.AdditionalData["owningTeam"])
}

func TestDefenderPlugin_EmitRevoked(t *testing.T) {
	var capturedAssessment DefenderAssessment

	client := &mockDefenderClient{
		createOrUpdate: func(_ context.Context, _, _ string, a DefenderAssessment) error {
			capturedAssessment = a
			return nil
		},
	}

	plugin := NewDefenderPlugin(DefenderPluginConfig{
		SubscriptionID: "sub-123",
		ClientFactory:  func() DefenderClient { return client },
	})

	revokedAt := time.Date(2024, 6, 3, 12, 0, 0, 0, time.UTC)
	err := plugin.EmitRevoked(context.Background(), "test-agent", revokedAt)
	require.NoError(t, err)

	assert.Equal(t, "NotApplicable", capturedAssessment.Status)
	assert.Equal(t, "2024-06-03T12:00:00Z", capturedAssessment.AdditionalData["revokedAt"])
}

func TestSecurityHubPlugin_EmitObserved(t *testing.T) {
	var capturedFindings []SecurityHubFinding

	client := &mockSecurityHubClient{
		batchImport: func(_ context.Context, findings []SecurityHubFinding) error {
			capturedFindings = findings
			return nil
		},
	}

	plugin := NewSecurityHubPlugin(SecurityHubPluginConfig{
		AWSAccountID:  "123456789012",
		Region:        "us-east-1",
		ProductArn:    "arn:aws:securityhub:us-east-1:123456789012:product/euno/posture",
		ClientFactory: func() SecurityHubClient { return client },
	})

	record := AgentInventoryRecord{
		AgentID:    "hub-agent",
		OwningTeam: "sre",
		Runtime:    "python/3.11",
		Region:     "us-east-1",
		FirstSeen:  time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		LastSeen:   time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC),
	}

	err := plugin.EmitObserved(context.Background(), record)
	require.NoError(t, err)

	require.Len(t, capturedFindings, 1)
	f := capturedFindings[0]
	assert.Equal(t, "2018-10-08", f.SchemaVersion)
	assert.Equal(t, "123456789012", f.AwsAccountID)
	assert.Equal(t, "ACTIVE", f.RecordState)
	assert.Equal(t, "hub-agent", f.ProductFields["agentId"])
	assert.Equal(t, "INFORMATIONAL", f.Severity.Label)
}

func TestSecurityHubPlugin_EmitRevoked(t *testing.T) {
	var capturedUpdate FindingUpdate

	client := &mockSecurityHubClient{
		batchUpdate: func(_ context.Context, _ []FindingIdentifier, update FindingUpdate) error {
			capturedUpdate = update
			return nil
		},
	}

	plugin := NewSecurityHubPlugin(SecurityHubPluginConfig{
		AWSAccountID:  "123456789012",
		Region:        "us-east-1",
		ProductArn:    "arn:aws:securityhub:us-east-1:123456789012:product/euno/posture",
		ClientFactory: func() SecurityHubClient { return client },
	})

	err := plugin.EmitRevoked(context.Background(), "hub-agent", time.Now())
	require.NoError(t, err)

	assert.Equal(t, "RESOLVED", capturedUpdate.Workflow.Status)
	assert.Equal(t, "ARCHIVED", capturedUpdate.RecordState)
}

func TestSccPlugin_EmitObserved(t *testing.T) {
	var capturedReq SccCreateFindingRequest

	client := &mockSccClient{
		createFinding: func(_ context.Context, req SccCreateFindingRequest) error {
			capturedReq = req
			return nil
		},
	}

	plugin := NewSccPlugin(SccPluginConfig{
		SourceName:    "organizations/123/sources/456",
		ProjectID:     "my-project",
		ClientFactory: func() SccClient { return client },
	})

	record := AgentInventoryRecord{
		AgentID:    "scc-agent",
		OwningTeam: "ml-team",
		Runtime:    "java/17",
		Region:     "us-central1",
		FirstSeen:  time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC),
		LastSeen:   time.Date(2024, 3, 2, 0, 0, 0, 0, time.UTC),
	}

	err := plugin.EmitObserved(context.Background(), record)
	require.NoError(t, err)

	assert.Equal(t, "organizations/123/sources/456", capturedReq.Parent)
	assert.Equal(t, "EUNO_AGENT_INVENTORY", capturedReq.Finding.Category)
	assert.Equal(t, "OBSERVATION", capturedReq.Finding.FindingClass)
	assert.Equal(t, "ACTIVE", capturedReq.Finding.State)
	assert.Equal(t, "scc-agent", capturedReq.Finding.SourceProperties["agentId"])
}

func TestSccPlugin_EmitObserved_AlreadyExists(t *testing.T) {
	var updateCalled bool

	client := &mockSccClient{
		createFinding: func(_ context.Context, _ SccCreateFindingRequest) error {
			return fmt.Errorf("rpc error: code = AlreadyExists desc = already exists")
		},
		updateFinding: func(_ context.Context, _ SccUpdateFindingRequest) error {
			updateCalled = true
			return nil
		},
	}

	plugin := NewSccPlugin(SccPluginConfig{
		SourceName:    "organizations/123/sources/456",
		ProjectID:     "my-project",
		ClientFactory: func() SccClient { return client },
	})

	record := AgentInventoryRecord{
		AgentID:   "scc-agent",
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}

	err := plugin.EmitObserved(context.Background(), record)
	require.NoError(t, err)
	assert.True(t, updateCalled)
}

func TestSccPlugin_EmitRevoked(t *testing.T) {
	var capturedReq SccUpdateFindingRequest

	client := &mockSccClient{
		updateFinding: func(_ context.Context, req SccUpdateFindingRequest) error {
			capturedReq = req
			return nil
		},
	}

	plugin := NewSccPlugin(SccPluginConfig{
		SourceName:    "organizations/123/sources/456",
		ProjectID:     "my-project",
		ClientFactory: func() SccClient { return client },
	})

	err := plugin.EmitRevoked(context.Background(), "scc-agent", time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)

	assert.Equal(t, "INACTIVE", capturedReq.Finding.State)
	assert.Contains(t, capturedReq.FindingName, "organizations/123/sources/456/findings/")
}

func TestStdoutPlugin_EmitObserved(t *testing.T) {
	var buf bytes.Buffer
	plugin := NewStdoutPlugin(&buf)

	record := AgentInventoryRecord{
		AgentID:    "stdout-agent",
		OwningTeam: "dev",
		FirstSeen:  time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		LastSeen:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	err := plugin.EmitObserved(context.Background(), record)
	require.NoError(t, err)

	var output map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &output)
	require.NoError(t, err)
	assert.Equal(t, "observed", output["type"])
}

func TestStdoutPlugin_EmitRevoked(t *testing.T) {
	var buf bytes.Buffer
	plugin := NewStdoutPlugin(&buf)

	err := plugin.EmitRevoked(context.Background(), "stdout-agent", time.Now())
	require.NoError(t, err)

	var output map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &output)
	require.NoError(t, err)
	assert.Equal(t, "revoked", output["type"])
	assert.Equal(t, "stdout-agent", output["agentId"])
}

// --- Helpers Tests ---

func TestSanitizeID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple-id", "simple-id"},
		{"agent@domain.com", "agent-domain-com"},
		{"a/b/c", "a-b-c"},
		{"valid_underscore", "valid_underscore"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, sanitizeID(tt.input))
		})
	}
}

func TestSanitizeFindingID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"short", "short"},
		{"agent@domain.com/path", "agent_domain_com_path"},
		{"a-very-long-identifier-that-exceeds-32", "a_very_long_identifier_that_exce"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeFindingID(tt.input)
			assert.Equal(t, tt.expected, result)
			assert.LessOrEqual(t, len(result), 32)
		})
	}
}

// --- Mock clients ---

type mockDefenderClient struct {
	createOrUpdate func(ctx context.Context, resourceID, assessmentName string, assessment DefenderAssessment) error
	delete         func(ctx context.Context, resourceID, assessmentName string) error
}

func (m *mockDefenderClient) CreateOrUpdateAssessment(ctx context.Context, resourceID, assessmentName string, assessment DefenderAssessment) error {
	if m.createOrUpdate != nil {
		return m.createOrUpdate(ctx, resourceID, assessmentName, assessment)
	}
	return nil
}

func (m *mockDefenderClient) DeleteAssessment(ctx context.Context, resourceID, assessmentName string) error {
	if m.delete != nil {
		return m.delete(ctx, resourceID, assessmentName)
	}
	return nil
}

type mockSecurityHubClient struct {
	batchImport func(ctx context.Context, findings []SecurityHubFinding) error
	batchUpdate func(ctx context.Context, identifiers []FindingIdentifier, update FindingUpdate) error
}

func (m *mockSecurityHubClient) BatchImportFindings(ctx context.Context, findings []SecurityHubFinding) error {
	if m.batchImport != nil {
		return m.batchImport(ctx, findings)
	}
	return nil
}

func (m *mockSecurityHubClient) BatchUpdateFindings(ctx context.Context, identifiers []FindingIdentifier, update FindingUpdate) error {
	if m.batchUpdate != nil {
		return m.batchUpdate(ctx, identifiers, update)
	}
	return nil
}

type mockSccClient struct {
	createFinding func(ctx context.Context, req SccCreateFindingRequest) error
	updateFinding func(ctx context.Context, req SccUpdateFindingRequest) error
}

func (m *mockSccClient) CreateFinding(ctx context.Context, req SccCreateFindingRequest) error {
	if m.createFinding != nil {
		return m.createFinding(ctx, req)
	}
	return nil
}

func (m *mockSccClient) UpdateFinding(ctx context.Context, req SccUpdateFindingRequest) error {
	if m.updateFinding != nil {
		return m.updateFinding(ctx, req)
	}
	return nil
}
