// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package ocsf

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAuthorizationEvent(t *testing.T) {
	t.Parallel()

	actor := Actor{
		UserID:   "user-123",
		UserName: "alice",
		TenantID: "tenant-1",
	}

	event := NewAuthorizationEvent(ActivityAuthGrant, &actor)

	if event.ClassUID != ClassAuthorization {
		t.Errorf("expected class_uid=%d, got %d", ClassAuthorization, event.ClassUID)
	}
	if event.ActivityID != ActivityAuthGrant {
		t.Errorf("expected activity_id=%d, got %d", ActivityAuthGrant, event.ActivityID)
	}
	if event.CategoryUID != 3 {
		t.Errorf("expected category_uid=3, got %d", event.CategoryUID)
	}
	if event.TypeUID != 300301 {
		t.Errorf("expected type_uid=300301, got %d", event.TypeUID)
	}
	if event.SchemaVersion != SchemaVersion {
		t.Errorf("expected schema_version=%q, got %q", SchemaVersion, event.SchemaVersion)
	}
	if event.Actor.UserID != "user-123" {
		t.Errorf("expected actor user_id=user-123, got %q", event.Actor.UserID)
	}
	if event.Time.IsZero() {
		t.Error("expected non-zero time")
	}
	if time.Since(event.Time) > 5*time.Second {
		t.Error("event time should be recent")
	}
}

func TestNewAuthorizationEvent_Deny(t *testing.T) {
	t.Parallel()

	actor := Actor{UserID: "user-456", TenantID: "tenant-2"}
	event := NewAuthorizationEvent(ActivityAuthDeny, &actor).
		WithStatus(StatusFailure, "denied").
		WithSeverity(SeverityMedium, "Medium").
		WithSOC2Controls(SOC2CC61, SOC2CC63)

	if event.StatusID != StatusFailure {
		t.Errorf("expected status_id=%d, got %d", StatusFailure, event.StatusID)
	}
	if event.Status != "denied" {
		t.Errorf("expected status=denied, got %q", event.Status)
	}
	if event.SeverityID != SeverityMedium {
		t.Errorf("expected severity_id=%d, got %d", SeverityMedium, event.SeverityID)
	}
	if len(event.SOC2Controls) != 2 {
		t.Fatalf("expected 2 SOC2 controls, got %d", len(event.SOC2Controls))
	}
	if event.SOC2Controls[0].ControlID != "CC6.1" {
		t.Errorf("expected SOC2 control CC6.1, got %q", event.SOC2Controls[0].ControlID)
	}
}

func TestNewAuthorizationEvent_Revoke(t *testing.T) {
	t.Parallel()

	actor := Actor{UserID: "admin-1", TenantID: "tenant-1"}
	event := NewAuthorizationEvent(ActivityAuthRevoke, &actor)
	event.TokenID = "jti-abc123"
	event.OperatorID = "operator-1"
	event.Decision = "revoked"

	if event.ActivityID != ActivityAuthRevoke {
		t.Errorf("expected activity_id=%d, got %d", ActivityAuthRevoke, event.ActivityID)
	}
	if event.TokenID != "jti-abc123" {
		t.Errorf("expected token_id=jti-abc123, got %q", event.TokenID)
	}
	if event.OperatorID != "operator-1" {
		t.Errorf("expected operator_id=operator-1, got %q", event.OperatorID)
	}
}

func TestNewAuthorizationEvent_CrossOrg(t *testing.T) {
	t.Parallel()

	actor := Actor{UserID: "partner-user", TenantID: "partner-org"}
	event := NewAuthorizationEvent(ActivityAuthGrant, &actor)
	event.CrossOrg = true
	event.PartnerDID = "did:web:partner.example.com"

	if !event.CrossOrg {
		t.Error("expected cross_org=true")
	}
	if event.PartnerDID != "did:web:partner.example.com" {
		t.Errorf("expected partner_did, got %q", event.PartnerDID)
	}
}

func TestNewAPIActivityEvent(t *testing.T) {
	t.Parallel()

	actor := Actor{
		UserID:    "user-789",
		TenantID:  "tenant-1",
		SessionID: "sess-abc",
		AgentID:   "agent-1",
	}

	event := NewAPIActivityEvent(ActivityAPICall, &actor)

	if event.ClassUID != ClassAPIActivity {
		t.Errorf("expected class_uid=%d, got %d", ClassAPIActivity, event.ClassUID)
	}
	if event.ActivityID != ActivityAPICall {
		t.Errorf("expected activity_id=%d, got %d", ActivityAPICall, event.ActivityID)
	}
	if event.CategoryUID != 6 {
		t.Errorf("expected category_uid=6, got %d", event.CategoryUID)
	}
	if event.TypeUID != 600301 {
		t.Errorf("expected type_uid=600301, got %d", event.TypeUID)
	}
	if event.Actor.SessionID != "sess-abc" {
		t.Errorf("expected session_id=sess-abc, got %q", event.Actor.SessionID)
	}
}

func TestAPIActivityEvent_ToolCall(t *testing.T) {
	t.Parallel()

	actor := Actor{UserID: "user-1", TenantID: "tenant-1"}
	event := NewAPIActivityEvent(ActivityAPIAllow, &actor).
		WithStatus(StatusSuccess, "allowed").
		WithSeverity(SeverityInformational, "Informational").
		WithSOC2Controls(SOC2CC72)

	event.ToolName = "code-search"
	event.ToolAction = "search"
	event.HTTPMethod = "POST"
	event.HTTPURL = "/api/v1/enforce"
	event.HTTPStatus = 200
	event.Duration = 42

	if event.ToolName != "code-search" {
		t.Errorf("expected tool_name=code-search, got %q", event.ToolName)
	}
	if event.Duration != 42 {
		t.Errorf("expected duration=42, got %d", event.Duration)
	}
	if event.StatusID != StatusSuccess {
		t.Errorf("expected status_id=%d, got %d", StatusSuccess, event.StatusID)
	}
	if len(event.SOC2Controls) != 1 {
		t.Fatalf("expected 1 SOC2 control, got %d", len(event.SOC2Controls))
	}
}

func TestAPIActivityEvent_Deny(t *testing.T) {
	t.Parallel()

	actor := Actor{UserID: "user-1", TenantID: "tenant-1"}
	event := NewAPIActivityEvent(ActivityAPIDeny, &actor).
		WithStatus(StatusFailure, "denied").
		WithSeverity(SeverityHigh, "High")

	event.ToolName = "file-write"
	event.ToolAction = "write"
	event.RequestID = "req-xyz"

	if event.StatusID != StatusFailure {
		t.Errorf("expected status_id=%d, got %d", StatusFailure, event.StatusID)
	}
	if event.SeverityID != SeverityHigh {
		t.Errorf("expected severity_id=%d, got %d", SeverityHigh, event.SeverityID)
	}
	if event.RequestID != "req-xyz" {
		t.Errorf("expected request_id=req-xyz, got %q", event.RequestID)
	}
}

func TestSOC2Controls(t *testing.T) {
	t.Parallel()

	controls := []SOC2Control{SOC2CC61, SOC2CC62, SOC2CC63, SOC2CC72, SOC2CC81}
	expectedIDs := []string{"CC6.1", "CC6.2", "CC6.3", "CC7.2", "CC8.1"}

	for i, ctrl := range controls {
		if ctrl.ControlID != expectedIDs[i] {
			t.Errorf("control %d: expected ID=%q, got %q", i, expectedIDs[i], ctrl.ControlID)
		}
		if ctrl.Category == "" {
			t.Errorf("control %d: expected non-empty category", i)
		}
		if ctrl.Description == "" {
			t.Errorf("control %d: expected non-empty description", i)
		}
	}
}

func TestActivityIDs(t *testing.T) {
	t.Parallel()

	// Verify authorization activity IDs are distinct.
	authIDs := []ActivityID{
		ActivityAuthGrant, ActivityAuthDeny, ActivityAuthRevoke,
		ActivityAuthAttenuate, ActivityAuthRenew, ActivityAuthOther,
	}
	seen := make(map[ActivityID]bool)
	for _, id := range authIDs {
		if seen[id] {
			t.Errorf("duplicate authorization activity ID: %d", id)
		}
		seen[id] = true
	}

	// Verify API activity IDs are distinct.
	apiIDs := []ActivityID{
		ActivityAPICall, ActivityAPIAllow, ActivityAPIDeny,
		ActivityAPIValidate, ActivityAPIOther,
	}
	seen = make(map[ActivityID]bool)
	for _, id := range apiIDs {
		if seen[id] {
			t.Errorf("duplicate API activity ID: %d", id)
		}
		seen[id] = true
	}
}

func TestAuthorizationEvent_MarshalJSON_UsesNestedObjects(t *testing.T) {
	t.Parallel()

	event := NewAuthorizationEvent(ActivityAuthGrant, &Actor{
		UserID:    "user-123",
		UserName:  "alice",
		TenantID:  "tenant-1",
		SessionID: "sess-1",
		AgentID:   "agent-1",
	}).WithSOC2Controls(SOC2CC61)
	event.TokenID = "token-1"

	data, err := json.Marshal(event)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(data, &decoded))
	metadata := decoded["metadata"].(map[string]any)
	assert.Equal(t, SchemaVersion, metadata["version"])

	actor := decoded["actor"].(map[string]any)
	user := actor["user"].(map[string]any)
	assert.Equal(t, "user-123", user["uid"])
	org := user["org"].(map[string]any)
	assert.Equal(t, "tenant-1", org["uid"])
	session := actor["session"].(map[string]any)
	assert.Equal(t, "sess-1", session["uid"])

	unmapped := decoded["unmapped"].(map[string]any)
	assert.Equal(t, "token-1", unmapped["token_id"])
}

func TestAPIActivityEvent_MarshalJSON_UsesNestedObjects(t *testing.T) {
	t.Parallel()

	event := NewAPIActivityEvent(ActivityAPIAllow, &Actor{UserID: "user-1", TenantID: "tenant-1"})
	event.APIOperation = "enforce"
	event.APIService = "gateway"
	event.APIVersion = "v1"
	event.HTTPMethod = "POST"
	event.HTTPURL = "/api/v1/enforce"
	event.HTTPStatus = 200
	event.SrcIP = "10.0.0.1"
	event.SrcPort = 443
	event.ToolName = "code-search"

	data, err := json.Marshal(event)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(data, &decoded))
	api := decoded["api"].(map[string]any)
	assert.Equal(t, "enforce", api["operation"])
	assert.Equal(t, "v1", api["version"])
	service := api["service"].(map[string]any)
	assert.Equal(t, "gateway", service["name"])

	httpRequest := decoded["http_request"].(map[string]any)
	assert.Equal(t, "POST", httpRequest["http_method"])
	url := httpRequest["url"].(map[string]any)
	assert.Equal(t, "/api/v1/enforce", url["path"])

	src := decoded["src_endpoint"].(map[string]any)
	assert.Equal(t, "10.0.0.1", src["ip"])
	assert.Equal(t, float64(443), src["port"])

	unmapped := decoded["unmapped"].(map[string]any)
	assert.Equal(t, "code-search", unmapped["tool_name"])
}
