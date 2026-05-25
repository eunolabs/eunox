// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package minter

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockAuth implements AdminAuthenticator for tests.
type mockAuth struct {
	operatorID string
	err        error
}

func (m *mockAuth) Authenticate(_ context.Context, _ *http.Request) (string, error) {
	return m.operatorID, m.err
}

// mockAnomalyDetector implements AnomalyDetector for tests.
type mockAnomalyDetector struct {
	velocityErr error
}

// RecordMint implements AnomalyDetector.
func (m *mockAnomalyDetector) RecordMint(_ context.Context, _ string) error { return nil }

// CheckVelocity implements AnomalyDetector.
func (m *mockAnomalyDetector) CheckVelocity(_ context.Context, _ string) error {
	return m.velocityErr
}

func newTestApp(t *testing.T) *App {
	t.Helper()
	pepper, err := NewPepperFromHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	return New(
		Config{
			Pepper:          pepper,
			DefaultTenantID: "test-tenant",
		},
		Dependencies{
			Store:   NewInMemoryStore(),
			Auth:    &mockAuth{operatorID: "test-operator"},
			Anomaly: &mockAnomalyDetector{},
			Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
	)
}

func TestApp_HealthLive(t *testing.T) {
	t.Parallel()
	app := newTestApp(t)
	req := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status=ok, got %q", resp["status"])
	}
}

func TestApp_HealthReady(t *testing.T) {
	t.Parallel()
	app := newTestApp(t)
	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestApp_CreateKey(t *testing.T) {
	t.Parallel()
	app := newTestApp(t)

	body := `{"description": "test key", "expiresInSeconds": 3600}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["keyId"] == nil || resp["keyId"] == "" {
		t.Error("expected keyId in response")
	}
	if resp["key"] == nil || resp["key"] == "" {
		t.Error("expected key in response")
	}
	if resp["tenantId"] != "test-tenant" {
		t.Errorf("expected tenantId=test-tenant, got %v", resp["tenantId"])
	}
}

func TestApp_CreateKey_CustomTenant(t *testing.T) {
	t.Parallel()
	app := newTestApp(t)

	body := `{"tenantId": "custom-tenant", "description": "custom"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["tenantId"] != "custom-tenant" {
		t.Errorf("expected tenantId=custom-tenant, got %v", resp["tenantId"])
	}
}

func TestApp_CreateKey_VelocityExceeded(t *testing.T) {
	t.Parallel()
	pepper, _ := NewPepperFromHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	app := New(
		Config{Pepper: pepper, DefaultTenantID: "t"},
		Dependencies{
			Store:   NewInMemoryStore(),
			Auth:    &mockAuth{operatorID: "op"},
			Anomaly: &mockAnomalyDetector{velocityErr: ErrVelocityExceeded},
			Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
	)

	body := `{"description": "test"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}
}

func TestApp_CreateKey_Unauthorized(t *testing.T) {
	t.Parallel()
	pepper, _ := NewPepperFromHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	app := New(
		Config{Pepper: pepper, DefaultTenantID: "t"},
		Dependencies{
			Store:   NewInMemoryStore(),
			Auth:    &mockAuth{err: ErrUnauthorized},
			Anomaly: &mockAnomalyDetector{},
			Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
	)

	body := `{"description": "test"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestApp_ListKeys(t *testing.T) {
	t.Parallel()
	app := newTestApp(t)

	// Create a key first.
	body := `{"description": "list-test"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create failed: %d", w.Code)
	}

	// List.
	req = httptest.NewRequest(http.MethodGet, "/admin/v1/keys?tenantId=test-tenant", nil)
	w = httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	keys, ok := resp["keys"].([]interface{})
	if !ok || len(keys) == 0 {
		t.Error("expected at least one key in list")
	}
}

func TestApp_RevokeKey(t *testing.T) {
	t.Parallel()
	app := newTestApp(t)

	// Create a key first.
	body := `{"description": "revoke-test"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	var createResp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &createResp)
	keyID := createResp["keyId"].(string)

	// Revoke.
	req = httptest.NewRequest(http.MethodDelete, "/admin/v1/keys/"+keyID, nil)
	w = httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestApp_RevokeKey_NotFound(t *testing.T) {
	t.Parallel()
	app := newTestApp(t)

	req := httptest.NewRequest(http.MethodDelete, "/admin/v1/keys/nonexistent", nil)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestApp_RevokeKey_AlreadyRevoked(t *testing.T) {
	t.Parallel()
	app := newTestApp(t)

	// Create and revoke.
	body := `{"description": "double-revoke"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	keyID := resp["keyId"].(string)

	// First revoke.
	req = httptest.NewRequest(http.MethodDelete, "/admin/v1/keys/"+keyID, nil)
	w = httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	// Second revoke should conflict.
	req = httptest.NewRequest(http.MethodDelete, "/admin/v1/keys/"+keyID, nil)
	w = httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", w.Code)
	}
}

func TestApp_Ping_Valid(t *testing.T) {
	t.Parallel()
	app := newTestApp(t)

	// Create a key first.
	body := `{"description": "ping-test"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	var createResp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &createResp)
	fullKey := createResp["key"].(string)

	// Ping.
	pingBody := `{"key":"` + fullKey + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/ping", bytes.NewBufferString(pingBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var pingResp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &pingResp)
	if pingResp["valid"] != true {
		t.Error("expected valid=true")
	}
}

func TestApp_Ping_InvalidKey(t *testing.T) {
	t.Parallel()
	app := newTestApp(t)

	body := `{"key":"not-a-valid-key"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ping", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestApp_Ping_KeyNotFound(t *testing.T) {
	t.Parallel()
	app := newTestApp(t)

	body := `{"key":"sk-nonexistent.secret"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ping", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestApp_Ping_RevokedKey(t *testing.T) {
	t.Parallel()
	app := newTestApp(t)

	// Create and revoke.
	body := `{"description": "revoke-ping"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	var createResp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &createResp)
	fullKey := createResp["key"].(string)
	keyID := createResp["keyId"].(string)

	// Revoke.
	req = httptest.NewRequest(http.MethodDelete, "/admin/v1/keys/"+keyID, nil)
	w = httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	// Ping revoked key.
	pingBody := `{"key":"` + fullKey + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/ping", bytes.NewBufferString(pingBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestApp_CreatePolicy(t *testing.T) {
	t.Parallel()
	app := newTestApp(t)

	body := `{"name":"default","description":"test policy","rules":{"allowedTools":["tool-a"],"maxCallsPerMinute":60}}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/policies", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["policyId"] == nil || resp["policyId"] == "" {
		t.Error("expected policyId in response")
	}
	if resp["name"] != "default" {
		t.Errorf("expected name=default, got %v", resp["name"])
	}
}

func TestApp_CreatePolicy_MissingName(t *testing.T) {
	t.Parallel()
	app := newTestApp(t)

	body := `{"description":"no name"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/policies", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestApp_CreatePolicy_DuplicateName(t *testing.T) {
	t.Parallel()
	app := newTestApp(t)

	body := `{"name":"dup-policy","description":"first"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/policies", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("first create failed: %d", w.Code)
	}

	// Duplicate.
	req = httptest.NewRequest(http.MethodPost, "/admin/v1/policies", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", w.Code)
	}
}

func TestApp_ListPolicies(t *testing.T) {
	t.Parallel()
	app := newTestApp(t)

	// Create policies.
	for _, name := range []string{"pol-a", "pol-b"} {
		body := `{"name":"` + name + `"}`
		req := httptest.NewRequest(http.MethodPost, "/admin/v1/policies", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		app.Handler().ServeHTTP(w, req)
	}

	// List.
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/policies?tenantId=test-tenant", nil)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	policies := resp["policies"].([]interface{})
	if len(policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(policies))
	}
}

func TestApp_ListPolicies_Empty(t *testing.T) {
	t.Parallel()
	app := newTestApp(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/policies", nil)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	policies := resp["policies"].([]interface{})
	if len(policies) != 0 {
		t.Fatalf("expected 0 policies, got %d", len(policies))
	}
}

func TestExtractClientIP_IgnoresForwardedHeaders(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.25:443"
	req.Header.Set("X-Forwarded-For", "203.0.113.77")

	if got := extractClientIP(req); got != "198.51.100.25" {
		t.Fatalf("expected remote addr IP, got %q", got)
	}
}
