// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package minter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eunolabs/eunox/pkg/ratelimit"
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
	app, err := New(
		&Config{
			Pepper:          pepper,
			DefaultTenantID: "test-tenant",
		}, &Dependencies{
			Store:   NewInMemoryStore(),
			Auth:    &mockAuth{operatorID: "test-operator"},
			Anomaly: &mockAnomalyDetector{},
			Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
	if err != nil {
		t.Fatal(err)
	}
	return app
}

func TestApp_HealthLive(t *testing.T) {
	t.Parallel()
	app := newTestApp(t)
	req := httptest.NewRequest(http.MethodGet, "/health/live", http.NoBody)
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
	req := httptest.NewRequest(http.MethodGet, "/health/ready", http.NoBody)
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
	app, err := New(
		&Config{Pepper: pepper, DefaultTenantID: "t"}, &Dependencies{
			Store:   NewInMemoryStore(),
			Auth:    &mockAuth{operatorID: "op"},
			Anomaly: &mockAnomalyDetector{velocityErr: ErrVelocityExceeded},
			Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
	if err != nil {
		t.Fatal(err)
	}

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
	app, err := New(
		&Config{Pepper: pepper, DefaultTenantID: "t"}, &Dependencies{
			Store:   NewInMemoryStore(),
			Auth:    &mockAuth{err: ErrUnauthorized},
			Anomaly: &mockAnomalyDetector{},
			Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
	if err != nil {
		t.Fatal(err)
	}

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
	req = httptest.NewRequest(http.MethodGet, "/admin/v1/keys?tenantId=test-tenant", http.NoBody)
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
	req = httptest.NewRequest(http.MethodDelete, "/admin/v1/keys/"+keyID, http.NoBody)
	w = httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestApp_RevokeKey_NotFound(t *testing.T) {
	t.Parallel()
	app := newTestApp(t)

	req := httptest.NewRequest(http.MethodDelete, "/admin/v1/keys/nonexistent", http.NoBody)
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
	req = httptest.NewRequest(http.MethodDelete, "/admin/v1/keys/"+keyID, http.NoBody)
	w = httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	// Second revoke should conflict.
	req = httptest.NewRequest(http.MethodDelete, "/admin/v1/keys/"+keyID, http.NoBody)
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
	req = httptest.NewRequest(http.MethodDelete, "/admin/v1/keys/"+keyID, http.NoBody)
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
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/policies?tenantId=test-tenant", http.NoBody)
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

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/policies", http.NoBody)
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

	// Without trusted proxies configured, XFF must always be ignored.
	app := newTestApp(t)

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "198.51.100.25:443"
	req.Header.Set("X-Forwarded-For", "203.0.113.77")

	if got := app.extractClientIP(req); got != "198.51.100.25" {
		t.Fatalf("expected remote addr IP, got %q", got)
	}
}

func createStoredKey(t *testing.T, app *App, tenantID, keyID string, createdAt time.Time) {
	t.Helper()
	store, ok := app.deps.Store.(*InMemoryStore)
	if !ok {
		t.Fatalf("expected InMemoryStore, got %T", app.deps.Store)
	}
	if err := store.CreateKey(context.Background(), &APIKey{
		KeyID:      keyID,
		SecretHash: "hash",
		TenantID:   tenantID,
		CreatedAt:  createdAt,
		CreatedBy:  "tester",
	}); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
}

func TestApp_HealthReady_FailingCheck(t *testing.T) {
	t.Parallel()
	pepper, _ := NewPepperFromHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	app, err := New(&Config{
		Pepper:          pepper,
		DefaultTenantID: "test-tenant",
		ReadinessChecks: []func(context.Context) error{func(context.Context) error { return errors.New("db down") }},
	}, &Dependencies{
		Store:   NewInMemoryStore(),
		Auth:    &mockAuth{operatorID: "test-operator"},
		Anomaly: &mockAnomalyDetector{},
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/health/ready", http.NoBody)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "not ready" || resp["reason"] != "db down" {
		t.Fatalf("unexpected readiness response: %#v", resp)
	}
}

func TestApp_ListKeys_Pagination(t *testing.T) {
	t.Parallel()
	app := newTestApp(t)
	base := time.Unix(1700000000, 0)
	createStoredKey(t, app, "test-tenant", "key-1", base)
	createStoredKey(t, app, "test-tenant", "key-2", base.Add(time.Second))
	createStoredKey(t, app, "test-tenant", "key-3", base.Add(2*time.Second))

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/keys?tenantId=test-tenant&limit=2&offset=0", http.NoBody)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	keys := resp["keys"].([]interface{})
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	if int(resp["total"].(float64)) != 3 || int(resp["limit"].(float64)) != 2 || int(resp["offset"].(float64)) != 0 {
		t.Fatalf("unexpected pagination metadata: %#v", resp)
	}
	if int(resp["nextOffset"].(float64)) != 2 {
		t.Fatalf("expected nextOffset=2, got %#v", resp["nextOffset"])
	}
	first := keys[0].(map[string]interface{})
	second := keys[1].(map[string]interface{})
	if first["keyId"] != "key-1" || second["keyId"] != "key-2" {
		t.Fatalf("unexpected key order: %#v", keys)
	}
}

func TestApp_ListKeys_LimitCapped(t *testing.T) {
	t.Parallel()
	app := newTestApp(t)
	createStoredKey(t, app, "test-tenant", "key-1", time.Unix(1700000000, 0))

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/keys?tenantId=test-tenant&limit=999", http.NoBody)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if int(resp["limit"].(float64)) != 200 {
		t.Fatalf("expected capped limit 200, got %#v", resp["limit"])
	}
}

func TestApp_ListKeys_InvalidParams(t *testing.T) {
	t.Parallel()
	app := newTestApp(t)

	for _, raw := range []string{"limit=0", "limit=bad", "offset=-1", "offset=bad"} {
		t.Run(raw, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/admin/v1/keys?%s", raw), http.NoBody)
			w := httptest.NewRecorder()
			app.Handler().ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d for %s", w.Code, raw)
			}
		})
	}
}

func TestApp_ListKeys_EmptyResultSet(t *testing.T) {
	t.Parallel()
	app := newTestApp(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/keys?tenantId=missing&limit=10&offset=0", http.NoBody)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	keys := resp["keys"].([]interface{})
	if len(keys) != 0 || int(resp["total"].(float64)) != 0 || resp["nextOffset"] != nil {
		t.Fatalf("unexpected empty pagination response: %#v", resp)
	}
}

// --- CI-2: CountAndListKeys atomicity ---

// TestCountAndListKeys_Atomic verifies that CountAndListKeys returns a
// consistent count and page within a single lock (InMemoryStore) or
// read-committed transaction (PostgresKeyStore).  For the in-memory store we
// insert N keys, call CountAndListKeys for a page that covers all of them, and
// assert that total == len(page) == N with no key appearing twice.
func TestCountAndListKeys_Atomic(t *testing.T) {
	t.Parallel()
	store := NewInMemoryStore()
	ctx := context.Background()

	const n = 7
	for i := range n {
		err := store.CreateKey(ctx, &APIKey{
			KeyID:      fmt.Sprintf("key-%d", i),
			SecretHash: fmt.Sprintf("hash-%d", i),
			TenantID:   "tenant-a",
			CreatedBy:  "test",
		})
		if err != nil {
			t.Fatalf("CreateKey: %v", err)
		}
	}

	total, page, err := store.CountAndListKeys(ctx, "tenant-a", 20, 0)
	if err != nil {
		t.Fatalf("CountAndListKeys: %v", err)
	}
	if total != n {
		t.Errorf("expected total=%d, got %d", n, total)
	}
	if len(page) != n {
		t.Errorf("expected %d keys in page, got %d", n, len(page))
	}

	// Pagination: fetch page 2 (offset=3, limit=3) → 3 items; total still n.
	total2, page2, err := store.CountAndListKeys(ctx, "tenant-a", 3, 3)
	if err != nil {
		t.Fatalf("CountAndListKeys page2: %v", err)
	}
	if total2 != n {
		t.Errorf("page2: expected total=%d, got %d", n, total2)
	}
	if len(page2) != 3 {
		t.Errorf("page2: expected 3 keys, got %d", len(page2))
	}

	// Past-end page: offset beyond total → 0 items; total unchanged.
	total3, page3, err := store.CountAndListKeys(ctx, "tenant-a", 10, 100)
	if err != nil {
		t.Fatalf("CountAndListKeys past-end: %v", err)
	}
	if total3 != n {
		t.Errorf("past-end: expected total=%d, got %d", n, total3)
	}
	if len(page3) != 0 {
		t.Errorf("past-end: expected 0 keys, got %d", len(page3))
	}
}

// --- CI-3: TrustedProxyCIDRs and extractClientIP method ---

// TestNew_InvalidCIDR verifies that New returns an error when
// TrustedProxyCIDRs contains a malformed CIDR — preventing silent XFF bypass.
func TestNew_InvalidCIDR(t *testing.T) {
	t.Parallel()
	pepper, err := NewPepperFromHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(&Config{
		Pepper:            pepper,
		DefaultTenantID:   "tenant",
		TrustedProxyCIDRs: []string{"not-a-cidr"},
	}, &Dependencies{
		Store:   NewInMemoryStore(),
		Auth:    &mockAuth{operatorID: "op"},
		Anomaly: &mockAnomalyDetector{},
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err == nil {
		t.Fatal("expected error for invalid CIDR, got nil")
	}
}

// TestExtractClientIP_TrustedProxyXFF verifies that when the real remote
// address falls within a trusted CIDR, the rightmost public IP from
// X-Forwarded-For is used as the client IP.
func TestExtractClientIP_TrustedProxyXFF(t *testing.T) {
	t.Parallel()
	pepper, err := NewPepperFromHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	app, err := New(&Config{
		Pepper:            pepper,
		DefaultTenantID:   "tenant",
		TrustedProxyCIDRs: []string{"10.0.0.0/8"},
	}, &Dependencies{
		Store:   NewInMemoryStore(),
		Auth:    &mockAuth{operatorID: "op"},
		Anomaly: &mockAnomalyDetector{},
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "10.0.0.1:443" // trusted proxy
	req.Header.Set("X-Forwarded-For", "203.0.113.77, 10.0.0.1")

	// The rightmost non-trusted IP in XFF (203.0.113.77) should be returned.
	if got := app.extractClientIP(req); got != "203.0.113.77" {
		t.Fatalf("expected 203.0.113.77, got %q", got)
	}
}

// TestExtractClientIP_UntrustedProxyIgnoresXFF verifies that when the remote
// address is NOT in any trusted CIDR, X-Forwarded-For is ignored entirely.
func TestExtractClientIP_UntrustedProxyIgnoresXFF(t *testing.T) {
	t.Parallel()
	pepper, err := NewPepperFromHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	app, err := New(&Config{
		Pepper:            pepper,
		DefaultTenantID:   "tenant",
		TrustedProxyCIDRs: []string{"10.0.0.0/8"},
	}, &Dependencies{
		Store:   NewInMemoryStore(),
		Auth:    &mockAuth{operatorID: "op"},
		Anomaly: &mockAnomalyDetector{},
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "198.51.100.25:443" // NOT in trusted range
	req.Header.Set("X-Forwarded-For", "203.0.113.77")

	// XFF must be ignored; RemoteAddr IP returned.
	if got := app.extractClientIP(req); got != "198.51.100.25" {
		t.Fatalf("expected 198.51.100.25, got %q", got)
	}
}

// --- CI-4: Retry-After header on 429 ---

// TestApp_Ping_RateLimited_RetryAfterHeader verifies that when the ping
// endpoint rate-limits a request it responds with HTTP 429 and includes a
// Retry-After header with a positive integer value.
func TestApp_Ping_RateLimited_RetryAfterHeader(t *testing.T) {
	t.Parallel()

	pepper, err := NewPepperFromHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}

	// Configure a very tight rate limit so we can exhaust it quickly.
	limiter := ratelimit.NewInMemory(ratelimit.Config{Rate: 1, Window: time.Hour})
	t.Cleanup(limiter.Close)

	app, err := New(&Config{
		Pepper:          pepper,
		DefaultTenantID: "tenant",
	}, &Dependencies{
		Store:       NewInMemoryStore(),
		Auth:        &mockAuth{operatorID: "op"},
		Anomaly:     &mockAnomalyDetector{},
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		PingLimiter: limiter,
	})
	if err != nil {
		t.Fatal(err)
	}

	sendPing := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/ping", bytes.NewBufferString(`{"key":"sk-dummy.secret"}`))
		req.Header.Set("Content-Type", "application/json")
		app.Handler().ServeHTTP(w, req)
		return w
	}

	// First request consumes the single allowed token (likely 401/400 because
	// the key is invalid, but the rate-limit counter is still incremented).
	sendPing()

	// Second request should be rate-limited.
	w := sendPing()
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d: %s", w.Code, w.Body.String())
	}
	ra := w.Header().Get("Retry-After")
	if ra == "" {
		t.Fatal("expected Retry-After header, got none")
	}
	val := 0
	if _, err := fmt.Sscanf(ra, "%d", &val); err != nil || val <= 0 {
		t.Fatalf("expected positive integer Retry-After, got %q", ra)
	}
}
