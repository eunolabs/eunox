// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package dbtokensvc

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── InMemoryTaskCredentialStore unit tests ───────────────────────────────────

func TestInMemoryTaskCredentialStore_RegisterAndList(t *testing.T) {
	t.Parallel()
	store := NewInMemoryTaskCredentialStore()
	ctx := context.Background()

	record := &TaskCredentialRecord{
		CredentialID: "cred-1",
		TaskID:       "task-abc",
		UserID:       "user-1",
		TenantID:     "tenant-1",
		Database:     "mydb",
		Adapter:      "aws-rds",
		IssuedAt:     time.Now(),
		ExpiresAt:    time.Now().Add(15 * time.Minute),
	}

	if err := store.Register(ctx, record); err != nil {
		t.Fatalf("Register: %v", err)
	}

	records, err := store.ListByTask(ctx, "task-abc")
	if err != nil {
		t.Fatalf("ListByTask: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].CredentialID != "cred-1" {
		t.Errorf("expected CredentialID=cred-1, got %q", records[0].CredentialID)
	}
}

func TestInMemoryTaskCredentialStore_ListByTask_ReturnsNilForUnknown(t *testing.T) {
	t.Parallel()
	store := NewInMemoryTaskCredentialStore()
	records, err := store.ListByTask(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("ListByTask: %v", err)
	}
	if records != nil {
		t.Errorf("expected nil for unknown task, got %v", records)
	}
}

func TestInMemoryTaskCredentialStore_ListByTask_ReturnsCopy(t *testing.T) {
	t.Parallel()
	store := NewInMemoryTaskCredentialStore()
	ctx := context.Background()

	rec := &TaskCredentialRecord{CredentialID: "cred-1", TaskID: "task-1"}
	_ = store.Register(ctx, rec)

	first, _ := store.ListByTask(ctx, "task-1")
	first[0].CredentialID = "mutated"

	second, _ := store.ListByTask(ctx, "task-1")
	if second[0].CredentialID != "cred-1" {
		t.Errorf("ListByTask returned a live slice; mutation affected internal state")
	}
}

func TestInMemoryTaskCredentialStore_Revoke(t *testing.T) {
	t.Parallel()
	store := NewInMemoryTaskCredentialStore()
	ctx := context.Background()

	for i := range 3 {
		_ = store.Register(ctx, &TaskCredentialRecord{
			CredentialID: "cred-" + string(rune('0'+i)),
			TaskID:       "task-xyz",
		})
	}

	count, err := store.Revoke(ctx, "task-xyz")
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if count != 3 {
		t.Errorf("expected count=3, got %d", count)
	}

	revoked, err := store.IsRevoked(ctx, "task-xyz")
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Error("expected task to be revoked")
	}
}

func TestInMemoryTaskCredentialStore_RevokeUnknown(t *testing.T) {
	t.Parallel()
	store := NewInMemoryTaskCredentialStore()

	count, err := store.Revoke(context.Background(), "unknown-task")
	if err != nil {
		t.Fatalf("Revoke on unknown task should not error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected count=0 for unknown task, got %d", count)
	}
}

func TestInMemoryTaskCredentialStore_IsRevoked_False(t *testing.T) {
	t.Parallel()
	store := NewInMemoryTaskCredentialStore()

	revoked, err := store.IsRevoked(context.Background(), "never-revoked")
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if revoked {
		t.Error("expected false for never-revoked task")
	}
}

func TestInMemoryTaskCredentialStore_MultipleTasksIsolated(t *testing.T) {
	t.Parallel()
	store := NewInMemoryTaskCredentialStore()
	ctx := context.Background()

	_ = store.Register(ctx, &TaskCredentialRecord{CredentialID: "cred-a", TaskID: "task-A"})
	_ = store.Register(ctx, &TaskCredentialRecord{CredentialID: "cred-b", TaskID: "task-B"})

	_, _ = store.Revoke(ctx, "task-A")

	revokedA, _ := store.IsRevoked(ctx, "task-A")
	revokedB, _ := store.IsRevoked(ctx, "task-B")

	if !revokedA {
		t.Error("task-A should be revoked")
	}
	if revokedB {
		t.Error("task-B should not be revoked")
	}
}

// ── HTTP handler tests ───────────────────────────────────────────────────────

// newTestAppWithStore builds an App wired with the given TaskStore.
func newTestAppWithStore(t *testing.T, store TaskCredentialStore) *App {
	t.Helper()
	verifier := &mockVerifier{
		claims: &TokenClaims{
			Subject:     "user-1",
			TenantID:    "tenant-1",
			DBResources: []string{"db://host/mydb"},
		},
	}
	adapter := &mockDBAdapter{
		cred: &DBCredential{
			Username:  "app_user",
			Token:     "iam-token-123",
			Host:      "mydb.rds.amazonaws.com",
			Port:      5432,
			Database:  "mydb",
			ExpiresAt: time.Now().Add(15 * time.Minute),
			Adapter:   "mock-db",
		},
	}
	app, err := New(
		Config{
			DefaultTTL: 15 * time.Minute,
			MaxTTL:     60 * time.Minute,
			Adapter:    "mock",
		},
		Dependencies{
			Adapter:  adapter,
			Verifier: verifier,
			Mapping: &CapabilityMapping{
				ResourceToUsername: map[string]string{
					"db://host/mydb": "app_user",
				},
			},
			Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
			TaskStore: store,
		},
	)
	if err != nil {
		t.Fatalf("newTestAppWithStore: %v", err)
	}
	return app
}

func TestMintDBToken_WithTaskID_RegistersCredential(t *testing.T) {
	t.Parallel()
	store := NewInMemoryTaskCredentialStore()
	app := newTestAppWithStore(t, store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/db-tokens", http.NoBody)
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("X-Eunox-Task-Id", "task-001")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp DBCredential
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.CredentialID == "" {
		t.Error("expected CredentialID to be set")
	}
	if resp.TaskID != "task-001" {
		t.Errorf("expected TaskID=task-001, got %q", resp.TaskID)
	}

	records, err := store.ListByTask(context.Background(), "task-001")
	if err != nil {
		t.Fatalf("ListByTask: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record in store, got %d", len(records))
	}
	if records[0].CredentialID != resp.CredentialID {
		t.Errorf("credential ID mismatch: store=%q, response=%q", records[0].CredentialID, resp.CredentialID)
	}
}

func TestMintDBToken_WithRevokedTask_ReturnsForbidden(t *testing.T) {
	t.Parallel()
	store := NewInMemoryTaskCredentialStore()
	_, _ = store.Revoke(context.Background(), "task-revoked")

	app := newTestAppWithStore(t, store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/db-tokens", http.NoBody)
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("X-Eunox-Task-Id", "task-revoked")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for revoked task, got %d: %s", w.Code, w.Body.String())
	}
	var body map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "task_revoked" {
		t.Errorf("expected error=task_revoked, got %q", body["error"])
	}
}

func TestMintDBToken_WithInvalidTaskID_ReturnsBadRequest(t *testing.T) {
	t.Parallel()
	app := newTestAppWithStore(t, NewInMemoryTaskCredentialStore())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/db-tokens", http.NoBody)
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("X-Eunox-Task-Id", strings.Repeat("x", 129)) // too long
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid task ID, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleTaskRevoke_Complete(t *testing.T) {
	t.Parallel()
	store := NewInMemoryTaskCredentialStore()
	ctx := context.Background()
	_ = store.Register(ctx, &TaskCredentialRecord{CredentialID: "cred-1", TaskID: "task-finish"})
	_ = store.Register(ctx, &TaskCredentialRecord{CredentialID: "cred-2", TaskID: "task-finish"})

	app := newTestAppWithStore(t, store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tasks/task-finish/complete", http.NoBody)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp taskRevokeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.TaskID != "task-finish" {
		t.Errorf("expected TaskID=task-finish, got %q", resp.TaskID)
	}
	if resp.RevokedCount != 2 {
		t.Errorf("expected RevokedCount=2, got %d", resp.RevokedCount)
	}
	if resp.AlreadyRevoked {
		t.Error("expected AlreadyRevoked=false on first revocation")
	}

	// Verify task is now revoked.
	revoked, _ := store.IsRevoked(ctx, "task-finish")
	if !revoked {
		t.Error("task should be revoked after /complete")
	}
}

func TestHandleTaskRevoke_Fail(t *testing.T) {
	t.Parallel()
	store := NewInMemoryTaskCredentialStore()
	app := newTestAppWithStore(t, store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tasks/task-failed/fail", http.NoBody)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	revoked, _ := store.IsRevoked(context.Background(), "task-failed")
	if !revoked {
		t.Error("task should be revoked after /fail")
	}
}

func TestHandleTaskRevoke_AlreadyRevoked(t *testing.T) {
	t.Parallel()
	store := NewInMemoryTaskCredentialStore()
	ctx := context.Background()
	_, _ = store.Revoke(ctx, "task-done")

	app := newTestAppWithStore(t, store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tasks/task-done/complete", http.NoBody)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp taskRevokeResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.AlreadyRevoked {
		t.Error("expected AlreadyRevoked=true on second revocation")
	}
}

func TestHandleTaskRevoke_NoStore_ReturnsOK(t *testing.T) {
	t.Parallel()
	// App with no TaskStore configured.
	app := newTestDBTokenApp(t, &mockVerifier{}, &mockDBAdapter{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tasks/task-x/complete", http.NoBody)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 when no store, got %d: %s", w.Code, w.Body.String())
	}
}
