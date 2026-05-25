// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package storagegrantsvc

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// mockVerifier implements TokenVerifier for tests.
type mockVerifier struct {
	claims *TokenClaims
	err    error
}

func (m *mockVerifier) VerifyAndExtractCaps(_ context.Context, _ string) (*TokenClaims, error) {
	return m.claims, m.err
}

// mockStorageAdapter implements CloudStorageAdapter for tests.
type mockStorageAdapter struct {
	grant *StorageGrant
	err   error
}

// Name implements CloudStorageAdapter.
func (m *mockStorageAdapter) Name() string { return "mock-storage" }

// MintGrant implements CloudStorageAdapter.
func (m *mockStorageAdapter) MintGrant(_ context.Context, _ MintStorageGrantRequest) (*StorageGrant, error) {
	return m.grant, m.err
}

func newTestStorageApp(t *testing.T, verifier TokenVerifier, adapter CloudStorageAdapter) *App {
	t.Helper()
	return New(
		Config{
			DefaultTTL: 15 * time.Minute,
			MaxTTL:     60 * time.Minute,
			Adapter:    "mock",
		},
		Dependencies{
			Adapter:  adapter,
			Verifier: verifier,
			Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
	)
}

func TestStorageGrantSvc_HealthLive(t *testing.T) {
	t.Parallel()
	app := newTestStorageApp(t, &mockVerifier{}, &mockStorageAdapter{})
	req := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestStorageGrantSvc_HealthReady(t *testing.T) {
	t.Parallel()
	app := newTestStorageApp(t, &mockVerifier{}, &mockStorageAdapter{})
	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestStorageGrantSvc_MintGrant_Success(t *testing.T) {
	t.Parallel()
	verifier := &mockVerifier{
		claims: &TokenClaims{
			Subject:          "user-1",
			TenantID:         "tenant-1",
			StorageResources: []string{"storage://my-bucket/data/"},
		},
	}
	adapter := &mockStorageAdapter{
		grant: &StorageGrant{
			URL:        "https://my-bucket.s3.us-east-1.amazonaws.com/data/?presigned",
			Bucket:     "my-bucket",
			Path:       "data/",
			Permission: "read",
			ExpiresAt:  time.Now().Add(15 * time.Minute),
			Adapter:    "mock-storage",
		},
	}
	app := newTestStorageApp(t, verifier, adapter)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/storage-grants", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp StorageGrant
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Bucket != "my-bucket" {
		t.Errorf("expected bucket=my-bucket, got %q", resp.Bucket)
	}
}

func TestStorageGrantSvc_MintGrant_WithBody(t *testing.T) {
	t.Parallel()
	verifier := &mockVerifier{
		claims: &TokenClaims{
			Subject:          "user-1",
			TenantID:         "tenant-1",
			StorageResources: []string{"storage://bucket/path"},
		},
	}
	adapter := &mockStorageAdapter{
		grant: &StorageGrant{
			URL:        "https://presigned",
			Bucket:     "custom-bucket",
			Path:       "custom/path",
			Permission: "write",
			Adapter:    "mock",
		},
	}
	app := newTestStorageApp(t, verifier, adapter)

	body := `{"bucket":"custom-bucket","path":"custom/path","permission":"write","ttlSeconds":600}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/storage-grants", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestStorageGrantSvc_MintGrant_MissingAuth(t *testing.T) {
	t.Parallel()
	app := newTestStorageApp(t, &mockVerifier{}, &mockStorageAdapter{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/storage-grants", nil)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestStorageGrantSvc_MintGrant_InvalidToken(t *testing.T) {
	t.Parallel()
	verifier := &mockVerifier{err: ErrInvalidToken}
	app := newTestStorageApp(t, verifier, &mockStorageAdapter{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/storage-grants", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestStorageGrantSvc_MintGrant_NoCapability(t *testing.T) {
	t.Parallel()
	verifier := &mockVerifier{
		claims: &TokenClaims{
			Subject:          "user-1",
			TenantID:         "tenant-1",
			StorageResources: []string{},
		},
	}
	app := newTestStorageApp(t, verifier, &mockStorageAdapter{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/storage-grants", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestStorageGrantSvc_MintGrant_InvalidPermission(t *testing.T) {
	t.Parallel()
	verifier := &mockVerifier{
		claims: &TokenClaims{
			Subject:          "user-1",
			TenantID:         "tenant-1",
			StorageResources: []string{"storage://bucket/path"},
		},
	}
	app := newTestStorageApp(t, verifier, &mockStorageAdapter{})

	body := `{"permission":"delete"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/storage-grants", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestStorageGrantSvc_MintGrant_AdapterError(t *testing.T) {
	t.Parallel()
	verifier := &mockVerifier{
		claims: &TokenClaims{
			Subject:          "user-1",
			TenantID:         "tenant-1",
			StorageResources: []string{"storage://bucket/path"},
		},
	}
	adapter := &mockStorageAdapter{err: ErrMintFailed}
	app := newTestStorageApp(t, verifier, adapter)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/storage-grants", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestExtractStorageFromURI(t *testing.T) {
	t.Parallel()
	tests := []struct {
		uri        string
		wantBucket string
		wantPath   string
	}{
		{"storage://my-bucket/data/file.txt", "my-bucket", "data/file.txt"},
		{"storage://bucket/", "bucket", ""},
		{"storage://bucket", "bucket", ""},
		{"", "", ""},
	}
	for _, tt := range tests {
		bucket, path := extractStorageFromURI(tt.uri)
		if bucket != tt.wantBucket {
			t.Errorf("extractStorageFromURI(%q) bucket = %q, want %q", tt.uri, bucket, tt.wantBucket)
		}
		if path != tt.wantPath {
			t.Errorf("extractStorageFromURI(%q) path = %q, want %q", tt.uri, path, tt.wantPath)
		}
	}
}

func TestIsPermissionAllowed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		perm string
		want bool
	}{
		{"read", true},
		{"write", true},
		{"readwrite", true},
		{"delete", false},
		{"admin", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isPermissionAllowed(tt.perm, []string{"storage://bucket"})
		if got != tt.want {
			t.Errorf("isPermissionAllowed(%q) = %v, want %v", tt.perm, got, tt.want)
		}
	}
}
