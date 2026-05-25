// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package dbtokensvc

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

// mockDBAdapter implements CloudDBAdapter for tests.
type mockDBAdapter struct {
	cred    *DBCredential
	err     error
	lastReq MintDBCredentialRequest
}

// Name implements CloudDBAdapter.
func (m *mockDBAdapter) Name() string { return "mock-db" }

// MintCredential implements CloudDBAdapter.
func (m *mockDBAdapter) MintCredential(_ context.Context, req MintDBCredentialRequest) (*DBCredential, error) {
	m.lastReq = req
	return m.cred, m.err
}

func newTestDBTokenApp(t *testing.T, verifier TokenVerifier, adapter CloudDBAdapter) *App {
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
			Mapping: &CapabilityMapping{
				ResourceToUsername: map[string]string{
					"db://host/mydb": "app_user",
				},
			},
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
	)
}

func TestDBTokenSvc_HealthLive(t *testing.T) {
	t.Parallel()
	app := newTestDBTokenApp(t, &mockVerifier{}, &mockDBAdapter{})
	req := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestDBTokenSvc_HealthReady(t *testing.T) {
	t.Parallel()
	app := newTestDBTokenApp(t, &mockVerifier{}, &mockDBAdapter{})
	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestDBTokenSvc_MintToken_Success(t *testing.T) {
	t.Parallel()
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
	app := newTestDBTokenApp(t, verifier, adapter)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/db-tokens", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp DBCredential
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Username != "app_user" {
		t.Errorf("expected username=app_user, got %q", resp.Username)
	}
	if resp.Database != "mydb" {
		t.Errorf("expected database=mydb, got %q", resp.Database)
	}
}

func TestDBTokenSvc_MintToken_WithTTL(t *testing.T) {
	t.Parallel()
	verifier := &mockVerifier{
		claims: &TokenClaims{
			Subject:     "user-1",
			TenantID:    "tenant-1",
			DBResources: []string{"db://host/mydb"},
		},
	}
	adapter := &mockDBAdapter{
		cred: &DBCredential{
			Username: "app_user",
			Host:     "mydb.rds.amazonaws.com",
			Port:     5432,
			Database: "mydb",
		},
	}
	app := newTestDBTokenApp(t, verifier, adapter)

	body := `{"database":"mydb","ttlSeconds":300}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/db-tokens", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if adapter.lastReq.TTL != 5*time.Minute {
		t.Fatalf("expected TTL=5m, got %s", adapter.lastReq.TTL)
	}
}

func TestDBTokenSvc_MintToken_ParsesChunkedBody(t *testing.T) {
	t.Parallel()
	verifier := &mockVerifier{
		claims: &TokenClaims{
			Subject:      "user-1",
			TenantID:     "tenant-1",
			DBResources:  []string{"db://host/mydb"},
			PolicyUserID: "app_user",
		},
	}
	adapter := &mockDBAdapter{
		cred: &DBCredential{
			Username: "app_user",
			Host:     "mydb.rds.amazonaws.com",
			Port:     5432,
			Database: "override",
		},
	}
	app := newTestDBTokenApp(t, verifier, adapter)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/db-tokens", bytes.NewBufferString(`{"database":"override","ttlSeconds":120}`))
	req.ContentLength = -1
	req.Header.Set("Authorization", "Bearer "+"test-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if adapter.lastReq.Database != "override" {
		t.Fatalf("expected database override from chunked body, got %q", adapter.lastReq.Database)
	}
	if adapter.lastReq.TTL != 2*time.Minute {
		t.Fatalf("expected TTL=2m, got %s", adapter.lastReq.TTL)
	}
}

func TestDBTokenSvc_MintToken_MissingAuth(t *testing.T) {
	t.Parallel()
	app := newTestDBTokenApp(t, &mockVerifier{}, &mockDBAdapter{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/db-tokens", nil)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestDBTokenSvc_MintToken_InvalidToken(t *testing.T) {
	t.Parallel()
	verifier := &mockVerifier{err: ErrInvalidToken}
	app := newTestDBTokenApp(t, verifier, &mockDBAdapter{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/db-tokens", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestDBTokenSvc_MintToken_NoCapability(t *testing.T) {
	t.Parallel()
	verifier := &mockVerifier{
		claims: &TokenClaims{
			Subject:     "user-1",
			TenantID:    "tenant-1",
			DBResources: []string{}, // no db caps
		},
	}
	app := newTestDBTokenApp(t, verifier, &mockDBAdapter{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/db-tokens", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestDBTokenSvc_MintToken_NoMapping(t *testing.T) {
	t.Parallel()
	verifier := &mockVerifier{
		claims: &TokenClaims{
			Subject:     "user-1",
			TenantID:    "tenant-1",
			DBResources: []string{"db://unknown/unknown"},
		},
	}
	// Use a mapping that doesn't match.
	app := New(
		Config{DefaultTTL: 15 * time.Minute, MaxTTL: 60 * time.Minute},
		Dependencies{
			Adapter:  &mockDBAdapter{},
			Verifier: verifier,
			Mapping: &CapabilityMapping{
				ResourceToUsername: map[string]string{
					"db://host/mydb": "app_user",
				},
			},
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
	)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/db-tokens", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDBTokenSvc_MintToken_AdapterError(t *testing.T) {
	t.Parallel()
	verifier := &mockVerifier{
		claims: &TokenClaims{
			Subject:     "user-1",
			TenantID:    "tenant-1",
			DBResources: []string{"db://host/mydb"},
		},
	}
	adapter := &mockDBAdapter{err: ErrMintFailed}
	app := newTestDBTokenApp(t, verifier, adapter)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/db-tokens", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestDBTokenSvc_MintToken_RequiresDatabase(t *testing.T) {
	t.Parallel()
	verifier := &mockVerifier{
		claims: &TokenClaims{
			Subject:      "user-1",
			TenantID:     "tenant-1",
			DBResources:  []string{"db://host"},
			PolicyUserID: "app_user",
		},
	}
	app := newTestDBTokenApp(t, verifier, &mockDBAdapter{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/db-tokens", nil)
	req.Header.Set("Authorization", "Bearer "+"test-token")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestExtractDatabaseFromURI(t *testing.T) {
	t.Parallel()
	tests := []struct {
		uri  string
		want string
	}{
		{"db://host/mydb", "mydb"},
		{"db://host:5432/mydb", "mydb"},
		{"db://host", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got := extractDatabaseFromURI(tt.uri)
		if got != tt.want {
			t.Errorf("extractDatabaseFromURI(%q) = %q, want %q", tt.uri, got, tt.want)
		}
	}
}

func TestExtractBearerToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		header string
		want   string
	}{
		{"Bearer test-token", "test-token"},
		{"Bearer ", ""},
		{"Basic abc", ""},
		{"", ""},
	}
	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if tt.header != "" {
			req.Header.Set("Authorization", tt.header)
		}
		got := extractBearerToken(req)
		if got != tt.want {
			t.Errorf("header=%q: got %q, want %q", tt.header, got, tt.want)
		}
	}
}
