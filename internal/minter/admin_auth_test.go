// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package minter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCombinedAdminAuth_APIKeyFallback(t *testing.T) {
	t.Parallel()

	combined := NewCombinedAdminAuth(CombinedAdminAuthConfig{
		AdminKey: "test-admin-key",
	})

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("X-Admin-Api-Key", "test-admin-key")

	opID, err := combined.Authenticate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opID != "admin-key-user" {
		t.Errorf("expected admin-key-user, got %q", opID)
	}
}

func TestCombinedAdminAuth_APIKeyFallback_XAdminKey(t *testing.T) {
	t.Parallel()

	combined := NewCombinedAdminAuth(CombinedAdminAuthConfig{
		AdminKey: "test-admin-key",
	})

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("X-Admin-Key", "test-admin-key")

	opID, err := combined.Authenticate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opID != "admin-key-user" {
		t.Errorf("expected admin-key-user, got %q", opID)
	}
}

func TestCombinedAdminAuth_InvalidAPIKey(t *testing.T) {
	t.Parallel()

	combined := NewCombinedAdminAuth(CombinedAdminAuthConfig{
		AdminKey: "correct-key",
	})

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("X-Admin-Api-Key", "wrong-key")

	_, err := combined.Authenticate(context.Background(), req)
	if err == nil {
		t.Error("expected error for invalid key")
	}
}

func TestCombinedAdminAuth_NoCredentials(t *testing.T) {
	t.Parallel()

	combined := NewCombinedAdminAuth(CombinedAdminAuthConfig{
		AdminKey: "key",
	})

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	_, err := combined.Authenticate(context.Background(), req)
	if err == nil {
		t.Error("expected error when no credentials provided")
	}
}

func TestCombinedAdminAuth_BearerWithNoJWT(t *testing.T) {
	t.Parallel()

	// JWT verifier is nil but bearer token is provided.
	combined := NewCombinedAdminAuth(CombinedAdminAuthConfig{
		AdminKey: "key",
	})

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "******")

	_, err := combined.Authenticate(context.Background(), req)
	if err == nil {
		t.Error("expected error when JWT not configured but bearer token provided")
	}
}

func TestCombinedAdminAuth_AdminKeyNotConfigured(t *testing.T) {
	t.Parallel()

	combined := NewCombinedAdminAuth(CombinedAdminAuthConfig{})

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("X-Admin-Api-Key", "some-key")

	_, err := combined.Authenticate(context.Background(), req)
	if err == nil {
		t.Error("expected error when admin key not configured")
	}
}
