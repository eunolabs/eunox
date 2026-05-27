// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package minter

import (
	"context"
	"testing"
	"time"
)

func TestInMemoryStore_CreateAndGetKey(t *testing.T) {
	t.Parallel()
	store := NewInMemoryStore()
	ctx := context.Background()

	key := &APIKey{
		KeyID:       "test-key-1",
		SecretHash:  "hash123",
		TenantID:    "tenant-1",
		Description: "test key",
		CreatedAt:   time.Now(),
		CreatedBy:   "admin",
	}

	if err := store.CreateKey(ctx, key); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	got, err := store.GetKey(ctx, "test-key-1")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if got.KeyID != "test-key-1" {
		t.Errorf("got KeyID %q, want %q", got.KeyID, "test-key-1")
	}
	if got.TenantID != "tenant-1" {
		t.Errorf("got TenantID %q, want %q", got.TenantID, "tenant-1")
	}
}

func TestInMemoryStore_GetKey_NotFound(t *testing.T) {
	t.Parallel()
	store := NewInMemoryStore()
	ctx := context.Background()

	_, err := store.GetKey(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent key")
	}
	if err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestInMemoryStore_ListKeys(t *testing.T) {
	t.Parallel()
	store := NewInMemoryStore()
	ctx := context.Background()

	for i := range 5 {
		key := &APIKey{
			KeyID:    "key-" + string(rune('a'+i)),
			TenantID: "tenant-1",
		}
		_ = store.CreateKey(ctx, key)
	}
	_ = store.CreateKey(ctx, &APIKey{KeyID: "other-key", TenantID: "tenant-2"})

	keys, err := store.ListKeys(ctx, "tenant-1", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 5 {
		t.Fatalf("expected 5 keys, got %d", len(keys))
	}

	// Test limit.
	keys, err = store.ListKeys(ctx, "tenant-1", 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys with limit, got %d", len(keys))
	}

	// Test offset.
	keys, err = store.ListKeys(ctx, "tenant-1", 10, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys with offset=3, got %d", len(keys))
	}
}

func TestInMemoryStore_RevokeKey(t *testing.T) {
	t.Parallel()
	store := NewInMemoryStore()
	ctx := context.Background()

	key := &APIKey{KeyID: "revoke-me", TenantID: "t1"}
	_ = store.CreateKey(ctx, key)

	revokedAt := time.Now()
	revoked, err := store.RevokeKey(ctx, "revoke-me", revokedAt)
	if err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	if revoked == nil {
		t.Fatal("RevokeKey: expected non-nil revoked key snapshot")
	}
	if revoked.KeyID != "revoke-me" {
		t.Errorf("RevokeKey: keyID = %q, want %q", revoked.KeyID, "revoke-me")
	}
	if !revoked.IsRevoked() {
		t.Error("RevokeKey: returned snapshot should have RevokedAt set")
	}

	got, _ := store.GetKey(ctx, "revoke-me")
	if !got.IsRevoked() {
		t.Error("key should be revoked in store after RevokeKey")
	}

	// Revoking again should return ErrKeyRevoked with a nil key.
	if _, err := store.RevokeKey(ctx, "revoke-me", time.Now()); err != ErrKeyRevoked {
		t.Errorf("expected ErrKeyRevoked, got %v", err)
	}
}

func TestInMemoryStore_RevokeKey_NotFound(t *testing.T) {
	t.Parallel()
	store := NewInMemoryStore()
	ctx := context.Background()

	if _, err := store.RevokeKey(ctx, "nonexistent", time.Now()); err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestInMemoryStore_PolicyCRUD(t *testing.T) {
	t.Parallel()
	store := NewInMemoryStore()
	ctx := context.Background()

	p := &Policy{
		PolicyID:    "pol-1",
		TenantID:    "t1",
		Name:        "default",
		Description: "default policy",
		Rules: PolicyRule{
			AllowedTools:      []string{"tool-a"},
			MaxCallsPerMinute: 100,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		CreatedBy: "admin",
	}

	// Create.
	if err := store.CreatePolicy(ctx, p); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	// Duplicate name should fail.
	dup := &Policy{PolicyID: "pol-2", TenantID: "t1", Name: "default"}
	if err := store.CreatePolicy(ctx, dup); err != ErrPolicyExists {
		t.Fatalf("expected ErrPolicyExists, got %v", err)
	}

	// Get by ID.
	got, err := store.GetPolicy(ctx, "pol-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "default" {
		t.Errorf("got Name %q, want %q", got.Name, "default")
	}

	// Get by name.
	got, err = store.GetPolicyByName(ctx, "t1", "default")
	if err != nil {
		t.Fatal(err)
	}
	if got.PolicyID != "pol-1" {
		t.Errorf("got PolicyID %q, want %q", got.PolicyID, "pol-1")
	}

	// List.
	policies, err := store.ListPolicies(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}

	// Update.
	p.Description = "updated"
	if err := store.UpdatePolicy(ctx, p); err != nil {
		t.Fatal(err)
	}
	got, _ = store.GetPolicy(ctx, "pol-1")
	if got.Description != "updated" {
		t.Errorf("expected updated description")
	}

	// Delete.
	if err := store.DeletePolicy(ctx, "pol-1"); err != nil {
		t.Fatal(err)
	}
	_, err = store.GetPolicy(ctx, "pol-1")
	if err != ErrPolicyNotFound {
		t.Errorf("expected ErrPolicyNotFound after delete, got %v", err)
	}
}

func TestInMemoryStore_GetPolicy_NotFound(t *testing.T) {
	t.Parallel()
	store := NewInMemoryStore()
	ctx := context.Background()

	_, err := store.GetPolicy(ctx, "nonexistent")
	if err != ErrPolicyNotFound {
		t.Errorf("expected ErrPolicyNotFound, got %v", err)
	}
}

func TestInMemoryStore_GetPolicyByName_NotFound(t *testing.T) {
	t.Parallel()
	store := NewInMemoryStore()
	ctx := context.Background()

	_, err := store.GetPolicyByName(ctx, "t1", "nonexistent")
	if err != ErrPolicyNotFound {
		t.Errorf("expected ErrPolicyNotFound, got %v", err)
	}
}

func TestInMemoryStore_DeletePolicy_NotFound(t *testing.T) {
	t.Parallel()
	store := NewInMemoryStore()
	ctx := context.Background()

	if err := store.DeletePolicy(ctx, "nonexistent"); err != ErrPolicyNotFound {
		t.Errorf("expected ErrPolicyNotFound, got %v", err)
	}
}

func TestInMemoryStore_UpdatePolicy_NotFound(t *testing.T) {
	t.Parallel()
	store := NewInMemoryStore()
	ctx := context.Background()

	p := &Policy{PolicyID: "nonexistent"}
	if err := store.UpdatePolicy(ctx, p); err != ErrPolicyNotFound {
		t.Errorf("expected ErrPolicyNotFound, got %v", err)
	}
}
