// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package minter

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/edgeobs/eunox/pkg/testutil"
)

// migratePostgres applies the minter schema to a test database by loading
// the real migration SQL from disk, ensuring the test always validates against
// the production schema rather than a potentially stale embedded copy.
func migratePostgres(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	// Load the canonical migration from disk (working dir is the package directory).
	sqlBytes, err := os.ReadFile("../../migrations/minter/001_create_api_keys.up.sql")
	if err != nil {
		t.Fatalf("read migration file: %v", err)
	}
	if _, err := db.Exec(string(sqlBytes)); err != nil {
		t.Fatalf("apply schema: %v", err)
	}
}

// newTestPostgresStore starts a PostgreSQL container and returns a ready-to-use
// PostgresKeyStore.  The caller must close the *sql.DB when done.
func newTestPostgresStore(t *testing.T) (*PostgresKeyStore, *sql.DB) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	pg, err := testutil.StartPostgres(ctx, testutil.PostgresContainerConfig{})
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	t.Cleanup(func() { _ = pg.Terminate(context.Background()) })

	migratePostgres(t, pg.DSN)

	db, err := sql.Open("postgres", pg.DSN)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	return NewPostgresKeyStore(db), db
}

func TestPostgresKeyStore_CreateAndGetKey(t *testing.T) {
	store, _ := newTestPostgresStore(t)
	ctx := context.Background()

	key := &APIKey{
		KeyID:       "pg-key-1",
		SecretHash:  "hash123",
		TenantID:    "tenant-1",
		Description: "test key",
		CreatedAt:   time.Now().UTC().Truncate(time.Microsecond),
		CreatedBy:   "admin",
		Metadata:    map[string]string{"env": "test"},
	}

	if err := store.CreateKey(ctx, key); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	got, err := store.GetKey(ctx, "pg-key-1")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if got.KeyID != key.KeyID {
		t.Errorf("KeyID = %q, want %q", got.KeyID, key.KeyID)
	}
	if got.TenantID != key.TenantID {
		t.Errorf("TenantID = %q, want %q", got.TenantID, key.TenantID)
	}
	if got.Description != key.Description {
		t.Errorf("Description = %q, want %q", got.Description, key.Description)
	}
	if got.Metadata["env"] != "test" {
		t.Errorf("Metadata[env] = %q, want %q", got.Metadata["env"], "test")
	}
}

func TestPostgresKeyStore_CreateKey_Duplicate(t *testing.T) {
	store, _ := newTestPostgresStore(t)
	ctx := context.Background()

	key := &APIKey{KeyID: "dup-key", TenantID: "t1", CreatedAt: time.Now()}
	if err := store.CreateKey(ctx, key); err != nil {
		t.Fatalf("first CreateKey: %v", err)
	}
	if err := store.CreateKey(ctx, key); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("expected ErrKeyExists on duplicate key_id insert, got %v", err)
	}
}

func TestPostgresKeyStore_GetKey_NotFound(t *testing.T) {
	store, _ := newTestPostgresStore(t)
	ctx := context.Background()

	_, err := store.GetKey(ctx, "nonexistent")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestPostgresKeyStore_ListKeys(t *testing.T) {
	store, _ := newTestPostgresStore(t)
	ctx := context.Background()

	for i := range 5 {
		key := &APIKey{
			KeyID:     fmt.Sprintf("list-key-%d", i),
			TenantID:  "tenant-list",
			CreatedAt: time.Now().UTC(),
		}
		if err := store.CreateKey(ctx, key); err != nil {
			t.Fatalf("CreateKey %d: %v", i, err)
		}
	}
	// Key for different tenant — should not appear.
	_ = store.CreateKey(ctx, &APIKey{KeyID: "other-tenant-key", TenantID: "other", CreatedAt: time.Now()})

	keys, err := store.ListKeys(ctx, "tenant-list", 10, 0)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 5 {
		t.Errorf("expected 5 keys, got %d", len(keys))
	}

	// Assert ascending (oldest-first) ordering to lock the pagination contract.
	for i := 1; i < len(keys); i++ {
		prev, curr := keys[i-1], keys[i]
		if prev.CreatedAt.After(curr.CreatedAt) {
			t.Errorf("ListKeys: ordering violation at index %d: %s (%s) > %s (%s)",
				i, prev.KeyID, prev.CreatedAt, curr.KeyID, curr.CreatedAt)
		}
	}

	// Limit.
	keys, err = store.ListKeys(ctx, "tenant-list", 2, 0)
	if err != nil {
		t.Fatalf("ListKeys limit=2: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("expected 2 keys with limit, got %d", len(keys))
	}

	// Offset.
	keys, err = store.ListKeys(ctx, "tenant-list", 10, 3)
	if err != nil {
		t.Fatalf("ListKeys offset=3: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("expected 2 keys with offset=3, got %d", len(keys))
	}
}

func TestPostgresKeyStore_CountKeys(t *testing.T) {
	store, _ := newTestPostgresStore(t)
	ctx := context.Background()

	_ = store.CreateKey(ctx, &APIKey{KeyID: "count-k1", TenantID: "count-tenant", CreatedAt: time.Now()})
	_ = store.CreateKey(ctx, &APIKey{KeyID: "count-k2", TenantID: "count-tenant", CreatedAt: time.Now()})
	_ = store.CreateKey(ctx, &APIKey{KeyID: "count-k3", TenantID: "other-tenant", CreatedAt: time.Now()})

	count, err := store.CountKeys(ctx, "count-tenant")
	if err != nil {
		t.Fatalf("CountKeys: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2, got %d", count)
	}
}

func TestPostgresKeyStore_RevokeKey(t *testing.T) {
	store, _ := newTestPostgresStore(t)
	ctx := context.Background()

	key := &APIKey{KeyID: "revoke-pg", TenantID: "t1", CreatedAt: time.Now()}
	if err := store.CreateKey(ctx, key); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	revokedAt := time.Now().UTC().Truncate(time.Microsecond)
	revoked, err := store.RevokeKey(ctx, "revoke-pg", revokedAt)
	if err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	if revoked == nil {
		t.Fatal("RevokeKey returned nil key")
	}
	if !revoked.IsRevoked() {
		t.Error("returned snapshot should have RevokedAt set")
	}

	// Verify persistence.
	got, err := store.GetKey(ctx, "revoke-pg")
	if err != nil {
		t.Fatalf("GetKey after revoke: %v", err)
	}
	if !got.IsRevoked() {
		t.Error("key should be revoked in store")
	}

	// Double-revoke.
	if _, err := store.RevokeKey(ctx, "revoke-pg", time.Now()); !errors.Is(err, ErrKeyRevoked) {
		t.Errorf("expected ErrKeyRevoked on double-revoke, got %v", err)
	}
}

func TestPostgresKeyStore_RevokeKey_NotFound(t *testing.T) {
	store, _ := newTestPostgresStore(t)
	ctx := context.Background()

	if _, err := store.RevokeKey(ctx, "nonexistent", time.Now()); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestPostgresKeyStore_PolicyCRUD(t *testing.T) {
	store, _ := newTestPostgresStore(t)
	ctx := context.Background()

	p := &Policy{
		PolicyID:    "pg-pol-1",
		TenantID:    "t1",
		Name:        "default",
		Description: "test policy",
		Rules: PolicyRule{
			AllowedTools:      []string{"tool-a", "tool-b"},
			MaxCallsPerMinute: 60,
		},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
		CreatedBy: "admin",
	}

	// Create.
	if err := store.CreatePolicy(ctx, p); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	// Duplicate name within the same tenant.
	dup := &Policy{PolicyID: "pg-pol-2", TenantID: "t1", Name: "default", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := store.CreatePolicy(ctx, dup); !errors.Is(err, ErrPolicyExists) {
		t.Fatalf("expected ErrPolicyExists on duplicate name, got %v", err)
	}

	// Same name under a different tenant is fine.
	other := &Policy{PolicyID: "pg-pol-3", TenantID: "t2", Name: "default", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := store.CreatePolicy(ctx, other); err != nil {
		t.Fatalf("CreatePolicy different tenant: %v", err)
	}

	// GetPolicy by ID.
	got, err := store.GetPolicy(ctx, "pg-pol-1")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if got.Name != "default" {
		t.Errorf("Name = %q, want %q", got.Name, "default")
	}
	if len(got.Rules.AllowedTools) != 2 {
		t.Errorf("AllowedTools len = %d, want 2", len(got.Rules.AllowedTools))
	}

	// GetPolicyByName.
	got, err = store.GetPolicyByName(ctx, "t1", "default")
	if err != nil {
		t.Fatalf("GetPolicyByName: %v", err)
	}
	if got.PolicyID != "pg-pol-1" {
		t.Errorf("PolicyID = %q, want %q", got.PolicyID, "pg-pol-1")
	}

	// ListPolicies.
	policies, err := store.ListPolicies(ctx, "t1")
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(policies) != 1 {
		t.Errorf("expected 1 policy for t1, got %d", len(policies))
	}

	// UpdatePolicy.
	p.Description = "updated description"
	p.UpdatedAt = time.Now().UTC()
	if err := store.UpdatePolicy(ctx, p); err != nil {
		t.Fatalf("UpdatePolicy: %v", err)
	}
	got, _ = store.GetPolicy(ctx, "pg-pol-1")
	if got.Description != "updated description" {
		t.Errorf("Description after update = %q, want %q", got.Description, "updated description")
	}

	// DeletePolicy.
	if err := store.DeletePolicy(ctx, "pg-pol-1"); err != nil {
		t.Fatalf("DeletePolicy: %v", err)
	}
	if _, err := store.GetPolicy(ctx, "pg-pol-1"); !errors.Is(err, ErrPolicyNotFound) {
		t.Errorf("expected ErrPolicyNotFound after delete, got %v", err)
	}
}

func TestPostgresKeyStore_GetPolicy_NotFound(t *testing.T) {
	store, _ := newTestPostgresStore(t)
	ctx := context.Background()

	if _, err := store.GetPolicy(ctx, "nonexistent"); !errors.Is(err, ErrPolicyNotFound) {
		t.Errorf("expected ErrPolicyNotFound, got %v", err)
	}
}

func TestPostgresKeyStore_GetPolicyByName_NotFound(t *testing.T) {
	store, _ := newTestPostgresStore(t)
	ctx := context.Background()

	if _, err := store.GetPolicyByName(ctx, "t1", "nonexistent"); !errors.Is(err, ErrPolicyNotFound) {
		t.Errorf("expected ErrPolicyNotFound, got %v", err)
	}
}

func TestPostgresKeyStore_DeletePolicy_NotFound(t *testing.T) {
	store, _ := newTestPostgresStore(t)
	ctx := context.Background()

	if err := store.DeletePolicy(ctx, "nonexistent"); !errors.Is(err, ErrPolicyNotFound) {
		t.Errorf("expected ErrPolicyNotFound, got %v", err)
	}
}

func TestPostgresKeyStore_UpdatePolicy_NotFound(t *testing.T) {
	store, _ := newTestPostgresStore(t)
	ctx := context.Background()

	p := &Policy{PolicyID: "nonexistent", UpdatedAt: time.Now()}
	if err := store.UpdatePolicy(ctx, p); !errors.Is(err, ErrPolicyNotFound) {
		t.Errorf("expected ErrPolicyNotFound, got %v", err)
	}
}

func TestPostgresKeyStore_KeyWithExpiry(t *testing.T) {
	store, _ := newTestPostgresStore(t)
	ctx := context.Background()

	expires := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Microsecond)
	key := &APIKey{
		KeyID:     "expiry-key",
		TenantID:  "t1",
		CreatedAt: time.Now().UTC(),
		ExpiresAt: &expires,
	}
	if err := store.CreateKey(ctx, key); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	got, err := store.GetKey(ctx, "expiry-key")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if got.ExpiresAt == nil {
		t.Fatal("ExpiresAt should not be nil")
	}
	if got.IsExpired(time.Now()) {
		t.Error("key should not be expired yet")
	}
	if !got.IsExpired(expires.Add(time.Second)) {
		t.Error("key should be expired after ExpiresAt")
	}
}
