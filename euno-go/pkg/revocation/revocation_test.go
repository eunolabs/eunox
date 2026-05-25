// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package revocation_test

import (
	"context"
	"testing"
	"time"

	"github.com/edgeobs/euno-platform/euno-go/pkg/revocation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInMemory_InitiallyNotRevoked(t *testing.T) {
	store := revocation.NewInMemory()
	ctx := context.Background()

	revoked, err := store.IsRevoked(ctx, "jti-1")
	require.NoError(t, err)
	assert.False(t, revoked)
}

func TestInMemory_Revoke(t *testing.T) {
	store := revocation.NewInMemory()
	ctx := context.Background()

	require.NoError(t, store.Revoke(ctx, "jti-1", 0))

	revoked, err := store.IsRevoked(ctx, "jti-1")
	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestInMemory_RevokeWithTTL(t *testing.T) {
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	store := revocation.NewInMemory(revocation.WithTimeFunc(func() time.Time { return now }))
	ctx := context.Background()

	require.NoError(t, store.Revoke(ctx, "jti-1", 60*time.Second))

	// Still revoked within TTL
	revoked, err := store.IsRevoked(ctx, "jti-1")
	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestInMemory_RevokeExpires(t *testing.T) {
	current := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	timeFunc := func() time.Time { return current }
	store := revocation.NewInMemory(revocation.WithTimeFunc(timeFunc))
	ctx := context.Background()

	require.NoError(t, store.Revoke(ctx, "jti-1", 60*time.Second))

	// Advance past TTL
	current = current.Add(61 * time.Second)

	revoked, err := store.IsRevoked(ctx, "jti-1")
	require.NoError(t, err)
	assert.False(t, revoked)
}

func TestInMemory_PermanentRevocation(t *testing.T) {
	current := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	timeFunc := func() time.Time { return current }
	store := revocation.NewInMemory(revocation.WithTimeFunc(timeFunc))
	ctx := context.Background()

	require.NoError(t, store.Revoke(ctx, "jti-1", 0)) // No TTL

	// Advance far into the future
	current = current.Add(365 * 24 * time.Hour)

	revoked, err := store.IsRevoked(ctx, "jti-1")
	require.NoError(t, err)
	assert.True(t, revoked) // Still revoked
}

func TestInMemory_MultipleRevocations(t *testing.T) {
	store := revocation.NewInMemory()
	ctx := context.Background()

	require.NoError(t, store.Revoke(ctx, "jti-1", 0))
	require.NoError(t, store.Revoke(ctx, "jti-2", 0))

	revoked1, err := store.IsRevoked(ctx, "jti-1")
	require.NoError(t, err)
	assert.True(t, revoked1)

	revoked2, err := store.IsRevoked(ctx, "jti-2")
	require.NoError(t, err)
	assert.True(t, revoked2)

	revoked3, err := store.IsRevoked(ctx, "jti-3")
	require.NoError(t, err)
	assert.False(t, revoked3)
}

func TestInMemory_Cleanup(t *testing.T) {
	current := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	timeFunc := func() time.Time { return current }
	store := revocation.NewInMemory(revocation.WithTimeFunc(timeFunc))
	ctx := context.Background()

	require.NoError(t, store.Revoke(ctx, "jti-1", 30*time.Second))
	require.NoError(t, store.Revoke(ctx, "jti-2", 0)) // Permanent

	// Advance past TTL
	current = current.Add(31 * time.Second)

	store.Cleanup()

	// jti-1 should be gone (expired)
	revoked, err := store.IsRevoked(ctx, "jti-1")
	require.NoError(t, err)
	assert.False(t, revoked)

	// jti-2 should still exist (permanent)
	revoked, err = store.IsRevoked(ctx, "jti-2")
	require.NoError(t, err)
	assert.True(t, revoked)
}
