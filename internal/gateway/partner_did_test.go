// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testPartnerDIDStore(t *testing.T, store PartnerDIDStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("register and list", func(t *testing.T) {
		err := store.Register(ctx, "did:web:partner1", "Partner 1", "First partner")
		require.NoError(t, err)

		partners, err := store.List(ctx)
		require.NoError(t, err)
		require.Len(t, partners, 1)
		assert.Equal(t, "did:web:partner1", partners[0].DID)
		assert.Equal(t, "Partner 1", partners[0].Name)
		assert.Equal(t, "First partner", partners[0].Description)
		assert.Equal(t, "pending", partners[0].Status)
	})

	t.Run("get existing", func(t *testing.T) {
		p, ok, err := store.Get(ctx, "did:web:partner1")
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, "Partner 1", p.Name)
	})

	t.Run("get non-existing", func(t *testing.T) {
		_, ok, err := store.Get(ctx, "did:web:nonexist")
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("set status", func(t *testing.T) {
		err := store.SetStatus(ctx, "did:web:partner1", "approved")
		require.NoError(t, err)

		p, ok, err := store.Get(ctx, "did:web:partner1")
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, "approved", p.Status)
	})

	t.Run("set status non-existing", func(t *testing.T) {
		err := store.SetStatus(ctx, "did:web:nonexist", "approved")
		assert.ErrorIs(t, err, ErrPartnerDIDNotFound)
	})

	t.Run("unregister", func(t *testing.T) {
		err := store.Unregister(ctx, "did:web:partner1")
		require.NoError(t, err)

		partners, err := store.List(ctx)
		require.NoError(t, err)
		assert.Empty(t, partners)
	})

	t.Run("unregister non-existing", func(t *testing.T) {
		err := store.Unregister(ctx, "did:web:nonexist")
		assert.ErrorIs(t, err, ErrPartnerDIDNotFound)
	})

	t.Run("register multiple", func(t *testing.T) {
		require.NoError(t, store.Register(ctx, "did:web:a", "A", ""))
		require.NoError(t, store.Register(ctx, "did:web:b", "B", ""))
		require.NoError(t, store.Register(ctx, "did:web:c", "C", ""))

		partners, err := store.List(ctx)
		require.NoError(t, err)
		assert.Len(t, partners, 3)
	})
}

func TestInMemoryPartnerDIDStore(t *testing.T) {
	t.Parallel()
	store := NewInMemoryPartnerDIDStore()
	testPartnerDIDStore(t, store)
}

func TestInMemoryPartnerDIDStore_Timestamps(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewInMemoryPartnerDIDStore()

	// Override time function for deterministic tests.
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return baseTime }

	err := store.Register(ctx, "did:web:ts-test", "TS Test", "")
	require.NoError(t, err)

	p, ok, err := store.Get(ctx, "did:web:ts-test")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, baseTime, p.RegisteredAt)
	assert.Equal(t, baseTime, p.UpdatedAt)

	// Advance time and update status.
	laterTime := baseTime.Add(time.Hour)
	store.now = func() time.Time { return laterTime }

	err = store.SetStatus(ctx, "did:web:ts-test", "approved")
	require.NoError(t, err)

	p, ok, err = store.Get(ctx, "did:web:ts-test")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, baseTime, p.RegisteredAt)
	assert.Equal(t, laterTime, p.UpdatedAt)
}

func TestInMemoryPartnerDIDStore_GetReturnsClone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewInMemoryPartnerDIDStore()
	require.NoError(t, store.Register(ctx, "did:web:clone-test", "Clone", ""))

	p, _, _ := store.Get(ctx, "did:web:clone-test")
	p.Name = "Mutated"

	// Original should be unchanged.
	p2, _, _ := store.Get(ctx, "did:web:clone-test")
	assert.Equal(t, "Clone", p2.Name)
}
