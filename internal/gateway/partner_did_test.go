// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testPartnerDIDStore(t *testing.T, store PartnerDIDStore) {
	t.Helper()

	t.Run("register and list", func(t *testing.T) {
		err := store.Register("did:web:partner1", "Partner 1", "First partner")
		require.NoError(t, err)

		partners := store.List()
		require.Len(t, partners, 1)
		assert.Equal(t, "did:web:partner1", partners[0].DID)
		assert.Equal(t, "Partner 1", partners[0].Name)
		assert.Equal(t, "First partner", partners[0].Description)
		assert.Equal(t, "pending", partners[0].Status)
	})

	t.Run("get existing", func(t *testing.T) {
		p, ok := store.Get("did:web:partner1")
		require.True(t, ok)
		assert.Equal(t, "Partner 1", p.Name)
	})

	t.Run("get non-existing", func(t *testing.T) {
		_, ok := store.Get("did:web:nonexist")
		assert.False(t, ok)
	})

	t.Run("set status", func(t *testing.T) {
		err := store.SetStatus("did:web:partner1", "approved")
		require.NoError(t, err)

		p, ok := store.Get("did:web:partner1")
		require.True(t, ok)
		assert.Equal(t, "approved", p.Status)
	})

	t.Run("set status non-existing", func(t *testing.T) {
		err := store.SetStatus("did:web:nonexist", "approved")
		assert.ErrorIs(t, err, ErrPartnerDIDNotFound)
	})

	t.Run("unregister", func(t *testing.T) {
		err := store.Unregister("did:web:partner1")
		require.NoError(t, err)

		partners := store.List()
		assert.Empty(t, partners)
	})

	t.Run("unregister non-existing", func(t *testing.T) {
		err := store.Unregister("did:web:nonexist")
		assert.ErrorIs(t, err, ErrPartnerDIDNotFound)
	})

	t.Run("register multiple", func(t *testing.T) {
		require.NoError(t, store.Register("did:web:a", "A", ""))
		require.NoError(t, store.Register("did:web:b", "B", ""))
		require.NoError(t, store.Register("did:web:c", "C", ""))

		partners := store.List()
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
	store := NewInMemoryPartnerDIDStore()

	// Override time function for deterministic tests.
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return baseTime }

	err := store.Register("did:web:ts-test", "TS Test", "")
	require.NoError(t, err)

	p, ok := store.Get("did:web:ts-test")
	require.True(t, ok)
	assert.Equal(t, baseTime, p.RegisteredAt)
	assert.Equal(t, baseTime, p.UpdatedAt)

	// Advance time and update status.
	laterTime := baseTime.Add(time.Hour)
	store.now = func() time.Time { return laterTime }

	err = store.SetStatus("did:web:ts-test", "approved")
	require.NoError(t, err)

	p, ok = store.Get("did:web:ts-test")
	require.True(t, ok)
	assert.Equal(t, baseTime, p.RegisteredAt)
	assert.Equal(t, laterTime, p.UpdatedAt)
}

func TestInMemoryPartnerDIDStore_GetReturnsClone(t *testing.T) {
	t.Parallel()
	store := NewInMemoryPartnerDIDStore()
	require.NoError(t, store.Register("did:web:clone-test", "Clone", ""))

	p, _ := store.Get("did:web:clone-test")
	p.Name = "Mutated"

	// Original should be unchanged.
	p2, _ := store.Get("did:web:clone-test")
	assert.Equal(t, "Clone", p2.Name)
}
