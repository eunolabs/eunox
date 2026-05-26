// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"context"
	"fmt"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedisPartnerDIDStore(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	store := NewRedisPartnerDIDStore(client)
	testPartnerDIDStore(t, store)
}

func TestRedisPartnerDIDStore_PersistenceAcrossInstances(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	// Register a partner with first instance.
	store1 := NewRedisPartnerDIDStore(client)
	require.NoError(t, store1.Register(ctx, "did:web:persistent", "Persistent", "test persistence"))
	require.NoError(t, store1.SetStatus(ctx, "did:web:persistent", "approved"))

	// Create a second instance (simulating another replica).
	store2 := NewRedisPartnerDIDStore(client)

	// Second instance should see the same data.
	p, ok, err := store2.Get(ctx, "did:web:persistent")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "Persistent", p.Name)
	assert.Equal(t, "approved", p.Status)

	partners, err := store2.List(ctx)
	require.NoError(t, err)
	require.Len(t, partners, 1)
}

func TestRedisPartnerDIDStore_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	store := NewRedisPartnerDIDStore(client)

	// Register multiple DIDs concurrently.
	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		go func(i int) {
			did := fmt.Sprintf("did:web:concurrent-%d", i)
			errs <- store.Register(ctx, did, "Partner", "")
		}(i)
	}
	for i := 0; i < 10; i++ {
		require.NoError(t, <-errs)
	}

	partners, err := store.List(ctx)
	require.NoError(t, err)
	assert.Len(t, partners, 10)
}
