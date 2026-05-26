// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
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

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	// Register a partner with first instance.
	store1 := NewRedisPartnerDIDStore(client)
	require.NoError(t, store1.Register("did:web:persistent", "Persistent", "test persistence"))
	require.NoError(t, store1.SetStatus("did:web:persistent", "approved"))

	// Create a second instance (simulating another replica).
	store2 := NewRedisPartnerDIDStore(client)

	// Second instance should see the same data.
	p, ok := store2.Get("did:web:persistent")
	require.True(t, ok)
	assert.Equal(t, "Persistent", p.Name)
	assert.Equal(t, "approved", p.Status)

	partners := store2.List()
	require.Len(t, partners, 1)
}

func TestRedisPartnerDIDStore_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	store := NewRedisPartnerDIDStore(client)

	// Register multiple DIDs concurrently.
	done := make(chan struct{}, 10)
	for i := 0; i < 10; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			did := fmt.Sprintf("did:web:concurrent-%d", i)
			_ = store.Register(did, "Partner", "")
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}

	partners := store.List()
	assert.Len(t, partners, 10)
}
