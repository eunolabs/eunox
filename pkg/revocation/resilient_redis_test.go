// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package revocation_test

import (
	"context"
	"testing"
	"time"

	"github.com/edgeobs/eunox/pkg/redisfailover"
	"github.com/edgeobs/eunox/pkg/revocation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResilientRedis_FailClosed_UnknownToken(t *testing.T) {
	// When Redis is unreachable and token is not in cache, fail-closed (treat as revoked).
	monitor := redisfailover.NewMonitor()
	reporter := monitor.Register("revocation")

	// Use the real Redis store with miniredis
	store := revocation.NewResilientRedisFromStore(
		&failingStore{},
		reporter,
		&revocation.ResilientRedisConfig{StaleTTL: 60 * time.Second},
	)

	revoked, err := store.IsRevoked(context.Background(), "unknown-token")
	require.NoError(t, err)
	assert.True(t, revoked, "unknown token during Redis failure should be treated as revoked (fail-closed)")
	assert.Equal(t, redisfailover.Degraded, reporter.State())
}

func TestResilientRedis_CacheServesStale(t *testing.T) {
	monitor := redisfailover.NewMonitor()
	reporter := monitor.Register("revocation")

	inner := &toggleStore{store: revocation.NewInMemory()}
	store := revocation.NewResilientRedisFromStore(
		inner,
		reporter,
		&revocation.ResilientRedisConfig{StaleTTL: 60 * time.Second},
	)

	// First call: Redis healthy, token not revoked
	revoked, err := store.IsRevoked(context.Background(), "token-1")
	require.NoError(t, err)
	assert.False(t, revoked)
	assert.Equal(t, redisfailover.Healthy, reporter.State())

	// Simulate Redis going down
	inner.SetFailing(true)

	// Token-1 should be served from cache (not revoked)
	revoked, err = store.IsRevoked(context.Background(), "token-1")
	require.NoError(t, err)
	assert.False(t, revoked, "cached token should retain its state")

	// Unknown token during outage: fail-closed
	revoked, err = store.IsRevoked(context.Background(), "new-token")
	require.NoError(t, err)
	assert.True(t, revoked, "unknown token during outage must fail-closed")
}

func TestResilientRedis_Revoke_CachesLocally(t *testing.T) {
	monitor := redisfailover.NewMonitor()
	reporter := monitor.Register("revocation")

	inner := &toggleStore{store: revocation.NewInMemory()}
	store := revocation.NewResilientRedisFromStore(
		inner,
		reporter,
		nil, // Use defaults
	)

	// Revoke while Redis is down
	inner.SetFailing(true)
	err := store.Revoke(context.Background(), "token-x", 0)
	assert.Error(t, err)

	// Even though Redis failed, local cache should know it's revoked
	revoked, err := store.IsRevoked(context.Background(), "token-x")
	require.NoError(t, err)
	assert.True(t, revoked, "locally cached revocation should persist")
}

func TestResilientRedis_HealthRecovery(t *testing.T) {
	monitor := redisfailover.NewMonitor()
	reporter := monitor.Register("revocation")

	inner := &toggleStore{store: revocation.NewInMemory()}
	store := revocation.NewResilientRedisFromStore(
		inner,
		reporter,
		nil,
	)

	// Start degraded
	inner.SetFailing(true)
	_, _ = store.IsRevoked(context.Background(), "token")
	assert.False(t, monitor.IsReady())

	// Recover
	inner.SetFailing(false)
	_, _ = store.IsRevoked(context.Background(), "token")
	assert.True(t, monitor.IsReady())
}

// failingStore always returns an error.
type failingStore struct{}

func (f *failingStore) IsRevoked(_ context.Context, _ string) (bool, error) {
	return false, assert.AnError
}

func (f *failingStore) Revoke(_ context.Context, _ string, _ time.Duration) error {
	return assert.AnError
}

// toggleStore wraps an in-memory store and can be toggled to simulate failures.
type toggleStore struct {
	store   revocation.Store
	failing bool
}

func (t *toggleStore) SetFailing(f bool) { t.failing = f }

func (t *toggleStore) IsRevoked(ctx context.Context, jti string) (bool, error) {
	if t.failing {
		return false, assert.AnError
	}
	return t.store.IsRevoked(ctx, jti)
}

func (t *toggleStore) Revoke(ctx context.Context, jti string, ttl time.Duration) error {
	if t.failing {
		return assert.AnError
	}
	return t.store.Revoke(ctx, jti, ttl)
}
