// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package revocation_test

import (
	"context"
	"testing"
	"time"

	"github.com/eunolabs/eunox/pkg/redisfailover"
	"github.com/eunolabs/eunox/pkg/revocation"
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

// TestResilientRedis_FailClosedDuringOutage verifies the H-2 fix: non-revoked
// tokens are NOT cached. During a Redis outage, every token that was previously
// seen as valid (revoked=false) fails closed rather than being served from a
// stale "not revoked" cache entry. Only confirmed revocations are cached.
func TestResilientRedis_FailClosedDuringOutage(t *testing.T) {
	monitor := redisfailover.NewMonitor()
	reporter := monitor.Register("revocation")

	inner := &toggleStore{store: revocation.NewInMemory()}
	store := revocation.NewResilientRedisFromStore(
		inner,
		reporter,
		&revocation.ResilientRedisConfig{StaleTTL: 60 * time.Second},
	)

	// First call: Redis healthy, token not revoked (result is NOT cached).
	revoked, err := store.IsRevoked(context.Background(), "token-1")
	require.NoError(t, err)
	assert.False(t, revoked)
	assert.Equal(t, redisfailover.Healthy, reporter.State())

	// Simulate Redis going down.
	inner.SetFailing(true)

	// token-1 was NOT cached (it was not revoked). On Redis failure it is treated
	// as revoked (fail-closed) rather than served as valid from a stale cache.
	revoked, err = store.IsRevoked(context.Background(), "token-1")
	require.NoError(t, err)
	assert.True(t, revoked, "non-revoked token must fail-closed during Redis outage (H-2 fix)")

	// Unknown token during outage: also fail-closed.
	revoked, err = store.IsRevoked(context.Background(), "new-token")
	require.NoError(t, err)
	assert.True(t, revoked, "unknown token during outage must fail-closed")
}

// TestResilientRedis_RevokedTokenCachedAndServedDuringOutage verifies that a
// confirmed revocation IS cached so revoked tokens remain blocked even when
// Redis is unreachable.
func TestResilientRedis_RevokedTokenCachedAndServedDuringOutage(t *testing.T) {
	monitor := redisfailover.NewMonitor()
	reporter := monitor.Register("revocation")

	inner := &toggleStore{store: revocation.NewInMemory()}
	store := revocation.NewResilientRedisFromStore(
		inner,
		reporter,
		&revocation.ResilientRedisConfig{StaleTTL: 60 * time.Second},
	)

	// Revoke the token while Redis is healthy.
	require.NoError(t, inner.store.Revoke(context.Background(), "revoked-tok", 0))

	// First read: Redis healthy, token IS revoked → cached as true.
	revoked, err := store.IsRevoked(context.Background(), "revoked-tok")
	require.NoError(t, err)
	assert.True(t, revoked)

	// Simulate Redis outage.
	inner.SetFailing(true)

	// Revoked status is served from cache even during the outage.
	revoked, err = store.IsRevoked(context.Background(), "revoked-tok")
	require.NoError(t, err)
	assert.True(t, revoked, "revoked token must remain blocked during Redis outage (served from cache)")
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
