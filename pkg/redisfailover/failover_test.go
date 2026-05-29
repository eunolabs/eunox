// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package redisfailover

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicy_String(t *testing.T) {
	assert.Equal(t, "fail-closed", FailClosed.String())
	assert.Equal(t, "fail-open", FailOpen.String())
	assert.Equal(t, "unknown", Policy(99).String())
}

func TestHealthState_String(t *testing.T) {
	assert.Equal(t, "healthy", Healthy.String())
	assert.Equal(t, "degraded", Degraded.String())
	assert.Equal(t, "unknown", HealthState(99).String())
}

func TestMonitor_AllHealthy(t *testing.T) {
	m := NewMonitor()
	r1 := m.Register("killswitch")
	r2 := m.Register("revocation")

	r1.MarkHealthy()
	r2.MarkHealthy()

	assert.True(t, m.IsReady())
	assert.Empty(t, m.DegradedComponents())
}

func TestMonitor_OneDegraded(t *testing.T) {
	m := NewMonitor()
	r1 := m.Register("killswitch")
	r2 := m.Register("revocation")

	r1.MarkHealthy()
	r2.MarkDegraded()

	assert.False(t, m.IsReady())
	assert.Equal(t, []string{"revocation"}, m.DegradedComponents())
}

func TestMonitor_RecoveryFromDegraded(t *testing.T) {
	m := NewMonitor()
	r := m.Register("ratelimit")

	r.MarkDegraded()
	assert.False(t, m.IsReady())

	r.MarkHealthy()
	assert.True(t, m.IsReady())
}

func TestMonitor_EmptyIsReady(t *testing.T) {
	m := NewMonitor()
	assert.True(t, m.IsReady())
}

func TestReporter_State(t *testing.T) {
	m := NewMonitor()
	r := m.Register("test")

	assert.Equal(t, Healthy, r.State())
	r.MarkDegraded()
	assert.Equal(t, Degraded, r.State())
	r.MarkHealthy()
	assert.Equal(t, Healthy, r.State())
}

func TestFallbackCache_PutAndGet(t *testing.T) {
	cache := NewFallbackCache(FallbackCacheConfig[string, bool]{
		StaleTTL: 30 * time.Second,
		Policy:   FailClosed,
	})

	cache.Put("token-123", true)

	val, ok := cache.Get("token-123")
	assert.True(t, ok)
	assert.True(t, val)
}

func TestFallbackCache_MissingKey(t *testing.T) {
	cache := NewFallbackCache(FallbackCacheConfig[string, bool]{
		StaleTTL:     30 * time.Second,
		Policy:       FailClosed,
		DefaultValue: true,
	})

	val, ok := cache.Get("nonexistent")
	assert.False(t, ok)
	assert.True(t, val) // Returns DefaultValue
}

func TestFallbackCache_ExpiredEntry(t *testing.T) {
	now := time.Now()
	var clock atomic.Int64
	clock.Store(now.UnixNano())

	cache := NewFallbackCache(FallbackCacheConfig[string, bool]{
		StaleTTL:     10 * time.Second,
		Policy:       FailClosed,
		DefaultValue: true,
	})
	cache.now = func() time.Time {
		return time.Unix(0, clock.Load())
	}

	cache.Put("key", false)

	// Still valid
	val, ok := cache.Get("key")
	assert.True(t, ok)
	assert.False(t, val)

	// Advance time past TTL
	clock.Store(now.Add(11 * time.Second).UnixNano())
	val, ok = cache.Get("key")
	assert.False(t, ok)
	assert.True(t, val) // DefaultValue
}

func TestFallbackCache_Delete(t *testing.T) {
	cache := NewFallbackCache(FallbackCacheConfig[string, bool]{
		StaleTTL: 30 * time.Second,
		Policy:   FailClosed,
	})

	cache.Put("key", true)
	cache.Delete("key")

	_, ok := cache.Get("key")
	assert.False(t, ok)
}

func TestFallbackCache_Len(t *testing.T) {
	cache := NewFallbackCache(FallbackCacheConfig[string, int]{
		StaleTTL: 30 * time.Second,
		Policy:   FailOpen,
	})

	assert.Equal(t, 0, cache.Len())
	cache.Put("a", 1)
	cache.Put("b", 2)
	assert.Equal(t, 2, cache.Len())
	cache.Delete("a")
	assert.Equal(t, 1, cache.Len())
}

func TestFallbackCache_DefaultStaleTTL(t *testing.T) {
	cache := NewFallbackCache(FallbackCacheConfig[string, bool]{
		StaleTTL: 0, // Should default to 30s
		Policy:   FailOpen,
	})
	assert.Equal(t, 30*time.Second, cache.staleTTL)
}

// mockPinger implements Pinger for testing.
type mockPinger struct {
	err atomic.Value
}

func (m *mockPinger) Ping(_ context.Context) error {
	val := m.err.Load()
	if val == nil {
		return nil
	}
	return val.(error)
}

func TestHealthChecker_HealthyInitially(t *testing.T) {
	m := NewMonitor()
	r := m.Register("test")
	pinger := &mockPinger{}

	hc := NewHealthChecker(pinger, r, 50*time.Millisecond)
	hc.Start(context.Background())
	defer hc.Stop()

	// Give initial check time to run
	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, Healthy, r.State())
}

func TestHealthChecker_DetectsDegradation(t *testing.T) {
	m := NewMonitor()
	r := m.Register("test")
	pinger := &mockPinger{}
	pinger.err.Store(errors.New("connection refused"))

	hc := NewHealthChecker(pinger, r, 50*time.Millisecond)
	hc.Start(context.Background())
	defer hc.Stop()

	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, Degraded, r.State())
}

func TestHealthChecker_DefaultInterval(t *testing.T) {
	m := NewMonitor()
	r := m.Register("test")
	pinger := &mockPinger{}

	hc := NewHealthChecker(pinger, r, 0)
	require.Equal(t, 5*time.Second, hc.interval)
	_ = r // suppress unused
}

func TestHealthChecker_Stop(t *testing.T) {
	m := NewMonitor()
	r := m.Register("test")
	pinger := &mockPinger{}

	hc := NewHealthChecker(pinger, r, 50*time.Millisecond)
	hc.Start(context.Background())
	hc.Stop()

	// Should not panic on double stop
	hc.Stop()
	_ = r
}
