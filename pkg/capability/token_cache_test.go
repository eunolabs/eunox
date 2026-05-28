// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package capability

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenCache_PutAndGet(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clk := &atomic.Value{}
	clk.Store(now)

	cache := NewTokenCache(TokenCacheConfig{
		MaxEntryTTL:     30 * time.Second,
		MaxSize:         100,
		CleanupInterval: time.Hour,
		Now:             func() time.Time { return clk.Load().(time.Time) },
	})

	payload := &TokenPayload{
		Subject:   "agent-1",
		ExpiresAt: now.Add(time.Hour).Unix(),
	}
	cache.Put("tok1", payload)

	got, ok := cache.Get("tok1")
	require.True(t, ok)
	assert.Equal(t, payload.Subject, got.Subject)
}

func TestTokenCache_Miss(t *testing.T) {
	cache := NewTokenCache(TokenCacheConfig{})
	cache.Start(context.Background())
	t.Cleanup(cache.Stop)

	_, ok := cache.Get("nonexistent")
	assert.False(t, ok)
}

func TestTokenCache_ExpiredEntry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var nowVal atomic.Value
	nowVal.Store(now)

	cache := NewTokenCache(TokenCacheConfig{
		MaxEntryTTL:     5 * time.Second,
		CleanupInterval: time.Hour,
		Now:             func() time.Time { return nowVal.Load().(time.Time) },
	})

	payload := &TokenPayload{
		Subject:   "agent-1",
		ExpiresAt: now.Add(time.Hour).Unix(),
	}
	cache.Put("tok1", payload)

	// Entry should be present immediately.
	_, ok := cache.Get("tok1")
	require.True(t, ok)

	// Advance clock past MaxEntryTTL.
	nowVal.Store(now.Add(6 * time.Second))
	_, ok = cache.Get("tok1")
	assert.False(t, ok, "expected cache miss after entry TTL expired")
}

func TestTokenCache_TokenExpiryBoundsTTL(t *testing.T) {
	// When the token expires sooner than MaxEntryTTL, the entry should use
	// the shorter token lifetime.
	now := time.Unix(1_700_000_000, 0)
	var nowVal atomic.Value
	nowVal.Store(now)

	cache := NewTokenCache(TokenCacheConfig{
		MaxEntryTTL:     60 * time.Second,
		CleanupInterval: time.Hour,
		Now:             func() time.Time { return nowVal.Load().(time.Time) },
	})

	// Token that expires in 5 seconds (less than MaxEntryTTL).
	payload := &TokenPayload{
		Subject:   "short-lived",
		ExpiresAt: now.Add(5 * time.Second).Unix(),
	}
	cache.Put("tok-short", payload)

	// Should be a hit before token expiry.
	_, ok := cache.Get("tok-short")
	require.True(t, ok)

	// Advance past token expiry — entry TTL was capped to token lifetime.
	nowVal.Store(now.Add(6 * time.Second))
	_, ok = cache.Get("tok-short")
	assert.False(t, ok, "expected cache miss because token has expired")
}

func TestTokenCache_AlreadyExpiredTokenNotCached(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	cache := NewTokenCache(TokenCacheConfig{
		MaxEntryTTL:     60 * time.Second,
		CleanupInterval: time.Hour,
		Now:             func() time.Time { return now },
	})

	// Token already expired.
	payload := &TokenPayload{
		Subject:   "expired",
		ExpiresAt: now.Add(-1 * time.Second).Unix(),
	}
	cache.Put("tok-expired", payload)

	_, ok := cache.Get("tok-expired")
	assert.False(t, ok, "already-expired token should not be retrievable")
}

func TestTokenCache_Invalidate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cache := NewTokenCache(TokenCacheConfig{
		MaxEntryTTL:     60 * time.Second,
		CleanupInterval: time.Hour,
		Now:             func() time.Time { return now },
	})

	payload := &TokenPayload{Subject: "agent-1", ExpiresAt: now.Add(time.Hour).Unix()}
	cache.Put("tok1", payload)

	_, ok := cache.Get("tok1")
	require.True(t, ok)

	cache.Invalidate("tok1")

	_, ok = cache.Get("tok1")
	assert.False(t, ok, "entry should be gone after Invalidate")
	assert.Equal(t, 0, cache.Len())
}

func TestTokenCache_MaxSize(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cache := NewTokenCache(TokenCacheConfig{
		MaxEntryTTL:     time.Hour,
		MaxSize:         3,
		CleanupInterval: time.Hour,
		Now:             func() time.Time { return now },
	})

	payload := &TokenPayload{ExpiresAt: now.Add(time.Hour).Unix()}
	cache.Put("t1", payload)
	cache.Put("t2", payload)
	cache.Put("t3", payload)

	assert.Equal(t, 3, cache.Len())

	// Adding a 4th entry should evict the oldest (t1).
	cache.Put("t4", payload)
	assert.Equal(t, 3, cache.Len())

	_, ok := cache.Get("t1")
	assert.False(t, ok, "oldest entry should have been evicted")

	_, ok = cache.Get("t4")
	assert.True(t, ok, "newest entry should be present")
}

func TestTokenCache_BackgroundCleanup(t *testing.T) {
	// Use a very short cleanup interval to exercise the cleanup loop.
	now := time.Unix(1_700_000_000, 0)
	var nowVal atomic.Value
	nowVal.Store(now)

	cache := NewTokenCache(TokenCacheConfig{
		MaxEntryTTL:     5 * time.Second,
		MaxSize:         100,
		CleanupInterval: 50 * time.Millisecond,
		Now:             func() time.Time { return nowVal.Load().(time.Time) },
	})

	ctx, cancel := context.WithCancel(context.Background())
	cache.Start(ctx)
	t.Cleanup(cancel)

	payload := &TokenPayload{Subject: "a", ExpiresAt: now.Add(time.Hour).Unix()}
	cache.Put("tok1", payload)
	assert.Equal(t, 1, cache.Len())

	// Advance clock past MaxEntryTTL so the entry is expired.
	nowVal.Store(now.Add(10 * time.Second))

	// Wait for cleanup to run.
	require.Eventually(t, func() bool {
		return cache.Len() == 0
	}, 500*time.Millisecond, 10*time.Millisecond, "cleanup should remove expired entry")
}

func TestTokenCache_StopIdempotent(t *testing.T) {
	cache := NewTokenCache(TokenCacheConfig{})
	cache.Start(context.Background())
	cache.Stop()
	// Second Stop must not panic.
	cache.Stop()
}

func TestTokenCache_DifferentTokensSamePayload(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cache := NewTokenCache(TokenCacheConfig{
		MaxEntryTTL:     time.Hour,
		CleanupInterval: time.Hour,
		Now:             func() time.Time { return now },
	})

	p1 := &TokenPayload{Subject: "agent-1", ExpiresAt: now.Add(time.Hour).Unix()}
	p2 := &TokenPayload{Subject: "agent-2", ExpiresAt: now.Add(time.Hour).Unix()}

	cache.Put("tok1", p1)
	cache.Put("tok2", p2)

	got1, ok := cache.Get("tok1")
	require.True(t, ok)
	assert.Equal(t, "agent-1", got1.Subject)

	got2, ok := cache.Get("tok2")
	require.True(t, ok)
	assert.Equal(t, "agent-2", got2.Subject)
}

func TestTokenCache_PutUpdatesExistingEntry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var nowVal atomic.Value
	nowVal.Store(now)

	cache := NewTokenCache(TokenCacheConfig{
		MaxEntryTTL:     30 * time.Second,
		MaxSize:         10,
		CleanupInterval: time.Hour,
		Now:             func() time.Time { return nowVal.Load().(time.Time) },
	})

	// Put an entry that should expire in 5 seconds (token TTL capped).
	p1 := &TokenPayload{Subject: "v1", ExpiresAt: now.Add(5 * time.Second).Unix()}
	cache.Put("tok1", p1)
	assert.Equal(t, 1, cache.Len())

	// Put the same token key again with a longer-lived payload — size stays 1.
	p2 := &TokenPayload{Subject: "v2", ExpiresAt: now.Add(time.Hour).Unix()}
	cache.Put("tok1", p2)
	assert.Equal(t, 1, cache.Len())

	got, ok := cache.Get("tok1")
	require.True(t, ok)
	// The entry is updated; latest payload is returned.
	assert.Equal(t, "v2", got.Subject)
}
