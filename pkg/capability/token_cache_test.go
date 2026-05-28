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

func TestTokenCache_SubSecondPrecision(t *testing.T) {
	// With integer-second truncation the cache entry TTL is rounded up by up
	// to 1 second relative to the token's actual expiry, causing the cache to
	// serve the token past its ExpiresAt time.
	//
	// Scenario:
	//   base = 1000.0s Unix
	//   now at Put = base + 0.5s  (1000.5s)
	//   token ExpiresAt = base + 1s Unix == 1001s  (0.5s from now)
	//
	// Old (integer arithmetic):
	//   tokenRemaining = (1001 - 1000) * second = 1s      ← overshoot by 0.5s
	//   entryExpiresAt = 1000.5 + 1s = 1001.5s
	//   → token still served at 1001.1s (0.1s PAST actual expiry) ← BUG
	//
	// New (sub-second):
	//   tokenRemaining = time.Unix(1001, 0).Sub(1000.5s) = 0.5s
	//   entryExpiresAt = 1000.5s + 0.5s = 1001.0s == ExpiresAt  ← correct
	//   → token not served at 1001.1s                             ← FIXED

	base := time.Unix(1000, 0)
	now := base.Add(500 * time.Millisecond) // 1000.5s: halfway through the expiry second

	cache := NewTokenCache(TokenCacheConfig{
		MaxEntryTTL: 30 * time.Second,
		Now:         func() time.Time { return now },
	})

	payload := &TokenPayload{
		Subject:   "user-1",
		ExpiresAt: base.Unix() + 1, // expires at 1001s exactly
	}
	cache.Put("tok", payload)

	// 100ms before expiry (1000.9s): must still be a hit.
	now = base.Add(900 * time.Millisecond)
	_, ok := cache.Get("tok")
	assert.True(t, ok, "token with 100ms remaining must be a cache hit")

	// 100ms after expiry (1001.1s): must be a miss.
	// With the old integer-second code the entry would have expired at 1001.5s
	// and would still be served here — this assertion catches the regression.
	now = base.Add(1100 * time.Millisecond)
	_, ok = cache.Get("tok")
	assert.False(t, ok, "token must not be served 100ms after its ExpiresAt timestamp")
}
