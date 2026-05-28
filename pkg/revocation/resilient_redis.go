// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package revocation

import (
	"context"
	"time"

	"github.com/eunolabs/eunox/pkg/redisfailover"
)

// ResilientRedis wraps a revocation store with fail-closed semantics.
// When the backing store is unreachable:
//   - Tokens recently seen as revoked remain treated as revoked (from cache).
//   - Tokens not in the local cache are treated as revoked (fail-closed).
//
// This ensures that an outage cannot cause revoked tokens to be accepted.
type ResilientRedis struct {
	inner    Store
	cache    *redisfailover.FallbackCache[string, bool]
	reporter *redisfailover.Reporter
}

// ResilientRedisConfig configures the resilient wrapper.
type ResilientRedisConfig struct {
	// StaleTTL is how long a cached revocation status remains valid after
	// the last successful read. Default: 60s.
	StaleTTL time.Duration
}

// NewResilientRedis creates a fail-closed revocation store that falls back
// to a local cache when Redis is unreachable.
func NewResilientRedis(inner *Redis, reporter *redisfailover.Reporter, cfg *ResilientRedisConfig) *ResilientRedis {
	return NewResilientRedisFromStore(inner, reporter, cfg)
}

// NewResilientRedisFromStore creates a fail-closed revocation store wrapping
// any Store implementation. Useful for testing with in-memory stores.
func NewResilientRedisFromStore(inner Store, reporter *redisfailover.Reporter, cfg *ResilientRedisConfig) *ResilientRedis {
	staleTTL := 60 * time.Second
	if cfg != nil && cfg.StaleTTL > 0 {
		staleTTL = cfg.StaleTTL
	}

	return &ResilientRedis{
		inner: inner,
		cache: redisfailover.NewFallbackCache(redisfailover.FallbackCacheConfig[string, bool]{
			StaleTTL:     staleTTL,
			Policy:       redisfailover.FailClosed,
			DefaultValue: true, // Fail-closed: assume revoked if unknown
		}),
		reporter: reporter,
	}
}

// IsRevoked checks if a token is revoked. On store failure, returns true
// (fail-closed) unless the token is cached as not-revoked within the stale TTL.
func (r *ResilientRedis) IsRevoked(ctx context.Context, jti string) (bool, error) {
	revoked, err := r.inner.IsRevoked(ctx, jti)
	if err != nil {
		r.reporter.MarkDegraded()
		// Fall back to cache
		if cached, ok := r.cache.Get(jti); ok {
			return cached, nil
		}
		// No cache entry: fail-closed (assume revoked)
		return true, nil
	}

	r.reporter.MarkHealthy()
	r.cache.Put(jti, revoked)
	return revoked, nil
}

// Revoke marks a token as revoked. Updates both the backing store and local cache.
func (r *ResilientRedis) Revoke(ctx context.Context, jti string, ttl time.Duration) error {
	err := r.inner.Revoke(ctx, jti, ttl)
	if err != nil {
		r.reporter.MarkDegraded()
		// Still cache locally so subsequent IsRevoked calls see it
		r.cache.Put(jti, true)
		return err
	}
	r.reporter.MarkHealthy()
	r.cache.Put(jti, true)
	return nil
}
