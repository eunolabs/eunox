// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package capability

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// TokenCacheConfig configures the in-process capability token cache.
type TokenCacheConfig struct {
	// MaxEntryTTL is the maximum duration a verified token is retained in the
	// cache, regardless of its own expiry. Set to 0 to use the default (30 s).
	// Shorter values increase freshness (revocation propagates faster); longer
	// values reduce Redis round-trips per pipeline agent.
	MaxEntryTTL time.Duration

	// MaxSize is the maximum number of entries held in the cache. When the
	// limit is reached, the oldest entries are evicted. Set to 0 to use the
	// default (4096).
	MaxSize int

	// CleanupInterval controls how often the background goroutine scans for
	// and removes expired entries. Set to 0 to use the default (60 s).
	CleanupInterval time.Duration

	// Now is an optional clock function used for testing. Defaults to time.Now.
	Now func() time.Time
}

const (
	defaultMaxEntryTTL      = 30 * time.Second
	defaultMaxSize          = 4096
	defaultCleanupInterval  = 60 * time.Second
)

// tokenCacheEntry holds a cached token payload and its eviction deadline.
type tokenCacheEntry struct {
	payload    *TokenPayload
	expiresAt  time.Time
	insertedAt time.Time // for LRU-style eviction when MaxSize is reached
}

// TokenCache is an in-process LRU-like cache for verified capability token
// payloads. It is safe for concurrent use.
//
// On a cache hit, the gateway skips the JWKS signature re-verification and
// Redis revocation round-trip for tokens that were validated within the last
// MaxEntryTTL seconds. Fail-closed: a cache miss always falls through to the
// full verification path.
//
// Security trade-off: a revoked token whose JWTID has been added to the
// revocation store will continue to be accepted for at most MaxEntryTTL after
// the cache entry was populated. Operators should set MaxEntryTTL to a value
// shorter than their required revocation propagation SLA (the default of 30 s
// matches the sub-second propagation guarantee provided by the Redis kill-switch
// path).
//
// Start() must be called before the cache is used. Stop() or the context passed
// to Start() must be used to shut it down and release the background goroutine.
type TokenCache struct {
	cfg TokenCacheConfig
	mu  sync.RWMutex
	// entries is keyed by the hex-encoded SHA-256 of the raw token string so
	// that large tokens do not occupy significant key memory.
	entries map[string]*tokenCacheEntry
	// insertOrder tracks insertion order for MaxSize eviction.
	insertOrder []string
	stopCh      chan struct{}
	stopped     bool
}

// NewTokenCache creates a new TokenCache. Call Start() before use.
func NewTokenCache(cfg TokenCacheConfig) *TokenCache {
	if cfg.MaxEntryTTL <= 0 {
		cfg.MaxEntryTTL = defaultMaxEntryTTL
	}
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = defaultMaxSize
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = defaultCleanupInterval
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &TokenCache{
		cfg:         cfg,
		entries:     make(map[string]*tokenCacheEntry, cfg.MaxSize),
		insertOrder: make([]string, 0, cfg.MaxSize),
		stopCh:      make(chan struct{}),
	}
}

// Start launches the background cleanup goroutine. ctx cancellation is an
// alternative to calling Stop().
func (c *TokenCache) Start(ctx context.Context) {
	go c.cleanupLoop(ctx)
}

// Stop shuts down the background cleanup goroutine.
func (c *TokenCache) Stop() {
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return
	}
	c.stopped = true
	c.mu.Unlock()
	close(c.stopCh)
}

// Get returns the cached TokenPayload for tokenStr, or (nil, false) if the
// entry is absent or has expired. The returned payload must be treated as
// read-only.
func (c *TokenCache) Get(tokenStr string) (*TokenPayload, bool) {
	key := tokenKey(tokenStr)
	now := c.cfg.Now()

	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok {
		return nil, false
	}
	if now.After(entry.expiresAt) {
		// Expired — treat as miss; background cleanup will remove it.
		return nil, false
	}
	return entry.payload, true
}

// Put stores payload in the cache keyed by tokenStr. The entry TTL is
// min(cfg.MaxEntryTTL, time remaining until token expiry) so that the cache
// never serves a structurally expired token.
//
// If MaxSize would be exceeded the oldest-inserted entries are evicted.
func (c *TokenCache) Put(tokenStr string, payload *TokenPayload) {
	key := tokenKey(tokenStr)
	now := c.cfg.Now()

	// Determine eviction time: min(MaxEntryTTL, token's remaining lifetime).
	// Use sub-second precision (time.Unix(ExpiresAt, 0).Sub(now)) so that the
	// cache entry never outlives the token by up to one full second, which
	// could otherwise happen with integer-second truncation.
	entryTTL := c.cfg.MaxEntryTTL
	if payload.ExpiresAt > 0 {
		tokenRemaining := time.Unix(payload.ExpiresAt, 0).Sub(now)
		if tokenRemaining <= 0 {
			// Token is already expired; nothing to cache.
			return
		}
		if tokenRemaining < entryTTL {
			entryTTL = tokenRemaining
		}
	}

	entry := &tokenCacheEntry{
		payload:    payload,
		expiresAt:  now.Add(entryTTL),
		insertedAt: now,
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.entries[key]; !exists {
		// Evict oldest entries if at capacity.
		for len(c.entries) >= c.cfg.MaxSize && len(c.insertOrder) > 0 {
			oldest := c.insertOrder[0]
			c.insertOrder = c.insertOrder[1:]
			delete(c.entries, oldest)
		}
		c.insertOrder = append(c.insertOrder, key)
	}
	c.entries[key] = entry
}

// Invalidate removes a specific token from the cache immediately. This is
// called on explicit revocation events so that the cached entry does not
// outlive the propagation of the revocation.
func (c *TokenCache) Invalidate(tokenStr string) {
	key := tokenKey(tokenStr)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[key]; ok {
		delete(c.entries, key)
		// Remove from insertOrder without preserving order for simplicity.
		for i, k := range c.insertOrder {
			if k == key {
				c.insertOrder = append(c.insertOrder[:i], c.insertOrder[i+1:]...)
				break
			}
		}
	}
}

// Len returns the number of entries currently held in the cache (including
// entries that have expired but not yet been cleaned up).
func (c *TokenCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// cleanupLoop removes expired entries at the configured interval.
func (c *TokenCache) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(c.cfg.CleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.purgeExpired()
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		}
	}
}

func (c *TokenCache) purgeExpired() {
	now := c.cfg.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, key)
		}
	}
	// Rebuild insertOrder to remove evicted keys.
	surviving := c.insertOrder[:0]
	for _, k := range c.insertOrder {
		if _, ok := c.entries[k]; ok {
			surviving = append(surviving, k)
		}
	}
	c.insertOrder = surviving
}

// tokenKey returns the cache key for a raw token string. Using a fixed-size
// hash prevents large tokens from inflating key memory.
func tokenKey(tokenStr string) string {
	h := sha256.Sum256([]byte(tokenStr))
	return hex.EncodeToString(h[:])
}
