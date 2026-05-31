// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

import (
	"container/list"
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
	defaultMaxEntryTTL     = 30 * time.Second
	defaultMaxSize         = 4096
	defaultCleanupInterval = 60 * time.Second
)

// tokenCacheEntry holds a cached token payload, its eviction deadline, and a
// pointer to its node in the insertion-order list.
type tokenCacheEntry struct {
	payload    *TokenPayload
	expiresAt  time.Time
	insertedAt time.Time
	listElem   *list.Element // back-pointer for O(1) removal from insertOrder
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
	// insertOrder is a doubly-linked list of cache keys in insertion order
	// (front = oldest). Each tokenCacheEntry holds a back-pointer to its list
	// element, enabling O(1) eviction in both Put (oldest entry) and Invalidate
	// (arbitrary entry). M-5 fix: replaced []string slice (O(n) removal) with
	// container/list.
	insertOrder *list.List
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
		insertOrder: list.New(),
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
		// Evict oldest entries if at capacity (O(1): remove front of list).
		for c.insertOrder.Len() >= c.cfg.MaxSize {
			front := c.insertOrder.Front()
			if front == nil {
				break
			}
			oldest := front.Value.(string)
			c.insertOrder.Remove(front)
			delete(c.entries, oldest)
		}
		// Add new key to back of list and store the element pointer.
		elem := c.insertOrder.PushBack(key)
		entry.listElem = elem
	}
	c.entries[key] = entry
}

// Invalidate removes a specific token from the cache immediately. This is
// called on explicit revocation events so that the cached entry does not
// outlive the propagation of the revocation.
//
// M-5 fix: removal is now O(1) — each entry holds a back-pointer to its
// node in the insertion-order doubly-linked list.
func (c *TokenCache) Invalidate(tokenStr string) {
	key := tokenKey(tokenStr)
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.entries[key]; ok {
		delete(c.entries, key)
		if entry.listElem != nil {
			c.insertOrder.Remove(entry.listElem)
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
			if entry.listElem != nil {
				c.insertOrder.Remove(entry.listElem)
			}
		}
	}
}

// tokenKey returns the cache key for a raw token string. Using a fixed-size
// hash prevents large tokens from inflating key memory.
func tokenKey(tokenStr string) string {
	h := sha256.Sum256([]byte(tokenStr))
	return hex.EncodeToString(h[:])
}
