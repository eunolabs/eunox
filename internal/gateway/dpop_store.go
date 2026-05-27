// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"context"
	"sync"
	"time"
)

// defaultDPoPCleanupInterval is the default interval between background
// cleanup sweeps for InMemoryDPoPStore.
const defaultDPoPCleanupInterval = 2 * time.Minute

// InMemoryDPoPStore is an in-memory DPoP JTI replay detection store.
//
// Call [InMemoryDPoPStore.Start] to begin the background cleanup goroutine that
// removes expired entries.  Without Start, expired entries are still evicted on
// write (when the map grows past 1000 entries), but memory usage is bounded
// only on write — not over time.
type InMemoryDPoPStore struct {
	mu              sync.Mutex
	seen            map[string]time.Time
	ttl             time.Duration
	now             func() time.Time
	cleanupInterval time.Duration
}

// NewInMemoryDPoPStore creates a new in-memory DPoP replay detection store.
// Proofs are remembered for the given TTL.  A background cleanup goroutine is
// started via [InMemoryDPoPStore.Start].
func NewInMemoryDPoPStore(ttl time.Duration) *InMemoryDPoPStore {
	return &InMemoryDPoPStore{
		seen:            make(map[string]time.Time),
		ttl:             ttl,
		now:             time.Now,
		cleanupInterval: defaultDPoPCleanupInterval,
	}
}

// Start launches a background goroutine that periodically removes expired JTI
// entries from the store.  The goroutine runs until ctx is cancelled.
//
// Start should be called once after construction.  It is safe to use the store
// before calling Start, but expired entries will only be evicted on write (when
// the seen-map exceeds 1000 entries) rather than on the cleanup interval.
func (s *InMemoryDPoPStore) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(s.cleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.cleanup()
			}
		}
	}()
}

// cleanup removes all expired entries from the seen map.
func (s *InMemoryDPoPStore) cleanup() {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.seen {
		if now.Sub(v) >= s.ttl {
			delete(s.seen, k)
		}
	}
}

// MarkUsed attempts to mark a DPoP JTI as used.
// Returns true if it was already used (replay detected).
func (s *InMemoryDPoPStore) MarkUsed(_ context.Context, jti string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()

	// Check if already seen and not expired
	if seenAt, exists := s.seen[jti]; exists {
		if now.Sub(seenAt) < s.ttl {
			return true, nil
		}
	}

	s.seen[jti] = now

	// Eager cleanup: remove expired entries when the map grows large to bound
	// worst-case memory between background sweeps.
	if len(s.seen) > 1000 {
		for k, v := range s.seen {
			if now.Sub(v) >= s.ttl {
				delete(s.seen, k)
			}
		}
	}

	return false, nil
}
