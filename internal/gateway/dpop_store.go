// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"context"
	"sync"
	"time"
)

// InMemoryDPoPStore is an in-memory DPoP JTI replay detection store.
type InMemoryDPoPStore struct {
	mu      sync.Mutex
	seen    map[string]time.Time
	ttl     time.Duration
	now     func() time.Time
}

// NewInMemoryDPoPStore creates a new in-memory DPoP replay detection store.
// Proofs are remembered for the given TTL.
func NewInMemoryDPoPStore(ttl time.Duration) *InMemoryDPoPStore {
	return &InMemoryDPoPStore{
		seen: make(map[string]time.Time),
		ttl:  ttl,
		now:  time.Now,
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

	// Periodic cleanup: remove expired entries
	if len(s.seen) > 1000 {
		for k, v := range s.seen {
			if now.Sub(v) >= s.ttl {
				delete(s.seen, k)
			}
		}
	}

	return false, nil
}
