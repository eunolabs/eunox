// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/edgeobs/eunox/pkg/redisfailover"
	"github.com/redis/go-redis/v9"
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

// RedisDPoPStore is a Redis-backed DPoP JTI replay detection store.
//
// Each JTI is stored as a Redis key with an expiry equal to the configured TTL,
// using SET NX (set-if-not-exists) so that the first write succeeds and all
// subsequent writes to the same key are rejected.  Redis manages expiry natively
// — no background cleanup goroutine is required.
type RedisDPoPStore struct {
	client redis.Cmdable
	ttl    time.Duration
}

// NewRedisDPoPStore creates a Redis-backed DPoP JTI replay detection store.
// The client must already be connected; the caller retains ownership.
func NewRedisDPoPStore(client redis.Cmdable, ttl time.Duration) *RedisDPoPStore {
	return &RedisDPoPStore{client: client, ttl: ttl}
}

// MarkUsed sets the JTI in Redis with an NX flag.
// Returns (true, nil) when the JTI was already present (replay detected).
// Returns (false, nil) when the JTI was newly recorded.
func (s *RedisDPoPStore) MarkUsed(ctx context.Context, jti string) (bool, error) {
	key := "dpop:jti:" + jti
	// SetNX returns true when the key did NOT previously exist (first use).
	ok, err := s.client.SetNX(ctx, key, 1, s.ttl).Result()
	if err != nil {
		return false, err
	}
	// ok = true  → key was set (first use, not a replay)
	// ok = false → key already existed (replay detected)
	return !ok, nil
}

// ResilientRedisDPoPStore wraps a [RedisDPoPStore] with fail-closed semantics.
//
// When Redis is unreachable, MarkUsed returns (true, nil) — treating the proof
// as already-used — so that DPoP-protected requests are denied rather than
// silently bypassing replay protection.  This matches the kill-switch and
// revocation fail-closed pattern used throughout the gateway.
type ResilientRedisDPoPStore struct {
	primary  *RedisDPoPStore
	reporter *redisfailover.Reporter
	logger   *slog.Logger
}

// NewResilientRedisDPoPStore creates a fail-closed resilient DPoP JTI store.
func NewResilientRedisDPoPStore(primary *RedisDPoPStore, reporter *redisfailover.Reporter, logger *slog.Logger) *ResilientRedisDPoPStore {
	if logger == nil {
		logger = slog.Default()
	}
	return &ResilientRedisDPoPStore{
		primary:  primary,
		reporter: reporter,
		logger:   logger,
	}
}

// MarkUsed checks replay protection against Redis.
//
// Failure policy: FAIL-CLOSED — when Redis is unreachable the method returns
// (true, nil), signalling a replay to the caller so that the request is denied.
// This is intentionally stricter than fail-open: a DPoP replay attack must not
// succeed just because Redis is temporarily unavailable.
func (s *ResilientRedisDPoPStore) MarkUsed(ctx context.Context, jti string) (bool, error) {
	alreadyUsed, err := s.primary.MarkUsed(ctx, jti)
	if err != nil {
		s.reporter.MarkDegraded()
		s.logger.Warn("DPoP store: Redis unavailable; failing closed — treating proof as replayed",
			slog.String("jti_prefix", safeJTIPrefix(jti)))
		// Fail-closed: deny the request by reporting the JTI as already used.
		return true, nil
	}
	s.reporter.MarkHealthy()
	return alreadyUsed, nil
}

// safeJTIPrefixLen is the number of characters of a JTI that are safe to log
// for correlation without exposing the full token identifier.
const safeJTIPrefixLen = 8

// safeJTIPrefix returns the first safeJTIPrefixLen characters of a JTI for log context
// without exposing the full value.
func safeJTIPrefix(jti string) string {
	if len(jti) <= safeJTIPrefixLen {
		return jti
	}
	return jti[:safeJTIPrefixLen] + "…"
}
