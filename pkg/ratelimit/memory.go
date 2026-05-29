// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package ratelimit

import (
	"context"
	"sync"
	"time"
)

type memoryEntry struct {
	timestamps []time.Time
}

// InMemoryLimiter implements rate limiting using an in-memory sliding window.
type InMemoryLimiter struct {
	mu              sync.Mutex
	cfg             Config
	entries         map[string]*memoryEntry
	now             func() time.Time
	cleanupInterval time.Duration
	stopCh          chan struct{}
	stopOnce        sync.Once
}

// NewInMemory creates an in-memory sliding-window rate limiter.
func NewInMemory(cfg Config) *InMemoryLimiter {
	limiter := &InMemoryLimiter{
		cfg:             cfg,
		entries:         make(map[string]*memoryEntry),
		now:             time.Now,
		cleanupInterval: defaultCleanupInterval(cfg.Window),
		stopCh:          make(chan struct{}),
	}

	if limiter.cleanupInterval > 0 {
		go limiter.cleanupLoop()
	}

	return limiter
}

// Allow checks whether the request for key is allowed.
func (l *InMemoryLimiter) Allow(ctx context.Context, key string) (bool, error) {
	result, err := l.Check(ctx, key)
	if err != nil {
		return false, err
	}
	return result.Allowed, nil
}

// Check checks the rate limit for key and returns detailed result information.
func (l *InMemoryLimiter) Check(_ context.Context, key string) (*Result, error) {
	if err := l.cfg.validate(); err != nil {
		return nil, err
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	entry := l.entries[key]
	if entry == nil {
		entry = &memoryEntry{}
		l.entries[key] = entry
	}

	entry.timestamps = pruneTimestamps(entry.timestamps, now, l.cfg.Window)
	limit := l.cfg.limit()

	if len(entry.timestamps) >= limit {
		retryAfter := timeUntilReset(entry.timestamps, now, l.cfg.Window)
		return &Result{
			Allowed:    false,
			Remaining:  0,
			ResetAfter: retryAfter,
			RetryAfter: retryAfter,
		}, nil
	}

	entry.timestamps = append(entry.timestamps, now)
	resetAfter := timeUntilReset(entry.timestamps, now, l.cfg.Window)

	return &Result{
		Allowed:    true,
		Remaining:  limit - len(entry.timestamps),
		ResetAfter: resetAfter,
	}, nil
}

// Cleanup removes expired entries from memory.
func (l *InMemoryLimiter) Cleanup() {
	if l == nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.cleanupExpiredLocked(l.now())
}

// Close stops the background cleanup loop.
func (l *InMemoryLimiter) Close() {
	if l == nil {
		return
	}

	l.stopOnce.Do(func() {
		close(l.stopCh)
	})
}

func (l *InMemoryLimiter) cleanupLoop() {
	ticker := time.NewTicker(l.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			l.Cleanup()
		case <-l.stopCh:
			return
		}
	}
}

func (l *InMemoryLimiter) cleanupExpiredLocked(now time.Time) {
	for key, entry := range l.entries {
		entry.timestamps = pruneTimestamps(entry.timestamps, now, l.cfg.Window)
		if len(entry.timestamps) == 0 {
			delete(l.entries, key)
		}
	}
}

func pruneTimestamps(timestamps []time.Time, now time.Time, window time.Duration) []time.Time {
	cutoff := now.Add(-window)
	kept := timestamps[:0]
	for _, ts := range timestamps {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	return kept
}

func timeUntilReset(timestamps []time.Time, now time.Time, window time.Duration) time.Duration {
	if len(timestamps) == 0 {
		return 0
	}
	return clampDuration(timestamps[0].Add(window).Sub(now))
}

func defaultCleanupInterval(window time.Duration) time.Duration {
	if window <= 0 {
		return 0
	}
	interval := window / 2
	if interval < time.Second {
		interval = time.Second
	}
	if interval > time.Minute {
		interval = time.Minute
	}
	return interval
}
