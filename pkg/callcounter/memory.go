// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package callcounter

import (
	"context"
	"sync"
	"time"
)

// entry tracks call timestamps for sliding window counting.
type entry struct {
	timestamps []time.Time
}

// InMemory is a sliding-window call counter backed by in-process memory.
// Suitable for single-replica deployments or testing.
type InMemory struct {
	mu      sync.Mutex
	entries map[string]*entry
	now     func() time.Time
}

// InMemoryOption configures the InMemory counter.
type InMemoryOption func(*InMemory)

// WithTimeFunc sets a custom time function (for testing).
func WithTimeFunc(fn func() time.Time) InMemoryOption {
	return func(m *InMemory) {
		m.now = fn
	}
}

// NewInMemory creates an in-memory sliding-window call counter.
func NewInMemory(opts ...InMemoryOption) *InMemory {
	m := &InMemory{
		entries: make(map[string]*entry),
		now:     time.Now,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// IncrementAndGet records a call and returns the number of calls within the window.
func (m *InMemory) IncrementAndGet(_ context.Context, key string, windowSec int) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	window := time.Duration(windowSec) * time.Second
	cutoff := now.Add(-window)

	e, ok := m.entries[key]
	if !ok {
		e = &entry{}
		m.entries[key] = e
	}

	// Remove expired timestamps
	valid := e.timestamps[:0]
	for _, ts := range e.timestamps {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}

	// Add current timestamp
	valid = append(valid, now)
	e.timestamps = valid

	return int64(len(valid)), nil
}

// Cleanup removes expired entries. Call periodically to prevent memory growth.
func (m *InMemory) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	for key, e := range m.entries {
		if len(e.timestamps) == 0 {
			delete(m.entries, key)
			continue
		}
		// If the most recent timestamp is old enough, the whole entry is stale
		if e.timestamps[len(e.timestamps)-1].Before(now.Add(-24 * time.Hour)) {
			delete(m.entries, key)
		}
	}
}
