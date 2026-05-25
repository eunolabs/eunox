// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package revocation

import (
	"context"
	"sync"
	"time"
)

type revokedEntry struct {
	expiresAt time.Time // zero means no expiry
}

// InMemory is an in-memory revocation store for single-replica or testing use.
type InMemory struct {
	mu      sync.RWMutex
	entries map[string]revokedEntry
	now     func() time.Time
}

// InMemoryOption configures the InMemory store.
type InMemoryOption func(*InMemory)

// WithTimeFunc sets a custom time function (for testing).
func WithTimeFunc(fn func() time.Time) InMemoryOption {
	return func(m *InMemory) {
		m.now = fn
	}
}

// NewInMemory creates an in-memory revocation store.
func NewInMemory(opts ...InMemoryOption) *InMemory {
	m := &InMemory{
		entries: make(map[string]revokedEntry),
		now:     time.Now,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// IsRevoked checks whether a token has been revoked.
func (m *InMemory) IsRevoked(_ context.Context, jti string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, exists := m.entries[jti]
	if !exists {
		return false, nil
	}

	// Check if the revocation has expired
	if !entry.expiresAt.IsZero() && m.now().After(entry.expiresAt) {
		return false, nil
	}

	return true, nil
}

// Revoke marks a token as revoked.
func (m *InMemory) Revoke(_ context.Context, jti string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = m.now().Add(ttl)
	}

	m.entries[jti] = revokedEntry{expiresAt: expiresAt}
	return nil
}

// Cleanup removes expired entries. Call periodically to prevent memory growth.
func (m *InMemory) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	for jti, entry := range m.entries {
		if !entry.expiresAt.IsZero() && now.After(entry.expiresAt) {
			delete(m.entries, jti)
		}
	}
}
