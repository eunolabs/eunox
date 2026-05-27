// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package minter

import (
	"context"
	"sort"
	"sync"
	"time"
)

// InMemoryStore implements KeyStore with in-memory maps. Suitable for testing and development.
type InMemoryStore struct {
	mu       sync.RWMutex
	keys     map[string]*APIKey
	policies map[string]*Policy
}

// NewInMemoryStore creates a new in-memory key store.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		keys:     make(map[string]*APIKey),
		policies: make(map[string]*Policy),
	}
}

// CreateKey implements KeyStore.
func (s *InMemoryStore) CreateKey(_ context.Context, key *APIKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[key.KeyID] = key
	return nil
}

// GetKey implements KeyStore.
func (s *InMemoryStore) GetKey(_ context.Context, keyID string) (*APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return k, nil
}

// CountKeys implements KeyStore.
func (s *InMemoryStore) CountKeys(_ context.Context, tenantID string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, k := range s.keys {
		if k.TenantID == tenantID {
			count++
		}
	}
	return count, nil
}

// ListKeys implements KeyStore.
func (s *InMemoryStore) ListKeys(_ context.Context, tenantID string, limit, offset int) ([]*APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*APIKey, 0, len(s.keys))
	for _, k := range s.keys {
		if k.TenantID == tenantID {
			result = append(result, k)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].KeyID < result[j].KeyID
		}
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})

	if offset >= len(result) {
		return nil, nil
	}
	result = result[offset:]
	if limit > 0 && limit < len(result) {
		result = result[:limit]
	}
	return result, nil
}

// RevokeKey implements KeyStore.
// It marks the key as revoked and returns a copy of the key with RevokedAt set.
// The returned snapshot is safe for the caller to use without re-querying the store,
// eliminating the TOCTOU race that arises from a separate GetKey call (CR-5).
func (s *InMemoryStore) RevokeKey(_ context.Context, keyID string, revokedAt time.Time) (*APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}
	if k.RevokedAt != nil {
		return nil, ErrKeyRevoked
	}
	k.RevokedAt = &revokedAt
	// Return a shallow copy so the caller's snapshot is stable even if the
	// in-memory entry is mutated later.
	snapshot := *k
	return &snapshot, nil
}

// CreatePolicy implements KeyStore.
func (s *InMemoryStore) CreatePolicy(_ context.Context, p *Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check for name uniqueness within tenant.
	for _, existing := range s.policies {
		if existing.TenantID == p.TenantID && existing.Name == p.Name {
			return ErrPolicyExists
		}
	}
	s.policies[p.PolicyID] = p
	return nil
}

// GetPolicy implements KeyStore.
func (s *InMemoryStore) GetPolicy(_ context.Context, policyID string) (*Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[policyID]
	if !ok {
		return nil, ErrPolicyNotFound
	}
	return p, nil
}

// GetPolicyByName implements KeyStore.
func (s *InMemoryStore) GetPolicyByName(_ context.Context, tenantID, name string) (*Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.policies {
		if p.TenantID == tenantID && p.Name == name {
			return p, nil
		}
	}
	return nil, ErrPolicyNotFound
}

// ListPolicies implements KeyStore.
func (s *InMemoryStore) ListPolicies(_ context.Context, tenantID string) ([]*Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Policy
	for _, p := range s.policies {
		if p.TenantID == tenantID {
			result = append(result, p)
		}
	}
	return result, nil
}

// UpdatePolicy implements KeyStore.
func (s *InMemoryStore) UpdatePolicy(_ context.Context, p *Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.policies[p.PolicyID]; !ok {
		return ErrPolicyNotFound
	}
	s.policies[p.PolicyID] = p
	return nil
}

// DeletePolicy implements KeyStore.
func (s *InMemoryStore) DeletePolicy(_ context.Context, policyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.policies[policyID]; !ok {
		return ErrPolicyNotFound
	}
	delete(s.policies, policyID)
	return nil
}
