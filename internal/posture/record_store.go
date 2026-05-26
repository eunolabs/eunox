// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package posture

import (
	"sync"
	"time"
)

// DefaultDedupeWindow is the default deduplication window for record emission.
const DefaultDedupeWindow = 5 * time.Minute

// InMemoryRecordStore implements RecordStore with an in-memory map.
// It tracks observed agents and applies deduplication to suppress redundant emissions.
type InMemoryRecordStore struct {
	mu           sync.RWMutex
	records      map[string]AgentInventoryRecord
	dedupeWindow time.Duration
}

// NewRecordStore creates a new InMemoryRecordStore with the given deduplication window.
func NewRecordStore(dedupeWindow time.Duration) *InMemoryRecordStore {
	if dedupeWindow < 0 {
		dedupeWindow = DefaultDedupeWindow
	}
	return &InMemoryRecordStore{
		records:      make(map[string]AgentInventoryRecord),
		dedupeWindow: dedupeWindow,
	}
}

// Upsert adds or updates a record. Returns true if the record should be emitted
// (new record or outside dedupe window).
func (s *InMemoryRecordStore) Upsert(record AgentInventoryRecord) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, found := s.records[record.AgentID]
	if !found {
		s.records[record.AgentID] = record
		return true
	}

	// Don't re-emit revoked agents.
	if existing.RevokedAt != nil {
		return false
	}

	// Deduplicate within window.
	if s.dedupeWindow > 0 && record.LastSeen.Sub(existing.LastSeen) < s.dedupeWindow {
		// Update lastSeen but suppress emission.
		existing.LastSeen = record.LastSeen
		s.records[record.AgentID] = existing
		return false
	}

	// Outside dedupe window: emit.
	record.FirstSeen = existing.FirstSeen // preserve original firstSeen
	s.records[record.AgentID] = record
	return true
}

// MarkRevoked marks an agent as revoked. Returns the record if found.
func (s *InMemoryRecordStore) MarkRevoked(agentID string, revokedAt time.Time) *AgentInventoryRecord {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, found := s.records[agentID]
	if !found {
		return nil
	}

	rec.RevokedAt = &revokedAt
	s.records[agentID] = rec
	return &rec
}

// ListActive returns all non-revoked records.
func (s *InMemoryRecordStore) ListActive() []AgentInventoryRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var active []AgentInventoryRecord
	for _, rec := range s.records {
		if rec.RevokedAt == nil {
			active = append(active, rec)
		}
	}
	return active
}

// Size returns the total number of tracked records.
func (s *InMemoryRecordStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.records)
}

// Compile-time interface check.
var _ RecordStore = (*InMemoryRecordStore)(nil)
