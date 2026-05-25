// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package posture

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRecordStore_Upsert_NewRecord(t *testing.T) {
	store := NewRecordStore(5 * time.Minute)

	record := AgentInventoryRecord{
		AgentID:    "agent-1",
		OwningTeam: "team-a",
		FirstSeen:  time.Now(),
		LastSeen:   time.Now(),
	}

	// New record should emit.
	assert.True(t, store.Upsert(record))
	assert.Equal(t, 1, store.Size())
}

func TestRecordStore_Upsert_DeduplicateWithinWindow(t *testing.T) {
	store := NewRecordStore(5 * time.Minute)

	now := time.Now()
	record := AgentInventoryRecord{
		AgentID:  "agent-1",
		FirstSeen: now,
		LastSeen:  now,
	}

	assert.True(t, store.Upsert(record))

	// Same agent within window: should not emit.
	record.LastSeen = now.Add(1 * time.Minute)
	assert.False(t, store.Upsert(record))
}

func TestRecordStore_Upsert_EmitOutsideWindow(t *testing.T) {
	store := NewRecordStore(5 * time.Minute)

	now := time.Now()
	record := AgentInventoryRecord{
		AgentID:  "agent-1",
		FirstSeen: now,
		LastSeen:  now,
	}

	assert.True(t, store.Upsert(record))

	// Same agent outside window: should emit.
	record.LastSeen = now.Add(6 * time.Minute)
	assert.True(t, store.Upsert(record))
}

func TestRecordStore_Upsert_PreservesFirstSeen(t *testing.T) {
	store := NewRecordStore(5 * time.Minute)

	firstSeen := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	record := AgentInventoryRecord{
		AgentID:  "agent-1",
		FirstSeen: firstSeen,
		LastSeen:  firstSeen,
	}
	store.Upsert(record)

	// Emit again outside window with different firstSeen.
	record.FirstSeen = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	record.LastSeen = firstSeen.Add(10 * time.Minute)
	store.Upsert(record)

	active := store.ListActive()
	assert.Len(t, active, 1)
	assert.Equal(t, firstSeen, active[0].FirstSeen)
}

func TestRecordStore_Upsert_RevokedAgentNotReemitted(t *testing.T) {
	store := NewRecordStore(5 * time.Minute)

	now := time.Now()
	record := AgentInventoryRecord{
		AgentID:  "agent-1",
		FirstSeen: now,
		LastSeen:  now,
	}

	store.Upsert(record)
	store.MarkRevoked("agent-1", now.Add(1*time.Minute))

	// Try to re-emit the revoked agent.
	record.LastSeen = now.Add(10 * time.Minute)
	assert.False(t, store.Upsert(record))
}

func TestRecordStore_MarkRevoked(t *testing.T) {
	store := NewRecordStore(5 * time.Minute)

	now := time.Now()
	record := AgentInventoryRecord{
		AgentID:    "agent-1",
		OwningTeam: "team-a",
		FirstSeen:  now,
		LastSeen:   now,
	}

	store.Upsert(record)

	// Mark as revoked.
	revokedAt := now.Add(5 * time.Minute)
	revoked := store.MarkRevoked("agent-1", revokedAt)
	assert.NotNil(t, revoked)
	assert.Equal(t, "agent-1", revoked.AgentID)
	assert.NotNil(t, revoked.RevokedAt)
	assert.Equal(t, revokedAt, *revoked.RevokedAt)
}

func TestRecordStore_MarkRevoked_NotFound(t *testing.T) {
	store := NewRecordStore(5 * time.Minute)

	revoked := store.MarkRevoked("nonexistent", time.Now())
	assert.Nil(t, revoked)
}

func TestRecordStore_ListActive(t *testing.T) {
	store := NewRecordStore(5 * time.Minute)

	now := time.Now()
	store.Upsert(AgentInventoryRecord{AgentID: "agent-1", FirstSeen: now, LastSeen: now})
	store.Upsert(AgentInventoryRecord{AgentID: "agent-2", FirstSeen: now, LastSeen: now})
	store.Upsert(AgentInventoryRecord{AgentID: "agent-3", FirstSeen: now, LastSeen: now})

	store.MarkRevoked("agent-2", now.Add(1*time.Minute))

	active := store.ListActive()
	assert.Len(t, active, 2)

	ids := make(map[string]bool)
	for _, r := range active {
		ids[r.AgentID] = true
	}
	assert.True(t, ids["agent-1"])
	assert.True(t, ids["agent-3"])
	assert.False(t, ids["agent-2"])
}

func TestRecordStore_Size(t *testing.T) {
	store := NewRecordStore(5 * time.Minute)

	now := time.Now()
	store.Upsert(AgentInventoryRecord{AgentID: "agent-1", FirstSeen: now, LastSeen: now})
	store.Upsert(AgentInventoryRecord{AgentID: "agent-2", FirstSeen: now, LastSeen: now})

	// Size includes revoked.
	store.MarkRevoked("agent-1", now)
	assert.Equal(t, 2, store.Size())
}
