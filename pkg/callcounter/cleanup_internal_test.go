// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package callcounter

import (
	"testing"
	"time"
)

// TestInMemory_Cleanup_EmptyTimestamps exercises the defensive branch in Cleanup
// that removes entries whose timestamp slice is empty.  This state cannot be
// produced via the public IncrementAndGet API (which always appends the current
// time), so we inject it directly through the internal entries map.
func TestInMemory_Cleanup_EmptyTimestamps(t *testing.T) {
	t.Parallel()
	m := NewInMemory()

	// Directly inject an entry with zero timestamps into the internal map.
	// This simulates a corrupt or zeroed-out entry that Cleanup must remove.
	m.mu.Lock()
	m.entries["ghost-key"] = &entry{timestamps: nil}
	m.mu.Unlock()

	// Cleanup must delete the entry without panicking.
	m.Cleanup()

	m.mu.Lock()
	_, stillPresent := m.entries["ghost-key"]
	m.mu.Unlock()

	if stillPresent {
		t.Error("Cleanup must remove entries with zero timestamps")
	}
}

// TestInMemory_Cleanup_StaleEntry verifies that Cleanup removes entries whose
// most-recent timestamp is more than 24 hours old.
func TestInMemory_Cleanup_StaleEntry(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	m := NewInMemory(WithTimeFunc(func() time.Time { return now }))

	// Record a call at t=0.
	m.mu.Lock()
	m.entries["stale-key"] = &entry{
		timestamps: []time.Time{now.Add(-25 * time.Hour)},
	}
	m.mu.Unlock()

	// Advance the clock by 26 hours so the entry is > 24 h old.
	now = now.Add(26 * time.Hour)
	m.Cleanup()

	m.mu.Lock()
	_, stillPresent := m.entries["stale-key"]
	m.mu.Unlock()

	if stillPresent {
		t.Error("Cleanup must remove entries whose most-recent timestamp is > 24 h old")
	}
}
