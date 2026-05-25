// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/edgeobs/euno-platform/euno-go/internal/gateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockTelemetrySink struct {
	mu     sync.Mutex
	events []gateway.TelemetryEvent
	err    error
}

func (m *mockTelemetrySink) Send(events []gateway.TelemetryEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.events = append(m.events, events...)
	return nil
}

func (m *mockTelemetrySink) getEvents() []gateway.TelemetryEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]gateway.TelemetryEvent(nil), m.events...)
}

func TestTelemetryCollector_Disabled(t *testing.T) {
	tc := gateway.NewTelemetryCollector(gateway.TelemetryCollectorConfig{
		Enabled: false,
	})

	tc.Record(gateway.TelemetryEvent{
		TenantID:   "tenant-1",
		Subcommand: "test",
	})

	assert.Equal(t, 0, tc.BufferLen())
}

func TestTelemetryCollector_RecordsEvents(t *testing.T) {
	tc := gateway.NewTelemetryCollector(gateway.TelemetryCollectorConfig{
		Enabled:  true,
		TenantID: "default-tenant",
	})

	tc.Record(gateway.TelemetryEvent{
		TenantID:   "tenant-1",
		Subcommand: "hosted-enforce",
		Metrics:    map[string]any{"decision": "allow"},
	})

	tc.Record(gateway.TelemetryEvent{
		Subcommand: "test-event",
	})

	assert.Equal(t, 2, tc.BufferLen())
}

func TestTelemetryCollector_RecordEnforcement(t *testing.T) {
	tc := gateway.NewTelemetryCollector(gateway.TelemetryCollectorConfig{
		Enabled:  true,
		TenantID: "t1",
	})

	tc.RecordEnforcement("tenant-x", "allow", 5*time.Millisecond)
	assert.Equal(t, 1, tc.BufferLen())
}

func TestTelemetryCollector_FlushSendsToSink(t *testing.T) {
	sink := &mockTelemetrySink{}
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	tc := gateway.NewTelemetryCollector(gateway.TelemetryCollectorConfig{
		Enabled:  true,
		TenantID: "tenant-flush",
		Sink:     sink,
		Now:      func() time.Time { return now },
	})

	tc.Record(gateway.TelemetryEvent{
		TenantID:   "tenant-flush",
		Subcommand: "hosted-enforce",
		Metrics:    map[string]any{"decision": "allow"},
	})

	tc.Record(gateway.TelemetryEvent{
		TenantID:   "tenant-flush",
		Subcommand: "hosted-enforce",
		Metrics:    map[string]any{"decision": "deny"},
	})

	tc.Flush()

	events := sink.getEvents()
	require.Len(t, events, 2)
	assert.Equal(t, "tenant-flush", events[0].TenantID)
	assert.Equal(t, "hosted-enforce", events[0].Subcommand)
	assert.Equal(t, "allow", events[0].Metrics["decision"])
	assert.Equal(t, now, events[0].Timestamp)

	// Buffer should be empty after flush
	assert.Equal(t, 0, tc.BufferLen())
}

func TestTelemetryCollector_FlushEmptyBuffer(t *testing.T) {
	sink := &mockTelemetrySink{}
	tc := gateway.NewTelemetryCollector(gateway.TelemetryCollectorConfig{
		Enabled: true,
		Sink:    sink,
	})

	// Flushing empty buffer should not call sink
	tc.Flush()
	assert.Empty(t, sink.getEvents())
}

func TestTelemetryCollector_FlushSinkError(t *testing.T) {
	sink := &mockTelemetrySink{err: errors.New("sink unavailable")}
	tc := gateway.NewTelemetryCollector(gateway.TelemetryCollectorConfig{
		Enabled: true,
		Sink:    sink,
	})

	tc.Record(gateway.TelemetryEvent{
		TenantID:   "t1",
		Subcommand: "test",
	})

	// Should not panic on sink error
	tc.Flush()
	assert.Equal(t, 0, tc.BufferLen()) // Buffer is cleared even on error
}

func TestTelemetryCollector_DefaultTenantID(t *testing.T) {
	sink := &mockTelemetrySink{}
	tc := gateway.NewTelemetryCollector(gateway.TelemetryCollectorConfig{
		Enabled:  true,
		TenantID: "default-t",
		Sink:     sink,
	})

	// Record event without explicit tenant
	tc.Record(gateway.TelemetryEvent{
		Subcommand: "test",
		Metrics:    map[string]any{"x": 1},
	})

	tc.Flush()

	events := sink.getEvents()
	require.Len(t, events, 1)
	assert.Equal(t, "default-t", events[0].TenantID)
}

func TestTelemetryCollector_StopFlushesRemaining(t *testing.T) {
	sink := &mockTelemetrySink{}
	tc := gateway.NewTelemetryCollector(gateway.TelemetryCollectorConfig{
		Enabled:       true,
		Sink:          sink,
		FlushInterval: 1 * time.Hour, // Very long so periodic flush won't trigger
	})

	tc.Record(gateway.TelemetryEvent{
		TenantID:   "t1",
		Subcommand: "test",
	})

	tc.Stop()

	events := sink.getEvents()
	assert.Len(t, events, 1)
}

func TestTelemetryCollector_PeriodicFlush(t *testing.T) {
	sink := &mockTelemetrySink{}
	tc := gateway.NewTelemetryCollector(gateway.TelemetryCollectorConfig{
		Enabled:       true,
		Sink:          sink,
		FlushInterval: 50 * time.Millisecond,
	})

	tc.Start()
	defer tc.Stop()

	tc.Record(gateway.TelemetryEvent{
		TenantID:   "t1",
		Subcommand: "test",
	})

	// Wait for periodic flush
	time.Sleep(200 * time.Millisecond)

	events := sink.getEvents()
	assert.GreaterOrEqual(t, len(events), 1)
}

// --- UsageTracker Tests ---

func TestUsageTracker_RecordAndGet(t *testing.T) {
	ut := gateway.NewUsageTracker()

	ut.RecordRequest("tenant-a", "allow")
	ut.RecordRequest("tenant-a", "allow")
	ut.RecordRequest("tenant-a", "deny")
	ut.RecordRequest("tenant-b", "allow")

	// Get all stats
	stats := ut.GetStats("")
	assert.Equal(t, 2, stats["total_tenants"])

	// Get filtered stats
	stats = ut.GetStats("tenant-a")
	assert.Equal(t, 1, stats["total_tenants"])
	tenants := stats["tenants"].([]*gateway.UsageStats)
	require.Len(t, tenants, 1)
	assert.Equal(t, int64(3), tenants[0].TotalRequests)
	assert.Equal(t, int64(2), tenants[0].AllowCount)
	assert.Equal(t, int64(1), tenants[0].DenyCount)
}

func TestUsageTracker_Reset(t *testing.T) {
	ut := gateway.NewUsageTracker()

	ut.RecordRequest("tenant-a", "allow")
	ut.Reset()

	stats := ut.GetStats("")
	assert.Equal(t, 0, stats["total_tenants"])
}

func TestUsageTracker_NonexistentTenant(t *testing.T) {
	ut := gateway.NewUsageTracker()

	stats := ut.GetStats("nonexistent")
	assert.Equal(t, 0, stats["total_tenants"])
}

// --- IdempotencyStore Tests ---

func TestIdempotencyStore_SetAndGet(t *testing.T) {
	store := gateway.NewIdempotencyStore()

	store.Set("key-1", []byte(`{"ok":true}`), 200)

	body, status, found := store.Get("key-1")
	assert.True(t, found)
	assert.Equal(t, 200, status)
	assert.Equal(t, `{"ok":true}`, string(body))
}

func TestIdempotencyStore_NotFound(t *testing.T) {
	store := gateway.NewIdempotencyStore()

	_, _, found := store.Get("missing")
	assert.False(t, found)
}

func TestIdempotencyStore_Expiry(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	store := gateway.NewIdempotencyStore(
		gateway.WithIdempotencyTTL(1*time.Hour),
		gateway.WithIdempotencyTimeFunc(func() time.Time { return now }),
	)

	store.Set("key-1", []byte(`{"ok":true}`), 200)

	// Still valid
	_, _, found := store.Get("key-1")
	assert.True(t, found)

	// Advance time past TTL
	now = now.Add(2 * time.Hour)

	_, _, found = store.Get("key-1")
	assert.False(t, found)
}

func TestIdempotencyStore_Cleanup(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	store := gateway.NewIdempotencyStore(
		gateway.WithIdempotencyTTL(1*time.Hour),
		gateway.WithIdempotencyTimeFunc(func() time.Time { return now }),
	)

	store.Set("key-1", []byte(`{}`), 200)
	store.Set("key-2", []byte(`{}`), 200)
	assert.Equal(t, 2, store.Len())

	// Advance and cleanup
	now = now.Add(2 * time.Hour)
	store.Cleanup()
	assert.Equal(t, 0, store.Len())
}
