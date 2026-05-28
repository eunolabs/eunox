// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway_test

import (
	"sync"
	"testing"
	"time"

	"github.com/eunolabs/eunox/internal/gateway"
	"github.com/stretchr/testify/assert"
)

// --- TEST-4: Concurrent Access Tests for Telemetry ---

func TestTelemetryCollector_ConcurrentRecord(t *testing.T) {
	t.Parallel()

	sink := &mockTelemetrySink{}
	tc := gateway.NewTelemetryCollector(gateway.TelemetryCollectorConfig{
		Enabled:       true,
		TenantID:      "concurrent-test",
		Sink:          sink,
		FlushInterval: time.Hour, // Don't auto-flush.
	})

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			tc.Record(gateway.TelemetryEvent{
				TenantID:   "concurrent-test",
				Subcommand: "hosted-enforce",
				Metrics:    map[string]any{"idx": idx},
			})
		}(i)
	}
	wg.Wait()

	assert.Equal(t, goroutines, tc.BufferLen())

	// Flush and verify all events received.
	tc.Flush()
	events := sink.getEvents()
	assert.Len(t, events, goroutines)
}

func TestTelemetryCollector_ConcurrentRecordAndFlush(t *testing.T) {
	t.Parallel()

	sink := &mockTelemetrySink{}
	tc := gateway.NewTelemetryCollector(gateway.TelemetryCollectorConfig{
		Enabled:       true,
		TenantID:      "concurrent-flush",
		Sink:          sink,
		FlushInterval: time.Hour,
	})

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines + 5) // 50 recorders + 5 flushers

	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			tc.Record(gateway.TelemetryEvent{
				TenantID:   "concurrent-flush",
				Subcommand: "test",
				Metrics:    map[string]any{"idx": idx},
			})
		}(i)
	}

	// Concurrent flushers.
	for range 5 {
		go func() {
			defer wg.Done()
			time.Sleep(1 * time.Millisecond)
			tc.Flush()
		}()
	}
	wg.Wait()

	// Final flush to catch anything remaining.
	tc.Flush()

	events := sink.getEvents()
	// All events should have been flushed (no data loss).
	assert.Equal(t, goroutines, len(events))
}

func TestTelemetryCollector_ConcurrentRecordAndStop(t *testing.T) {
	t.Parallel()

	sink := &mockTelemetrySink{}
	tc := gateway.NewTelemetryCollector(gateway.TelemetryCollectorConfig{
		Enabled:       true,
		TenantID:      "stop-test",
		Sink:          sink,
		FlushInterval: time.Hour,
	})

	const goroutines = 30
	var wg sync.WaitGroup
	wg.Add(goroutines + 1)

	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			tc.Record(gateway.TelemetryEvent{
				TenantID:   "stop-test",
				Subcommand: "test",
				Metrics:    map[string]any{"idx": idx},
			})
		}(i)
	}

	go func() {
		defer wg.Done()
		time.Sleep(2 * time.Millisecond)
		tc.Stop()
	}()
	wg.Wait()

	// After Stop, some events may have been delivered, but no panics or races.
	events := sink.getEvents()
	assert.LessOrEqual(t, len(events), goroutines)
}

func TestTelemetryCollector_ConcurrentRecordEnforcement(t *testing.T) {
	t.Parallel()

	sink := &mockTelemetrySink{}
	tc := gateway.NewTelemetryCollector(gateway.TelemetryCollectorConfig{
		Enabled:       true,
		TenantID:      "enforcement-test",
		Sink:          sink,
		FlushInterval: time.Hour,
	})

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			tc.RecordEnforcement("enforcement-test", "allow", 5*time.Millisecond)
		}()
	}
	wg.Wait()

	assert.Equal(t, goroutines, tc.BufferLen())
}

func TestUsageTracker_ConcurrentRecordAndGet(t *testing.T) {
	t.Parallel()

	ut := gateway.NewUsageTracker()

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Concurrent writers.
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			tenant := "tenant-" + itoa(idx%5)
			decision := "allow"
			if idx%3 == 0 {
				decision = "deny"
			}
			ut.RecordRequest(tenant, decision)
		}(i)
	}

	// Concurrent readers.
	for range goroutines {
		go func() {
			defer wg.Done()
			_ = ut.GetStats("")
		}()
	}
	wg.Wait()

	stats := ut.GetStats("")
	assert.Equal(t, 5, stats["total_tenants"])
}

func TestIdempotencyStore_ConcurrentSetAndGet(t *testing.T) {
	t.Parallel()

	store := gateway.NewIdempotencyStore()

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Concurrent writers.
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			key := "key-" + itoa(idx)
			store.Set(key, []byte(`{"idx":`+itoa(idx)+`}`), 200, nil)
		}(i)
	}

	// Concurrent readers.
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			key := "key-" + itoa(idx)
			_, _, _, _ = store.Get(key)
		}(i)
	}
	wg.Wait()

	// Verify at least some entries are readable.
	_, _, _, found := store.Get("key-0")
	assert.True(t, found)
}

func itoa(i int) string {
	const digits = "0123456789"
	if i < 0 {
		return "-" + itoa(-i)
	}
	if i < 10 {
		return string(digits[i])
	}
	return itoa(i/10) + string(digits[i%10])
}
