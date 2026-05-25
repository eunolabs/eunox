// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"encoding/json"
	"log/slog"
	"sync"
	"time"
)

// TelemetryEvent represents a single telemetry data point collected by the gateway.
type TelemetryEvent struct {
	TenantID   string         `json:"tenantId"`
	Subcommand string         `json:"subcommand"`
	Timestamp  time.Time      `json:"timestamp"`
	Metrics    map[string]any `json:"metrics"`
}

// TelemetryCollectorConfig configures the gateway telemetry collector.
type TelemetryCollectorConfig struct {
	// Enabled controls whether telemetry is collected. Defaults to true.
	Enabled bool
	// FlushInterval is how often telemetry is flushed. Defaults to 5 minutes.
	FlushInterval time.Duration
	// TenantID scopes telemetry to a specific tenant.
	TenantID string
	// Logger for telemetry operations.
	Logger *slog.Logger
	// Sink receives flushed telemetry events. If nil, events are discarded.
	Sink TelemetrySink
	// Now provides the current time (for testing).
	Now func() time.Time
}

// TelemetrySink receives batches of telemetry events on flush.
type TelemetrySink interface {
	// Send delivers a batch of telemetry events.
	Send(events []TelemetryEvent) error
}

// TelemetryCollector collects per-tenant telemetry metrics and flushes them periodically.
type TelemetryCollector struct {
	config  TelemetryCollectorConfig
	mu      sync.Mutex
	buffer  []TelemetryEvent
	stopCh  chan struct{}
	stopped bool
}

// NewTelemetryCollector creates a new telemetry collector.
func NewTelemetryCollector(cfg TelemetryCollectorConfig) *TelemetryCollector {
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 5 * time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	return &TelemetryCollector{
		config: cfg,
		buffer: make([]TelemetryEvent, 0, 64),
		stopCh: make(chan struct{}),
	}
}

// Start begins the periodic flush goroutine.
func (tc *TelemetryCollector) Start() {
	if !tc.config.Enabled {
		return
	}
	go tc.flushLoop()
}

// Stop terminates the flush goroutine and flushes remaining events.
func (tc *TelemetryCollector) Stop() {
	tc.mu.Lock()
	if tc.stopped {
		tc.mu.Unlock()
		return
	}
	tc.stopped = true
	tc.mu.Unlock()

	close(tc.stopCh)
	tc.Flush()
}

// Record adds a telemetry event to the buffer.
func (tc *TelemetryCollector) Record(event TelemetryEvent) {
	if !tc.config.Enabled {
		return
	}

	tc.mu.Lock()
	defer tc.mu.Unlock()

	if event.Timestamp.IsZero() {
		event.Timestamp = tc.config.Now()
	}
	if event.TenantID == "" {
		event.TenantID = tc.config.TenantID
	}

	tc.buffer = append(tc.buffer, event)
}

// RecordEnforcement records an enforcement decision telemetry event.
func (tc *TelemetryCollector) RecordEnforcement(tenantID, decision string, duration time.Duration) {
	tc.Record(TelemetryEvent{
		TenantID:   tenantID,
		Subcommand: "hosted-enforce",
		Metrics: map[string]any{
			"decision":    decision,
			"duration_ms": duration.Milliseconds(),
		},
	})
}

// Flush sends all buffered events to the sink.
func (tc *TelemetryCollector) Flush() {
	tc.mu.Lock()
	if len(tc.buffer) == 0 {
		tc.mu.Unlock()
		return
	}

	events := tc.buffer
	tc.buffer = make([]TelemetryEvent, 0, 64)
	tc.mu.Unlock()

	if tc.config.Sink == nil {
		return
	}

	if err := tc.config.Sink.Send(events); err != nil {
		tc.config.Logger.Error("failed to flush telemetry",
			slog.Int("events", len(events)),
			slog.String("error", err.Error()),
		)
	}
}

// BufferLen returns the number of buffered events (for testing).
func (tc *TelemetryCollector) BufferLen() int {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return len(tc.buffer)
}

func (tc *TelemetryCollector) flushLoop() {
	ticker := time.NewTicker(tc.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			tc.Flush()
		case <-tc.stopCh:
			return
		}
	}
}

// MarshalJSON serializes a TelemetryEvent for transport.
func (e TelemetryEvent) MarshalJSON() ([]byte, error) {
	type Alias TelemetryEvent
	return json.Marshal(struct {
		Alias
		Timestamp string `json:"timestamp"`
	}{
		Alias:     Alias(e),
		Timestamp: e.Timestamp.UTC().Format(time.RFC3339),
	})
}

// UsageTracker tracks request usage per tenant.
type UsageTracker struct {
	mu    sync.Mutex
	stats map[string]*UsageStats
	now   func() time.Time
}

// UsageStats holds usage statistics for a tenant.
type UsageStats struct {
	TenantID      string    `json:"tenantId"`
	TotalRequests int64     `json:"totalRequests"`
	AllowCount    int64     `json:"allowCount"`
	DenyCount     int64     `json:"denyCount"`
	LastRequestAt time.Time `json:"lastRequestAt"`
	ResetAt       time.Time `json:"resetAt"`
}

// NewUsageTracker creates a new usage tracker.
func NewUsageTracker() *UsageTracker {
	return &UsageTracker{
		stats: make(map[string]*UsageStats),
		now:   time.Now,
	}
}

// RecordRequest records a request for the given tenant.
func (ut *UsageTracker) RecordRequest(tenantID, decision string) {
	ut.mu.Lock()
	defer ut.mu.Unlock()

	s, ok := ut.stats[tenantID]
	if !ok {
		s = &UsageStats{
			TenantID: tenantID,
			ResetAt:  ut.now(),
		}
		ut.stats[tenantID] = s
	}

	s.TotalRequests++
	s.LastRequestAt = ut.now()

	switch decision {
	case "allow":
		s.AllowCount++
	case "deny":
		s.DenyCount++
	}
}

// GetStats returns usage statistics, optionally filtered by tenant.
func (ut *UsageTracker) GetStats(tenantFilter string) map[string]any {
	ut.mu.Lock()
	defer ut.mu.Unlock()

	if tenantFilter != "" {
		s, ok := ut.stats[tenantFilter]
		if !ok {
			return map[string]any{
				"tenants":       []any{},
				"total_tenants": 0,
			}
		}
		snapshot := *s
		return map[string]any{
			"tenants":       []UsageStats{snapshot},
			"total_tenants": 1,
		}
	}

	tenants := make([]UsageStats, 0, len(ut.stats))
	for _, s := range ut.stats {
		snapshot := *s
		tenants = append(tenants, snapshot)
	}

	return map[string]any{
		"tenants":       tenants,
		"total_tenants": len(tenants),
	}
}

// Reset clears all usage statistics.
func (ut *UsageTracker) Reset() {
	ut.mu.Lock()
	defer ut.mu.Unlock()
	ut.stats = make(map[string]*UsageStats)
}
