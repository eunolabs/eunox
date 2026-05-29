// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package minter

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// AnomalyDetector tracks mint velocity and flags anomalies.
type AnomalyDetector interface {
	// RecordMint records a key mint event for the given tenant.
	RecordMint(ctx context.Context, tenantID string) error
	// CheckVelocity returns an error if the mint rate exceeds the configured threshold.
	CheckVelocity(ctx context.Context, tenantID string) error
}

// VelocityConfig configures the velocity-based anomaly detector.
type VelocityConfig struct {
	MaxMintsPerWindow int           // Maximum mints allowed per window.
	Window            time.Duration // Time window for velocity tracking.
}

// InMemoryAnomalyDetector tracks mint velocity using in-memory sliding windows.
type InMemoryAnomalyDetector struct {
	config VelocityConfig
	logger *slog.Logger

	mu      sync.Mutex
	buckets map[string]*velocityBucket
}

type velocityBucket struct {
	timestamps []time.Time
}

// NewInMemoryAnomalyDetector creates an anomaly detector with the given velocity configuration.
func NewInMemoryAnomalyDetector(cfg VelocityConfig, logger *slog.Logger) *InMemoryAnomalyDetector {
	if cfg.MaxMintsPerWindow <= 0 {
		cfg.MaxMintsPerWindow = 100
	}
	if cfg.Window <= 0 {
		cfg.Window = time.Minute
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &InMemoryAnomalyDetector{
		config:  cfg,
		logger:  logger,
		buckets: make(map[string]*velocityBucket),
	}
}

// RecordMint implements AnomalyDetector.
func (d *InMemoryAnomalyDetector) RecordMint(_ context.Context, tenantID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	b, ok := d.buckets[tenantID]
	if !ok {
		b = &velocityBucket{}
		d.buckets[tenantID] = b
	}
	b.timestamps = append(b.timestamps, time.Now())
	return nil
}

// CheckVelocity implements AnomalyDetector.
func (d *InMemoryAnomalyDetector) CheckVelocity(ctx context.Context, tenantID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	b, ok := d.buckets[tenantID]
	if !ok {
		return nil
	}

	cutoff := time.Now().Add(-d.config.Window)
	d.pruneOlderThan(b, cutoff)

	if len(b.timestamps) >= d.config.MaxMintsPerWindow {
		d.logger.WarnContext(ctx, "velocity limit exceeded",
			"tenantId", tenantID,
			"count", len(b.timestamps),
			"window", d.config.Window.String(),
			"max", d.config.MaxMintsPerWindow,
		)
		return ErrVelocityExceeded
	}
	return nil
}

func (d *InMemoryAnomalyDetector) pruneOlderThan(b *velocityBucket, cutoff time.Time) {
	i := 0
	for i < len(b.timestamps) && b.timestamps[i].Before(cutoff) {
		i++
	}
	b.timestamps = b.timestamps[i:]
}
