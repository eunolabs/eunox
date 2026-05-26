// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package minter

import (
	"context"
	"testing"
	"time"
)

func TestInMemoryAnomalyDetector_UnderThreshold(t *testing.T) {
	t.Parallel()

	d := NewInMemoryAnomalyDetector(VelocityConfig{MaxMintsPerWindow: 10, Window: time.Minute}, nil)
	ctx := context.Background()

	// Record a few mints, should be fine.
	for range 5 {
		if err := d.RecordMint(ctx, "tenant-1"); err != nil {
			t.Fatal(err)
		}
	}

	if err := d.CheckVelocity(ctx, "tenant-1"); err != nil {
		t.Errorf("expected no error with 5 mints (threshold=10), got %v", err)
	}
}

func TestInMemoryAnomalyDetector_ExceedsThreshold(t *testing.T) {
	t.Parallel()

	d := NewInMemoryAnomalyDetector(VelocityConfig{MaxMintsPerWindow: 5, Window: time.Minute}, nil)
	ctx := context.Background()

	// Record enough to exceed.
	for range 6 {
		_ = d.RecordMint(ctx, "tenant-1")
	}

	err := d.CheckVelocity(ctx, "tenant-1")
	if err == nil {
		t.Error("expected velocity exceeded error")
	}
	if err != ErrVelocityExceeded {
		t.Errorf("expected ErrVelocityExceeded, got %v", err)
	}
}

func TestInMemoryAnomalyDetector_MultiTenant(t *testing.T) {
	t.Parallel()

	d := NewInMemoryAnomalyDetector(VelocityConfig{MaxMintsPerWindow: 3, Window: time.Minute}, nil)
	ctx := context.Background()

	// Tenant 1 exceeds.
	for range 4 {
		_ = d.RecordMint(ctx, "t1")
	}
	// Tenant 2 is fine.
	_ = d.RecordMint(ctx, "t2")

	if err := d.CheckVelocity(ctx, "t1"); err == nil {
		t.Error("expected t1 to exceed velocity")
	}
	if err := d.CheckVelocity(ctx, "t2"); err != nil {
		t.Errorf("t2 should not exceed velocity, got %v", err)
	}
}

func TestInMemoryAnomalyDetector_WindowExpiry(t *testing.T) {
	t.Parallel()

	// Very short window for testing.
	d := NewInMemoryAnomalyDetector(VelocityConfig{MaxMintsPerWindow: 2, Window: 50 * time.Millisecond}, nil)
	ctx := context.Background()

	_ = d.RecordMint(ctx, "t1")
	_ = d.RecordMint(ctx, "t1")
	_ = d.RecordMint(ctx, "t1")

	// Should exceed now.
	if err := d.CheckVelocity(ctx, "t1"); err == nil {
		t.Error("expected velocity exceeded")
	}

	// Wait for window to expire.
	time.Sleep(60 * time.Millisecond)

	// Should be fine now.
	if err := d.CheckVelocity(ctx, "t1"); err != nil {
		t.Errorf("after window expiry, velocity check should pass: %v", err)
	}
}

func TestInMemoryAnomalyDetector_DefaultConfig(t *testing.T) {
	t.Parallel()

	// Default config should use sensible defaults.
	d := NewInMemoryAnomalyDetector(VelocityConfig{}, nil)
	ctx := context.Background()

	// Should not panic and should accept mints up to default limit (100).
	_ = d.RecordMint(ctx, "t1")
	if err := d.CheckVelocity(ctx, "t1"); err != nil {
		t.Errorf("expected no error with defaults, got %v", err)
	}
}
