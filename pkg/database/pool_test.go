// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package database

import (
	"database/sql"
	"testing"
	"time"

	"github.com/eunolabs/eunox/pkg/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite" // SQLite driver for testing
)

func TestOpenPool_EmptyDSN(t *testing.T) {
	_, err := OpenPool("sqlite", "", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DSN must not be empty")
}

func TestOpenPool_DefaultConfig(t *testing.T) {
	db, err := OpenPool("sqlite", ":memory:", nil)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	stats := db.Stats()
	assert.Equal(t, 25, stats.MaxOpenConnections)
}

func TestOpenPool_CustomConfig(t *testing.T) {
	cfg := &config.DatabasePoolConfig{
		MaxOpenConns:           10,
		MaxIdleConns:           3,
		ConnMaxLifetimeSeconds: 120,
		ConnMaxIdleTimeSeconds: 30,
	}

	db, err := OpenPool("sqlite", ":memory:", cfg)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	stats := db.Stats()
	assert.Equal(t, 10, stats.MaxOpenConnections)
}

func TestOpenPool_InvalidDriver(t *testing.T) {
	_, err := OpenPool("nonexistent-driver", "dsn", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database: open")
}

func TestConfigurePool(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	cfg := &config.DatabasePoolConfig{
		MaxOpenConns:           15,
		MaxIdleConns:           4,
		ConnMaxLifetimeSeconds: 180,
		ConnMaxIdleTimeSeconds: 45,
	}
	ConfigurePool(db, cfg)

	stats := db.Stats()
	assert.Equal(t, 15, stats.MaxOpenConnections)
}

func TestConfigurePool_NilConfig(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	ConfigurePool(db, nil)

	stats := db.Stats()
	assert.Equal(t, 25, stats.MaxOpenConnections)
}

func TestDefaultDatabasePoolConfig(t *testing.T) {
	cfg := config.DefaultDatabasePoolConfig()
	assert.Equal(t, 25, cfg.MaxOpenConns)
	assert.Equal(t, 5, cfg.MaxIdleConns)
	assert.Equal(t, 300, cfg.ConnMaxLifetimeSeconds)
	assert.Equal(t, 60, cfg.ConnMaxIdleTimeSeconds)
}

func TestDatabasePoolConfig_Durations(t *testing.T) {
	cfg := config.DatabasePoolConfig{
		ConnMaxLifetimeSeconds: 600,
		ConnMaxIdleTimeSeconds: 120,
	}
	assert.Equal(t, 10*time.Minute, cfg.ConnMaxLifetime())
	assert.Equal(t, 2*time.Minute, cfg.ConnMaxIdleTime())
}

func TestPoolMetrics(t *testing.T) {
	db, err := OpenPool("sqlite", ":memory:", nil)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	reg := prometheus.NewRegistry()
	cleanup, err := PoolMetrics(db, reg, "test-service")
	require.NoError(t, err)
	require.NotNil(t, cleanup)

	// Gather metrics to verify they're registered
	families, err := reg.Gather()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(families), 5)

	// Verify metric names
	names := make(map[string]bool)
	for _, f := range families {
		names[f.GetName()] = true
	}
	assert.True(t, names["db_pool_open_connections"])
	assert.True(t, names["db_pool_in_use_connections"])
	assert.True(t, names["db_pool_idle_connections"])
	assert.True(t, names["db_pool_wait_count_total"])
	assert.True(t, names["db_pool_wait_duration_seconds_total"])

	// Cleanup should unregister
	cleanup()

	// Re-register should succeed after cleanup
	cleanup2, err := PoolMetrics(db, reg, "test-service")
	require.NoError(t, err)
	cleanup2()
}

func TestPoolMetrics_ServiceLabel(t *testing.T) {
	db, err := OpenPool("sqlite", ":memory:", nil)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	reg := prometheus.NewRegistry()
	cleanup, err := PoolMetrics(db, reg, "minter")
	require.NoError(t, err)
	defer cleanup()

	families, err := reg.Gather()
	require.NoError(t, err)

	// Check that the service label is set correctly
	for _, f := range families {
		for _, m := range f.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "service" {
					assert.Equal(t, "minter", lp.GetValue())
				}
			}
		}
	}
}
