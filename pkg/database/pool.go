// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package database provides PostgreSQL connection pool management with
// production-grade defaults and Prometheus metrics integration.
package database

import (
	"database/sql"
	"fmt"

	"github.com/eunolabs/eunox/pkg/config"
	"github.com/prometheus/client_golang/prometheus"
)

// OpenPool opens a database connection pool with the given driver, DSN, and pool
// configuration. It applies connection limits and lifetime settings to prevent
// resource exhaustion in production.
//
// For PostgreSQL, use driver "pgx" with a side-effect import of
// "github.com/jackc/pgx/v5/stdlib".
//
// The caller is responsible for calling db.Close() when done.
func OpenPool(driver, dsn string, poolCfg *config.DatabasePoolConfig) (*sql.DB, error) {
	if dsn == "" {
		return nil, fmt.Errorf("database: DSN must not be empty")
	}

	cfg := config.DefaultDatabasePoolConfig()
	if poolCfg != nil {
		cfg = *poolCfg
	}

	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("database: open: %w", err)
	}

	ConfigurePool(db, &cfg)

	return db, nil
}

// ConfigurePool applies pool settings to an existing *sql.DB.
// Use this when you already have an open database connection and want to
// apply production-grade pool settings.
func ConfigurePool(db *sql.DB, cfg *config.DatabasePoolConfig) {
	if cfg == nil {
		defaults := config.DefaultDatabasePoolConfig()
		cfg = &defaults
	}
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime())
	db.SetConnMaxIdleTime(cfg.ConnMaxIdleTime())
}

// PoolMetrics registers Prometheus gauges that track connection pool state.
// The returned cleanup function unregisters the metrics collector.
func PoolMetrics(db *sql.DB, registerer prometheus.Registerer, serviceName string) (func(), error) {
	collector := newPoolCollector(db, serviceName)
	if err := registerer.Register(collector); err != nil {
		return nil, fmt.Errorf("database: register pool metrics: %w", err)
	}
	return func() { registerer.Unregister(collector) }, nil
}

// poolCollector implements prometheus.Collector for database/sql pool stats.
type poolCollector struct {
	db      *sql.DB
	service string

	openConns   *prometheus.Desc
	inUse       *prometheus.Desc
	idle        *prometheus.Desc
	waitCount   *prometheus.Desc
	waitSeconds *prometheus.Desc
}

func newPoolCollector(db *sql.DB, service string) *poolCollector {
	labels := []string{"service"}
	return &poolCollector{
		db:      db,
		service: service,
		openConns: prometheus.NewDesc(
			"db_pool_open_connections",
			"Number of open connections to the database",
			labels, nil,
		),
		inUse: prometheus.NewDesc(
			"db_pool_in_use_connections",
			"Number of connections currently in use",
			labels, nil,
		),
		idle: prometheus.NewDesc(
			"db_pool_idle_connections",
			"Number of idle connections in the pool",
			labels, nil,
		),
		waitCount: prometheus.NewDesc(
			"db_pool_wait_count_total",
			"Total number of connections waited for",
			labels, nil,
		),
		waitSeconds: prometheus.NewDesc(
			"db_pool_wait_duration_seconds_total",
			"Total time blocked waiting for a new connection",
			labels, nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *poolCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.openConns
	ch <- c.inUse
	ch <- c.idle
	ch <- c.waitCount
	ch <- c.waitSeconds
}

// Collect implements prometheus.Collector.
func (c *poolCollector) Collect(ch chan<- prometheus.Metric) {
	stats := c.db.Stats()
	ch <- prometheus.MustNewConstMetric(c.openConns, prometheus.GaugeValue, float64(stats.OpenConnections), c.service)
	ch <- prometheus.MustNewConstMetric(c.inUse, prometheus.GaugeValue, float64(stats.InUse), c.service)
	ch <- prometheus.MustNewConstMetric(c.idle, prometheus.GaugeValue, float64(stats.Idle), c.service)
	ch <- prometheus.MustNewConstMetric(c.waitCount, prometheus.CounterValue, float64(stats.WaitCount), c.service)
	ch <- prometheus.MustNewConstMetric(c.waitSeconds, prometheus.CounterValue, stats.WaitDuration.Seconds(), c.service)
}
