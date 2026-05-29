// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package config

import "time"

// DatabasePoolConfig holds PostgreSQL connection pool configuration.
// These settings control how the Go database/sql pool manages connections
// to prevent resource exhaustion and stale connection issues.
//
// Recommended settings by deployment tier:
//   - Single-replica: MaxOpenConns=25, MaxIdleConns=5, ConnMaxLifetime=5m
//   - Multi-replica: MaxOpenConns=10, MaxIdleConns=3, ConnMaxLifetime=5m
//     (lower per-replica to respect shared max_connections)
//   - With PgBouncer: ConnMaxLifetime should be less than PgBouncer's server_idle_timeout
type DatabasePoolConfig struct {
	// MaxOpenConns is the maximum number of open connections to the database.
	// Default: 25. Set to 0 for unlimited (not recommended for production).
	MaxOpenConns int `env:"DB_MAX_OPEN_CONNS" default:"25" min:"0"`

	// MaxIdleConns is the maximum number of connections in the idle pool.
	// Default: 5. Should be <= MaxOpenConns.
	MaxIdleConns int `env:"DB_MAX_IDLE_CONNS" default:"5" min:"0"`

	// ConnMaxLifetimeSeconds is the maximum time a connection may be reused, in seconds.
	// Default: 300 (5 minutes). Ensures connections are recycled after network
	// partitions or PgBouncer timeouts. Set to 0 for no limit (not recommended).
	ConnMaxLifetimeSeconds int `env:"DB_CONN_MAX_LIFETIME_SECONDS" default:"300" min:"0"`

	// ConnMaxIdleTimeSeconds is the maximum time a connection may sit idle, in seconds.
	// Default: 60 (1 minute). Idle connections beyond this are closed.
	ConnMaxIdleTimeSeconds int `env:"DB_CONN_MAX_IDLE_TIME_SECONDS" default:"60" min:"0"`
}

// DefaultDatabasePoolConfig returns the default pool configuration suitable
// for single-replica deployments against PostgreSQL without connection pooler.
func DefaultDatabasePoolConfig() DatabasePoolConfig {
	return DatabasePoolConfig{
		MaxOpenConns:           25,
		MaxIdleConns:           5,
		ConnMaxLifetimeSeconds: 300,
		ConnMaxIdleTimeSeconds: 60,
	}
}

// ConnMaxLifetime returns ConnMaxLifetimeSeconds as a time.Duration.
func (c *DatabasePoolConfig) ConnMaxLifetime() time.Duration {
	return time.Duration(c.ConnMaxLifetimeSeconds) * time.Second
}

// ConnMaxIdleTime returns ConnMaxIdleTimeSeconds as a time.Duration.
func (c *DatabasePoolConfig) ConnMaxIdleTime() time.Duration {
	return time.Duration(c.ConnMaxIdleTimeSeconds) * time.Second
}
