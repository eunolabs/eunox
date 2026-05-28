// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package migrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"hash/fnv"
)

// ── PostgresStateStore ──────────────────────────────────────────────────────

// PostgresStateStore implements [StateStore] backed by a shared
// schema_migrations table in PostgreSQL, keyed by schema name.  This lets the
// minter and audit schemas live in different databases (each with their own
// schema_migrations table) or in the same database (distinct rows).
type PostgresStateStore struct {
	db         *sql.DB
	schemaName string
}

// NewPostgresStateStore returns a [StateStore] that tracks migration state for
// schemaName in the schema_migrations table of db.
// Call [Runner.MigrateUp] (which internally calls [Init]) before any reads.
func NewPostgresStateStore(db *sql.DB, schemaName string) *PostgresStateStore {
	return &PostgresStateStore{db: db, schemaName: schemaName}
}

const createMigrationsTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    schema_name TEXT        NOT NULL DEFAULT '',
    version     INTEGER     NOT NULL DEFAULT 0,
    dirty       BOOLEAN     NOT NULL DEFAULT FALSE,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (schema_name)
)`

// Init creates the schema_migrations table if it does not already exist.
// Idempotent: safe to call on every service startup.
func (s *PostgresStateStore) Init(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, createMigrationsTable); err != nil {
		return fmt.Errorf("migrate: init schema_migrations: %w", err)
	}
	return nil
}

// CurrentVersion returns the migration version and dirty flag for this schema.
// Returns (0, false, nil) when no row exists — a fresh, unmigrated database.
func (s *PostgresStateStore) CurrentVersion(ctx context.Context) (version int, dirty bool, err error) {
	const q = `SELECT version, dirty FROM schema_migrations WHERE schema_name = $1`
	row := s.db.QueryRowContext(ctx, q, s.schemaName)
	if err = row.Scan(&version, &dirty); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("migrate: current version for %q: %w", s.schemaName, err)
	}
	return version, dirty, nil
}

// SetVersion upserts the migration version and dirty flag for this schema.
func (s *PostgresStateStore) SetVersion(ctx context.Context, version int, dirty bool) error {
	const q = `
		INSERT INTO schema_migrations (schema_name, version, dirty, applied_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (schema_name)
		DO UPDATE SET version    = EXCLUDED.version,
		              dirty      = EXCLUDED.dirty,
		              applied_at = NOW()`
	if _, err := s.db.ExecContext(ctx, q, s.schemaName, version, dirty); err != nil {
		return fmt.Errorf("migrate: set version for %q: %w", s.schemaName, err)
	}
	return nil
}

// ── PostgresSQLExecutor ─────────────────────────────────────────────────────

// PostgresSQLExecutor implements [SQLExecutor] by executing SQL directly
// against a *sql.DB.
type PostgresSQLExecutor struct {
	db *sql.DB
}

// NewPostgresSQLExecutor returns a [SQLExecutor] backed by db.
func NewPostgresSQLExecutor(db *sql.DB) *PostgresSQLExecutor {
	return &PostgresSQLExecutor{db: db}
}

// ExecMigration runs a single migration SQL statement.
func (e *PostgresSQLExecutor) ExecMigration(ctx context.Context, sqlStr string) error {
	if _, err := e.db.ExecContext(ctx, sqlStr); err != nil {
		return fmt.Errorf("migrate: exec: %w", err)
	}
	return nil
}

// ── PostgresAdvisoryLocker ──────────────────────────────────────────────────

// PostgresAdvisoryLocker implements [AdvisoryLocker] using PostgreSQL
// session-level advisory locks (pg_try_advisory_lock / pg_advisory_unlock).
//
// The lock ID is derived from the schema name, so different schemas never
// contend even when they share a single Postgres instance.  The "eunox:migrate:"
// prefix ensures Eunox migration locks do not collide with advisory locks
// used elsewhere in the application.
type PostgresAdvisoryLocker struct {
	db     *sql.DB
	lockID int64
}

// NewPostgresAdvisoryLocker returns an [AdvisoryLocker] whose advisory lock
// ID is derived from schema.
func NewPostgresAdvisoryLocker(db *sql.DB, schema string) *PostgresAdvisoryLocker {
	return &PostgresAdvisoryLocker{db: db, lockID: schemaLockID(schema)}
}

// Lock acquires the session-level advisory lock.
// Returns [ErrLockHeld] when another database session already holds it.
func (l *PostgresAdvisoryLocker) Lock(ctx context.Context) error {
	var acquired bool
	err := l.db.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", l.lockID).Scan(&acquired)
	if err != nil {
		return fmt.Errorf("migrate: advisory lock: %w", err)
	}
	if !acquired {
		return ErrLockHeld
	}
	return nil
}

// Unlock releases the session-level advisory lock.
func (l *PostgresAdvisoryLocker) Unlock(ctx context.Context) error {
	if _, err := l.db.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", l.lockID); err != nil {
		return fmt.Errorf("migrate: advisory unlock: %w", err)
	}
	return nil
}

// schemaLockID maps a schema name to a stable int64 advisory lock ID via FNV-1a.
func schemaLockID(schema string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("eunox:migrate:" + schema))
	return int64(h.Sum64()) //nolint:gosec // G115: intentional bit-cast; advisory lock IDs are bigints that span the full uint64 range
}
