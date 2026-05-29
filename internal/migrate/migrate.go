// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

// Package migrate provides production-grade database migration tooling
// with rollback safety checks, advisory locking for multi-instance deploys,
// and pre-migration backup hooks.
package migrate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Errors returned by the migration runner.
var (
	ErrLockFailed      = errors.New("migrate: failed to acquire advisory lock")
	ErrLockHeld        = errors.New("migrate: advisory lock is already held by another process")
	ErrNoDownMigration = errors.New("migrate: up migration has no corresponding down migration (rollback unsafe)")
	ErrDirtyState      = errors.New("migrate: database is in a dirty state from a previous failed migration")
	ErrBackupFailed    = errors.New("migrate: pre-migration backup hook failed")
	ErrNoMigrations    = errors.New("migrate: no migration files found")
	ErrInvalidVersion  = errors.New("migrate: invalid migration version number")
	ErrInvalidConfig   = errors.New("migrate: invalid runner config")
	ErrMissingStore    = errors.New("migrate: state store is required")
	ErrMissingExecutor = errors.New("migrate: sql executor is required")
	ErrDuplicatePair   = errors.New("migrate: duplicate migration version/direction")
)

// Direction represents the migration direction.
type Direction string

const (
	// Up applies forward migrations.
	Up Direction = "up"
	// Down applies rollback migrations.
	Down Direction = "down"
)

// Migration represents a single parsed migration file.
type Migration struct {
	Version     int
	Description string
	Direction   Direction
	SQL         string
}

// BackupHook is called before migrations are applied, giving operators
// the opportunity to create a database backup before potentially destructive changes.
type BackupHook func(ctx context.Context, currentVersion int) error

// StateStore persists migration state (current version, dirty flag).
type StateStore interface {
	// CurrentVersion returns the current schema version and whether it is dirty.
	CurrentVersion(ctx context.Context) (version int, dirty bool, err error)
	// SetVersion records a successful migration to the given version.
	SetVersion(ctx context.Context, version int, dirty bool) error
	// Init ensures the schema tracking table exists.
	Init(ctx context.Context) error
}

// AdvisoryLocker provides distributed locking for multi-instance safety.
type AdvisoryLocker interface {
	// Lock acquires an advisory lock. Returns ErrLockHeld if already held.
	Lock(ctx context.Context) error
	// Unlock releases the advisory lock.
	Unlock(ctx context.Context) error
}

// SQLExecutor executes raw SQL statements during migrations.
type SQLExecutor interface {
	// ExecMigration executes a SQL migration statement.
	ExecMigration(ctx context.Context, sql string) error
}

// Runner executes database migrations with safety checks.
type Runner struct {
	migrations []Migration
	store      StateStore
	locker     AdvisoryLocker
	backup     BackupHook
	executor   SQLExecutor
	logger     *slog.Logger
}

// Config configures the migration runner.
type Config struct {
	// Source is the filesystem containing migration SQL files.
	Source fs.FS
	// Dir is the subdirectory within Source to read migrations from (default "").
	Dir string
	// Store is the state persistence backend.
	Store StateStore
	// Executor runs the SQL migration statements against the database.
	Executor SQLExecutor
	// Locker is the distributed lock backend (optional for single-instance deploys).
	Locker AdvisoryLocker
	// BackupHook is called before applying migrations (optional).
	BackupHook BackupHook
	// Logger for migration progress (optional; uses slog.Default() if nil).
	Logger *slog.Logger
}

// NewRunner creates a migration runner from the given configuration.
// It parses all SQL migration files from Source and validates rollback safety.
func NewRunner(cfg *Config) (*Runner, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: config is nil", ErrInvalidConfig)
	}
	if cfg.Store == nil {
		return nil, ErrMissingStore
	}
	if cfg.Executor == nil {
		return nil, ErrMissingExecutor
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	migrations, err := parseMigrations(cfg.Source, cfg.Dir)
	if err != nil {
		return nil, err
	}

	if len(migrations) == 0 {
		return nil, ErrNoMigrations
	}

	return &Runner{
		migrations: migrations,
		store:      cfg.Store,
		locker:     cfg.Locker,
		backup:     cfg.BackupHook,
		executor:   cfg.Executor,
		logger:     cfg.Logger,
	}, nil
}

// ValidateRollbackSafety checks that every up migration has a corresponding
// down migration, ensuring safe rollback is possible.
func (r *Runner) ValidateRollbackSafety() error {
	upVersions := map[int]bool{}
	downVersions := map[int]bool{}

	for i := range r.migrations {
		m := &r.migrations[i]
		switch m.Direction {
		case Up:
			upVersions[m.Version] = true
		case Down:
			downVersions[m.Version] = true
		}
	}

	for v := range upVersions {
		if !downVersions[v] {
			return fmt.Errorf("%w: version %d", ErrNoDownMigration, v)
		}
	}

	return nil
}

// MigrateUp applies all pending up migrations up to the latest version.
// It acquires an advisory lock (if configured), runs the backup hook, validates
// rollback safety, checks for dirty state, and then applies migrations sequentially.
func (r *Runner) MigrateUp(ctx context.Context) (applied int, err error) {
	return r.MigrateUpTo(ctx, r.latestVersion())
}

// MigrateUpTo applies up migrations up to and including the target version.
func (r *Runner) MigrateUpTo(ctx context.Context, target int) (applied int, err error) {
	if err := r.acquireLock(ctx); err != nil {
		return 0, err
	}
	defer r.releaseLock(ctx)

	if err := r.store.Init(ctx); err != nil {
		return 0, fmt.Errorf("migrate: init state store: %w", err)
	}

	current, dirty, err := r.store.CurrentVersion(ctx)
	if err != nil {
		return 0, fmt.Errorf("migrate: read current version: %w", err)
	}
	if dirty {
		return 0, fmt.Errorf("%w: version %d", ErrDirtyState, current)
	}

	if err := r.ValidateRollbackSafety(); err != nil {
		return 0, err
	}

	// Determine which migrations to apply.
	pending := r.pendingUp(current, target)
	if len(pending) == 0 {
		r.logger.Info("migrate: already at target version", "current", current, "target", target)
		return 0, nil
	}

	// Run backup hook before applying.
	if r.backup != nil {
		r.logger.Info("migrate: running pre-migration backup hook", "currentVersion", current)
		if err := r.backup(ctx, current); err != nil {
			return 0, fmt.Errorf("%w: %v", ErrBackupFailed, err)
		}
	}

	// Apply migrations sequentially.
	for i := range pending {
		m := &pending[i]
		r.logger.Info("migrate: applying migration",
			"version", m.Version,
			"direction", m.Direction,
			"description", m.Description,
		)

		// Mark dirty before execution.
		if err := r.store.SetVersion(ctx, m.Version, true); err != nil {
			return applied, fmt.Errorf("migrate: mark dirty v%d: %w", m.Version, err)
		}

		if err := r.execSQL(ctx, m.SQL); err != nil {
			return applied, fmt.Errorf("migrate: apply v%d (%s): %w", m.Version, m.Description, err)
		}

		// Mark clean after successful execution.
		if err := r.store.SetVersion(ctx, m.Version, false); err != nil {
			return applied, fmt.Errorf("migrate: mark clean v%d: %w", m.Version, err)
		}

		applied++
	}

	r.logger.Info("migrate: completed", "applied", applied, "newVersion", target)
	return applied, nil
}

// MigrateDown rolls back one migration from the current version.
func (r *Runner) MigrateDown(ctx context.Context) error {
	return r.MigrateDownTo(ctx, -1)
}

// MigrateDownTo rolls back migrations down to (but not including) the target version.
// Pass target=0 to roll back all migrations.
// Pass target=-1 to roll back exactly one migration.
func (r *Runner) MigrateDownTo(ctx context.Context, target int) error {
	if err := r.acquireLock(ctx); err != nil {
		return err
	}
	defer r.releaseLock(ctx)

	if err := r.store.Init(ctx); err != nil {
		return fmt.Errorf("migrate: init state store: %w", err)
	}

	current, dirty, err := r.store.CurrentVersion(ctx)
	if err != nil {
		return fmt.Errorf("migrate: read current version: %w", err)
	}
	if dirty {
		return fmt.Errorf("%w: version %d", ErrDirtyState, current)
	}

	// -1 means "roll back one step".
	if target == -1 {
		target = current - 1
	}

	if target >= current {
		r.logger.Info("migrate: nothing to roll back", "current", current, "target", target)
		return nil
	}

	if target < 0 {
		target = 0
	}

	// Get down migrations in reverse order.
	pending := r.pendingDown(current, target)
	if len(pending) == 0 {
		if current == 0 {
			return nil
		}
		return fmt.Errorf("%w: version %d", ErrNoDownMigration, current)
	}

	// Run backup hook before rollback.
	if r.backup != nil {
		r.logger.Info("migrate: running pre-rollback backup hook", "currentVersion", current)
		if err := r.backup(ctx, current); err != nil {
			return fmt.Errorf("%w: %v", ErrBackupFailed, err)
		}
	}

	for i := range pending {
		m := &pending[i]
		r.logger.Info("migrate: rolling back migration",
			"version", m.Version,
			"description", m.Description,
		)

		// Mark the migration currently being executed as dirty.
		newVersion := m.Version - 1
		if err := r.store.SetVersion(ctx, m.Version, true); err != nil {
			return fmt.Errorf("migrate: mark dirty rollback v%d: %w", m.Version, err)
		}

		if err := r.execSQL(ctx, m.SQL); err != nil {
			return fmt.Errorf("migrate: rollback v%d (%s): %w", m.Version, m.Description, err)
		}

		// Mark clean.
		if err := r.store.SetVersion(ctx, newVersion, false); err != nil {
			return fmt.Errorf("migrate: mark clean after rollback v%d: %w", m.Version, err)
		}
	}

	r.logger.Info("migrate: rollback completed", "newVersion", target)
	return nil
}

// CurrentVersion returns the current migration version.
func (r *Runner) CurrentVersion(ctx context.Context) (version int, dirty bool, err error) {
	if err := r.store.Init(ctx); err != nil {
		return 0, false, err
	}
	return r.store.CurrentVersion(ctx)
}

// LatestVersion returns the highest version available in the migration source.
func (r *Runner) LatestVersion() int {
	return r.latestVersion()
}

// Pending returns the number of unapplied up migrations from current to latest.
func (r *Runner) Pending(ctx context.Context) (int, error) {
	if err := r.store.Init(ctx); err != nil {
		return 0, err
	}
	current, _, err := r.store.CurrentVersion(ctx)
	if err != nil {
		return 0, err
	}
	return len(r.pendingUp(current, r.latestVersion())), nil
}

// --- Internal helpers ---

func (r *Runner) latestVersion() int {
	latest := 0
	for i := range r.migrations {
		if r.migrations[i].Direction == Up && r.migrations[i].Version > latest {
			latest = r.migrations[i].Version
		}
	}
	return latest
}

func (r *Runner) pendingUp(current, target int) []Migration {
	var result []Migration
	for i := range r.migrations {
		m := &r.migrations[i]
		if m.Direction == Up && m.Version > current && m.Version <= target {
			result = append(result, *m)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Version < result[j].Version })
	return result
}

func (r *Runner) pendingDown(current, target int) []Migration {
	var result []Migration
	for i := range r.migrations {
		m := &r.migrations[i]
		if m.Direction == Down && m.Version <= current && m.Version > target {
			result = append(result, *m)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Version > result[j].Version })
	return result
}

func (r *Runner) acquireLock(ctx context.Context) error {
	if r.locker == nil {
		return nil
	}
	return r.locker.Lock(ctx)
}

func (r *Runner) releaseLock(ctx context.Context) {
	if r.locker == nil {
		return
	}
	if err := r.locker.Unlock(ctx); err != nil {
		r.logger.Error("migrate: failed to release advisory lock", "error", err)
	}
}

// execSQL delegates SQL execution to the configured SQLExecutor.
func (r *Runner) execSQL(ctx context.Context, sql string) error {
	if r.executor == nil {
		return ErrMissingExecutor
	}
	return r.executor.ExecMigration(ctx, sql)
}

// --- File parsing ---

func parseMigrations(source fs.FS, dir string) ([]Migration, error) {
	if source == nil {
		return nil, fmt.Errorf("migrate: source filesystem is nil")
	}

	entries, err := fs.ReadDir(source, normalizeDir(dir))
	if err != nil {
		return nil, fmt.Errorf("migrate: read directory %q: %w", dir, err)
	}

	var migrations []Migration
	seen := map[string]struct{}{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}

		// I-2 fix: skip (with a warning) any .sql file whose name does not
		// follow the <version>.<description>.<up|down>.sql convention, rather
		// than returning a hard error. Seed files, schema dumps, and fixture
		// files committed for documentation would otherwise block NewRunner.
		m, err := parseFilename(name)
		if err != nil {
			slog.Default().Warn("migrate: skipping unrecognized SQL file",
				slog.String("file", name),
				slog.String("reason", err.Error()),
			)
			continue
		}

		content, err := fs.ReadFile(source, path.Join(normalizeDir(dir), name))
		if err != nil {
			return nil, fmt.Errorf("migrate: read file %s: %w", name, err)
		}
		m.SQL = string(content)
		key := fmt.Sprintf("%d:%s", m.Version, m.Direction)
		if _, ok := seen[key]; ok {
			return nil, fmt.Errorf("%w: version %d direction %s", ErrDuplicatePair, m.Version, m.Direction)
		}
		seen[key] = struct{}{}
		migrations = append(migrations, m)
	}

	return migrations, nil
}

func parseFilename(name string) (Migration, error) {
	// Expected format: NNN_description.up.sql or NNN_description.down.sql
	var m Migration

	switch {
	case strings.HasSuffix(name, ".up.sql"):
		m.Direction = Up
		name = strings.TrimSuffix(name, ".up.sql")
	case strings.HasSuffix(name, ".down.sql"):
		m.Direction = Down
		name = strings.TrimSuffix(name, ".down.sql")
	default:
		return m, fmt.Errorf("migrate: unrecognized file suffix: %s", name)
	}

	parts := strings.SplitN(name, "_", 2)
	if len(parts) < 2 {
		return m, fmt.Errorf("%w: filename %q must be NNN_description", ErrInvalidVersion, name)
	}

	version, err := strconv.Atoi(parts[0])
	if err != nil || version <= 0 {
		return m, fmt.Errorf("%w: %q is not a positive integer", ErrInvalidVersion, parts[0])
	}

	m.Version = version
	m.Description = parts[1]
	return m, nil
}

func normalizeDir(dir string) string {
	if dir == "" {
		return "."
	}
	return dir
}

// --- Timestamp helper for logging ---

// Timestamp returns the current UTC time formatted for migration logs.
func Timestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}
