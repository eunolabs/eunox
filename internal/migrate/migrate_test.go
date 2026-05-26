// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package migrate

import (
	"context"
	"errors"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testFS() fs.FS {
	return fstest.MapFS{
		"001_create_users.up.sql":   {Data: []byte("CREATE TABLE users (id TEXT);")},
		"001_create_users.down.sql": {Data: []byte("DROP TABLE users;")},
		"002_add_email.up.sql":      {Data: []byte("ALTER TABLE users ADD COLUMN email TEXT;")},
		"002_add_email.down.sql":    {Data: []byte("ALTER TABLE users DROP COLUMN email;")},
		"003_add_index.up.sql":      {Data: []byte("CREATE INDEX idx_users_email ON users(email);")},
		"003_add_index.down.sql":    {Data: []byte("DROP INDEX idx_users_email;")},
	}
}

func testFSNoDown() fs.FS {
	return fstest.MapFS{
		"001_create_users.up.sql": {Data: []byte("CREATE TABLE users (id TEXT);")},
		"002_add_email.up.sql":    {Data: []byte("ALTER TABLE users ADD COLUMN email TEXT;")},
	}
}

func testFSWithSubdir() fs.FS {
	return fstest.MapFS{
		"minter/001_create_keys.up.sql":   {Data: []byte("CREATE TABLE api_keys (id TEXT);")},
		"minter/001_create_keys.down.sql": {Data: []byte("DROP TABLE api_keys;")},
	}
}

func newTestRunner(t *testing.T, source fs.FS, dir string, executor SQLExecutor, locker AdvisoryLocker, backup BackupHook) *Runner {
	t.Helper()
	if executor == nil {
		executor = NewMemoryExecutor()
	}
	r, err := NewRunner(&Config{
		Source:     source,
		Dir:        dir,
		Store:      NewMemoryStateStore(),
		Executor:   executor,
		Locker:     locker,
		BackupHook: backup,
	})
	require.NoError(t, err)
	return r
}

// --- NewRunner tests ---

func TestNewRunner_Success(t *testing.T) {
	r, err := NewRunner(&Config{
		Source:   testFS(),
		Store:    NewMemoryStateStore(),
		Executor: NewMemoryExecutor(),
	})
	require.NoError(t, err)
	assert.NotNil(t, r)
	assert.Equal(t, 3, r.LatestVersion())
}

func TestNewRunner_WithSubdir(t *testing.T) {
	r, err := NewRunner(&Config{
		Source:   testFSWithSubdir(),
		Dir:      "minter",
		Store:    NewMemoryStateStore(),
		Executor: NewMemoryExecutor(),
	})
	require.NoError(t, err)
	assert.Equal(t, 1, r.LatestVersion())
}

func TestNewRunner_NilSource(t *testing.T) {
	_, err := NewRunner(&Config{
		Source:   nil,
		Store:    NewMemoryStateStore(),
		Executor: NewMemoryExecutor(),
	})
	assert.Error(t, err)
}

func TestNewRunner_NilConfig(t *testing.T) {
	_, err := NewRunner(nil)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

func TestNewRunner_NilStore(t *testing.T) {
	_, err := NewRunner(&Config{
		Source:   testFS(),
		Executor: NewMemoryExecutor(),
	})
	assert.ErrorIs(t, err, ErrMissingStore)
}

func TestNewRunner_NilExecutor(t *testing.T) {
	_, err := NewRunner(&Config{
		Source: testFS(),
		Store:  NewMemoryStateStore(),
	})
	assert.ErrorIs(t, err, ErrMissingExecutor)
}

func TestNewRunner_EmptyDir(t *testing.T) {
	emptyFS := fstest.MapFS{
		"readme.txt": {Data: []byte("no migrations here")},
	}
	_, err := NewRunner(&Config{
		Source:   emptyFS,
		Store:    NewMemoryStateStore(),
		Executor: NewMemoryExecutor(),
	})
	assert.ErrorIs(t, err, ErrNoMigrations)
}

func TestNewRunner_InvalidFilename(t *testing.T) {
	badFS := fstest.MapFS{
		"abc_bad.up.sql": {Data: []byte("SELECT 1;")},
	}
	_, err := NewRunner(&Config{
		Source:   badFS,
		Store:    NewMemoryStateStore(),
		Executor: NewMemoryExecutor(),
	})
	assert.ErrorIs(t, err, ErrInvalidVersion)
}

func TestNewRunner_ZeroVersion(t *testing.T) {
	badFS := fstest.MapFS{
		"000_bad.up.sql": {Data: []byte("SELECT 1;")},
	}
	_, err := NewRunner(&Config{
		Source:   badFS,
		Store:    NewMemoryStateStore(),
		Executor: NewMemoryExecutor(),
	})
	assert.ErrorIs(t, err, ErrInvalidVersion)
}

// --- ValidateRollbackSafety tests ---

func TestValidateRollbackSafety_AllPaired(t *testing.T) {
	r := newTestRunner(t, testFS(), "", nil, nil, nil)
	err := r.ValidateRollbackSafety()
	assert.NoError(t, err)
}

func TestValidateRollbackSafety_MissingDown(t *testing.T) {
	r := newTestRunner(t, testFSNoDown(), "", nil, nil, nil)
	err := r.ValidateRollbackSafety()
	assert.ErrorIs(t, err, ErrNoDownMigration)
}

// --- MigrateUp tests ---

func TestMigrateUp_AllMigrations(t *testing.T) {
	exec := NewMemoryExecutor()
	r := newTestRunner(t, testFS(), "", exec, nil, nil)

	applied, err := r.MigrateUp(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 3, applied)
	assert.Len(t, exec.Executed, 3)
	assert.Equal(t, "CREATE TABLE users (id TEXT);", exec.Executed[0])
	assert.Equal(t, "ALTER TABLE users ADD COLUMN email TEXT;", exec.Executed[1])
	assert.Equal(t, "CREATE INDEX idx_users_email ON users(email);", exec.Executed[2])
}

func TestMigrateUp_Idempotent(t *testing.T) {
	exec := NewMemoryExecutor()
	r := newTestRunner(t, testFS(), "", exec, nil, nil)

	_, err := r.MigrateUp(context.Background())
	require.NoError(t, err)

	// Running again should apply nothing.
	applied, err := r.MigrateUp(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, applied)
	assert.Len(t, exec.Executed, 3) // No additional executions.
}

func TestMigrateUpTo_PartialMigration(t *testing.T) {
	exec := NewMemoryExecutor()
	r := newTestRunner(t, testFS(), "", exec, nil, nil)

	applied, err := r.MigrateUpTo(context.Background(), 2)
	require.NoError(t, err)
	assert.Equal(t, 2, applied)
	assert.Len(t, exec.Executed, 2)
}

func TestMigrateUp_DirtyState(t *testing.T) {
	store := NewMemoryStateStore()
	_ = store.Init(context.Background())
	_ = store.SetVersion(context.Background(), 1, true) // Dirty!

	r, err := NewRunner(&Config{
		Source:   testFS(),
		Store:    store,
		Executor: NewMemoryExecutor(),
	})
	require.NoError(t, err)

	_, err = r.MigrateUp(context.Background())
	assert.ErrorIs(t, err, ErrDirtyState)
}

func TestMigrateUp_RollbackSafetyFails(t *testing.T) {
	store := NewMemoryStateStore()
	r, err := NewRunner(&Config{
		Source:   testFSNoDown(),
		Store:    store,
		Executor: NewMemoryExecutor(),
	})
	require.NoError(t, err)

	_, err = r.MigrateUp(context.Background())
	assert.ErrorIs(t, err, ErrNoDownMigration)
}

func TestMigrateUp_WithAdvisoryLock(t *testing.T) {
	exec := NewMemoryExecutor()
	locker := NewMemoryLocker()
	r := newTestRunner(t, testFS(), "", exec, locker, nil)

	applied, err := r.MigrateUp(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 3, applied)
	// Lock should be released after migration.
	assert.False(t, locker.IsHeld())
}

func TestMigrateUp_LockAlreadyHeld(t *testing.T) {
	exec := NewMemoryExecutor()
	locker := NewMemoryLocker()
	_ = locker.Lock(context.Background()) // Pre-hold the lock.

	r := newTestRunner(t, testFS(), "", exec, locker, nil)

	_, err := r.MigrateUp(context.Background())
	assert.ErrorIs(t, err, ErrLockHeld)
}

func TestMigrateUp_BackupHookCalled(t *testing.T) {
	exec := NewMemoryExecutor()
	backupCalled := false
	backup := func(_ context.Context, version int) error {
		backupCalled = true
		assert.Equal(t, 0, version) // Starting from scratch.
		return nil
	}

	r := newTestRunner(t, testFS(), "", exec, nil, backup)
	_, err := r.MigrateUp(context.Background())
	require.NoError(t, err)
	assert.True(t, backupCalled)
}

func TestMigrateUp_BackupHookFails(t *testing.T) {
	exec := NewMemoryExecutor()
	backup := func(_ context.Context, _ int) error {
		return errors.New("backup failed: disk full")
	}

	r := newTestRunner(t, testFS(), "", exec, nil, backup)
	_, err := r.MigrateUp(context.Background())
	assert.ErrorIs(t, err, ErrBackupFailed)
	assert.Empty(t, exec.Executed) // No migrations should run.
}

func TestMigrateUp_ExecutorFails(t *testing.T) {
	exec := NewMemoryExecutor()
	exec.FailOnSQL = "ALTER TABLE users ADD COLUMN email TEXT;"
	exec.FailError = errors.New("syntax error")

	r := newTestRunner(t, testFS(), "", exec, nil, nil)
	applied, err := r.MigrateUp(context.Background())
	assert.Error(t, err)
	assert.Equal(t, 1, applied) // Only first migration succeeded.
	assert.Contains(t, err.Error(), "v2")
}

// --- MigrateDown tests ---

func TestMigrateDown_OneStep(t *testing.T) {
	exec := NewMemoryExecutor()
	r := newTestRunner(t, testFS(), "", exec, nil, nil)

	// First migrate up.
	_, err := r.MigrateUp(context.Background())
	require.NoError(t, err)
	exec.Executed = nil // Reset.

	// Roll back one step.
	err = r.MigrateDown(context.Background())
	require.NoError(t, err)
	assert.Len(t, exec.Executed, 1)
	assert.Equal(t, "DROP INDEX idx_users_email;", exec.Executed[0])
}

func TestMigrateDownTo_MultipleSteps(t *testing.T) {
	exec := NewMemoryExecutor()
	r := newTestRunner(t, testFS(), "", exec, nil, nil)

	_, err := r.MigrateUp(context.Background())
	require.NoError(t, err)
	exec.Executed = nil

	// Roll back to version 1.
	err = r.MigrateDownTo(context.Background(), 1)
	require.NoError(t, err)
	assert.Len(t, exec.Executed, 2)
	// Should be in reverse order: 3 down, then 2 down.
	assert.Equal(t, "DROP INDEX idx_users_email;", exec.Executed[0])
	assert.Equal(t, "ALTER TABLE users DROP COLUMN email;", exec.Executed[1])
}

func TestMigrateDownTo_AllTheWay(t *testing.T) {
	exec := NewMemoryExecutor()
	r := newTestRunner(t, testFS(), "", exec, nil, nil)

	_, err := r.MigrateUp(context.Background())
	require.NoError(t, err)
	exec.Executed = nil

	err = r.MigrateDownTo(context.Background(), 0)
	require.NoError(t, err)
	assert.Len(t, exec.Executed, 3)
}

func TestMigrateDown_NothingToRollback(t *testing.T) {
	exec := NewMemoryExecutor()
	r := newTestRunner(t, testFS(), "", exec, nil, nil)

	// Don't migrate up first.
	err := r.MigrateDown(context.Background())
	require.NoError(t, err)
	assert.Empty(t, exec.Executed)
}

func TestMigrateDown_NoDownMigrationForCurrentVersion(t *testing.T) {
	store := NewMemoryStateStore()
	require.NoError(t, store.Init(context.Background()))
	require.NoError(t, store.SetVersion(context.Background(), 1, false))
	onlyUp := fstest.MapFS{
		"001_create_users.up.sql": {Data: []byte("CREATE TABLE users (id TEXT);")},
	}

	r, err := NewRunner(&Config{
		Source:   onlyUp,
		Store:    store,
		Executor: NewMemoryExecutor(),
	})
	require.NoError(t, err)

	err = r.MigrateDown(context.Background())
	assert.ErrorIs(t, err, ErrNoDownMigration)
}

func TestMigrateDown_DirtyState(t *testing.T) {
	store := NewMemoryStateStore()
	_ = store.Init(context.Background())
	_ = store.SetVersion(context.Background(), 2, true)

	r, err := NewRunner(&Config{
		Source:   testFS(),
		Store:    store,
		Executor: NewMemoryExecutor(),
	})
	require.NoError(t, err)

	err = r.MigrateDown(context.Background())
	assert.ErrorIs(t, err, ErrDirtyState)
}

func TestMigrateDown_WithBackupHook(t *testing.T) {
	exec := NewMemoryExecutor()
	backupVersions := []int{}
	backup := func(_ context.Context, version int) error {
		backupVersions = append(backupVersions, version)
		return nil
	}

	r := newTestRunner(t, testFS(), "", exec, nil, backup)
	_, _ = r.MigrateUp(context.Background())
	exec.Executed = nil

	err := r.MigrateDown(context.Background())
	require.NoError(t, err)
	// Backup called during MigrateUp (at v0) and MigrateDown (at v3).
	require.Len(t, backupVersions, 2)
	assert.Equal(t, 0, backupVersions[0]) // Before up.
	assert.Equal(t, 3, backupVersions[1]) // Before down.
}

func TestMigrateDown_FailedDownLeavesCurrentVersionDirty(t *testing.T) {
	exec := NewMemoryExecutor()
	exec.FailOnSQL = "DROP INDEX idx_users_email;"
	exec.FailError = errors.New("rollback failed")
	store := NewMemoryStateStore()
	r, err := NewRunner(&Config{
		Source:   testFS(),
		Store:    store,
		Executor: exec,
	})
	require.NoError(t, err)
	_, err = r.MigrateUp(context.Background())
	require.NoError(t, err)

	err = r.MigrateDown(context.Background())
	require.Error(t, err)

	version, dirty, err := r.CurrentVersion(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 3, version)
	assert.True(t, dirty)
}

// --- CurrentVersion & Pending tests ---

func TestCurrentVersion(t *testing.T) {
	r := newTestRunner(t, testFS(), "", NewMemoryExecutor(), nil, nil)

	version, dirty, err := r.CurrentVersion(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, version)
	assert.False(t, dirty)

	_, _ = r.MigrateUp(context.Background())

	version, dirty, err = r.CurrentVersion(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 3, version)
	assert.False(t, dirty)
}

func TestPending(t *testing.T) {
	r := newTestRunner(t, testFS(), "", NewMemoryExecutor(), nil, nil)

	pending, err := r.Pending(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 3, pending)

	_, _ = r.MigrateUpTo(context.Background(), 2)

	pending, err = r.Pending(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, pending)
}

// --- File parsing tests ---

func TestParseFilename_Valid(t *testing.T) {
	tests := []struct {
		name        string
		filename    string
		wantVersion int
		wantDir     Direction
		wantDesc    string
	}{
		{"up migration", "001_create_users.up.sql", 1, Up, "create_users"},
		{"down migration", "001_create_users.down.sql", 1, Down, "create_users"},
		{"higher version", "042_add_feature.up.sql", 42, Up, "add_feature"},
		{"multi-word desc", "003_add_user_email_index.up.sql", 3, Up, "add_user_email_index"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := parseFilename(tc.filename)
			require.NoError(t, err)
			assert.Equal(t, tc.wantVersion, m.Version)
			assert.Equal(t, tc.wantDir, m.Direction)
			assert.Equal(t, tc.wantDesc, m.Description)
		})
	}
}

func TestParseFilename_Invalid(t *testing.T) {
	tests := []struct {
		name     string
		filename string
	}{
		{"no suffix", "001_users.sql"},
		{"bad version", "abc_users.up.sql"},
		{"zero version", "000_users.up.sql"},
		{"no underscore", "001.up.sql"},
		{"negative version", "-1_bad.up.sql"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseFilename(tc.filename)
			assert.Error(t, err)
		})
	}
}

func TestNewRunner_DuplicateVersionDirectionRejected(t *testing.T) {
	dup := fstest.MapFS{
		"001_create_users.up.sql":   {Data: []byte("CREATE TABLE users (id TEXT);")},
		"001_create_users2.up.sql":  {Data: []byte("CREATE TABLE users2 (id TEXT);")},
		"001_create_users.down.sql": {Data: []byte("DROP TABLE users;")},
	}
	_, err := NewRunner(&Config{
		Source:   dup,
		Store:    NewMemoryStateStore(),
		Executor: NewMemoryExecutor(),
	})
	assert.ErrorIs(t, err, ErrDuplicatePair)
}

// --- MemoryLocker tests ---

func TestMemoryLocker_LockUnlock(t *testing.T) {
	l := NewMemoryLocker()

	err := l.Lock(context.Background())
	require.NoError(t, err)
	assert.True(t, l.IsHeld())

	err = l.Unlock(context.Background())
	require.NoError(t, err)
	assert.False(t, l.IsHeld())
}

func TestMemoryLocker_DoubleLockFails(t *testing.T) {
	l := NewMemoryLocker()

	_ = l.Lock(context.Background())
	err := l.Lock(context.Background())
	assert.ErrorIs(t, err, ErrLockHeld)
}

// --- MemoryExecutor tests ---

func TestMemoryExecutor_Records(t *testing.T) {
	e := NewMemoryExecutor()

	err := e.ExecMigration(context.Background(), "CREATE TABLE x;")
	require.NoError(t, err)
	assert.Equal(t, []string{"CREATE TABLE x;"}, e.Executed)
}

func TestMemoryExecutor_FailOnSpecificSQL(t *testing.T) {
	e := NewMemoryExecutor()
	e.FailOnSQL = "BAD SQL"
	e.FailError = errors.New("exec failed")

	err := e.ExecMigration(context.Background(), "GOOD SQL")
	require.NoError(t, err)

	err = e.ExecMigration(context.Background(), "BAD SQL")
	assert.Error(t, err)
}

// --- LatestVersion tests ---

func TestLatestVersion(t *testing.T) {
	r := newTestRunner(t, testFS(), "", nil, nil, nil)
	assert.Equal(t, 3, r.LatestVersion())
}

// --- Integration scenario: partial migrate up then down ---

func TestMigrateUpThenPartialDown(t *testing.T) {
	exec := NewMemoryExecutor()
	r := newTestRunner(t, testFS(), "", exec, nil, nil)

	// Migrate up to v2.
	applied, err := r.MigrateUpTo(context.Background(), 2)
	require.NoError(t, err)
	assert.Equal(t, 2, applied)

	// Now migrate up the rest.
	applied, err = r.MigrateUp(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, applied)

	// Roll back to v1.
	exec.Executed = nil
	err = r.MigrateDownTo(context.Background(), 1)
	require.NoError(t, err)
	assert.Len(t, exec.Executed, 2) // v3 down, v2 down
}

func TestMigrateDown_WithLock(t *testing.T) {
	exec := NewMemoryExecutor()
	locker := NewMemoryLocker()
	r := newTestRunner(t, testFS(), "", exec, locker, nil)

	_, _ = r.MigrateUp(context.Background())
	assert.False(t, locker.IsHeld()) // Lock released after up.

	err := r.MigrateDown(context.Background())
	require.NoError(t, err)
	assert.False(t, locker.IsHeld()) // Lock released after down.
}
