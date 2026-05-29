// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package migrate

import (
	"context"
	"sync"
)

// MemoryStateStore is an in-memory implementation of StateStore for testing.
type MemoryStateStore struct {
	mu      sync.Mutex
	version int
	dirty   bool
	inited  bool
}

// NewMemoryStateStore creates a new in-memory state store.
func NewMemoryStateStore() *MemoryStateStore {
	return &MemoryStateStore{}
}

// Init marks the store as initialized.
func (m *MemoryStateStore) Init(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inited = true
	return nil
}

// CurrentVersion returns the current version and dirty state.
func (m *MemoryStateStore) CurrentVersion(_ context.Context) (version int, dirty bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.version, m.dirty, nil
}

// SetVersion sets the current version and dirty state.
func (m *MemoryStateStore) SetVersion(_ context.Context, version int, dirty bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.version = version
	m.dirty = dirty
	return nil
}

// MemoryLocker is an in-memory advisory lock for testing.
type MemoryLocker struct {
	mu   sync.Mutex
	held bool
}

// NewMemoryLocker creates a new in-memory advisory locker.
func NewMemoryLocker() *MemoryLocker {
	return &MemoryLocker{}
}

// Lock acquires the advisory lock.
func (l *MemoryLocker) Lock(_ context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.held {
		return ErrLockHeld
	}
	l.held = true
	return nil
}

// Unlock releases the advisory lock.
func (l *MemoryLocker) Unlock(_ context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.held = false
	return nil
}

// IsHeld returns whether the lock is currently held.
func (l *MemoryLocker) IsHeld() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.held
}

// MemoryExecutor records SQL executions for testing.
type MemoryExecutor struct {
	mu        sync.Mutex
	Executed  []string
	FailOnSQL string // If set, return error when this SQL is encountered.
	FailError error
}

// NewMemoryExecutor creates a new in-memory SQL executor.
func NewMemoryExecutor() *MemoryExecutor {
	return &MemoryExecutor{}
}

// ExecMigration records the SQL and optionally returns an error.
func (e *MemoryExecutor) ExecMigration(_ context.Context, sql string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.FailOnSQL != "" && sql == e.FailOnSQL {
		return e.FailError
	}
	e.Executed = append(e.Executed, sql)
	return nil
}
