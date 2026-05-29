// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package dbtokensvc

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ErrTaskAlreadyRevoked is returned when attempting to mint credentials for
// a task that has already been completed or failed.
var ErrTaskAlreadyRevoked = fmt.Errorf("dbtokensvc: task has been revoked; no new credentials can be minted")

// TaskCredentialRecord tracks a single credential issued for a specific task.
type TaskCredentialRecord struct {
	CredentialID string
	TaskID       string
	UserID       string
	TenantID     string
	Database     string
	Adapter      string
	IssuedAt     time.Time
	ExpiresAt    time.Time
}

// TaskCredentialStore tracks credentials issued per task and provides revocation.
//
// Revocation is logical: the store marks a task as revoked so that subsequent
// mint attempts for the same task are rejected immediately. Credentials issued
// before revocation continue to function until their natural TTL expiry — this
// is an inherent property of cloud IAM tokens (AWS RDS IAM minimum TTL is 15
// minutes). The key benefit is that the privilege-exposure window drops from
// the maximum token TTL to the actual task duration.
type TaskCredentialStore interface {
	// Register records a newly-minted credential associated with a task.
	Register(ctx context.Context, record *TaskCredentialRecord) error

	// Revoke marks a task as revoked and returns the count of credentials that
	// were registered under it. Calling Revoke on an unknown task ID is not an
	// error and returns (0, nil).
	Revoke(ctx context.Context, taskID string) (int, error)

	// IsRevoked reports whether the given task has been revoked.
	IsRevoked(ctx context.Context, taskID string) (bool, error)

	// ListByTask returns all credential records registered for a task.
	// Returns nil, nil when no records exist for the task.
	ListByTask(ctx context.Context, taskID string) ([]TaskCredentialRecord, error)
}

// InMemoryTaskCredentialStore is a thread-safe in-memory [TaskCredentialStore].
// Suitable for single-process deployments. For multi-replica deployments use a
// Redis-backed implementation that coordinates revocation across instances.
type InMemoryTaskCredentialStore struct {
	mu          sync.RWMutex
	credentials map[string][]TaskCredentialRecord // taskID → records
	revoked     map[string]struct{}               // set of revoked task IDs
}

// NewInMemoryTaskCredentialStore creates a new [InMemoryTaskCredentialStore].
func NewInMemoryTaskCredentialStore() *InMemoryTaskCredentialStore {
	return &InMemoryTaskCredentialStore{
		credentials: make(map[string][]TaskCredentialRecord),
		revoked:     make(map[string]struct{}),
	}
}

// Register implements [TaskCredentialStore].
func (s *InMemoryTaskCredentialStore) Register(_ context.Context, record *TaskCredentialRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.credentials[record.TaskID] = append(s.credentials[record.TaskID], *record)
	return nil
}

// Revoke implements [TaskCredentialStore].
func (s *InMemoryTaskCredentialStore) Revoke(_ context.Context, taskID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[taskID] = struct{}{}
	return len(s.credentials[taskID]), nil
}

// IsRevoked implements [TaskCredentialStore].
func (s *InMemoryTaskCredentialStore) IsRevoked(_ context.Context, taskID string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.revoked[taskID]
	return ok, nil
}

// ListByTask implements [TaskCredentialStore].
func (s *InMemoryTaskCredentialStore) ListByTask(_ context.Context, taskID string) ([]TaskCredentialRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	records := s.credentials[taskID]
	if len(records) == 0 {
		return nil, nil
	}
	out := make([]TaskCredentialRecord, len(records))
	copy(out, records)
	return out, nil
}
