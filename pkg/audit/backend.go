// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// DB is a minimal database interface for the audit ledger backends.
// This allows testing without a real PostgreSQL connection.
type DB interface {
	ExecContext(ctx context.Context, query string, args ...any) (Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) Row
	QueryContext(ctx context.Context, query string, args ...any) (Rows, error)
}

// Result is a minimal result interface.
type Result interface {
	RowsAffected() (int64, error)
}

// Row is a minimal row interface for single-row queries.
type Row interface {
	Scan(dest ...any) error
}

// Rows is a minimal rows interface for multi-row queries.
type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Close() error
	Err() error
}

// AdvisoryLock provides PostgreSQL advisory lock operations.
type AdvisoryLock interface {
	// TryLock attempts to acquire an advisory lock. Returns true if acquired.
	TryLock(ctx context.Context, lockID int64) (bool, error)
	// Unlock releases an advisory lock.
	Unlock(ctx context.Context, lockID int64) error
}

// PostgresLedgerBackend implements LedgerBackend using PostgreSQL with a global advisory lock.
// This ensures single-writer semantics for the HMAC chain when running a single replica.
type PostgresLedgerBackend struct {
	db          DB
	lock        AdvisoryLock
	lockID      int64
	lockTimeout time.Duration

	mu     sync.Mutex
	closed bool
}

// PostgresLedgerConfig configures the PostgreSQL ledger backend.
type PostgresLedgerConfig struct {
	// LockID is the advisory lock ID to prevent concurrent writers.
	// Default: 8675309 (arbitrary fixed ID for the audit ledger).
	LockID int64

	// LockTimeout is the maximum time the database session is allowed to wait
	// when acquiring the advisory lock.  When non-zero, AcquireLock emits a
	// PostgreSQL SET lock_timeout statement before calling TryLock so that the
	// database returns a lock_timeout error promptly if contention is detected,
	// rather than waiting indefinitely.  This is only effective when the
	// AdvisoryLock implementation uses a blocking lock call (e.g.
	// pg_advisory_lock); implementations backed by pg_try_advisory_lock return
	// immediately regardless of this setting.
	//
	// A value of 0 (the default) disables the timeout.
	LockTimeout time.Duration
}

const defaultLockID int64 = 8675309

// NewPostgresLedgerBackend creates a new single-replica PostgreSQL ledger backend.
func NewPostgresLedgerBackend(db DB, lock AdvisoryLock, cfg PostgresLedgerConfig) *PostgresLedgerBackend {
	lockID := cfg.LockID
	if lockID == 0 {
		lockID = defaultLockID
	}
	return &PostgresLedgerBackend{
		db:          db,
		lock:        lock,
		lockID:      lockID,
		lockTimeout: cfg.LockTimeout,
	}
}

// AcquireLock attempts to acquire the advisory lock. Must be called before Append.
//
// When PostgresLedgerConfig.LockTimeout is non-zero, AcquireLock first sets the
// session-level lock_timeout so that the subsequent advisory-lock call returns
// quickly when contention is detected rather than blocking indefinitely.
func (b *PostgresLedgerBackend) AcquireLock(ctx context.Context) error {
	if b.lockTimeout > 0 {
		ms := b.lockTimeout.Milliseconds()
		// SET does not support query parameters in PostgreSQL; ms is an int64
		// derived from a time.Duration so there is no injection risk here.
		if _, err := b.db.ExecContext(ctx, fmt.Sprintf("SET lock_timeout = '%dms'", ms)); err != nil {
			return fmt.Errorf("audit: set lock_timeout: %w", err)
		}
	}

	acquired, err := b.lock.TryLock(ctx, b.lockID)
	if err != nil {
		return fmt.Errorf("audit: acquire advisory lock: %w", err)
	}
	if !acquired {
		return ErrLockContention
	}
	return nil
}

// ReleaseLock releases the advisory lock.
func (b *PostgresLedgerBackend) ReleaseLock(ctx context.Context) error {
	return b.lock.Unlock(ctx, b.lockID)
}

// Append persists a signed audit evidence record to PostgreSQL.
func (b *PostgresLedgerBackend) Append(ctx context.Context, evidence *SignedAuditEvidence) error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return ErrBackendClosed
	}
	b.mu.Unlock()

	detail, err := json.Marshal(evidence.Record.Detail)
	if err != nil {
		detail = []byte("null")
	}

	ocsfJSON, err := json.Marshal(evidence.Record.OCSFEvent)
	if err != nil {
		ocsfJSON = []byte("null")
	}

	const query = `INSERT INTO audit_records (
		id, tenant_id, timestamp, event_type, actor_user_id, actor_tenant_id,
		action, resource_uid, resource_type, outcome, detail, ocsf_event,
		signature, algorithm, key_id, chain_hash, previous_hash,
		replica_id, sequence_num
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)`

	_, err = b.db.ExecContext(ctx, query,
		evidence.Record.ID,
		evidence.Record.TenantID,
		evidence.Record.Timestamp,
		evidence.Record.EventType,
		evidence.Record.Actor.UserID,
		evidence.Record.Actor.TenantID,
		evidence.Record.Action,
		evidence.Record.Resource.UID,
		evidence.Record.Resource.Type,
		evidence.Record.Outcome,
		detail,
		ocsfJSON,
		evidence.Signature,
		evidence.Algorithm,
		evidence.KeyID,
		evidence.ChainHash,
		evidence.PreviousHash,
		evidence.ReplicaID,
		evidence.SequenceNum,
	)
	if err != nil {
		return fmt.Errorf("audit: insert record: %w", err)
	}
	return nil
}

// LastChainHash returns the chain hash of the most recent record.
func (b *PostgresLedgerBackend) LastChainHash(ctx context.Context) (string, error) {
	var hash *string
	err := b.db.QueryRowContext(ctx,
		`SELECT chain_hash FROM audit_records ORDER BY sequence_num DESC LIMIT 1`,
	).Scan(&hash)
	if err != nil {
		if isNoRows(err) {
			return "", nil
		}
		return "", fmt.Errorf("audit: query last chain hash: %w", err)
	}
	if hash == nil {
		return "", nil
	}
	return *hash, nil
}

// LastSequenceNum returns the latest sequence number.
func (b *PostgresLedgerBackend) LastSequenceNum(ctx context.Context) (int64, error) {
	var seq *int64
	err := b.db.QueryRowContext(ctx,
		`SELECT sequence_num FROM audit_records ORDER BY sequence_num DESC LIMIT 1`,
	).Scan(&seq)
	if err != nil {
		if isNoRows(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("audit: query last sequence num: %w", err)
	}
	if seq == nil {
		return 0, nil
	}
	return *seq, nil
}

// Close releases held resources.
func (b *PostgresLedgerBackend) Close() error {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	return nil
}

// PerReplicaPostgresLedgerBackend implements LedgerBackend using PostgreSQL with
// per-replica HMAC chains. No advisory lock is needed because each replica maintains
// its own independent chain, enabling horizontal scaling without contention.
type PerReplicaPostgresLedgerBackend struct {
	db        DB
	replicaID string

	mu     sync.Mutex
	closed bool
}

// NewPerReplicaPostgresLedgerBackend creates a lock-free per-replica ledger backend.
func NewPerReplicaPostgresLedgerBackend(db DB, replicaID string) *PerReplicaPostgresLedgerBackend {
	return &PerReplicaPostgresLedgerBackend{
		db:        db,
		replicaID: replicaID,
	}
}

// Append persists a signed audit evidence record scoped to this replica.
func (b *PerReplicaPostgresLedgerBackend) Append(ctx context.Context, evidence *SignedAuditEvidence) error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return ErrBackendClosed
	}
	b.mu.Unlock()

	detail, err := json.Marshal(evidence.Record.Detail)
	if err != nil {
		detail = []byte("null")
	}

	ocsfJSON, err := json.Marshal(evidence.Record.OCSFEvent)
	if err != nil {
		ocsfJSON = []byte("null")
	}

	evidence.ReplicaID = b.replicaID

	const query = `INSERT INTO audit_records (
		id, tenant_id, timestamp, event_type, actor_user_id, actor_tenant_id,
		action, resource_uid, resource_type, outcome, detail, ocsf_event,
		signature, algorithm, key_id, chain_hash, previous_hash,
		replica_id, sequence_num
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)`

	_, err = b.db.ExecContext(ctx, query,
		evidence.Record.ID,
		evidence.Record.TenantID,
		evidence.Record.Timestamp,
		evidence.Record.EventType,
		evidence.Record.Actor.UserID,
		evidence.Record.Actor.TenantID,
		evidence.Record.Action,
		evidence.Record.Resource.UID,
		evidence.Record.Resource.Type,
		evidence.Record.Outcome,
		detail,
		ocsfJSON,
		evidence.Signature,
		evidence.Algorithm,
		evidence.KeyID,
		evidence.ChainHash,
		evidence.PreviousHash,
		b.replicaID,
		evidence.SequenceNum,
	)
	if err != nil {
		return fmt.Errorf("audit: insert record (replica %s): %w", b.replicaID, err)
	}
	return nil
}

// LastChainHash returns the chain hash of the most recent record for this replica.
func (b *PerReplicaPostgresLedgerBackend) LastChainHash(ctx context.Context) (string, error) {
	var hash *string
	err := b.db.QueryRowContext(ctx,
		`SELECT chain_hash FROM audit_records WHERE replica_id = $1 ORDER BY sequence_num DESC LIMIT 1`,
		b.replicaID,
	).Scan(&hash)
	if err != nil {
		if isNoRows(err) {
			return "", nil
		}
		return "", fmt.Errorf("audit: query last chain hash (replica %s): %w", b.replicaID, err)
	}
	if hash == nil {
		return "", nil
	}
	return *hash, nil
}

// LastSequenceNum returns the latest sequence number for this replica.
func (b *PerReplicaPostgresLedgerBackend) LastSequenceNum(ctx context.Context) (int64, error) {
	var seq *int64
	err := b.db.QueryRowContext(ctx,
		`SELECT sequence_num FROM audit_records WHERE replica_id = $1 ORDER BY sequence_num DESC LIMIT 1`,
		b.replicaID,
	).Scan(&seq)
	if err != nil {
		if isNoRows(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("audit: query last sequence num (replica %s): %w", b.replicaID, err)
	}
	if seq == nil {
		return 0, nil
	}
	return *seq, nil
}

// Close releases held resources.
func (b *PerReplicaPostgresLedgerBackend) Close() error {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	return nil
}

// isNoRows checks if an error is a "no rows" sentinel.
// We use a string check to avoid importing database/sql just for sql.ErrNoRows.
func isNoRows(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, errNoRows) || err.Error() == "sql: no rows in result set"
}

var errNoRows = errors.New("sql: no rows in result set")

// --- Query Store ---

// PageParams defines pagination parameters.
type PageParams struct {
	Offset int
	Limit  int
}

// QueryFilter defines filtering criteria for audit queries.
type QueryFilter struct {
	TenantID  string
	EventType string
	Action    string
	ActorID   string
	StartTime *time.Time
	EndTime   *time.Time
}

// QueryResult holds paginated query results.
type QueryResult struct {
	Records    []SignedAuditEvidence
	TotalCount int64
	HasMore    bool
}

// QueryStore provides read-only access to audit records.
type QueryStore interface {
	// Query returns paginated audit records matching the filter.
	Query(ctx context.Context, filter *QueryFilter, page PageParams) (*QueryResult, error)
	// GetByID retrieves a single audit record by ID.
	GetByID(ctx context.Context, id string) (*SignedAuditEvidence, error)
	// GetChainSegment retrieves a contiguous chain segment for verification.
	GetChainSegment(ctx context.Context, replicaID string, fromSeq, toSeq int64) ([]SignedAuditEvidence, error)
}

// PostgresQueryStore implements QueryStore using PostgreSQL.
type PostgresQueryStore struct {
	db DB
}

// NewPostgresQueryStore creates a new read-only query store.
func NewPostgresQueryStore(db DB) *PostgresQueryStore {
	return &PostgresQueryStore{db: db}
}

// Query returns paginated audit records matching the filter.
func (s *PostgresQueryStore) Query(ctx context.Context, filter *QueryFilter, page PageParams) (*QueryResult, error) {
	if filter == nil {
		filter = &QueryFilter{}
	}
	if page.Limit <= 0 {
		page.Limit = 50
	}
	if page.Limit > 1000 {
		page.Limit = 1000
	}
	if page.Offset < 0 {
		return nil, ErrInvalidPage
	}

	// Build WHERE clause dynamically.
	where, args := buildWhereClause(filter)

	// Count total.
	countQuery := "SELECT COUNT(*) FROM audit_records" + where
	var total int64
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("audit: count records: %w", err)
	}

	// Fetch page.
	selectQuery := `SELECT id, tenant_id, timestamp, event_type, actor_user_id, actor_tenant_id,
		action, resource_uid, resource_type, outcome, detail, ocsf_event,
		signature, algorithm, key_id, chain_hash, previous_hash,
		replica_id, sequence_num
		FROM audit_records` + where + ` ORDER BY timestamp DESC, replica_id DESC, sequence_num DESC LIMIT $` + fmt.Sprintf("%d", len(args)+1) + ` OFFSET $` + fmt.Sprintf("%d", len(args)+2)
	args = append(args, page.Limit, page.Offset)

	rows, err := s.db.QueryContext(ctx, selectQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: query records: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var records []SignedAuditEvidence
	for rows.Next() {
		var ev SignedAuditEvidence
		var detail, ocsfJSON []byte
		err := rows.Scan(
			&ev.Record.ID, &ev.Record.TenantID, &ev.Record.Timestamp,
			&ev.Record.EventType, &ev.Record.Actor.UserID, &ev.Record.Actor.TenantID,
			&ev.Record.Action, &ev.Record.Resource.UID, &ev.Record.Resource.Type,
			&ev.Record.Outcome, &detail, &ocsfJSON,
			&ev.Signature, &ev.Algorithm, &ev.KeyID,
			&ev.ChainHash, &ev.PreviousHash, &ev.ReplicaID, &ev.SequenceNum,
		)
		if err != nil {
			return nil, fmt.Errorf("audit: scan record: %w", err)
		}
		ev.Record.Detail = detail
		if len(ocsfJSON) > 0 && string(ocsfJSON) != "null" {
			ev.Record.OCSFEvent = json.RawMessage(ocsfJSON)
		}
		records = append(records, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: iterate records: %w", err)
	}

	return &QueryResult{
		Records:    records,
		TotalCount: total,
		HasMore:    int64(page.Offset+len(records)) < total,
	}, nil
}

// GetByID retrieves a single audit record by ID.
func (s *PostgresQueryStore) GetByID(ctx context.Context, id string) (*SignedAuditEvidence, error) {
	const query = `SELECT id, tenant_id, timestamp, event_type, actor_user_id, actor_tenant_id,
		action, resource_uid, resource_type, outcome, detail, ocsf_event,
		signature, algorithm, key_id, chain_hash, previous_hash,
		replica_id, sequence_num
		FROM audit_records WHERE id = $1`

	var ev SignedAuditEvidence
	var detail, ocsfJSON []byte
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&ev.Record.ID, &ev.Record.TenantID, &ev.Record.Timestamp,
		&ev.Record.EventType, &ev.Record.Actor.UserID, &ev.Record.Actor.TenantID,
		&ev.Record.Action, &ev.Record.Resource.UID, &ev.Record.Resource.Type,
		&ev.Record.Outcome, &detail, &ocsfJSON,
		&ev.Signature, &ev.Algorithm, &ev.KeyID,
		&ev.ChainHash, &ev.PreviousHash, &ev.ReplicaID, &ev.SequenceNum,
	)
	if err != nil {
		if isNoRows(err) {
			return nil, ErrRecordNotFound
		}
		return nil, fmt.Errorf("audit: get by id: %w", err)
	}
	ev.Record.Detail = detail
	if len(ocsfJSON) > 0 && string(ocsfJSON) != "null" {
		ev.Record.OCSFEvent = json.RawMessage(ocsfJSON)
	}
	return &ev, nil
}

// GetChainSegment retrieves a contiguous chain segment for verification.
func (s *PostgresQueryStore) GetChainSegment(ctx context.Context, replicaID string, fromSeq, toSeq int64) ([]SignedAuditEvidence, error) {
	const query = `SELECT id, tenant_id, timestamp, event_type, actor_user_id, actor_tenant_id,
		action, resource_uid, resource_type, outcome, detail, ocsf_event,
		signature, algorithm, key_id, chain_hash, previous_hash,
		replica_id, sequence_num
		FROM audit_records WHERE replica_id = $1 AND sequence_num >= $2 AND sequence_num <= $3
		ORDER BY sequence_num ASC`

	rows, err := s.db.QueryContext(ctx, query, replicaID, fromSeq, toSeq)
	if err != nil {
		return nil, fmt.Errorf("audit: query chain segment: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var records []SignedAuditEvidence
	for rows.Next() {
		var ev SignedAuditEvidence
		var detail, ocsfJSON []byte
		err := rows.Scan(
			&ev.Record.ID, &ev.Record.TenantID, &ev.Record.Timestamp,
			&ev.Record.EventType, &ev.Record.Actor.UserID, &ev.Record.Actor.TenantID,
			&ev.Record.Action, &ev.Record.Resource.UID, &ev.Record.Resource.Type,
			&ev.Record.Outcome, &detail, &ocsfJSON,
			&ev.Signature, &ev.Algorithm, &ev.KeyID,
			&ev.ChainHash, &ev.PreviousHash, &ev.ReplicaID, &ev.SequenceNum,
		)
		if err != nil {
			return nil, fmt.Errorf("audit: scan chain segment record: %w", err)
		}
		ev.Record.Detail = detail
		if len(ocsfJSON) > 0 && string(ocsfJSON) != "null" {
			ev.Record.OCSFEvent = json.RawMessage(ocsfJSON)
		}
		records = append(records, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: iterate chain segment: %w", err)
	}
	return records, nil
}

func buildWhereClause(filter *QueryFilter) (where string, args []any) {
	var conditions []string
	argIdx := 1

	if filter.TenantID != "" {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIdx))
		args = append(args, filter.TenantID)
		argIdx++
	}
	if filter.EventType != "" {
		conditions = append(conditions, fmt.Sprintf("event_type = $%d", argIdx))
		args = append(args, filter.EventType)
		argIdx++
	}
	if filter.Action != "" {
		conditions = append(conditions, fmt.Sprintf("action = $%d", argIdx))
		args = append(args, filter.Action)
		argIdx++
	}
	if filter.ActorID != "" {
		conditions = append(conditions, fmt.Sprintf("actor_user_id = $%d", argIdx))
		args = append(args, filter.ActorID)
		argIdx++
	}
	if filter.StartTime != nil {
		conditions = append(conditions, fmt.Sprintf("timestamp >= $%d", argIdx))
		args = append(args, *filter.StartTime)
		argIdx++
	}
	if filter.EndTime != nil {
		conditions = append(conditions, fmt.Sprintf("timestamp <= $%d", argIdx))
		args = append(args, *filter.EndTime)
	}

	if len(conditions) == 0 {
		return "", nil
	}

	where = " WHERE "
	for i, c := range conditions {
		if i > 0 {
			where += " AND "
		}
		where += c
	}
	return where, args
}
