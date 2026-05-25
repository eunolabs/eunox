// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/edgeobs/euno-platform/euno-go/pkg/crypto"
	"github.com/edgeobs/euno-platform/euno-go/pkg/ocsf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Test Helpers ---

// mockSigner implements crypto.Signer for tests.
type mockSigner struct {
	algorithm crypto.Algorithm
	keyID     string
	sigFunc   func(ctx context.Context, digest []byte) ([]byte, error)
}

func (m *mockSigner) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	if m.sigFunc != nil {
		return m.sigFunc(ctx, digest)
	}
	return []byte("mock-signature"), nil
}

func (m *mockSigner) Algorithm() crypto.Algorithm { return m.algorithm }
func (m *mockSigner) KeyID() string               { return m.keyID }

// inMemoryLedgerBackend is an in-memory implementation of LedgerBackend for tests.
type inMemoryLedgerBackend struct {
	mu      sync.Mutex
	records []SignedAuditEvidence
	closed  bool
}

func newInMemoryLedgerBackend() *inMemoryLedgerBackend {
	return &inMemoryLedgerBackend{}
}

func (b *inMemoryLedgerBackend) Append(_ context.Context, evidence *SignedAuditEvidence) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return ErrBackendClosed
	}
	b.records = append(b.records, *evidence)
	return nil
}

func (b *inMemoryLedgerBackend) LastChainHash(_ context.Context) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.records) == 0 {
		return "", nil
	}
	return b.records[len(b.records)-1].ChainHash, nil
}

func (b *inMemoryLedgerBackend) LastSequenceNum(_ context.Context) (int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.records) == 0 {
		return 0, nil
	}
	return b.records[len(b.records)-1].SequenceNum, nil
}

func (b *inMemoryLedgerBackend) Close() error {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	return nil
}

func (b *inMemoryLedgerBackend) Records() []SignedAuditEvidence {
	b.mu.Lock()
	defer b.mu.Unlock()
	result := make([]SignedAuditEvidence, len(b.records))
	copy(result, b.records)
	return result
}

// --- Pipeline Tests ---

func TestNewPipeline_RequiresSigner(t *testing.T) {
	t.Parallel()
	backend := newInMemoryLedgerBackend()
	_, err := NewPipeline(nil, backend, PipelineConfig{})
	assert.ErrorIs(t, err, ErrNoSigner)
}

func TestNewPipeline_RequiresBackend(t *testing.T) {
	t.Parallel()
	signer := NewEvidenceSigner(&mockSigner{algorithm: crypto.ES256, keyID: "test-key"})
	_, err := NewPipeline(signer, nil, PipelineConfig{})
	assert.ErrorIs(t, err, ErrNoBackend)
}

func TestPipeline_Append_Success(t *testing.T) {
	t.Parallel()

	signer := NewEvidenceSigner(&mockSigner{algorithm: crypto.ES256, keyID: "test-key"})
	backend := newInMemoryLedgerBackend()
	pipeline, err := NewPipeline(signer, backend, PipelineConfig{ReplicaID: "replica-1"})
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, pipeline.Initialize(ctx))

	entry := &LogEntry{
		TenantID:  "tenant-1",
		EventType: "token.issued",
		Actor:     ocsf.Actor{UserID: "user-1", TenantID: "tenant-1"},
		Action:    "issue",
		Outcome:   "success",
	}

	err = pipeline.Append(ctx, entry)
	require.NoError(t, err)

	records := backend.Records()
	require.Len(t, records, 1)

	rec := records[0]
	assert.NotEmpty(t, rec.Record.ID)
	assert.Equal(t, "tenant-1", rec.Record.TenantID)
	assert.Equal(t, "token.issued", rec.Record.EventType)
	assert.NotEmpty(t, rec.Signature)
	assert.Equal(t, "ES256", rec.Algorithm)
	assert.Equal(t, "test-key", rec.KeyID)
	assert.NotEmpty(t, rec.ChainHash)
	assert.Empty(t, rec.PreviousHash) // First record has no previous.
	assert.Equal(t, "replica-1", rec.ReplicaID)
	assert.Equal(t, int64(1), rec.SequenceNum)
}

func TestPipeline_Append_ChainIntegrity(t *testing.T) {
	t.Parallel()

	signer := NewEvidenceSigner(&mockSigner{algorithm: crypto.ES256, keyID: "test-key"})
	backend := newInMemoryLedgerBackend()
	pipeline, err := NewPipeline(signer, backend, PipelineConfig{ReplicaID: "replica-1"})
	require.NoError(t, err)
	require.NoError(t, pipeline.Initialize(context.Background()))

	ctx := context.Background()

	// Append multiple entries.
	for i := 0; i < 5; i++ {
		entry := &LogEntry{
			TenantID:  "tenant-1",
			EventType: "token.issued",
			Actor:     ocsf.Actor{UserID: "user-1"},
			Action:    "issue",
			Outcome:   "success",
		}
		require.NoError(t, pipeline.Append(ctx, entry))
	}

	records := backend.Records()
	require.Len(t, records, 5)

	// Verify chain integrity.
	for i, rec := range records {
		// Verify chain hash.
		assert.True(t, VerifyChainHash(&rec), "chain hash verification failed at record %d", i)

		// Verify previous hash linkage.
		if i == 0 {
			assert.Empty(t, rec.PreviousHash)
		} else {
			assert.Equal(t, records[i-1].ChainHash, rec.PreviousHash,
				"previous hash mismatch at record %d", i)
		}

		// Verify sequence numbers are monotonically increasing.
		assert.Equal(t, int64(i+1), rec.SequenceNum)
	}
}

func TestPipeline_Append_DetectsTampering(t *testing.T) {
	t.Parallel()

	signer := NewEvidenceSigner(&mockSigner{algorithm: crypto.ES256, keyID: "test-key"})
	backend := newInMemoryLedgerBackend()
	pipeline, err := NewPipeline(signer, backend, PipelineConfig{ReplicaID: "replica-1"})
	require.NoError(t, err)
	require.NoError(t, pipeline.Initialize(context.Background()))

	ctx := context.Background()

	entry := &LogEntry{
		TenantID:  "tenant-1",
		EventType: "token.issued",
		Actor:     ocsf.Actor{UserID: "user-1"},
		Action:    "issue",
		Outcome:   "success",
	}
	require.NoError(t, pipeline.Append(ctx, entry))

	records := backend.Records()
	require.Len(t, records, 1)

	// Tamper with the record ID (which is an input to chain hash).
	tampered := records[0]
	tampered.Record.ID = "tampered-id"

	// Chain hash verification should fail because ID is part of the hash input.
	assert.False(t, VerifyChainHash(&tampered), "tampered record ID should fail chain verification")

	// Tamper with the signature (also part of chain hash input).
	tampered2 := records[0]
	tampered2.Signature = "tampered-signature"
	assert.False(t, VerifyChainHash(&tampered2), "tampered signature should fail chain verification")
}

func TestPipeline_Append_NilEntry(t *testing.T) {
	t.Parallel()

	signer := NewEvidenceSigner(&mockSigner{algorithm: crypto.ES256, keyID: "test-key"})
	backend := newInMemoryLedgerBackend()
	pipeline, err := NewPipeline(signer, backend, PipelineConfig{})
	require.NoError(t, err)

	err = pipeline.Append(context.Background(), nil)
	assert.ErrorIs(t, err, ErrNilEntry)
}

func TestPipeline_Append_AfterClose(t *testing.T) {
	t.Parallel()

	signer := NewEvidenceSigner(&mockSigner{algorithm: crypto.ES256, keyID: "test-key"})
	backend := newInMemoryLedgerBackend()
	pipeline, err := NewPipeline(signer, backend, PipelineConfig{})
	require.NoError(t, err)
	require.NoError(t, pipeline.Initialize(context.Background()))

	require.NoError(t, pipeline.Close())

	err = pipeline.Append(context.Background(), &LogEntry{
		EventType: "test",
		Action:    "test",
	})
	assert.ErrorIs(t, err, ErrBackendClosed)
}

func TestPipeline_Append_AssignsIDAndTimestamp(t *testing.T) {
	t.Parallel()

	signer := NewEvidenceSigner(&mockSigner{algorithm: crypto.ES256, keyID: "test-key"})
	backend := newInMemoryLedgerBackend()
	pipeline, err := NewPipeline(signer, backend, PipelineConfig{})
	require.NoError(t, err)
	require.NoError(t, pipeline.Initialize(context.Background()))

	entry := &LogEntry{
		TenantID:  "tenant-1",
		EventType: "test",
		Action:    "action",
		Outcome:   "success",
	}
	require.NoError(t, pipeline.Append(context.Background(), entry))

	records := backend.Records()
	require.Len(t, records, 1)
	assert.NotEmpty(t, records[0].Record.ID)
	assert.False(t, records[0].Record.Timestamp.IsZero())
}

func TestPipeline_Append_PreservesExistingID(t *testing.T) {
	t.Parallel()

	signer := NewEvidenceSigner(&mockSigner{algorithm: crypto.ES256, keyID: "test-key"})
	backend := newInMemoryLedgerBackend()
	pipeline, err := NewPipeline(signer, backend, PipelineConfig{})
	require.NoError(t, err)
	require.NoError(t, pipeline.Initialize(context.Background()))

	entry := &LogEntry{
		ID:        "custom-id-123",
		TenantID:  "tenant-1",
		EventType: "test",
		Action:    "action",
		Outcome:   "success",
	}
	require.NoError(t, pipeline.Append(context.Background(), entry))

	records := backend.Records()
	assert.Equal(t, "custom-id-123", records[0].Record.ID)
}

func TestPipeline_Append_WithOCSFEvent(t *testing.T) {
	t.Parallel()

	signer := NewEvidenceSigner(&mockSigner{algorithm: crypto.ES256, keyID: "test-key"})
	backend := newInMemoryLedgerBackend()
	pipeline, err := NewPipeline(signer, backend, PipelineConfig{})
	require.NoError(t, err)
	require.NoError(t, pipeline.Initialize(context.Background()))

	ocsfEvent := ocsf.NewAuthorizationEvent(ocsf.ActivityAuthGrant, ocsf.Actor{
		UserID:   "user-1",
		TenantID: "tenant-1",
	})

	entry := &LogEntry{
		TenantID:  "tenant-1",
		EventType: "authorization",
		Actor:     ocsf.Actor{UserID: "user-1", TenantID: "tenant-1"},
		Action:    "grant",
		Outcome:   "success",
		OCSFEvent: ocsfEvent,
	}
	require.NoError(t, pipeline.Append(context.Background(), entry))

	records := backend.Records()
	require.Len(t, records, 1)
	assert.NotNil(t, records[0].Record.OCSFEvent)
}

func TestPipeline_ReplicaID(t *testing.T) {
	t.Parallel()

	signer := NewEvidenceSigner(&mockSigner{algorithm: crypto.ES256, keyID: "test-key"})
	backend := newInMemoryLedgerBackend()

	// With explicit replica ID.
	pipeline, err := NewPipeline(signer, backend, PipelineConfig{ReplicaID: "my-replica"})
	require.NoError(t, err)
	assert.Equal(t, "my-replica", pipeline.ReplicaID())

	// Without explicit replica ID (auto-generated).
	pipeline2, err := NewPipeline(signer, backend, PipelineConfig{})
	require.NoError(t, err)
	assert.NotEmpty(t, pipeline2.ReplicaID())
	assert.NotEqual(t, "my-replica", pipeline2.ReplicaID())
}

// --- EvidenceSigner Tests ---

func TestEvidenceSigner_Sign(t *testing.T) {
	t.Parallel()

	signer := NewEvidenceSigner(&mockSigner{
		algorithm: crypto.ES256,
		keyID:     "test-key",
		sigFunc: func(_ context.Context, digest []byte) ([]byte, error) {
			return append([]byte("signed:"), digest[:8]...), nil
		},
	})

	entry := &LogEntry{
		ID:        "entry-1",
		Timestamp: time.Now().UTC(),
		TenantID:  "tenant-1",
		EventType: "test",
		Action:    "test-action",
		Outcome:   "success",
	}

	sig, err := signer.Sign(context.Background(), entry)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)
	assert.Equal(t, "ES256", signer.Algorithm())
	assert.Equal(t, "test-key", signer.KeyID())
}

func TestEvidenceSigner_SignError(t *testing.T) {
	t.Parallel()

	expectedErr := errors.New("signing failed")
	signer := NewEvidenceSigner(&mockSigner{
		algorithm: crypto.ES256,
		keyID:     "test-key",
		sigFunc: func(_ context.Context, _ []byte) ([]byte, error) {
			return nil, expectedErr
		},
	})

	entry := &LogEntry{
		ID:        "entry-1",
		EventType: "test",
		Action:    "action",
	}

	_, err := signer.Sign(context.Background(), entry)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signing failed")
}

// --- Chain Hash Tests ---

func TestComputeChainHash_Genesis(t *testing.T) {
	t.Parallel()

	hash := ComputeChainHash("", "record-1", time.Now().UTC(), "sig-1")
	assert.NotEmpty(t, hash)
}

func TestComputeChainHash_Deterministic(t *testing.T) {
	t.Parallel()

	ts := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	hash1 := ComputeChainHash("prev-hash", "record-1", ts, "sig-1")
	hash2 := ComputeChainHash("prev-hash", "record-1", ts, "sig-1")
	assert.Equal(t, hash1, hash2)
}

func TestComputeChainHash_DifferentInputsProduceDifferentHashes(t *testing.T) {
	t.Parallel()

	ts := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	hash1 := ComputeChainHash("prev-hash", "record-1", ts, "sig-1")
	hash2 := ComputeChainHash("prev-hash", "record-2", ts, "sig-1")
	hash3 := ComputeChainHash("different-prev", "record-1", ts, "sig-1")

	assert.NotEqual(t, hash1, hash2)
	assert.NotEqual(t, hash1, hash3)
}

func TestVerifyChainHash_Valid(t *testing.T) {
	t.Parallel()

	ts := time.Now().UTC()
	chainHash := ComputeChainHash("prev", "id-1", ts, "sig-1")

	evidence := &SignedAuditEvidence{
		Record: LogEntry{
			ID:        "id-1",
			Timestamp: ts,
		},
		Signature:    "sig-1",
		PreviousHash: "prev",
		ChainHash:    chainHash,
	}

	assert.True(t, VerifyChainHash(evidence))
}

func TestVerifyChainHash_Invalid(t *testing.T) {
	t.Parallel()

	evidence := &SignedAuditEvidence{
		Record: LogEntry{
			ID:        "id-1",
			Timestamp: time.Now().UTC(),
		},
		Signature:    "sig-1",
		PreviousHash: "prev",
		ChainHash:    "definitely-wrong-hash",
	}

	assert.False(t, VerifyChainHash(evidence))
}

// --- Detail marshaling test ---

func TestLogEntry_DetailMarshal(t *testing.T) {
	t.Parallel()

	detail := map[string]string{"key": "value", "tool": "code-search"}
	detailJSON, err := json.Marshal(detail)
	require.NoError(t, err)

	entry := &LogEntry{
		ID:        "entry-1",
		TenantID:  "tenant-1",
		EventType: "api.call",
		Action:    "tool-invoke",
		Outcome:   "success",
		Detail:    detailJSON,
	}

	data, err := json.Marshal(entry)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"code-search"`)
}

// --- PostgresLedgerBackend Tests (with mock DB) ---

type mockResult struct {
	rowsAffected int64
}

func (m *mockResult) RowsAffected() (int64, error) { return m.rowsAffected, nil }

type mockRow struct {
	values []any
	err    error
}

func (m *mockRow) Scan(dest ...any) error {
	if m.err != nil {
		return m.err
	}
	for i, d := range dest {
		if i < len(m.values) {
			switch v := d.(type) {
			case **string:
				if m.values[i] != nil {
					s := m.values[i].(string)
					*v = &s
				}
			case **int64:
				if m.values[i] != nil {
					n := m.values[i].(int64)
					*v = &n
				}
			}
		}
	}
	return nil
}

type mockRows struct {
	current int
	data    [][]any
	err     error
}

func (m *mockRows) Next() bool {
	m.current++
	return m.current <= len(m.data)
}

func (m *mockRows) Scan(_ ...any) error { return nil }
func (m *mockRows) Close() error        { return nil }
func (m *mockRows) Err() error           { return m.err }

type mockDB struct {
	execErr  error
	queryRow *mockRow
	rows     *mockRows
}

func (m *mockDB) ExecContext(_ context.Context, _ string, _ ...any) (Result, error) {
	if m.execErr != nil {
		return nil, m.execErr
	}
	return &mockResult{rowsAffected: 1}, nil
}

func (m *mockDB) QueryRowContext(_ context.Context, _ string, _ ...any) Row {
	if m.queryRow != nil {
		return m.queryRow
	}
	return &mockRow{err: errNoRows}
}

func (m *mockDB) QueryContext(_ context.Context, _ string, _ ...any) (Rows, error) {
	if m.rows != nil {
		return m.rows, nil
	}
	return &mockRows{}, nil
}

type mockAdvisoryLock struct {
	locked bool
	err    error
}

func (m *mockAdvisoryLock) TryLock(_ context.Context, _ int64) (bool, error) {
	if m.err != nil {
		return false, m.err
	}
	if m.locked {
		return false, nil
	}
	m.locked = true
	return true, nil
}

func (m *mockAdvisoryLock) Unlock(_ context.Context, _ int64) error {
	m.locked = false
	return nil
}

func TestPostgresLedgerBackend_AcquireLock(t *testing.T) {
	t.Parallel()

	lock := &mockAdvisoryLock{}
	db := &mockDB{}
	backend := NewPostgresLedgerBackend(db, lock, PostgresLedgerConfig{})

	err := backend.AcquireLock(context.Background())
	require.NoError(t, err)
	assert.True(t, lock.locked)
}

func TestPostgresLedgerBackend_AcquireLock_Contention(t *testing.T) {
	t.Parallel()

	lock := &mockAdvisoryLock{locked: true}
	db := &mockDB{}
	backend := NewPostgresLedgerBackend(db, lock, PostgresLedgerConfig{})

	err := backend.AcquireLock(context.Background())
	assert.ErrorIs(t, err, ErrLockContention)
}

func TestPostgresLedgerBackend_Append(t *testing.T) {
	t.Parallel()

	db := &mockDB{}
	lock := &mockAdvisoryLock{}
	backend := NewPostgresLedgerBackend(db, lock, PostgresLedgerConfig{})

	evidence := &SignedAuditEvidence{
		Record: LogEntry{
			ID:        "rec-1",
			TenantID:  "tenant-1",
			Timestamp: time.Now().UTC(),
			EventType: "test",
			Actor:     ocsf.Actor{UserID: "user-1", TenantID: "tenant-1"},
			Action:    "test-action",
			Outcome:   "success",
		},
		Signature:   "sig-1",
		Algorithm:   "ES256",
		KeyID:       "key-1",
		ChainHash:   "chain-1",
		ReplicaID:   "replica-1",
		SequenceNum: 1,
	}

	err := backend.Append(context.Background(), evidence)
	require.NoError(t, err)
}

func TestPostgresLedgerBackend_Append_DBError(t *testing.T) {
	t.Parallel()

	db := &mockDB{execErr: errors.New("connection refused")}
	lock := &mockAdvisoryLock{}
	backend := NewPostgresLedgerBackend(db, lock, PostgresLedgerConfig{})

	evidence := &SignedAuditEvidence{
		Record: LogEntry{ID: "rec-1", Timestamp: time.Now().UTC()},
	}

	err := backend.Append(context.Background(), evidence)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")
}

func TestPostgresLedgerBackend_LastChainHash_Empty(t *testing.T) {
	t.Parallel()

	db := &mockDB{}
	lock := &mockAdvisoryLock{}
	backend := NewPostgresLedgerBackend(db, lock, PostgresLedgerConfig{})

	hash, err := backend.LastChainHash(context.Background())
	require.NoError(t, err)
	assert.Empty(t, hash)
}

func TestPostgresLedgerBackend_LastChainHash_HasRecords(t *testing.T) {
	t.Parallel()

	hash := "abc123"
	db := &mockDB{
		queryRow: &mockRow{values: []any{hash}},
	}
	lock := &mockAdvisoryLock{}
	backend := NewPostgresLedgerBackend(db, lock, PostgresLedgerConfig{})

	result, err := backend.LastChainHash(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "abc123", result)
}

func TestPostgresLedgerBackend_Close(t *testing.T) {
	t.Parallel()

	db := &mockDB{}
	lock := &mockAdvisoryLock{}
	backend := NewPostgresLedgerBackend(db, lock, PostgresLedgerConfig{})

	require.NoError(t, backend.Close())

	// Append after close should fail.
	evidence := &SignedAuditEvidence{
		Record: LogEntry{ID: "rec-1", Timestamp: time.Now().UTC()},
	}
	err := backend.Append(context.Background(), evidence)
	assert.ErrorIs(t, err, ErrBackendClosed)
}

// --- PerReplicaPostgresLedgerBackend Tests ---

func TestPerReplicaBackend_Append(t *testing.T) {
	t.Parallel()

	db := &mockDB{}
	backend := NewPerReplicaPostgresLedgerBackend(db, "replica-1")

	evidence := &SignedAuditEvidence{
		Record: LogEntry{
			ID:        "rec-1",
			TenantID:  "tenant-1",
			Timestamp: time.Now().UTC(),
			EventType: "test",
			Action:    "action",
			Outcome:   "success",
		},
		Signature:   "sig-1",
		Algorithm:   "ES256",
		KeyID:       "key-1",
		ChainHash:   "chain-1",
		ReplicaID:   "replica-1",
		SequenceNum: 1,
	}

	err := backend.Append(context.Background(), evidence)
	require.NoError(t, err)
}

func TestPerReplicaBackend_Close(t *testing.T) {
	t.Parallel()

	db := &mockDB{}
	backend := NewPerReplicaPostgresLedgerBackend(db, "replica-1")

	require.NoError(t, backend.Close())

	evidence := &SignedAuditEvidence{
		Record: LogEntry{ID: "rec-1", Timestamp: time.Now().UTC()},
	}
	err := backend.Append(context.Background(), evidence)
	assert.ErrorIs(t, err, ErrBackendClosed)
}

// --- QueryStore Tests ---

func TestPostgresQueryStore_GetByID_NotFound(t *testing.T) {
	t.Parallel()

	db := &mockDB{}
	store := NewPostgresQueryStore(db)

	_, err := store.GetByID(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, ErrRecordNotFound)
}

func TestPostgresQueryStore_Query_InvalidPage(t *testing.T) {
	t.Parallel()

	db := &mockDB{
		queryRow: &mockRow{values: []any{int64(0)}},
	}
	store := NewPostgresQueryStore(db)

	_, err := store.Query(context.Background(), QueryFilter{}, PageParams{Offset: -1})
	assert.ErrorIs(t, err, ErrInvalidPage)
}

// --- Integration-style pipeline test ---

func TestPipeline_FullChainVerification(t *testing.T) {
	t.Parallel()

	signer := NewEvidenceSigner(&mockSigner{algorithm: crypto.ES256, keyID: "audit-key-1"})
	backend := newInMemoryLedgerBackend()
	pipeline, err := NewPipeline(signer, backend, PipelineConfig{ReplicaID: "test-replica"})
	require.NoError(t, err)
	require.NoError(t, pipeline.Initialize(context.Background()))

	ctx := context.Background()

	// Simulate a sequence of audit events.
	events := []struct {
		eventType string
		action    string
		outcome   string
	}{
		{"token.issued", "issue", "success"},
		{"enforcement.allow", "enforce", "allow"},
		{"enforcement.deny", "enforce", "deny"},
		{"token.revoked", "revoke", "success"},
		{"admin.kill_switch", "activate", "success"},
	}

	for _, ev := range events {
		entry := &LogEntry{
			TenantID:  "tenant-1",
			EventType: ev.eventType,
			Actor:     ocsf.Actor{UserID: "user-1", TenantID: "tenant-1"},
			Action:    ev.action,
			Outcome:   ev.outcome,
		}
		require.NoError(t, pipeline.Append(ctx, entry))
	}

	records := backend.Records()
	require.Len(t, records, 5)

	// Verify entire chain.
	for i, rec := range records {
		assert.True(t, VerifyChainHash(&rec), "chain verification failed at index %d", i)
		assert.Equal(t, int64(i+1), rec.SequenceNum)
		assert.Equal(t, "test-replica", rec.ReplicaID)

		if i > 0 {
			assert.Equal(t, records[i-1].ChainHash, rec.PreviousHash)
		}
	}
}

func TestPipeline_BackendErrorRollsBackSequence(t *testing.T) {
	t.Parallel()

	signer := NewEvidenceSigner(&mockSigner{algorithm: crypto.ES256, keyID: "test-key"})

	failAfter := 2
	callCount := 0
	backend := &failingBackend{
		inner:     newInMemoryLedgerBackend(),
		failAfter: &failAfter,
		count:     &callCount,
	}

	pipeline, err := NewPipeline(signer, backend, PipelineConfig{ReplicaID: "replica-1"})
	require.NoError(t, err)
	require.NoError(t, pipeline.Initialize(context.Background()))

	ctx := context.Background()

	// First two should succeed.
	for i := 0; i < 2; i++ {
		entry := &LogEntry{EventType: "test", Action: "action", Outcome: "success"}
		require.NoError(t, pipeline.Append(ctx, entry))
	}

	// Third should fail.
	entry := &LogEntry{EventType: "test", Action: "action", Outcome: "success"}
	err = pipeline.Append(ctx, entry)
	assert.Error(t, err)

	// Verify sequence was rolled back - next successful append gets seq 3.
	*backend.failAfter = 100 // Stop failing.
	entry = &LogEntry{EventType: "test", Action: "action", Outcome: "success"}
	require.NoError(t, pipeline.Append(ctx, entry))

	records := backend.inner.Records()
	assert.Equal(t, int64(3), records[len(records)-1].SequenceNum)
}

type failingBackend struct {
	inner     *inMemoryLedgerBackend
	failAfter *int
	count     *int
}

func (b *failingBackend) Append(ctx context.Context, evidence *SignedAuditEvidence) error {
	*b.count++
	if *b.count > *b.failAfter {
		return errors.New("simulated backend failure")
	}
	return b.inner.Append(ctx, evidence)
}

func (b *failingBackend) LastChainHash(ctx context.Context) (string, error) {
	return b.inner.LastChainHash(ctx)
}

func (b *failingBackend) LastSequenceNum(ctx context.Context) (int64, error) {
	return b.inner.LastSequenceNum(ctx)
}

func (b *failingBackend) Close() error {
	return b.inner.Close()
}
