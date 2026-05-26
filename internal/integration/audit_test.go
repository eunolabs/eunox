// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package integration

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edgeobs/eunox/pkg/audit"
	eunocrypto "github.com/edgeobs/eunox/pkg/crypto"
	"github.com/edgeobs/eunox/pkg/ocsf"
)

// inMemoryLedgerBackend is an in-memory LedgerBackend for integration tests.
type inMemoryLedgerBackend struct {
	records []audit.SignedAuditEvidence
}

func newInMemoryLedgerBackend() *inMemoryLedgerBackend {
	return &inMemoryLedgerBackend{}
}

func (b *inMemoryLedgerBackend) Append(_ context.Context, evidence *audit.SignedAuditEvidence) error {
	b.records = append(b.records, *evidence)
	return nil
}

func (b *inMemoryLedgerBackend) LastChainHash(_ context.Context) (string, error) {
	if len(b.records) == 0 {
		return "", nil
	}
	return b.records[len(b.records)-1].ChainHash, nil
}

func (b *inMemoryLedgerBackend) LastSequenceNum(_ context.Context) (int64, error) {
	return int64(len(b.records)), nil
}

func (b *inMemoryLedgerBackend) Close() error {
	return nil
}

// TestAudit_PipelineChainIntegrity verifies the HMAC chain hash integrity
// across multiple appended entries (SOC2 compliance requirement).
func TestAudit_PipelineChainIntegrity(t *testing.T) {
	ctx := context.Background()

	signerKey, err := eunocrypto.GenerateECDSASigner("audit-key-1", eunocrypto.ES256)
	require.NoError(t, err)

	evidenceSigner := audit.NewEvidenceSigner(signerKey)
	backend := newInMemoryLedgerBackend()

	pipeline, err := audit.NewPipeline(evidenceSigner, backend, audit.PipelineConfig{
		ReplicaID: "test-replica-1",
	})
	require.NoError(t, err)
	require.NoError(t, pipeline.Initialize(ctx))

	// Append multiple entries
	entries := []*audit.LogEntry{
		{Action: "issue", Actor: ocsf.Actor{AgentID: "agent-1"}, Resource: ocsf.Resource{Name: "file://readme.md"}, Outcome: "success"},
		{Action: "enforce", Actor: ocsf.Actor{AgentID: "agent-1"}, Resource: ocsf.Resource{Name: "db://users"}, Outcome: "failure"},
		{Action: "revoke", Actor: ocsf.Actor{AgentID: "admin"}, Resource: ocsf.Resource{UID: "jti-123"}, Outcome: "success"},
		{Action: "enforce", Actor: ocsf.Actor{AgentID: "agent-2"}, Resource: ocsf.Resource{Name: "file://config.yaml"}, Outcome: "success"},
		{Action: "kill-switch", Actor: ocsf.Actor{AgentID: "admin"}, Resource: ocsf.Resource{Name: "global"}, Outcome: "success"},
	}

	for _, entry := range entries {
		require.NoError(t, pipeline.Append(ctx, entry))
	}

	// Verify chain integrity on all records
	require.Len(t, backend.records, 5)
	for i, rec := range backend.records {
		valid := audit.VerifyChainHash(&rec)
		assert.True(t, valid, "chain hash verification failed at record %d", i)
	}

	// Verify chain linkage: each record's previousHash matches prior record's chainHash
	for i := 1; i < len(backend.records); i++ {
		assert.Equal(t, backend.records[i-1].ChainHash, backend.records[i].PreviousHash,
			"chain linkage broken at record %d", i)
	}

	// Genesis record has empty previousHash
	assert.Empty(t, backend.records[0].PreviousHash)
}

// TestAudit_PipelineTamperDetection verifies that tampered records are detected.
func TestAudit_PipelineTamperDetection(t *testing.T) {
	ctx := context.Background()

	signerKey, err := eunocrypto.GenerateECDSASigner("audit-key-2", eunocrypto.ES256)
	require.NoError(t, err)

	evidenceSigner := audit.NewEvidenceSigner(signerKey)
	backend := newInMemoryLedgerBackend()

	pipeline, err := audit.NewPipeline(evidenceSigner, backend, audit.PipelineConfig{
		ReplicaID: "test-replica-tamper",
	})
	require.NoError(t, err)
	require.NoError(t, pipeline.Initialize(ctx))

	require.NoError(t, pipeline.Append(ctx, &audit.LogEntry{
		Action: "enforce", Actor: ocsf.Actor{AgentID: "agent-1"}, Resource: ocsf.Resource{Name: "tool-x"}, Outcome: "success",
	}))
	require.NoError(t, pipeline.Append(ctx, &audit.LogEntry{
		Action: "enforce", Actor: ocsf.Actor{AgentID: "agent-2"}, Resource: ocsf.Resource{Name: "tool-y"}, Outcome: "failure",
	}))

	require.Len(t, backend.records, 2)

	// Original should verify
	assert.True(t, audit.VerifyChainHash(&backend.records[0]))
	assert.True(t, audit.VerifyChainHash(&backend.records[1]))

	// Tamper with record ID
	tampered := backend.records[1]
	tampered.Record.ID = "tampered-id"
	assert.False(t, audit.VerifyChainHash(&tampered), "tampered record ID should fail chain verification")

	// Tamper with signature
	tampered2 := backend.records[0]
	tampered2.Signature = "fake-signature"
	assert.False(t, audit.VerifyChainHash(&tampered2), "tampered signature should fail chain verification")
}

// TestAudit_PipelineSignatures verifies that each record has a valid non-empty signature.
func TestAudit_PipelineSignatures(t *testing.T) {
	ctx := context.Background()

	signerKey, err := eunocrypto.GenerateECDSASigner("audit-key-3", eunocrypto.ES256)
	require.NoError(t, err)

	evidenceSigner := audit.NewEvidenceSigner(signerKey)
	backend := newInMemoryLedgerBackend()

	pipeline, err := audit.NewPipeline(evidenceSigner, backend, audit.PipelineConfig{
		ReplicaID: "test-replica-sig",
	})
	require.NoError(t, err)
	require.NoError(t, pipeline.Initialize(ctx))

	require.NoError(t, pipeline.Append(ctx, &audit.LogEntry{
		Action: "enforce", Actor: ocsf.Actor{AgentID: "agent-1"}, Resource: ocsf.Resource{Name: "tool-1"}, Outcome: "success",
	}))

	require.Len(t, backend.records, 1)
	rec := backend.records[0]

	assert.NotEmpty(t, rec.Signature)
	assert.NotEmpty(t, rec.Record.ID)
	assert.NotEmpty(t, rec.ChainHash)
	assert.Equal(t, "audit-key-3", rec.KeyID)
	assert.Equal(t, "ES256", rec.Algorithm)
	assert.False(t, rec.Record.Timestamp.IsZero())
}

// TestAudit_PipelineReplicaIsolation verifies that multiple replicas
// maintain independent chains (important for distributed audit).
func TestAudit_PipelineReplicaIsolation(t *testing.T) {
	ctx := context.Background()

	signerKey, err := eunocrypto.GenerateECDSASigner("audit-key-4", eunocrypto.ES256)
	require.NoError(t, err)

	evidenceSigner := audit.NewEvidenceSigner(signerKey)

	backend1 := newInMemoryLedgerBackend()
	backend2 := newInMemoryLedgerBackend()

	pipeline1, err := audit.NewPipeline(evidenceSigner, backend1, audit.PipelineConfig{ReplicaID: "replica-A"})
	require.NoError(t, err)
	require.NoError(t, pipeline1.Initialize(ctx))

	pipeline2, err := audit.NewPipeline(evidenceSigner, backend2, audit.PipelineConfig{ReplicaID: "replica-B"})
	require.NoError(t, err)
	require.NoError(t, pipeline2.Initialize(ctx))

	// Append to both pipelines
	require.NoError(t, pipeline1.Append(ctx, &audit.LogEntry{Action: "enforce", Actor: ocsf.Actor{AgentID: "a1"}, Outcome: "success"}))
	require.NoError(t, pipeline2.Append(ctx, &audit.LogEntry{Action: "enforce", Actor: ocsf.Actor{AgentID: "a2"}, Outcome: "success"}))

	// Each has one record
	assert.Len(t, backend1.records, 1)
	assert.Len(t, backend2.records, 1)

	// Both verify independently
	assert.True(t, audit.VerifyChainHash(&backend1.records[0]))
	assert.True(t, audit.VerifyChainHash(&backend2.records[0]))

	// Verify replica IDs
	assert.Equal(t, "replica-A", pipeline1.ReplicaID())
	assert.Equal(t, "replica-B", pipeline2.ReplicaID())
}

// TestAudit_SequenceNumbers verifies monotonically increasing sequence numbers.
func TestAudit_SequenceNumbers(t *testing.T) {
	ctx := context.Background()

	signerKey, err := eunocrypto.GenerateECDSASigner("audit-key-6", eunocrypto.ES256)
	require.NoError(t, err)

	evidenceSigner := audit.NewEvidenceSigner(signerKey)
	backend := newInMemoryLedgerBackend()

	pipeline, err := audit.NewPipeline(evidenceSigner, backend, audit.PipelineConfig{ReplicaID: "seq-replica"})
	require.NoError(t, err)
	require.NoError(t, pipeline.Initialize(ctx))

	for i := 0; i < 10; i++ {
		require.NoError(t, pipeline.Append(ctx, &audit.LogEntry{
			Action: "enforce", Actor: ocsf.Actor{AgentID: "agent"}, Outcome: "success",
		}))
	}

	require.Len(t, backend.records, 10)
	for i := 1; i < len(backend.records); i++ {
		assert.Greater(t, backend.records[i].SequenceNum, backend.records[i-1].SequenceNum,
			"sequence numbers should be monotonically increasing")
	}
}
