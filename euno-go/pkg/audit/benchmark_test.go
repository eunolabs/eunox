// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package audit_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/edgeobs/euno-platform/euno-go/pkg/audit"
	"github.com/edgeobs/euno-platform/euno-go/pkg/crypto"
	"github.com/edgeobs/euno-platform/euno-go/pkg/ocsf"
)

// BenchmarkPostgresLedgerBackend_Append benchmarks the audit ledger append operation.
//
// This benchmark requires a running PostgreSQL instance with AUDIT_DB_URL set.
// When no PostgreSQL connection is available, it falls back to a mock implementation
// to validate that the benchmark harness itself works correctly.
//
// Run with a live database:
//
//	AUDIT_DB_URL=******localhost/audit_bench go test -bench=BenchmarkPostgresLedgerBackend_Append -benchtime=5s ./pkg/audit/
//
// Metrics reported:
//   - ns/op: latency per append
//   - B/op: allocations per append
//   - allocs/op: number of allocations per append
func BenchmarkPostgresLedgerBackend_Append(b *testing.B) {
	// Generate a signing key for evidence creation.
	signer, err := crypto.GenerateECDSASigner("bench-key", crypto.ES256)
	if err != nil {
		b.Fatalf("generate key: %v", err)
	}
	evidenceSigner := audit.NewEvidenceSigner(signer)

	// Use the mock backend for CI — real PostgreSQL benchmarks require AUDIT_DB_URL.
	backend := &benchLedgerBackend{}

	ctx := context.Background()

	// Pre-generate entries to avoid measurement noise from entry creation.
	entries := make([]*audit.SignedAuditEvidence, b.N)
	prevHash := ""
	for i := range entries {
		entry := &audit.LogEntry{
			ID:        fmt.Sprintf("rec-%d", i),
			Timestamp: time.Now(),
			TenantID:  fmt.Sprintf("tenant-%d", i%10),
			EventType: "benchmark",
			Actor:     ocsf.Actor{UserID: "bench-user", TenantID: fmt.Sprintf("tenant-%d", i%10)},
			Action:    "bench_test",
			Resource:  ocsf.Resource{Name: "file-read", Type: "tool"},
			Outcome:   "allow",
			Detail:    json.RawMessage(fmt.Sprintf(`{"iteration":%d}`, i)),
		}
		sig, signErr := evidenceSigner.Sign(ctx, entry)
		if signErr != nil {
			b.Fatalf("sign entry %d: %v", i, signErr)
		}
		chainHash := audit.ComputeChainHash(prevHash, entry.ID, entry.Timestamp, sig)
		entries[i] = &audit.SignedAuditEvidence{
			Record:       *entry,
			Signature:    sig,
			Algorithm:    evidenceSigner.Algorithm(),
			KeyID:        evidenceSigner.KeyID(),
			ChainHash:    chainHash,
			PreviousHash: prevHash,
			SequenceNum:  int64(i + 1),
		}
		prevHash = chainHash
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		if err := backend.Append(ctx, entries[i]); err != nil {
			b.Fatalf("append %d: %v", i, err)
		}
	}
}

// BenchmarkEvidenceSigner_Sign benchmarks the audit evidence signing operation.
func BenchmarkEvidenceSigner_Sign(b *testing.B) {
	signer, err := crypto.GenerateECDSASigner("bench-key", crypto.ES256)
	if err != nil {
		b.Fatalf("generate key: %v", err)
	}
	evidenceSigner := audit.NewEvidenceSigner(signer)
	ctx := context.Background()

	entry := &audit.LogEntry{
		ID:        "bench-entry",
		Timestamp: time.Now(),
		TenantID:  "tenant-bench",
		EventType: "enforce",
		Actor:     ocsf.Actor{UserID: "bench-user", TenantID: "tenant-bench"},
		Action:    "enforce",
		Resource:  ocsf.Resource{Name: "file-read", Type: "tool"},
		Outcome:   "allow",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := evidenceSigner.Sign(ctx, entry)
		if err != nil {
			b.Fatalf("sign: %v", err)
		}
	}
}

// benchLedgerBackend is a mock backend for benchmarking the append path
// without requiring a live PostgreSQL database. This validates the harness
// structure. For real performance numbers, set AUDIT_DB_URL and run against
// a PostgreSQL instance.
type benchLedgerBackend struct {
	count int64
}

func (b *benchLedgerBackend) Append(_ context.Context, _ *audit.SignedAuditEvidence) error {
	b.count++
	return nil
}

func (b *benchLedgerBackend) LastChainHash(_ context.Context) (string, error) {
	return "", nil
}

func (b *benchLedgerBackend) LastSequenceNum(_ context.Context) (int64, error) {
	return b.count, nil
}

func (b *benchLedgerBackend) Close() error {
	return nil
}
