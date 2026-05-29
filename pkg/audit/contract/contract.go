// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package contract defines the backend-agnostic interfaces and domain types
// for the audit pipeline.
//
// D-1 fix: separating these definitions from the pkg/audit implementation
// package lets new LedgerBackend and Pipeline implementations be developed in
// independent packages without importing pkg/audit's transitive dependencies.
// pkg/audit re-exports all types here as type aliases so existing callers
// require no changes.
package contract

import (
	"context"
	"encoding/json"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/eunolabs/eunox/pkg/ocsf"
)

// LogEntry represents a single audit event before signing.
type LogEntry struct {
	// ID is a unique identifier for the audit record.
	ID string `json:"id"`
	// Timestamp is when the event occurred.
	Timestamp time.Time `json:"timestamp"`
	// TenantID scopes the record.
	TenantID string `json:"tenantId"`
	// EventType classifies the audit event.
	EventType string `json:"eventType"`
	// Actor who performed the action.
	Actor ocsf.Actor `json:"actor"`
	// Action performed.
	Action string `json:"action"`
	// Resource targeted.
	Resource ocsf.Resource `json:"resource,omitempty"`
	// Outcome (success/failure).
	Outcome string `json:"outcome"`
	// Detail is arbitrary structured data.
	Detail json.RawMessage `json:"detail,omitempty"`
	// OCSFEvent optionally holds the full OCSF event for export.
	OCSFEvent any `json:"ocsfEvent,omitempty"`

	// TraceSpanContext carries the OpenTelemetry span context from the caller
	// so that the async drain goroutine can reconstruct a linked context.
	// Not serialised (json:"-") — in-process only.
	TraceSpanContext trace.SpanContext `json:"-"`
}

// SignedAuditEvidence wraps a signed audit entry with chain integrity metadata.
type SignedAuditEvidence struct {
	// Record is the audit log entry.
	Record LogEntry `json:"record"`
	// Signature is the digital signature over the canonical record bytes.
	Signature string `json:"signature"`
	// Algorithm is the signing algorithm used.
	Algorithm string `json:"algorithm"`
	// KeyID identifies the signing key.
	KeyID string `json:"keyId"`
	// ChainHash is the HMAC chain hash linking this record to the previous one.
	ChainHash string `json:"chainHash"`
	// PreviousHash is the chain hash of the immediately preceding record.
	PreviousHash string `json:"previousHash"`
	// ReplicaID identifies which replica produced this record.
	ReplicaID string `json:"replicaId,omitempty"`
	// SequenceNum is the monotonic sequence within the chain.
	SequenceNum int64 `json:"sequenceNum"`
}

// Pipeline is the core interface for appending audit entries.
type Pipeline interface {
	// Append adds an audit log entry to the pipeline. The entry is signed,
	// chained, and persisted atomically.
	Append(ctx context.Context, entry *LogEntry) error
	// Close flushes pending operations and releases resources.
	Close() error
}

// LedgerBackend is the storage interface for persisting signed audit evidence.
// New backend implementations (e.g. S3, Kafka, BigQuery) can implement this
// interface in their own packages without importing pkg/audit.
type LedgerBackend interface {
	// Append persists a signed audit evidence record.
	Append(ctx context.Context, evidence *SignedAuditEvidence) error
	// LastChainHash returns the chain hash of the most recent record.
	LastChainHash(ctx context.Context) (string, error)
	// LastSequenceNum returns the latest sequence number.
	LastSequenceNum(ctx context.Context) (int64, error)
	// Close releases any held resources.
	Close() error
}
