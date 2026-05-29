// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

// Package audit implements the audit pipeline with cryptographic signing, HMAC chain
// integrity, PostgreSQL ledger backends, and OCSF export capabilities.
package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/eunolabs/eunox/pkg/audit/contract"
	"github.com/eunolabs/eunox/pkg/crypto"
	"github.com/google/uuid"
)

// Errors returned by the audit package.
var (
	ErrNilEntry       = errors.New("audit: nil entry")
	ErrNoSigner       = errors.New("audit: no evidence signer configured")
	ErrNoBackend      = errors.New("audit: no ledger backend configured")
	ErrNotInitialized = errors.New("audit: pipeline is not initialized")
	ErrChainBroken    = errors.New("audit: HMAC chain integrity violation")
	ErrRecordNotFound = errors.New("audit: record not found")
	ErrInvalidPage    = errors.New("audit: invalid page parameters")
	ErrBackendClosed  = errors.New("audit: backend is closed")
	ErrLockContention = errors.New("audit: advisory lock contention")
)

// LogEntry, SignedAuditEvidence, Pipeline, and LedgerBackend are defined in
// pkg/audit/contract and re-exported here as type aliases so that existing
// callers (e.g. internal/gateway) continue to compile without modification.
// D-1 fix: moving the canonical definitions to the contract sub-package
// decouples interface consumers from the implementation package.
type (
	LogEntry            = contract.LogEntry
	SignedAuditEvidence = contract.SignedAuditEvidence
	Pipeline            = contract.Pipeline
	LedgerBackend       = contract.LedgerBackend
)

// EvidenceSigner signs audit entries to produce tamper-evident records.
type EvidenceSigner struct {
	signer crypto.Signer
}

// NewEvidenceSigner creates an EvidenceSigner with the given crypto signer.
func NewEvidenceSigner(signer crypto.Signer) *EvidenceSigner {
	return &EvidenceSigner{signer: signer}
}

// Sign produces a digital signature over the canonical JSON representation of an entry.
func (es *EvidenceSigner) Sign(ctx context.Context, entry *LogEntry) (string, error) {
	canonical, err := json.Marshal(entry)
	if err != nil {
		return "", fmt.Errorf("audit: marshal entry for signing: %w", err)
	}

	// For algorithms that require pre-hashing (RSA, ECDSA), hash the content.
	// For EdDSA, pass raw content (Ed25519 hashes internally).
	var digest []byte
	if es.signer.Algorithm() == crypto.EdDSA {
		digest = canonical
	} else {
		h := sha256.Sum256(canonical)
		digest = h[:]
	}

	sig, err := es.signer.Sign(ctx, digest)
	if err != nil {
		return "", fmt.Errorf("audit: sign entry: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// Algorithm returns the signing algorithm.
func (es *EvidenceSigner) Algorithm() string {
	return string(es.signer.Algorithm())
}

// KeyID returns the key identifier.
func (es *EvidenceSigner) KeyID() string {
	return es.signer.KeyID()
}

// ComputeChainHash computes the HMAC-SHA256 chain hash linking a record to the previous hash.
//
// When chainSecret is non-empty it is used as the outer HMAC key, anchoring the
// entire chain to a dedicated secret that can be rotated independently of the
// per-record signing key.  The message still encodes the previousHash so
// that the chain linkage cannot be reordered even if the secret is known.
//
// When chainSecret is empty the function falls back to the legacy behaviour:
// the previousHash itself is used as the HMAC key (genesis record uses "genesis").
// This preserves backward-compatibility with chains written before AUDIT_CHAIN_HMAC_SECRET
// was configured.
//
// chainHash = HMAC-SHA256(key: chainSecret || previousHash, message: recordID || timestamp || signature)
func ComputeChainHash(previousHash, recordID string, timestamp time.Time, signature string) string {
	return computeChainHashWithSecret("", previousHash, recordID, timestamp, signature)
}

// ComputeChainHashWithSecret is like ComputeChainHash but uses a dedicated
// chain secret as the primary HMAC key, incorporating the previousHash into the
// message so that per-record linkage is preserved.
func ComputeChainHashWithSecret(chainSecret, previousHash, recordID string, timestamp time.Time, signature string) string {
	return computeChainHashWithSecret(chainSecret, previousHash, recordID, timestamp, signature)
}

func computeChainHashWithSecret(chainSecret, previousHash, recordID string, timestamp time.Time, signature string) string {
	var key []byte
	if chainSecret != "" {
		// Dedicated chain secret: key = chainSecret so the chain is anchored to
		// a secret that can be rotated independently of the signing key.  The
		// previousHash is included in the message to preserve per-record linkage.
		key = []byte(chainSecret)
	} else {
		// Legacy behaviour: derive the HMAC key from the previous hash so that
		// each record authenticates the next in a self-referential chain.
		key = []byte(previousHash)
		if previousHash == "" {
			key = []byte("genesis")
		}
	}

	var message string
	if chainSecret != "" {
		// Include previousHash in the message when using a dedicated secret so
		// that the chain ordering is still cryptographically bound.
		message = fmt.Sprintf("%s|%s|%s|%s", previousHash, recordID, timestamp.UTC().Format(time.RFC3339Nano), signature)
	} else {
		message = fmt.Sprintf("%s|%s|%s", recordID, timestamp.UTC().Format(time.RFC3339Nano), signature)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(message))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// VerifyChainHash verifies that a chain hash is valid given the inputs.
// Use VerifyChainHashWithSecret when a dedicated chain HMAC secret was used.
func VerifyChainHash(evidence *SignedAuditEvidence) bool {
	return VerifyChainHashWithSecret("", evidence)
}

// VerifyChainHashWithSecret verifies a chain hash produced with a dedicated secret.
func VerifyChainHashWithSecret(chainSecret string, evidence *SignedAuditEvidence) bool {
	expected := computeChainHashWithSecret(
		chainSecret,
		evidence.PreviousHash,
		evidence.Record.ID,
		evidence.Record.Timestamp,
		evidence.Signature,
	)
	return hmac.Equal([]byte(expected), []byte(evidence.ChainHash))
}

// DefaultPipeline is the standard implementation of the Pipeline interface.
//
// # Per-replica chain model (A-2)
//
// lastChainHash and lastSeqNum are in-process state. In a multi-replica
// deployment each pod maintains its own independent chain starting from its
// own genesis hash; there is no global ordering across replicas. Sequence
// numbers are monotonically increasing within a single replica with possible
// gaps after backend failures (see M-1 fix), but they are NOT globally
// monotonic across replicas.
//
// Cross-replica audit integrity verification requires external tooling that
// groups records by ReplicaID and validates each replica's chain independently.
// A replica restart calls Initialize to reload lastChainHash and lastSeqNum
// from the backend, but in-flight writes that were lost in the async pipeline
// on a crash produce silent gaps in the chain.
//
// Operators who need globally monotonic sequence numbers should front the
// pipeline with a distributed allocator (Postgres sequence or Redis INCR)
// and set that value as the record's SequenceNum before calling Append.
type DefaultPipeline struct {
	signer          *EvidenceSigner
	backend         LedgerBackend
	replicaID       string
	chainHMACSecret string

	mu            sync.Mutex
	lastChainHash string
	lastSeqNum    int64
	initialized   bool
	closed        bool
}

// PipelineConfig holds configuration for the default pipeline.
type PipelineConfig struct {
	// ReplicaID identifies this pipeline instance (for per-replica chains).
	ReplicaID string

	// ChainHMACSecret is an optional dedicated secret for the HMAC chain
	// integrity hash.  When set, the chain hash is computed with this secret
	// as the HMAC key rather than the previous hash, decoupling the chain
	// integrity mechanism from the per-record signing key.
	//
	// Populate from the AUDIT_CHAIN_HMAC_SECRET environment variable.
	// Omitting this field preserves backward-compatible behaviour (the previous
	// hash is used as the HMAC key, with "genesis" for the first record).
	ChainHMACSecret string
}

// NewPipeline creates a new DefaultPipeline.
func NewPipeline(signer *EvidenceSigner, backend LedgerBackend, cfg PipelineConfig) (*DefaultPipeline, error) {
	if signer == nil {
		return nil, ErrNoSigner
	}
	if backend == nil {
		return nil, ErrNoBackend
	}

	replicaID := cfg.ReplicaID
	if replicaID == "" {
		replicaID = uuid.New().String()
	}

	return &DefaultPipeline{
		signer:          signer,
		backend:         backend,
		replicaID:       replicaID,
		chainHMACSecret: cfg.ChainHMACSecret,
	}, nil
}

// Initialize loads the last chain state from the backend. Must be called before Append.
func (p *DefaultPipeline) Initialize(ctx context.Context) error {
	hash, err := p.backend.LastChainHash(ctx)
	if err != nil {
		return fmt.Errorf("audit: initialize chain hash: %w", err)
	}
	seq, err := p.backend.LastSequenceNum(ctx)
	if err != nil {
		return fmt.Errorf("audit: initialize sequence num: %w", err)
	}
	p.mu.Lock()
	p.lastChainHash = hash
	p.lastSeqNum = seq
	p.initialized = true
	p.mu.Unlock()
	return nil
}

// Append signs and persists an audit log entry with chain integrity.
func (p *DefaultPipeline) Append(ctx context.Context, entry *LogEntry) error {
	if entry == nil {
		return ErrNilEntry
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return ErrBackendClosed
	}
	if !p.initialized {
		return ErrNotInitialized
	}

	// Work on a shallow copy so we never mutate the caller's struct.
	// Callers often retain a reference to the LogEntry they passed in; mutating
	// it in-place would silently change their view of the record.
	rec := *entry
	if rec.ID == "" {
		rec.ID = uuid.New().String()
	}
	if rec.Timestamp.IsZero() {
		rec.Timestamp = time.Now().UTC()
	}

	// Sign the entry.
	signature, err := p.signer.Sign(ctx, &rec)
	if err != nil {
		return err
	}

	// Compute chain hash using the dedicated chain secret when configured,
	// otherwise fall back to legacy behaviour.
	chainHash := ComputeChainHashWithSecret(p.chainHMACSecret, p.lastChainHash, rec.ID, rec.Timestamp, signature)

	// Increment sequence.
	p.lastSeqNum++

	evidence := &SignedAuditEvidence{
		Record:       rec,
		Signature:    signature,
		Algorithm:    p.signer.Algorithm(),
		KeyID:        p.signer.KeyID(),
		ChainHash:    chainHash,
		PreviousHash: p.lastChainHash,
		ReplicaID:    p.replicaID,
		SequenceNum:  p.lastSeqNum,
	}

	// Persist to backend.
	// M-1 fix: do NOT roll back lastSeqNum on failure. If the backend partially
	// committed before returning an error, rolling back causes the next record to
	// reuse the same sequence number — a collision that chain integrity tools cannot
	// detect without a full hash scan. Sequence numbers are monotonically increasing
	// with possible gaps after failures, not gapless.
	if err := p.backend.Append(ctx, evidence); err != nil {
		return err
	}

	// Update chain state.
	p.lastChainHash = chainHash
	return nil
}

// Close marks the pipeline as closed and closes the backend.
func (p *DefaultPipeline) Close() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	return p.backend.Close()
}

// ReplicaID returns the replica identifier for this pipeline instance.
func (p *DefaultPipeline) ReplicaID() string {
	return p.replicaID
}
