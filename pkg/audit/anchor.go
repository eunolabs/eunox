// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// ChainAnchor represents an anchoring checkpoint to an external ledger.
type ChainAnchor struct {
	// AnchorID uniquely identifies this anchor.
	AnchorID string `json:"anchorId"`
	// ReplicaID identifies the chain being anchored.
	ReplicaID string `json:"replicaId"`
	// SequenceNum is the latest sequence number at anchor time.
	SequenceNum int64 `json:"sequenceNum"`
	// ChainHash is the chain hash at the anchor point.
	ChainHash string `json:"chainHash"`
	// MerkleRoot is the SHA-256 root of all chain hashes in the range.
	MerkleRoot string `json:"merkleRoot"`
	// Timestamp is when the anchor was created.
	Timestamp time.Time `json:"timestamp"`
	// ExternalRef is the reference in the external ledger (e.g., transaction hash, object key).
	ExternalRef string `json:"externalRef,omitempty"`
	// Backend identifies which anchoring backend was used.
	Backend string `json:"backend"`
}

// AnchorBackend is the interface for external ledger anchoring.
type AnchorBackend interface {
	// Anchor submits a chain anchor to the external ledger and returns an external reference.
	Anchor(ctx context.Context, anchor *ChainAnchor) (externalRef string, err error)
	// Verify checks that an anchor exists in the external ledger.
	Verify(ctx context.Context, anchor *ChainAnchor) (bool, error)
	// Name returns the backend name.
	Name() string
}

// AnchorService manages periodic anchoring of audit chains to external ledgers.
type AnchorService struct {
	backends   []AnchorBackend
	queryStore QueryStore
	logger     *slog.Logger
}

// NewAnchorService creates a new anchor service.
func NewAnchorService(queryStore QueryStore, logger *slog.Logger, backends ...AnchorBackend) *AnchorService {
	if logger == nil {
		logger = slog.Default()
	}
	return &AnchorService{
		backends:   backends,
		queryStore: queryStore,
		logger:     logger,
	}
}

// CreateAnchor produces an anchor for the given replica's chain at its current tip.
func (s *AnchorService) CreateAnchor(ctx context.Context, replicaID string, fromSeq, toSeq int64) (*ChainAnchor, error) {
	segment, err := s.queryStore.GetChainSegment(ctx, replicaID, fromSeq, toSeq)
	if err != nil {
		return nil, fmt.Errorf("audit: get chain segment for anchoring: %w", err)
	}
	if len(segment) == 0 {
		return nil, fmt.Errorf("audit: no records in segment [%d, %d]", fromSeq, toSeq)
	}

	// Compute Merkle root from chain hashes.
	merkleRoot := computeMerkleRoot(segment)

	lastRecord := segment[len(segment)-1]
	anchor := &ChainAnchor{
		AnchorID:    fmt.Sprintf("anchor-%s-%d", replicaID, toSeq),
		ReplicaID:   replicaID,
		SequenceNum: lastRecord.SequenceNum,
		ChainHash:   lastRecord.ChainHash,
		MerkleRoot:  merkleRoot,
		Timestamp:   time.Now().UTC(),
	}

	return anchor, nil
}

// SubmitAnchor submits an anchor to all configured backends.
func (s *AnchorService) SubmitAnchor(ctx context.Context, anchor *ChainAnchor) error {
	for _, backend := range s.backends {
		ref, err := backend.Anchor(ctx, anchor)
		if err != nil {
			s.logger.Error("audit: anchor submission failed",
				"backend", backend.Name(), "error", err)
			return fmt.Errorf("audit: anchor to %s: %w", backend.Name(), err)
		}
		anchor.ExternalRef = ref
		anchor.Backend = backend.Name()
		s.logger.Info("audit: anchor submitted",
			"backend", backend.Name(), "ref", ref, "sequence", anchor.SequenceNum)
	}
	return nil
}

// computeMerkleRoot builds a binary Merkle tree over chain hashes.
func computeMerkleRoot(records []SignedAuditEvidence) string {
	if len(records) == 0 {
		return ""
	}

	// Start with leaf hashes.
	hashes := make([][]byte, len(records))
	for i, r := range records {
		h := sha256.Sum256([]byte(r.ChainHash))
		hashes[i] = h[:]
	}

	// Build tree bottom-up.
	for len(hashes) > 1 {
		var next [][]byte
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				combined := make([]byte, 0, len(hashes[i])+len(hashes[i+1]))
				combined = append(combined, hashes[i]...)
				combined = append(combined, hashes[i+1]...)
				h := sha256.Sum256(combined)
				next = append(next, h[:])
			} else {
				// Odd number: carry the last hash up.
				next = append(next, hashes[i])
			}
		}
		hashes = next
	}

	return hex.EncodeToString(hashes[0])
}

// --- S3 Anchor Backend ---

// S3AnchorConfig configures the S3 anchoring backend.
type S3AnchorConfig struct {
	// Bucket is the S3 bucket name for anchor objects.
	Bucket string
	// Prefix is the key prefix for anchor objects.
	Prefix string
	// Region is the AWS region.
	Region string
	// Endpoint override for testing/localstack.
	Endpoint string
}

// S3AnchorBackend anchors chain checkpoints to S3 immutable objects.
type S3AnchorBackend struct {
	config S3AnchorConfig
	client *http.Client
}

// NewS3AnchorBackend creates a new S3 anchor backend.
func NewS3AnchorBackend(cfg S3AnchorConfig) *S3AnchorBackend {
	return &S3AnchorBackend{
		config: cfg,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// Name returns the backend identifier.
func (b *S3AnchorBackend) Name() string { return "s3" }

// Anchor stores the anchor as an immutable S3 object.
func (b *S3AnchorBackend) Anchor(ctx context.Context, anchor *ChainAnchor) (string, error) {
	body, err := json.Marshal(anchor)
	if err != nil {
		return "", fmt.Errorf("audit: marshal anchor for S3: %w", err)
	}

	key := fmt.Sprintf("%s%s.json", b.config.Prefix, anchor.AnchorID)
	endpoint := b.config.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://%s.s3.%s.amazonaws.com", b.config.Bucket, b.config.Region)
	}
	url := fmt.Sprintf("%s/%s", endpoint, key)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("audit: create S3 request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// TODO(audit): Implement AWS SigV4 signing for production S3 access.
	// Current implementation assumes pre-signed URLs or test endpoints.

	resp, err := b.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("audit: S3 PUT failed: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return fmt.Sprintf("s3://%s/%s", b.config.Bucket, key), nil
	}

	return "", fmt.Errorf("audit: S3 returned status %d", resp.StatusCode)
}

// Verify checks that the anchor object exists in S3.
func (b *S3AnchorBackend) Verify(ctx context.Context, anchor *ChainAnchor) (bool, error) {
	key := fmt.Sprintf("%s%s.json", b.config.Prefix, anchor.AnchorID)
	endpoint := b.config.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://%s.s3.%s.amazonaws.com", b.config.Bucket, b.config.Region)
	}
	url := fmt.Sprintf("%s/%s", endpoint, key)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return false, fmt.Errorf("audit: create S3 HEAD request: %w", err)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("audit: S3 HEAD failed: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	return resp.StatusCode == http.StatusOK, nil
}

// --- Azure Confidential Ledger Backend ---

// AzureConfidentialLedgerConfig configures the Azure Confidential Ledger backend.
type AzureConfidentialLedgerConfig struct {
	// LedgerName is the Azure Confidential Ledger instance name.
	LedgerName string
	// Endpoint override (default: constructed from LedgerName).
	Endpoint string
	// AuthToken is the Azure AD bearer token for authentication.
	AuthToken string
}

// AzureConfidentialLedgerBackend anchors chain checkpoints to Azure Confidential Ledger.
type AzureConfidentialLedgerBackend struct {
	config AzureConfidentialLedgerConfig
	client *http.Client
}

// NewAzureConfidentialLedgerBackend creates a new Azure Confidential Ledger anchor backend.
func NewAzureConfidentialLedgerBackend(cfg AzureConfidentialLedgerConfig) *AzureConfidentialLedgerBackend {
	if cfg.Endpoint == "" && cfg.LedgerName != "" {
		cfg.Endpoint = fmt.Sprintf("https://%s.confidential-ledger.azure.com", cfg.LedgerName)
	}
	return &AzureConfidentialLedgerBackend{
		config: cfg,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// Name returns the backend identifier.
func (b *AzureConfidentialLedgerBackend) Name() string { return "azure-confidential-ledger" }

// Anchor writes the anchor to Azure Confidential Ledger.
func (b *AzureConfidentialLedgerBackend) Anchor(ctx context.Context, anchor *ChainAnchor) (string, error) {
	body, err := json.Marshal(anchor)
	if err != nil {
		return "", fmt.Errorf("audit: marshal anchor for ACL: %w", err)
	}

	url := fmt.Sprintf("%s/app/transactions?api-version=2022-05-13&collectionId=euno-audit",
		b.config.Endpoint)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("audit: create ACL request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if b.config.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+b.config.AuthToken)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("audit: ACL POST failed: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// Extract transaction ID from response.
		var result struct {
			TransactionID string `json:"transactionId"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil && result.TransactionID != "" {
			return result.TransactionID, nil
		}
		return fmt.Sprintf("acl-%s-%d", anchor.ReplicaID, anchor.SequenceNum), nil
	}

	return "", fmt.Errorf("audit: ACL returned status %d", resp.StatusCode)
}

// Verify checks that the anchor transaction exists in Azure Confidential Ledger.
func (b *AzureConfidentialLedgerBackend) Verify(ctx context.Context, anchor *ChainAnchor) (bool, error) {
	if anchor.ExternalRef == "" {
		return false, nil
	}

	url := fmt.Sprintf("%s/app/transactions/%s?api-version=2022-05-13",
		b.config.Endpoint, anchor.ExternalRef)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("audit: create ACL GET request: %w", err)
	}
	if b.config.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+b.config.AuthToken)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("audit: ACL GET failed: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	return resp.StatusCode == http.StatusOK, nil
}
