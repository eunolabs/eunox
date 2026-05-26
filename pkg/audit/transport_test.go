// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/edgeobs/eunox/pkg/crypto"
	"github.com/edgeobs/eunox/pkg/ocsf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPTransport_Send_Success(t *testing.T) {
	t.Parallel()

	var received []SignedAuditEvidence
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := NewHTTPTransport(&HTTPTransportConfig{
		TransportConfig: TransportConfig{
			BatchSize:     10,
			FlushInterval: 1 * time.Hour, // Large to avoid flush loop interference.
			MaxRetries:    1,
			RetryBackoff:  10 * time.Millisecond,
			BufferSize:    100,
		},
		Endpoint: server.URL,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer func() { _ = transport.Close() }()

	records := []SignedAuditEvidence{
		{
			Record:    LogEntry{ID: "rec-1", EventType: "test", Action: "action"},
			Signature: "sig-1",
			ChainHash: "hash-1",
		},
		{
			Record:    LogEntry{ID: "rec-2", EventType: "test", Action: "action"},
			Signature: "sig-2",
			ChainHash: "hash-2",
		},
	}

	err := transport.Send(context.Background(), records)
	require.NoError(t, err)
	assert.Len(t, received, 2)
	assert.Equal(t, "rec-1", received[0].Record.ID)
	assert.Equal(t, "rec-2", received[1].Record.ID)
}

func TestHTTPTransport_Send_WithAuth(t *testing.T) {
	t.Parallel()

	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := NewHTTPTransport(&HTTPTransportConfig{
		TransportConfig: TransportConfig{
			FlushInterval: 1 * time.Hour,
			BufferSize:    100,
		},
		Endpoint:   server.URL,
		AuthHeader: "Splunk abc123token",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer func() { _ = transport.Close() }()

	err := transport.Send(context.Background(), []SignedAuditEvidence{
		{Record: LogEntry{ID: "rec-1"}},
	})
	require.NoError(t, err)
	assert.Equal(t, "Splunk abc123token", receivedAuth)
}

func TestHTTPTransport_Send_WithHeaders(t *testing.T) {
	t.Parallel()

	var receivedHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := NewHTTPTransport(&HTTPTransportConfig{
		TransportConfig: TransportConfig{
			FlushInterval: 1 * time.Hour,
			BufferSize:    100,
		},
		Endpoint: server.URL,
		Headers:  map[string]string{"X-Custom": "custom-value"},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer func() { _ = transport.Close() }()

	err := transport.Send(context.Background(), []SignedAuditEvidence{
		{Record: LogEntry{ID: "rec-1"}},
	})
	require.NoError(t, err)
	assert.Equal(t, "custom-value", receivedHeaders.Get("X-Custom"))
}

func TestHTTPTransport_Send_RetryOnFailure(t *testing.T) {
	t.Parallel()

	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempt := atomic.AddInt32(&attempts, 1)
		if attempt < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := NewHTTPTransport(&HTTPTransportConfig{
		TransportConfig: TransportConfig{
			FlushInterval: 1 * time.Hour,
			MaxRetries:    3,
			RetryBackoff:  1 * time.Millisecond,
			BufferSize:    100,
		},
		Endpoint: server.URL,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer func() { _ = transport.Close() }()

	err := transport.Send(context.Background(), []SignedAuditEvidence{
		{Record: LogEntry{ID: "rec-1"}},
	})
	require.NoError(t, err)
	assert.Equal(t, int32(3), atomic.LoadInt32(&attempts))
}

func TestHTTPTransport_Send_MaxRetriesExhausted(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	transport := NewHTTPTransport(&HTTPTransportConfig{
		TransportConfig: TransportConfig{
			FlushInterval: 1 * time.Hour,
			MaxRetries:    2,
			RetryBackoff:  1 * time.Millisecond,
			BufferSize:    100,
		},
		Endpoint: server.URL,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer func() { _ = transport.Close() }()

	err := transport.Send(context.Background(), []SignedAuditEvidence{
		{Record: LogEntry{ID: "rec-1"}},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "delivery failed after")
}

func TestHTTPTransport_Send_EmptyBatch(t *testing.T) {
	t.Parallel()

	transport := NewHTTPTransport(&HTTPTransportConfig{
		TransportConfig: TransportConfig{
			FlushInterval: 1 * time.Hour,
			BufferSize:    100,
		},
		Endpoint: "http://localhost:9999",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer func() { _ = transport.Close() }()

	err := transport.Send(context.Background(), nil)
	require.NoError(t, err)
}

func TestHTTPTransport_Enqueue_AfterClose(t *testing.T) {
	t.Parallel()

	transport := NewHTTPTransport(&HTTPTransportConfig{
		TransportConfig: TransportConfig{
			FlushInterval: 1 * time.Hour,
			BufferSize:    100,
		},
		Endpoint: "http://localhost:9999",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	require.NoError(t, transport.Close())

	err := transport.Enqueue(&SignedAuditEvidence{})
	assert.ErrorIs(t, err, ErrTransportClosed)
}

func TestHTTPTransport_Enqueue_BufferFull(t *testing.T) {
	t.Parallel()

	transport := NewHTTPTransport(&HTTPTransportConfig{
		TransportConfig: TransportConfig{
			FlushInterval: 1 * time.Hour,
			BufferSize:    1, // Tiny buffer.
		},
		Endpoint: "http://localhost:9999",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer func() { _ = transport.Close() }()

	// First should succeed.
	err := transport.Enqueue(&SignedAuditEvidence{Record: LogEntry{ID: "1"}})
	require.NoError(t, err)

	// Second should fail (buffer full).
	err = transport.Enqueue(&SignedAuditEvidence{Record: LogEntry{ID: "2"}})
	assert.ErrorIs(t, err, ErrBatchFull)
}

func TestHTTPTransport_FlushLoop(t *testing.T) {
	t.Parallel()

	var received int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var records []SignedAuditEvidence
		_ = json.Unmarshal(body, &records)
		atomic.AddInt64(&received, int64(len(records)))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := NewHTTPTransport(&HTTPTransportConfig{
		TransportConfig: TransportConfig{
			BatchSize:     10,
			FlushInterval: 50 * time.Millisecond,
			MaxRetries:    1,
			RetryBackoff:  1 * time.Millisecond,
			BufferSize:    100,
		},
		Endpoint: server.URL,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Enqueue some records.
	for i := 0; i < 3; i++ {
		err := transport.Enqueue(&SignedAuditEvidence{
			Record: LogEntry{ID: "rec", EventType: "test"},
		})
		require.NoError(t, err)
	}

	// Wait for flush.
	time.Sleep(200 * time.Millisecond)

	_ = transport.Close()

	assert.Equal(t, int64(3), atomic.LoadInt64(&received))
}

// --- Azure Sentinel Transport Tests ---

func TestAzureSentinelTransport_Send_Success(t *testing.T) {
	t.Parallel()

	var receivedLogType string
	var receivedAuth string
	var receivedDate string
	var receivedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedLogType = r.Header.Get("Log-Type")
		receivedAuth = r.Header.Get("Authorization")
		receivedDate = r.Header.Get("x-ms-date")
		receivedPath = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	records := []SignedAuditEvidence{
		{Record: LogEntry{ID: "rec-1", EventType: "test"}},
	}
	sharedKey := base64.StdEncoding.EncodeToString([]byte("key-456"))
	transport := NewAzureSentinelTransport(&AzureSentinelConfig{
		TransportConfig: TransportConfig{
			FlushInterval: 1 * time.Hour,
			MaxRetries:    1,
			RetryBackoff:  1 * time.Millisecond,
			BufferSize:    100,
		},
		WorkspaceID: "ws-123",
		SharedKey:   sharedKey,
		LogType:     "EunoAudit",
		Endpoint:    server.URL,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer func() { _ = transport.Close() }()

	err := transport.Send(context.Background(), records)
	require.NoError(t, err)
	assert.Equal(t, "EunoAudit", receivedLogType)
	assert.NotEmpty(t, receivedDate)
	assert.Equal(t, "/", receivedPath)
	assert.Contains(t, receivedAuth, "SharedKey ws-123:")
	assert.NotContains(t, receivedAuth, sharedKey)
}

func TestAzureSentinelTransport_Enqueue_AfterClose(t *testing.T) {
	t.Parallel()

	transport := NewAzureSentinelTransport(&AzureSentinelConfig{
		TransportConfig: TransportConfig{
			FlushInterval: 1 * time.Hour,
			BufferSize:    100,
		},
		Endpoint: "http://localhost:9999",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	require.NoError(t, transport.Close())

	err := transport.Enqueue(&SignedAuditEvidence{})
	assert.ErrorIs(t, err, ErrTransportClosed)
}

func TestAzureSentinelTransport_DefaultLogType(t *testing.T) {
	t.Parallel()

	var receivedLogType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedLogType = r.Header.Get("Log-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := NewAzureSentinelTransport(&AzureSentinelConfig{
		TransportConfig: TransportConfig{
			FlushInterval: 1 * time.Hour,
			BufferSize:    100,
		},
		Endpoint: server.URL,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer func() { _ = transport.Close() }()

	err := transport.Send(context.Background(), []SignedAuditEvidence{
		{Record: LogEntry{ID: "rec-1"}},
	})
	require.NoError(t, err)
	assert.Equal(t, "EunoAudit", receivedLogType)
}

func TestBuildAzureSentinelAuthorization(t *testing.T) {
	t.Parallel()

	authHeader, err := buildAzureSentinelAuthorization("ws-123", base64.StdEncoding.EncodeToString([]byte("key-456")), 34, "application/json", "Mon, 01 Jan 2024 00:00:00 GMT", "/api/logs")
	require.NoError(t, err)

	stringToSign := "POST\n" + strconv.Itoa(34) + "\napplication/json\nx-ms-date:Mon, 01 Jan 2024 00:00:00 GMT\n/api/logs"
	mac := hmac.New(sha256.New, []byte("key-456"))
	mac.Write([]byte(stringToSign))
	expectedAuth := "SharedKey ws-123:" + base64.StdEncoding.EncodeToString(mac.Sum(nil))
	assert.Equal(t, expectedAuth, authHeader)
}

// --- Anchor Tests ---

func TestComputeMerkleRoot_SingleRecord(t *testing.T) {
	t.Parallel()

	records := []SignedAuditEvidence{
		{ChainHash: "hash-1"},
	}
	root := computeMerkleRoot(records)
	assert.NotEmpty(t, root)
}

func TestComputeMerkleRoot_MultipleRecords(t *testing.T) {
	t.Parallel()

	records := []SignedAuditEvidence{
		{ChainHash: "hash-1"},
		{ChainHash: "hash-2"},
		{ChainHash: "hash-3"},
		{ChainHash: "hash-4"},
	}
	root := computeMerkleRoot(records)
	assert.NotEmpty(t, root)

	// Same input should produce same root.
	root2 := computeMerkleRoot(records)
	assert.Equal(t, root, root2)
}

func TestComputeMerkleRoot_OddRecords(t *testing.T) {
	t.Parallel()

	records := []SignedAuditEvidence{
		{ChainHash: "hash-1"},
		{ChainHash: "hash-2"},
		{ChainHash: "hash-3"},
	}
	root := computeMerkleRoot(records)
	assert.NotEmpty(t, root)
}

func TestComputeMerkleRoot_Empty(t *testing.T) {
	t.Parallel()
	root := computeMerkleRoot(nil)
	assert.Empty(t, root)
}

func TestAnchorService_CreateAnchor(t *testing.T) {
	t.Parallel()

	// Create an in-memory query store that returns chain segments.
	store := &mockQueryStore{
		chainSegment: []SignedAuditEvidence{
			{ChainHash: "hash-1", SequenceNum: 1, ReplicaID: "replica-1"},
			{ChainHash: "hash-2", SequenceNum: 2, ReplicaID: "replica-1"},
			{ChainHash: "hash-3", SequenceNum: 3, ReplicaID: "replica-1"},
		},
	}

	service := NewAnchorService(store, slog.New(slog.NewTextHandler(io.Discard, nil)))

	anchor, err := service.CreateAnchor(context.Background(), "replica-1", 1, 3)
	require.NoError(t, err)
	assert.Equal(t, "replica-1", anchor.ReplicaID)
	assert.Equal(t, int64(3), anchor.SequenceNum)
	assert.Equal(t, "hash-3", anchor.ChainHash)
	assert.NotEmpty(t, anchor.MerkleRoot)
	assert.NotEmpty(t, anchor.AnchorID)
}

func TestAnchorService_CreateAnchor_EmptySegment(t *testing.T) {
	t.Parallel()

	store := &mockQueryStore{chainSegment: nil}
	service := NewAnchorService(store, slog.New(slog.NewTextHandler(io.Discard, nil)))

	_, err := service.CreateAnchor(context.Background(), "replica-1", 1, 3)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no records in segment")
}

func TestAnchorService_SubmitAnchor(t *testing.T) {
	t.Parallel()

	mockBackend := &mockAnchorBackend{ref: "s3://bucket/anchor-1.json"}
	store := &mockQueryStore{}
	service := NewAnchorService(store, slog.New(slog.NewTextHandler(io.Discard, nil)), mockBackend)

	anchor := &ChainAnchor{
		AnchorID:    "anchor-1",
		ReplicaID:   "replica-1",
		SequenceNum: 5,
		ChainHash:   "hash-5",
		MerkleRoot:  "merkle-root",
		Timestamp:   time.Now().UTC(),
	}

	err := service.SubmitAnchor(context.Background(), anchor)
	require.NoError(t, err)
	assert.Equal(t, "s3://bucket/anchor-1.json", anchor.ExternalRef)
	assert.Equal(t, "mock-anchor", anchor.Backend)
}

// --- Anchor Backend Tests ---

func TestS3AnchorBackend_Name(t *testing.T) {
	t.Parallel()
	backend := NewS3AnchorBackend(S3AnchorConfig{})
	assert.Equal(t, "s3", backend.Name())
}

func TestAzureConfidentialLedgerBackend_Name(t *testing.T) {
	t.Parallel()
	backend := NewAzureConfidentialLedgerBackend(AzureConfidentialLedgerConfig{})
	assert.Equal(t, "azure-confidential-ledger", backend.Name())
}

func TestS3AnchorBackend_Anchor(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Contains(t, r.URL.Path, "anchor-test.json")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	backend := NewS3AnchorBackend(S3AnchorConfig{
		Bucket:   "test-bucket",
		Prefix:   "anchors/",
		Endpoint: server.URL,
	})

	anchor := &ChainAnchor{
		AnchorID:    "anchor-test",
		ReplicaID:   "replica-1",
		SequenceNum: 10,
		ChainHash:   "chain-hash-10",
		MerkleRoot:  "merkle-root-10",
		Timestamp:   time.Now().UTC(),
	}

	ref, err := backend.Anchor(context.Background(), anchor)
	require.NoError(t, err)
	assert.Contains(t, ref, "s3://test-bucket/anchors/anchor-test.json")
}

func TestS3AnchorBackend_Verify(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodHead, r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	backend := NewS3AnchorBackend(S3AnchorConfig{
		Bucket:   "test-bucket",
		Prefix:   "anchors/",
		Endpoint: server.URL,
	})

	anchor := &ChainAnchor{AnchorID: "anchor-test"}
	exists, err := backend.Verify(context.Background(), anchor)
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestAzureConfidentialLedgerBackend_Anchor(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Contains(t, r.URL.Path, "/app/transactions")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"transactionId":"tx-12345"}`))
	}))
	defer server.Close()

	backend := NewAzureConfidentialLedgerBackend(AzureConfidentialLedgerConfig{
		LedgerName: "test-ledger",
		Endpoint:   server.URL,
		AuthToken:  "test-token",
	})

	anchor := &ChainAnchor{
		AnchorID:    "anchor-1",
		ReplicaID:   "replica-1",
		SequenceNum: 5,
	}

	ref, err := backend.Anchor(context.Background(), anchor)
	require.NoError(t, err)
	assert.Equal(t, "tx-12345", ref)
}

func TestAzureConfidentialLedgerBackend_Verify(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Contains(t, r.URL.Path, "tx-12345")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	backend := NewAzureConfidentialLedgerBackend(AzureConfidentialLedgerConfig{
		Endpoint: server.URL,
	})

	anchor := &ChainAnchor{ExternalRef: "tx-12345"}
	exists, err := backend.Verify(context.Background(), anchor)
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestAzureConfidentialLedgerBackend_Verify_NoRef(t *testing.T) {
	t.Parallel()

	backend := NewAzureConfidentialLedgerBackend(AzureConfidentialLedgerConfig{
		Endpoint: "http://localhost:9999",
	})

	anchor := &ChainAnchor{ExternalRef: ""}
	exists, err := backend.Verify(context.Background(), anchor)
	require.NoError(t, err)
	assert.False(t, exists)
}

// --- Test mocks ---

type mockQueryStore struct {
	chainSegment []SignedAuditEvidence
}

func (s *mockQueryStore) Query(_ context.Context, _ *QueryFilter, _ PageParams) (*QueryResult, error) {
	return &QueryResult{Records: s.chainSegment, TotalCount: int64(len(s.chainSegment))}, nil
}

func (s *mockQueryStore) GetByID(_ context.Context, _ string) (*SignedAuditEvidence, error) {
	return nil, ErrRecordNotFound
}

func (s *mockQueryStore) GetChainSegment(_ context.Context, _ string, _, _ int64) ([]SignedAuditEvidence, error) {
	return s.chainSegment, nil
}

type mockAnchorBackend struct {
	ref string
	err error
}

func (m *mockAnchorBackend) Anchor(_ context.Context, _ *ChainAnchor) (string, error) {
	return m.ref, m.err
}

func (m *mockAnchorBackend) Verify(_ context.Context, _ *ChainAnchor) (bool, error) {
	return m.ref != "", m.err
}

func (m *mockAnchorBackend) Name() string { return "mock-anchor" }

// --- End-to-end integration test ---

func TestIntegration_EnforcementDecision_AuditRecord_ExportVerify(t *testing.T) {
	t.Parallel()

	// 1. Create signer.
	signer := NewEvidenceSigner(&mockSigner{algorithm: crypto.ES256, keyID: "audit-key-prod"})

	// 2. Create backend.
	backend := newInMemoryLedgerBackend()

	// 3. Create pipeline.
	pipeline, err := NewPipeline(signer, backend, PipelineConfig{ReplicaID: "gw-replica-1"})
	require.NoError(t, err)
	require.NoError(t, pipeline.Initialize(context.Background()))

	// 4. Simulate enforcement decision → audit record.
	ocsfEvent := ocsf.NewAPIActivityEvent(ocsf.ActivityAPIAllow, &ocsf.Actor{
		UserID:    "agent-123",
		TenantID:  "tenant-org-1",
		SessionID: "session-abc",
	}).WithStatus(ocsf.StatusSuccess, "allowed").
		WithSOC2Controls(ocsf.SOC2CC61, ocsf.SOC2CC72)

	ocsfEvent.ToolName = "code-search"
	ocsfEvent.ToolAction = "search"
	ocsfEvent.HTTPMethod = "POST"
	ocsfEvent.HTTPURL = "/api/v1/enforce"
	ocsfEvent.Duration = 12

	entry := &LogEntry{
		TenantID:  "tenant-org-1",
		EventType: "enforcement.allow",
		Actor: ocsf.Actor{
			UserID:    "agent-123",
			TenantID:  "tenant-org-1",
			SessionID: "session-abc",
		},
		Action:    "enforce",
		Outcome:   "allow",
		OCSFEvent: ocsfEvent,
	}

	require.NoError(t, pipeline.Append(context.Background(), entry))

	// 5. Export → verify signature (chain hash verification).
	records := backend.Records()
	require.Len(t, records, 1)

	exported := records[0]
	assert.Equal(t, "tenant-org-1", exported.Record.TenantID)
	assert.Equal(t, "enforcement.allow", exported.Record.EventType)
	assert.NotEmpty(t, exported.Signature)
	assert.Equal(t, "ES256", exported.Algorithm)
	assert.Equal(t, "audit-key-prod", exported.KeyID)
	assert.True(t, VerifyChainHash(&exported))
	assert.Equal(t, "gw-replica-1", exported.ReplicaID)
	assert.NotNil(t, exported.Record.OCSFEvent)
}
