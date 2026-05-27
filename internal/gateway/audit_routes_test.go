// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/edgeobs/eunox/internal/gateway"
	"github.com/edgeobs/eunox/pkg/audit"
	"github.com/edgeobs/eunox/pkg/callcounter"
	"github.com/edgeobs/eunox/pkg/capability"
	"github.com/edgeobs/eunox/pkg/enforcement"
	"github.com/edgeobs/eunox/pkg/killswitch"
	"github.com/edgeobs/eunox/pkg/ocsf"
	"github.com/edgeobs/eunox/pkg/revocation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mock implementations for audit tests ---

type mockQueryStore struct {
	records      []audit.SignedAuditEvidence
	chainSegment []audit.SignedAuditEvidence
	queryErr     error
	lastFilter   audit.QueryFilter
	lastPage     audit.PageParams
	queryCount   int
}

func (s *mockQueryStore) Query(_ context.Context, filter *audit.QueryFilter, page audit.PageParams) (*audit.QueryResult, error) {
	if s.queryErr != nil {
		return nil, s.queryErr
	}
	s.lastFilter = *filter
	s.lastPage = page
	s.queryCount++
	return &audit.QueryResult{
		Records:    s.records,
		TotalCount: int64(len(s.records)),
		HasMore:    false,
	}, nil
}

func (s *mockQueryStore) GetByID(_ context.Context, id string) (*audit.SignedAuditEvidence, error) {
	for i := range s.records {
		if s.records[i].Record.ID == id {
			return &s.records[i], nil
		}
	}
	return nil, audit.ErrRecordNotFound
}

func (s *mockQueryStore) GetChainSegment(_ context.Context, _ string, _, _ int64) ([]audit.SignedAuditEvidence, error) {
	if s.queryErr != nil {
		return nil, s.queryErr
	}
	return s.chainSegment, nil
}

type mockAuditJWTVerifier struct {
	claims *capability.TokenPayload
	err    error
}

func (m *mockAuditJWTVerifier) VerifyToken(_ context.Context, _ string) (*capability.TokenPayload, error) {
	return m.claims, m.err
}

func newAuditTestApp(t *testing.T, auditDeps *gateway.AuditDependencies) *gateway.App {
	return newAuditTestAppWithConfig(t, auditDeps, nil, &gateway.Config{AdminAPIKey: "test-admin-key"})
}

func newAuditTestAppWithConfig(t *testing.T, auditDeps *gateway.AuditDependencies, verifier gateway.JWTVerifier, cfg *gateway.Config) *gateway.App {
	t.Helper()

	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ks := killswitch.NewInMemory()
	revStore := revocation.NewInMemory()
	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	deps := gateway.Dependencies{
		Engine:      engine,
		KillSwitch:  ks,
		Revocation:  revStore,
		DPoPStore:   dpopStore,
		JWTVerifier: verifier,
		Logger:      logger,
		Audit:       auditDeps,
	}

	app, err := gateway.New(cfg, &deps)
	require.NoError(t, err)
	return app
}

func withAuditAdminAuth(req *http.Request) *http.Request {
	req.Header.Set("X-Admin-Api-Key", "test-admin-key")
	return req
}

func TestAuditRecords_NoAuditConfigured(t *testing.T) {
	t.Parallel()

	app := newAuditTestApp(t, nil)
	// Auth passes (admin key), but audit store is not configured — expect 503.
	req := withAuditAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/audit/records", http.NoBody))
	rec := httptest.NewRecorder()

	app.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestAuditRecords_Success(t *testing.T) {
	t.Parallel()

	store := &mockQueryStore{
		records: []audit.SignedAuditEvidence{
			{
				Record:    audit.LogEntry{ID: "rec-1", TenantID: "t1", EventType: "enforce"},
				Signature: "sig-1",
				ChainHash: "hash-1",
			},
			{
				Record:    audit.LogEntry{ID: "rec-2", TenantID: "t1", EventType: "enforce"},
				Signature: "sig-2",
				ChainHash: "hash-2",
			},
		},
	}

	app := newAuditTestApp(t, &gateway.AuditDependencies{QueryStore: store})
	req := withAuditAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/audit/records?tenant_id=t1", http.NoBody))
	rec := httptest.NewRecorder()

	app.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var result map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
	assert.Equal(t, float64(2), result["total_count"])
}

func TestAuditRecords_WithPagination(t *testing.T) {
	t.Parallel()

	store := &mockQueryStore{records: []audit.SignedAuditEvidence{}}
	app := newAuditTestApp(t, &gateway.AuditDependencies{QueryStore: store})

	req := withAuditAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/audit/records?page=2&page_size=25", http.NoBody))
	rec := httptest.NewRecorder()

	app.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, audit.PageParams{Offset: 25, Limit: 25}, store.lastPage)
}

func TestAuditExport_Success(t *testing.T) {
	t.Parallel()

	ocsfEvent := ocsf.NewAPIActivityEvent(ocsf.ActivityAPIAllow, &ocsf.Actor{
		UserID: "user-1", TenantID: "t1",
	})

	store := &mockQueryStore{
		records: []audit.SignedAuditEvidence{
			{
				Record: audit.LogEntry{
					ID:        "rec-1",
					TenantID:  "t1",
					EventType: "enforce",
					OCSFEvent: ocsfEvent,
				},
			},
		},
	}

	app := newAuditTestApp(t, &gateway.AuditDependencies{QueryStore: store})
	req := withAuditAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/audit/export?tenant_id=t1", http.NoBody))
	rec := httptest.NewRecorder()

	app.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "1.1.0", rec.Header().Get("X-OCSF-Version"))

	var result map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
	assert.Equal(t, "1.1.0", result["schema_version"])
	events := result["events"].([]any)
	assert.Len(t, events, 1)
}

func TestAuditExport_NoOCSFEvent(t *testing.T) {
	t.Parallel()

	store := &mockQueryStore{
		records: []audit.SignedAuditEvidence{
			{
				Record: audit.LogEntry{
					ID:        "rec-1",
					TenantID:  "t1",
					EventType: "enforce",
					Action:    "allow",
					Outcome:   "success",
					Timestamp: time.Now().UTC(),
				},
			},
		},
	}

	app := newAuditTestApp(t, &gateway.AuditDependencies{QueryStore: store})
	req := withAuditAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/audit/export", http.NoBody))
	rec := httptest.NewRecorder()

	app.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var result map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
	events := result["events"].([]any)
	assert.Len(t, events, 1)
	// Should have a wrapped OCSF envelope.
	event := events[0].(map[string]any)
	assert.Equal(t, float64(6003), event["class_uid"])
}

func TestAuditSigningKeys_Success(t *testing.T) {
	t.Parallel()

	keys := []gateway.SigningKeyInfo{
		{KeyID: "key-1", Algorithm: "ES256", PublicKey: "base64pubkey"},
	}

	app := newAuditTestApp(t, &gateway.AuditDependencies{SigningKeys: keys})
	req := withAuditAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/audit/signing-keys", http.NoBody))
	rec := httptest.NewRecorder()

	app.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var result map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
	returnedKeys := result["keys"].([]any)
	assert.Len(t, returnedKeys, 1)
}

func TestAuditSigningKeys_NotConfigured(t *testing.T) {
	t.Parallel()

	app := newAuditTestApp(t, nil)
	// Auth passes (admin key), but audit pipeline is not configured — expect 503.
	req := withAuditAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/audit/signing-keys", http.NoBody))
	rec := httptest.NewRecorder()

	app.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestAuditChainProof_Success(t *testing.T) {
	t.Parallel()

	// Build a valid chain segment with fixed timestamps.
	ts1 := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	ts2 := time.Date(2025, 1, 1, 0, 0, 1, 0, time.UTC)

	prevHash := audit.ComputeChainHash("", "rec-1", ts1, "sig-1")
	nextHash := audit.ComputeChainHash(prevHash, "rec-2", ts2, "sig-2")

	store := &mockQueryStore{
		chainSegment: []audit.SignedAuditEvidence{
			{
				Record:       audit.LogEntry{ID: "rec-1", Timestamp: ts1},
				Signature:    "sig-1",
				ChainHash:    prevHash,
				PreviousHash: "",
				SequenceNum:  1,
				ReplicaID:    "replica-1",
			},
			{
				Record:       audit.LogEntry{ID: "rec-2", Timestamp: ts2},
				Signature:    "sig-2",
				ChainHash:    nextHash,
				PreviousHash: prevHash,
				SequenceNum:  2,
				ReplicaID:    "replica-1",
			},
		},
	}

	app := newAuditTestApp(t, &gateway.AuditDependencies{QueryStore: store})
	req := withAuditAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/audit/chain-proof?replica_id=replica-1&from_seq=1&to_seq=2", http.NoBody))
	rec := httptest.NewRecorder()

	app.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var result map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
	assert.Equal(t, true, result["valid"])
	assert.Equal(t, float64(2), result["count"])
}

func TestAuditChainProof_MissingReplicaID(t *testing.T) {
	t.Parallel()

	store := &mockQueryStore{}
	app := newAuditTestApp(t, &gateway.AuditDependencies{QueryStore: store})
	req := withAuditAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/audit/chain-proof?from_seq=1&to_seq=5", http.NoBody))
	rec := httptest.NewRecorder()

	app.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAuditChainProof_InvalidFromSeq(t *testing.T) {
	t.Parallel()

	store := &mockQueryStore{}
	app := newAuditTestApp(t, &gateway.AuditDependencies{QueryStore: store})
	req := withAuditAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/audit/chain-proof?replica_id=r1&from_seq=abc&to_seq=5", http.NoBody))
	rec := httptest.NewRecorder()

	app.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAuditChainProof_InvalidToSeq(t *testing.T) {
	t.Parallel()

	store := &mockQueryStore{}
	app := newAuditTestApp(t, &gateway.AuditDependencies{QueryStore: store})
	req := withAuditAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/audit/chain-proof?replica_id=r1&from_seq=5&to_seq=2", http.NoBody))
	rec := httptest.NewRecorder()

	app.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAuditChainProof_BrokenChain(t *testing.T) {
	t.Parallel()

	store := &mockQueryStore{
		chainSegment: []audit.SignedAuditEvidence{
			{
				Record:       audit.LogEntry{ID: "rec-1", Timestamp: time.Now()},
				Signature:    "sig-1",
				ChainHash:    "valid-hash",
				PreviousHash: "",
				SequenceNum:  1,
			},
			{
				Record:       audit.LogEntry{ID: "rec-2", Timestamp: time.Now()},
				Signature:    "sig-2",
				ChainHash:    "TAMPERED",
				PreviousHash: "valid-hash",
				SequenceNum:  2,
			},
		},
	}

	app := newAuditTestApp(t, &gateway.AuditDependencies{QueryStore: store})
	req := withAuditAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/audit/chain-proof?replica_id=r1&from_seq=1&to_seq=2", http.NoBody))
	rec := httptest.NewRecorder()

	app.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var result map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
	assert.Equal(t, false, result["valid"])
}

func TestAuditRecords_RequiresAuthentication(t *testing.T) {
	t.Parallel()

	store := &mockQueryStore{}
	app := newAuditTestAppWithConfig(t, &gateway.AuditDependencies{QueryStore: store}, nil, &gateway.Config{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/records", http.NoBody)
	rec := httptest.NewRecorder()

	app.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Zero(t, store.queryCount)
}

func TestAuditRecords_JWTScopesTenantFilter(t *testing.T) {
	t.Parallel()

	store := &mockQueryStore{}
	verifier := &mockAuditJWTVerifier{
		claims: &capability.TokenPayload{
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			AuthorizedBy: &capability.AuthorizedBy{
				TenantID: "tenant-jwt",
			},
		},
	}
	app := newAuditTestAppWithConfig(t, &gateway.AuditDependencies{QueryStore: store}, verifier, &gateway.Config{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/records", http.NoBody)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	app.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "tenant-jwt", store.lastFilter.TenantID)
}

func TestAuditRecords_JWTRejectsTenantMismatch(t *testing.T) {
	t.Parallel()

	store := &mockQueryStore{}
	verifier := &mockAuditJWTVerifier{
		claims: &capability.TokenPayload{
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			AuthorizedBy: &capability.AuthorizedBy{
				TenantID: "tenant-jwt",
			},
		},
	}
	app := newAuditTestAppWithConfig(t, &gateway.AuditDependencies{QueryStore: store}, verifier, &gateway.Config{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/records?tenant_id=other-tenant", http.NoBody)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	app.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Zero(t, store.queryCount)
}

func TestAuditChainProof_BrokenLinkage(t *testing.T) {
	t.Parallel()

	ts1 := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	ts2 := time.Date(2025, 1, 1, 0, 0, 1, 0, time.UTC)
	hash1 := audit.ComputeChainHash("", "rec-1", ts1, "sig-1")
	hash2 := audit.ComputeChainHash("different-previous-hash", "rec-2", ts2, "sig-2")

	store := &mockQueryStore{
		chainSegment: []audit.SignedAuditEvidence{
			{
				Record:       audit.LogEntry{ID: "rec-1", Timestamp: ts1},
				Signature:    "sig-1",
				ChainHash:    hash1,
				PreviousHash: "",
				SequenceNum:  1,
			},
			{
				Record:       audit.LogEntry{ID: "rec-2", Timestamp: ts2},
				Signature:    "sig-2",
				ChainHash:    hash2,
				PreviousHash: "different-previous-hash",
				SequenceNum:  2,
			},
		},
	}

	app := newAuditTestApp(t, &gateway.AuditDependencies{QueryStore: store})
	req := withAuditAdminAuth(httptest.NewRequest(http.MethodGet, "/api/v1/audit/chain-proof?replica_id=r1&from_seq=1&to_seq=2", http.NoBody))
	rec := httptest.NewRecorder()

	app.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var result map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
	assert.Equal(t, false, result["valid"])
	assert.Equal(t, float64(2), result["broken_at_seq"])
}

// CI-7: audit auth middleware tests.

func TestAuditMiddleware_UnauthenticatedReturns401(t *testing.T) {
	t.Parallel()

	store := &mockQueryStore{}
	app := newAuditTestApp(t, &gateway.AuditDependencies{QueryStore: store})
	// No credentials — middleware must return 401.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/records", http.NoBody)
	rec := httptest.NewRecorder()

	app.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAuditMiddleware_WrongAdminKeyReturns401(t *testing.T) {
	t.Parallel()

	store := &mockQueryStore{}
	app := newAuditTestApp(t, &gateway.AuditDependencies{QueryStore: store})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/records", http.NoBody)
	req.Header.Set("X-Admin-Api-Key", "wrong-key")
	rec := httptest.NewRecorder()

	app.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAuditMiddleware_AuthAppliedToAllAuditRoutes(t *testing.T) {
	t.Parallel()

	store := &mockQueryStore{}
	app := newAuditTestApp(t, &gateway.AuditDependencies{QueryStore: store, SigningKeys: []gateway.SigningKeyInfo{}})

	routes := []string{
		"/api/v1/audit/records",
		"/api/v1/audit/export",
		"/api/v1/audit/signing-keys",
		"/api/v1/audit/chain-proof",
	}
	for _, path := range routes {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
			// No auth headers — all routes must return 401.
			rec := httptest.NewRecorder()
			app.Handler().ServeHTTP(rec, req)
			assert.Equal(t, http.StatusUnauthorized, rec.Code, "expected 401 for unauthenticated request to %s", path)
		})
	}
}
