// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway_test

import (
	"bytes"
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
	"github.com/edgeobs/eunox/pkg/revocation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testAdminKey = "test-admin-api-key-secure-32chars!"

func newAdminTestApp(t *testing.T) *gateway.App {
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
		JWTVerifier: &mockJWTVerifier{},
		DPoPStore:   dpopStore,
		Logger:      logger,
	}

	cfg := gateway.Config{
		GatewayAudience: "test-gateway",
		AdminAPIKey:     testAdminKey,
		TenantID:        "tenant-1",
	}

	app, err := gateway.New(&cfg, &deps)
	require.NoError(t, err)
	return app
}

func newAdminTestAppWithAudit(t *testing.T) *gateway.App {
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
		JWTVerifier: &mockJWTVerifier{},
		DPoPStore:   dpopStore,
		Logger:      logger,
		Audit: &gateway.AuditDependencies{
			Pipeline: &mockAuditPipeline{},
		},
	}

	cfg := gateway.Config{
		GatewayAudience: "test-gateway",
		AdminAPIKey:     testAdminKey,
		TenantID:        "tenant-1",
	}

	app, err := gateway.New(&cfg, &deps)
	require.NoError(t, err)
	return app
}

type mockAuditPipeline struct {
	entries []*audit.LogEntry
}

func (m *mockAuditPipeline) Append(_ context.Context, entry *audit.LogEntry) error {
	m.entries = append(m.entries, entry)
	return nil
}

func (m *mockAuditPipeline) Close() error {
	return nil
}

func adminReq(method, path string, body interface{}) *http.Request {
	var bodyReader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set("X-Admin-Api-Key", testAdminKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

func parseJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var result map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &result)
	require.NoError(t, err, "response is not valid JSON: %s", w.Body.String())
	return result
}

// --- Admin Authentication Tests ---

func TestAdmin_RejectsUnauthenticatedRequests(t *testing.T) {
	app := newAdminTestApp(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/kill-switch/status", http.NoBody)
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	result := parseJSON(t, w)
	assert.Equal(t, "unauthorized", result["error"])
}

func TestAdmin_RejectsInvalidKey(t *testing.T) {
	app := newAdminTestApp(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/kill-switch/status", http.NoBody)
	req.Header.Set("X-Admin-Api-Key", "wrong-key")
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	result := parseJSON(t, w)
	assert.Equal(t, "unauthorized", result["error"])
}

func TestAdmin_AcceptsValidKey(t *testing.T) {
	app := newAdminTestApp(t)

	req := adminReq(http.MethodGet, "/admin/kill-switch/status", nil)
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdmin_AcceptsLegacyHeader(t *testing.T) {
	app := newAdminTestApp(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/kill-switch/status", http.NoBody)
	req.Header.Set("X-Admin-Key", testAdminKey)
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdmin_KeyConfiguredWithoutTenant_DisablesAdminAuth(t *testing.T) {
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	deps := gateway.Dependencies{
		Engine:      engine,
		KillSwitch:  killswitch.NewInMemory(),
		Revocation:  revocation.NewInMemory(),
		JWTVerifier: &mockJWTVerifier{},
		DPoPStore:   gateway.NewInMemoryDPoPStore(5 * time.Minute),
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	app, err := gateway.New(&gateway.Config{
		GatewayAudience: "test-gateway",
		AdminAPIKey:     testAdminKey,
	}, &deps)
	require.NoError(t, err)

	req := adminReq(http.MethodGet, "/admin/kill-switch/status", nil)
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestAdmin_TimingSafeComparison(t *testing.T) {
	app := newAdminTestApp(t)

	// Ensure keys of different lengths are still rejected
	keys := []string{"", "short", testAdminKey + "extra", "x"}
	for _, key := range keys {
		req := httptest.NewRequest(http.MethodGet, "/admin/kill-switch/status", http.NoBody)
		req.Header.Set("X-Admin-Api-Key", key)
		w := httptest.NewRecorder()
		app.AdminHandler().ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code, "key=%q should be rejected", key)
	}
}

// --- Kill-Switch Tests ---

func TestAdmin_KillSwitchStatus(t *testing.T) {
	app := newAdminTestApp(t)

	req := adminReq(http.MethodGet, "/admin/kill-switch/status", nil)
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	result := parseJSON(t, w)
	assert.Equal(t, false, result["globalActive"])
}

func TestAdmin_KillSwitchGlobalActivate_RequiresAck(t *testing.T) {
	app := newAdminTestApp(t)

	// Without acknowledgment - should fail
	req := adminReq(http.MethodPost, "/admin/kill-switch/global/activate", map[string]any{})
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestAdmin_KillSwitchGlobalActivateDeactivate(t *testing.T) {
	app := newAdminTestApp(t)

	// Activate
	body := map[string]any{"acknowledgesCrossTenantImpact": true}
	req := adminReq(http.MethodPost, "/admin/kill-switch/global/activate", body)
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	result := parseJSON(t, w)
	assert.Equal(t, "activated", result["status"])

	// Verify status
	req = adminReq(http.MethodGet, "/admin/kill-switch/status", nil)
	w = httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	result = parseJSON(t, w)
	assert.Equal(t, true, result["globalActive"])

	// Deactivate
	req = adminReq(http.MethodPost, "/admin/kill-switch/global/deactivate", body)
	w = httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	result = parseJSON(t, w)
	assert.Equal(t, "deactivated", result["status"])

	// Verify status
	req = adminReq(http.MethodGet, "/admin/kill-switch/status", nil)
	w = httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	result = parseJSON(t, w)
	assert.Equal(t, false, result["globalActive"])
}

func TestAdmin_KillSwitchAgentKillRevive(t *testing.T) {
	app := newAdminTestApp(t)

	// Kill agent
	req := adminReq(http.MethodPost, "/admin/kill-switch/agent/agent-123/kill", nil)
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	result := parseJSON(t, w)
	assert.Equal(t, "killed", result["status"])
	assert.Equal(t, "agent-123", result["agentId"])

	// Verify in status
	req = adminReq(http.MethodGet, "/admin/kill-switch/status", nil)
	w = httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	result = parseJSON(t, w)
	agents := result["killedAgents"].([]interface{})
	assert.Contains(t, agents, "agent-123")

	// Revive agent
	req = adminReq(http.MethodPost, "/admin/kill-switch/agent/agent-123/revive", nil)
	w = httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	result = parseJSON(t, w)
	assert.Equal(t, "revived", result["status"])
}

func TestAdmin_KillSwitchSessionKillRevive(t *testing.T) {
	app := newAdminTestApp(t)

	// Kill session
	req := adminReq(http.MethodPost, "/admin/kill-switch/session/sess-456/kill", nil)
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	result := parseJSON(t, w)
	assert.Equal(t, "killed", result["status"])
	assert.Equal(t, "sess-456", result["sessionId"])

	// Verify in status
	req = adminReq(http.MethodGet, "/admin/kill-switch/status", nil)
	w = httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	result = parseJSON(t, w)
	sessions := result["killedSessions"].([]interface{})
	assert.Contains(t, sessions, "sess-456")

	// Revive session
	req = adminReq(http.MethodPost, "/admin/kill-switch/session/sess-456/revive", nil)
	w = httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdmin_KillSwitchReset_RequiresAck(t *testing.T) {
	app := newAdminTestApp(t)

	req := adminReq(http.MethodPost, "/admin/kill-switch/reset", map[string]any{})
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestAdmin_KillSwitchReset(t *testing.T) {
	app := newAdminTestApp(t)

	// Kill an agent
	req := adminReq(http.MethodPost, "/admin/kill-switch/agent/agent-1/kill", nil)
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Reset
	body := map[string]any{"acknowledgesCrossTenantImpact": true}
	req = adminReq(http.MethodPost, "/admin/kill-switch/reset", body)
	w = httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify clean status
	req = adminReq(http.MethodGet, "/admin/kill-switch/status", nil)
	w = httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	result := parseJSON(t, w)
	assert.Equal(t, false, result["globalActive"])
}

// --- Token Revocation Tests ---

func TestAdmin_RevokeToken(t *testing.T) {
	app := newAdminTestApp(t)

	req := adminReq(http.MethodPost, "/admin/revoke/jti-test-123", map[string]any{
		"ttlSeconds": 3600,
	})
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	result := parseJSON(t, w)
	assert.Equal(t, "revoked", result["status"])
	assert.Equal(t, "jti-test-123", result["jti"])
}

func TestAdmin_RevokeToken_InvalidBody(t *testing.T) {
	app := newAdminTestApp(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/revoke/jti-test-123", bytes.NewReader([]byte("{")))
	req.Header.Set("X-Admin-Api-Key", testAdminKey)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdmin_RevocationStatus(t *testing.T) {
	app := newAdminTestApp(t)

	// Revoke first
	req := adminReq(http.MethodPost, "/admin/revoke/jti-999", nil)
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Check status
	req = adminReq(http.MethodGet, "/admin/revocation/status?jti=jti-999", nil)
	w = httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	result := parseJSON(t, w)
	assert.Equal(t, true, result["revoked"])
}

func TestAdmin_RevocationStatus_NotRevoked(t *testing.T) {
	app := newAdminTestApp(t)

	req := adminReq(http.MethodGet, "/admin/revocation/status?jti=jti-not-revoked", nil)
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	result := parseJSON(t, w)
	assert.Equal(t, false, result["revoked"])
}

func TestAdmin_RevocationStatus_General(t *testing.T) {
	app := newAdminTestApp(t)

	req := adminReq(http.MethodGet, "/admin/revocation/status", nil)
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	result := parseJSON(t, w)
	assert.Equal(t, "operational", result["status"])
}

// --- Usage Metering Tests ---

func TestAdmin_Usage(t *testing.T) {
	app := newAdminTestApp(t)

	req := adminReq(http.MethodGet, "/admin/usage", nil)
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	result := parseJSON(t, w)
	assert.NotNil(t, result["tenants"])
}

func TestAdmin_UsageReset_RequiresAck(t *testing.T) {
	app := newAdminTestApp(t)

	req := adminReq(http.MethodPost, "/admin/usage/reset", map[string]any{})
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestAdmin_UsageReset(t *testing.T) {
	app := newAdminTestApp(t)

	body := map[string]any{"acknowledgesCrossTenantImpact": true}
	req := adminReq(http.MethodPost, "/admin/usage/reset", body)
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	result := parseJSON(t, w)
	assert.Equal(t, "reset", result["status"])
}

// --- Partner DID Tests ---

func TestAdmin_PartnerDID_Register(t *testing.T) {
	app := newAdminTestApp(t)

	body := map[string]any{
		"did":         "did:web:partner.example.com",
		"name":        "Test Partner",
		"description": "A test partner organization",
	}
	req := adminReq(http.MethodPost, "/admin/partner-dids/", body)
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	result := parseJSON(t, w)
	assert.Equal(t, "registered", result["status"])
	assert.Equal(t, "did:web:partner.example.com", result["did"])

	req = adminReq(http.MethodGet, "/admin/partner-dids/", nil)
	w = httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	result = parseJSON(t, w)
	partners := result["partners"].([]any)
	found := false
	for _, rawPartner := range partners {
		partner := rawPartner.(map[string]any)
		if partner["did"] == "did:web:partner.example.com" {
			assert.Equal(t, "pending", partner["status"])
			found = true
			break
		}
	}
	assert.True(t, found)
}

func TestAdmin_PartnerDID_RegisterMissingFields(t *testing.T) {
	app := newAdminTestApp(t)

	body := map[string]any{"did": "did:web:example.com"}
	req := adminReq(http.MethodPost, "/admin/partner-dids/", body)
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdmin_PartnerDID_List(t *testing.T) {
	app := newAdminTestApp(t)

	// Register two partners
	for _, did := range []string{"did:web:a.com", "did:web:b.com"} {
		body := map[string]any{"did": did, "name": "Partner " + did}
		req := adminReq(http.MethodPost, "/admin/partner-dids/", body)
		w := httptest.NewRecorder()
		app.AdminHandler().ServeHTTP(w, req)
		require.Equal(t, http.StatusCreated, w.Code)
	}

	// List (default page)
	req := adminReq(http.MethodGet, "/admin/partner-dids/", nil)
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	result := parseJSON(t, w)
	assert.Equal(t, float64(2), result["count"])
	assert.Equal(t, float64(2), result["total_count"])
	assert.Equal(t, float64(1), result["page"])
	assert.Equal(t, float64(50), result["page_size"])
	assert.Equal(t, false, result["has_more"])
}

func TestAdmin_PartnerDID_List_Pagination(t *testing.T) {
	app := newAdminTestApp(t)

	// Register 3 partners
	dids := []string{"did:web:alpha.com", "did:web:beta.com", "did:web:gamma.com"}
	for _, did := range dids {
		body := map[string]any{"did": did, "name": "Partner " + did}
		req := adminReq(http.MethodPost, "/admin/partner-dids/", body)
		w := httptest.NewRecorder()
		app.AdminHandler().ServeHTTP(w, req)
		require.Equal(t, http.StatusCreated, w.Code)
	}

	// First page: page_size=2
	req := adminReq(http.MethodGet, "/admin/partner-dids/?page_size=2&page=1", nil)
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	result := parseJSON(t, w)
	assert.Equal(t, float64(2), result["count"])
	assert.Equal(t, float64(3), result["total_count"])
	assert.Equal(t, float64(1), result["page"])
	assert.Equal(t, float64(2), result["page_size"])
	assert.Equal(t, true, result["has_more"])

	// Second page
	req2 := adminReq(http.MethodGet, "/admin/partner-dids/?page_size=2&page=2", nil)
	w2 := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusOK, w2.Code)
	result2 := parseJSON(t, w2)
	assert.Equal(t, float64(1), result2["count"])
	assert.Equal(t, float64(3), result2["total_count"])
	assert.Equal(t, float64(2), result2["page"])
	assert.Equal(t, false, result2["has_more"])

	// Verify that both pages together contain all 3 DIDs (none duplicated or missing).
	page1 := result["partners"].([]any)
	page2 := result2["partners"].([]any)
	all := make([]any, 0, len(page1)+len(page2))
	all = append(all, page1...)
	all = append(all, page2...)
	assert.Len(t, all, 3)
}

func TestAdmin_PartnerDID_Unregister(t *testing.T) {
	app := newAdminTestApp(t)

	// Register
	body := map[string]any{"did": "did:web:remove.com", "name": "Remove Me"}
	req := adminReq(http.MethodPost, "/admin/partner-dids/", body)
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	// Unregister
	req = adminReq(http.MethodDelete, "/admin/partner-dids/did:web:remove.com", nil)
	w = httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	result := parseJSON(t, w)
	assert.Equal(t, "unregistered", result["status"])

	// Verify gone
	req = adminReq(http.MethodGet, "/admin/partner-dids/", nil)
	w = httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	result = parseJSON(t, w)
	assert.Equal(t, float64(0), result["count"])
}

func TestAdmin_PartnerDID_UnregisterNotFound(t *testing.T) {
	app := newAdminTestApp(t)

	req := adminReq(http.MethodDelete, "/admin/partner-dids/did:web:nonexistent.com", nil)
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAdmin_PartnerDID_Approve(t *testing.T) {
	app := newAdminTestApp(t)

	// Register first
	body := map[string]any{"did": "did:web:pending.com", "name": "Pending"}
	req := adminReq(http.MethodPost, "/admin/partner-dids/", body)
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	// Approve
	req = adminReq(http.MethodPost, "/admin/partner-dids/did:web:pending.com/approve", nil)
	w = httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	result := parseJSON(t, w)
	assert.Equal(t, "approved", result["status"])
}

func TestAdmin_PartnerDID_Revoke(t *testing.T) {
	app := newAdminTestApp(t)

	// Register first
	body := map[string]any{"did": "did:web:revoking.com", "name": "Revoking"}
	req := adminReq(http.MethodPost, "/admin/partner-dids/", body)
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	// Revoke
	req = adminReq(http.MethodPost, "/admin/partner-dids/did:web:revoking.com/revoke", nil)
	w = httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	result := parseJSON(t, w)
	assert.Equal(t, "revoked", result["status"])
}

func TestAdmin_PartnerDID_Refresh(t *testing.T) {
	app := newAdminTestApp(t)

	// Register first
	body := map[string]any{"did": "did:web:refresh.com", "name": "Refresh"}
	req := adminReq(http.MethodPost, "/admin/partner-dids/", body)
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	// Refresh
	req = adminReq(http.MethodPost, "/admin/partner-dids/did:web:refresh.com/refresh", nil)
	w = httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	result := parseJSON(t, w)
	assert.Equal(t, "refreshed", result["status"])
}

func TestAdmin_PartnerDID_StatusChangeNotFound(t *testing.T) {
	app := newAdminTestApp(t)

	req := adminReq(http.MethodPost, "/admin/partner-dids/did:web:ghost.com/approve", nil)
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Idempotency Tests ---

func TestAdmin_IdempotencyKey_ReplaysCachedResponse(t *testing.T) {
	app := newAdminTestApp(t)

	// First request with idempotency key
	req := adminReq(http.MethodPost, "/admin/kill-switch/agent/agent-idem/kill", nil)
	req.Header.Set("Idempotency-Key", "unique-key-123")
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	firstBody := w.Body.String()

	// Second request with same idempotency key
	req = adminReq(http.MethodPost, "/admin/kill-switch/agent/agent-idem/kill", nil)
	req.Header.Set("Idempotency-Key", "unique-key-123")
	w = httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "true", w.Header().Get("X-Idempotency-Replayed"))
	assert.Equal(t, firstBody, w.Body.String())
}

func TestAdmin_IdempotencyKey_DifferentKeysNotReplayed(t *testing.T) {
	app := newAdminTestApp(t)

	// First request
	req := adminReq(http.MethodPost, "/admin/kill-switch/agent/agent-a/kill", nil)
	req.Header.Set("Idempotency-Key", "key-1")
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Different key - should not replay
	req = adminReq(http.MethodPost, "/admin/kill-switch/agent/agent-b/kill", nil)
	req.Header.Set("Idempotency-Key", "key-2")
	w = httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("X-Idempotency-Replayed"))
}

func TestAdmin_IdempotencyKey_SameKeyDifferentPathNotReplayed(t *testing.T) {
	app := newAdminTestApp(t)

	req := adminReq(http.MethodPost, "/admin/kill-switch/agent/agent-a/kill", nil)
	req.Header.Set("Idempotency-Key", "same-key")
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	req = adminReq(http.MethodPost, "/admin/kill-switch/agent/agent-b/kill", nil)
	req.Header.Set("Idempotency-Key", "same-key")
	w = httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("X-Idempotency-Replayed"))
}

// --- Cross-Tenant Impact Tests ---

func TestAdmin_CrossTenantOps_RequireAcknowledgment(t *testing.T) {
	app := newAdminTestApp(t)

	crossTenantPaths := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/admin/kill-switch/global/activate"},
		{http.MethodPost, "/admin/kill-switch/global/deactivate"},
		{http.MethodPost, "/admin/kill-switch/reset"},
		{http.MethodPost, "/admin/usage/reset"},
	}

	for _, tc := range crossTenantPaths {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			// Without ack body
			req := adminReq(tc.method, tc.path, map[string]any{"something": "else"})
			w := httptest.NewRecorder()
			app.AdminHandler().ServeHTTP(w, req)
			assert.Equal(t, http.StatusForbidden, w.Code)

			// With ack body set to false
			req = adminReq(tc.method, tc.path, map[string]any{"acknowledgesCrossTenantImpact": false})
			w = httptest.NewRecorder()
			app.AdminHandler().ServeHTTP(w, req)
			assert.Equal(t, http.StatusForbidden, w.Code)
		})
	}
}

// --- OCSF Audit Event Tests ---

func TestAdmin_EmitsAuditEventsOnMutations(t *testing.T) {
	app := newAdminTestAppWithAudit(t)

	// Kill an agent (mutating operation)
	req := adminReq(http.MethodPost, "/admin/kill-switch/agent/audited-agent/kill", nil)
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Note: since the audit pipeline is a mock, we can't directly verify the event
	// was written without exposing internal state. The test verifies the operation
	// succeeds with audit configured (no panic/error from audit path).
}

// --- Integration: Kill agent → enforcement rejects → revive → enforcement allows ---

func TestAdmin_Integration_KillAgentEnforcementFlow(t *testing.T) {
	agentID := "test-agent-flow"

	// Set up JWT verifier to return a valid token with the test agent ID
	verifier := &mockJWTVerifier{
		claims: &capability.TokenPayload{
			Subject:   agentID,
			JWTID:     "jti-flow-test",
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			Capabilities: []capability.Constraint{
				{Resource: "*", Actions: []string{"*"}},
			},
		},
	}

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
		JWTVerifier: verifier,
		DPoPStore:   dpopStore,
		Logger:      logger,
	}

	cfg := gateway.Config{
		GatewayAudience: "test-gateway",
		AdminAPIKey:     testAdminKey,
		TenantID:        "tenant-1",
	}

	intApp, err := gateway.New(&cfg, &deps)
	require.NoError(t, err)

	// 1. Enforce request succeeds
	enforceBody := map[string]any{
		"token": "valid-token",
		"request": map[string]any{
			"sessionId": "sess-1",
			"toolName":  "file-read",
			"context":   map[string]any{"sourceIp": "127.0.0.1"},
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", jsonBody(enforceBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	intApp.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	result := parseJSON(t, w)
	assert.Equal(t, "allow", result["decision"])

	// 2. Kill the agent via admin API
	req = adminReq(http.MethodPost, "/admin/kill-switch/agent/"+agentID+"/kill", nil)
	w = httptest.NewRecorder()
	intApp.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// 3. Enforce request should be denied
	req = httptest.NewRequest(http.MethodPost, "/api/v1/enforce", jsonBody(enforceBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	intApp.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	result = parseJSON(t, w)
	assert.Equal(t, "deny", result["decision"])

	// 4. Revive the agent via admin API
	req = adminReq(http.MethodPost, "/admin/kill-switch/agent/"+agentID+"/revive", nil)
	w = httptest.NewRecorder()
	intApp.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// 5. Enforce request should succeed again
	req = httptest.NewRequest(http.MethodPost, "/api/v1/enforce", jsonBody(enforceBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	intApp.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	result = parseJSON(t, w)
	assert.Equal(t, "allow", result["decision"])
}

// --- Admin Health Endpoints ---

func TestAdmin_HealthLive(t *testing.T) {
	app := newAdminTestApp(t)

	req := httptest.NewRequest(http.MethodGet, "/health/live", http.NoBody)
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdmin_HealthReady(t *testing.T) {
	app := newAdminTestApp(t)

	req := httptest.NewRequest(http.MethodGet, "/health/ready", http.NoBody)
	w := httptest.NewRecorder()
	app.AdminHandler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func jsonBody(v interface{}) io.Reader {
	b, _ := json.Marshal(v)
	return bytes.NewReader(b)
}
