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
	"github.com/edgeobs/eunox/pkg/callcounter"
	"github.com/edgeobs/eunox/pkg/capability"
	"github.com/edgeobs/eunox/pkg/enforcement"
	"github.com/edgeobs/eunox/pkg/killswitch"
	"github.com/edgeobs/eunox/pkg/revocation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockJWTVerifier is a test JWT verifier that returns preconfigured claims.
type mockJWTVerifier struct {
	claims *capability.TokenPayload
	err    error
}

func (m *mockJWTVerifier) VerifyToken(_ context.Context, _ string) (*capability.TokenPayload, error) {
	return m.claims, m.err
}

func newTestApp(t *testing.T, verifier gateway.JWTVerifier) (app *gateway.App, ks *killswitch.InMemory, revStore *revocation.InMemory) {
	t.Helper()

	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ks = killswitch.NewInMemory()
	revStore = revocation.NewInMemory()
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
		AllowedOrigins:  []string{"http://localhost:3000"},
	}

	var err error
	app, err = gateway.New(&cfg, &deps)
	require.NoError(t, err)
	return app, ks, revStore
}

func TestHealthLive(t *testing.T) {
	verifier := &mockJWTVerifier{}
	app, _, _ := newTestApp(t, verifier)

	req := httptest.NewRequest(http.MethodGet, "/health/live", http.NoBody)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "ok")
}

func TestHealthReady(t *testing.T) {
	verifier := &mockJWTVerifier{}
	app, _, _ := newTestApp(t, verifier)

	req := httptest.NewRequest(http.MethodGet, "/health/ready", http.NoBody)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "ready")
}

func TestHealthReady_NotReady(t *testing.T) {
	t.Parallel()

	verifier := &mockJWTVerifier{}
	// Build app with IsReady returning false (simulates drain delay).
	ready := false
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
		AllowedOrigins:  []string{"http://localhost:3000"},
		IsReady:         func() bool { return ready },
	}
	app, err := gateway.New(&cfg, &deps)
	require.NoError(t, err)

	// Not ready yet.
	req := httptest.NewRequest(http.MethodGet, "/health/ready", http.NoBody)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "not_ready")

	// Now simulate ready state.
	ready = true
	req2 := httptest.NewRequest(http.MethodGet, "/health/ready", http.NoBody)
	w2 := httptest.NewRecorder()
	app.Handler().ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)
	assert.Contains(t, w2.Body.String(), "ready")
}

func TestEnforce_MissingToken(t *testing.T) {
	verifier := &mockJWTVerifier{}
	app, _, _ := newTestApp(t, verifier)

	body := `{"request":{"sessionId":"s1","toolName":"tool"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestEnforce_InvalidToken(t *testing.T) {
	verifier := &mockJWTVerifier{err: assert.AnError}
	app, _, _ := newTestApp(t, verifier)

	payload := map[string]interface{}{
		"token": "invalid-token",
		"request": map[string]interface{}{
			"sessionId": "sess-1",
			"toolName":  "tool",
		},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp capability.EnforceResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeAuthorizationFailed, resp.Denial.Code)
}

func TestEnforce_Allow(t *testing.T) {
	claims := &capability.TokenPayload{
		Subject:   "agent-1",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		JWTID:     "jti-1",
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	}
	verifier := &mockJWTVerifier{claims: claims}
	app, _, _ := newTestApp(t, verifier)

	payload := map[string]interface{}{
		"token": "valid-token",
		"request": map[string]interface{}{
			"sessionId": "sess-1",
			"toolName":  "tool",
		},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp capability.EnforceResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
}

func TestEnforce_DenyKillSwitch(t *testing.T) {
	claims := &capability.TokenPayload{
		Subject:   "agent-1",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		JWTID:     "jti-1",
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	}
	verifier := &mockJWTVerifier{claims: claims}
	app, ks, _ := newTestApp(t, verifier)

	// Kill agent-1
	require.NoError(t, ks.KillAgent(context.Background(), "agent-1"))

	payload := map[string]interface{}{
		"token": "valid-token",
		"request": map[string]interface{}{
			"sessionId": "sess-1",
			"toolName":  "tool",
		},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp capability.EnforceResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeKillSwitch, resp.Denial.Code)
}

func TestEnforce_DenyRevoked(t *testing.T) {
	claims := &capability.TokenPayload{
		Subject:   "agent-1",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		JWTID:     "jti-revoked",
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	}
	verifier := &mockJWTVerifier{claims: claims}
	app, _, revStore := newTestApp(t, verifier)

	// Revoke the token
	require.NoError(t, revStore.Revoke(context.Background(), "jti-revoked", 0))

	payload := map[string]interface{}{
		"token": "valid-token",
		"request": map[string]interface{}{
			"sessionId": "sess-1",
			"toolName":  "tool",
		},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp capability.EnforceResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeRevoked, resp.Denial.Code)
}

func TestEnforce_DenyExpired(t *testing.T) {
	claims := &capability.TokenPayload{
		Subject:   "agent-1",
		ExpiresAt: time.Now().Add(-time.Hour).Unix(), // Expired
		JWTID:     "jti-1",
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	}
	verifier := &mockJWTVerifier{claims: claims}
	app, _, _ := newTestApp(t, verifier)

	payload := map[string]interface{}{
		"token": "expired-token",
		"request": map[string]interface{}{
			"sessionId": "sess-1",
			"toolName":  "tool",
		},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp capability.EnforceResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeExpired, resp.Denial.Code)
}

func TestEnforce_DenyCondition(t *testing.T) {
	claims := &capability.TokenPayload{
		Subject:   "agent-1",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		JWTID:     "jti-1",
		Capabilities: []capability.Constraint{
			{
				Resource: "tool",
				Actions:  []string{"*"},
				Conditions: []capability.Condition{
					&capability.IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}},
				},
			},
		},
	}
	verifier := &mockJWTVerifier{claims: claims}
	app, _, _ := newTestApp(t, verifier)

	payload := map[string]interface{}{
		"token": "valid-token",
		"request": map[string]interface{}{
			"sessionId": "sess-1",
			"toolName":  "tool",
			"context": map[string]interface{}{
				"sourceIp": "192.168.1.1",
			},
		},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp capability.EnforceResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ConditionTypeIPRange, resp.Denial.ConditionType)
}

func TestEnforce_DPoP_ReplayDetection(t *testing.T) {
	claims := &capability.TokenPayload{
		Subject:   "agent-1",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		JWTID:     "jti-1",
		// No Confirmation/JKT — replay detection test does not require DPoP binding
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	}
	verifier := &mockJWTVerifier{claims: claims}
	app, _, _ := newTestApp(t, verifier)

	payload := map[string]interface{}{
		"token": "valid-token",
		"request": map[string]interface{}{
			"sessionId": "sess-1",
			"toolName":  "tool",
		},
		"dpop": map[string]interface{}{
			"proof":      "unique-proof-1",
			"httpMethod": "POST",
			"httpUrl":    "https://gateway.example.com/api/v1/enforce",
		},
	}
	body, _ := json.Marshal(payload)

	// First request should succeed
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp1 capability.EnforceResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp1))
	assert.Equal(t, capability.DecisionAllow, resp1.Decision)

	// Replay the same request — should be denied
	body, _ = json.Marshal(payload)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/enforce", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp2 capability.EnforceResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp2))
	assert.Equal(t, capability.DecisionDeny, resp2.Decision)
}

func TestEnforce_DPoP_JKT_VerifiesBinding(t *testing.T) {
	// When a token carries a DPoP confirmation JKT, full DPoP proof verification
	// is performed (RFC 9449). An invalid proof JWT is rejected.
	claims := &capability.TokenPayload{
		Subject:      "agent-1",
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
		Confirmation: &capability.Confirmation{JKT: "some-thumbprint"},
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	}
	verifier := &mockJWTVerifier{claims: claims}
	app, _, _ := newTestApp(t, verifier)

	payload := map[string]interface{}{
		"token": "valid-token",
		"request": map[string]interface{}{
			"sessionId": "sess-1",
			"toolName":  "tool",
		},
		"dpop": map[string]interface{}{
			"proof":      "invalid-proof-not-a-jwt",
			"httpMethod": "POST",
			"httpUrl":    "https://gateway.example.com/api/v1/enforce",
		},
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp capability.EnforceResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	require.NotNil(t, resp.Denial)
	assert.Contains(t, resp.Denial.Message, "DPoP")
}

func TestValidate_AllowMatchingCapability(t *testing.T) {
	claims := &capability.TokenPayload{
		Subject:   "agent-1",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{Resource: "file:read", Actions: []string{"read"}},
			{Resource: "email:send", Actions: []string{"send"}},
		},
	}
	verifier := &mockJWTVerifier{claims: claims}
	app, _, _ := newTestApp(t, verifier)

	payload := map[string]interface{}{
		"token":    "valid-token",
		"action":   "read",
		"resource": "file:read",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp capability.ValidateActionResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Allowed)
	assert.NotNil(t, resp.MatchedCapability)
}

func TestValidate_DenyNoMatch(t *testing.T) {
	claims := &capability.TokenPayload{
		Subject:   "agent-1",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{Resource: "file:read", Actions: []string{"read"}},
		},
	}
	verifier := &mockJWTVerifier{claims: claims}
	app, _, _ := newTestApp(t, verifier)

	payload := map[string]interface{}{
		"token":    "valid-token",
		"action":   "delete",
		"resource": "database",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp capability.ValidateActionResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Allowed)
}

// TestValidate_GlobMatchingCapability verifies that /validate uses the same
// glob-aware matching semantics as /enforce.  A wildcard resource pattern
// (e.g. "tools/*") that would be matched by the enforcement engine must also
// be matched by /validate — the old linear first-match scan with exact
// equality only handled "*", not real glob patterns.
func TestValidate_GlobMatchingCapability(t *testing.T) {
	claims := &capability.TokenPayload{
		Subject:   "agent-1",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{Resource: "tools/*", Actions: []string{"call"}},
		},
	}
	verifier := &mockJWTVerifier{claims: claims}
	app, _, _ := newTestApp(t, verifier)

	payload := map[string]interface{}{
		"token":    "valid-token",
		"action":   "call",
		"resource": "tools/calculator",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp capability.ValidateActionResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Allowed, "glob pattern 'tools/*' should match 'tools/calculator'")
	assert.NotNil(t, resp.MatchedCapability)
}

func newTestAppWithBackend(t *testing.T, verifier gateway.JWTVerifier, backendURL string) (*gateway.App, *killswitch.InMemory) {
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
		JWTVerifier: verifier,
		DPoPStore:   dpopStore,
		Logger:      logger,
	}

	cfg := gateway.Config{
		BackendURL:      backendURL,
		GatewayAudience: "test-gateway",
		AllowedOrigins:  []string{"http://localhost:3000"},
	}

	app, err := gateway.New(&cfg, &deps)
	require.NoError(t, err)
	return app, ks
}

func TestProxy_MissingAuth(t *testing.T) {
	// Need a backend so we don't short-circuit with 502
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	verifier := &mockJWTVerifier{}
	app, _ := newTestAppWithBackend(t, verifier, backend.URL)

	req := httptest.NewRequest(http.MethodGet, "/proxy/some/path", http.NoBody)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestProxy_InvalidToken(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	verifier := &mockJWTVerifier{err: assert.AnError}
	app, _ := newTestAppWithBackend(t, verifier, backend.URL)

	req := httptest.NewRequest(http.MethodGet, "/proxy/some/path", http.NoBody)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestProxy_KillSwitchBlocks(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	claims := &capability.TokenPayload{
		Subject:   "agent-1",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		JWTID:     "jti-1",
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	}
	verifier := &mockJWTVerifier{claims: claims}
	app, ks := newTestAppWithBackend(t, verifier, backend.URL)

	require.NoError(t, ks.ActivateGlobal(context.Background()))

	req := httptest.NewRequest(http.MethodGet, "/proxy/some/path", http.NoBody)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestProxy_NoBackend(t *testing.T) {
	claims := &capability.TokenPayload{
		Subject:   "agent-1",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		JWTID:     "jti-1",
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	}
	verifier := &mockJWTVerifier{claims: claims}
	app, _, _ := newTestApp(t, verifier)

	req := httptest.NewRequest(http.MethodGet, "/proxy/some/path", http.NoBody)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadGateway, w.Code)
}

func TestProxy_SuccessWithBackend(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"response":"from backend"}`))
	}))
	defer backend.Close()

	claims := &capability.TokenPayload{
		Subject:   "agent-1",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		JWTID:     "jti-1",
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	}
	verifier := &mockJWTVerifier{claims: claims}
	app, _ := newTestAppWithBackend(t, verifier, backend.URL)

	req := httptest.NewRequest(http.MethodGet, "/proxy/some/path", http.NoBody)
	req.Header.Set("Authorization", "Bearer valid-token")
	req.Header.Set("X-Tool-Name", "some-tool")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "from backend")
}

func TestCORS_AllowedOrigin(t *testing.T) {
	verifier := &mockJWTVerifier{}
	app, _, _ := newTestApp(t, verifier)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/enforce", http.NoBody)
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "http://localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_DisallowedOrigin(t *testing.T) {
	verifier := &mockJWTVerifier{}
	app, _, _ := newTestApp(t, verifier)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/enforce", http.NoBody)
	req.Header.Set("Origin", "http://evil.com")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	// No CORS header set
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_WildcardProductionError(t *testing.T) {
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ks := killswitch.NewInMemory()
	revStore := revocation.NewInMemory()
	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)

	deps := gateway.Dependencies{
		Engine:      engine,
		KillSwitch:  ks,
		Revocation:  revStore,
		JWTVerifier: &mockJWTVerifier{},
		DPoPStore:   dpopStore,
	}

	cfg := gateway.Config{
		GatewayAudience: "test-gateway",
		AllowedOrigins:  []string{"*"},
		Environment:     "production",
	}

	_, err := gateway.New(&cfg, &deps)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CORS wildcard")
}

func TestCORS_WildcardNoErrorInDevelopment(t *testing.T) {
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ks := killswitch.NewInMemory()
	revStore := revocation.NewInMemory()
	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)

	deps := gateway.Dependencies{
		Engine:      engine,
		KillSwitch:  ks,
		Revocation:  revStore,
		JWTVerifier: &mockJWTVerifier{},
		DPoPStore:   dpopStore,
	}

	cfg := gateway.Config{
		GatewayAudience: "test-gateway",
		AllowedOrigins:  []string{"*"},
		Environment:     "development",
	}

	_, err := gateway.New(&cfg, &deps)
	require.NoError(t, err)
}

// TestCORS_ProductionExplicitOrigins_NoError verifies that explicit CORS origins
// in production do not cause New() to return an error (Finding 4).
func TestCORS_ProductionExplicitOrigins_NoError(t *testing.T) {
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ks := killswitch.NewInMemory()
	revStore := revocation.NewInMemory()
	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)

	deps := gateway.Dependencies{
		Engine:      engine,
		KillSwitch:  ks,
		Revocation:  revStore,
		JWTVerifier: &mockJWTVerifier{},
		DPoPStore:   dpopStore,
	}

	cfg := gateway.Config{
		GatewayAudience: "test-gateway",
		AllowedOrigins:  []string{"https://app.example.com", "https://admin.example.com"},
		Environment:     "production",
	}

	_, err := gateway.New(&cfg, &deps)
	assert.NoError(t, err, "production with explicit origins must not error")
}

// TestCORS_ProductionNoOrigins_NoError verifies that an empty AllowedOrigins
// list in production does not cause New() to return an error (Finding 4).
func TestCORS_ProductionNoOrigins_NoError(t *testing.T) {
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ks := killswitch.NewInMemory()
	revStore := revocation.NewInMemory()
	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)

	deps := gateway.Dependencies{
		Engine:      engine,
		KillSwitch:  ks,
		Revocation:  revStore,
		JWTVerifier: &mockJWTVerifier{},
		DPoPStore:   dpopStore,
	}

	cfg := gateway.Config{
		GatewayAudience: "test-gateway",
		AllowedOrigins:  nil,
		Environment:     "production",
	}

	_, err := gateway.New(&cfg, &deps)
	assert.NoError(t, err, "production with no AllowedOrigins must not error")
}

func TestEnforce_GlobalKillSwitch(t *testing.T) {
	claims := &capability.TokenPayload{
		Subject:   "agent-1",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		JWTID:     "jti-1",
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	}
	verifier := &mockJWTVerifier{claims: claims}
	app, ks, _ := newTestApp(t, verifier)

	// Activate global kill switch
	require.NoError(t, ks.ActivateGlobal(context.Background()))

	payload := map[string]interface{}{
		"token": "valid-token",
		"request": map[string]interface{}{
			"sessionId": "sess-1",
			"toolName":  "tool",
		},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	var resp capability.EnforceResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, capability.DecisionDeny, resp.Decision)
	assert.Equal(t, capability.ErrCodeKillSwitch, resp.Denial.Code)
}

func TestEnforce_RedactFieldsObligation(t *testing.T) {
	claims := &capability.TokenPayload{
		Subject:   "agent-1",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		JWTID:     "jti-1",
		Capabilities: []capability.Constraint{
			{
				Resource: "tool",
				Actions:  []string{"*"},
				Conditions: []capability.Condition{
					&capability.RedactFieldsCondition{Fields: []string{"$.ssn", "$.password"}},
				},
			},
		},
	}
	verifier := &mockJWTVerifier{claims: claims}
	app, _, _ := newTestApp(t, verifier)

	payload := map[string]interface{}{
		"token": "valid-token",
		"request": map[string]interface{}{
			"sessionId": "sess-1",
			"toolName":  "tool",
		},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	var resp capability.EnforceResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, capability.DecisionAllow, resp.Decision)
	require.Len(t, resp.Obligations, 1)
	assert.Equal(t, "redactFields", resp.Obligations[0].Type)
	assert.Equal(t, []string{"$.ssn", "$.password"}, resp.Obligations[0].Paths)
}

// --- CI-1: Revocation and kill-switch checks in /validate ---

// errRevocationStore is a revocation.Store whose IsRevoked always returns an
// error, used to verify fail-closed behaviour in handleValidate.
type errRevocationStore struct{}

func (errRevocationStore) IsRevoked(_ context.Context, _ string) (bool, error) {
	return false, assert.AnError
}
func (errRevocationStore) Revoke(_ context.Context, _ string, _ time.Duration) error { return nil }
func (errRevocationStore) Unrevoke(_ context.Context, _ string) error                { return nil }

// errKillSwitchManager is a killswitch.Manager whose ShouldBlock always returns
// an error, used to verify fail-closed behaviour in handleValidate.
type errKillSwitchManager struct{ *killswitch.InMemory }

func (errKillSwitchManager) ShouldBlock(_ context.Context, _, _ string) (bool, error) {
	return false, assert.AnError
}

func newTestAppWithStores(
	t *testing.T,
	verifier gateway.JWTVerifier,
	ks killswitch.Manager,
	rev revocation.Store,
) *gateway.App {
	t.Helper()
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	deps := gateway.Dependencies{
		Engine:      engine,
		KillSwitch:  ks,
		Revocation:  rev,
		JWTVerifier: verifier,
		DPoPStore:   dpopStore,
		Logger:      logger,
	}
	cfg := gateway.Config{
		GatewayAudience: "test-gateway",
		AllowedOrigins:  []string{"http://localhost:3000"},
	}
	app, err := gateway.New(&cfg, &deps)
	require.NoError(t, err)
	return app
}

// TestValidate_RevokedToken verifies that /validate returns allowed=false when
// the token's JTI has been revoked in the revocation store.
func TestValidate_RevokedToken(t *testing.T) {
	claims := &capability.TokenPayload{
		JWTID:     "jti-revoked-validate",
		Subject:   "agent-1",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{Resource: "tools/*", Actions: []string{"call"}},
		},
	}
	verifier := &mockJWTVerifier{claims: claims}
	revStore := revocation.NewInMemory()
	ks := killswitch.NewInMemory()

	require.NoError(t, revStore.Revoke(context.Background(), "jti-revoked-validate", 0))
	app := newTestAppWithStores(t, verifier, ks, revStore)

	payload := map[string]interface{}{
		"token":    "valid-token",
		"action":   "call",
		"resource": "tools/calculator",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp capability.ValidateActionResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Allowed, "revoked token must be denied by /validate")
	assert.Equal(t, "token has been revoked", resp.Reason)
}

// TestValidate_KillSwitchBlocked verifies that /validate returns allowed=false
// when the token's subject has been blocked by the kill-switch.
func TestValidate_KillSwitchBlocked(t *testing.T) {
	claims := &capability.TokenPayload{
		JWTID:     "jti-ks",
		Subject:   "agent-blocked",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{Resource: "tools/*", Actions: []string{"call"}},
		},
	}
	verifier := &mockJWTVerifier{claims: claims}
	revStore := revocation.NewInMemory()
	ks := killswitch.NewInMemory()

	require.NoError(t, ks.KillAgent(context.Background(), "agent-blocked"))
	app := newTestAppWithStores(t, verifier, ks, revStore)

	payload := map[string]interface{}{
		"token":    "valid-token",
		"action":   "call",
		"resource": "tools/calculator",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp capability.ValidateActionResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Allowed, "kill-switch blocked subject must be denied by /validate")
	assert.Equal(t, "kill switch is active", resp.Reason)
}

// TestValidate_RevocationError verifies that /validate fails closed (503) when
// the revocation store returns an error.
func TestValidate_RevocationError(t *testing.T) {
	claims := &capability.TokenPayload{
		JWTID:     "jti-revoc-err",
		Subject:   "agent-1",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{Resource: "tools/*", Actions: []string{"call"}},
		},
	}
	verifier := &mockJWTVerifier{claims: claims}
	app := newTestAppWithStores(t, verifier, killswitch.NewInMemory(), errRevocationStore{})

	payload := map[string]interface{}{
		"token":    "valid-token",
		"action":   "call",
		"resource": "tools/calculator",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code, "/validate must fail closed on revocation store error")
}

// TestValidate_KillSwitchError verifies that /validate fails closed (503) when
// the kill-switch returns an error.
func TestValidate_KillSwitchError(t *testing.T) {
	claims := &capability.TokenPayload{
		JWTID:     "jti-ks-err",
		Subject:   "agent-1",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{Resource: "tools/*", Actions: []string{"call"}},
		},
	}
	verifier := &mockJWTVerifier{claims: claims}
	app := newTestAppWithStores(t, verifier, errKillSwitchManager{killswitch.NewInMemory()}, revocation.NewInMemory())

	payload := map[string]interface{}{
		"token":    "valid-token",
		"action":   "call",
		"resource": "tools/calculator",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code, "/validate must fail closed on kill-switch error")
}
