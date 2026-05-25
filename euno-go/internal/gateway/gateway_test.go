// Copyright 2024-2025 Euno Platform Authors
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

	"github.com/edgeobs/euno-platform/euno-go/internal/gateway"
	"github.com/edgeobs/euno-platform/euno-go/pkg/callcounter"
	"github.com/edgeobs/euno-platform/euno-go/pkg/capability"
	"github.com/edgeobs/euno-platform/euno-go/pkg/enforcement"
	"github.com/edgeobs/euno-platform/euno-go/pkg/killswitch"
	"github.com/edgeobs/euno-platform/euno-go/pkg/revocation"
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

func newTestApp(t *testing.T, verifier gateway.JWTVerifier) (*gateway.App, *killswitch.InMemory, *revocation.InMemory) {
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
		GatewayAudience: "test-gateway",
		AllowedOrigins:  []string{"http://localhost:3000"},
	}

	app := gateway.New(cfg, deps)
	return app, ks, revStore
}

func TestHealthLive(t *testing.T) {
	verifier := &mockJWTVerifier{}
	app, _, _ := newTestApp(t, verifier)

	req := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "ok")
}

func TestHealthReady(t *testing.T) {
	verifier := &mockJWTVerifier{}
	app, _, _ := newTestApp(t, verifier)

	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "ready")
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
		Subject:      "agent-1",
		ExpiresAt:    time.Now().Add(time.Hour).Unix(),
		JWTID:        "jti-1",
		Confirmation: &capability.Confirmation{JKT: "thumbprint"},
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

	app := gateway.New(cfg, deps)
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

	req := httptest.NewRequest(http.MethodGet, "/proxy/some/path", nil)
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

	req := httptest.NewRequest(http.MethodGet, "/proxy/some/path", nil)
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

	req := httptest.NewRequest(http.MethodGet, "/proxy/some/path", nil)
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

	req := httptest.NewRequest(http.MethodGet, "/proxy/some/path", nil)
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

	req := httptest.NewRequest(http.MethodGet, "/proxy/some/path", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "from backend")
}

func TestCORS_AllowedOrigin(t *testing.T) {
	verifier := &mockJWTVerifier{}
	app, _, _ := newTestApp(t, verifier)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/enforce", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "http://localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_DisallowedOrigin(t *testing.T) {
	verifier := &mockJWTVerifier{}
	app, _, _ := newTestApp(t, verifier)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/enforce", nil)
	req.Header.Set("Origin", "http://evil.com")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)

	// No CORS header set
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
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
