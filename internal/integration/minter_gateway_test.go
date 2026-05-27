// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package integration provides cross-service integration tests.
package integration

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
	"github.com/edgeobs/eunox/internal/minter"
	"github.com/edgeobs/eunox/pkg/callcounter"
	"github.com/edgeobs/eunox/pkg/capability"
	"github.com/edgeobs/eunox/pkg/enforcement"
	"github.com/edgeobs/eunox/pkg/killswitch"
	"github.com/edgeobs/eunox/pkg/revocation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test-only constants. These values are for integration testing only and must
// never be used in production environments.
const (
	testPepperHex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	testAdminKey  = "integration-test-admin-key-32chr!"
	testMinterKey = "minter-admin-key-for-integration"
)

// keyBasedJWTVerifier simulates a JWT verifier that accepts API keys minted by the minter.
// In a real system, the API key would be exchanged for a JWT via the issuer, but for
// this integration test we simulate the flow by mapping the key hash to claims.
type keyBasedJWTVerifier struct {
	pepper *minter.Pepper
	store  minter.KeyStore
}

func (v *keyBasedJWTVerifier) VerifyToken(ctx context.Context, tokenStr string) (*capability.TokenPayload, error) {
	// In this integration test, the "token" is the full API key (sk-{id}.{secret}).
	// We validate it against the minter's key store.
	keyID, secret, err := minter.ParseKey(tokenStr)
	if err != nil {
		return nil, err
	}

	key, err := v.store.GetKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	if key.IsRevoked() {
		return nil, minter.ErrKeyRevoked
	}
	if key.IsExpired(time.Now()) {
		return nil, minter.ErrKeyExpired
	}

	if !v.pepper.VerifySecret(secret, key.SecretHash) {
		return nil, minter.ErrInvalidKey
	}

	return &capability.TokenPayload{
		Subject:   key.TenantID,
		JWTID:     key.KeyID,
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	}, nil
}

// TestIntegration_MinterToGateway_KeyBasedAuthFlow tests the full flow:
// 1. Minter creates an API key
// 2. Key is used to authenticate against gateway enforcement
// 3. Key is revoked via minter
// 4. Revoked key is rejected by gateway
func TestIntegration_MinterToGateway_KeyBasedAuthFlow(t *testing.T) {
	// --- Setup minter ---
	pepper, err := minter.NewPepperFromHex(testPepperHex)
	require.NoError(t, err)

	keyStore := minter.NewInMemoryStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	minterAuth := &mockMinterAuth{operatorID: "test-operator"}
	minterApp := minter.New(minter.Config{
		Pepper:          pepper,
		DefaultTenantID: "tenant-integration",
	}, &minter.Dependencies{
		Store:   keyStore,
		Auth:    minterAuth,
		Anomaly: minter.NewInMemoryAnomalyDetector(minter.VelocityConfig{MaxMintsPerWindow: 100, Window: time.Minute}, logger),
		Logger:  logger,
	})

	minterSrv := httptest.NewServer(minterApp.Handler())
	defer minterSrv.Close()

	// --- Setup gateway with key-based verifier ---
	verifier := &keyBasedJWTVerifier{
		pepper: pepper,
		store:  keyStore,
	}

	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ks := killswitch.NewInMemory()
	revStore := revocation.NewInMemory()
	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)

	gwDeps := gateway.Dependencies{
		Engine:      engine,
		KillSwitch:  ks,
		Revocation:  revStore,
		JWTVerifier: verifier,
		DPoPStore:   dpopStore,
		Logger:      logger,
	}

	gwCfg := gateway.Config{
		GatewayAudience: "test-gateway",
		AdminAPIKey:     testAdminKey,
		TenantID:        "tenant-integration",
	}

	gwApp, err := gateway.New(&gwCfg, &gwDeps)
	require.NoError(t, err)

	// --- Step 1: Mint an API key ---
	mintReqBody := map[string]any{
		"description": "integration test key",
		"tenantId":    "tenant-integration",
	}
	mintBody, _ := json.Marshal(mintReqBody)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, minterSrv.URL+"/admin/v1/keys", bytes.NewReader(mintBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Api-Key", testMinterKey)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var mintResult struct {
		KeyID  string `json:"keyId"`
		Key    string `json:"key"`
		Secret string `json:"secret"`
	}
	err = json.NewDecoder(resp.Body).Decode(&mintResult)
	require.NoError(t, err)
	require.NotEmpty(t, mintResult.Key)

	t.Logf("Minted key: keyId=%s", mintResult.KeyID)

	// --- Step 2: Use key to authenticate enforce request ---
	enforcePayload := map[string]any{
		"token": mintResult.Key,
		"request": map[string]any{
			"sessionId": "sess-integration",
			"toolName":  "file-read",
			"context":   map[string]any{"sourceIp": "10.0.0.1"},
		},
	}
	enforceBody, _ := json.Marshal(enforcePayload)

	enforceReq := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", bytes.NewReader(enforceBody))
	enforceReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	gwApp.Handler().ServeHTTP(w, enforceReq)

	assert.Equal(t, http.StatusOK, w.Code)
	var enforceResp map[string]any
	err = json.Unmarshal(w.Body.Bytes(), &enforceResp)
	require.NoError(t, err)
	assert.Equal(t, "allow", enforceResp["decision"], "valid key should be allowed")

	// --- Step 3: Revoke the key via minter ---
	revokeReq, _ := http.NewRequestWithContext(context.Background(), http.MethodDelete, minterSrv.URL+"/admin/v1/keys/"+mintResult.KeyID, http.NoBody)
	revokeReq.Header.Set("X-Admin-Api-Key", testMinterKey)

	resp, err = http.DefaultClient.Do(revokeReq)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	t.Log("Key revoked via minter")

	// --- Step 4: Revoked key should be rejected by gateway ---
	enforceReq = httptest.NewRequest(http.MethodPost, "/api/v1/enforce", bytes.NewReader(enforceBody))
	enforceReq.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	gwApp.Handler().ServeHTTP(w, enforceReq)

	assert.Equal(t, http.StatusOK, w.Code)
	err = json.Unmarshal(w.Body.Bytes(), &enforceResp)
	require.NoError(t, err)
	assert.Equal(t, "deny", enforceResp["decision"], "revoked key should be denied")
}

// TestIntegration_MinterToGateway_ExpiredKeyRejected tests that expired keys are rejected.
func TestIntegration_MinterToGateway_ExpiredKeyRejected(t *testing.T) {
	pepper, err := minter.NewPepperFromHex(testPepperHex)
	require.NoError(t, err)

	keyStore := minter.NewInMemoryStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Mint a key manually with a past expiry
	mintResult, err := minter.MintKey(pepper)
	require.NoError(t, err)

	expiresAt := time.Now().Add(-1 * time.Hour) // Already expired
	key := &minter.APIKey{
		KeyID:       mintResult.KeyID,
		SecretHash:  mintResult.SecretHash,
		TenantID:    "tenant-expired",
		Description: "expired test key",
		CreatedAt:   time.Now().Add(-2 * time.Hour),
		ExpiresAt:   &expiresAt,
		CreatedBy:   "test",
	}
	err = keyStore.CreateKey(context.Background(), key)
	require.NoError(t, err)

	// Setup gateway
	verifier := &keyBasedJWTVerifier{pepper: pepper, store: keyStore}
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ks := killswitch.NewInMemory()
	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)

	gwApp, err := gateway.New(&gateway.Config{
		GatewayAudience: "test-gw",
		AdminAPIKey:     testAdminKey,
	}, &gateway.Dependencies{
		Engine:      engine,
		KillSwitch:  ks,
		Revocation:  revocation.NewInMemory(),
		JWTVerifier: verifier,
		DPoPStore:   dpopStore,
		Logger:      logger,
	})
	require.NoError(t, err)

	// Try to enforce with expired key
	enforcePayload := map[string]any{
		"token": mintResult.FullKey,
		"request": map[string]any{
			"sessionId": "sess-1",
			"toolName":  "test-tool",
			"context":   map[string]any{"sourceIp": "10.0.0.1"},
		},
	}
	body, _ := json.Marshal(enforcePayload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	gwApp.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "deny", resp["decision"])
}

// mockMinterAuth is a mock admin authenticator for the minter.
type mockMinterAuth struct {
	operatorID string
}

func (m *mockMinterAuth) Authenticate(_ context.Context, r *http.Request) (string, error) {
	apiKey := r.Header.Get("X-Admin-Api-Key")
	if apiKey == "" {
		apiKey = r.Header.Get("X-Admin-Key")
	}
	if apiKey == testMinterKey {
		return m.operatorID, nil
	}
	return "", minter.ErrUnauthorized
}
