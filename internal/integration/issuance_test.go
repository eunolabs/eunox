// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edgeobs/eunox/internal/gateway"
	"github.com/edgeobs/eunox/internal/issuer"
	"github.com/edgeobs/eunox/internal/issuer/policy"
	"github.com/edgeobs/eunox/pkg/capability"
	eunocrypto "github.com/edgeobs/eunox/pkg/crypto"
	"github.com/edgeobs/eunox/pkg/enforcement"
	"github.com/edgeobs/eunox/pkg/killswitch"
	"github.com/edgeobs/eunox/pkg/observability"
	"github.com/edgeobs/eunox/pkg/revocation"
)

// TestIssuance_FullRoundTrip tests the complete flow:
// 1. Authenticate with IdP token
// 2. Request capability token from issuer
// 3. Use capability token at gateway for enforcement
func TestIssuance_FullRoundTrip(t *testing.T) {
	ctx := context.Background()
	_ = ctx

	// --- Setup crypto ---
	signingKey, err := eunocrypto.GenerateECDSASigner("round-trip-key-1", eunocrypto.ES256)
	require.NoError(t, err)

	idKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// --- Setup issuer ---
	policyEngine := policy.New()
	policyEngine.SetPolicy(&policy.RoleCapabilityPolicy{
		Role:          "default",
		MaxTTLSeconds: 3600,
		Capabilities: []capability.Constraint{
			{Resource: "file://*", Actions: []string{"read", "write"}},
			{Resource: "db://production/*", Actions: []string{"query"}},
		},
	})

	idProvider := &testIdentityProvider{
		publicKey: &idKey.PublicKey,
		issuer:    "https://idp.test",
		audience:  "https://issuer.test",
	}

	keyStore := issuer.NewSingleKeyStore(signingKey)
	metrics := observability.NewMetricsRegistry("test", "issuance")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	issuerApp := issuer.New(
		issuer.Config{
			IssuerDID:       "did:web:issuer.test",
			IssuerURL:       "https://issuer.test",
			DefaultTokenTTL: 300,
			MaxTokenTTL:     3600,
			Audience:        "https://gateway.test",
		},
		issuer.Dependencies{
			PolicyEngine: policyEngine,
			Identity:     idProvider,
			KeyStore:     keyStore,
			Logger:       logger,
			Metrics:      metrics,
		},
	)
	issuerSrv := httptest.NewServer(issuerApp.Handler())
	defer issuerSrv.Close()

	// --- Step 1: Request token from issuer ---
	idToken := generateTestIdentityToken(t, idKey, "dev-user-1")
	issueReq := map[string]any{
		"token": idToken,
		"capabilities": []map[string]any{
			{"resource": "file://*", "actions": []string{"read"}},
		},
		"ttl": 600,
	}
	issueBody, _ := json.Marshal(issueReq)

	resp, err := http.Post(issuerSrv.URL+"/api/v1/issue", "application/json", strings.NewReader(string(issueBody)))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var issueResp issuer.IssueResponse
	err = json.NewDecoder(resp.Body).Decode(&issueResp)
	require.NoError(t, err)
	assert.NotEmpty(t, issueResp.Token)
	assert.NotEmpty(t, issueResp.TokenID)
	assert.True(t, issueResp.ExpiresAt > time.Now().Unix())

	// --- Step 2: Use token at gateway ---
	engine := enforcement.New()
	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)

	gwApp := gateway.New(
		gateway.Config{
			GatewayAudience: "https://gateway.test",
			AdminAPIKey:     testAdminKey,
		},
		gateway.Dependencies{
			Engine:      engine,
			KillSwitch:  killswitch.NewInMemory(),
			Revocation:  revocation.NewInMemory(),
			JWTVerifier: &testJWTVerifier{signingKey: signingKey},
			DPoPStore:   dpopStore,
			Logger:      logger,
			Metrics:     metrics,
		},
	)

	enforcePayload := map[string]any{
		"token": issueResp.Token,
		"request": map[string]any{
			"sessionId": "session-roundtrip",
			"toolName":  "file://*",
			"context":   map[string]any{"sourceIp": "10.0.0.1", "operation": "read"},
		},
	}
	enforceBody, _ := json.Marshal(enforcePayload)

	enforceReq := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", strings.NewReader(string(enforceBody)))
	enforceReq.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	gwApp.Handler().ServeHTTP(w, enforceReq)

	assert.Equal(t, http.StatusOK, w.Code)
	var enforceResp map[string]any
	err = json.Unmarshal(w.Body.Bytes(), &enforceResp)
	require.NoError(t, err)
	assert.Equal(t, "allow", enforceResp["decision"])

	// --- Step 3: Verify denied access for ungranted capability ---
	deniedPayload := map[string]any{
		"token": issueResp.Token,
		"request": map[string]any{
			"sessionId": "session-roundtrip",
			"toolName":  "admin-panel",
			"context":   map[string]any{"sourceIp": "10.0.0.1"},
		},
	}
	deniedBody, _ := json.Marshal(deniedPayload)
	deniedReq := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", strings.NewReader(string(deniedBody)))
	deniedReq.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	gwApp.Handler().ServeHTTP(w, deniedReq)

	assert.Equal(t, http.StatusOK, w.Code)
	err = json.Unmarshal(w.Body.Bytes(), &enforceResp)
	require.NoError(t, err)
	assert.Equal(t, "deny", enforceResp["decision"])
}

// TestIssuance_Attenuation_SubsetEnforcement verifies capability attenuation:
// issue broad token → attenuate to subset → verify attenuated token only covers subset.
func TestIssuance_Attenuation_SubsetEnforcement(t *testing.T) {
	signingKey, err := eunocrypto.GenerateECDSASigner("attenuation-key-1", eunocrypto.ES256)
	require.NoError(t, err)

	idKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	policyEngine := policy.New()
	policyEngine.SetPolicy(&policy.RoleCapabilityPolicy{
		Role:          "default",
		MaxTTLSeconds: 3600,
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	})

	idProvider := &testIdentityProvider{
		publicKey: &idKey.PublicKey,
		issuer:    "https://idp.test",
		audience:  "https://issuer.test",
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	issuerApp := issuer.New(
		issuer.Config{
			IssuerDID:       "did:web:issuer.test",
			IssuerURL:       "https://issuer.test",
			DefaultTokenTTL: 3600,
			MaxTokenTTL:     3600,
			Audience:        "https://gateway.test",
		},
		issuer.Dependencies{
			PolicyEngine: policyEngine,
			Identity:     idProvider,
			KeyStore:     issuer.NewSingleKeyStore(signingKey),
			Logger:       logger,
		},
	)
	issuerSrv := httptest.NewServer(issuerApp.Handler())
	defer issuerSrv.Close()

	// Step 1: Issue broad token
	idToken := generateTestIdentityToken(t, idKey, "attenuator-user")
	issueBody, _ := json.Marshal(map[string]any{"token": idToken})
	resp, err := http.Post(issuerSrv.URL+"/api/v1/issue", "application/json", strings.NewReader(string(issueBody)))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var broadToken issuer.IssueResponse
	err = json.NewDecoder(resp.Body).Decode(&broadToken)
	require.NoError(t, err)

	// Step 2: Attenuate to file-read only
	attBody, _ := json.Marshal(map[string]any{
		"parentToken": broadToken.Token,
		"capabilities": []map[string]any{
			{"resource": "file-read", "actions": []string{"read"}},
		},
		"ttl": 300,
	})
	resp, err = http.Post(issuerSrv.URL+"/api/v1/attenuate", "application/json", strings.NewReader(string(attBody)))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var attToken issuer.AttenuateResponse
	err = json.NewDecoder(resp.Body).Decode(&attToken)
	require.NoError(t, err)
	assert.NotEmpty(t, attToken.Token)
	assert.True(t, attToken.ExpiresAt <= broadToken.ExpiresAt)

	// Step 3: Use attenuated token at gateway
	engine := enforcement.New()
	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)
	gwApp := gateway.New(
		gateway.Config{GatewayAudience: "https://gateway.test", AdminAPIKey: testAdminKey},
		gateway.Dependencies{
			Engine:      engine,
			KillSwitch:  killswitch.NewInMemory(),
			Revocation:  revocation.NewInMemory(),
			JWTVerifier: &testJWTVerifier{signingKey: signingKey},
			DPoPStore:   dpopStore,
			Logger:      logger,
		},
	)

	// file-read allowed
	enforceBody, _ := json.Marshal(map[string]any{
		"token": attToken.Token,
		"request": map[string]any{
			"sessionId": "att-sess",
			"toolName":  "file-read",
			"context":   map[string]any{"sourceIp": "10.0.0.1", "operation": "read"},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", strings.NewReader(string(enforceBody)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	gwApp.Handler().ServeHTTP(w, req)
	var enforceResp map[string]any
	err = json.Unmarshal(w.Body.Bytes(), &enforceResp)
	require.NoError(t, err)
	assert.Equal(t, "allow", enforceResp["decision"])

	// Other tool denied (no matching capability in the attenuated set)
	enforceBody, _ = json.Marshal(map[string]any{
		"token": attToken.Token,
		"request": map[string]any{
			"sessionId": "att-sess",
			"toolName":  "db-query",
			"context":   map[string]any{"sourceIp": "10.0.0.1"},
		},
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/enforce", strings.NewReader(string(enforceBody)))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	gwApp.Handler().ServeHTTP(w, req)
	err = json.Unmarshal(w.Body.Bytes(), &enforceResp)
	require.NoError(t, err)
	assert.Equal(t, "deny", enforceResp["decision"])
}

// TestIssuance_JWKSEndpoint verifies the JWKS endpoint returns valid key material.
func TestIssuance_JWKSEndpoint(t *testing.T) {
	signingKey, err := eunocrypto.GenerateECDSASigner("jwks-key-1", eunocrypto.ES256)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	issuerApp := issuer.New(
		issuer.Config{
			IssuerDID:       "did:web:issuer.test",
			IssuerURL:       "https://issuer.test",
			DefaultTokenTTL: 300,
			MaxTokenTTL:     3600,
			Audience:        "https://gateway.test",
		},
		issuer.Dependencies{
			PolicyEngine: policy.New(),
			Identity:     &testIdentityProvider{},
			KeyStore:     issuer.NewSingleKeyStore(signingKey),
			Logger:       logger,
		},
	)
	issuerSrv := httptest.NewServer(issuerApp.Handler())
	defer issuerSrv.Close()

	resp, err := http.Get(issuerSrv.URL + "/.well-known/jwks.json")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var jwks jose.JSONWebKeySet
	err = json.NewDecoder(resp.Body).Decode(&jwks)
	require.NoError(t, err)
	require.Len(t, jwks.Keys, 1)
	assert.Equal(t, "jwks-key-1", jwks.Keys[0].KeyID)
	assert.Equal(t, "sig", jwks.Keys[0].Use)
}

// TestIssuance_KeyRotation verifies that after key rotation, tokens signed with
// different keys are independently verifiable.
func TestIssuance_KeyRotation(t *testing.T) {
	key1, err := eunocrypto.GenerateECDSASigner("key-v1", eunocrypto.ES256)
	require.NoError(t, err)
	key2, err := eunocrypto.GenerateECDSASigner("key-v2", eunocrypto.ES256)
	require.NoError(t, err)

	idKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	policyEngine := policy.New()
	policyEngine.SetPolicy(&policy.RoleCapabilityPolicy{
		Role:          "default",
		MaxTTLSeconds: 3600,
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	})

	idProvider := &testIdentityProvider{
		publicKey: &idKey.PublicKey,
		issuer:    "https://idp.test",
		audience:  "https://issuer.test",
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Issue token with key1
	issuerApp1 := issuer.New(
		issuer.Config{
			IssuerDID: "did:web:issuer.test", IssuerURL: "https://issuer.test",
			DefaultTokenTTL: 3600, MaxTokenTTL: 3600, Audience: "https://gateway.test",
		},
		issuer.Dependencies{
			PolicyEngine: policyEngine, Identity: idProvider,
			KeyStore: issuer.NewSingleKeyStore(key1), Logger: logger,
		},
	)
	issuerSrv1 := httptest.NewServer(issuerApp1.Handler())
	defer issuerSrv1.Close()

	idToken := generateTestIdentityToken(t, idKey, "rotation-user")
	issueBody, _ := json.Marshal(map[string]any{"token": idToken})
	resp, err := http.Post(issuerSrv1.URL+"/api/v1/issue", "application/json", strings.NewReader(string(issueBody)))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var tokenV1 issuer.IssueResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenV1)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenV1.Token)

	// Issue token with key2
	issuerApp2 := issuer.New(
		issuer.Config{
			IssuerDID: "did:web:issuer.test", IssuerURL: "https://issuer.test",
			DefaultTokenTTL: 3600, MaxTokenTTL: 3600, Audience: "https://gateway.test",
		},
		issuer.Dependencies{
			PolicyEngine: policyEngine, Identity: idProvider,
			KeyStore: issuer.NewSingleKeyStore(key2), Logger: logger,
		},
	)
	issuerSrv2 := httptest.NewServer(issuerApp2.Handler())
	defer issuerSrv2.Close()

	resp, err = http.Post(issuerSrv2.URL+"/api/v1/issue", "application/json", strings.NewReader(string(issueBody)))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var tokenV2 issuer.IssueResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenV2)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenV2.Token)
	assert.NotEqual(t, tokenV1.Token, tokenV2.Token)

	// Both should be valid when verified with their respective keys
	gwVerifier1 := &testJWTVerifier{signingKey: key1}
	payload1, err := gwVerifier1.VerifyToken(context.Background(), tokenV1.Token)
	require.NoError(t, err)
	assert.Equal(t, "rotation-user", payload1.Subject)

	gwVerifier2 := &testJWTVerifier{signingKey: key2}
	payload2, err := gwVerifier2.VerifyToken(context.Background(), tokenV2.Token)
	require.NoError(t, err)
	assert.Equal(t, "rotation-user", payload2.Subject)
}

// TestIssuance_ExpiredToken_DeniedAtGateway verifies expired tokens are rejected.
func TestIssuance_ExpiredToken_DeniedAtGateway(t *testing.T) {
	expiredClaims := &capability.TokenPayload{
		Subject:   "user-expired",
		JWTID:     "expired-jti",
		ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(),
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	}

	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	gwApp := gateway.New(
		gateway.Config{GatewayAudience: "https://gateway.test", AdminAPIKey: testAdminKey},
		gateway.Dependencies{
			Engine:      enforcement.New(),
			KillSwitch:  killswitch.NewInMemory(),
			Revocation:  revocation.NewInMemory(),
			JWTVerifier: &staticClaimsVerifier{claims: expiredClaims},
			DPoPStore:   dpopStore,
			Logger:      logger,
		},
	)

	enforceBody, _ := json.Marshal(map[string]any{
		"token": "expired-token",
		"request": map[string]any{
			"sessionId": "sess-exp",
			"toolName":  "tool",
			"context":   map[string]any{"sourceIp": "10.0.0.1"},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enforce", strings.NewReader(string(enforceBody)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	gwApp.Handler().ServeHTTP(w, req)

	var enforceResp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &enforceResp)
	assert.Equal(t, "deny", enforceResp["decision"])
	denial := enforceResp["denial"].(map[string]any)
	assert.Equal(t, "TOKEN_EXPIRED", denial["code"])
}

// TestIssuance_Discovery_Endpoint verifies the discovery endpoint returns correct metadata.
func TestIssuance_Discovery_Endpoint(t *testing.T) {
	signingKey, err := eunocrypto.GenerateECDSASigner("disc-key", eunocrypto.ES256)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	issuerApp := issuer.New(
		issuer.Config{
			IssuerDID:       "did:web:issuer.test",
			IssuerURL:       "https://issuer.test",
			DefaultTokenTTL: 300,
			MaxTokenTTL:     3600,
			Audience:        "https://gateway.test",
		},
		issuer.Dependencies{
			PolicyEngine: policy.New(),
			Identity:     &testIdentityProvider{},
			KeyStore:     issuer.NewSingleKeyStore(signingKey),
			Logger:       logger,
		},
	)
	issuerSrv := httptest.NewServer(issuerApp.Handler())
	defer issuerSrv.Close()

	resp, err := http.Get(issuerSrv.URL + "/.well-known/capability-issuer")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var discovery map[string]any
	err = json.NewDecoder(resp.Body).Decode(&discovery)
	require.NoError(t, err)
	assert.Equal(t, "did:web:issuer.test", discovery["issuer"])
}

// TestIssuance_InvalidIdentityToken verifies the issuer rejects invalid identity tokens.
func TestIssuance_InvalidIdentityToken(t *testing.T) {
	signingKey, err := eunocrypto.GenerateECDSASigner("inv-key", eunocrypto.ES256)
	require.NoError(t, err)

	idKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	idProvider := &testIdentityProvider{
		publicKey: &idKey.PublicKey,
		issuer:    "https://idp.test",
		audience:  "https://issuer.test",
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	issuerApp := issuer.New(
		issuer.Config{
			IssuerDID: "did:web:issuer.test", IssuerURL: "https://issuer.test",
			DefaultTokenTTL: 300, MaxTokenTTL: 3600, Audience: "https://gateway.test",
		},
		issuer.Dependencies{
			PolicyEngine: policy.New(), Identity: idProvider,
			KeyStore: issuer.NewSingleKeyStore(signingKey), Logger: logger,
		},
	)
	issuerSrv := httptest.NewServer(issuerApp.Handler())
	defer issuerSrv.Close()

	// Send invalid/garbage token
	issueBody, _ := json.Marshal(map[string]any{"token": "garbage.invalid.token"})
	resp, err := http.Post(issuerSrv.URL+"/api/v1/issue", "application/json", strings.NewReader(string(issueBody)))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestIssuance_TokenRenewal verifies the renewal endpoint refreshes token expiry.
func TestIssuance_TokenRenewal(t *testing.T) {
	signingKey, err := eunocrypto.GenerateECDSASigner("renew-key", eunocrypto.ES256)
	require.NoError(t, err)

	idKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	policyEngine := policy.New()
	policyEngine.SetPolicy(&policy.RoleCapabilityPolicy{
		Role:          "default",
		MaxTTLSeconds: 3600,
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	})

	idProvider := &testIdentityProvider{
		publicKey: &idKey.PublicKey,
		issuer:    "https://idp.test",
		audience:  "https://issuer.test",
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	issuerApp := issuer.New(
		issuer.Config{
			IssuerDID: "did:web:issuer.test", IssuerURL: "https://issuer.test",
			DefaultTokenTTL: 300, MaxTokenTTL: 3600, Audience: "https://gateway.test",
		},
		issuer.Dependencies{
			PolicyEngine: policyEngine, Identity: idProvider,
			KeyStore: issuer.NewSingleKeyStore(signingKey), Logger: logger,
		},
	)
	issuerSrv := httptest.NewServer(issuerApp.Handler())
	defer issuerSrv.Close()

	// Issue initial token
	idToken := generateTestIdentityToken(t, idKey, "renew-user")
	issueBody, _ := json.Marshal(map[string]any{"token": idToken, "ttl": 60})
	resp, err := http.Post(issuerSrv.URL+"/api/v1/issue", "application/json", strings.NewReader(string(issueBody)))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var originalToken issuer.IssueResponse
	err = json.NewDecoder(resp.Body).Decode(&originalToken)
	require.NoError(t, err)

	// Renew the token (requires fresh idToken for re-auth)
	renewBody, _ := json.Marshal(map[string]any{"token": originalToken.Token, "idToken": idToken, "ttl": 300})
	resp, err = http.Post(issuerSrv.URL+"/api/v1/renew", "application/json", strings.NewReader(string(renewBody)))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var renewed issuer.RenewResponse
	err = json.NewDecoder(resp.Body).Decode(&renewed)
	require.NoError(t, err)
	assert.NotEmpty(t, renewed.Token)
	assert.True(t, renewed.ExpiresAt > originalToken.ExpiresAt)
}
