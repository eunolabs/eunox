// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/internal/agentruntime"
	"github.com/eunolabs/eunox/internal/agentruntime/adapters"
	"github.com/eunolabs/eunox/internal/gateway"
	"github.com/eunolabs/eunox/internal/issuer"
	"github.com/eunolabs/eunox/internal/issuer/policy"
	"github.com/eunolabs/eunox/pkg/capability"
	eunoxcrypto "github.com/eunolabs/eunox/pkg/crypto"
	"github.com/eunolabs/eunox/pkg/enforcement"
	"github.com/eunolabs/eunox/pkg/identity"
	"github.com/eunolabs/eunox/pkg/observability"
)

// testIdentityProvider is a simple identity.Provider that verifies tokens
// signed with a known ECDSA key for integration testing.
type testIdentityProvider struct {
	publicKey *ecdsa.PublicKey
	issuer    string
	audience  string
}

func (p *testIdentityProvider) VerifyToken(_ context.Context, tokenStr string) (*identity.UserContext, error) {
	tok, err := jwt.ParseSigned(tokenStr, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, err
	}

	var claims jwt.Claims
	if err := tok.Claims(p.publicKey, &claims); err != nil {
		return nil, err
	}

	expected := jwt.Expected{
		Issuer: p.issuer,
		Time:   time.Now(),
	}
	if err := claims.ValidateWithLeeway(expected, 2*time.Minute); err != nil {
		return nil, err
	}

	return &identity.UserContext{
		Subject:  claims.Subject,
		Roles:    []string{"default"},
		Provider: "test",
	}, nil
}

// testJWTVerifier verifies capability tokens signed by the test issuer.
type testJWTVerifier struct {
	signingKey *eunoxcrypto.SoftwareSigner
}

func (v *testJWTVerifier) VerifyToken(_ context.Context, tokenStr string) (*capability.TokenPayload, error) {
	// Get the public key info
	pubKeys := issuer.NewSingleKeyStore(v.signingKey).PublicKeys()
	if len(pubKeys) == 0 {
		return nil, fmt.Errorf("no public keys available")
	}

	// Parse using go-jose
	parsed, err := jose.ParseSigned(tokenStr, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, fmt.Errorf("parse signed token: %w", err)
	}

	// Verify and extract claims
	var payload capability.TokenPayload
	payloadBytes, err := parsed.Verify(pubKeys[0].PublicKey)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}

	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal token payload: %w", err)
	}

	return &payload, nil
}

// testHintsProvider provides static capabilities for integration tests (F-1 fix).
type testHintsProvider struct {
	capabilities []capability.Constraint
}

func (p *testHintsProvider) GetHints(_ context.Context) (*agentruntime.IssuanceHints, error) {
	return &agentruntime.IssuanceHints{
		Capabilities: p.capabilities,
	}, nil
}

func newTestHintsProvider(capabilities []capability.Constraint) *testHintsProvider {
	return &testHintsProvider{capabilities: capabilities}
}

// setupTestIssuer creates an issuer server for testing with the given capabilities policy.
func setupTestIssuer(t *testing.T, signingKey *eunoxcrypto.SoftwareSigner, idKey *ecdsa.PrivateKey, caps []capability.Constraint) *httptest.Server {
	t.Helper()

	policyEngine := policy.New()
	policyEngine.SetPolicy(&policy.RoleCapabilityPolicy{
		Role:          "default",
		MaxTTLSeconds: 3600,
		Capabilities:  caps,
	})

	idProvider := &testIdentityProvider{
		publicKey: &idKey.PublicKey,
		issuer:    "https://idp.test",
		audience:  "https://issuer.test",
	}

	keyStore := issuer.NewSingleKeyStore(signingKey)
	metrics := observability.NewMetricsRegistry("test", "integration")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	app := issuer.New(&issuer.Config{
		IssuerDID:       "did:web:issuer.test",
		IssuerURL:       "https://issuer.test",
		DefaultTokenTTL: 300,
		MaxTokenTTL:     3600,
		Audience:        "https://gateway.test",
	}, &issuer.Dependencies{
		PolicyEngine: policyEngine,
		Identity:     idProvider,
		KeyStore:     keyStore,
		Logger:       logger,
		Metrics:      metrics,
	})

	return httptest.NewServer(app.Handler())
}

// setupTestGateway creates a gateway server for testing.
func setupTestGateway(t *testing.T, signingKey *eunoxcrypto.SoftwareSigner) *httptest.Server {
	t.Helper()

	engine := enforcement.New()
	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)
	metrics := observability.NewMetricsRegistry("test", "integration")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	app, err := gateway.New(&gateway.Config{
		AdminAPIKey:     "test-admin-key",
		GatewayAudience: "https://gateway.test",
	}, &gateway.Dependencies{
		Engine:      engine,
		JWTVerifier: &testJWTVerifier{signingKey: signingKey},
		DPoPStore:   dpopStore,
		Logger:      logger,
		Metrics:     metrics,
	})
	require.NoError(t, err)

	return httptest.NewServer(app.Handler())
}

// generateTestIdentityToken creates a signed identity token for testing.
func generateTestIdentityToken(t *testing.T, idKey *ecdsa.PrivateKey, subject string) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: idKey}, nil)
	require.NoError(t, err)

	claims := jwt.Claims{
		Subject:   subject,
		Issuer:    "https://idp.test",
		Audience:  jwt.Audience{"https://issuer.test"},
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Expiry:    jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		NotBefore: jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)),
	}

	tokenStr, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return tokenStr
}

// TestAgentRuntime_FullLoop tests the complete flow:
// runtime → issuer (token acquisition) → gateway (enforcement) → mock upstream
func TestAgentRuntime_FullLoop(t *testing.T) {
	ctx := context.Background()

	// --- Setup signing key ---
	signingKey, err := eunoxcrypto.GenerateECDSASigner("test-key-1", eunoxcrypto.ES256)
	require.NoError(t, err)

	// --- Setup identity key ---
	idKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	idTokenStr := generateTestIdentityToken(t, idKey, "agent-user-1")

	// --- Setup issuer ---
	issuerServer := setupTestIssuer(t, signingKey, idKey, []capability.Constraint{
		{Resource: "*", Actions: []string{"*"}},
	})
	defer issuerServer.Close()

	// --- Setup mock upstream tool ---
	upstreamCalled := false
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		authHeader := r.Header.Get("Authorization")
		assert.NotEmpty(t, authHeader)
		assert.Contains(t, authHeader, "Bearer ")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"content":"file contents here"}`))
	}))
	defer upstreamServer.Close()

	// --- Setup gateway ---
	gatewayServer := setupTestGateway(t, signingKey)
	defer gatewayServer.Close()

	// --- Create agent runtime with capabilities (F-1 fix requires non-empty capabilities) ---
	dpopDisabled := false
	hints := newTestHintsProvider([]capability.Constraint{
		{Resource: "*", Actions: []string{"*"}},
	})
	rt, err := agentruntime.New(&agentruntime.Config{
		IssuerURL:     issuerServer.URL,
		GatewayURL:    gatewayServer.URL,
		IdentityToken: idTokenStr,
		DPoPEnabled:   &dpopDisabled,
	}, agentruntime.WithHintsProvider(hints))

	require.NoError(t, err)
	defer rt.Stop()

	// --- Test 1: Token acquisition ---
	token, err := rt.GetToken(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, token.Token)
	assert.NotEmpty(t, token.TokenID)
	assert.True(t, token.ExpiresAt > time.Now().Unix())

	// --- Test 2: Tool invocation through gateway (enforcement only, no upstream) ---
	resp, err := rt.InvokeTool(ctx, &agentruntime.ToolRequest{
		SessionID: "integration-session-1",
		ToolName:  "read_file",
		Arguments: map[string]interface{}{"path": "/home/user/test.txt"},
	})
	require.NoError(t, err)
	assert.True(t, resp.Allowed)

	// --- Test 3: Tool invocation with upstream call ---
	resp, err = rt.InvokeTool(ctx, &agentruntime.ToolRequest{
		SessionID:  "integration-session-1",
		ToolName:   "read_file",
		Arguments:  map[string]interface{}{"path": "/home/user/test.txt"},
		HTTPMethod: "GET",
		URL:        upstreamServer.URL + "/api/files/test.txt",
	})
	require.NoError(t, err)
	assert.True(t, resp.Allowed)
	assert.Equal(t, 200, resp.StatusCode)
	assert.True(t, upstreamCalled)
	assert.Contains(t, string(resp.Body), "file contents here")

	// --- Test 4: Token caching (second call reuses token) ---
	token2, err := rt.GetToken(ctx)
	require.NoError(t, err)
	assert.Equal(t, token.Token, token2.Token)
}

// TestAgentRuntime_DPoPEndToEnd tests that DPoP proofs are correctly generated
// and the JKT is bound to the issued token.
func TestAgentRuntime_DPoPEndToEnd(t *testing.T) {
	signingKey, err := eunoxcrypto.GenerateECDSASigner("test-key-1", eunoxcrypto.ES256)
	require.NoError(t, err)

	idKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	idTokenStr := generateTestIdentityToken(t, idKey, "agent-user-dpop")

	issuerServer := setupTestIssuer(t, signingKey, idKey, []capability.Constraint{
		{Resource: "file:///*", Actions: []string{"read"}},
	})
	defer issuerServer.Close()

	// Create runtime with DPoP enabled (default) and capabilities hint (F-1 fix)
	hints := newTestHintsProvider([]capability.Constraint{
		{Resource: "file:///*", Actions: []string{"read"}},
	})
	rt, err := agentruntime.New(&agentruntime.Config{
		IssuerURL:     issuerServer.URL,
		GatewayURL:    "https://gateway.test",
		IdentityToken: idTokenStr,
	}, agentruntime.WithHintsProvider(hints))

	require.NoError(t, err)
	defer rt.Stop()

	// Verify DPoP thumbprint is non-empty
	thumbprint := rt.DPoPThumbprint()
	assert.NotEmpty(t, thumbprint)

	// Acquire token
	token, err := rt.GetToken(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, token.Token)

	// Parse the token to verify JKT binding
	parts := strings.SplitN(token.Token, ".", 3)
	require.Len(t, parts, 3)

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var claims map[string]interface{}
	err = json.Unmarshal(claimsBytes, &claims)
	require.NoError(t, err)

	// The token should have a cnf.jkt claim matching the DPoP thumbprint
	cnf, ok := claims["cnf"].(map[string]interface{})
	require.True(t, ok, "token should have cnf claim")
	assert.Equal(t, thumbprint, cnf["jkt"])
}

// TestAgentRuntime_ManifestDrivenIssuance tests using a manifest to drive token requests.
func TestAgentRuntime_ManifestDrivenIssuance(t *testing.T) {
	signingKey, err := eunoxcrypto.GenerateECDSASigner("test-key-1", eunoxcrypto.ES256)
	require.NoError(t, err)

	idKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	idTokenStr := generateTestIdentityToken(t, idKey, "manifest-agent")

	issuerServer := setupTestIssuer(t, signingKey, idKey, []capability.Constraint{
		{Resource: "db://production/*", Actions: []string{"query", "insert"}},
	})
	defer issuerServer.Close()

	// Build manifest
	manifest, err := agentruntime.NewManifestBuilder("db-query-agent").
		WithVersion("2.0.0").
		WithDescription("Agent that queries production databases").
		AddResourceAccess("db://production/*", "query", "insert").
		WithDefaultTTL(600).
		Build()
	require.NoError(t, err)

	// Create runtime with manifest-driven hints
	dpopDisabled := false
	rt, err := agentruntime.New(&agentruntime.Config{
		IssuerURL:     issuerServer.URL,
		GatewayURL:    "https://gateway.test",
		IdentityToken: idTokenStr,
		DPoPEnabled:   &dpopDisabled,
	},
		agentruntime.WithHintsProvider(agentruntime.NewStaticHintsProvider(manifest)))

	require.NoError(t, err)
	defer rt.Stop()

	token, err := rt.GetToken(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, token.Token)
}

// TestAgentRuntime_HTTPAdapterFullLoop tests the HTTP adapter with a real issuer and gateway.
func TestAgentRuntime_HTTPAdapterFullLoop(t *testing.T) {
	ctx := context.Background()

	signingKey, err := eunoxcrypto.GenerateECDSASigner("test-key-1", eunoxcrypto.ES256)
	require.NoError(t, err)

	idKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	idTokenStr := generateTestIdentityToken(t, idKey, "adapter-agent")

	issuerServer := setupTestIssuer(t, signingKey, idKey, []capability.Constraint{
		{Resource: "*", Actions: []string{"*"}},
	})
	defer issuerServer.Close()

	gatewayServer := setupTestGateway(t, signingKey)
	defer gatewayServer.Close()

	// Upstream
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"id":1},{"id":2}]}`))
	}))
	defer upstreamServer.Close()

	// Runtime with capabilities hints (F-1 fix)
	dpopDisabled := false
	hints := newTestHintsProvider([]capability.Constraint{
		{Resource: "*", Actions: []string{"*"}},
	})
	rt, err := agentruntime.New(&agentruntime.Config{
		IssuerURL:     issuerServer.URL,
		GatewayURL:    gatewayServer.URL,
		IdentityToken: idTokenStr,
		DPoPEnabled:   &dpopDisabled,
	}, agentruntime.WithHintsProvider(hints))

	require.NoError(t, err)
	defer rt.Stop()

	// Use HTTP adapter
	httpAdapter := adapters.NewHTTPAdapter(rt, upstreamServer.URL, "session-adapter")

	var result map[string]interface{}
	err = httpAdapter.CallJSON(ctx, &adapters.HTTPToolCall{
		ToolName:  "list_items",
		Method:    "GET",
		Path:      "/api/items",
		Arguments: map[string]interface{}{"limit": 10},
	}, &result)

	require.NoError(t, err)

	items, ok := result["items"].([]interface{})
	require.True(t, ok)
	assert.Len(t, items, 2)
}
