// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package issuer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/internal/issuer/policy"
	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/crypto"
	"github.com/eunolabs/eunox/pkg/identity"
	"github.com/eunolabs/eunox/pkg/revocation"
)

// --- Test Helpers ---

type mockIdentity struct {
	verifyFunc func(ctx context.Context, token string) (*identity.UserContext, error)
}

func (m *mockIdentity) VerifyToken(ctx context.Context, token string) (*identity.UserContext, error) {
	return m.verifyFunc(ctx, token)
}

type mockRateLimiter struct {
	allowFunc func(ctx context.Context, key string) (bool, error)
}

func (m *mockRateLimiter) Allow(ctx context.Context, key string) (bool, error) {
	return m.allowFunc(ctx, key)
}

func testKeyStore(t *testing.T) *SingleKeyStore {
	t.Helper()
	signer, err := crypto.GenerateECDSASigner("test-key-1", crypto.ES256)
	require.NoError(t, err)
	return NewSingleKeyStore(signer)
}

func testApp(t *testing.T, opts ...func(*testAppConfig)) *App {
	t.Helper()

	cfg := &testAppConfig{
		identityFunc: func(_ context.Context, _ string) (*identity.UserContext, error) {
			return &identity.UserContext{
				Subject:  "user-123",
				Email:    "alice@example.com",
				Roles:    []string{"admin"},
				TenantID: "tenant-1",
				Provider: "test",
			}, nil
		},
		rateLimitFunc: func(_ context.Context, _ string) (bool, error) {
			return true, nil
		},
	}

	for _, opt := range opts {
		opt(cfg)
	}

	pe := policy.New()
	pe.SetPolicy(&policy.RoleCapabilityPolicy{
		Role:          "admin",
		Description:   "Admin role",
		MaxTTLSeconds: 3600,
		Capabilities: []capability.Constraint{
			{Resource: "tool:*", Actions: []string{"invoke", "read", "write"}},
		},
	})
	pe.SetPolicy(&policy.RoleCapabilityPolicy{
		Role:          "default",
		Description:   "Default role",
		MaxTTLSeconds: 900,
		Capabilities: []capability.Constraint{
			{Resource: "tool:read-only", Actions: []string{"read"}},
		},
	})

	ks := testKeyStore(t)

	appCfg := Config{
		IssuerDID:       "did:web:test.example.com",
		IssuerURL:       "https://issuer.example.com",
		DefaultTokenTTL: 900,
		MaxTokenTTL:     3600,
		Audience:        "https://gateway.example.com",
		AdminAPIKey:     "test-admin-key",
	}

	deps := Dependencies{
		PolicyEngine: pe,
		Identity:     &mockIdentity{verifyFunc: cfg.identityFunc},
		KeyStore:     ks,
		RateLimiter:  &mockRateLimiter{allowFunc: cfg.rateLimitFunc},
		Revocation:   cfg.revocationStore,
	}

	return New(&appCfg, &deps)
}

type testAppConfig struct {
	identityFunc    func(ctx context.Context, token string) (*identity.UserContext, error)
	rateLimitFunc   func(ctx context.Context, key string) (bool, error)
	revocationStore revocation.Store
}

func withIdentity(fn func(ctx context.Context, token string) (*identity.UserContext, error)) func(*testAppConfig) {
	return func(c *testAppConfig) {
		c.identityFunc = fn
	}
}

func withRateLimit(fn func(ctx context.Context, key string) (bool, error)) func(*testAppConfig) {
	return func(c *testAppConfig) {
		c.rateLimitFunc = fn
	}
}

func withRevocation(store revocation.Store) func(*testAppConfig) {
	return func(c *testAppConfig) {
		c.revocationStore = store
	}
}

func doPost(app *App, path string, body interface{}) *httptest.ResponseRecorder {
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if app.config.AdminAPIKey != "" {
		req.Header.Set(adminAPIKeyHeader(), app.config.AdminAPIKey)
	}
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	return w
}

func doGet(app *App, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
	if app.config.AdminAPIKey != "" {
		req.Header.Set(adminAPIKeyHeader(), app.config.AdminAPIKey)
	}
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	return w
}

// defaultTestCaps provides standard capabilities for test issue requests (F-1 fix).
var defaultTestCaps = []capability.Constraint{
	{Resource: "tool:*", Actions: []string{"invoke", "read", "write"}},
}

// --- Health Tests ---

func TestHealth(t *testing.T) {
	app := testApp(t)

	t.Run("liveness", func(t *testing.T) {
		w := doGet(app, "/health/live")
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("readiness", func(t *testing.T) {
		w := doGet(app, "/health/ready")
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// --- Issue Tests ---

func TestIssue_Success(t *testing.T) {
	app := testApp(t)

	w := doPost(app, "/api/v1/issue", IssueRequest{
		Token:        "valid-id-token",
		Capabilities: defaultTestCaps,
		TTL:          600,
	})

	assert.Equal(t, http.StatusOK, w.Code)

	var resp IssueResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.Token)
	assert.NotEmpty(t, resp.TokenID)
	assert.True(t, resp.ExpiresAt > resp.IssuedAt)

	// Verify the token is a valid JWT
	parts := splitToken(resp.Token)
	require.NotNil(t, parts)

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var claims capability.TokenPayload
	require.NoError(t, json.Unmarshal(payloadBytes, &claims))
	assert.Equal(t, "did:web:test.example.com", claims.Issuer)
	assert.Equal(t, "user-123", claims.Subject)
	assert.Equal(t, "https://gateway.example.com", claims.Audience)
	assert.Equal(t, resp.TokenID, claims.JWTID)
	assert.NotEmpty(t, claims.Capabilities)
	assert.NotNil(t, claims.AuthorizedBy)
	assert.Equal(t, "user-123", claims.AuthorizedBy.UserID)
	assert.Equal(t, []string{"admin"}, claims.AuthorizedBy.Roles)
}

func TestIssue_WithRequestedCapabilities(t *testing.T) {
	app := testApp(t)

	w := doPost(app, "/api/v1/issue", IssueRequest{
		Token: "valid-id-token",
		Capabilities: []capability.Constraint{
			{Resource: "tool:specific", Actions: []string{"read"}},
		},
	})

	assert.Equal(t, http.StatusOK, w.Code)

	var resp IssueResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.Token)
}

func TestIssue_IgnoresRequestedAudienceOverride(t *testing.T) {
	app := testApp(t)

	w := doPost(app, "/api/v1/issue", IssueRequest{
		Token:        "valid-id-token",
		Capabilities: defaultTestCaps,
		Audience:     "https://attacker.example.com",
	})

	assert.Equal(t, http.StatusOK, w.Code)
	var resp IssueResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	claims, err := app.verifyCapabilityToken(context.Background(), resp.Token)
	require.NoError(t, err)
	assert.Equal(t, "https://gateway.example.com", claims.Audience)
}

func TestIssue_MissingToken(t *testing.T) {
	app := testApp(t)

	w := doPost(app, "/api/v1/issue", IssueRequest{})
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestIssue_IdentityVerificationFailed(t *testing.T) {
	app := testApp(t, withIdentity(func(_ context.Context, _ string) (*identity.UserContext, error) {
		return nil, errors.New("token expired")
	}))

	w := doPost(app, "/api/v1/issue", IssueRequest{Token: "bad-token"})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestIssue_RateLimited(t *testing.T) {
	app := testApp(t, withRateLimit(func(_ context.Context, _ string) (bool, error) {
		return false, nil
	}))

	w := doPost(app, "/api/v1/issue", IssueRequest{Token: "valid-token", Capabilities: defaultTestCaps})
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

func TestIssue_RateLimiterError(t *testing.T) {
	app := testApp(t, withRateLimit(func(_ context.Context, _ string) (bool, error) {
		return false, errors.New("redis down")
	}))

	w := doPost(app, "/api/v1/issue", IssueRequest{Token: "valid-token", Capabilities: defaultTestCaps})
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestIssue_NoPolicyForRole(t *testing.T) {
	app := testApp(t, withIdentity(func(_ context.Context, _ string) (*identity.UserContext, error) {
		return &identity.UserContext{
			Subject: "user-456",
			Roles:   []string{"unknown-role"},
		}, nil
	}))

	w := doPost(app, "/api/v1/issue", IssueRequest{Token: "valid-token", Capabilities: defaultTestCaps})
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestIssue_DPoPBinding(t *testing.T) {
	app := testApp(t)

	w := doPost(app, "/api/v1/issue", IssueRequest{
		Token:        "valid-id-token",
		Capabilities: defaultTestCaps,
		DPoP:         &DPoPBinding{JKT: "test-thumbprint-hash"},
	})

	assert.Equal(t, http.StatusOK, w.Code)

	var resp IssueResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	// Verify DPoP binding in token
	parts := splitToken(resp.Token)
	require.NotNil(t, parts)
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims capability.TokenPayload
	require.NoError(t, json.Unmarshal(payloadBytes, &claims))
	require.NotNil(t, claims.Confirmation)
	assert.Equal(t, "test-thumbprint-hash", claims.Confirmation.JKT)
}

func TestIssue_TTLCapping(t *testing.T) {
	app := testApp(t)

	// Request TTL exceeding max — should be capped to MaxTokenTTL (3600)
	w := doPost(app, "/api/v1/issue", IssueRequest{
		Token:        "valid-id-token",
		Capabilities: defaultTestCaps,
		TTL:          99999,
	})

	assert.Equal(t, http.StatusOK, w.Code)

	var resp IssueResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	actualTTL := resp.ExpiresAt - resp.IssuedAt
	assert.True(t, actualTTL <= 3600, "TTL should be capped to 3600 seconds")
}

func TestIssue_EmptyBody(t *testing.T) {
	app := testApp(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/issue", http.NoBody)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- Attenuation Tests ---

func TestAttenuate_Success(t *testing.T) {
	app := testApp(t)

	// First issue a parent token
	issueResp := doPost(app, "/api/v1/issue", IssueRequest{Token: "valid-id-token", Capabilities: defaultTestCaps, TTL: 3600})
	require.Equal(t, http.StatusOK, issueResp.Code)

	var parentResp IssueResponse
	require.NoError(t, json.Unmarshal(issueResp.Body.Bytes(), &parentResp))

	// Attenuate with subset capabilities
	w := doPost(app, "/api/v1/attenuate", AttenuateRequest{
		ParentToken: parentResp.Token,
		Capabilities: []capability.Constraint{
			{Resource: "tool:specific", Actions: []string{"read"}},
		},
		TTL: 600,
	})

	assert.Equal(t, http.StatusOK, w.Code)

	var attResp AttenuateResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &attResp))
	assert.NotEmpty(t, attResp.Token)
	assert.True(t, attResp.ExpiresAt-attResp.IssuedAt <= 600)

	// Verify parent reference
	parts := splitToken(attResp.Token)
	require.NotNil(t, parts)
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims capability.TokenPayload
	require.NoError(t, json.Unmarshal(payloadBytes, &claims))
	assert.Equal(t, parentResp.TokenID, claims.ParentCapabilityID)
}

func TestAttenuate_MissingParentToken(t *testing.T) {
	app := testApp(t)
	w := doPost(app, "/api/v1/attenuate", AttenuateRequest{
		Capabilities: []capability.Constraint{{Resource: "tool:x", Actions: []string{"read"}}},
	})
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAttenuate_MissingCapabilities(t *testing.T) {
	app := testApp(t)
	w := doPost(app, "/api/v1/attenuate", AttenuateRequest{
		ParentToken: "some-token",
	})
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAttenuate_InvalidParentToken(t *testing.T) {
	app := testApp(t)
	w := doPost(app, "/api/v1/attenuate", AttenuateRequest{
		ParentToken:  "invalid-jwt-token",
		Capabilities: []capability.Constraint{{Resource: "tool:x", Actions: []string{"read"}}},
	})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAttenuate_RejectsForgedParentToken(t *testing.T) {
	app := testApp(t)

	issueResp := doPost(app, "/api/v1/issue", IssueRequest{Token: "valid-id-token", Capabilities: defaultTestCaps, TTL: 3600})
	require.Equal(t, http.StatusOK, issueResp.Code)
	var parentResp IssueResponse
	require.NoError(t, json.Unmarshal(issueResp.Body.Bytes(), &parentResp))

	parts := splitToken(parentResp.Token)
	require.NotNil(t, parts)
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var payload capability.TokenPayload
	require.NoError(t, json.Unmarshal(payloadBytes, &payload))
	payload.Subject = "forged-user"
	forgedPayload, err := json.Marshal(payload)
	require.NoError(t, err)

	forgedToken := parts[0] + "." + base64.RawURLEncoding.EncodeToString(forgedPayload) + "." + parts[2]
	w := doPost(app, "/api/v1/attenuate", AttenuateRequest{
		ParentToken:  forgedToken,
		Capabilities: []capability.Constraint{{Resource: "tool:x", Actions: []string{"read"}}},
	})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAttenuate_TTLCannotExceedParent(t *testing.T) {
	app := testApp(t)

	// Issue parent with short TTL
	issueResp := doPost(app, "/api/v1/issue", IssueRequest{Token: "valid-id-token", Capabilities: defaultTestCaps, TTL: 120})
	require.Equal(t, http.StatusOK, issueResp.Code)

	var parentResp IssueResponse
	require.NoError(t, json.Unmarshal(issueResp.Body.Bytes(), &parentResp))

	// Request longer TTL than parent remaining
	w := doPost(app, "/api/v1/attenuate", AttenuateRequest{
		ParentToken: parentResp.Token,
		Capabilities: []capability.Constraint{
			{Resource: "tool:x", Actions: []string{"read"}},
		},
		TTL: 9999,
	})

	assert.Equal(t, http.StatusOK, w.Code)

	var attResp AttenuateResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &attResp))
	// Child TTL should be capped to parent remaining
	assert.True(t, attResp.ExpiresAt-attResp.IssuedAt <= 120)
}

// --- Renewal Tests ---

func TestRenew_Success(t *testing.T) {
	app := testApp(t)

	// Issue original token
	issueResp := doPost(app, "/api/v1/issue", IssueRequest{Token: "valid-id-token", Capabilities: defaultTestCaps, TTL: 300})
	require.Equal(t, http.StatusOK, issueResp.Code)

	var originalResp IssueResponse
	require.NoError(t, json.Unmarshal(issueResp.Body.Bytes(), &originalResp))

	// Wait a moment then renew
	time.Sleep(10 * time.Millisecond)

	w := doPost(app, "/api/v1/renew", RenewRequest{
		Token:   originalResp.Token,
		IDToken: "fresh-id-token",
	})

	assert.Equal(t, http.StatusOK, w.Code)

	var renewResp RenewResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &renewResp))
	assert.NotEmpty(t, renewResp.Token)
	assert.NotEqual(t, originalResp.TokenID, renewResp.TokenID)
	// Renewed token should have new expiry
	assert.True(t, renewResp.ExpiresAt > originalResp.ExpiresAt-5)
}

func TestRenew_MissingToken(t *testing.T) {
	app := testApp(t)
	w := doPost(app, "/api/v1/renew", RenewRequest{IDToken: "fresh"})
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRenew_MissingIDToken(t *testing.T) {
	app := testApp(t)
	w := doPost(app, "/api/v1/renew", RenewRequest{Token: "some-token"})
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRenew_SubjectMismatch(t *testing.T) {
	app := testApp(t)

	// Issue token
	issueResp := doPost(app, "/api/v1/issue", IssueRequest{Token: "valid-id-token", Capabilities: defaultTestCaps})
	require.Equal(t, http.StatusOK, issueResp.Code)
	var originalResp IssueResponse
	require.NoError(t, json.Unmarshal(issueResp.Body.Bytes(), &originalResp))

	// Create a new app where identity returns different subject for renew
	callCount := 0
	app2 := testApp(t, withIdentity(func(_ context.Context, _ string) (*identity.UserContext, error) {
		callCount++
		if callCount == 1 {
			return &identity.UserContext{Subject: "user-123", Roles: []string{"admin"}}, nil
		}
		return &identity.UserContext{Subject: "different-user", Roles: []string{"admin"}}, nil
	}))

	// Issue with app2
	issueResp2 := doPost(app2, "/api/v1/issue", IssueRequest{Token: "valid-id-token", Capabilities: defaultTestCaps})
	require.Equal(t, http.StatusOK, issueResp2.Code)
	var resp2 IssueResponse
	require.NoError(t, json.Unmarshal(issueResp2.Body.Bytes(), &resp2))

	// Renew with different subject
	w := doPost(app2, "/api/v1/renew", RenewRequest{
		Token:   resp2.Token,
		IDToken: "fresh-token",
	})
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestRenew_RevokedToken (T-3): a capability token that has been explicitly revoked
// must be rejected on /api/v1/renew with 401 Unauthorized (U-2 fix).
func TestRenew_RevokedToken(t *testing.T) {
	revStore := revocation.NewInMemory()
	app := testApp(t, withRevocation(revStore))

	// Issue an original capability token.
	issueResp := doPost(app, "/api/v1/issue", IssueRequest{
		Token:        "valid-id-token",
		Capabilities: defaultTestCaps,
		TTL:          300,
	})
	require.Equal(t, http.StatusOK, issueResp.Code)

	var originalResp IssueResponse
	require.NoError(t, json.Unmarshal(issueResp.Body.Bytes(), &originalResp))
	require.NotEmpty(t, originalResp.TokenID)

	// Revoke the token in the store.
	require.NoError(t, revStore.Revoke(context.Background(), originalResp.TokenID, 10*time.Minute))

	// Renewal attempt must be rejected with 401.
	w := doPost(app, "/api/v1/renew", RenewRequest{
		Token:   originalResp.Token,
		IDToken: "fresh-id-token",
	})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRenew_NonRevokedToken_WithRevocationStore ensures that a valid, non-revoked
// token can still be renewed when a revocation store is configured.
func TestRenew_NonRevokedToken_WithRevocationStore(t *testing.T) {
	revStore := revocation.NewInMemory()
	app := testApp(t, withRevocation(revStore))

	// Issue an original capability token.
	issueResp := doPost(app, "/api/v1/issue", IssueRequest{
		Token:        "valid-id-token",
		Capabilities: defaultTestCaps,
		TTL:          300,
	})
	require.Equal(t, http.StatusOK, issueResp.Code)

	var originalResp IssueResponse
	require.NoError(t, json.Unmarshal(issueResp.Body.Bytes(), &originalResp))

	// Renewal must succeed — the token is NOT revoked.
	w := doPost(app, "/api/v1/renew", RenewRequest{
		Token:   originalResp.Token,
		IDToken: "fresh-id-token",
	})
	assert.Equal(t, http.StatusOK, w.Code)
}

// --- JWKS Tests ---

func TestJWKS(t *testing.T) {
	app := testApp(t)

	w := doGet(app, "/.well-known/jwks.json")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
	assert.Equal(t, "public, max-age=300", w.Header().Get("Cache-Control"))

	var jwks map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &jwks))
	keys, ok := jwks["keys"].([]interface{})
	require.True(t, ok)
	assert.Len(t, keys, 1)

	key := keys[0].(map[string]interface{})
	assert.Equal(t, "EC", key["kty"])
	assert.Equal(t, "test-key-1", key["kid"])
	assert.Equal(t, "sig", key["use"])
	assert.NotEmpty(t, key["x"])
	assert.NotEmpty(t, key["y"])
}

// --- DID Document Tests ---

func TestDIDDocument(t *testing.T) {
	app := testApp(t)

	w := doGet(app, "/.well-known/did.json")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/did+json")

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &doc))
	assert.Equal(t, "did:web:test.example.com", doc["id"])
	assert.NotNil(t, doc["verificationMethod"])
	assert.NotNil(t, doc["authentication"])
}

// --- Discovery Tests ---

func TestDiscovery(t *testing.T) {
	app := testApp(t)

	w := doGet(app, "/.well-known/capability-issuer")
	assert.Equal(t, http.StatusOK, w.Code)

	var disc map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &disc))
	assert.Equal(t, "did:web:test.example.com", disc["issuer"])
	assert.Equal(t, "https://issuer.example.com", disc["issuer_url"])
	assert.Contains(t, disc["jwks_uri"], "/.well-known/jwks.json")
	assert.Contains(t, disc["token_endpoint"], "/api/v1/issue")
}

// --- Public Key Tests ---

func TestPublicKey(t *testing.T) {
	app := testApp(t)

	w := doGet(app, "/api/v1/public-key")
	assert.Equal(t, http.StatusOK, w.Code)

	var pk map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &pk))
	assert.Equal(t, "test-key-1", pk["keyId"])
	assert.Equal(t, "ES256", pk["algorithm"])
	assert.Equal(t, "sig", pk["use"])
}

// --- Admin Role Policy Tests ---

func TestAdminRolePolicy_CRUD(t *testing.T) {
	app := testApp(t)

	// Create a new policy
	w := doPost(app, "/admin/role-policy/viewer", RolePolicyRequest{
		Description:   "Viewer role",
		MaxTTLSeconds: 1800,
		Capabilities: []capability.Constraint{
			{Resource: "tool:docs", Actions: []string{"read"}},
		},
	})
	assert.Equal(t, http.StatusOK, w.Code)

	// List policies
	w = doGet(app, "/admin/role-policy")
	assert.Equal(t, http.StatusOK, w.Code)

	var listResp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listResp))
	policies := listResp["policies"].([]interface{})
	assert.GreaterOrEqual(t, len(policies), 3) // admin + default + viewer

	// Delete
	req := httptest.NewRequest(http.MethodDelete, "/admin/role-policy/viewer", http.NoBody)
	req.Header.Set(adminAPIKeyHeader(), app.config.AdminAPIKey)
	w = httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Delete non-existent
	req = httptest.NewRequest(http.MethodDelete, "/admin/role-policy/nonexistent", http.NoBody)
	req.Header.Set(adminAPIKeyHeader(), app.config.AdminAPIKey)
	w = httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAdminRolePolicy_MissingCapabilities(t *testing.T) {
	app := testApp(t)

	w := doPost(app, "/admin/role-policy/empty", RolePolicyRequest{
		Description: "No caps",
	})
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- SCIM Tests ---

func TestSCIM_CreateUser(t *testing.T) {
	app := testApp(t)

	w := doPost(app, "/scim/v2/Users", SCIMUserRequest{
		Schemas:  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		UserName: "alice",
		Active:   true,
	})
	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/scim+json")

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "alice", resp["userName"])
	assert.NotEmpty(t, resp["id"])
}

func TestSCIM_CreateUser_MissingUserName(t *testing.T) {
	app := testApp(t)
	w := doPost(app, "/scim/v2/Users", SCIMUserRequest{Active: true})
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSCIM_CreateGroup(t *testing.T) {
	app := testApp(t)

	w := doPost(app, "/scim/v2/Groups", SCIMGroupRequest{
		Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		DisplayName: "Engineering",
	})
	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/scim+json")
}

func TestSCIM_CreateGroup_MissingName(t *testing.T) {
	app := testApp(t)
	w := doPost(app, "/scim/v2/Groups", SCIMGroupRequest{})
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminEndpoints_RequireAdminAPIKey(t *testing.T) {
	app := testApp(t)
	req := httptest.NewRequest(http.MethodGet, "/admin/role-policy", http.NoBody)
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSCIMEndpoints_RequireAdminAPIKey(t *testing.T) {
	app := testApp(t)
	data, err := json.Marshal(SCIMUserRequest{UserName: "alice", Active: true})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- Token Signing Tests ---

func TestSignToken_ValidJWT(t *testing.T) {
	app := testApp(t)

	payload := &capability.TokenPayload{
		Issuer:        "did:web:test.example.com",
		Subject:       "user-123",
		Audience:      "https://gateway.example.com",
		IssuedAt:      time.Now().Unix(),
		ExpiresAt:     time.Now().Add(time.Hour).Unix(),
		JWTID:         "token-id-1",
		SchemaVersion: capability.SchemaVersion,
	}

	tokenStr, err := app.signToken(context.Background(), payload)
	require.NoError(t, err)

	parts := splitToken(tokenStr)
	require.NotNil(t, parts)

	// Verify header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var header map[string]string
	require.NoError(t, json.Unmarshal(headerBytes, &header))
	assert.Equal(t, "JWT", header["typ"])
	assert.Equal(t, "ES256", header["alg"])
	assert.Equal(t, "test-key-1", header["kid"])
}

func TestSignToken_ES384Digest(t *testing.T) {
	signer, err := crypto.GenerateECDSASigner("test-key-384", crypto.ES384)
	require.NoError(t, err)

	pe := policy.New()
	pe.SetPolicy(&policy.RoleCapabilityPolicy{
		Role:          "admin",
		MaxTTLSeconds: 3600,
		Capabilities:  []capability.Constraint{{Resource: "tool:*", Actions: []string{"read"}}},
	})

	app := New(&Config{
		IssuerDID:       "did:web:test.example.com",
		IssuerURL:       "https://issuer.example.com",
		DefaultTokenTTL: 900,
		MaxTokenTTL:     3600,
		Audience:        "https://gateway.example.com",
		AdminAPIKey:     "test-admin-key",
	}, &Dependencies{
		PolicyEngine: pe,
		Identity: &mockIdentity{verifyFunc: func(_ context.Context, _ string) (*identity.UserContext, error) {
			return &identity.UserContext{Subject: "user-123", Roles: []string{"admin"}}, nil
		}},
		KeyStore:    NewSingleKeyStore(signer),
		RateLimiter: &mockRateLimiter{allowFunc: func(_ context.Context, _ string) (bool, error) { return true, nil }},
	})

	resp := doPost(app, "/api/v1/issue", IssueRequest{Token: "valid-id-token", Capabilities: defaultTestCaps})
	require.Equal(t, http.StatusOK, resp.Code)
	var issueResp IssueResponse
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &issueResp))
	_, err = app.verifyCapabilityToken(context.Background(), issueResp.Token)
	require.NoError(t, err)
}

func TestJWKS_RSAUsesConfiguredAlgorithm(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwks := buildJWKS([]PublicKeyInfo{
		{
			KeyID:     "rsa-key",
			Algorithm: crypto.PS256,
			PublicKey: &privateKey.PublicKey,
			Use:       "sig",
		},
	})

	keys, ok := jwks["keys"].([]map[string]interface{})
	if !ok {
		rawKeys, rawOK := jwks["keys"].([]interface{})
		require.True(t, rawOK)
		require.Len(t, rawKeys, 1)
		key, keyOK := rawKeys[0].(map[string]interface{})
		require.True(t, keyOK)
		assert.Equal(t, "PS256", key["alg"])
		return
	}

	require.Len(t, keys, 1)
	assert.Equal(t, "PS256", keys[0]["alg"])
}

// --- Edge Cases ---

func TestSplitToken(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect bool
	}{
		{"valid three parts", "a.b.c", true},
		{"two parts", "a.b", false},
		{"four parts", "a.b.c.d", false},
		{"one part", "abc", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitToken(tt.input)
			if tt.expect {
				assert.NotNil(t, result)
			} else {
				assert.Nil(t, result)
			}
		})
	}
}

func TestComputePolicyHash(t *testing.T) {
	caps := []capability.Constraint{
		{Resource: "tool:a", Actions: []string{"read"}},
	}

	hash1 := computePolicyHash(caps)
	hash2 := computePolicyHash(caps)
	assert.Equal(t, hash1, hash2)
	assert.NotEmpty(t, hash1)

	// Different caps → different hash
	caps2 := []capability.Constraint{
		{Resource: "tool:b", Actions: []string{"write"}},
	}
	hash3 := computePolicyHash(caps2)
	assert.NotEqual(t, hash1, hash3)
}

// --- Integration: Full Issuance → Verification Round-Trip ---

func TestIntegration_IssueAttenuateVerify(t *testing.T) {
	app := testApp(t)

	// Step 1: Issue a token
	issueResp := doPost(app, "/api/v1/issue", IssueRequest{
		Token:        "valid-id-token",
		Capabilities: defaultTestCaps,
		TTL:          3600,
	})
	require.Equal(t, http.StatusOK, issueResp.Code)

	var issued IssueResponse
	require.NoError(t, json.Unmarshal(issueResp.Body.Bytes(), &issued))

	// Step 2: Attenuate the token
	attResp := doPost(app, "/api/v1/attenuate", AttenuateRequest{
		ParentToken: issued.Token,
		Capabilities: []capability.Constraint{
			{Resource: "tool:specific", Actions: []string{"read"}},
		},
		TTL: 600,
	})
	require.Equal(t, http.StatusOK, attResp.Code)

	var attenuated AttenuateResponse
	require.NoError(t, json.Unmarshal(attResp.Body.Bytes(), &attenuated))

	// Step 3: Verify the attenuated token can be parsed
	claims, err := app.verifyCapabilityToken(context.Background(), attenuated.Token)
	require.NoError(t, err)
	assert.Equal(t, "user-123", claims.Subject)
	assert.Equal(t, issued.TokenID, claims.ParentCapabilityID)
	assert.Len(t, claims.Capabilities, 1)
	assert.Equal(t, "tool:specific", claims.Capabilities[0].Resource)
}

func TestIntegration_IssueRenewRoundTrip(t *testing.T) {
	app := testApp(t)

	// Issue
	issueResp := doPost(app, "/api/v1/issue", IssueRequest{Token: "valid-id-token", Capabilities: defaultTestCaps, TTL: 300})
	require.Equal(t, http.StatusOK, issueResp.Code)

	var issued IssueResponse
	require.NoError(t, json.Unmarshal(issueResp.Body.Bytes(), &issued))

	// Renew
	renewResp := doPost(app, "/api/v1/renew", RenewRequest{
		Token:   issued.Token,
		IDToken: "fresh-id-token",
		TTL:     600,
	})
	require.Equal(t, http.StatusOK, renewResp.Code)

	var renewed RenewResponse
	require.NoError(t, json.Unmarshal(renewResp.Body.Bytes(), &renewed))

	// Verify renewed token
	claims, err := app.verifyCapabilityToken(context.Background(), renewed.Token)
	require.NoError(t, err)
	assert.Equal(t, "user-123", claims.Subject)
	// Renewed token has same capabilities as original
	assert.NotEmpty(t, claims.Capabilities)
}

func TestHealth_ReadinessFailure(t *testing.T) {
	app := testApp(t)
	app.config.ReadinessChecks = []func(context.Context) error{func(context.Context) error {
		return errors.New("policy db unavailable")
	}}

	w := doGet(app, "/health/ready")
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "not ready")
	assert.Contains(t, w.Body.String(), "policy db unavailable")
}
