// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOIDCProviderVerifyToken(t *testing.T) {
	privateKey, publicJWK := mustRSAJWK(t, "oidc-key")
	server, issuerURL, jwksHits := newOIDCServer(t, "", &publicJWK)
	defer server.Close()

	provider, err := NewOIDCProvider(&OIDCConfig{
		IssuerURL:      issuerURL,
		Audience:       "api://eunox",
		RequiredScopes: []string{"openid", "profile"},
		RolesClaimPath: "realm_access.roles",
		CacheTTL:       time.Hour,
	}, server.Client())
	require.NoError(t, err)

	token := mustSignedToken(t, jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), publicJWK.KeyID), &jwt.Claims{
		Issuer:   issuerURL,
		Subject:  "user-123",
		Audience: jwt.Audience{"api://eunox"},
		IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}, map[string]interface{}{
		"email": "alice@example.com",
		"name":  "Alice",
		"scope": "openid profile email",
		"realm_access": map[string]interface{}{
			"roles": []string{"admin", "operator"},
		},
		"tenant_id": "tenant-1",
	})

	user, err := provider.VerifyToken(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "user-123", user.Subject)
	assert.Equal(t, "alice@example.com", user.Email)
	assert.Equal(t, "Alice", user.Name)
	assert.Equal(t, []string{"admin", "operator"}, user.Roles)
	assert.Equal(t, "tenant-1", user.TenantID)
	assert.Equal(t, string(ProviderTypeOIDC), user.Provider)

	_, err = provider.VerifyToken(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(jwksHits), "expected cached JWKS to be reused")
}

func TestCognitoClaimMapping(t *testing.T) {
	privateKey, publicJWK := mustRSAJWK(t, "cognito-key")
	server, _, _ := newOIDCServer(t, "/pool-1", &publicJWK)
	defer server.Close()

	client := newRewriteClient(t, server)
	provider, err := NewCognitoProvider(CognitoConfig{
		Region:      "us-east-1",
		UserPoolID:  "pool-1",
		AppClientID: "app-client",
	}, client)
	require.NoError(t, err)

	issuerURL := "https://cognito-idp.us-east-1.amazonaws.com/pool-1"
	token := mustSignedToken(t, jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), publicJWK.KeyID), &jwt.Claims{
		Issuer:   issuerURL,
		Subject:  "cognito-user",
		Audience: jwt.Audience{"app-client"},
		IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}, map[string]interface{}{
		"email":            "bob@example.com",
		"cognito:username": "bob",
		"cognito:groups":   []string{"admins", "developers"},
		"custom:tenant_id": "tenant-cognito",
	})

	user, err := provider.VerifyToken(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, []string{"admins", "developers"}, user.Roles)
	assert.Equal(t, "tenant-cognito", user.TenantID)
	assert.Equal(t, "bob", user.Name)
	assert.Equal(t, string(ProviderTypeCognito), user.Provider)
}

func TestAzureADClaimMapping(t *testing.T) {
	privateKey, publicJWK := mustRSAJWK(t, "azure-key")
	server, _, _ := newOIDCServer(t, "/tenant-1/v2.0", &publicJWK)
	defer server.Close()

	provider, err := NewAzureADProvider(AzureADConfig{TenantID: "tenant-1", ClientID: "client-id"}, newRewriteClient(t, server))
	require.NoError(t, err)

	issuerURL := "https://login.microsoftonline.com/tenant-1/v2.0"
	token := mustSignedToken(t, jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), publicJWK.KeyID), &jwt.Claims{
		Issuer:   issuerURL,
		Subject:  "azure-user",
		Audience: jwt.Audience{"client-id"},
		IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}, map[string]interface{}{
		"preferred_username": "carol@example.com",
		"name":               "Carol",
		"roles":              []string{"Admin"},
		"groups":             []string{"GroupA"},
		"tid":                "tenant-azure",
	})

	user, err := provider.VerifyToken(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, []string{"Admin", "GroupA"}, user.Roles)
	assert.Equal(t, "tenant-azure", user.TenantID)
	assert.Equal(t, "carol@example.com", user.Email)
	assert.Equal(t, string(ProviderTypeAzureAD), user.Provider)
}

func TestGCPClaimMapping(t *testing.T) {
	privateKey, publicJWK := mustRSAJWK(t, "gcp-key")
	server, _, _ := newOIDCServer(t, "", &publicJWK)
	defer server.Close()

	provider, err := NewGCPProvider(GCPConfig{Audience: "gcp-audience"}, newRewriteClient(t, server))
	require.NoError(t, err)

	token := mustSignedToken(t, jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), publicJWK.KeyID), &jwt.Claims{
		Issuer:   "https://accounts.google.com",
		Subject:  "google-user",
		Audience: jwt.Audience{"gcp-audience"},
		IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}, map[string]interface{}{
		"email": "dana@example.com",
		"name":  "Dana",
		"hd":    "example.com",
	})

	user, err := provider.VerifyToken(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "example.com", user.TenantID)
	assert.Equal(t, string(ProviderTypeGCP), user.Provider)
}

func TestDIDProviderVerifyToken(t *testing.T) {
	privateKey, publicJWK := mustRSAJWK(t, "did-key")
	provider, err := NewDIDProvider(DIDConfig{TrustedDIDs: []string{"did:example:123"}})
	require.NoError(t, err)

	token := mustSignedToken(t, jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("jwk"), publicJWK.Public()), &jwt.Claims{
		Issuer:   "did:example:123",
		Subject:  "did:example:123",
		Audience: jwt.Audience{"did:example:verifier"},
		IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}, map[string]interface{}{
		"name": "DID User",
	})

	user, err := provider.VerifyToken(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "did:example:123", user.Subject)
	assert.Equal(t, string(ProviderTypeDID), user.Provider)
}

func TestProviderErrors(t *testing.T) {
	privateKey, publicJWK := mustRSAJWK(t, "oidc-key")
	server, issuerURL, _ := newOIDCServer(t, "", &publicJWK)
	defer server.Close()

	provider, err := NewOIDCProvider(&OIDCConfig{IssuerURL: issuerURL, Audience: "api://eunox"}, server.Client())
	require.NoError(t, err)

	validClaims := jwt.Claims{
		Issuer:   issuerURL,
		Subject:  "user-123",
		Audience: jwt.Audience{"api://eunox"},
		IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}

	t.Run("expired token", func(t *testing.T) {
		token := mustSignedToken(t, jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), publicJWK.KeyID), &jwt.Claims{
			Issuer:   issuerURL,
			Subject:  "user-123",
			Audience: jwt.Audience{"api://eunox"},
			IssuedAt: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			Expiry:   jwt.NewNumericDate(time.Now().Add(-time.Hour)),
		}, nil)
		_, err := provider.VerifyToken(context.Background(), token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "validate token claims")
	})

	t.Run("invalid signature", func(t *testing.T) {
		otherPrivateKey, _ := mustRSAJWK(t, "other-key")
		token := mustSignedToken(t, jose.SigningKey{Algorithm: jose.RS256, Key: otherPrivateKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), publicJWK.KeyID), &validClaims, nil)
		_, err := provider.VerifyToken(context.Background(), token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "verify token signature")
	})

	t.Run("malformed token", func(t *testing.T) {
		_, err := provider.VerifyToken(context.Background(), "not-a-jwt")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse token")
	})

	t.Run("missing required claims", func(t *testing.T) {
		token := mustSignedToken(t, jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), publicJWK.KeyID), &jwt.Claims{
			Issuer:   issuerURL,
			Audience: jwt.Audience{"api://eunox"},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}, nil)
		_, err := provider.VerifyToken(context.Background(), token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "subject")
	})

	t.Run("missing required scopes", func(t *testing.T) {
		scopedProvider, err := NewOIDCProvider(&OIDCConfig{IssuerURL: issuerURL, Audience: "api://eunox", RequiredScopes: []string{"openid"}}, server.Client())
		require.NoError(t, err)
		token := mustSignedToken(t, jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), publicJWK.KeyID), &validClaims, map[string]interface{}{"scope": "email"})
		_, err = scopedProvider.VerifyToken(context.Background(), token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "required scopes")
	})

	t.Run("did missing embedded key", func(t *testing.T) {
		didProvider, err := NewDIDProvider(DIDConfig{TrustedDIDs: []string{"did:example:123"}})
		require.NoError(t, err)
		token := mustSignedToken(t, jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, (&jose.SignerOptions{}).WithType("JWT"), &jwt.Claims{
			Issuer:   "did:example:123",
			Subject:  "did:example:123",
			Audience: jwt.Audience{"did:example:verifier"},
			IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}, nil)
		_, err = didProvider.VerifyToken(context.Background(), token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "embedded JWK")
	})
}

func TestConstructorsValidateConfig(t *testing.T) {
	_, err := NewOIDCProvider(&OIDCConfig{}, nil)
	require.Error(t, err)

	_, err = NewCognitoProvider(CognitoConfig{}, nil)
	require.Error(t, err)

	_, err = NewAzureADProvider(AzureADConfig{}, nil)
	require.Error(t, err)

	_, err = NewGCPProvider(GCPConfig{}, nil)
	require.Error(t, err)

	_, err = NewDIDProvider(DIDConfig{})
	require.Error(t, err)
}

func TestNewHTTPJWKSClient_DefaultsHTTPTimeout(t *testing.T) {
	client := NewHTTPJWKSClient(nil, 0)
	require.NotNil(t, client.httpClient)
	assert.Equal(t, defaultHTTPTimeout, client.httpClient.Timeout)
}

func mustRSAJWK(t *testing.T, keyID string) (*rsa.PrivateKey, jose.JSONWebKey) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return privateKey, jose.JSONWebKey{Key: &privateKey.PublicKey, KeyID: keyID, Use: "sig", Algorithm: string(jose.RS256)}
}

func mustSignedToken(t *testing.T, signingKey jose.SigningKey, options *jose.SignerOptions, registered *jwt.Claims, privateClaims map[string]interface{}) string {
	t.Helper()
	signer, err := jose.NewSigner(signingKey, options)
	require.NoError(t, err)

	builder := jwt.Signed(signer).Claims(*registered)
	if privateClaims != nil {
		builder = builder.Claims(privateClaims)
	}
	token, err := builder.Serialize()
	require.NoError(t, err)
	return token
}

func newOIDCServer(t *testing.T, issuerPath string, key *jose.JSONWebKey) (server *httptest.Server, issuerURL string, jwksHitCount *int32) {
	t.Helper()
	var hitCount int32
	issuerPath = trimTrailingSlash(issuerPath)
	if issuerPath == "" {
		issuerPath = ""
	}

	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case issuerPath + "/.well-known/openid-configuration":
			require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"jwks_uri": server.URL + issuerPath + "/jwks"}))
		case issuerPath + "/jwks":
			atomic.AddInt32(&hitCount, 1)
			require.NoError(t, json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{*key}}))
		default:
			http.NotFound(w, r)
		}
	}))

	issuerURL = server.URL + issuerPath
	return server, trimTrailingSlash(issuerURL), &hitCount
}

func newRewriteClient(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	baseURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	client := server.Client()
	baseTransport := client.Transport
	client.Transport = &rewriteTransport{baseURL: baseURL, base: baseTransport}
	return client
}

func trimTrailingSlash(value string) string {
	if value == "/" {
		return ""
	}
	return strings.TrimRight(value, "/")
}

type rewriteTransport struct {
	baseURL *url.URL
	base    http.RoundTripper
}

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = t.baseURL.Scheme
	clone.URL.Host = t.baseURL.Host
	return t.base.RoundTrip(clone)
}

// ─── Finding 2: http.DefaultClient replaced with timeout-configured client ───

// TestNewHTTPJWKSClient_NilClientUsesTimeout verifies that passing a nil
// httpClient to NewHTTPJWKSClient results in a client with a non-zero timeout,
// not the global http.DefaultClient (which has no timeout).
func TestNewHTTPJWKSClient_NilClientUsesTimeout(t *testing.T) {
	jwksClient := NewHTTPJWKSClient(nil, 0)
	require.NotNil(t, jwksClient)
	assert.Equal(t, defaultHTTPTimeout, jwksClient.httpClient.Timeout,
		"nil httpClient must be replaced with a timeout-configured client")
	assert.NotSame(t, http.DefaultClient, jwksClient.httpClient,
		"must not fall back to the global http.DefaultClient")
}

// TestNewHTTPJWKSClient_ExplicitClientPreserved verifies that a caller-supplied
// http.Client is used as-is (its timeout is not overridden).
func TestNewHTTPJWKSClient_ExplicitClientPreserved(t *testing.T) {
	custom := &http.Client{Timeout: 42 * time.Second}
	jwksClient := NewHTTPJWKSClient(custom, 0)
	require.NotNil(t, jwksClient)
	assert.Equal(t, 42*time.Second, jwksClient.httpClient.Timeout,
		"caller-supplied client timeout must not be overridden")
}

// TestNewOIDCProvider_NilClientUsesDefaultTimeout verifies that NewOIDCProvider
// with a nil httpClient successfully creates a provider by using the internal
// timeout-configured client (Finding 2: no more http.DefaultClient fallback).
func TestNewOIDCProvider_NilClientUsesDefaultTimeout(t *testing.T) {
	privateKey, publicJWK := mustRSAJWK(t, "nil-client-key")
	server, issuerURL, _ := newOIDCServer(t, "", &publicJWK)
	defer server.Close()

	_ = privateKey // key only needed to set up the test server

	provider, err := NewOIDCProvider(&OIDCConfig{
		IssuerURL: issuerURL,
		Audience:  "api://test",
	}, nil)
	require.NoError(t, err, "nil httpClient must not cause an error")
	assert.NotNil(t, provider)
}
