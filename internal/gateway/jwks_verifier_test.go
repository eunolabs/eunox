// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edgeobs/eunox/internal/gateway"
	"github.com/edgeobs/eunox/pkg/capability"
)

func newTestJWKS(t *testing.T) (*ecdsa.PrivateKey, string, *httptest.Server) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	kid := "test-key-1"
	jwk := jose.JSONWebKey{
		Key:       key.Public(),
		KeyID:     kid,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}

	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(srv.Close)

	return key, kid, srv
}

func signCapabilityToken(t *testing.T, key *ecdsa.PrivateKey, kid string, claims interface{}) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), kid),
	)
	require.NoError(t, err)

	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return raw
}

func TestJWKSVerifier_VerifyToken_Success(t *testing.T) {
	t.Parallel()
	key, kid, srv := newTestJWKS(t)

	verifier := gateway.NewJWKSVerifier(gateway.JWKSVerifierConfig{
		JWKSURL:  srv.URL,
		CacheTTL: 1 * time.Second,
	})

	now := time.Now()
	claims := map[string]interface{}{
		"iss":           "https://issuer.example.com",
		"sub":           "user-123",
		"aud":           "gateway",
		"iat":           now.Unix(),
		"exp":           now.Add(1 * time.Hour).Unix(),
		"jti":           "token-abc",
		"schemaVersion": "1.0",
		"capabilities": []capability.Constraint{
			{Resource: "tool://example/api", Actions: []string{"invoke"}},
		},
	}

	token := signCapabilityToken(t, key, kid, claims)

	payload, err := verifier.VerifyToken(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "https://issuer.example.com", payload.Issuer)
	assert.Equal(t, "user-123", payload.Subject)
	assert.Equal(t, "token-abc", payload.JWTID)
	assert.Equal(t, "1.0", payload.SchemaVersion)
	assert.Len(t, payload.Capabilities, 1)
	assert.Equal(t, "tool://example/api", payload.Capabilities[0].Resource)
}

func TestJWKSVerifier_VerifyToken_ExpiredToken(t *testing.T) {
	t.Parallel()
	key, kid, srv := newTestJWKS(t)

	verifier := gateway.NewJWKSVerifier(gateway.JWKSVerifierConfig{
		JWKSURL:  srv.URL,
		CacheTTL: 1 * time.Second,
	})

	now := time.Now()
	claims := map[string]interface{}{
		"iss": "https://issuer.example.com",
		"sub": "user-123",
		"aud": "gateway",
		"iat": now.Add(-2 * time.Hour).Unix(),
		"exp": now.Add(-1 * time.Hour).Unix(), // expired
		"jti": "token-expired",
	}

	token := signCapabilityToken(t, key, kid, claims)

	_, err := verifier.VerifyToken(context.Background(), token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validate claims")
}

func TestJWKSVerifier_VerifyToken_WrongKey(t *testing.T) {
	t.Parallel()

	// Generate a different key not in the JWKS.
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, _, srv := newTestJWKS(t)

	verifier := gateway.NewJWKSVerifier(gateway.JWKSVerifierConfig{
		JWKSURL:  srv.URL,
		CacheTTL: 1 * time.Second,
	})

	now := time.Now()
	claims := map[string]interface{}{
		"iss": "https://issuer.example.com",
		"sub": "user-123",
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
		"jti": "token-wrong-key",
	}

	// Sign with wrong key but use a kid that matches nothing.
	token := signCapabilityToken(t, wrongKey, "unknown-kid", claims)

	_, err = verifier.VerifyToken(context.Background(), token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no matching key")
}

func TestJWKSVerifier_VerifyToken_RequireKID(t *testing.T) {
	t.Parallel()
	key, _, srv := newTestJWKS(t)

	verifier := gateway.NewJWKSVerifier(gateway.JWKSVerifierConfig{
		JWKSURL:    srv.URL,
		RequireKID: true,
		CacheTTL:   1 * time.Second,
	})

	now := time.Now()
	claims := map[string]interface{}{
		"iss": "https://issuer.example.com",
		"sub": "user-123",
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
	}

	// Sign without kid.
	token := signCapabilityToken(t, key, "", claims)

	_, err := verifier.VerifyToken(context.Background(), token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing required kid")
}

func TestJWKSVerifier_VerifyToken_AudienceCheck(t *testing.T) {
	t.Parallel()
	key, kid, srv := newTestJWKS(t)

	verifier := gateway.NewJWKSVerifier(gateway.JWKSVerifierConfig{
		JWKSURL:  srv.URL,
		Audience: "expected-audience",
		CacheTTL: 1 * time.Second,
	})

	now := time.Now()
	claims := map[string]interface{}{
		"iss": "https://issuer.example.com",
		"sub": "user-123",
		"aud": "wrong-audience",
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
	}

	token := signCapabilityToken(t, key, kid, claims)

	_, err := verifier.VerifyToken(context.Background(), token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validate claims")
}

func TestJWKSVerifier_VerifyToken_JWKSUnavailable(t *testing.T) {
	t.Parallel()

	// Generate a key and sign a valid token so the verifier reaches the JWKS fetch.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	kid := "unavail-key"

	// Point to a server that 500s.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	verifier := gateway.NewJWKSVerifier(gateway.JWKSVerifierConfig{
		JWKSURL:  srv.URL,
		CacheTTL: 1 * time.Second,
	})

	now := time.Now()
	claims := map[string]interface{}{
		"iss": "https://issuer.example.com",
		"sub": "user-123",
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
	}
	token := signCapabilityToken(t, key, kid, claims)

	_, err = verifier.VerifyToken(context.Background(), token)
	require.Error(t, err)
}

func TestJWKSVerifier_VerifyToken_CachesKeys(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	kid := "cache-test-key"
	jwk := jose.JSONWebKey{
		Key:       key.Public(),
		KeyID:     kid,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}

	callCount := int32(0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(srv.Close)

	verifier := gateway.NewJWKSVerifier(gateway.JWKSVerifierConfig{
		JWKSURL:  srv.URL,
		CacheTTL: 10 * time.Minute, // long cache
	})

	now := time.Now()
	claims := map[string]interface{}{
		"iss": "https://issuer.example.com",
		"sub": "user-123",
		"iat": now.Unix(),
		"exp": now.Add(1 * time.Hour).Unix(),
	}

	token := signCapabilityToken(t, key, kid, claims)

	// First call fetches JWKS.
	_, err = verifier.VerifyToken(context.Background(), token)
	require.NoError(t, err)

	// Second call uses cache.
	_, err = verifier.VerifyToken(context.Background(), token)
	require.NoError(t, err)

	assert.Equal(t, int32(1), atomic.LoadInt32(&callCount), "JWKS should be fetched only once due to caching")
}

func TestJWKSVerifier_VerifyToken_InvalidToken(t *testing.T) {
	t.Parallel()
	_, _, srv := newTestJWKS(t)

	verifier := gateway.NewJWKSVerifier(gateway.JWKSVerifierConfig{
		JWKSURL:  srv.URL,
		CacheTTL: 1 * time.Second,
	})

	_, err := verifier.VerifyToken(context.Background(), "not-a-jwt")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse JWT")
}

// TestJWKSVerifier_TracingTransport verifies that the tracing transport
// injected by NewJWKSVerifier propagates outbound headers without breaking
// normal JWKS fetches.  This is a black-box smoke test for P2-4 because OTel
// headers are only present when a real tracing SDK is initialised; here we
// verify that the transport doesn't panic or corrupt requests.
func TestJWKSVerifier_TracingTransport(t *testing.T) {
	t.Parallel()
	key, kid, srv := newTestJWKS(t)

	// The verifier wraps the default HTTP client in a tracingTransport.
	verifier := gateway.NewJWKSVerifier(gateway.JWKSVerifierConfig{
		JWKSURL:  srv.URL,
		CacheTTL: time.Minute,
	})

	now := time.Now()
	claims := map[string]interface{}{
		"iss":           "https://issuer.example.com",
		"sub":           "traced-user",
		"iat":           now.Unix(),
		"exp":           now.Add(time.Hour).Unix(),
		"schemaVersion": "1.0",
	}
	token := signCapabilityToken(t, key, kid, claims)

	// Verification should succeed even when no active span exists.
	payload, err := verifier.VerifyToken(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "traced-user", payload.Subject)
}
