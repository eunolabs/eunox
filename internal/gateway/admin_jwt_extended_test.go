// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package gateway_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eunolabs/eunox/internal/gateway"
)

// --- TEST-1: Admin JWT Verification Extended Tests ---

func TestAdminJWTVerifier_MalformedToken(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	kid := "malformed-test"
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: pub, KeyID: kid, Algorithm: string(jose.EdDSA), Use: "sig"}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	auth := gateway.NewCombinedAdminAuth(gateway.CombinedAdminAuthConfig{
		JWKSURI:     srv.URL,
		JWTAudience: "gateway-admin",
		TenantID:    "tenant-1",
	})

	tests := []struct {
		name  string
		token string
	}{
		{name: "completely invalid string", token: "not.a.jwt.at.all"},
		{name: "empty token after Bearer", token: ""},
		{name: "base64 garbage", token: "******"},
		{name: "single segment", token: "single-segment-no-dots"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/admin/v1/status", http.NoBody)
			req.Header.Set("Authorization", "Bearer "+tt.token)

			_, err := auth.Authenticate(context.Background(), req)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "JWT verification failed")
		})
	}
}

func TestAdminJWTVerifier_AudienceMismatch(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	kid := "aud-test-key"
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: pub, KeyID: kid, Algorithm: string(jose.EdDSA), Use: "sig"}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	auth := gateway.NewCombinedAdminAuth(gateway.CombinedAdminAuthConfig{
		JWKSURI:     srv.URL,
		JWTAudience: "correct-audience",
		TenantID:    "t-1",
	})

	token := signAdminJWT(t, priv, kid, "operator-1", "wrong-audience")
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/status", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)

	_, err = auth.Authenticate(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validate claims")
}

func TestAdminJWTVerifier_MissingSubjectClaim(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	kid := "sub-test-key"
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: pub, KeyID: kid, Algorithm: string(jose.EdDSA), Use: "sig"}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	auth := gateway.NewCombinedAdminAuth(gateway.CombinedAdminAuthConfig{
		JWKSURI:  srv.URL,
		TenantID: "t-1",
	})

	// Sign JWT without subject claim.
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: priv},
		(&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), kid),
	)
	require.NoError(t, err)

	claims := jwt.Claims{
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
	}

	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/status", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+raw)

	_, err = auth.Authenticate(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JWT missing sub claim")
}

func TestAdminJWTVerifier_JWKSEndpointUnavailable(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	auth := gateway.NewCombinedAdminAuth(gateway.CombinedAdminAuthConfig{
		JWKSURI:  srv.URL,
		TenantID: "t-1",
	})

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	token := signAdminJWT(t, priv, "any-kid", "op-1", "")

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/status", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)

	_, err = auth.Authenticate(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JWT verification failed")
}

func TestAdminJWTVerifier_JWKSEndpointReturnsInvalidJSON(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`not valid json`))
	}))
	defer srv.Close()

	auth := gateway.NewCombinedAdminAuth(gateway.CombinedAdminAuthConfig{
		JWKSURI:  srv.URL,
		TenantID: "t-1",
	})

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	token := signAdminJWT(t, priv, "kid-1", "op-1", "")

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/status", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)

	_, err = auth.Authenticate(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JWT verification failed")
}

func TestAdminJWTVerifier_KeyRotation(t *testing.T) {
	t.Parallel()

	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	kid1 := "key-v1"

	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	kid2 := "key-v2"

	var mu sync.Mutex
	currentJWKS := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: pub1, KeyID: kid1, Algorithm: string(jose.EdDSA), Use: "sig"}},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		jwks := currentJWKS
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	// Use short cache TTL so rotation triggers a refetch.
	verifier := gateway.NewAdminJWTVerifier(gateway.AdminJWTVerifierConfig{
		JWKSURI:  srv.URL,
		CacheTTL: 10 * time.Millisecond,
	})

	// Verify with key v1.
	token1 := signAdminJWT(t, priv1, kid1, "op-1", "")
	sub, err := verifier.Verify(context.Background(), token1)
	require.NoError(t, err)
	assert.Equal(t, "op-1", sub)

	// Wait for cache to expire then rotate.
	time.Sleep(20 * time.Millisecond)

	mu.Lock()
	currentJWKS = jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: pub2, KeyID: kid2, Algorithm: string(jose.EdDSA), Use: "sig"}},
	}
	mu.Unlock()

	// Token signed with v2 should work after JWKS refresh.
	token2 := signAdminJWT(t, priv2, kid2, "op-2", "")
	sub, err = verifier.Verify(context.Background(), token2)
	require.NoError(t, err)
	assert.Equal(t, "op-2", sub)
}

func TestAdminJWTVerifier_RSAKey(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := "rsa-key-1"
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: &privateKey.PublicKey, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	auth := gateway.NewCombinedAdminAuth(gateway.CombinedAdminAuthConfig{
		JWKSURI:     srv.URL,
		JWTAudience: "admin",
		TenantID:    "t-1",
	})

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), kid),
	)
	require.NoError(t, err)

	claims := jwt.Claims{
		Subject:  "rsa-operator",
		Audience: jwt.Audience{"admin"},
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
	}

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/status", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)

	identity, err := auth.Authenticate(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "rsa-operator", identity.OperatorID)
}

func TestAdminJWTVerifier_ECDSAKey(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	kid := "ecdsa-key-1"
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: &privateKey.PublicKey, KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	auth := gateway.NewCombinedAdminAuth(gateway.CombinedAdminAuthConfig{
		JWKSURI:  srv.URL,
		TenantID: "t-1",
	})

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: privateKey},
		(&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), kid),
	)
	require.NoError(t, err)

	claims := jwt.Claims{
		Subject:  "ecdsa-operator",
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
	}

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/status", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)

	identity, err := auth.Authenticate(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "ecdsa-operator", identity.OperatorID)
}

func TestAdminJWTVerifier_WrongSignatureKey(t *testing.T) {
	t.Parallel()

	pubA, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	kid := "key-a"

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: pubA, KeyID: kid, Algorithm: string(jose.EdDSA), Use: "sig"}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	auth := gateway.NewCombinedAdminAuth(gateway.CombinedAdminAuthConfig{
		JWKSURI:  srv.URL,
		TenantID: "t-1",
	})

	// Sign with a different key but using the same kid.
	_, privB, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	token := signAdminJWT(t, privB, kid, "op-1", "")

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/status", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)

	_, err = auth.Authenticate(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verify signature")
}

func TestAdminJWTVerifier_ConcurrentVerification(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	kid := "concurrent-key"
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: pub, KeyID: kid, Algorithm: string(jose.EdDSA), Use: "sig"}},
	}

	var fetchCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetchCount.Add(1)
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	auth := gateway.NewCombinedAdminAuth(gateway.CombinedAdminAuthConfig{
		JWKSURI:  srv.URL,
		TenantID: "t-1",
	})

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	errs := make([]error, goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			token := signAdminJWT(t, priv, kid, "op-concurrent", "")
			req := httptest.NewRequest(http.MethodGet, "/admin/v1/status", http.NoBody)
			req.Header.Set("Authorization", "Bearer "+token)

			_, errs[idx] = auth.Authenticate(context.Background(), req)
		}(i)
	}
	wg.Wait()

	for i, e := range errs {
		assert.NoError(t, e, "goroutine %d failed", i)
	}

	// JWKS should be cached — fetch count should be small.
	assert.LessOrEqual(t, fetchCount.Load(), int64(3),
		"JWKS caching should prevent excessive fetches")
}

func TestAdminJWTVerifier_CacheExpiry(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	kid := "cache-test-key"
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: pub, KeyID: kid, Algorithm: string(jose.EdDSA), Use: "sig"}},
	}

	var fetchCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetchCount.Add(1)
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	verifier := gateway.NewAdminJWTVerifier(gateway.AdminJWTVerifierConfig{
		JWKSURI:  srv.URL,
		CacheTTL: 50 * time.Millisecond,
	})

	token := signAdminJWT(t, priv, kid, "op-1", "")

	// First call fetches JWKS.
	_, err = verifier.Verify(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, int64(1), fetchCount.Load())

	// Immediate second call should use cache.
	_, err = verifier.Verify(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, int64(1), fetchCount.Load())

	// Wait for cache to expire.
	time.Sleep(100 * time.Millisecond)

	// Next call should refetch.
	_, err = verifier.Verify(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, int64(2), fetchCount.Load())
}

func TestAdminJWTVerifier_ContextCancellation(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(5 * time.Second):
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	verifier := gateway.NewAdminJWTVerifier(gateway.AdminJWTVerifierConfig{
		JWKSURI: srv.URL,
		Client:  &http.Client{Timeout: 100 * time.Millisecond},
	})

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	token := signAdminJWT(t, priv, "kid", "op-1", "")

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = verifier.Verify(ctx, token)
	require.Error(t, err)
}

func TestAdminJWTVerifier_NotYetValid(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	kid := "nbf-test-key"
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: pub, KeyID: kid, Algorithm: string(jose.EdDSA), Use: "sig"}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	verifier := gateway.NewAdminJWTVerifier(gateway.AdminJWTVerifierConfig{
		JWKSURI: srv.URL,
	})

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: priv},
		(&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), kid),
	)
	require.NoError(t, err)

	claims := jwt.Claims{
		Subject:   "future-op",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		Expiry:    jwt.NewNumericDate(time.Now().Add(2 * time.Hour)),
	}

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)

	_, err = verifier.Verify(context.Background(), token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validate claims")
}

func TestCombinedAdminAuth_XAdminKeyHeader(t *testing.T) {
	t.Parallel()

	auth := gateway.NewCombinedAdminAuth(gateway.CombinedAdminAuthConfig{
		AdminKey: "key-123",
		TenantID: "t-1",
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/status", http.NoBody)
	req.Header.Set("X-Admin-Key", "key-123")

	identity, err := auth.Authenticate(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "t-1", identity.TenantID)
}

func TestCombinedAdminAuth_BearerTakesPrecedence(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	kid := "precedence-key"
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: pub, KeyID: kid, Algorithm: string(jose.EdDSA), Use: "sig"}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	auth := gateway.NewCombinedAdminAuth(gateway.CombinedAdminAuthConfig{
		JWKSURI:  srv.URL,
		AdminKey: "static-key",
		TenantID: "t-1",
	})

	token := signAdminJWT(t, priv, kid, "jwt-operator", "")
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/status", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Admin-Api-Key", "static-key")

	identity, err := auth.Authenticate(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "jwt-operator", identity.OperatorID, "****** should take precedence")
}

func TestCombinedAdminAuth_NoCredentials(t *testing.T) {
	t.Parallel()

	auth := gateway.NewCombinedAdminAuth(gateway.CombinedAdminAuthConfig{
		AdminKey: "key-abc",
		TenantID: "t-1",
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/status", http.NoBody)

	_, err := auth.Authenticate(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no admin credentials provided")
}
