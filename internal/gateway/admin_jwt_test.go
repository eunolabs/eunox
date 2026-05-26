// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edgeobs/eunox/internal/gateway"
)

func TestCombinedAdminAuth_JWT(t *testing.T) {
	// Generate test key.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// JWKS server.
	kid := "test-key-1"
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			Key:       pub,
			KeyID:     kid,
			Algorithm: string(jose.EdDSA),
			Use:       "sig",
		}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	auth := gateway.NewCombinedAdminAuth(gateway.CombinedAdminAuthConfig{
		JWKSURI:     srv.URL,
		JWTAudience: "gateway-admin",
		AdminKey:    "static-key-123",
		TenantID:    "tenant-1",
	})

	t.Run("valid JWT", func(t *testing.T) {
		token := signAdminJWT(t, priv, kid, "operator-alice", "gateway-admin")
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/status", http.NoBody)
		req.Header.Set("Authorization", "Bearer "+token)

		identity, err := auth.Authenticate(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, "operator-alice", identity.OperatorID)
		assert.Equal(t, "tenant-1", identity.TenantID)
	})

	t.Run("expired JWT", func(t *testing.T) {
		token := signAdminJWTWithExp(t, priv, kid, "op-1", "gateway-admin", time.Now().Add(-1*time.Hour))
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/status", http.NoBody)
		req.Header.Set("Authorization", "Bearer "+token)

		_, err := auth.Authenticate(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "validate claims")
	})

	t.Run("wrong kid", func(t *testing.T) {
		token := signAdminJWT(t, priv, "nonexistent-kid", "op-1", "gateway-admin")
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/status", http.NoBody)
		req.Header.Set("Authorization", "Bearer "+token)

		_, err := auth.Authenticate(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no matching key")
	})

	t.Run("static key fallback", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/status", http.NoBody)
		req.Header.Set("X-Admin-Api-Key", "static-key-123")

		identity, err := auth.Authenticate(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, "admin-key-user", identity.OperatorID)
		assert.Equal(t, "tenant-1", identity.TenantID)
	})

	t.Run("invalid static key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/status", http.NoBody)
		req.Header.Set("X-Admin-Api-Key", "wrong-key")

		_, err := auth.Authenticate(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid admin key")
	})

	t.Run("no credentials", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/status", http.NoBody)

		_, err := auth.Authenticate(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no admin credentials")
	})
}

func TestCombinedAdminAuth_JWTOnly(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	kid := "jwt-only-key"
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

	t.Run("JWT works", func(t *testing.T) {
		token := signAdminJWT(t, priv, kid, "op-jwt", "")
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/status", http.NoBody)
		req.Header.Set("Authorization", "Bearer "+token)

		identity, err := auth.Authenticate(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, "op-jwt", identity.OperatorID)
	})

	t.Run("static key not configured", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/status", http.NoBody)
		req.Header.Set("X-Admin-Api-Key", "some-key")

		_, err := auth.Authenticate(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "admin key not configured")
	})
}

func TestCombinedAdminAuth_StaticKeyOnly(t *testing.T) {
	auth := gateway.NewCombinedAdminAuth(gateway.CombinedAdminAuthConfig{
		AdminKey: "key-abc",
		TenantID: "t-2",
	})

	t.Run("static key works", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/status", http.NoBody)
		req.Header.Set("X-Admin-Api-Key", "key-abc")

		identity, err := auth.Authenticate(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, "admin-key-user", identity.OperatorID)
	})

	t.Run("bearer without JWT verifier", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/status", http.NoBody)
		req.Header.Set("Authorization", "Bearer fake-jwt")

		_, err := auth.Authenticate(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "JWT auth not configured")
	})
}

// --- Helper ---

func signAdminJWT(t *testing.T, key ed25519.PrivateKey, kid, subject, audience string) string {
	t.Helper()
	return signAdminJWTWithExp(t, key, kid, subject, audience, time.Now().Add(1*time.Hour))
}

func signAdminJWTWithExp(t *testing.T, key ed25519.PrivateKey, kid, subject, audience string, expiry time.Time) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: key},
		(&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), kid),
	)
	require.NoError(t, err)

	claims := jwt.Claims{
		Subject:  subject,
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(expiry),
	}
	if audience != "" {
		claims.Audience = jwt.Audience{audience}
	}

	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return raw
}
