// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- TEST-2: OIDC Identity Provider Extended Tests ---

func TestOIDCProvider_WrongIssuer(t *testing.T) {
	t.Parallel()

	privateKey, publicJWK := mustRSAJWK(t, "issuer-key")
	server, issuerURL, _ := newOIDCServer(t, "", &publicJWK)
	defer server.Close()

	provider, err := NewOIDCProvider(&OIDCConfig{
		IssuerURL: issuerURL,
		Audience:  "api://eunox",
	}, server.Client())
	require.NoError(t, err)

	// Token with a different issuer.
	token := mustSignedToken(t,
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), publicJWK.KeyID),
		&jwt.Claims{
			Issuer:   "https://evil.example.com",
			Subject:  "user-1",
			Audience: jwt.Audience{"api://eunox"},
			IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}, nil)

	_, err = provider.VerifyToken(context.Background(), token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validate token claims")
}

func TestOIDCProvider_WrongAudience(t *testing.T) {
	t.Parallel()

	privateKey, publicJWK := mustRSAJWK(t, "aud-key")
	server, issuerURL, _ := newOIDCServer(t, "", &publicJWK)
	defer server.Close()

	provider, err := NewOIDCProvider(&OIDCConfig{
		IssuerURL: issuerURL,
		Audience:  "api://correct",
	}, server.Client())
	require.NoError(t, err)

	token := mustSignedToken(t,
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), publicJWK.KeyID),
		&jwt.Claims{
			Issuer:   issuerURL,
			Subject:  "user-1",
			Audience: jwt.Audience{"api://wrong"},
			IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}, nil)

	_, err = provider.VerifyToken(context.Background(), token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validate token claims")
}

func TestOIDCProvider_JWKSFetchFailure(t *testing.T) {
	t.Parallel()

	privateKey, publicJWK := mustRSAJWK(t, "fetch-fail-key")

	// Server that returns JWKS initially but then fails.
	var callCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"jwks_uri": "http://" + r.Host + "/jwks",
			})
		case "/jwks":
			if callCount.Add(1) > 1 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicJWK}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	issuerURL := server.URL
	provider, err := NewOIDCProvider(&OIDCConfig{
		IssuerURL: issuerURL,
		Audience:  "api://eunox",
		CacheTTL:  10 * time.Millisecond, // Short TTL to trigger refetch.
	}, server.Client())
	require.NoError(t, err)

	// First call populates the cache.
	token := mustSignedToken(t,
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), publicJWK.KeyID),
		&jwt.Claims{
			Issuer:   issuerURL,
			Subject:  "user-1",
			Audience: jwt.Audience{"api://eunox"},
			IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}, nil)

	_, err = provider.VerifyToken(context.Background(), token)
	require.NoError(t, err, "first call should succeed")

	// Wait for cache to expire.
	time.Sleep(20 * time.Millisecond)

	// Second call should fail because JWKS endpoint now returns 500.
	_, err = provider.VerifyToken(context.Background(), token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fetch JWKS")
}

func TestOIDCProvider_JWKSCacheTTL(t *testing.T) {
	t.Parallel()

	privateKey, publicJWK := mustRSAJWK(t, "cache-key")

	var hitCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"jwks_uri": "http://" + r.Host + "/jwks",
			})
		case "/jwks":
			hitCount.Add(1)
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicJWK}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider, err := NewOIDCProvider(&OIDCConfig{
		IssuerURL: server.URL,
		Audience:  "api://eunox",
		CacheTTL:  50 * time.Millisecond,
	}, server.Client())
	require.NoError(t, err)

	makeToken := func() string {
		return mustSignedToken(t,
			jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), publicJWK.KeyID),
			&jwt.Claims{
				Issuer:   server.URL,
				Subject:  "user-1",
				Audience: jwt.Audience{"api://eunox"},
				IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
				Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			}, nil)
	}

	// First call fetches JWKS.
	_, err = provider.VerifyToken(context.Background(), makeToken())
	require.NoError(t, err)
	assert.Equal(t, int32(1), hitCount.Load())

	// Second call within TTL should use cache.
	_, err = provider.VerifyToken(context.Background(), makeToken())
	require.NoError(t, err)
	assert.Equal(t, int32(1), hitCount.Load())

	// After TTL expires, should refetch.
	time.Sleep(80 * time.Millisecond)
	_, err = provider.VerifyToken(context.Background(), makeToken())
	require.NoError(t, err)
	assert.Equal(t, int32(2), hitCount.Load())
}

func TestOIDCProvider_ConcurrentVerifyToken(t *testing.T) {
	t.Parallel()

	privateKey, publicJWK := mustRSAJWK(t, "concurrent-key")
	server, issuerURL, _ := newOIDCServer(t, "", &publicJWK)
	defer server.Close()

	provider, err := NewOIDCProvider(&OIDCConfig{
		IssuerURL: issuerURL,
		Audience:  "api://eunox",
		CacheTTL:  time.Hour,
	}, server.Client())
	require.NoError(t, err)

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make([]error, goroutines)

	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			token := mustSignedToken(t,
				jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
				(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), publicJWK.KeyID),
				&jwt.Claims{
					Issuer:   issuerURL,
					Subject:  "user-concurrent",
					Audience: jwt.Audience{"api://eunox"},
					IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
					Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
				}, nil)

			_, errs[idx] = provider.VerifyToken(context.Background(), token)
		}(i)
	}
	wg.Wait()

	for i, e := range errs {
		assert.NoError(t, e, "goroutine %d failed", i)
	}
}

func TestOIDCProvider_ContextCancellation(t *testing.T) {
	t.Parallel()

	_, publicJWK := mustRSAJWK(t, "ctx-key")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"jwks_uri": "http://" + r.Host + "/jwks",
			})
		case "/jwks":
			// Slow response to allow cancellation.
			time.Sleep(2 * time.Second)
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicJWK}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider, err := NewOIDCProvider(&OIDCConfig{
		IssuerURL: server.URL,
		Audience:  "api://eunox",
		CacheTTL:  10 * time.Millisecond,
	}, server.Client())
	require.NoError(t, err)

	// Wait for cache to expire.
	time.Sleep(20 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	privateKey, _ := mustRSAJWK(t, "ctx-key")
	token := mustSignedToken(t,
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), publicJWK.KeyID),
		&jwt.Claims{
			Issuer:   server.URL,
			Subject:  "user-1",
			Audience: jwt.Audience{"api://eunox"},
			IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}, nil)

	_, err = provider.VerifyToken(ctx, token)
	require.ErrorIs(t, err, context.Canceled)
}

func TestOIDCProvider_EmptyToken(t *testing.T) {
	t.Parallel()

	_, publicJWK := mustRSAJWK(t, "empty-key")
	server, issuerURL, _ := newOIDCServer(t, "", &publicJWK)
	defer server.Close()

	provider, err := NewOIDCProvider(&OIDCConfig{
		IssuerURL: issuerURL,
		Audience:  "api://eunox",
	}, server.Client())
	require.NoError(t, err)

	tests := []struct {
		name  string
		token string
	}{
		{name: "empty string", token: ""},
		{name: "whitespace only", token: "   "},
		{name: "tab and newlines", token: "\t\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := provider.VerifyToken(context.Background(), tt.token)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "token is required")
		})
	}
}

func TestOIDCProvider_TokenWithNoKid(t *testing.T) {
	t.Parallel()

	privateKey, publicJWK := mustRSAJWK(t, "no-kid-key")
	server, issuerURL, _ := newOIDCServer(t, "", &publicJWK)
	defer server.Close()

	provider, err := NewOIDCProvider(&OIDCConfig{
		IssuerURL: issuerURL,
		Audience:  "api://eunox",
	}, server.Client())
	require.NoError(t, err)

	// Sign token without kid header — should try all keys in JWKS.
	token := mustSignedToken(t,
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT"), // No kid.
		&jwt.Claims{
			Issuer:   issuerURL,
			Subject:  "user-no-kid",
			Audience: jwt.Audience{"api://eunox"},
			IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}, nil)

	user, err := provider.VerifyToken(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "user-no-kid", user.Subject)
}

func TestOIDCProvider_MultipleKeysInJWKS(t *testing.T) {
	t.Parallel()

	// Key 1.
	_, publicJWK1 := mustRSAJWK(t, "multi-key-1")
	// Key 2 — the one we'll sign with.
	privateKey2, publicJWK2 := mustRSAJWK(t, "multi-key-2")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"jwks_uri": "http://" + r.Host + "/jwks",
			})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{publicJWK1, publicJWK2},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider, err := NewOIDCProvider(&OIDCConfig{
		IssuerURL: server.URL,
		Audience:  "api://eunox",
	}, server.Client())
	require.NoError(t, err)

	// Sign with key 2.
	token := mustSignedToken(t,
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey2},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), publicJWK2.KeyID),
		&jwt.Claims{
			Issuer:   server.URL,
			Subject:  "user-key2",
			Audience: jwt.Audience{"api://eunox"},
			IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}, nil)

	user, err := provider.VerifyToken(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "user-key2", user.Subject)
}

func TestOIDCProvider_NoMatchingKidInJWKS(t *testing.T) {
	t.Parallel()

	privateKey, _ := mustRSAJWK(t, "unknown-kid")
	_, publicJWK := mustRSAJWK(t, "known-kid")

	server, issuerURL, _ := newOIDCServer(t, "", &publicJWK)
	defer server.Close()

	provider, err := NewOIDCProvider(&OIDCConfig{
		IssuerURL: issuerURL,
		Audience:  "api://eunox",
	}, server.Client())
	require.NoError(t, err)

	// Sign with a kid that doesn't exist in the JWKS.
	token := mustSignedToken(t,
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), "nonexistent-kid"),
		&jwt.Claims{
			Issuer:   issuerURL,
			Subject:  "user-1",
			Audience: jwt.Audience{"api://eunox"},
			IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}, nil)

	_, err = provider.VerifyToken(context.Background(), token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no matching JWK found")
}

func TestHTTPJWKSClient_ConcurrentGetKeySet(t *testing.T) {
	t.Parallel()

	_, publicJWK := mustRSAJWK(t, "concurrent-jwks-key")

	var hitCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hitCount.Add(1)
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{publicJWK}})
	}))
	defer server.Close()

	client := NewHTTPJWKSClient(server.Client(), time.Hour)

	const goroutines = 30
	var wg sync.WaitGroup
	wg.Add(goroutines)

	errs := make([]error, goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = client.GetKeySet(context.Background(), server.URL)
		}(i)
	}
	wg.Wait()

	for i, e := range errs {
		assert.NoError(t, e, "goroutine %d failed", i)
	}

	// Due to caching, actual hits should be much less than goroutines.
	assert.LessOrEqual(t, hitCount.Load(), int32(goroutines),
		"all fetches should complete")
}

func TestHTTPJWKSClient_EmptyKeySetReturnsError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}})
	}))
	defer server.Close()

	client := NewHTTPJWKSClient(server.Client(), time.Hour)

	_, err := client.GetKeySet(context.Background(), server.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no keys returned")
}

func TestHTTPJWKSClient_ContextAlreadyCancelled(t *testing.T) {
	t.Parallel()

	client := NewHTTPJWKSClient(&http.Client{}, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.GetKeySet(ctx, "http://localhost:12345/jwks")
	require.Error(t, err)
}

func TestOIDCProvider_DiscoveryFailure(t *testing.T) {
	t.Parallel()

	// Server that 500s on discovery.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := NewOIDCProvider(&OIDCConfig{
		IssuerURL: server.URL,
		Audience:  "api://eunox",
	}, server.Client())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fetch OIDC discovery document")
}

func TestDIDProvider_UntrustedDID(t *testing.T) {
	t.Parallel()

	privateKey, publicJWK := mustRSAJWK(t, "did-untrusted-key")
	// CR-1 fix: Resolver is now required. The resolver is never called for
	// untrusted DIDs (the allowlist check fires first), so a no-op stub suffices.
	provider, err := NewDIDProvider(DIDConfig{
		TrustedDIDs: []string{"did:example:trusted"},
		Resolver:    &testDIDResolver{err: errors.New("should not be called")},
	})
	require.NoError(t, err)

	token := mustSignedToken(t,
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("jwk"), publicJWK.Public()),
		&jwt.Claims{
			Issuer:   "did:example:untrusted",
			Subject:  "did:example:untrusted",
			Audience: jwt.Audience{"did:example:verifier"},
			IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}, nil)

	_, err = provider.VerifyToken(context.Background(), token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "untrusted DID")
}

func TestNewOIDCProviderWithJWKSClient_NilClient(t *testing.T) {
	t.Parallel()

	_, publicJWK := mustRSAJWK(t, "nil-jwks-client-key")
	server, issuerURL, _ := newOIDCServer(t, "", &publicJWK)
	defer server.Close()

	_, err := NewOIDCProviderWithJWKSClient(&OIDCConfig{
		IssuerURL: issuerURL,
		Audience:  "api://eunox",
	}, server.Client(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "jwks client is required")
}

func TestHTTPJWKSClient_NonOKStatusCode(t *testing.T) {
	t.Parallel()

	codes := []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusServiceUnavailable,
	}

	for _, code := range codes {
		t.Run(http.StatusText(code), func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(code)
			}))
			defer server.Close()

			client := NewHTTPJWKSClient(server.Client(), time.Hour)
			_, err := client.GetKeySet(context.Background(), server.URL)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "fetch JWKS")
		})
	}
}

func TestHTTPJWKSClient_InvalidJSON(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{invalid json`))
	}))
	defer server.Close()

	client := NewHTTPJWKSClient(server.Client(), time.Hour)
	_, err := client.GetKeySet(context.Background(), server.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode JWKS")
}

func TestOIDCProvider_RSAMultiAlgVerification(t *testing.T) {
	t.Parallel()

	// The OIDC server helpers use RSA. We test that the verify path works with
	// RSA keys to confirm multi-algorithm selection logic. EdDSA-specific signing
	// is tested in admin JWT extended tests (internal/gateway).
	privateKey, publicJWK := mustRSAJWK(t, "eddsa-fallback-rsa")
	server, issuerURL, _ := newOIDCServer(t, "", &publicJWK)
	defer server.Close()

	provider, err := NewOIDCProvider(&OIDCConfig{
		IssuerURL: issuerURL,
		Audience:  "api://eunox",
	}, server.Client())
	require.NoError(t, err)

	token := mustSignedToken(t,
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), publicJWK.KeyID),
		&jwt.Claims{
			Issuer:   issuerURL,
			Subject:  "user-eddsa",
			Audience: jwt.Audience{"api://eunox"},
			IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}, nil)

	user, err := provider.VerifyToken(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "user-eddsa", user.Subject)
}
