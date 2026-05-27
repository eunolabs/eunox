// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package capability

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/edgeobs/eunox/pkg/circuitbreaker"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeJWKSServer serves a JWKS endpoint containing the provided public key.
func makeJWKSServer(t *testing.T, pub interface{}, kid string) *httptest.Server {
	t.Helper()
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: pub, KeyID: kid, Use: "sig"}},
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
}

// makeCapabilityToken signs a minimal capability JWT for testing.
func makeCapabilityToken(t *testing.T, privateKey interface{}, kid, sub, aud string, exp time.Time) string {
	t.Helper()

	var alg jose.SignatureAlgorithm
	switch privateKey.(type) {
	case *ecdsa.PrivateKey:
		alg = jose.ES256
	case *rsa.PrivateKey:
		alg = jose.RS256
	default:
		t.Fatalf("unsupported key type %T", privateKey)
	}

	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: alg, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	require.NoError(t, err)

	now := time.Now()
	// Use only TokenPayload so its zero-value fields don't overwrite jwt.Claims values.
	// TokenPayload mirrors JWT standard claims directly (iss, sub, aud, iat, exp, jti).
	payload := TokenPayload{
		Subject:       sub,
		Audience:      aud,
		IssuedAt:      now.Unix(),
		ExpiresAt:     exp.Unix(),
		JWTID:         "jti-test",
		SchemaVersion: SchemaVersion,
		Capabilities:  []Constraint{},
	}

	token, err := jwt.Signed(sig).Claims(payload).Serialize()
	require.NoError(t, err)
	return token
}

func TestJWKSClientVerifyToken(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	srv := makeJWKSServer(t, &privateKey.PublicKey, "key-1")
	defer srv.Close()

	client := NewJWKSClient(JWKSClientConfig{
		JWKSURL:    srv.URL,
		Audience:   "test-audience",
		RequireKID: true,
		CacheTTL:   time.Minute,
		Client:     srv.Client(),
	})

	token := makeCapabilityToken(t, privateKey, "key-1", "sub-1", "test-audience", time.Now().Add(time.Hour))
	payload, err := client.VerifyToken(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "sub-1", payload.Subject)
}

func TestJWKSClientVerifyTokenCached(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &privateKey.PublicKey, KeyID: "k1", Use: "sig"}}}
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	client := NewJWKSClient(JWKSClientConfig{
		JWKSURL:  srv.URL,
		CacheTTL: time.Hour,
		Client:   srv.Client(),
	})

	token := makeCapabilityToken(t, privateKey, "k1", "sub-1", "", time.Now().Add(time.Hour))

	_, err = client.VerifyToken(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	_, err = client.VerifyToken(context.Background(), token)
	require.NoError(t, err)
	// Second call should hit cache, not the server again
	assert.Equal(t, 1, callCount)
}

func TestJWKSClientVerifyTokenExpired(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	srv := makeJWKSServer(t, &privateKey.PublicKey, "key-1")
	defer srv.Close()

	client := NewJWKSClient(JWKSClientConfig{
		JWKSURL: srv.URL,
		Client:  srv.Client(),
	})

	// Expired 2 hours ago (well beyond leeway)
	token := makeCapabilityToken(t, privateKey, "key-1", "sub-1", "", time.Now().Add(-2*time.Hour))
	_, err = client.VerifyToken(context.Background(), token)
	require.Error(t, err)
}

func TestJWKSClientVerifyTokenWrongKID(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	srv := makeJWKSServer(t, &privateKey.PublicKey, "key-1")
	defer srv.Close()

	client := NewJWKSClient(JWKSClientConfig{
		JWKSURL:    srv.URL,
		RequireKID: true,
		Client:     srv.Client(),
		CacheTTL:   time.Millisecond, // expire immediately to force refresh
	})

	token := makeCapabilityToken(t, privateKey, "wrong-kid", "sub-1", "", time.Now().Add(time.Hour))
	_, err = client.VerifyToken(context.Background(), token)
	require.Error(t, err)
}

func TestJWKSClientRequireKIDMissing(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	srv := makeJWKSServer(t, &privateKey.PublicKey, "key-1")
	defer srv.Close()

	client := NewJWKSClient(JWKSClientConfig{
		JWKSURL:    srv.URL,
		RequireKID: true,
		Client:     srv.Client(),
	})

	// Build token without kid header
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err)
	claims := jwt.Claims{
		Subject:  "sub",
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}
	token, err := jwt.Signed(sig).Claims(claims).Serialize()
	require.NoError(t, err)

	_, err = client.VerifyToken(context.Background(), token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing required kid")
}

func TestJWKSClientServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := NewJWKSClient(JWKSClientConfig{
		JWKSURL: srv.URL,
		Client:  srv.Client(),
	})

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	token := makeCapabilityToken(t, privateKey, "k", "sub", "", time.Now().Add(time.Hour))
	_, err = client.VerifyToken(context.Background(), token)
	require.Error(t, err)
}

func TestJWKSClientInvalidJWKS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	client := NewJWKSClient(JWKSClientConfig{
		JWKSURL: srv.URL,
		Client:  srv.Client(),
	})

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	token := makeCapabilityToken(t, privateKey, "k", "sub", "", time.Now().Add(time.Hour))
	_, err = client.VerifyToken(context.Background(), token)
	require.Error(t, err)
}

func TestJWKSClientInvalidToken(t *testing.T) {
	srv := makeJWKSServer(t, nil, "")
	defer srv.Close()

	client := NewJWKSClient(JWKSClientConfig{
		JWKSURL: srv.URL,
		Client:  srv.Client(),
	})

	_, err := client.VerifyToken(context.Background(), "not-a-jwt")
	require.Error(t, err)
}

func TestJWKSClientNoKeysInJWKS(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Serve an empty JWKS
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}}
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	client := NewJWKSClient(JWKSClientConfig{
		JWKSURL:  srv.URL,
		Client:   srv.Client(),
		CacheTTL: time.Millisecond,
	})

	token := makeCapabilityToken(t, privateKey, "k", "sub", "", time.Now().Add(time.Hour))
	_, err = client.VerifyToken(context.Background(), token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no matching key")
}

func TestJWKSClientDefaultConfig(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	srv := makeJWKSServer(t, &privateKey.PublicKey, "rsa-1")
	defer srv.Close()

	// Test default config values (nil Client, zero CacheTTL)
	client := NewJWKSClient(JWKSClientConfig{
		JWKSURL: srv.URL,
	})
	assert.Equal(t, 5*time.Minute, client.cacheTTL)
	assert.NotNil(t, client.client)
	assert.NotNil(t, client.logger)
}

func TestJWKSClientContextCancelled(t *testing.T) {
	ready := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(ready)
		// Block until the request context is done
		<-r.Context().Done()
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := NewJWKSClient(JWKSClientConfig{
		JWKSURL: srv.URL,
		Client:  &http.Client{Timeout: 5 * time.Second},
	})

	ctx, cancel := context.WithCancel(context.Background())

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	token := makeCapabilityToken(t, privateKey, "k", "sub", "", time.Now().Add(time.Hour))

	errCh := make(chan error, 1)
	go func() {
		_, err := client.VerifyToken(ctx, token)
		errCh <- err
	}()

	<-ready
	cancel()

	err = <-errCh
	require.Error(t, err)
}

func TestJWKSClientVerifyAudienceMismatch(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	srv := makeJWKSServer(t, &privateKey.PublicKey, "key-1")
	defer srv.Close()

	client := NewJWKSClient(JWKSClientConfig{
		JWKSURL:  srv.URL,
		Audience: "expected-audience",
		Client:   srv.Client(),
	})

	token := makeCapabilityToken(t, privateKey, "key-1", "sub-1", "other-audience", time.Now().Add(time.Hour))
	_, err = client.VerifyToken(context.Background(), token)
	require.Error(t, err)
}

func TestJWKSClientVerifyTokenMissingClaims(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	srv := makeJWKSServer(t, &privateKey.PublicKey, "key-1")
	defer srv.Close()

	client := NewJWKSClient(JWKSClientConfig{
		JWKSURL: srv.URL,
		Client:  srv.Client(),
	})

	// Token missing iat
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "key-1"),
	)
	require.NoError(t, err)
	token, err := jwt.Signed(sig).Claims(map[string]interface{}{
		"exp": time.Now().Add(time.Hour).Unix(),
		"sub": "sub-1",
	}).Serialize()
	require.NoError(t, err)

	_, err = client.VerifyToken(context.Background(), token)
	require.Error(t, err)
}

func TestJWKSClientBreaker_OpensAfterFailures(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	breaker := circuitbreaker.New(circuitbreaker.Config{FailureThreshold: 2, CooldownDuration: time.Minute, HalfOpenMaxProbes: 1})
	client := NewJWKSClient(JWKSClientConfig{JWKSURL: server.URL, Client: server.Client(), Breaker: breaker})
	token := makeCapabilityToken(t, privateKey, "k1", "sub", "", time.Now().Add(time.Hour))

	for range 2 {
		_, err = client.VerifyToken(context.Background(), token)
		require.Error(t, err)
	}
	assert.Equal(t, int32(2), hits.Load())

	_, err = client.VerifyToken(context.Background(), token)
	require.Error(t, err)
	assert.ErrorIs(t, err, circuitbreaker.ErrOpen)
	assert.Equal(t, int32(2), hits.Load())
}

func TestJWKSClientBreaker_HalfOpenAfterCooldown(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	now := time.Now()
	currentTime := now
	breaker := circuitbreaker.New(
		circuitbreaker.Config{FailureThreshold: 1, CooldownDuration: 50 * time.Millisecond, HalfOpenMaxProbes: 1},
		circuitbreaker.WithClock(func() time.Time { return currentTime }),
	)

	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		if hits.Load() == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &privateKey.PublicKey, KeyID: "k1", Use: "sig"}}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	client := NewJWKSClient(JWKSClientConfig{JWKSURL: server.URL, Client: server.Client(), Breaker: breaker})
	token := makeCapabilityToken(t, privateKey, "k1", "sub", "", time.Now().Add(time.Hour))

	_, err = client.VerifyToken(context.Background(), token)
	require.Error(t, err)
	assert.Equal(t, int32(1), hits.Load())

	_, err = client.VerifyToken(context.Background(), token)
	require.Error(t, err)
	assert.True(t, errors.Is(err, circuitbreaker.ErrOpen))
	assert.Equal(t, int32(1), hits.Load())

	currentTime = currentTime.Add(60 * time.Millisecond)
	payload, err := client.VerifyToken(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "sub", payload.Subject)
	assert.Equal(t, int32(2), hits.Load())
	assert.Equal(t, circuitbreaker.StateClosed, breaker.State())
}
