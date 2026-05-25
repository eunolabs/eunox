// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edgeobs/euno-platform/euno-go/internal/gateway"
	"github.com/edgeobs/euno-platform/euno-go/pkg/callcounter"
	"github.com/edgeobs/euno-platform/euno-go/pkg/capability"
	"github.com/edgeobs/euno-platform/euno-go/pkg/did"
	"github.com/edgeobs/euno-platform/euno-go/pkg/enforcement"
	"github.com/edgeobs/euno-platform/euno-go/pkg/federation"
	"github.com/edgeobs/euno-platform/euno-go/pkg/killswitch"
	"github.com/edgeobs/euno-platform/euno-go/pkg/revocation"
)

func TestPartnerTokenVerifier_VerifyPartnerToken(t *testing.T) {
	// Generate a test Ed25519 key pair.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Set up a registry with an approved partner.
	reg := federation.NewPartnerDIDRegistry()
	require.NoError(t, reg.Register("did:web:partner.example.com", "Partner", ""))
	require.NoError(t, reg.Approve("did:web:partner.example.com"))

	// Mock DID resolver that returns the public key.
	resolver := &mockPartnerDIDResolver{keys: map[string][]ed25519.PublicKey{
		"did:web:partner.example.com": {pub},
	}}

	pir := federation.NewPartnerIssuerResolver(federation.PartnerIssuerResolverConfig{
		Registry: reg,
		Resolver: resolver,
		CircuitBreaker: federation.CircuitBreakerConfig{
			FailureThreshold:  3,
			CooldownDuration:  10 * time.Second,
			HalfOpenMaxProbes: 1,
		},
	})

	verifier := gateway.NewPartnerTokenVerifier(gateway.PartnerTokenVerifierConfig{
		Resolver: pir,
		Audience: "https://gateway.euno.ai",
	})

	t.Run("valid partner token", func(t *testing.T) {
		token := signPartnerToken(t, priv, "did:web:partner.example.com", "user-123", "https://gateway.euno.ai")

		result, err := verifier.VerifyPartnerToken(context.Background(), token)
		require.NoError(t, err)
		assert.Equal(t, "did:web:partner.example.com", result.PartnerDID)
		assert.True(t, result.CrossOrg)
		assert.Equal(t, "user-123", result.Claims.Subject)
	})

	t.Run("expired token", func(t *testing.T) {
		token := signPartnerTokenWithExp(t, priv, "did:web:partner.example.com", "user-1",
			"https://gateway.euno.ai", time.Now().Add(-1*time.Hour).Unix())

		_, err := verifier.VerifyPartnerToken(context.Background(), token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("non-DID issuer", func(t *testing.T) {
		token := signPartnerToken(t, priv, "https://auth.example.com", "user-1", "")

		_, err := verifier.VerifyPartnerToken(context.Background(), token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a DID")
	})

	t.Run("unknown partner", func(t *testing.T) {
		token := signPartnerToken(t, priv, "did:web:unknown.com", "user-1", "")

		_, err := verifier.VerifyPartnerToken(context.Background(), token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "resolve partner issuer")
	})

	t.Run("audience mismatch", func(t *testing.T) {
		token := signPartnerToken(t, priv, "did:web:partner.example.com", "user-1", "https://wrong.example.com")

		_, err := verifier.VerifyPartnerToken(context.Background(), token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "audience mismatch")
	})
}

func TestMultiIssuerVerifier_VerifyToken(t *testing.T) {
	t.Run("local success", func(t *testing.T) {
		claims := &capability.TokenPayload{
			Issuer:  "https://local.euno.ai",
			Subject: "user-1",
		}
		local := &mockLocalJWTVerifier{claims: claims}
		multi := gateway.NewMultiIssuerVerifier(gateway.MultiIssuerVerifierConfig{
			LocalVerifier: local,
		})

		result, err := multi.VerifyToken(context.Background(), "any-token")
		require.NoError(t, err)
		assert.Equal(t, "user-1", result.Subject)
	})

	t.Run("local fails, partner nil", func(t *testing.T) {
		local := &mockLocalJWTVerifier{err: assert.AnError}
		multi := gateway.NewMultiIssuerVerifier(gateway.MultiIssuerVerifierConfig{
			LocalVerifier: local,
		})

		_, err := multi.VerifyToken(context.Background(), "bad-token")
		require.Error(t, err)
	})
}

func TestIONHealthEndpoint(t *testing.T) {
	t.Run("unconfigured", func(t *testing.T) {
		app, _, _ := newTestApp(t, &mockLocalJWTVerifier{claims: &capability.TokenPayload{}})
		req := httptest.NewRequest(http.MethodGet, "/healthz/did-ion", nil)
		rr := httptest.NewRecorder()
		app.Handler().ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
		assert.Equal(t, "unconfigured", resp["status"])
	})

	t.Run("healthy", func(t *testing.T) {
		// Start a mock ION endpoint.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"did:ion:test"}`))
		}))
		defer srv.Close()

		ionResolver := did.NewIONResolver(did.WithIONEndpoint(srv.URL + "/"))
		app := newTestAppWithION(t, ionResolver)

		req := httptest.NewRequest(http.MethodGet, "/healthz/did-ion", nil)
		rr := httptest.NewRecorder()
		app.Handler().ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
		assert.Equal(t, "healthy", resp["status"])
	})

	t.Run("unhealthy", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		ionResolver := did.NewIONResolver(did.WithIONEndpoint(srv.URL + "/"))
		app := newTestAppWithION(t, ionResolver)

		req := httptest.NewRequest(http.MethodGet, "/healthz/did-ion", nil)
		rr := httptest.NewRecorder()
		app.Handler().ServeHTTP(rr, req)

		assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
		assert.Equal(t, "unhealthy", resp["status"])
	})
}

func newTestAppWithION(t *testing.T, ionResolver *did.IONResolver) *gateway.App {
	t.Helper()
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ks := killswitch.NewInMemory()
	revStore := revocation.NewInMemory()
	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	deps := gateway.Dependencies{
		Engine:      engine,
		KillSwitch:  ks,
		Revocation:  revStore,
		JWTVerifier: &mockLocalJWTVerifier{claims: &capability.TokenPayload{}},
		DPoPStore:   dpopStore,
		Logger:      logger,
		IONResolver: ionResolver,
	}

	cfg := gateway.Config{
		GatewayAudience: "test-gateway",
		AllowedOrigins:  []string{"http://localhost:3000"},
	}

	return gateway.New(cfg, deps)
}

// --- Test Helpers ---

func signPartnerToken(t *testing.T, key ed25519.PrivateKey, issuer, subject, audience string) string {
	t.Helper()
	return signPartnerTokenWithExp(t, key, issuer, subject, audience, time.Now().Add(1*time.Hour).Unix())
}

func signPartnerTokenWithExp(t *testing.T, key ed25519.PrivateKey, issuer, subject, audience string, exp int64) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key}, nil)
	require.NoError(t, err)

	claims := capability.TokenPayload{
		Issuer:    issuer,
		Subject:   subject,
		Audience:  audience,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: exp,
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return raw
}

type mockLocalJWTVerifier struct {
	claims *capability.TokenPayload
	err    error
}

func (m *mockLocalJWTVerifier) VerifyToken(_ context.Context, _ string) (*capability.TokenPayload, error) {
	return m.claims, m.err
}

// mockPartnerDIDResolver returns pre-configured keys for partner DIDs.
type mockPartnerDIDResolver struct {
	keys map[string][]ed25519.PublicKey
}

func (m *mockPartnerDIDResolver) Resolve(_ context.Context, didURI string) (*did.Document, error) {
	keys, ok := m.keys[didURI]
	if !ok {
		return nil, assert.AnError
	}
	doc := &did.Document{
		ID:                 didURI,
		VerificationMethod: make([]did.VerificationMethod, 0, len(keys)),
	}
	for i, k := range keys {
		doc.VerificationMethod = append(doc.VerificationMethod, did.VerificationMethod{
			ID:         didURI + "#key-" + string(rune('0'+i)),
			Type:       "Ed25519VerificationKey2020",
			Controller: didURI,
			PublicKeyMultibase: encodeEd25519Multibase(k),
		})
	}
	return doc, nil
}

func encodeEd25519Multibase(pub ed25519.PublicKey) string {
	// Encode as multicodec: 0xed 0x01 prefix + raw key, then base58btc with 'z' prefix.
	data := make([]byte, 0, 2+len(pub))
	data = append(data, 0xed, 0x01)
	data = append(data, pub...)
	return "z" + base58Encode(data)
}

func base58Encode(data []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	// Simple big-endian base58 encoding.
	if len(data) == 0 {
		return ""
	}
	// Count leading zeros.
	var leadingZeros int
	for _, b := range data {
		if b != 0 {
			break
		}
		leadingZeros++
	}
	// Convert to base58.
	size := len(data)*138/100 + 1
	buf := make([]byte, size)
	for _, b := range data {
		carry := int(b)
		for i := size - 1; i >= 0; i-- {
			carry += 256 * int(buf[i])
			buf[i] = byte(carry % 58)
			carry /= 58
		}
	}
	// Skip leading zeros in buf.
	start := 0
	for start < len(buf) && buf[start] == 0 {
		start++
	}
	result := make([]byte, leadingZeros+len(buf)-start)
	for i := range leadingZeros {
		result[i] = alphabet[0]
	}
	for i, b := range buf[start:] {
		result[leadingZeros+i] = alphabet[b]
	}
	return string(result)
}
