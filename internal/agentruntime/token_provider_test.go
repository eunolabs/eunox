// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package agentruntime

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestTokenResponse(expiresInSeconds int64) *HTTPResponse { //nolint:unparam // test helper kept parametric for clarity
	resp := TokenResponse{
		Token:     "test-capability-token",
		ExpiresAt: time.Now().Unix() + expiresInSeconds,
		IssuedAt:  time.Now().Unix(),
		TokenID:   "test-token-id",
	}
	body, _ := json.Marshal(resp)
	return &HTTPResponse{
		StatusCode: 200,
		Headers:    map[string]string{},
		Body:       body,
	}
}

func TestAuthTokenProvider_AcquireToken(t *testing.T) {
	client := NewMockHTTPClient(func(_ *HTTPRequest) (*HTTPResponse, error) {
		return newTestTokenResponse(3600), nil
	})

	provider := NewAuthTokenProvider(&AuthTokenProviderConfig{
		IssuerURL:     "https://issuer.example.com",
		HTTPClient:    client,
		IdentityToken: "test-identity-token",
		RetryConfig:   RetryConfig{MaxRetries: 1, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
	})

	defer provider.Stop()

	token, err := provider.GetToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "test-capability-token", token.Token)
	assert.Equal(t, "test-token-id", token.TokenID)

	// Verify the request was made to the correct URL
	reqs := client.Requests()
	require.Len(t, reqs, 1)
	assert.Equal(t, "POST", reqs[0].Method)
	assert.Equal(t, "https://issuer.example.com/api/v1/issue", reqs[0].URL)
}

func TestAuthTokenProvider_TokenCaching(t *testing.T) {
	callCount := 0
	client := NewMockHTTPClient(func(_ *HTTPRequest) (*HTTPResponse, error) {
		callCount++
		return newTestTokenResponse(3600), nil
	})

	provider := NewAuthTokenProvider(&AuthTokenProviderConfig{
		IssuerURL:     "https://issuer.example.com",
		HTTPClient:    client,
		IdentityToken: "test-identity-token",
		RefreshBefore: 30 * time.Second,
		RetryConfig:   RetryConfig{MaxRetries: 1, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
	})

	defer provider.Stop()

	// First call acquires the token
	token1, err := provider.GetToken(context.Background())
	require.NoError(t, err)

	// Second call should return cached token
	token2, err := provider.GetToken(context.Background())
	require.NoError(t, err)

	assert.Equal(t, token1.Token, token2.Token)
	assert.Equal(t, 1, callCount)
}

func TestAuthTokenProvider_ProactiveRefresh(t *testing.T) {
	callCount := 0
	client := NewMockHTTPClient(func(_ *HTTPRequest) (*HTTPResponse, error) {
		callCount++
		return newTestTokenResponse(3600), nil
	})

	provider := NewAuthTokenProvider(&AuthTokenProviderConfig{
		IssuerURL:     "https://issuer.example.com",
		HTTPClient:    client,
		IdentityToken: "test-identity-token",
		RefreshBefore: 30 * time.Second,
		RetryConfig:   RetryConfig{MaxRetries: 1, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
	})

	defer provider.Stop()

	// Set nowFunc to simulate time passing
	provider.nowFunc = time.Now

	// Acquire initial token
	token1, err := provider.GetToken(context.Background())
	require.NoError(t, err)
	require.NotNil(t, token1)

	// Simulate token about to expire (within refresh window)
	provider.nowFunc = func() time.Time {
		return time.Unix(token1.ExpiresAt-10, 0) // 10s before expiry
	}

	// This should trigger a refresh because we're within the refreshBefore window
	token2, err := provider.GetToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, callCount)
	assert.NotNil(t, token2)
}

func TestAuthTokenProvider_DPoPBinding(t *testing.T) {
	client := NewMockHTTPClient(func(_ *HTTPRequest) (*HTTPResponse, error) {
		return newTestTokenResponse(3600), nil
	})

	dpop, err := NewDPoPProofGenerator()
	require.NoError(t, err)

	provider := NewAuthTokenProvider(&AuthTokenProviderConfig{
		IssuerURL:     "https://issuer.example.com",
		HTTPClient:    client,
		DPoP:          dpop,
		IdentityToken: "test-identity-token",
		RetryConfig:   RetryConfig{MaxRetries: 1, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
	})

	defer provider.Stop()

	_, err = provider.GetToken(context.Background())
	require.NoError(t, err)

	// Verify the request includes DPoP binding
	reqs := client.Requests()
	require.Len(t, reqs, 1)

	var body map[string]interface{}
	err = json.Unmarshal(reqs[0].Body, &body)
	require.NoError(t, err)

	dpopBinding, ok := body["dpop"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, dpop.Thumbprint(), dpopBinding["jkt"])

	// Verify DPoP header is present
	assert.NotEmpty(t, reqs[0].Headers["DPoP"])
}

func TestAuthTokenProvider_NonceFromServer(t *testing.T) {
	dpop, err := NewDPoPProofGenerator()
	require.NoError(t, err)

	callCount := 0
	client := NewMockHTTPClient(func(_ *HTTPRequest) (*HTTPResponse, error) {
		callCount++
		resp := newTestTokenResponse(3600)
		resp.Headers["Dpop-Nonce"] = "server-nonce-abc"
		return resp, nil
	})

	provider := NewAuthTokenProvider(&AuthTokenProviderConfig{
		IssuerURL:     "https://issuer.example.com",
		HTTPClient:    client,
		DPoP:          dpop,
		IdentityToken: "test-identity-token",
		RetryConfig:   RetryConfig{MaxRetries: 1, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
	})

	defer provider.Stop()

	_, err = provider.GetToken(context.Background())
	require.NoError(t, err)

	// Verify the nonce was stored in the DPoP generator
	proof, err := dpop.GenerateProof("POST", "https://example.com")
	require.NoError(t, err)
	claims, err := VerifyDPoPProof(proof)
	require.NoError(t, err)
	assert.Equal(t, "server-nonce-abc", claims["nonce"])
}

func TestAuthTokenProvider_RetryOnTransientError(t *testing.T) {
	callCount := 0
	client := NewMockHTTPClient(func(_ *HTTPRequest) (*HTTPResponse, error) {
		callCount++
		if callCount < 3 {
			return &HTTPResponse{
				StatusCode: 503,
				Headers:    map[string]string{},
				Body:       []byte(`{"error":"service unavailable"}`),
			}, nil
		}
		return newTestTokenResponse(3600), nil
	})

	provider := NewAuthTokenProvider(&AuthTokenProviderConfig{
		IssuerURL:     "https://issuer.example.com",
		HTTPClient:    client,
		IdentityToken: "test-identity-token",
		RetryConfig:   RetryConfig{MaxRetries: 3, BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond},
	})

	defer provider.Stop()

	token, err := provider.GetToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "test-capability-token", token.Token)
	assert.Equal(t, 3, callCount)
}

func TestAuthTokenProvider_IdentityTokenProvider(t *testing.T) {
	client := NewMockHTTPClient(func(_ *HTTPRequest) (*HTTPResponse, error) {
		return newTestTokenResponse(3600), nil
	})

	tokenProviderCalled := false
	provider := NewAuthTokenProvider(&AuthTokenProviderConfig{
		IssuerURL:  "https://issuer.example.com",
		HTTPClient: client,
		IdentityTokenProvider: func(_ context.Context) (string, error) {
			tokenProviderCalled = true
			return "fresh-identity-token", nil
		},
		RetryConfig: RetryConfig{MaxRetries: 1, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
	})

	defer provider.Stop()

	_, err := provider.GetToken(context.Background())
	require.NoError(t, err)
	assert.True(t, tokenProviderCalled)

	// Verify the fresh token was used
	reqs := client.Requests()
	var body map[string]interface{}
	_ = json.Unmarshal(reqs[0].Body, &body)
	assert.Equal(t, "fresh-identity-token", body["token"])
}

func TestAuthTokenProvider_NoIdentityToken(t *testing.T) {
	client := NewMockHTTPClient(func(_ *HTTPRequest) (*HTTPResponse, error) {
		return newTestTokenResponse(3600), nil
	})

	provider := NewAuthTokenProvider(&AuthTokenProviderConfig{
		IssuerURL:     "https://issuer.example.com",
		HTTPClient:    client,
		IdentityToken: "",
		RetryConfig:   RetryConfig{MaxRetries: 0, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
	})

	defer provider.Stop()

	_, err := provider.GetToken(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no identity token available")
}

func TestAuthTokenProvider_HTTPError(t *testing.T) {
	client := NewMockHTTPClient(func(_ *HTTPRequest) (*HTTPResponse, error) {
		return nil, errors.New("connection refused")
	})

	provider := NewAuthTokenProvider(&AuthTokenProviderConfig{
		IssuerURL:     "https://issuer.example.com",
		HTTPClient:    client,
		IdentityToken: "test-token",
		RetryConfig:   RetryConfig{MaxRetries: 0, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
	})

	defer provider.Stop()

	_, err := provider.GetToken(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")
}

func TestAuthTokenProvider_NonTransient4xx(t *testing.T) {
	client := NewMockHTTPClient(func(_ *HTTPRequest) (*HTTPResponse, error) {
		return &HTTPResponse{
			StatusCode: 401,
			Headers:    map[string]string{},
			Body:       []byte(`{"error":"unauthorized"}`),
		}, nil
	})

	provider := NewAuthTokenProvider(&AuthTokenProviderConfig{
		IssuerURL:     "https://issuer.example.com",
		HTTPClient:    client,
		IdentityToken: "test-token",
		RetryConfig:   RetryConfig{MaxRetries: 3, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
	})

	defer provider.Stop()

	_, err := provider.GetToken(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")

	// Should not retry on 4xx (non-transient)
	assert.Len(t, client.Requests(), 1)
}

func TestAuthTokenProvider_IssuanceHints(t *testing.T) {
	client := NewMockHTTPClient(func(_ *HTTPRequest) (*HTTPResponse, error) {
		return newTestTokenResponse(3600), nil
	})

	hints := &IssuanceHints{
		TTL:      600,
		Audience: "https://my-service.example.com",
	}

	provider := NewAuthTokenProvider(&AuthTokenProviderConfig{
		IssuerURL:     "https://issuer.example.com",
		HTTPClient:    client,
		IdentityToken: "test-token",
		HintsProvider: &staticTestHints{hints: hints},
		RetryConfig:   RetryConfig{MaxRetries: 1, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
	})

	defer provider.Stop()

	_, err := provider.GetToken(context.Background())
	require.NoError(t, err)

	reqs := client.Requests()
	var body map[string]interface{}
	_ = json.Unmarshal(reqs[0].Body, &body)
	assert.Equal(t, float64(600), body["ttl"])
	assert.Equal(t, "https://my-service.example.com", body["audience"])
}

type staticTestHints struct {
	hints *IssuanceHints
}

func (h *staticTestHints) GetHints(_ context.Context) (*IssuanceHints, error) {
	return h.hints, nil
}
