// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package agentruntime

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newAllowResponse() *HTTPResponse {
	resp := capability.EnforceResponse{
		RequestID: "req-1",
		Decision:  capability.DecisionAllow,
		DecidedAt: time.Now().UTC().Format(time.RFC3339),
	}
	body, _ := json.Marshal(resp)
	return &HTTPResponse{
		StatusCode: 200,
		Headers:    map[string]string{},
		Body:       body,
	}
}

func newDenyResponse(code, message string) *HTTPResponse {
	resp := capability.EnforceResponse{
		RequestID: "req-1",
		Decision:  capability.DecisionDeny,
		DecidedAt: time.Now().UTC().Format(time.RFC3339),
		Denial: &capability.DenialInfo{
			Code:    code,
			Message: message,
		},
	}
	body, _ := json.Marshal(resp)
	return &HTTPResponse{
		StatusCode: 200,
		Headers:    map[string]string{},
		Body:       body,
	}
}

func setupToolInvoker(t *testing.T, gatewayHandler func(*HTTPRequest) (*HTTPResponse, error)) (*ToolInvoker, *MockHTTPClient) {
	t.Helper()

	issueCount := 0
	client := NewMockHTTPClient(func(req *HTTPRequest) (*HTTPResponse, error) {
		if req.URL == "https://issuer.example.com/api/v1/issue" {
			issueCount++
			return newTestTokenResponse(3600), nil
		}
		return gatewayHandler(req)
	})

	dpopEnabled := false
	tokenProvider := NewAuthTokenProvider(&AuthTokenProviderConfig{
		IssuerURL:     "https://issuer.example.com",
		HTTPClient:    client,
		IdentityToken: "test-identity",
		DPoP:          nil,
		RetryConfig:   RetryConfig{MaxRetries: 1, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
	})

	t.Cleanup(tokenProvider.Stop)

	_ = dpopEnabled
	_ = issueCount

	invoker := NewToolInvoker(&ToolInvokerConfig{
		GatewayURL:    "https://gateway.example.com",
		HTTPClient:    client,
		TokenProvider: tokenProvider,
		RetryConfig:   RetryConfig{MaxRetries: 1, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
	})

	return invoker, client
}

func TestToolInvoker_AllowedRequest(t *testing.T) {
	invoker, _ := setupToolInvoker(t, func(_ *HTTPRequest) (*HTTPResponse, error) {
		return newAllowResponse(), nil
	})

	resp, err := invoker.Invoke(context.Background(), &ToolRequest{
		SessionID:  "session-1",
		ToolName:   "read_file",
		Arguments:  map[string]interface{}{"path": "/etc/hosts"},
		HTTPMethod: "GET",
	})

	require.NoError(t, err)
	assert.True(t, resp.Allowed)
}

func TestToolInvoker_DeniedRequest(t *testing.T) {
	invoker, _ := setupToolInvoker(t, func(_ *HTTPRequest) (*HTTPResponse, error) {
		return newDenyResponse("CAPABILITY_MISMATCH", "no matching capability for action"), nil
	})

	resp, err := invoker.Invoke(context.Background(), &ToolRequest{
		SessionID: "session-1",
		ToolName:  "delete_file",
		Arguments: map[string]interface{}{"path": "/secret"},
	})

	require.NoError(t, err)
	assert.False(t, resp.Allowed)
	assert.NotNil(t, resp.Denial)
	assert.Equal(t, "CAPABILITY_MISMATCH", resp.Denial.Code)
}

func TestToolInvoker_EnforceRequestPayload(t *testing.T) {
	invoker, client := setupToolInvoker(t, func(_ *HTTPRequest) (*HTTPResponse, error) {
		return newAllowResponse(), nil
	})

	_, err := invoker.Invoke(context.Background(), &ToolRequest{
		SessionID: "test-session",
		ToolName:  "write_file",
		Arguments: map[string]interface{}{"path": "/tmp/test.txt", "content": "hello"},
		Context: &ToolRequestContext{
			SourceIP:  "10.0.0.1",
			Operation: "write",
		},
		HTTPMethod: "POST",
	})
	require.NoError(t, err)

	// Find the gateway request (not the issuer request)
	reqs := client.Requests()
	var gatewayReq *HTTPRequest
	for _, r := range reqs {
		if r.URL == "https://gateway.example.com/api/v1/enforce" {
			gatewayReq = r
			break
		}
	}
	require.NotNil(t, gatewayReq)

	var payload enforcePayload
	err = json.Unmarshal(gatewayReq.Body, &payload)
	require.NoError(t, err)

	assert.Equal(t, "test-capability-token", payload.Token)
	assert.Equal(t, "test-session", payload.Request.SessionID)
	assert.Equal(t, "write_file", payload.Request.ToolName)
	assert.Equal(t, "10.0.0.1", payload.Request.Context.SourceIP)
	assert.Equal(t, "write", payload.Request.Context.Operation)
}

func TestToolInvoker_WithDPoP(t *testing.T) {
	dpop, err := NewDPoPProofGenerator()
	require.NoError(t, err)

	client := NewMockHTTPClient(func(req *HTTPRequest) (*HTTPResponse, error) {
		if req.URL == "https://issuer.example.com/api/v1/issue" {
			return newTestTokenResponse(3600), nil
		}
		return newAllowResponse(), nil
	})

	tokenProvider := NewAuthTokenProvider(&AuthTokenProviderConfig{
		IssuerURL:     "https://issuer.example.com",
		HTTPClient:    client,
		IdentityToken: "test-identity",
		DPoP:          dpop,
		RetryConfig:   RetryConfig{MaxRetries: 1, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
	})

	defer tokenProvider.Stop()

	invoker := NewToolInvoker(&ToolInvokerConfig{
		GatewayURL:    "https://gateway.example.com",
		HTTPClient:    client,
		TokenProvider: tokenProvider,
		DPoP:          dpop,
		RetryConfig:   RetryConfig{MaxRetries: 1, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
	})

	resp, err := invoker.Invoke(context.Background(), &ToolRequest{
		SessionID:  "session-1",
		ToolName:   "read_file",
		HTTPMethod: "GET",
		URL:        "https://tools.example.com/files",
	})
	require.NoError(t, err)
	assert.True(t, resp.Allowed)

	// Verify DPoP payload is omitted from enforce request.
	var gatewayReq *HTTPRequest
	var upstreamReq *HTTPRequest
	for _, r := range client.Requests() {
		if r.URL == "https://gateway.example.com/api/v1/enforce" {
			gatewayReq = r
		}
		if r.URL == "https://tools.example.com/files" {
			upstreamReq = r
		}
	}
	require.NotNil(t, gatewayReq)
	require.NotNil(t, upstreamReq)

	var payload enforcePayload
	err = json.Unmarshal(gatewayReq.Body, &payload)
	require.NoError(t, err)
	assert.Nil(t, payload.DPoP)
	assert.NotEmpty(t, upstreamReq.Headers["DPoP"])
}

func TestToolInvoker_UpstreamCall(t *testing.T) {
	client := NewMockHTTPClient(func(req *HTTPRequest) (*HTTPResponse, error) {
		if req.URL == "https://issuer.example.com/api/v1/issue" {
			return newTestTokenResponse(3600), nil
		}
		if req.URL == "https://gateway.example.com/api/v1/enforce" {
			return newAllowResponse(), nil
		}
		// Upstream tool response
		if req.URL == "https://tools.example.com/api/read" {
			return &HTTPResponse{
				StatusCode: 200,
				Headers:    map[string]string{"Content-Type": "application/json"},
				Body:       []byte(`{"data":"result"}`),
			}, nil
		}
		return &HTTPResponse{StatusCode: 404, Headers: map[string]string{}, Body: []byte("not found")}, nil
	})

	tokenProvider := NewAuthTokenProvider(&AuthTokenProviderConfig{
		IssuerURL:     "https://issuer.example.com",
		HTTPClient:    client,
		IdentityToken: "test-identity",
		RetryConfig:   RetryConfig{MaxRetries: 1, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
	})

	defer tokenProvider.Stop()

	invoker := NewToolInvoker(&ToolInvokerConfig{
		GatewayURL:    "https://gateway.example.com",
		HTTPClient:    client,
		TokenProvider: tokenProvider,
		RetryConfig:   RetryConfig{MaxRetries: 1, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
	})

	resp, err := invoker.Invoke(context.Background(), &ToolRequest{
		SessionID:  "session-1",
		ToolName:   "read_file",
		HTTPMethod: "GET",
		URL:        "https://tools.example.com/api/read",
	})

	require.NoError(t, err)
	assert.True(t, resp.Allowed)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, `{"data":"result"}`, string(resp.Body))
}

func TestToolInvoker_GatewayRetry(t *testing.T) {
	callCount := 0
	client := NewMockHTTPClient(func(req *HTTPRequest) (*HTTPResponse, error) {
		if req.URL == "https://issuer.example.com/api/v1/issue" {
			return newTestTokenResponse(3600), nil
		}
		callCount++
		if callCount < 2 {
			return &HTTPResponse{
				StatusCode: 503,
				Headers:    map[string]string{},
				Body:       []byte("service unavailable"),
			}, nil
		}
		return newAllowResponse(), nil
	})

	tokenProvider := NewAuthTokenProvider(&AuthTokenProviderConfig{
		IssuerURL:     "https://issuer.example.com",
		HTTPClient:    client,
		IdentityToken: "test-identity",
		RetryConfig:   RetryConfig{MaxRetries: 1, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
	})

	defer tokenProvider.Stop()

	invoker := NewToolInvoker(&ToolInvokerConfig{
		GatewayURL:    "https://gateway.example.com",
		HTTPClient:    client,
		TokenProvider: tokenProvider,
		RetryConfig:   RetryConfig{MaxRetries: 3, BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond},
	})

	resp, err := invoker.Invoke(context.Background(), &ToolRequest{
		SessionID: "session-1",
		ToolName:  "read_file",
	})

	require.NoError(t, err)
	assert.True(t, resp.Allowed)
	assert.Equal(t, 2, callCount)
}

func TestToolInvoker_NoURL(t *testing.T) {
	invoker, _ := setupToolInvoker(t, func(_ *HTTPRequest) (*HTTPResponse, error) {
		return newAllowResponse(), nil
	})

	// When no URL is provided, just return the enforcement result
	resp, err := invoker.Invoke(context.Background(), &ToolRequest{
		SessionID: "session-1",
		ToolName:  "read_file",
	})

	require.NoError(t, err)
	assert.True(t, resp.Allowed)
	assert.Equal(t, 200, resp.StatusCode)
}

func TestToolInvoker_UpstreamCall_DefaultHTTPMethod(t *testing.T) {
	client := NewMockHTTPClient(func(req *HTTPRequest) (*HTTPResponse, error) {
		if req.URL == "https://issuer.example.com/api/v1/issue" {
			return newTestTokenResponse(3600), nil
		}
		if req.URL == "https://gateway.example.com/api/v1/enforce" {
			return newAllowResponse(), nil
		}
		if req.URL == "https://tools.example.com/api/read" {
			assert.Equal(t, "GET", req.Method)
			return &HTTPResponse{
				StatusCode: 200,
				Headers:    map[string]string{"Content-Type": "application/json"},
				Body:       []byte(`{"data":"result"}`),
			}, nil
		}
		return &HTTPResponse{StatusCode: 404, Headers: map[string]string{}, Body: []byte("not found")}, nil
	})

	tokenProvider := NewAuthTokenProvider(&AuthTokenProviderConfig{
		IssuerURL:     "https://issuer.example.com",
		HTTPClient:    client,
		IdentityToken: "test-identity",
		RetryConfig:   RetryConfig{MaxRetries: 1, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
	})

	defer tokenProvider.Stop()

	invoker := NewToolInvoker(&ToolInvokerConfig{
		GatewayURL:    "https://gateway.example.com",
		HTTPClient:    client,
		TokenProvider: tokenProvider,
		RetryConfig:   RetryConfig{MaxRetries: 1, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
	})

	resp, err := invoker.Invoke(context.Background(), &ToolRequest{
		SessionID: "session-1",
		ToolName:  "read_file",
		URL:       "https://tools.example.com/api/read",
	})

	require.NoError(t, err)
	assert.True(t, resp.Allowed)
	assert.Equal(t, 200, resp.StatusCode)
}
