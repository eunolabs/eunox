// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package adapters

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/edgeobs/euno-platform/euno-go/internal/agentruntime"
	"github.com/edgeobs/euno-platform/euno-go/pkg/capability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockHTTPClient implements agentruntime.HTTPClient for testing.
type mockHTTPClient struct {
	handler func(*agentruntime.HTTPRequest) (*agentruntime.HTTPResponse, error)
}

func (m *mockHTTPClient) Do(req *agentruntime.HTTPRequest) (*agentruntime.HTTPResponse, error) {
	return m.handler(req)
}

func newTestRuntime(t *testing.T, gatewayDecision capability.Decision) *agentruntime.Runtime {
	t.Helper()

	client := &mockHTTPClient{
		handler: func(req *agentruntime.HTTPRequest) (*agentruntime.HTTPResponse, error) {
			if req.URL == "https://issuer.example.com/api/v1/issue" {
				resp := agentruntime.TokenResponse{
					Token:     "test-token",
					ExpiresAt: time.Now().Unix() + 3600,
					IssuedAt:  time.Now().Unix(),
					TokenID:   "tid-1",
				}
				body, _ := json.Marshal(resp)
				return &agentruntime.HTTPResponse{StatusCode: 200, Headers: map[string]string{}, Body: body}, nil
			}
			if req.URL == "https://gateway.example.com/api/v1/enforce" {
				resp := capability.EnforceResponse{
					Decision:  gatewayDecision,
					DecidedAt: time.Now().UTC().Format(time.RFC3339),
				}
				if gatewayDecision == capability.DecisionDeny {
					resp.Denial = &capability.DenialInfo{
						Code:    "DENIED",
						Message: "access denied by policy",
					}
				}
				body, _ := json.Marshal(resp)
				return &agentruntime.HTTPResponse{StatusCode: 200, Headers: map[string]string{}, Body: body}, nil
			}
			// Upstream tool
			return &agentruntime.HTTPResponse{
				StatusCode: 200,
				Headers:    map[string]string{"Content-Type": "application/json"},
				Body:       []byte(`{"result":"success"}`),
			}, nil
		},
	}

	dpopDisabled := false
	rt, err := agentruntime.New(agentruntime.Config{
		IssuerURL:     "https://issuer.example.com",
		GatewayURL:    "https://gateway.example.com",
		IdentityToken: "id-token",
		HTTPClient:    client,
		DPoPEnabled:   &dpopDisabled,
	})
	require.NoError(t, err)
	t.Cleanup(rt.Stop)
	return rt
}

// --- HTTP Adapter Tests ---

func TestHTTPAdapter_Call(t *testing.T) {
	rt := newTestRuntime(t, capability.DecisionAllow)
	adapter := NewHTTPAdapter(rt, "https://tools.example.com", "session-1")

	resp, err := adapter.Call(context.Background(), HTTPToolCall{
		ToolName:  "read_file",
		Method:    "GET",
		Path:      "/api/files/test.txt",
		Arguments: map[string]interface{}{"path": "/test.txt"},
	})

	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, `{"result":"success"}`, string(resp.Body))
}

func TestHTTPAdapter_CallDenied(t *testing.T) {
	rt := newTestRuntime(t, capability.DecisionDeny)
	adapter := NewHTTPAdapter(rt, "https://tools.example.com", "session-1")

	_, err := adapter.Call(context.Background(), HTTPToolCall{
		ToolName: "delete_file",
		Method:   "DELETE",
		Path:     "/api/files/secret",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "denied")
}

func TestHTTPAdapter_CallJSON(t *testing.T) {
	rt := newTestRuntime(t, capability.DecisionAllow)
	adapter := NewHTTPAdapter(rt, "https://tools.example.com", "session-1")

	var result map[string]string
	err := adapter.CallJSON(context.Background(), HTTPToolCall{
		ToolName: "get_data",
		Method:   "GET",
		Path:     "/api/data",
	}, &result)

	require.NoError(t, err)
	assert.Equal(t, "success", result["result"])
}

func TestHTTPAdapter_CallJSONRequest(t *testing.T) {
	rt := newTestRuntime(t, capability.DecisionAllow)
	adapter := NewHTTPAdapter(rt, "https://tools.example.com", "session-1")

	resp, err := adapter.CallJSONRequest(context.Background(), HTTPToolCall{
		ToolName: "create_file",
		Method:   "POST",
		Path:     "/api/files",
	}, map[string]string{"name": "test.txt"})

	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}

func TestHTTPAdapter_DefaultMethod(t *testing.T) {
	rt := newTestRuntime(t, capability.DecisionAllow)
	adapter := NewHTTPAdapter(rt, "https://tools.example.com", "session-1")

	// When no method specified, defaults to POST
	resp, err := adapter.Call(context.Background(), HTTPToolCall{
		ToolName: "action",
		Path:     "/api/action",
	})

	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}

// --- LangChain Adapter Tests ---

func TestLangChainAdapter_Call(t *testing.T) {
	rt := newTestRuntime(t, capability.DecisionAllow)
	adapter := NewLangChainAdapter(rt, "session-1",
		Tool{Name: "search", Description: "Search the web"},
		Tool{Name: "calculate", Description: "Calculate math"},
	)

	result := adapter.Call(context.Background(), "search", `{"query":"golang"}`)
	require.NoError(t, result.Error)
	// No upstream URL in this test, so output is empty
	assert.Empty(t, result.Output)
}

func TestLangChainAdapter_CallDenied(t *testing.T) {
	rt := newTestRuntime(t, capability.DecisionDeny)
	adapter := NewLangChainAdapter(rt, "session-1",
		Tool{Name: "search", Description: "Search the web"},
	)

	result := adapter.Call(context.Background(), "search", `{"query":"secret"}`)
	require.Error(t, result.Error)
	assert.Contains(t, result.Error.Error(), "denied")
}

func TestLangChainAdapter_InvalidJSON(t *testing.T) {
	rt := newTestRuntime(t, capability.DecisionAllow)
	adapter := NewLangChainAdapter(rt, "session-1")

	result := adapter.Call(context.Background(), "tool", "not-json{")
	require.Error(t, result.Error)
	assert.Contains(t, result.Error.Error(), "invalid tool input JSON")
}

func TestLangChainAdapter_EmptyInput(t *testing.T) {
	rt := newTestRuntime(t, capability.DecisionAllow)
	adapter := NewLangChainAdapter(rt, "session-1")

	result := adapter.Call(context.Background(), "tool", "")
	require.NoError(t, result.Error)
}

func TestLangChainAdapter_CallWithArgs(t *testing.T) {
	rt := newTestRuntime(t, capability.DecisionAllow)
	adapter := NewLangChainAdapter(rt, "session-1")

	result := adapter.CallWithArgs(context.Background(), "search", map[string]interface{}{
		"query": "golang concurrency",
	})
	require.NoError(t, result.Error)
}

func TestLangChainAdapter_Tools(t *testing.T) {
	rt := newTestRuntime(t, capability.DecisionAllow)
	tools := []Tool{
		{Name: "search", Description: "Search"},
		{Name: "calc", Description: "Calculate"},
	}
	adapter := NewLangChainAdapter(rt, "session-1", tools...)

	assert.Equal(t, tools, adapter.Tools())
}

// --- Function Call Adapter Tests ---

func TestFunctionCallAdapter_Invoke(t *testing.T) {
	rt := newTestRuntime(t, capability.DecisionAllow)
	adapter := NewFunctionCallAdapter(rt, "session-1")

	result, err := adapter.Invoke(context.Background(), "read_file", map[string]interface{}{
		"path": "/test.txt",
	})

	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

func TestFunctionCallAdapter_InvokeDenied(t *testing.T) {
	rt := newTestRuntime(t, capability.DecisionDeny)
	adapter := NewFunctionCallAdapter(rt, "session-1")

	result, err := adapter.Invoke(context.Background(), "delete_file", map[string]interface{}{
		"path": "/secret",
	})

	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.DenialMessage, "denied")
}

func TestFunctionCallAdapter_RegisterHandler(t *testing.T) {
	rt := newTestRuntime(t, capability.DecisionAllow)
	adapter := NewFunctionCallAdapter(rt, "session-1")

	adapter.RegisterHandler("compute", func(_ context.Context, args map[string]interface{}, _ *agentruntime.ToolResponse) (interface{}, error) {
		return map[string]interface{}{
			"computed": true,
			"input":   args["x"],
		}, nil
	})

	result, err := adapter.Invoke(context.Background(), "compute", map[string]interface{}{
		"x": 42,
	})

	require.NoError(t, err)
	assert.True(t, result.Allowed)
	m := result.Result.(map[string]interface{})
	assert.Equal(t, true, m["computed"])
	assert.Equal(t, 42, m["input"])
}

func TestFunctionCallAdapter_InvokeWithURL(t *testing.T) {
	rt := newTestRuntime(t, capability.DecisionAllow)
	adapter := NewFunctionCallAdapter(rt, "session-1")

	result, err := adapter.InvokeWithURL(
		context.Background(),
		"read_file",
		map[string]interface{}{"path": "/test"},
		"GET",
		"https://tools.example.com/files/test",
		nil,
	)

	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, `{"result":"success"}`, result.Result)
}
