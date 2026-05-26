// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package agentruntime

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/edgeobs/eunox/pkg/capability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_RequiredConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		err  string
	}{
		{
			name: "missing issuer URL",
			cfg:  Config{GatewayURL: "https://gw.example.com", IdentityToken: "tok"},
			err:  "IssuerURL is required",
		},
		{
			name: "missing gateway URL",
			cfg:  Config{IssuerURL: "https://issuer.example.com", IdentityToken: "tok"},
			err:  "GatewayURL is required",
		},
		{
			name: "missing identity",
			cfg:  Config{IssuerURL: "https://issuer.example.com", GatewayURL: "https://gw.example.com"},
			err:  "either IdentityToken or IdentityTokenProvider is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(&tt.cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.err)
		})
	}
}

func TestNew_ValidConfig(t *testing.T) {
	client := NewMockHTTPClient(func(_ *HTTPRequest) (*HTTPResponse, error) {
		return newTestTokenResponse(3600), nil
	})

	rt, err := New(&Config{
		IssuerURL:     "https://issuer.example.com",
		GatewayURL:    "https://gw.example.com",
		IdentityToken: "my-id-token",
		HTTPClient:    client,
	})

	require.NoError(t, err)
	require.NotNil(t, rt)
	defer rt.Stop()

	// DPoP is enabled by default
	assert.NotEmpty(t, rt.DPoPThumbprint())
}

func TestNew_DPoPDisabled(t *testing.T) {
	client := NewMockHTTPClient(func(_ *HTTPRequest) (*HTTPResponse, error) {
		return newTestTokenResponse(3600), nil
	})

	dpopDisabled := false
	rt, err := New(&Config{
		IssuerURL:     "https://issuer.example.com",
		GatewayURL:    "https://gw.example.com",
		IdentityToken: "my-id-token",
		HTTPClient:    client,
		DPoPEnabled:   &dpopDisabled,
	})

	require.NoError(t, err)
	defer rt.Stop()

	assert.Empty(t, rt.DPoPThumbprint())
}

func TestRuntime_GetToken(t *testing.T) {
	client := NewMockHTTPClient(func(_ *HTTPRequest) (*HTTPResponse, error) {
		return newTestTokenResponse(3600), nil
	})

	dpopDisabled := false
	rt, err := New(&Config{
		IssuerURL:     "https://issuer.example.com",
		GatewayURL:    "https://gw.example.com",
		IdentityToken: "my-id-token",
		HTTPClient:    client,
		DPoPEnabled:   &dpopDisabled,
	})

	require.NoError(t, err)
	defer rt.Stop()

	token, err := rt.GetToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "test-capability-token", token.Token)
}

func TestRuntime_InvokeTool(t *testing.T) {
	client := NewMockHTTPClient(func(req *HTTPRequest) (*HTTPResponse, error) {
		if req.URL == "https://issuer.example.com/api/v1/issue" {
			return newTestTokenResponse(3600), nil
		}
		if req.URL == "https://gw.example.com/api/v1/enforce" {
			resp := capability.EnforceResponse{
				Decision:  capability.DecisionAllow,
				DecidedAt: time.Now().UTC().Format(time.RFC3339),
			}
			body, _ := json.Marshal(resp)
			return &HTTPResponse{StatusCode: 200, Headers: map[string]string{}, Body: body}, nil
		}
		return &HTTPResponse{StatusCode: 404, Headers: map[string]string{}, Body: []byte("not found")}, nil
	})

	dpopDisabled := false
	rt, err := New(&Config{
		IssuerURL:     "https://issuer.example.com",
		GatewayURL:    "https://gw.example.com",
		IdentityToken: "my-id-token",
		HTTPClient:    client,
		DPoPEnabled:   &dpopDisabled,
	})

	require.NoError(t, err)
	defer rt.Stop()

	resp, err := rt.InvokeTool(context.Background(), &ToolRequest{
		SessionID: "sess-1",
		ToolName:  "read_file",
		Arguments: map[string]interface{}{"path": "/tmp/test"},
	})
	require.NoError(t, err)
	assert.True(t, resp.Allowed)
}

func TestRuntime_WithHintsProvider(t *testing.T) {
	client := NewMockHTTPClient(func(_ *HTTPRequest) (*HTTPResponse, error) {
		return newTestTokenResponse(3600), nil
	})

	manifest, err := NewManifestBuilder("test-agent").
		WithVersion("1.0.0").
		AddResourceAccess("file:///*", "read", "write").
		WithDefaultTTL(300).
		Build()
	require.NoError(t, err)

	dpopDisabled := false
	rt, err := New(&Config{
		IssuerURL:     "https://issuer.example.com",
		GatewayURL:    "https://gw.example.com",
		IdentityToken: "my-id-token",
		HTTPClient:    client,
		DPoPEnabled:   &dpopDisabled,
	},
		WithHintsProvider(NewStaticHintsProvider(manifest)))

	require.NoError(t, err)
	defer rt.Stop()

	_, err = rt.GetToken(context.Background())
	require.NoError(t, err)

	// Verify the TTL hint was sent
	reqs := client.Requests()
	require.NotEmpty(t, reqs)
	var body map[string]interface{}
	_ = json.Unmarshal(reqs[0].Body, &body)
	assert.Equal(t, float64(300), body["ttl"])
}

func TestRuntime_WithIdentityTokenProvider(t *testing.T) {
	client := NewMockHTTPClient(func(_ *HTTPRequest) (*HTTPResponse, error) {
		return newTestTokenResponse(3600), nil
	})

	dpopDisabled := false
	rt, err := New(&Config{
		IssuerURL:  "https://issuer.example.com",
		GatewayURL: "https://gw.example.com",
		IdentityTokenProvider: func(_ context.Context) (string, error) {
			return "dynamic-token", nil
		},
		HTTPClient:  client,
		DPoPEnabled: &dpopDisabled,
	})

	require.NoError(t, err)
	defer rt.Stop()

	_, err = rt.GetToken(context.Background())
	require.NoError(t, err)

	reqs := client.Requests()
	var body map[string]interface{}
	_ = json.Unmarshal(reqs[0].Body, &body)
	assert.Equal(t, "dynamic-token", body["token"])
}
