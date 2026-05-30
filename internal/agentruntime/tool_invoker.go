// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package agentruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/eunolabs/eunox/pkg/capability"
)

// ToolInvoker routes tool calls through the gateway enforcement layer.
// It handles token attachment, DPoP proof generation, and enforcement responses.
type ToolInvoker struct {
	gatewayURL    string
	httpClient    HTTPClient
	tokenProvider *AuthTokenProvider
	dpop          *DPoPProofGenerator
	retryConfig   RetryConfig
	logger        *slog.Logger
}

// ToolInvokerConfig configures the ToolInvoker.
type ToolInvokerConfig struct {
	GatewayURL    string
	HTTPClient    HTTPClient
	TokenProvider *AuthTokenProvider
	DPoP          *DPoPProofGenerator
	RetryConfig   RetryConfig
	Logger        *slog.Logger
}

// NewToolInvoker creates a new ToolInvoker.
func NewToolInvoker(cfg *ToolInvokerConfig) *ToolInvoker {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.RetryConfig == (RetryConfig{}) {
		cfg.RetryConfig = DefaultRetryConfig()
	}
	return &ToolInvoker{
		gatewayURL:    cfg.GatewayURL,
		httpClient:    cfg.HTTPClient,
		tokenProvider: cfg.TokenProvider,
		dpop:          cfg.DPoP,
		retryConfig:   cfg.RetryConfig,
		logger:        cfg.Logger,
	}
}

// Invoke executes a tool request through the gateway enforcement layer.
// It acquires a token, generates DPoP proof (if enabled), sends the enforcement
// request to the gateway, and returns the result.
func (inv *ToolInvoker) Invoke(ctx context.Context, req *ToolRequest) (*ToolResponse, error) {
	return RetryFunc(ctx, inv.retryConfig, func(ctx context.Context) (*ToolResponse, error) {
		return inv.invokeOnce(ctx, req)
	})
}

func (inv *ToolInvoker) invokeOnce(ctx context.Context, req *ToolRequest) (*ToolResponse, error) {
	// Acquire token
	token, err := inv.tokenProvider.GetToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("get capability token: %w", err)
	}

	// Build enforcement request context
	var enforceCtx capability.EnforceRequestContext
	if req.Context != nil {
		enforceCtx = capability.EnforceRequestContext{
			SourceIP:   req.Context.SourceIP,
			Recipients: req.Context.Recipients,
			Operation:  req.Context.Operation,
			FilePath:   req.Context.FilePath,
		}
	}

	// Build enforcement request
	enforceReq := enforcePayload{
		Token: token.Token,
		Request: capability.EnforceRequest{
			SessionID: req.SessionID,
			ToolName:  req.ToolName,
			Arguments: req.Arguments,
			Context:   enforceCtx,
		},
	}

	bodyBytes, err := json.Marshal(enforceReq)
	if err != nil {
		return nil, fmt.Errorf("marshal enforce request: %w", err)
	}

	url := inv.gatewayURL + "/api/v1/enforce"
	headers := map[string]string{
		"Content-Type": "application/json",
	}

	resp, err := inv.httpClient.Do(&HTTPRequest{
		Context: ctx,
		Method:  "POST",
		URL:     url,
		Headers: headers,
		Body:    bodyBytes,
	})
	if err != nil {
		return nil, &TransientError{Err: fmt.Errorf("HTTP request to gateway: %w", err)}
	}

	// Handle DPoP nonce from server
	if nonceHeader, ok := resp.Headers["Dpop-Nonce"]; ok && inv.dpop != nil {
		inv.dpop.SetNonce(nonceHeader)
	}

	if resp.StatusCode == 429 || resp.StatusCode >= 500 {
		return nil, &TransientError{
			Err:        fmt.Errorf("gateway returned status %d: %s", resp.StatusCode, string(resp.Body)),
			StatusCode: resp.StatusCode,
		}
	}

	// Parse enforcement response
	var enforceResp capability.EnforceResponse
	if err := json.Unmarshal(resp.Body, &enforceResp); err != nil {
		return nil, fmt.Errorf("unmarshal enforce response: %w", err)
	}

	if enforceResp.Decision != capability.DecisionAllow {
		return &ToolResponse{
			Allowed: false,
			Denial:  enforceResp.Denial,
		}, nil
	}

	// Tool invocation was allowed — execute the upstream tool call
	return inv.callUpstream(ctx, req, token)
}

func (inv *ToolInvoker) callUpstream(ctx context.Context, req *ToolRequest, token *TokenResponse) (*ToolResponse, error) {
	if req.URL == "" {
		// No upstream URL — just return the enforcement result
		return &ToolResponse{
			Allowed:    true,
			StatusCode: 200,
		}, nil
	}

	headers := map[string]string{
		"Authorization": "Bearer " + token.Token,
	}
	for k, v := range req.Headers {
		headers[k] = v
	}

	method := req.HTTPMethod
	if method == "" {
		if len(req.Body) > 0 {
			method = "POST"
		} else {
			method = "GET"
		}
	}

	// Add DPoP proof for the upstream call
	if inv.dpop != nil {
		proof, err := inv.dpop.GenerateProof(method, req.URL)
		if err != nil {
			return nil, fmt.Errorf("generate DPoP proof for upstream: %w", err)
		}
		headers["DPoP"] = proof
	}

	resp, err := inv.httpClient.Do(&HTTPRequest{
		Context: ctx,
		Method:  method,
		URL:     req.URL,
		Headers: headers,
		Body:    req.Body,
	})
	if err != nil {
		return nil, &TransientError{Err: fmt.Errorf("upstream tool call: %w", err)}
	}

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	return &ToolResponse{
		Allowed:    true,
		StatusCode: resp.StatusCode,
		Headers:    resp.Headers,
		Body:       resp.Body,
	}, nil
}

// enforcePayload is the request body for the gateway's POST /api/v1/enforce endpoint.
type enforcePayload struct {
	Token   string                    `json:"token"`
	Request capability.EnforceRequest `json:"request"`
	DPoP    *capability.DPoPProof     `json:"dpop,omitempty"`
}
