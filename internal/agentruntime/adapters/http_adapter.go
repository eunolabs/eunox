// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package adapters provides framework-specific adapters for the agent runtime.
package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/edgeobs/eunox/internal/agentruntime"
)

// HTTPAdapter adapts the agent runtime for generic HTTP/REST-based tool calls.
// It wraps an upstream HTTP service with Euno enforcement.
type HTTPAdapter struct {
	runtime   *agentruntime.Runtime
	baseURL   string
	sessionID string
}

// NewHTTPAdapter creates a new HTTPAdapter that routes requests through the given runtime.
func NewHTTPAdapter(rt *agentruntime.Runtime, baseURL, sessionID string) *HTTPAdapter {
	return &HTTPAdapter{
		runtime:   rt,
		baseURL:   strings.TrimRight(baseURL, "/"),
		sessionID: sessionID,
	}
}

// HTTPToolCall describes an HTTP-based tool invocation.
type HTTPToolCall struct {
	// ToolName is the name of the tool for enforcement.
	ToolName string
	// Method is the HTTP method (GET, POST, PUT, DELETE, etc.).
	Method string
	// Path is the URL path relative to the adapter's base URL.
	Path string
	// Headers are optional headers to include in the request.
	Headers map[string]string
	// Body is the optional request body.
	Body []byte
	// Arguments are the tool call arguments for enforcement evaluation.
	Arguments map[string]interface{}
}

// HTTPToolResponse wraps the response from an HTTP tool call.
type HTTPToolResponse struct {
	// StatusCode is the HTTP status code from the upstream service.
	StatusCode int
	// Headers are the response headers.
	Headers map[string]string
	// Body is the raw response body.
	Body []byte
}

// Call executes an HTTP tool call through the runtime.
func (a *HTTPAdapter) Call(ctx context.Context, call *HTTPToolCall) (*HTTPToolResponse, error) {
	url := a.baseURL + "/" + strings.TrimLeft(call.Path, "/")

	method := call.Method
	if method == "" {
		method = http.MethodPost
	}

	resp, err := a.runtime.InvokeTool(ctx, &agentruntime.ToolRequest{
		SessionID:  a.sessionID,
		ToolName:   call.ToolName,
		Arguments:  call.Arguments,
		HTTPMethod: method,
		URL:        url,
		Headers:    call.Headers,
		Body:       call.Body,
	})
	if err != nil {
		return nil, fmt.Errorf("invoke tool %q: %w", call.ToolName, err)
	}

	if !resp.Allowed {
		msg := "access denied"
		if resp.Denial != nil {
			msg = resp.Denial.Message
		}
		return nil, fmt.Errorf("tool %q denied: %s", call.ToolName, msg)
	}

	return &HTTPToolResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Headers,
		Body:       resp.Body,
	}, nil
}

// CallJSON executes an HTTP tool call and unmarshals the response body into result.
func (a *HTTPAdapter) CallJSON(ctx context.Context, call *HTTPToolCall, result interface{}) error {
	resp, err := a.Call(ctx, call)
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("tool %q returned status %d: %s", call.ToolName, resp.StatusCode, string(resp.Body))
	}

	if result != nil && len(resp.Body) > 0 {
		if err := json.Unmarshal(resp.Body, result); err != nil {
			return fmt.Errorf("unmarshal response from tool %q: %w", call.ToolName, err)
		}
	}

	return nil
}

// CallJSONRequest executes an HTTP tool call with a JSON request body.
func (a *HTTPAdapter) CallJSONRequest(ctx context.Context, call *HTTPToolCall, reqBody interface{}) (*HTTPToolResponse, error) {
	if reqBody != nil {
		bodyBytes, err := json.Marshal(reqBody)
		if err != nil {
			return nil, fmt.Errorf("marshal request body for tool %q: %w", call.ToolName, err)
		}
		call.Body = bodyBytes
		if call.Headers == nil {
			call.Headers = make(map[string]string)
		}
		call.Headers["Content-Type"] = "application/json"
	}
	return a.Call(ctx, call)
}
