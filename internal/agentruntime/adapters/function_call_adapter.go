// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package adapters

import (
	"context"
	"fmt"

	"github.com/edgeobs/eunox/internal/agentruntime"
)

// FunctionCallAdapter wraps the agent runtime for generic function-call patterns.
// It provides a simple invoke-by-name interface suitable for any function-calling
// framework or custom agent loop.
type FunctionCallAdapter struct {
	runtime   *agentruntime.Runtime
	sessionID string
	handlers  map[string]FunctionHandler
}

// FunctionHandler is a callback that processes the tool response after enforcement.
// It receives the raw response body from the upstream tool and can transform it.
type FunctionHandler func(ctx context.Context, args map[string]interface{}, resp *agentruntime.ToolResponse) (interface{}, error)

// NewFunctionCallAdapter creates a new FunctionCallAdapter.
func NewFunctionCallAdapter(rt *agentruntime.Runtime, sessionID string) *FunctionCallAdapter {
	return &FunctionCallAdapter{
		runtime:   rt,
		sessionID: sessionID,
		handlers:  make(map[string]FunctionHandler),
	}
}

// RegisterHandler registers a handler function for a named tool.
// The handler is called after successful enforcement to process the response.
func (a *FunctionCallAdapter) RegisterHandler(toolName string, handler FunctionHandler) {
	a.handlers[toolName] = handler
}

// FunctionCallResult represents the result of a function call.
type FunctionCallResult struct {
	// Result is the processed output from the handler (or raw response if no handler).
	Result interface{}
	// Allowed indicates whether the gateway permitted the action.
	Allowed bool
	// DenialMessage is set when the call was denied.
	DenialMessage string
}

// Invoke calls a tool by name with the given arguments.
// If a handler is registered for the tool, it processes the response.
// Otherwise, the raw response body is returned as a string.
func (a *FunctionCallAdapter) Invoke(ctx context.Context, toolName string, args map[string]interface{}) (*FunctionCallResult, error) {
	resp, err := a.runtime.InvokeTool(ctx, &agentruntime.ToolRequest{
		SessionID:  a.sessionID,
		ToolName:   toolName,
		Arguments:  args,
		HTTPMethod: "POST",
	})
	if err != nil {
		return nil, fmt.Errorf("invoke tool %q: %w", toolName, err)
	}

	if !resp.Allowed {
		msg := "access denied"
		if resp.Denial != nil {
			msg = resp.Denial.Message
		}
		return &FunctionCallResult{
			Allowed:       false,
			DenialMessage: msg,
		}, nil
	}

	// If a handler is registered, use it to process the response
	if handler, ok := a.handlers[toolName]; ok {
		result, err := handler(ctx, args, resp)
		if err != nil {
			return nil, fmt.Errorf("handler for tool %q: %w", toolName, err)
		}
		return &FunctionCallResult{
			Allowed: true,
			Result:  result,
		}, nil
	}

	// Default: return raw response body
	var result interface{}
	if resp.Body != nil {
		result = string(resp.Body)
	}

	return &FunctionCallResult{
		Allowed: true,
		Result:  result,
	}, nil
}

// InvokeWithURL calls a tool with enforcement and routes to a specific upstream URL.
func (a *FunctionCallAdapter) InvokeWithURL(ctx context.Context, toolName string, args map[string]interface{}, method, url string, body []byte) (*FunctionCallResult, error) {
	resp, err := a.runtime.InvokeTool(ctx, &agentruntime.ToolRequest{
		SessionID:  a.sessionID,
		ToolName:   toolName,
		Arguments:  args,
		HTTPMethod: method,
		URL:        url,
		Body:       body,
	})
	if err != nil {
		return nil, fmt.Errorf("invoke tool %q: %w", toolName, err)
	}

	if !resp.Allowed {
		msg := "access denied"
		if resp.Denial != nil {
			msg = resp.Denial.Message
		}
		return &FunctionCallResult{
			Allowed:       false,
			DenialMessage: msg,
		}, nil
	}

	if handler, ok := a.handlers[toolName]; ok {
		result, err := handler(ctx, args, resp)
		if err != nil {
			return nil, fmt.Errorf("handler for tool %q: %w", toolName, err)
		}
		return &FunctionCallResult{
			Allowed: true,
			Result:  result,
		}, nil
	}

	var result interface{}
	if resp.Body != nil {
		result = string(resp.Body)
	}

	return &FunctionCallResult{
		Allowed: true,
		Result:  result,
	}, nil
}
