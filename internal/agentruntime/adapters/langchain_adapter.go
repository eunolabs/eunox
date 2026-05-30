// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package adapters

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/eunolabs/eunox/internal/agentruntime"
)

// Tool represents a LangChain-compatible tool definition.
// It provides a standard interface for function-calling LLM frameworks.
type Tool struct {
	// Name is the tool name used in enforcement and function calls.
	Name string
	// Description is a human-readable description of what the tool does.
	Description string
	// InputSchema describes the expected input JSON schema (optional).
	InputSchema interface{}
}

// LangChainAdapter provides a LangChain-compatible interface for tool invocation.
// It wraps the agent runtime to present tools in a format compatible with
// Go LangChain ecosystem libraries (e.g., github.com/tmc/langchaingo).
type LangChainAdapter struct {
	runtime   *agentruntime.Runtime
	tools     []Tool
	sessionID string
}

// NewLangChainAdapter creates a new LangChainAdapter.
func NewLangChainAdapter(rt *agentruntime.Runtime, sessionID string, tools ...Tool) *LangChainAdapter {
	return &LangChainAdapter{
		runtime:   rt,
		tools:     tools,
		sessionID: sessionID,
	}
}

// Tools returns the list of available tool definitions.
func (a *LangChainAdapter) Tools() []Tool {
	return a.tools
}

// ToolResult represents the result of a tool invocation.
type ToolResult struct {
	// Output is the tool's output (typically JSON-serialized).
	Output string
	// Error is set if the tool invocation failed.
	Error error
}

// Call invokes a tool by name with the given JSON input.
// This matches the LangChain tool-calling convention where tools accept
// a string input (typically JSON) and return a string output.
func (a *LangChainAdapter) Call(ctx context.Context, toolName, input string) ToolResult {
	var arguments map[string]interface{}
	if input != "" {
		if err := json.Unmarshal([]byte(input), &arguments); err != nil {
			return ToolResult{Error: fmt.Errorf("invalid tool input JSON: %w", err)}
		}
	}

	resp, err := a.runtime.InvokeTool(ctx, &agentruntime.ToolRequest{
		SessionID:  a.sessionID,
		ToolName:   toolName,
		Arguments:  arguments,
		HTTPMethod: "POST",
	})
	if err != nil {
		return ToolResult{Error: fmt.Errorf("invoke tool %q: %w", toolName, err)}
	}

	if !resp.Allowed {
		msg := "access denied"
		if resp.Denial != nil {
			msg = resp.Denial.Message
		}
		return ToolResult{Error: fmt.Errorf("tool %q denied: %s", toolName, msg)}
	}

	if resp.Body != nil {
		return ToolResult{Output: string(resp.Body)}
	}

	return ToolResult{Output: ""}
}

// CallWithArgs invokes a tool by name with structured arguments.
func (a *LangChainAdapter) CallWithArgs(ctx context.Context, toolName string, args map[string]interface{}) ToolResult {
	inputBytes, err := json.Marshal(args)
	if err != nil {
		return ToolResult{Error: fmt.Errorf("marshal tool arguments: %w", err)}
	}
	return a.Call(ctx, toolName, string(inputBytes))
}
