// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package agentruntime implements the agent runtime library for embedding in
// agent applications. It manages token lifecycle, DPoP proof generation, and
// tool invocation through the Eunox gateway.
package agentruntime

import (
	"context"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
)

// TokenResponse represents a token acquired from the issuer.
type TokenResponse struct {
	// Token is the signed JWT capability token.
	Token string
	// ExpiresAt is the Unix timestamp when the token expires.
	ExpiresAt int64
	// IssuedAt is the Unix timestamp when the token was issued.
	IssuedAt int64
	// TokenID is the unique identifier for this token (jti claim).
	TokenID string
}

// IssuanceHints provides context that influences token issuance requests.
type IssuanceHints struct {
	// Capabilities are the requested capability constraints.
	Capabilities []capability.Constraint
	// TTL is the requested token lifetime in seconds. Zero uses server default.
	TTL int
	// Audience is the target audience for the token.
	Audience string
}

// IssuanceHintsProvider supplies context for token requests.
// Implementations can return dynamic hints based on the agent's current state.
type IssuanceHintsProvider interface {
	// GetHints returns the issuance hints for the next token request.
	GetHints(ctx context.Context) (*IssuanceHints, error)
}

// ToolRequest represents a tool invocation request to be routed through the gateway.
type ToolRequest struct {
	// SessionID identifies the current session for the enforcement request.
	SessionID string
	// ToolName is the name of the tool being invoked.
	ToolName string
	// Arguments are the tool call arguments.
	Arguments map[string]interface{}
	// Context provides additional context for enforcement evaluation.
	Context *ToolRequestContext
	// HTTPMethod is the HTTP method for the upstream tool call (used in DPoP proof).
	HTTPMethod string
	// URL is the upstream tool URL to call after enforcement succeeds.
	URL string
	// Headers are additional headers to forward to the upstream tool.
	Headers map[string]string
	// Body is the request body for the upstream tool call.
	Body []byte
}

// ToolRequestContext carries request attributes for enforcement evaluation.
type ToolRequestContext struct {
	SourceIP   string   `json:"sourceIp,omitempty"`
	Recipients []string `json:"recipients,omitempty"`
	Operation  string   `json:"operation,omitempty"`
	FilePath   string   `json:"filePath,omitempty"`
}

// ToolResponse represents the result of a tool invocation.
type ToolResponse struct {
	// Allowed indicates whether the gateway permitted the action.
	Allowed bool
	// StatusCode is the HTTP status code from the upstream tool (if allowed).
	StatusCode int
	// Headers are the response headers from the upstream tool.
	Headers map[string]string
	// Body is the response body from the upstream tool.
	Body []byte
	// Denial contains denial information if the action was rejected.
	Denial *capability.DenialInfo
}

// Config holds the agent runtime configuration.
type Config struct {
	// IssuerURL is the base URL of the capability issuer service.
	IssuerURL string
	// GatewayURL is the base URL of the enforcement gateway service.
	GatewayURL string
	// IdentityToken is the initial identity token for authentication with the issuer.
	IdentityToken string
	// IdentityTokenProvider optionally provides fresh identity tokens.
	// If set, this is called when acquiring a new token (not when returning a cached token).
	// If not set, IdentityToken is used.
	IdentityTokenProvider func(ctx context.Context) (string, error)
	// RefreshBeforeExpiry is the duration before token expiry to trigger proactive refresh.
	// Default is 30 seconds.
	RefreshBeforeExpiry time.Duration
	// MaxRetries is the maximum number of retry attempts for transient failures.
	// Default is 3.
	MaxRetries int
	// RetryBaseDelay is the base delay for exponential backoff.
	// Default is 100ms.
	RetryBaseDelay time.Duration
	// RetryMaxDelay is the maximum delay between retries.
	// Default is 5s.
	RetryMaxDelay time.Duration
	// DPoPEnabled controls whether DPoP proofs are generated. Default is true.
	DPoPEnabled *bool
	// HTTPClient is an optional custom HTTP client for outgoing requests.
	// If nil, a default client with sensible timeouts is used.
	HTTPClient HTTPClient
}

// HTTPClient is the interface for making HTTP requests. Compatible with *http.Client.
type HTTPClient interface {
	Do(req *HTTPRequest) (*HTTPResponse, error)
}

// HTTPRequest wraps an outgoing HTTP request.
type HTTPRequest struct {
	Context context.Context
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
}

// HTTPResponse wraps an incoming HTTP response.
type HTTPResponse struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
}
