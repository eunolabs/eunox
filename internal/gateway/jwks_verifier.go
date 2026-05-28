// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/circuitbreaker"
)

// tracingTransport is an http.RoundTripper that injects the current OTel trace
// context into outbound request headers using the globally configured
// TextMapPropagator (P2-4).  This allows downstream services (e.g. JWKS
// endpoints) to participate in the distributed trace started by the gateway.
type tracingTransport struct {
	base http.RoundTripper
}

// RoundTrip injects trace context before delegating to the base transport.
func (t *tracingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid mutating the caller's copy.
	req = req.Clone(req.Context())
	otel.GetTextMapPropagator().Inject(req.Context(), propagation.HeaderCarrier(req.Header))
	return t.base.RoundTrip(req)
}

// withTracingTransport wraps an *http.Client so that its transport propagates
// OTel trace context on every outbound request.  If client is nil a new one
// with a 10-second timeout is created.
func withTracingTransport(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	clone := *client
	clone.Transport = &tracingTransport{base: base}
	return &clone
}

// JWKSVerifier verifies capability tokens against a JWKS endpoint.
// It implements the JWTVerifier interface by delegating to capability.JWKSClient.
type JWKSVerifier struct {
	client *capability.JWKSClient
}

// JWKSVerifierConfig configures the JWKSVerifier.
type JWKSVerifierConfig struct {
	// JWKSURL is the endpoint serving the issuer's JSON Web Key Set.
	JWKSURL string
	// Audience is the expected audience in the token (optional).
	Audience string
	// RequireKID requires the JWT header to contain a kid for key selection.
	RequireKID bool
	// CacheTTL is how long JWKS responses are cached. Default: 5 minutes.
	CacheTTL time.Duration
	// Client is the HTTP client for JWKS fetching. Default: 10s timeout.
	Client *http.Client
	// Logger for operational messages.
	Logger *slog.Logger
	// Breaker protects JWKS fetches from repeated upstream failures.
	Breaker *circuitbreaker.Breaker
}

// NewJWKSVerifier creates a JWKS-based capability token verifier.
// The HTTP client is automatically wrapped with a tracing transport that
// propagates the active OTel span context to the JWKS endpoint (P2-4).
func NewJWKSVerifier(cfg JWKSVerifierConfig) *JWKSVerifier {
	return &JWKSVerifier{
		client: capability.NewJWKSClient(capability.JWKSClientConfig{
			JWKSURL:    cfg.JWKSURL,
			Audience:   cfg.Audience,
			RequireKID: cfg.RequireKID,
			CacheTTL:   cfg.CacheTTL,
			Client:     withTracingTransport(cfg.Client),
			Logger:     cfg.Logger,
			Breaker:    cfg.Breaker,
		}),
	}
}

// VerifyToken verifies a capability token's signature and standard claims, returning the parsed payload.
func (v *JWKSVerifier) VerifyToken(ctx context.Context, tokenStr string) (*capability.TokenPayload, error) {
	return v.client.VerifyToken(ctx, tokenStr)
}
