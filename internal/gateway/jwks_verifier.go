// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/edgeobs/eunox/pkg/capability"
	"github.com/edgeobs/eunox/pkg/circuitbreaker"
)

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
func NewJWKSVerifier(cfg JWKSVerifierConfig) *JWKSVerifier {
	return &JWKSVerifier{
		client: capability.NewJWKSClient(capability.JWKSClientConfig{
			JWKSURL:    cfg.JWKSURL,
			Audience:   cfg.Audience,
			RequireKID: cfg.RequireKID,
			CacheTTL:   cfg.CacheTTL,
			Client:     cfg.Client,
			Logger:     cfg.Logger,
			Breaker:    cfg.Breaker,
		}),
	}
}

// VerifyToken verifies a capability token's signature and standard claims, returning the parsed payload.
func (v *JWKSVerifier) VerifyToken(ctx context.Context, tokenStr string) (*capability.TokenPayload, error) {
	return v.client.VerifyToken(ctx, tokenStr)
}
