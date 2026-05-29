// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package dbtokensvc

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/eunolabs/eunox/pkg/capability"
)

// JWKSTokenVerifier verifies capability tokens via JWKS and extracts DB-related claims.
// It implements the TokenVerifier interface.
type JWKSTokenVerifier struct {
	client *capability.JWKSClient
}

// JWKSTokenVerifierConfig configures the JWKS-based token verifier.
type JWKSTokenVerifierConfig struct {
	// JWKSURL is the endpoint serving the issuer's JSON Web Key Set.
	JWKSURL string
	// Audience is the expected audience in the token (optional).
	Audience string
	// CacheTTL is how long JWKS responses are cached. Default: 5 minutes.
	CacheTTL time.Duration
	// Client is the HTTP client for JWKS fetching. Default: 10s timeout.
	Client *http.Client
	// Logger for operational messages.
	Logger *slog.Logger
}

// NewJWKSTokenVerifier creates a JWKS-based token verifier for the DB token service.
func NewJWKSTokenVerifier(cfg JWKSTokenVerifierConfig) *JWKSTokenVerifier {
	return &JWKSTokenVerifier{
		client: capability.NewJWKSClient(capability.JWKSClientConfig{
			JWKSURL:  cfg.JWKSURL,
			Audience: cfg.Audience,
			CacheTTL: cfg.CacheTTL,
			Client:   cfg.Client,
			Logger:   cfg.Logger,
		}),
	}
}

// VerifyAndExtractCaps verifies a JWT and returns the subject and db:// capabilities.
func (v *JWKSTokenVerifier) VerifyAndExtractCaps(ctx context.Context, tokenStr string) (*TokenClaims, error) {
	payload, err := v.client.VerifyToken(ctx, tokenStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	// Extract db:// resources from capabilities.
	var dbResources []string
	for _, cap := range payload.Capabilities {
		if strings.HasPrefix(cap.Resource, "db://") {
			dbResources = append(dbResources, cap.Resource)
		}
	}

	tenantID := ""
	if payload.AuthorizedBy != nil {
		tenantID = payload.AuthorizedBy.TenantID
	}

	return &TokenClaims{
		Subject:     payload.Subject,
		TenantID:    tenantID,
		DBResources: dbResources,
	}, nil
}
