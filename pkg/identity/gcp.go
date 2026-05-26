// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-jose/go-jose/v4/jwt"
)

// GCPConfig configures a GCP Cloud Identity provider.
type GCPConfig struct {
	Audience string
}

// GCPProvider verifies Google-issued identity tokens.
type GCPProvider struct {
	oidc *OIDCProvider
}

// NewGCPProvider creates a GCP Cloud Identity-backed identity provider.
func NewGCPProvider(cfg GCPConfig, httpClient *http.Client) (*GCPProvider, error) {
	if strings.TrimSpace(cfg.Audience) == "" {
		return nil, fmt.Errorf("audience is required")
	}

	oidcProvider, err := newOIDCProvider(OIDCConfig{
		IssuerURL: "https://accounts.google.com",
		Audience:  strings.TrimSpace(cfg.Audience),
	}, httpClient, ProviderTypeGCP, func(registered jwt.Claims, raw map[string]interface{}) (*UserContext, error) {
		return &UserContext{
			Subject:  registered.Subject,
			Email:    firstNonEmptyString(raw, "email"),
			Name:     firstNonEmptyString(raw, "name", "email"),
			Roles:    uniqueStrings(stringsFromClaim(raw, "roles")),
			TenantID: firstNonEmptyString(raw, "hd"),
			Provider: string(ProviderTypeGCP),
			Claims:   raw,
		}, nil
	})
	if err != nil {
		return nil, err
	}

	return &GCPProvider{oidc: oidcProvider}, nil
}

// VerifyToken validates a GCP token and maps provider-specific claims.
func (p *GCPProvider) VerifyToken(ctx context.Context, token string) (*UserContext, error) {
	return p.oidc.VerifyToken(ctx, token)
}
