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

// AzureADConfig configures an Azure AD / Entra ID identity provider.
type AzureADConfig struct {
	TenantID string
	ClientID string
}

// AzureADProvider verifies Azure AD / Entra ID-issued identity tokens.
type AzureADProvider struct {
	oidc *OIDCProvider
}

// NewAzureADProvider creates an Azure AD / Entra ID-backed identity provider.
func NewAzureADProvider(cfg AzureADConfig, httpClient *http.Client) (*AzureADProvider, error) {
	if strings.TrimSpace(cfg.TenantID) == "" {
		return nil, fmt.Errorf("tenant ID is required")
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, fmt.Errorf("client ID is required")
	}

	issuerURL := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", strings.TrimSpace(cfg.TenantID))
	oidcProvider, err := newOIDCProvider(&OIDCConfig{
		IssuerURL: issuerURL,
		Audience:  strings.TrimSpace(cfg.ClientID),
	}, httpClient, ProviderTypeAzureAD, func(registered jwt.Claims, raw map[string]interface{}) (*UserContext, error) {
		roles := append(stringsFromClaim(raw, "roles"), stringsFromClaim(raw, "groups")...)
		return &UserContext{
			Subject:  registered.Subject,
			Email:    firstNonEmptyString(raw, "email", "preferred_username", "upn"),
			Name:     firstNonEmptyString(raw, "name", "preferred_username"),
			Roles:    uniqueStrings(roles),
			TenantID: firstNonEmptyString(raw, "tid"),
			Provider: string(ProviderTypeAzureAD),
			Claims:   raw,
		}, nil
	})
	if err != nil {
		return nil, err
	}

	return &AzureADProvider{oidc: oidcProvider}, nil
}

// VerifyToken validates an Azure AD / Entra ID token and maps provider-specific claims.
func (p *AzureADProvider) VerifyToken(ctx context.Context, token string) (*UserContext, error) {
	return p.oidc.VerifyToken(ctx, token)
}
