// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-jose/go-jose/v4/jwt"
)

// CognitoConfig configures an AWS Cognito identity provider.
type CognitoConfig struct {
	Region      string
	UserPoolID  string
	AppClientID string
}

// CognitoProvider verifies AWS Cognito-issued identity tokens.
type CognitoProvider struct {
	oidc *OIDCProvider
}

// NewCognitoProvider creates a Cognito-backed identity provider.
func NewCognitoProvider(cfg CognitoConfig, httpClient *http.Client) (*CognitoProvider, error) {
	if strings.TrimSpace(cfg.Region) == "" {
		return nil, fmt.Errorf("region is required")
	}
	if strings.TrimSpace(cfg.UserPoolID) == "" {
		return nil, fmt.Errorf("user pool ID is required")
	}
	if strings.TrimSpace(cfg.AppClientID) == "" {
		return nil, fmt.Errorf("app client ID is required")
	}

	issuerURL := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", strings.TrimSpace(cfg.Region), strings.TrimSpace(cfg.UserPoolID))
	oidcProvider, err := newOIDCProvider(OIDCConfig{
		IssuerURL:      issuerURL,
		Audience:       strings.TrimSpace(cfg.AppClientID),
		RolesClaimPath: "cognito:groups",
	}, httpClient, ProviderTypeCognito, func(registered jwt.Claims, raw map[string]interface{}) (*UserContext, error) {
		return &UserContext{
			Subject:  registered.Subject,
			Email:    firstNonEmptyString(raw, "email"),
			Name:     firstNonEmptyString(raw, "name", "cognito:username", "username"),
			Roles:    uniqueStrings(stringsFromClaim(raw, "cognito:groups")),
			TenantID: firstNonEmptyString(raw, "custom:tenant_id"),
			Provider: string(ProviderTypeCognito),
			Claims:   raw,
		}, nil
	})
	if err != nil {
		return nil, err
	}

	return &CognitoProvider{oidc: oidcProvider}, nil
}

// VerifyToken validates a Cognito token and maps Cognito-specific claims.
func (p *CognitoProvider) VerifyToken(ctx context.Context, token string) (*UserContext, error) {
	return p.oidc.VerifyToken(ctx, token)
}
