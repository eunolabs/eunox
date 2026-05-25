// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

// Package identity provides identity-provider adapters for verifying user identity tokens.
package identity

import "context"

// Provider verifies an identity token and returns a UserContext.
type Provider interface {
	VerifyToken(ctx context.Context, token string) (*UserContext, error)
}

// UserContext represents the authenticated user from an identity provider.
type UserContext struct {
	Subject  string                 // Unique user identifier (sub claim)
	Email    string                 // User email if available
	Name     string                 // Display name
	Roles    []string               // Assigned roles
	TenantID string                 // Multi-tenant identifier
	Provider string                 // Provider name (e.g., "oidc", "cognito", "azure-ad")
	Claims   map[string]interface{} // Raw claims from the token
}

// ProviderType identifies the identity provider type.
type ProviderType string

const (
	// ProviderTypeOIDC identifies a generic OIDC provider.
	ProviderTypeOIDC ProviderType = "oidc"
	// ProviderTypeCognito identifies an AWS Cognito provider.
	ProviderTypeCognito ProviderType = "cognito"
	// ProviderTypeAzureAD identifies an Azure AD / Entra ID provider.
	ProviderTypeAzureAD ProviderType = "azure-ad"
	// ProviderTypeGCP identifies a GCP Cloud Identity provider.
	ProviderTypeGCP ProviderType = "gcp-identity"
	// ProviderTypeDID identifies a DID-based provider.
	ProviderTypeDID ProviderType = "did"
)
