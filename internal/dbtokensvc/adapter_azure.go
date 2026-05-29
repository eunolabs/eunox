// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package dbtokensvc

import (
	"context"
	"fmt"
	"time"
)

// AzureTokenProvider acquires Azure AD access tokens for a given resource.
// Implementations may use managed identity, client credentials, or workload identity.
type AzureTokenProvider interface {
	// GetToken acquires an access token for the specified resource scope.
	GetToken(ctx context.Context, scope string) (*AzureToken, error)
}

// AzureToken represents an Azure AD access token.
type AzureToken struct {
	// AccessToken is the bearer token string.
	AccessToken string
	// ExpiresOn is when the token expires.
	ExpiresOn time.Time
}

// RealAzureSQLAdapterConfig configures the production Azure SQL adapter.
type RealAzureSQLAdapterConfig struct {
	// ServerName is the Azure SQL fully qualified server name (e.g., "myserver.database.windows.net").
	ServerName string
	// Port is the database port (default 1433).
	Port int
	// TokenProvider supplies Azure AD tokens for the database resource.
	TokenProvider AzureTokenProvider
}

// RealAzureSQLAdapter generates Azure AD access tokens for Azure SQL Database
// authentication using Azure AD-integrated authentication.
type RealAzureSQLAdapter struct {
	serverName    string
	port          int
	tokenProvider AzureTokenProvider
}

// AzureSQLResourceScope is the resource identifier for Azure SQL Database.
const AzureSQLResourceScope = "https://database.windows.net/.default"

// NewRealAzureSQLAdapter creates a production Azure SQL adapter.
func NewRealAzureSQLAdapter(cfg RealAzureSQLAdapterConfig) (*RealAzureSQLAdapter, error) {
	if cfg.ServerName == "" {
		return nil, fmt.Errorf("dbtokensvc: Azure SQL server name is required")
	}
	if cfg.TokenProvider == nil {
		return nil, fmt.Errorf("dbtokensvc: Azure token provider is required")
	}
	if cfg.Port == 0 {
		cfg.Port = 1433
	}
	return &RealAzureSQLAdapter{
		serverName:    cfg.ServerName,
		port:          cfg.Port,
		tokenProvider: cfg.TokenProvider,
	}, nil
}

// Name implements CloudDBAdapter.
func (a *RealAzureSQLAdapter) Name() string { return "azure-sql" }

// MintCredential acquires an Azure AD token for Azure SQL Database authentication.
// The token is used as the password in SQL Server connections with Azure AD auth enabled.
func (a *RealAzureSQLAdapter) MintCredential(ctx context.Context, req *MintDBCredentialRequest) (*DBCredential, error) {
	token, err := a.tokenProvider.GetToken(ctx, AzureSQLResourceScope)
	if err != nil {
		return nil, fmt.Errorf("dbtokensvc: acquire Azure SQL token: %w", err)
	}

	// Azure SQL tokens have a fixed expiry from AAD (typically 1 hour).
	// We report the actual token expiry, not the requested TTL.
	expiresAt := token.ExpiresOn
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(req.TTL)
	}

	return &DBCredential{
		Username:  req.DBUsername,
		Token:     token.AccessToken,
		Host:      a.serverName,
		Port:      a.port,
		Database:  req.Database,
		ExpiresAt: expiresAt,
		Adapter:   a.Name(),
	}, nil
}
