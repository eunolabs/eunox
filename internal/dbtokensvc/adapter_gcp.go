// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package dbtokensvc

import (
	"context"
	"fmt"
	"time"
)

// GCPTokenProvider acquires Google Cloud OAuth2 access tokens.
// Implementations may use Application Default Credentials (ADC),
// service account key files, or workload identity federation.
type GCPTokenProvider interface {
	// GetAccessToken acquires an OAuth2 access token with the given scopes.
	GetAccessToken(ctx context.Context, scopes []string) (*GCPToken, error)
}

// GCPToken represents a Google Cloud OAuth2 access token.
type GCPToken struct {
	// AccessToken is the OAuth2 bearer token string.
	AccessToken string
	// ExpiresAt is when the token expires.
	ExpiresAt time.Time
}

// RealGCPCloudSQLAdapterConfig configures the production GCP Cloud SQL adapter.
type RealGCPCloudSQLAdapterConfig struct {
	// InstanceConnection is the Cloud SQL instance connection name
	// in the format "project:region:instance".
	InstanceConnection string
	// Port is the database port (default 5432 for PostgreSQL, 3306 for MySQL).
	Port int
	// TokenProvider supplies GCP OAuth2 tokens for Cloud SQL IAM authentication.
	TokenProvider GCPTokenProvider
}

// GCPCloudSQLScopes are the OAuth2 scopes required for Cloud SQL IAM auth.
var GCPCloudSQLScopes = []string{
	"https://www.googleapis.com/auth/sqlservice.login",
}

// RealGCPCloudSQLAdapter generates OAuth2 access tokens for GCP Cloud SQL
// IAM database authentication.
type RealGCPCloudSQLAdapter struct {
	instanceConnection string
	port               int
	tokenProvider      GCPTokenProvider
}

// NewRealGCPCloudSQLAdapter creates a production GCP Cloud SQL IAM adapter.
func NewRealGCPCloudSQLAdapter(cfg RealGCPCloudSQLAdapterConfig) (*RealGCPCloudSQLAdapter, error) {
	if cfg.InstanceConnection == "" {
		return nil, fmt.Errorf("dbtokensvc: GCP instance connection name is required")
	}
	if cfg.TokenProvider == nil {
		return nil, fmt.Errorf("dbtokensvc: GCP token provider is required")
	}
	if cfg.Port == 0 {
		cfg.Port = 5432
	}
	return &RealGCPCloudSQLAdapter{
		instanceConnection: cfg.InstanceConnection,
		port:               cfg.Port,
		tokenProvider:      cfg.TokenProvider,
	}, nil
}

// Name implements CloudDBAdapter.
func (a *RealGCPCloudSQLAdapter) Name() string { return "gcp-cloudsql" }

// MintCredential acquires a GCP OAuth2 token for Cloud SQL IAM database authentication.
// The token is used as the password when connecting to Cloud SQL instances with
// IAM database authentication enabled.
func (a *RealGCPCloudSQLAdapter) MintCredential(ctx context.Context, req *MintDBCredentialRequest) (*DBCredential, error) {
	token, err := a.tokenProvider.GetAccessToken(ctx, GCPCloudSQLScopes)
	if err != nil {
		return nil, fmt.Errorf("dbtokensvc: acquire GCP Cloud SQL token: %w", err)
	}

	// GCP tokens have a fixed expiry (typically 1 hour).
	expiresAt := token.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(req.TTL)
	}

	return &DBCredential{
		Username:  req.DBUsername,
		Token:     token.AccessToken,
		Host:      a.instanceConnection,
		Port:      a.port,
		Database:  req.Database,
		ExpiresAt: expiresAt,
		Adapter:   a.Name(),
	}, nil
}
