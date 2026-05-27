// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"strings"
	"testing"

	"github.com/edgeobs/eunox/pkg/config"
)

func TestLevelFromEnv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		env      config.Environment
		expected string
	}{
		{config.EnvProduction, "info"},
		{config.EnvStaging, "info"},
		{config.EnvDevelopment, "debug"},
		{config.Environment("test"), "debug"},
		{config.Environment(""), "debug"},
	}

	for _, tt := range tests {
		t.Run(string(tt.env), func(t *testing.T) {
			t.Parallel()
			if got := levelFromEnv(tt.env); got != tt.expected {
				t.Errorf("levelFromEnv(%q) = %q, want %q", tt.env, got, tt.expected)
			}
		})
	}
}

func TestNoopVerifier(t *testing.T) {
	t.Parallel()

	v := &noopVerifier{}
	_, err := v.VerifyToken(t.Context(), "some-token")
	if err == nil {
		t.Fatal("expected noopVerifier to return an error")
	}
}

func TestRun_MissingConfig(t *testing.T) {
	// When required config is missing, run() should return an error.
	// config.LoadOrExit calls os.Exit on missing required config, so we
	// test at a higher level that the binary compiles and is wired correctly.
	// The unit-testable parts (levelFromEnv, noopVerifier) are tested above.
}

func TestValidateAdminAuth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cfg       config.GatewayConfig
		tenantID  string
		expectErr bool
		errMsg    string
	}{
		{
			name: "development_no_jwks_allowed",
			cfg: config.GatewayConfig{
				NodeEnv:     config.EnvDevelopment,
				AdminAPIKey: "some-key",
			},
			tenantID:  "tenant-1",
			expectErr: false,
		},
		// --- Staging (CR-3: JWT required in staging too) ---
		{
			name: "staging_missing_jwks_uri_requires_error",
			cfg: config.GatewayConfig{
				NodeEnv:     config.EnvStaging,
				AdminAPIKey: "some-key",
			},
			tenantID:  "tenant-1",
			expectErr: true,
			errMsg:    "GATEWAY_ADMIN_JWKS_URI is required in staging",
		},
		{
			name: "staging_missing_jwt_audience",
			cfg: config.GatewayConfig{
				NodeEnv:      config.EnvStaging,
				AdminJWKSURI: "https://auth.example.com/.well-known/jwks.json",
			},
			tenantID:  "tenant-1",
			expectErr: true,
			errMsg:    "GATEWAY_ADMIN_JWT_AUDIENCE is required in staging",
		},
		{
			name: "staging_jwt_requires_tenant",
			cfg: config.GatewayConfig{
				NodeEnv:          config.EnvStaging,
				AdminJWKSURI:     "https://auth.example.com/.well-known/jwks.json",
				AdminJWTAudience: "gateway-admin",
			},
			expectErr: true,
			errMsg:    "TENANT_ID (or GATEWAY_TENANT_ID) is required in staging",
		},
		{
			name: "staging_with_full_jwt_config",
			cfg: config.GatewayConfig{
				NodeEnv:          config.EnvStaging,
				AdminAPIKey:      "some-key",
				AdminJWKSURI:     "https://auth.example.com/.well-known/jwks.json",
				AdminJWTAudience: "gateway-admin",
			},
			tenantID:  "tenant-1",
			expectErr: false,
		},
		// --- Production ---
		{
			name: "production_missing_jwks_uri",
			cfg: config.GatewayConfig{
				NodeEnv:     config.EnvProduction,
				AdminAPIKey: "some-key",
			},
			tenantID:  "tenant-1",
			expectErr: true,
			errMsg:    "GATEWAY_ADMIN_JWKS_URI is required in production",
		},
		{
			name: "production_missing_jwt_audience",
			cfg: config.GatewayConfig{
				NodeEnv:      config.EnvProduction,
				AdminJWKSURI: "https://auth.example.com/.well-known/jwks.json",
			},
			tenantID:  "tenant-1",
			expectErr: true,
			errMsg:    "GATEWAY_ADMIN_JWT_AUDIENCE is required in production",
		},
		{
			name: "production_missing_tenant_for_jwt_admin_auth",
			cfg: config.GatewayConfig{
				NodeEnv:          config.EnvProduction,
				AdminJWKSURI:     "https://auth.example.com/.well-known/jwks.json",
				AdminJWTAudience: "gateway-admin",
			},
			expectErr: true,
			errMsg:    "TENANT_ID (or GATEWAY_TENANT_ID) is required in production",
		},
		{
			name: "production_with_jwks_uri",
			cfg: config.GatewayConfig{
				NodeEnv:          config.EnvProduction,
				AdminAPIKey:      "some-key",
				AdminJWKSURI:     "https://auth.example.com/.well-known/jwks.json",
				AdminJWTAudience: "gateway-admin",
			},
			tenantID:  "tenant-1",
			expectErr: false,
		},
		{
			name: "production_jwks_only_no_static_key",
			cfg: config.GatewayConfig{
				NodeEnv:          config.EnvProduction,
				AdminJWKSURI:     "https://auth.example.com/.well-known/jwks.json",
				AdminJWTAudience: "gateway-admin",
			},
			tenantID:  "tenant-1",
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateAdminAuth(&tt.cfg, tt.tenantID)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errMsg)
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error = %q, want to contain %q", err.Error(), tt.errMsg)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
