// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1
package config

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadValidGatewayConfig(t *testing.T) {
	unsetEnv(t, gatewayEnvKeys...)
	t.Setenv("ADMIN_HOST", "127.0.0.1")
	t.Setenv("ISSUER_JWKS_URL", "https://issuer.example.com/.well-known/jwks.json")
	t.Setenv("BACKEND_SERVICE_URL", "https://backend.example.com")
	t.Setenv("ADMIN_API_KEY", "super-secret-admin-key")
	t.Setenv("HOSTED_MODE", "true")

	var cfg GatewayConfig
	errs := Load("", &cfg)

	require.Empty(t, errs)
	assert.Equal(t, EnvDevelopment, cfg.NodeEnv)
	assert.Equal(t, 3002, cfg.Port)
	assert.Equal(t, 3003, cfg.AdminPort)
	assert.Equal(t, "127.0.0.1", cfg.AdminHost)
	assert.Equal(t, "https://issuer.example.com/.well-known/jwks.json", cfg.IssuerJWKSURL)
	assert.Equal(t, "https://backend.example.com", cfg.BackendServiceURL)
	assert.Equal(t, true, cfg.RequireKID)
	assert.Equal(t, 300, cfg.JWKSCacheTTL)
	assert.Equal(t, "tool-gateway", cfg.GatewayAudience)
	assert.True(t, cfg.HostedMode)
	assert.Equal(t, 60000, cfg.RateLimitWindowMS)
	assert.Equal(t, 1000, cfg.RateLimitMaxRequests)
}

func TestLoadMissingRequired(t *testing.T) {
	unsetEnv(t, "REQUIRED_NAME")

	type requiredConfig struct {
		Name string `env:"REQUIRED_NAME" required:"true"`
	}

	var cfg requiredConfig
	errs := Load("", &cfg)

	require.Len(t, errs, 1)
	assert.Equal(t, "Name", errs[0].Field)
	assert.Equal(t, "REQUIRED_NAME", errs[0].Env)
	assert.Equal(t, "is required", errs[0].Message)
}

func TestLoadInvalidEnum(t *testing.T) {
	unsetEnv(t, "NODE_ENV")
	t.Setenv("NODE_ENV", "qa")

	var cfg GatewayConfig
	errs := Load("", &cfg)

	require.NotEmpty(t, errs)
	assert.Contains(t, errs[0].Message, "must be one of: development, staging, production")
}

func TestLoadMinMax(t *testing.T) {
	unsetEnv(t, "PORT")

	type portConfig struct {
		Port int `env:"PORT" min:"1" max:"65535"`
	}

	t.Run("below minimum", func(t *testing.T) {
		t.Setenv("PORT", "0")
		var cfg portConfig
		errs := Load("", &cfg)
		require.Len(t, errs, 1)
		assert.Contains(t, errs[0].Message, "greater than or equal to 1")
	})

	t.Run("above maximum", func(t *testing.T) {
		t.Setenv("PORT", "70000")
		var cfg portConfig
		errs := Load("", &cfg)
		require.Len(t, errs, 1)
		assert.Contains(t, errs[0].Message, "less than or equal to 65535")
	})
}

func TestLoadProductionValidation(t *testing.T) {
	unsetEnv(t, minterEnvKeys...)
	t.Setenv("NODE_ENV", "production")

	var cfg MinterConfig
	errs := Load("", &cfg)

	require.Len(t, errs, 4)
	assert.ElementsMatch(t, []string{"AdminAPIKey", "PepperHex", "AuditDBURL", "APIKeyDBURL"}, validationFields(errs))
}

func TestLoadProductionMinLength(t *testing.T) {
	unsetEnv(t, minterEnvKeys...)
	t.Setenv("NODE_ENV", "production")
	t.Setenv("MINTER_ADMIN_API_KEY", "short")
	t.Setenv("MINTER_PEPPER_HEX", validPepperHex)
	t.Setenv("MINTER_AUDIT_DB_URL", "postgres://audit")
	t.Setenv("MINTER_API_KEY_DB_URL", "postgres://apikeys")

	var cfg MinterConfig
	errs := Load("", &cfg)

	require.Len(t, errs, 1)
	assert.Equal(t, "AdminAPIKey", errs[0].Field)
	assert.Contains(t, errs[0].Message, "at least 32 characters")
	assert.Empty(t, errs[0].Value)
}

func TestLoadProductionNotValue(t *testing.T) {
	unsetEnv(t, minterEnvKeys...)
	t.Setenv("NODE_ENV", "production")
	t.Setenv("MINTER_ADMIN_API_KEY", "dev-admin-key")
	t.Setenv("MINTER_PEPPER_HEX", validPepperHex)
	t.Setenv("MINTER_AUDIT_DB_URL", "postgres://audit")
	t.Setenv("MINTER_API_KEY_DB_URL", "postgres://apikeys")

	var cfg MinterConfig
	errs := Load("", &cfg)

	require.Len(t, errs, 2)
	assert.ElementsMatch(t, []string{"AdminAPIKey", "AdminAPIKey"}, validationFields(errs))
	assert.True(t, containsMessage(errs, "must not equal \"dev-admin-key\" in production"))
}

func TestLoadRegexValidation(t *testing.T) {
	unsetEnv(t, minterEnvKeys...)
	t.Setenv("MINTER_PEPPER_HEX", "not-hex")

	var cfg MinterConfig
	errs := Load("", &cfg)

	require.Len(t, errs, 1)
	assert.Equal(t, "PepperHex", errs[0].Field)
	assert.Contains(t, errs[0].Message, "must match regex")
	assert.Empty(t, errs[0].Value)
}

func TestLoadDefaults(t *testing.T) {
	unsetEnv(t, gatewayEnvKeys...)

	var cfg GatewayConfig
	errs := Load("", &cfg)

	require.Empty(t, errs)
	assert.Equal(t, EnvDevelopment, cfg.NodeEnv)
	assert.Equal(t, TierSingleReplica, cfg.DeploymentTier)
	assert.Equal(t, 3002, cfg.Port)
	assert.Equal(t, 3003, cfg.AdminPort)
	assert.Equal(t, true, cfg.RequireKID)
	assert.Equal(t, 300, cfg.JWKSCacheTTL)
	assert.Equal(t, "tool-gateway", cfg.GatewayAudience)
	assert.False(t, cfg.HostedMode)
}

func TestLoadBooleanCoercion(t *testing.T) {
	unsetEnv(t, gatewayEnvKeys...)
	t.Setenv("HOSTED_MODE", "true")
	t.Setenv("EUNO_REQUIRE_KID", "false")

	var cfg GatewayConfig
	errs := Load("", &cfg)

	require.Empty(t, errs)
	assert.True(t, cfg.HostedMode)
	assert.False(t, cfg.RequireKID)
}

func TestLoadCSVField(t *testing.T) {
	unsetEnv(t, "ALLOWED_ORIGINS")
	t.Setenv("ALLOWED_ORIGINS", "https://a.example, https://b.example")

	type csvConfig struct {
		AllowedOrigins []string `env:"ALLOWED_ORIGINS"`
	}

	var cfg csvConfig
	errs := Load("", &cfg)

	require.Empty(t, errs)
	assert.Equal(t, []string{"https://a.example", "https://b.example"}, cfg.AllowedOrigins)
}

func TestValidationErrorFormat(t *testing.T) {
	err := ValidationError{Field: "AdminAPIKey", Env: "ADMIN_API_KEY", Message: "is required"}
	assert.Equal(t, "AdminAPIKey (ADMIN_API_KEY): is required", err.Error())
}

func unsetEnv(t *testing.T, keys ...string) {
	t.Helper()
	for _, key := range keys {
		original, existed := os.LookupEnv(key)
		require.NoError(t, os.Unsetenv(key))
		key := key
		t.Cleanup(func() {
			if existed {
				_ = os.Setenv(key, original)
				return
			}
			_ = os.Unsetenv(key)
		})
	}
}

func validationFields(errs []ValidationError) []string {
	fields := make([]string, 0, len(errs))
	for _, err := range errs {
		fields = append(fields, err.Field)
	}
	return fields
}

func containsMessage(errs []ValidationError, want string) bool {
	for _, err := range errs {
		if strings.Contains(err.Message, want) {
			return true
		}
	}
	return false
}

var gatewayEnvKeys = []string{
	"NODE_ENV",
	"EUNO_DEPLOYMENT_TIER",
	"PORT",
	"ADMIN_PORT",
	"ADMIN_HOST",
	"ISSUER_JWKS_URL",
	"BACKEND_SERVICE_URL",
	"ADMIN_API_KEY",
	"EUNO_REQUIRE_KID",
	"EUNO_JWKS_CACHE_TTL_SECONDS",
	"GATEWAY_AUDIENCE",
	"HOSTED_MODE",
	"TENANT_ID",
	"REDIS_URL",
	"REVOCATION_REDIS_URL",
	"KILL_SWITCH_REDIS_URL",
	"CALL_COUNTER_REDIS_URL",
	"RATE_LIMIT_WINDOW_MS",
	"RATE_LIMIT_MAX_REQUESTS",
	"ALLOWED_ORIGINS",
	"EUNO_TELEMETRY",
	"TELEMETRY_FLUSH_MS",
}

var minterEnvKeys = []string{
	"NODE_ENV",
	"MINTER_PORT",
	"MINTER_ISSUER_DID",
	"MINTER_GATEWAY_AUDIENCE",
	"MINTER_TOKEN_TTL_SECONDS",
	"MINTER_ADMIN_API_KEY",
	"MINTER_PEPPER_HEX",
	"MINTER_KMS_PROVIDER",
	"MINTER_PRIVATE_KEY_PEM",
	"MINTER_PUBLIC_KEY_PEM",
	"MINTER_SIGNING_ALGORITHM",
	"MINTER_AUDIT_DB_URL",
	"MINTER_API_KEY_DB_URL",
	"REDIS_URL",
	"MINTER_RATE_LIMIT_MAX",
	"MINTER_RATE_LIMIT_WINDOW_SECONDS",
}

const validPepperHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
