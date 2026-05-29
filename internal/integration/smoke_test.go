// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

// smoke_test.go covers fast, stateless structural checks that don't fit a
// more specific file: config schema round-trips, expected environment variable
// names, and format contracts for externally-visible identifiers.
package integration

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConfig_JSONRoundTrip verifies that representative config payloads
// round-trip through JSON encoding without field loss.
func TestConfig_JSONRoundTrip(t *testing.T) {
	configs := []struct {
		name   string
		config map[string]any
	}{
		{
			name: "minimal_gateway_config",
			config: map[string]any{
				"gatewayAudience": "https://gateway.example.com",
				"adminApiKey":     "a-secure-key-at-least-32-chars-long",
			},
		},
		{
			name: "full_gateway_config",
			config: map[string]any{
				"gatewayAudience": "https://gateway.example.com",
				"adminApiKey":     "a-secure-key-at-least-32-chars-long",
				"tenantId":        "tenant-001",
				"jwksUri":         "https://issuer.example.com/.well-known/jwks.json",
				"dpopEnabled":     true,
				"dpopTTL":         300,
			},
		},
		{
			name: "issuer_config",
			config: map[string]any{
				"issuerDid":       "did:web:issuer.example.com",
				"issuerUrl":       "https://issuer.example.com",
				"defaultTokenTtl": 300,
				"maxTokenTtl":     3600,
				"audience":        "https://gateway.example.com",
			},
		},
	}

	for _, tc := range configs {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.config)
			require.NoError(t, err)

			var roundTripped map[string]any
			err = json.Unmarshal(data, &roundTripped)
			require.NoError(t, err)

			for key, expected := range tc.config {
				actual := roundTripped[key]
				// JSON numbers unmarshal as float64; compare numerically.
				switch ev := expected.(type) {
				case int:
					assert.InDelta(t, float64(ev), actual, 0.001, "field %s should round-trip", key)
				default:
					assert.Equal(t, expected, actual, "field %s should round-trip", key)
				}
			}
		})
	}
}

// TestEnv_ServiceVarIsolation verifies that service environment variables are
// not pre-set in the test process, which would contaminate integration tests
// that rely on defaults or explicit configuration.
func TestEnv_ServiceVarIsolation(t *testing.T) {
	allVars := []string{
		// Gateway
		"GATEWAY_AUDIENCE",
		"ADMIN_API_KEY",
		"JWKS_URI",
		"DPOP_ENABLED",
		// Issuer
		"ISSUER_DID",
		"ISSUER_URL",
		"DEFAULT_TOKEN_TTL",
		"MAX_TOKEN_TTL",
		// Minter
		"MINTER_PEPPER_HEX",
		"MINTER_ADMIN_KEY",
		"MINTER_DB_URL",
	}

	for _, envVar := range allVars {
		val := os.Getenv(envVar)
		assert.Empty(t, val, "env var %s should not be set in test environment", envVar)
	}
}

// TestMinter_APIKeyFormat verifies the minter API key format is consistent
// with the documented contract: sk-{id}.{secret}
func TestMinter_APIKeyFormat(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		isValid bool
	}{
		{"valid_format", "sk-abc123.secret456def", true},
		{"missing_prefix", "abc123.secret456def", false},
		{"missing_separator", "sk-abc123secret456def", false},
		{"empty", "", false},
		{"prefix_only", "sk-", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.isValid, isValidAPIKeyFormat(tc.key))
		})
	}
}

// isValidAPIKeyFormat checks whether a string matches the expected API key
// format: sk-{base64url-keyId}.{base64url-secret}
func isValidAPIKeyFormat(key string) bool {
	if len(key) < 5 || key[:3] != "sk-" {
		return false
	}
	rest := key[3:]
	dotIdx := -1
	for i, c := range rest {
		if c == '.' {
			dotIdx = i
			break
		}
	}
	return dotIdx > 0 && dotIdx < len(rest)-1
}
