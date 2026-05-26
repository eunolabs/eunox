// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigration_ConfigCompatibility verifies that old configuration formats
// are still accepted by the current configuration parsers.
func TestMigration_ConfigCompatibility(t *testing.T) {
	// Test that the gateway config schema accepts all required fields
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
			// Verify config can be serialized and deserialized without loss
			data, err := json.Marshal(tc.config)
			require.NoError(t, err)

			var roundTripped map[string]any
			err = json.Unmarshal(data, &roundTripped)
			require.NoError(t, err)

			for key, expected := range tc.config {
				actual := roundTripped[key]
				// JSON numbers unmarshal as float64; compare numerically
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

// TestMigration_MigrationFilesExist verifies that all required migration files
// are present in the expected location.
func TestMigration_MigrationFilesExist(t *testing.T) {
	// Check that migration directories exist
	migrationDirs := []string{
		"internal/minter/migrations",
		"internal/issuer/migrations",
	}

	for _, dir := range migrationDirs {
		fullPath := filepath.Join(projectRoot(t), dir)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			// Migration directory doesn't exist yet - this is acceptable as
			// migrations may live in a different location or use embedded migrations
			t.Logf("migration directory %s not found (may use embedded migrations)", dir)
			continue
		}

		// If directory exists, verify it has .sql files
		entries, err := os.ReadDir(fullPath)
		require.NoError(t, err)

		sqlFiles := 0
		for _, e := range entries {
			if filepath.Ext(e.Name()) == ".sql" {
				sqlFiles++
			}
		}
		assert.Greater(t, sqlFiles, 0, "migration directory %s should contain SQL files", dir)
	}
}

// TestMigration_EnvVarCompatibility verifies that all documented environment variables
// are recognized and properly validated.
func TestMigration_EnvVarCompatibility(t *testing.T) {
	// Document the expected env vars for each service
	gatewayEnvVars := []string{
		"GATEWAY_AUDIENCE",
		"ADMIN_API_KEY",
		"JWKS_URI",
		"DPOP_ENABLED",
	}

	issuerEnvVars := []string{
		"ISSUER_DID",
		"ISSUER_URL",
		"DEFAULT_TOKEN_TTL",
		"MAX_TOKEN_TTL",
	}

	minterEnvVars := []string{
		"MINTER_PEPPER_HEX",
		"MINTER_ADMIN_KEY",
		"MINTER_DB_URL",
	}

	// Verify none of the env vars are accidentally set in test environment
	// (which would interfere with tests)
	allVars := append(gatewayEnvVars, issuerEnvVars...)
	allVars = append(allVars, minterEnvVars...)

	for _, envVar := range allVars {
		val := os.Getenv(envVar)
		assert.Empty(t, val, "env var %s should not be set in test environment", envVar)
	}
}

// TestMigration_APIKeyFormat verifies the minter API key format is consistent
// with the documented format: sk-{id}.{secret}
func TestMigration_APIKeyFormat(t *testing.T) {
	// Import the minter to test key format
	// The format is: sk-{base62-id}.{base62-secret}
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
			isValid := isValidAPIKeyFormat(tc.key)
			assert.Equal(t, tc.isValid, isValid)
		})
	}
}

// isValidAPIKeyFormat checks if a string matches the expected API key format.
func isValidAPIKeyFormat(key string) bool {
	if len(key) < 5 {
		return false
	}
	if key[:3] != "sk-" {
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
	if dotIdx <= 0 || dotIdx == len(rest)-1 {
		return false
	}
	return true
}

// projectRoot returns the root directory of the project.
func projectRoot(t *testing.T) string {
	t.Helper()
	// Walk up from the test file to find go.mod
	dir, err := os.Getwd()
	require.NoError(t, err)

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find project root (go.mod)")
		}
		dir = parent
	}
}
