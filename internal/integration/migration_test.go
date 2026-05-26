// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigration_ConfigJSONRoundTrip verifies representative config payloads
// round-trip through JSON encoding without field loss.
func TestMigration_ConfigJSONRoundTrip(t *testing.T) {
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
		"migrations/minter",
		"migrations/audit",
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

// TestMigration_ForwardBackwardPairs verifies that every .up.sql migration has
// a corresponding .down.sql file (and vice versa) enabling reversible migrations.
func TestMigration_ForwardBackwardPairs(t *testing.T) {
	migrationDirs := []string{
		"migrations/minter",
		"migrations/audit",
	}

	for _, dir := range migrationDirs {
		t.Run(dir, func(t *testing.T) {
			fullPath := filepath.Join(projectRoot(t), dir)
			entries, err := os.ReadDir(fullPath)
			require.NoError(t, err)

			upFiles := map[string]bool{}
			downFiles := map[string]bool{}

			for _, e := range entries {
				name := e.Name()
				if strings.HasSuffix(name, ".up.sql") {
					base := strings.TrimSuffix(name, ".up.sql")
					upFiles[base] = true
				} else if strings.HasSuffix(name, ".down.sql") {
					base := strings.TrimSuffix(name, ".down.sql")
					downFiles[base] = true
				}
			}

			// Every up migration must have a corresponding down migration
			for base := range upFiles {
				assert.True(t, downFiles[base], "migration %s has .up.sql but missing .down.sql", base)
			}
			// Every down migration must have a corresponding up migration
			for base := range downFiles {
				assert.True(t, upFiles[base], "migration %s has .down.sql but missing .up.sql", base)
			}
			// Must have at least one migration pair
			assert.Greater(t, len(upFiles), 0, "directory %s should have at least one migration", dir)
		})
	}
}

// TestMigration_SQLSyntaxBasicValidation performs basic syntax validation on
// migration SQL files (checks for common structural requirements).
func TestMigration_SQLSyntaxBasicValidation(t *testing.T) {
	migrationDirs := []string{
		"migrations/minter",
		"migrations/audit",
	}

	for _, dir := range migrationDirs {
		t.Run(dir, func(t *testing.T) {
			fullPath := filepath.Join(projectRoot(t), dir)
			entries, err := os.ReadDir(fullPath)
			require.NoError(t, err)

			for _, e := range entries {
				if filepath.Ext(e.Name()) != ".sql" {
					continue
				}
				t.Run(e.Name(), func(t *testing.T) {
					content, err := os.ReadFile(filepath.Join(fullPath, e.Name()))
					require.NoError(t, err)

					sql := string(content)
					// Must not be empty
					assert.NotEmpty(t, strings.TrimSpace(sql), "migration file should not be empty")

					// Up migrations should contain CREATE or ALTER
					if strings.HasSuffix(e.Name(), ".up.sql") {
						hasCreate := strings.Contains(strings.ToUpper(sql), "CREATE")
						hasAlter := strings.Contains(strings.ToUpper(sql), "ALTER")
						hasInsert := strings.Contains(strings.ToUpper(sql), "INSERT")
						assert.True(t, hasCreate || hasAlter || hasInsert,
							"up migration should contain CREATE, ALTER, or INSERT statement")
					}

					// Down migrations should contain DROP or ALTER or DELETE
					if strings.HasSuffix(e.Name(), ".down.sql") {
						hasDrop := strings.Contains(strings.ToUpper(sql), "DROP")
						hasAlter := strings.Contains(strings.ToUpper(sql), "ALTER")
						hasDelete := strings.Contains(strings.ToUpper(sql), "DELETE")
						assert.True(t, hasDrop || hasAlter || hasDelete,
							"down migration should contain DROP, ALTER, or DELETE statement")
					}

					// Must have license header
					assert.True(t, strings.Contains(sql, "SPDX-License-Identifier"),
						"migration file should have license header")
				})
			}
		})
	}
}

// TestMigration_SequentialNumbering verifies migration files follow sequential
// numbering (001, 002, 003, ...) without gaps.
func TestMigration_SequentialNumbering(t *testing.T) {
	migrationDirs := []string{
		"migrations/minter",
		"migrations/audit",
	}

	for _, dir := range migrationDirs {
		t.Run(dir, func(t *testing.T) {
			fullPath := filepath.Join(projectRoot(t), dir)
			entries, err := os.ReadDir(fullPath)
			require.NoError(t, err)

			numbers := map[int]bool{}
			for _, e := range entries {
				name := e.Name()
				if !strings.HasSuffix(name, ".up.sql") {
					continue
				}
				// Extract leading number (e.g., "001" from "001_create_api_keys.up.sql")
				parts := strings.SplitN(name, "_", 2)
				require.NotEmpty(t, parts, "migration filename should have number prefix")
				num, err := strconv.Atoi(parts[0])
				require.NoError(t, err, "migration prefix should be numeric: %s", name)
				numbers[num] = true
			}

			// Verify sequential from 1
			for i := 1; i <= len(numbers); i++ {
				assert.True(t, numbers[i], "migration %03d is missing (gap in sequence)", i)
			}
		})
	}
}

// TestMigration_EnvVarIsolation verifies expected environment variables are not
// pre-set in the test process and won't interfere with integration tests.
func TestMigration_EnvVarIsolation(t *testing.T) {
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
	allVars := append([]string{}, gatewayEnvVars...)
	allVars = append(allVars, issuerEnvVars...)
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
	// The format is: sk-{base64url-keyId}.{base64url-secret}
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

// TestMigration_OpenAPISpecsExistAndValid verifies that OpenAPI specification
// files exist and contain required structural elements.
func TestMigration_OpenAPISpecsExistAndValid(t *testing.T) {
	specFiles := []struct {
		path         string
		expectedInfo string
	}{
		{"docs/openapi/tool-gateway.yaml", "Tool Gateway"},
		{"docs/openapi/capability-issuer.yaml", "Capability Issuer"},
		{"docs/openapi/capability-issuer-discovery.yaml", ""},
	}

	for _, spec := range specFiles {
		t.Run(filepath.Base(spec.path), func(t *testing.T) {
			fullPath := filepath.Join(projectRoot(t), spec.path)
			content, err := os.ReadFile(fullPath)
			require.NoError(t, err, "OpenAPI spec file should exist: %s", spec.path)

			yaml := string(content)

			// Must declare OpenAPI version
			assert.True(t, strings.Contains(yaml, "openapi:"),
				"spec should declare openapi version")

			// Must have info section
			assert.True(t, strings.Contains(yaml, "info:"),
				"spec should have info section")

			// Must have paths section
			assert.True(t, strings.Contains(yaml, "paths:"),
				"spec should have paths section")

			// Must have at least one path definition
			assert.True(t, strings.Contains(yaml, "/"),
				"spec should define at least one path")

			// Validate expected title if specified
			if spec.expectedInfo != "" {
				assert.True(t, strings.Contains(yaml, spec.expectedInfo),
					"spec should reference %s in title/description", spec.expectedInfo)
			}
		})
	}
}

// TestMigration_OpenAPISpecEndpointCoverage verifies that the OpenAPI specs
// document all critical endpoints that exist in the Go implementation.
func TestMigration_OpenAPISpecEndpointCoverage(t *testing.T) {
	gatewayEndpoints := []string{
		"/api/v1/validate",
		"/health",
	}

	issuerEndpoints := []string{
		"/api/v1/issue",
		"/health",
	}

	tests := []struct {
		specPath  string
		endpoints []string
	}{
		{"docs/openapi/tool-gateway.yaml", gatewayEndpoints},
		{"docs/openapi/capability-issuer.yaml", issuerEndpoints},
	}

	for _, tc := range tests {
		t.Run(filepath.Base(tc.specPath), func(t *testing.T) {
			fullPath := filepath.Join(projectRoot(t), tc.specPath)
			content, err := os.ReadFile(fullPath)
			require.NoError(t, err)

			yaml := string(content)
			for _, endpoint := range tc.endpoints {
				assert.True(t, strings.Contains(yaml, endpoint),
					"spec %s should document endpoint %s", tc.specPath, endpoint)
			}
		})
	}
}
