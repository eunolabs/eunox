// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOpenAPI_SpecsExistAndValid verifies that OpenAPI specification files
// exist and contain the required structural elements.
func TestOpenAPI_SpecsExistAndValid(t *testing.T) {
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

			assert.True(t, strings.Contains(yaml, "openapi:"),
				"spec should declare openapi version")
			assert.True(t, strings.Contains(yaml, "info:"),
				"spec should have info section")
			assert.True(t, strings.Contains(yaml, "paths:"),
				"spec should have paths section")
			assert.True(t, strings.Contains(yaml, "/"),
				"spec should define at least one path")

			if spec.expectedInfo != "" {
				assert.True(t, strings.Contains(yaml, spec.expectedInfo),
					"spec should reference %s in title/description", spec.expectedInfo)
			}
		})
	}
}

// TestOpenAPI_EndpointCoverage verifies that the OpenAPI specs document all
// critical endpoints that exist in the Go implementation.
func TestOpenAPI_EndpointCoverage(t *testing.T) {
	tests := []struct {
		specPath  string
		endpoints []string
	}{
		{
			"docs/openapi/tool-gateway.yaml",
			[]string{"/api/v1/validate", "/health"},
		},
		{
			"docs/openapi/capability-issuer.yaml",
			[]string{"/api/v1/issue", "/health"},
		},
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
