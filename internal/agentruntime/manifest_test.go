// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package agentruntime

import (
	"context"
	"testing"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManifestBuilder_ValidManifest(t *testing.T) {
	manifest, err := NewManifestBuilder("test-agent").
		WithVersion("1.0.0").
		WithDescription("A test agent").
		WithDefaultTTL(600).
		WithAudience("https://example.com").
		AddResourceAccess("file:///*", "read", "write").
		AddResourceAccess("db://mydb/*", "query").
		Build()

	require.NoError(t, err)
	assert.Equal(t, "test-agent", manifest.Name)
	assert.Equal(t, "1.0.0", manifest.Version)
	assert.Equal(t, "A test agent", manifest.Description)
	assert.Equal(t, 600, manifest.DefaultTTL)
	assert.Equal(t, "https://example.com", manifest.Audience)
	assert.Len(t, manifest.Capabilities, 2)
	assert.Equal(t, "file:///*", manifest.Capabilities[0].Resource)
	assert.Equal(t, []string{"read", "write"}, manifest.Capabilities[0].Actions)
}

func TestManifestBuilder_MissingName(t *testing.T) {
	_, err := NewManifestBuilder("").
		WithVersion("1.0.0").
		AddResourceAccess("file:///*", "read").
		Build()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "name is required")
}

func TestManifestBuilder_MissingVersion(t *testing.T) {
	_, err := NewManifestBuilder("agent").
		AddResourceAccess("file:///*", "read").
		Build()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "version is required")
}

func TestManifestBuilder_NoCapabilities(t *testing.T) {
	_, err := NewManifestBuilder("agent").
		WithVersion("1.0.0").
		Build()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one capability is required")
}

func TestManifestBuilder_EmptyResource(t *testing.T) {
	_, err := NewManifestBuilder("agent").
		WithVersion("1.0.0").
		AddResourceAccess("", "read").
		Build()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "resource is required")
}

func TestManifestBuilder_EmptyActions(t *testing.T) {
	_, err := NewManifestBuilder("agent").
		WithVersion("1.0.0").
		AddCapability(capability.Constraint{Resource: "file:///*"}).
		Build()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one action is required")
}

func TestManifestBuilder_EmptyActionString(t *testing.T) {
	_, err := NewManifestBuilder("agent").
		WithVersion("1.0.0").
		AddResourceAccess("file:///*", "read", "").
		Build()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "action must not be empty")
}

func TestManifestBuilder_AddCapability(t *testing.T) {
	manifest, err := NewManifestBuilder("agent").
		WithVersion("1.0.0").
		AddCapability(capability.Constraint{
			Resource: "api://service/*",
			Actions:  []string{"invoke"},
			Conditions: []capability.Condition{
				&capability.TimeWindowCondition{
					NotBefore: "2025-01-01T09:00:00Z",
					NotAfter:  "2025-12-31T17:00:00Z",
				},
			},
		}).
		Build()

	require.NoError(t, err)
	assert.Len(t, manifest.Capabilities, 1)
	assert.Equal(t, "api://service/*", manifest.Capabilities[0].Resource)
	assert.Len(t, manifest.Capabilities[0].Conditions, 1)
}

func TestManifest_ToIssuanceHints(t *testing.T) {
	manifest := &AgentCapabilityManifest{
		Name:    "agent",
		Version: "1.0.0",
		Capabilities: []capability.Constraint{
			{Resource: "file:///*", Actions: []string{"read"}},
		},
		DefaultTTL: 300,
		Audience:   "https://example.com",
	}

	hints := manifest.ToIssuanceHints()
	assert.Equal(t, 300, hints.TTL)
	assert.Equal(t, "https://example.com", hints.Audience)
	assert.Len(t, hints.Capabilities, 1)
}

func TestStaticHintsProvider(t *testing.T) {
	manifest := &AgentCapabilityManifest{
		Name:    "agent",
		Version: "1.0.0",
		Capabilities: []capability.Constraint{
			{Resource: "file:///*", Actions: []string{"read"}},
		},
		DefaultTTL: 300,
	}

	provider := NewStaticHintsProvider(manifest)
	hints, err := provider.GetHints(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 300, hints.TTL)
	assert.Len(t, hints.Capabilities, 1)
}

func TestManifestBuilder_MultipleErrors(t *testing.T) {
	_, err := NewManifestBuilder("").
		AddResourceAccess("", "read").
		Build()

	require.Error(t, err)
	// Should report multiple errors
	assert.Contains(t, err.Error(), "name is required")
	assert.Contains(t, err.Error(), "version is required")
	assert.Contains(t, err.Error(), "resource is required")
}
