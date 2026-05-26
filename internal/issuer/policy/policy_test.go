// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/edgeobs/eunox/pkg/capability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEngine_LoadFromFile(t *testing.T) {
	policyFile := File{
		Version: "1.0",
		Policies: []RoleCapabilityPolicy{
			{
				Role:          "developer",
				Description:   "Developer role",
				MaxTTLSeconds: 3600,
				Capabilities: []capability.Constraint{
					{
						Resource: "tool:*",
						Actions:  []string{"read", "write"},
					},
				},
			},
			{
				Role:          "viewer",
				Description:   "Viewer role",
				MaxTTLSeconds: 1800,
				Capabilities: []capability.Constraint{
					{
						Resource: "tool:*",
						Actions:  []string{"read"},
					},
				},
			},
		},
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")
	data, err := json.Marshal(policyFile)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))

	engine := New()
	err = engine.LoadFromFile(path)
	require.NoError(t, err)

	// Test GetPolicy
	dev, err := engine.GetPolicy("developer")
	require.NoError(t, err)
	assert.Equal(t, "developer", dev.Role)
	assert.Equal(t, 3600, dev.MaxTTLSeconds)
	assert.Len(t, dev.Capabilities, 1)
	assert.Equal(t, "tool:*", dev.Capabilities[0].Resource)

	// Test non-existent role
	_, err = engine.GetPolicy("admin")
	assert.ErrorIs(t, err, ErrPolicyNotFound)
}

func TestEngine_SetPolicy(t *testing.T) {
	engine := New()

	policy := &RoleCapabilityPolicy{
		Role:          "admin",
		MaxTTLSeconds: 7200,
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	}

	engine.SetPolicy(policy)

	got, err := engine.GetPolicy("admin")
	require.NoError(t, err)
	assert.Equal(t, "admin", got.Role)
	assert.Equal(t, 7200, got.MaxTTLSeconds)
}

func TestEngine_RemovePolicy(t *testing.T) {
	engine := New()
	engine.SetPolicy(&RoleCapabilityPolicy{Role: "temp"})

	assert.True(t, engine.RemovePolicy("temp"))
	assert.False(t, engine.RemovePolicy("temp"))

	_, err := engine.GetPolicy("temp")
	assert.ErrorIs(t, err, ErrPolicyNotFound)
}

func TestEngine_ListPolicies(t *testing.T) {
	engine := New()
	engine.SetPolicy(&RoleCapabilityPolicy{Role: "a"})
	engine.SetPolicy(&RoleCapabilityPolicy{Role: "b"})

	policies := engine.ListPolicies()
	assert.Len(t, policies, 2)
}

func TestEngine_MaxTTLForRole(t *testing.T) {
	engine := New(WithDefaultMaxTTL(600))
	engine.SetPolicy(&RoleCapabilityPolicy{Role: "fast", MaxTTLSeconds: 300})
	engine.SetPolicy(&RoleCapabilityPolicy{Role: "default", MaxTTLSeconds: 0})

	assert.Equal(t, 300, engine.MaxTTLForRole("fast"))
	assert.Equal(t, 600, engine.MaxTTLForRole("default"))
	assert.Equal(t, 600, engine.MaxTTLForRole("nonexistent"))
}

func TestEngine_IntersectCapabilities_DefaultsToPolicy(t *testing.T) {
	engine := New()
	engine.SetPolicy(&RoleCapabilityPolicy{
		Role: "dev",
		Capabilities: []capability.Constraint{
			{Resource: "tool:read", Actions: []string{"GET"}},
			{Resource: "tool:write", Actions: []string{"POST"}},
		},
	})

	// Empty request → returns all policy capabilities
	caps, err := engine.IntersectCapabilities("dev", nil)
	require.NoError(t, err)
	assert.Len(t, caps, 2)
}

func TestEngine_IntersectCapabilities_NarrowsToIntersection(t *testing.T) {
	engine := New()
	engine.SetPolicy(&RoleCapabilityPolicy{
		Role: "dev",
		Capabilities: []capability.Constraint{
			{Resource: "tool:*", Actions: []string{"read", "write", "delete"}},
		},
	})

	requested := []capability.Constraint{
		{Resource: "tool:files", Actions: []string{"read", "write"}},
	}

	caps, err := engine.IntersectCapabilities("dev", requested)
	require.NoError(t, err)
	require.Len(t, caps, 1)
	assert.Equal(t, "tool:files", caps[0].Resource)
	assert.Equal(t, []string{"read", "write"}, caps[0].Actions)
}

func TestEngine_IntersectCapabilities_NoMatch(t *testing.T) {
	engine := New()
	engine.SetPolicy(&RoleCapabilityPolicy{
		Role: "viewer",
		Capabilities: []capability.Constraint{
			{Resource: "docs:*", Actions: []string{"read"}},
		},
	})

	requested := []capability.Constraint{
		{Resource: "admin:panel", Actions: []string{"write"}},
	}

	_, err := engine.IntersectCapabilities("viewer", requested)
	assert.ErrorIs(t, err, ErrInvalidManifest)
}

func TestEngine_IntersectCapabilities_ActionIntersection(t *testing.T) {
	engine := New()
	engine.SetPolicy(&RoleCapabilityPolicy{
		Role: "dev",
		Capabilities: []capability.Constraint{
			{Resource: "api:*", Actions: []string{"GET", "POST"}},
		},
	})

	// Request includes DELETE which policy doesn't allow
	requested := []capability.Constraint{
		{Resource: "api:users", Actions: []string{"GET", "DELETE"}},
	}

	caps, err := engine.IntersectCapabilities("dev", requested)
	require.NoError(t, err)
	require.Len(t, caps, 1)
	assert.Equal(t, []string{"GET"}, caps[0].Actions)
}

func TestEngine_IntersectCapabilities_PolicyWildcardActions(t *testing.T) {
	engine := New()
	engine.SetPolicy(&RoleCapabilityPolicy{
		Role: "admin",
		Capabilities: []capability.Constraint{
			{Resource: "*", Actions: []string{"*"}},
		},
	})

	requested := []capability.Constraint{
		{Resource: "tool:fs", Actions: []string{"read", "write"}},
	}

	caps, err := engine.IntersectCapabilities("admin", requested)
	require.NoError(t, err)
	require.Len(t, caps, 1)
	assert.Equal(t, []string{"read", "write"}, caps[0].Actions)
}

func TestValidateSubset_Valid(t *testing.T) {
	parent := []capability.Constraint{
		{Resource: "tool:*", Actions: []string{"read", "write", "delete"}},
	}
	child := []capability.Constraint{
		{Resource: "tool:files", Actions: []string{"read"}},
	}

	err := ValidateSubset(child, parent)
	assert.NoError(t, err)
}

func TestValidateSubset_Invalid_ResourceNotCovered(t *testing.T) {
	parent := []capability.Constraint{
		{Resource: "tool:files", Actions: []string{"read"}},
	}
	child := []capability.Constraint{
		{Resource: "admin:panel", Actions: []string{"read"}},
	}

	err := ValidateSubset(child, parent)
	assert.ErrorIs(t, err, ErrSubsetViolation)
}

func TestValidateSubset_Invalid_ActionNotCovered(t *testing.T) {
	parent := []capability.Constraint{
		{Resource: "tool:*", Actions: []string{"read"}},
	}
	child := []capability.Constraint{
		{Resource: "tool:files", Actions: []string{"read", "write"}},
	}

	err := ValidateSubset(child, parent)
	assert.ErrorIs(t, err, ErrSubsetViolation)
}

func TestValidateSubset_ChildWildcardActions(t *testing.T) {
	parent := []capability.Constraint{
		{Resource: "tool:*", Actions: []string{"read"}},
	}
	child := []capability.Constraint{
		{Resource: "tool:files", Actions: []string{"*"}},
	}

	err := ValidateSubset(child, parent)
	assert.ErrorIs(t, err, ErrSubsetViolation)
}

func TestValidateSubset_Invalid_DropsParentConditions(t *testing.T) {
	parent := []capability.Constraint{
		{
			Resource: "tool:*",
			Actions:  []string{"read"},
			Conditions: []capability.Condition{
				capability.IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}},
			},
		},
	}
	child := []capability.Constraint{
		{
			Resource: "tool:files",
			Actions:  []string{"read"},
		},
	}

	err := ValidateSubset(child, parent)
	assert.ErrorIs(t, err, ErrSubsetViolation)
}

func TestValidateSubset_Invalid_DropsParentArgumentSchema(t *testing.T) {
	parent := []capability.Constraint{
		{
			Resource: "tool:*",
			Actions:  []string{"read"},
			ArgumentSchema: &capability.ArgumentSchema{
				Type: capability.SchemaType{Single: "object"},
			},
		},
	}
	child := []capability.Constraint{
		{
			Resource: "tool:files",
			Actions:  []string{"read"},
		},
	}

	err := ValidateSubset(child, parent)
	assert.ErrorIs(t, err, ErrSubsetViolation)
}

func TestEngine_HotReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")

	// Write initial policy
	initial := File{
		Version: "1.0",
		Policies: []RoleCapabilityPolicy{
			{Role: "dev", MaxTTLSeconds: 900},
		},
	}
	writePolicy(t, path, initial)

	engine := New(WithPollInterval(50 * time.Millisecond))
	require.NoError(t, engine.LoadFromFile(path))
	engine.StartHotReload()
	defer engine.Stop()

	// Verify initial
	p, err := engine.GetPolicy("dev")
	require.NoError(t, err)
	assert.Equal(t, 900, p.MaxTTLSeconds)

	// Update policy file
	time.Sleep(100 * time.Millisecond) // ensure mtime changes
	updated := File{
		Version: "1.0",
		Policies: []RoleCapabilityPolicy{
			{Role: "dev", MaxTTLSeconds: 1800},
			{Role: "ops", MaxTTLSeconds: 600},
		},
	}
	writePolicy(t, path, updated)

	// Wait for reload
	time.Sleep(200 * time.Millisecond)

	p, err = engine.GetPolicy("dev")
	require.NoError(t, err)
	assert.Equal(t, 1800, p.MaxTTLSeconds)

	_, err = engine.GetPolicy("ops")
	assert.NoError(t, err)
}

func TestEngine_StopIsIdempotent(_ *testing.T) {
	engine := New()
	engine.Stop()
	engine.Stop()
}

func TestResourceCovers(t *testing.T) {
	tests := []struct {
		policy   string
		request  string
		expected bool
	}{
		{"*", "anything", true},
		{"tool:read", "tool:read", true},
		{"tool:read", "tool:write", false},
		{"tool:*", "tool:read", true},
		{"tool:*", "tool:", true},
		{"tool:", "tool:read", false},
	}

	for _, tt := range tests {
		t.Run(tt.policy+"_"+tt.request, func(t *testing.T) {
			assert.Equal(t, tt.expected, resourceCovers(tt.policy, tt.request))
		})
	}
}

func TestEngine_LoadFromFile_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(path, []byte("not json"), 0o600))

	engine := New()
	err := engine.LoadFromFile(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse policy file")
}

func TestEngine_LoadFromFile_NotFound(t *testing.T) {
	engine := New()
	err := engine.LoadFromFile("/nonexistent/path.json")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read policy file")
}

func TestEngine_IntersectCapabilities_PolicyNotFound(t *testing.T) {
	engine := New()
	_, err := engine.IntersectCapabilities("nonexistent", nil)
	assert.ErrorIs(t, err, ErrPolicyNotFound)
}

func TestEngine_IntersectCapabilities_MergesConditions(t *testing.T) {
	engine := New()
	engine.SetPolicy(&RoleCapabilityPolicy{
		Role: "dev",
		Capabilities: []capability.Constraint{
			{
				Resource: "*",
				Actions:  []string{"*"},
				Conditions: []capability.Condition{
					&capability.IPRangeCondition{CIDRs: []string{"10.0.0.0/8"}},
				},
			},
		},
	})

	requested := []capability.Constraint{
		{
			Resource: "tool:fs",
			Actions:  []string{"read"},
			Conditions: []capability.Condition{
				&capability.TimeWindowCondition{NotAfter: "2030-01-01T00:00:00Z"},
			},
		},
	}

	caps, err := engine.IntersectCapabilities("dev", requested)
	require.NoError(t, err)
	require.Len(t, caps, 1)
	// Should have both conditions (requested + policy)
	assert.Len(t, caps[0].Conditions, 2)
}

func writePolicy(t *testing.T, path string, pf File) {
	t.Helper()
	data, err := json.Marshal(pf)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
}
