// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package agentruntime

import (
	"context"
	"fmt"
	"strings"

	"github.com/eunolabs/eunox/pkg/capability"
)

// AgentCapabilityManifest declares the capabilities an agent requires.
// It is used to request capability tokens from the issuer with the
// appropriate scope and constraints.
type AgentCapabilityManifest struct {
	// Name is a human-readable name for the agent.
	Name string `json:"name"`
	// Version is the agent version.
	Version string `json:"version"`
	// Description is an optional human-readable description of the agent.
	Description string `json:"description,omitempty"`
	// Capabilities lists the capability constraints the agent requires.
	Capabilities []capability.Constraint `json:"capabilities"`
	// DefaultTTL is the default token TTL in seconds.
	DefaultTTL int `json:"defaultTtl,omitempty"`
	// Audience is the target audience for tokens.
	Audience string `json:"audience,omitempty"`
}

// ManifestBuilder provides a fluent API for building agent capability manifests.
type ManifestBuilder struct {
	manifest AgentCapabilityManifest
}

// NewManifestBuilder creates a new ManifestBuilder with the given agent name.
func NewManifestBuilder(name string) *ManifestBuilder {
	return &ManifestBuilder{
		manifest: AgentCapabilityManifest{
			Name: name,
		},
	}
}

// WithVersion sets the agent version.
func (b *ManifestBuilder) WithVersion(version string) *ManifestBuilder {
	b.manifest.Version = version
	return b
}

// WithDescription sets the agent description.
func (b *ManifestBuilder) WithDescription(description string) *ManifestBuilder {
	b.manifest.Description = description
	return b
}

// WithDefaultTTL sets the default token TTL in seconds.
func (b *ManifestBuilder) WithDefaultTTL(ttl int) *ManifestBuilder {
	b.manifest.DefaultTTL = ttl
	return b
}

// WithAudience sets the target audience.
func (b *ManifestBuilder) WithAudience(audience string) *ManifestBuilder {
	b.manifest.Audience = audience
	return b
}

// AddCapability adds a capability constraint to the manifest.
func (b *ManifestBuilder) AddCapability(c capability.Constraint) *ManifestBuilder {
	b.manifest.Capabilities = append(b.manifest.Capabilities, c)
	return b
}

// AddResourceAccess is a convenience method for adding a resource access capability.
func (b *ManifestBuilder) AddResourceAccess(resource string, actions ...string) *ManifestBuilder {
	c := capability.Constraint{
		Resource: resource,
		Actions:  actions,
	}
	b.manifest.Capabilities = append(b.manifest.Capabilities, c)
	return b
}

// Build validates and returns the manifest.
func (b *ManifestBuilder) Build() (*AgentCapabilityManifest, error) {
	if err := b.validate(); err != nil {
		return nil, err
	}
	m := b.manifest
	return &m, nil
}

func (b *ManifestBuilder) validate() error {
	var errs []string

	if strings.TrimSpace(b.manifest.Name) == "" {
		errs = append(errs, "name is required")
	}

	if strings.TrimSpace(b.manifest.Version) == "" {
		errs = append(errs, "version is required")
	}

	if len(b.manifest.Capabilities) == 0 {
		errs = append(errs, "at least one capability is required")
	}

	for i, c := range b.manifest.Capabilities {
		if strings.TrimSpace(c.Resource) == "" {
			errs = append(errs, fmt.Sprintf("capability[%d]: resource is required", i))
		}
		if len(c.Actions) == 0 {
			errs = append(errs, fmt.Sprintf("capability[%d]: at least one action is required", i))
		}
		for j, action := range c.Actions {
			if strings.TrimSpace(action) == "" {
				errs = append(errs, fmt.Sprintf("capability[%d].actions[%d]: action must not be empty", i, j))
			}
		}
	}

	if b.manifest.DefaultTTL < 0 {
		errs = append(errs, "defaultTtl must be non-negative")
	}

	if len(errs) > 0 {
		return fmt.Errorf("manifest validation failed: %s", strings.Join(errs, "; "))
	}

	return nil
}

// ToIssuanceHints converts the manifest to IssuanceHints for token requests.
func (m *AgentCapabilityManifest) ToIssuanceHints() *IssuanceHints {
	return &IssuanceHints{
		Capabilities: m.Capabilities,
		TTL:          m.DefaultTTL,
		Audience:     m.Audience,
	}
}

// StaticHintsProvider wraps a manifest to implement IssuanceHintsProvider.
type StaticHintsProvider struct {
	hints *IssuanceHints
}

// NewStaticHintsProvider creates a hints provider that always returns the same hints.
func NewStaticHintsProvider(manifest *AgentCapabilityManifest) *StaticHintsProvider {
	return &StaticHintsProvider{
		hints: manifest.ToIssuanceHints(),
	}
}

// GetHints returns the static issuance hints.
func (p *StaticHintsProvider) GetHints(_ context.Context) (*IssuanceHints, error) {
	return p.hints, nil
}
