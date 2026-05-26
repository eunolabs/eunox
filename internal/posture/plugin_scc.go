// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package posture

import (
	"context"
	"fmt"
	"time"
)

// SccClient is the interface for interacting with GCP Security Command Center.
type SccClient interface {
	// CreateFinding creates a new finding in SCC.
	CreateFinding(ctx context.Context, req *SccCreateFindingRequest) error
	// UpdateFinding updates an existing finding in SCC.
	UpdateFinding(ctx context.Context, req *SccUpdateFindingRequest) error
}

// SccCreateFindingRequest is the request to create a finding.
type SccCreateFindingRequest struct {
	Parent    string     `json:"parent"`
	FindingID string     `json:"findingId"`
	Finding   SccFinding `json:"finding"`
}

// SccUpdateFindingRequest is the request to update a finding.
type SccUpdateFindingRequest struct {
	FindingName string     `json:"name"`
	Finding     SccFinding `json:"finding"`
	UpdateMask  []string   `json:"updateMask"`
}

// SccFinding represents a GCP Security Command Center finding.
type SccFinding struct {
	State            string            `json:"state"`
	Category         string            `json:"category"`
	FindingClass     string            `json:"findingClass"`
	EventTime        string            `json:"eventTime"`
	SourceProperties map[string]string `json:"sourceProperties"`
	Description      string            `json:"description"`
	ResourceName     string            `json:"resourceName,omitempty"`
}

// SccPluginConfig holds configuration for the GCP Security Command Center plugin.
type SccPluginConfig struct {
	// SourceName is the SCC source (e.g., "organizations/123/sources/456").
	SourceName string
	// ProjectID is the GCP project ID.
	ProjectID string
	// ClientFactory creates the SCC client (test seam).
	ClientFactory func() SccClient
}

// SccPlugin delivers posture records to GCP Security Command Center as findings.
type SccPlugin struct {
	config SccPluginConfig
	client SccClient
}

// NewSccPlugin creates a new GCP Security Command Center plugin.
func NewSccPlugin(cfg SccPluginConfig) *SccPlugin {
	var client SccClient
	if cfg.ClientFactory != nil {
		client = cfg.ClientFactory()
	}

	return &SccPlugin{
		config: cfg,
		client: client,
	}
}

// Name returns the plugin identifier.
func (p *SccPlugin) Name() string {
	return "scc"
}

// EmitObserved creates or updates a finding for the observed agent.
func (p *SccPlugin) EmitObserved(ctx context.Context, record *AgentInventoryRecord) error {
	if p.client == nil {
		return fmt.Errorf("scc plugin: client not configured")
	}

	findingID := sanitizeFindingID(record.AgentID)

	finding := SccFinding{
		State:        "ACTIVE",
		Category:     "EUNO_AGENT_INVENTORY",
		FindingClass: "OBSERVATION",
		EventTime:    record.LastSeen.UTC().Format(time.RFC3339),
		Description:  fmt.Sprintf("AI agent %s observed in posture inventory", record.AgentID),
		ResourceName: fmt.Sprintf("//euno.dev/agents/%s", record.AgentID),
		SourceProperties: map[string]string{
			"agentId":                record.AgentID,
			"owningTeam":             record.OwningTeam,
			"capabilityManifestHash": record.CapabilityManifestHash,
			"runtime":                record.Runtime,
			"region":                 record.Region,
			"firstSeen":              record.FirstSeen.UTC().Format(time.RFC3339),
			"lastSeen":               record.LastSeen.UTC().Format(time.RFC3339),
		},
	}

	// Try create first; if already exists, fall back to update.
	err := p.client.CreateFinding(ctx, &SccCreateFindingRequest{
		Parent:    p.config.SourceName,
		FindingID: findingID,
		Finding:   finding,
	})

	if err != nil && isAlreadyExists(err) {
		return p.client.UpdateFinding(ctx, &SccUpdateFindingRequest{
			FindingName: fmt.Sprintf("%s/findings/%s", p.config.SourceName, findingID),
			Finding:     finding,
			UpdateMask:  []string{"state", "event_time", "source_properties"},
		})

	}

	return err
}

// EmitRevoked marks the finding as inactive.
func (p *SccPlugin) EmitRevoked(ctx context.Context, agentID string, revokedAt time.Time) error {
	if p.client == nil {
		return fmt.Errorf("scc plugin: client not configured")
	}

	findingID := sanitizeFindingID(agentID)

	finding := SccFinding{
		State:     "INACTIVE",
		EventTime: revokedAt.UTC().Format(time.RFC3339),
		SourceProperties: map[string]string{
			"agentId":   agentID,
			"revokedAt": revokedAt.UTC().Format(time.RFC3339),
		},
	}

	return p.client.UpdateFinding(ctx, &SccUpdateFindingRequest{
		FindingName: fmt.Sprintf("%s/findings/%s", p.config.SourceName, findingID),
		Finding:     finding,
		UpdateMask:  []string{"state", "event_time", "source_properties"},
	})

}

// sanitizeFindingID replaces non-alphanumeric characters and caps length for SCC finding IDs.
func sanitizeFindingID(id string) string {
	const maxLen = 32
	result := make([]byte, 0, len(id))
	for _, c := range []byte(id) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			result = append(result, c)
		} else {
			result = append(result, '_')
		}
	}
	if len(result) > maxLen {
		result = result[:maxLen]
	}
	return string(result)
}

// isAlreadyExists checks if an error indicates the resource already exists.
func isAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	// Check for common "already exists" patterns.
	msg := err.Error()
	for _, pattern := range []string{"ALREADY_EXISTS", "already exists", "AlreadyExists", "code 6"} {
		if containsStr(msg, pattern) {
			return true
		}
	}
	return false
}

// containsStr is a simple substring check without importing strings.
func containsStr(s, substr string) bool {
	return len(substr) <= len(s) && searchStr(s, substr) >= 0
}

func searchStr(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// Compile-time interface check.
var _ Plugin = (*SccPlugin)(nil)
