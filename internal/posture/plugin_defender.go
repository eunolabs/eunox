// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package posture

import (
	"context"
	"fmt"
	"time"
)

// DefenderClient is the interface for interacting with Microsoft Defender for Cloud.
type DefenderClient interface {
	// CreateOrUpdateAssessment creates or updates a custom security assessment.
	CreateOrUpdateAssessment(ctx context.Context, resourceID, assessmentName string, assessment DefenderAssessment) error
	// DeleteAssessment deletes a custom security assessment.
	DeleteAssessment(ctx context.Context, resourceID, assessmentName string) error
}

// DefenderAssessment represents a Microsoft Defender custom assessment payload.
type DefenderAssessment struct {
	Status         string            `json:"status"`
	AdditionalData map[string]string `json:"additionalData"`
	Description    string            `json:"description"`
	DisplayName    string            `json:"displayName"`
	ResourceID     string            `json:"resourceId,omitempty"`
}

// DefenderPluginConfig holds configuration for the Microsoft Defender CSPM plugin.
type DefenderPluginConfig struct {
	// SubscriptionID is the Azure subscription ID.
	SubscriptionID string
	// AssessmentNamePrefix is the prefix for custom assessment names.
	AssessmentNamePrefix string
	// ClientFactory creates the Defender client (test seam).
	ClientFactory func() DefenderClient
}

// DefenderPlugin delivers posture records to Microsoft Defender for Cloud
// as custom security assessments.
type DefenderPlugin struct {
	config DefenderPluginConfig
	client DefenderClient
}

// NewDefenderPlugin creates a new Microsoft Defender CSPM plugin.
func NewDefenderPlugin(cfg DefenderPluginConfig) *DefenderPlugin {
	if cfg.AssessmentNamePrefix == "" {
		cfg.AssessmentNamePrefix = "eunox-agent-"
	}

	var client DefenderClient
	if cfg.ClientFactory != nil {
		client = cfg.ClientFactory()
	}

	return &DefenderPlugin{
		config: cfg,
		client: client,
	}
}

// Name returns the plugin identifier.
func (p *DefenderPlugin) Name() string {
	return "defender"
}

// EmitObserved creates or updates a custom assessment for the observed agent.
func (p *DefenderPlugin) EmitObserved(ctx context.Context, record *AgentInventoryRecord) error {
	if p.client == nil {
		return fmt.Errorf("defender plugin: client not configured")
	}

	resourceID := fmt.Sprintf("/subscriptions/%s", p.config.SubscriptionID)
	assessmentName := p.config.AssessmentNamePrefix + sanitizeID(record.AgentID)

	assessment := DefenderAssessment{
		Status:      "Healthy",
		DisplayName: fmt.Sprintf("AI Agent: %s", record.AgentID),
		Description: "Eunox AI agent inventory posture record",
		AdditionalData: map[string]string{
			"agentId":                record.AgentID,
			"owningTeam":             record.OwningTeam,
			"capabilityManifestHash": record.CapabilityManifestHash,
			"runtime":                record.Runtime,
			"region":                 record.Region,
			"firstSeen":              record.FirstSeen.UTC().Format(time.RFC3339),
			"lastSeen":               record.LastSeen.UTC().Format(time.RFC3339),
		},
	}

	return p.client.CreateOrUpdateAssessment(ctx, resourceID, assessmentName, assessment)
}

// EmitRevoked marks the agent's assessment as not applicable (soft delete).
func (p *DefenderPlugin) EmitRevoked(ctx context.Context, agentID string, revokedAt time.Time) error {
	if p.client == nil {
		return fmt.Errorf("defender plugin: client not configured")
	}

	resourceID := fmt.Sprintf("/subscriptions/%s", p.config.SubscriptionID)
	assessmentName := p.config.AssessmentNamePrefix + sanitizeID(agentID)

	assessment := DefenderAssessment{
		Status:      "NotApplicable",
		DisplayName: fmt.Sprintf("AI Agent: %s (revoked)", agentID),
		Description: "Eunox AI agent revoked",
		AdditionalData: map[string]string{
			"agentId":   agentID,
			"revokedAt": revokedAt.UTC().Format(time.RFC3339),
		},
	}

	return p.client.CreateOrUpdateAssessment(ctx, resourceID, assessmentName, assessment)
}

// Compile-time interface check.
var _ Plugin = (*DefenderPlugin)(nil)
