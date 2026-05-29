// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package posture

import (
	"context"
	"fmt"
	"time"
)

// SecurityHubClient is the interface for interacting with AWS Security Hub.
type SecurityHubClient interface {
	// BatchImportFindings imports findings into Security Hub.
	BatchImportFindings(ctx context.Context, findings []SecurityHubFinding) error
	// BatchUpdateFindings updates existing findings in Security Hub.
	BatchUpdateFindings(ctx context.Context, identifiers []FindingIdentifier, update FindingUpdate) error
}

// SecurityHubFinding represents an AWS Security Hub ASFF finding.
type SecurityHubFinding struct {
	SchemaVersion     string            `json:"SchemaVersion"`
	ID                string            `json:"Id"`
	ProductArn        string            `json:"ProductArn"`
	GeneratorID       string            `json:"GeneratorId"`
	AwsAccountID      string            `json:"AwsAccountId"`
	Types             []string          `json:"Types"`
	CreatedAt         string            `json:"CreatedAt"`
	UpdatedAt         string            `json:"UpdatedAt"`
	Severity          FindingSeverity   `json:"Severity"`
	Title             string            `json:"Title"`
	Description       string            `json:"Description"`
	ProductFields     map[string]string `json:"ProductFields"`
	Resources         []FindingResource `json:"Resources"`
	Workflow          *FindingWorkflow  `json:"Workflow,omitempty"`
	RecordState       string            `json:"RecordState"`
	UserDefinedFields map[string]string `json:"UserDefinedFields,omitempty"`
}

// FindingSeverity represents the severity section of a finding.
type FindingSeverity struct {
	Label string `json:"Label"`
}

// FindingResource represents a resource referenced by a finding.
type FindingResource struct {
	Type   string            `json:"Type"`
	ID     string            `json:"Id"`
	Region string            `json:"Region"`
	Tags   map[string]string `json:"Tags,omitempty"`
}

// FindingWorkflow represents the workflow status.
type FindingWorkflow struct {
	Status string `json:"Status"`
}

// FindingIdentifier identifies a specific finding for updates.
type FindingIdentifier struct {
	ID         string `json:"Id"`
	ProductArn string `json:"ProductArn"`
}

// FindingUpdate contains the fields to update on a finding.
type FindingUpdate struct {
	Workflow    *FindingWorkflow `json:"Workflow,omitempty"`
	RecordState string           `json:"RecordState,omitempty"`
}

// SecurityHubPluginConfig holds configuration for the AWS Security Hub plugin.
type SecurityHubPluginConfig struct {
	// AWSAccountID is the AWS account ID.
	AWSAccountID string
	// Region is the AWS region.
	Region string
	// ProductArn is the ARN of the Security Hub product.
	ProductArn string
	// GeneratorID identifies the finding generator.
	GeneratorID string
	// ClientFactory creates the Security Hub client (test seam).
	ClientFactory func() SecurityHubClient
}

// SecurityHubPlugin delivers posture records to AWS Security Hub as ASFF findings.
type SecurityHubPlugin struct {
	config SecurityHubPluginConfig
	client SecurityHubClient
}

// NewSecurityHubPlugin creates a new AWS Security Hub plugin.
func NewSecurityHubPlugin(cfg SecurityHubPluginConfig) *SecurityHubPlugin {
	if cfg.GeneratorID == "" {
		cfg.GeneratorID = "eunox/posture-emitter/v1"
	}

	var client SecurityHubClient
	if cfg.ClientFactory != nil {
		client = cfg.ClientFactory()
	}

	return &SecurityHubPlugin{
		config: cfg,
		client: client,
	}
}

// Name returns the plugin identifier.
func (p *SecurityHubPlugin) Name() string {
	return "security-hub"
}

// EmitObserved imports a finding for the observed agent.
func (p *SecurityHubPlugin) EmitObserved(ctx context.Context, record *AgentInventoryRecord) error {
	if p.client == nil {
		return fmt.Errorf("security-hub plugin: client not configured")
	}

	findingID := fmt.Sprintf("eunox-agent/%s", sanitizeID(record.AgentID))
	now := time.Now().UTC().Format(time.RFC3339)

	finding := SecurityHubFinding{
		SchemaVersion: "2018-10-08",
		ID:            findingID,
		ProductArn:    p.config.ProductArn,
		GeneratorID:   p.config.GeneratorID,
		AwsAccountID:  p.config.AWSAccountID,
		Types:         []string{"Software and Configuration Checks/AWS Security Best Practices/AI-Inventory"},
		CreatedAt:     record.FirstSeen.UTC().Format(time.RFC3339),
		UpdatedAt:     now,
		Severity:      FindingSeverity{Label: "INFORMATIONAL"},
		Title:         fmt.Sprintf("AI Agent Inventory: %s", record.AgentID),
		Description:   "Eunox AI agent observed in posture inventory",
		RecordState:   "ACTIVE",
		ProductFields: map[string]string{
			"agentId":                record.AgentID,
			"owningTeam":             record.OwningTeam,
			"capabilityManifestHash": record.CapabilityManifestHash,
			"runtime":                record.Runtime,
			"region":                 record.Region,
		},
		Resources: []FindingResource{
			{
				Type:   "Other",
				ID:     record.AgentID,
				Region: p.config.Region,
				Tags: map[string]string{
					"agentId":    record.AgentID,
					"owningTeam": record.OwningTeam,
					"runtime":    record.Runtime,
				},
			},
		},
	}

	return p.client.BatchImportFindings(ctx, []SecurityHubFinding{finding})
}

// EmitRevoked updates the finding to resolved state.
func (p *SecurityHubPlugin) EmitRevoked(ctx context.Context, agentID string, _ time.Time) error {
	if p.client == nil {
		return fmt.Errorf("security-hub plugin: client not configured")
	}

	findingID := fmt.Sprintf("eunox-agent/%s", sanitizeID(agentID))

	identifiers := []FindingIdentifier{
		{
			ID:         findingID,
			ProductArn: p.config.ProductArn,
		},
	}

	update := FindingUpdate{
		Workflow:    &FindingWorkflow{Status: "RESOLVED"},
		RecordState: "ARCHIVED",
	}

	return p.client.BatchUpdateFindings(ctx, identifiers, update)
}

// Compile-time interface check.
var _ Plugin = (*SecurityHubPlugin)(nil)
