// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package config provides configuration models, loading, and validation helpers for Euno services.
package config

// EmitterConfig holds the Posture Emitter configuration.
type EmitterConfig struct {
	NodeEnv        Environment    `env:"NODE_ENV" default:"development" enum:"development,staging,production"`
	DeploymentTier DeploymentTier `env:"EUNO_DEPLOYMENT_TIER" default:"single-replica" enum:"single-replica,multi-replica,multi-region-active-active"`
	Port           int            `env:"PORT" default:"3008" min:"1" max:"65535"`

	// Emitter core
	Enabled         bool   `env:"POSTURE_EMITTER_ENABLED" default:"true"`
	QueuePath       string `env:"POSTURE_DURABLE_QUEUE_PATH" default:"posture-queue.db"`
	FlushIntervalMS int    `env:"POSTURE_DURABLE_POLL_INTERVAL_MS" default:"1000" min:"100"`
	MaxAttempts     int    `env:"POSTURE_DURABLE_MAX_ATTEMPTS" default:"10" min:"1"`
	BatchSize       int    `env:"POSTURE_DURABLE_BATCH_SIZE" default:"50" min:"1"`
	PluginTimeoutMS int    `env:"POSTURE_PLUGIN_TIMEOUT_MS" default:"5000" min:"100"`
	BackoffBaseMS   int    `env:"POSTURE_BACKOFF_BASE_MS" default:"1000" min:"100"`
	BackoffMaxMS    int    `env:"POSTURE_BACKOFF_MAX_MS" default:"300000" min:"1000"`
	DedupeWindowMS  int    `env:"POSTURE_DEDUPE_WINDOW_MS" default:"300000" min:"0"`

	// Health
	HealthMaxQueueDepth int `env:"POSTURE_HEALTH_MAX_QUEUE_DEPTH" default:"10000" min:"1"`

	// Request body limits
	MaxRequestBodySize int `env:"POSTURE_MAX_REQUEST_BODY_SIZE" default:"1048576" min:"1024" max:"104857600"`

	// Plugin selection (comma-separated: "defender,security-hub,scc,stdout")
	Plugins string `env:"POSTURE_EMITTER_PLUGINS" default:"stdout"`

	// Microsoft Defender CSPM
	DefenderSubscriptionID       string `env:"DEFENDER_SUBSCRIPTION_ID"`
	DefenderAssessmentNamePrefix string `env:"DEFENDER_ASSESSMENT_NAME_PREFIX" default:"euno-agent-"`

	// AWS Security Hub
	AWSAccountID     string `env:"AWS_ACCOUNT_ID"`
	AWSRegion        string `env:"AWS_REGION"`
	SecurityHubArn   string `env:"SECURITY_HUB_PRODUCT_ARN"`
	SecurityHubGenID string `env:"SECURITY_HUB_GENERATOR_ID" default:"euno/posture-emitter/v1"`

	// GCP Security Command Center
	GCPSourceName string `env:"GCP_SCC_SOURCE_NAME"`
	GCPProjectID  string `env:"GCP_PROJECT_ID"`
}
