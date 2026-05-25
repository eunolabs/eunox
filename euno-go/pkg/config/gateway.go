// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

// Package config provides configuration models, loading, and validation helpers for Euno services.
package config

// GatewayConfig holds the Tool Gateway configuration.
type GatewayConfig struct {
	NodeEnv           Environment    `env:"NODE_ENV" default:"development" enum:"development,staging,production"`
	DeploymentTier    DeploymentTier `env:"EUNO_DEPLOYMENT_TIER" default:"single-replica" enum:"single-replica,multi-replica,multi-region-active-active"`
	Port              int            `env:"PORT" default:"3002" min:"1" max:"65535"`
	AdminPort         int            `env:"ADMIN_PORT" default:"3003" min:"1" max:"65535"`
	AdminHost         string         `env:"ADMIN_HOST" production:"required"`
	IssuerJWKSURL     string         `env:"ISSUER_JWKS_URL"`
	BackendServiceURL string         `env:"BACKEND_SERVICE_URL"`
	AdminAPIKey       string         `env:"ADMIN_API_KEY" production:"required"`
	RequireKID        bool           `env:"EUNO_REQUIRE_KID" default:"true"`
	JWKSCacheTTL      int            `env:"EUNO_JWKS_CACHE_TTL_SECONDS" default:"300" min:"0"`
	GatewayAudience   string         `env:"GATEWAY_AUDIENCE" default:"tool-gateway"`
	HostedMode        bool           `env:"HOSTED_MODE" default:"false"`
	TenantID          string         `env:"TENANT_ID"`

	// Redis
	RedisURL            string `env:"REDIS_URL"`
	RevocationRedisURL  string `env:"REVOCATION_REDIS_URL"`
	KillSwitchRedisURL  string `env:"KILL_SWITCH_REDIS_URL"`
	CallCounterRedisURL string `env:"CALL_COUNTER_REDIS_URL"`

	// Rate limiting
	RateLimitWindowMS    int `env:"RATE_LIMIT_WINDOW_MS" default:"60000" min:"1"`
	RateLimitMaxRequests int `env:"RATE_LIMIT_MAX_REQUESTS" default:"1000" min:"1"`

	// CORS
	AllowedOrigins string `env:"ALLOWED_ORIGINS"`

	// Telemetry
	TelemetryEnabled bool `env:"EUNO_TELEMETRY" default:"true"`
	TelemetryFlushMS int  `env:"TELEMETRY_FLUSH_MS" default:"300000" min:"1000"`
}
