// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package config provides configuration models, loading, and validation helpers for Eunox services.
package config

// GatewayConfig holds the Tool Gateway configuration.
type GatewayConfig struct {
	NodeEnv           Environment    `env:"NODE_ENV" default:"development" enum:"development,staging,production"`
	DeploymentTier    DeploymentTier `env:"EUNOX_DEPLOYMENT_TIER" default:"single-replica" enum:"single-replica,multi-replica,multi-region-active-active"`
	Port              int            `env:"PORT" default:"3002" min:"1" max:"65535"`
	AdminPort         int            `env:"ADMIN_PORT" default:"3003" min:"1" max:"65535"`
	AdminHost         string         `env:"ADMIN_HOST" production:"required"`
	IssuerJWKSURL     string         `env:"ISSUER_JWKS_URL"`
	BackendServiceURL string         `env:"BACKEND_SERVICE_URL"`
	AdminAPIKey       string         `env:"ADMIN_API_KEY"`
	AdminJWKSURI      string         `env:"ADMIN_JWKS_URI"`
	AdminJWTAudience  string         `env:"ADMIN_JWT_AUDIENCE"`
	RequireKID        bool           `env:"EUNOX_REQUIRE_KID" default:"true"`
	JWKSCacheTTL      int            `env:"EUNOX_JWKS_CACHE_TTL_SECONDS" default:"300" min:"0"`
	GatewayAudience   string         `env:"GATEWAY_AUDIENCE" default:"tool-gateway"`
	HostedMode        bool           `env:"HOSTED_MODE" default:"false"`
	TenantID          string         `env:"TENANT_ID"`

	// Redis
	RedisURL            string `env:"REDIS_URL"`
	RevocationRedisURL  string `env:"REVOCATION_REDIS_URL"`
	KillSwitchRedisURL  string `env:"KILL_SWITCH_REDIS_URL"`
	CallCounterRedisURL string `env:"CALL_COUNTER_REDIS_URL"`
	PartnerDIDsRedisURL string `env:"PARTNER_DIDS_REDIS_URL"`
	// DPoPRedisURL is the Redis URL for the DPoP JTI replay-detection store.
	// When empty, REDIS_URL is used as a fallback.  In multi-replica deployments
	// a Redis-backed store is required so that replay tokens are rejected across
	// all gateway instances.
	DPoPRedisURL string `env:"DPOP_REDIS_URL"`
	// RateLimiterRedisURL is the Redis URL for the public enforcement rate limiter.
	// When empty, REDIS_URL is used as a fallback.  In multi-replica deployments
	// a shared Redis-backed limiter is required so the effective rate limit is not
	// multiplied by the number of replicas.
	RateLimiterRedisURL string `env:"RATE_LIMITER_REDIS_URL"`

	// Rate limiting
	RateLimitWindowMS       int `env:"RATE_LIMIT_WINDOW_MS" default:"60000" min:"1"`
	RateLimitMaxRequests    int `env:"RATE_LIMIT_MAX_REQUESTS" default:"1000" min:"1"`
	AdminRateLimitPerMinute int `env:"ADMIN_RATE_LIMIT_PER_MINUTE" default:"10" min:"1"`

	// CORS
	AllowedOrigins string `env:"ALLOWED_ORIGINS"`

	// Telemetry
	TelemetryEnabled bool `env:"EUNOX_TELEMETRY" default:"true"`
	TelemetryFlushMS int  `env:"TELEMETRY_FLUSH_MS" default:"300000" min:"1000"`

	// Request body limits
	MaxRequestBodySize int `env:"MAX_REQUEST_BODY_SIZE" default:"1048576" min:"1024" max:"104857600"`

	// TrustedProxyCIDRs is a comma-separated list of CIDR blocks (e.g. "10.0.0.0/8,172.16.0.0/12")
	// whose requests are permitted to set the X-Forwarded-For header.  When this list is non-empty
	// and the immediate peer matches one of the CIDRs, the real client IP is extracted from XFF.
	TrustedProxyCIDRs []string `env:"TRUSTED_PROXY_CIDRS"`

	// Token cache (P2-2).
	// TokenCacheTTLSeconds is the maximum number of seconds a verified capability
	// token is held in the in-process cache.  0 (default) disables the cache so
	// every request performs a full JWKS + revocation round-trip.
	// Recommended range: 10–60 s.  Must be shorter than the operator's revocation
	// propagation SLA because revoked tokens continue to be served from the cache
	// until the entry expires.
	TokenCacheTTLSeconds int `env:"TOKEN_CACHE_TTL_SECONDS" default:"0" min:"0"`
	// TokenCacheMaxSize caps the number of entries in the in-process token cache.
	// Defaults to 4096.
	TokenCacheMaxSize int `env:"TOKEN_CACHE_MAX_SIZE" default:"4096" min:"1"`
}
