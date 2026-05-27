// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package config provides configuration models, loading, and validation helpers for Eunox services.
package config

// MinterConfig holds the API-Key Minter configuration.
type MinterConfig struct {
	NodeEnv             Environment `env:"NODE_ENV" default:"development" enum:"development,staging,production"`
	Port                int         `env:"MINTER_PORT" default:"3004" min:"1" max:"65535"`
	IssuerDID           string      `env:"MINTER_ISSUER_DID" default:"did:web:minter.eunox.local"`
	GatewayAudience     string      `env:"MINTER_GATEWAY_AUDIENCE" default:"tool-gateway"`
	TokenTTLSeconds     int         `env:"MINTER_TOKEN_TTL_SECONDS" default:"300" min:"1"`
	AdminAPIKey         string      `env:"MINTER_ADMIN_API_KEY" production:"required,min_length:32,not:dev-admin-key"`
	PepperHex           string      `env:"MINTER_PEPPER_HEX" production:"required" regex:"^[0-9a-fA-F]{64}$"`
	KMSProvider         string      `env:"MINTER_KMS_PROVIDER" enum:"azure-keyvault,aws-kms,gcp-cloudkms"`
	PrivateKeyPEM       string      `env:"MINTER_PRIVATE_KEY_PEM"`
	PublicKeyPEM        string      `env:"MINTER_PUBLIC_KEY_PEM"`
	SigningAlgorithm    string      `env:"MINTER_SIGNING_ALGORITHM"`
	AuditDBURL          string      `env:"MINTER_AUDIT_DB_URL" production:"required"`
	APIKeyDBURL         string      `env:"MINTER_API_KEY_DB_URL" production:"required"`
	RedisURL            string      `env:"REDIS_URL"`
	RateLimitMax        int         `env:"MINTER_RATE_LIMIT_MAX" default:"100" min:"1"`
	RateLimitWindowSecs int         `env:"MINTER_RATE_LIMIT_WINDOW_SECONDS" default:"60" min:"1"`

	// Database connection pool
	DBPool DatabasePoolConfig

	// Request body limits
	MaxRequestBodySize int `env:"MINTER_MAX_REQUEST_BODY_SIZE" default:"1048576" min:"1024" max:"104857600"`
}
