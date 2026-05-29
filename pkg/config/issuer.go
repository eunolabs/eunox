// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

// Package config provides configuration models, loading, and validation helpers for Eunox services.
package config

// IssuerConfig holds the Capability Issuer configuration.
type IssuerConfig struct {
	NodeEnv                 Environment      `env:"NODE_ENV" default:"development" enum:"development,staging,production"`
	DeploymentTier          DeploymentTier   `env:"EUNOX_DEPLOYMENT_TIER" default:"single-replica" enum:"single-replica,multi-replica,multi-region-active-active"`
	Port                    int              `env:"PORT" default:"3001" min:"1" max:"65535"`
	SigningProvider         SigningProvider  `env:"SIGNING_PROVIDER" default:"azure-keyvault" enum:"azure-keyvault,aws-kms,gcp-cloudkms,software"`
	IdentityProvider        IdentityProvider `env:"IDENTITY_PROVIDER" default:"azure-ad" enum:"azure-ad,aws-cognito,gcp-identity,did,oidc"`
	IssuerDID               string           `env:"ISSUER_DID"`
	IssuerURL               string           `env:"ISSUER_URL"`
	Audience                string           `env:"AUDIENCE"`
	AdminAPIKey             string           `env:"ADMIN_API_KEY" production:"required"`
	DefaultTokenTTL         int              `env:"DEFAULT_TOKEN_TTL" default:"900" min:"1"`
	MaxTokenTTL             int              `env:"MAX_TOKEN_TTL" default:"86400" min:"1"`
	KeyRotationIntervalDays int              `env:"ISSUER_KEY_ROTATION_INTERVAL_DAYS" default:"90" min:"1"`
	RolePolicyFile          string           `env:"ROLE_POLICY_FILE"`

	// Rate limiting
	RateLimitPerMinute int    `env:"RATE_LIMIT_PER_MINUTE" default:"60" min:"1"`
	RedisURL           string `env:"REDIS_URL"`

	// Revocation — shared with the gateway so that tokens revoked by the
	// gateway are also rejected by /renew.  Falls back to REDIS_URL when
	// unset.  Recommended to set explicitly in multi-replica deployments.
	RevocationRedisURL string `env:"REVOCATION_REDIS_URL"`

	// OIDC
	OIDCIssuerURL string `env:"OIDC_ISSUER_URL"`

	// Azure Key Vault
	AzureKeyVaultURL     string `env:"AZURE_KEYVAULT_URL"`
	AzureKeyVaultKeyName string `env:"AZURE_KEYVAULT_KEY_NAME"`

	// AWS KMS
	AWSKMSRegion string `env:"AWS_KMS_REGION"`
	AWSKMSKeyID  string `env:"AWS_KMS_KEY_ID"`

	// GCP Cloud KMS
	GCPProjectID        string `env:"GCP_PROJECT_ID"`
	GCPLocationID       string `env:"GCP_LOCATION_ID" default:"global"`
	GCPKeyringID        string `env:"GCP_KEYRING_ID"`
	GCPCryptoKeyID      string `env:"GCP_CRYPTOKEY_ID"`
	GCPCryptoKeyVersion string `env:"GCP_CRYPTOKEY_VERSION" default:"1"`

	// Azure AD
	AzureADTenantID string `env:"AZURE_AD_TENANT_ID"`
	AzureADClientID string `env:"AZURE_AD_CLIENT_ID"`

	// AWS Cognito
	AWSCognitoRegion     string `env:"AWS_COGNITO_REGION"`
	AWSCognitoUserPoolID string `env:"AWS_COGNITO_USER_POOL_ID"`

	// GCP Identity
	GCPIdentityAudience string `env:"GCP_IDENTITY_AUDIENCE"`

	// Request body limits
	MaxRequestBodySize int `env:"MAX_REQUEST_BODY_SIZE" default:"1048576" min:"1024" max:"104857600"`
}
