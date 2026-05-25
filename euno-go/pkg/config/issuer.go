// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

// Package config provides configuration models, loading, and validation helpers for Euno services.
package config

// IssuerConfig holds the Capability Issuer configuration.
type IssuerConfig struct {
	NodeEnv          Environment      `env:"NODE_ENV" default:"development" enum:"development,staging,production"`
	DeploymentTier   DeploymentTier   `env:"EUNO_DEPLOYMENT_TIER" default:"single-replica" enum:"single-replica,multi-replica,multi-region-active-active"`
	Port             int              `env:"PORT" default:"3001" min:"1" max:"65535"`
	SigningProvider  SigningProvider  `env:"SIGNING_PROVIDER" default:"azure-keyvault" enum:"azure-keyvault,aws-kms,gcp-cloudkms"`
	IdentityProvider IdentityProvider `env:"IDENTITY_PROVIDER" default:"azure-ad" enum:"azure-ad,aws-cognito,gcp-identity,did"`
	IssuerDID        string           `env:"ISSUER_DID"`
	DefaultTokenTTL  int              `env:"DEFAULT_TOKEN_TTL" default:"900" min:"1"`
	RolePolicyFile   string           `env:"ROLE_POLICY_FILE"`

	// Azure Key Vault
	AzureKeyVaultURL     string `env:"AZURE_KEYVAULT_URL"`
	AzureKeyVaultKeyName string `env:"AZURE_KEYVAULT_KEY_NAME"`

	// AWS KMS
	AWSKMSRegion string `env:"AWS_KMS_REGION"`
	AWSKMSKeyID  string `env:"AWS_KMS_KEY_ID"`

	// GCP Cloud KMS
	GCPProjectID   string `env:"GCP_PROJECT_ID"`
	GCPKeyringID   string `env:"GCP_KEYRING_ID"`
	GCPCryptoKeyID string `env:"GCP_CRYPTOKEY_ID"`

	// Azure AD
	AzureADTenantID string `env:"AZURE_AD_TENANT_ID"`
	AzureADClientID string `env:"AZURE_AD_CLIENT_ID"`

	// AWS Cognito
	AWSCognitoRegion     string `env:"AWS_COGNITO_REGION"`
	AWSCognitoUserPoolID string `env:"AWS_COGNITO_USER_POOL_ID"`

	// GCP Identity
	GCPIdentityAudience string `env:"GCP_IDENTITY_AUDIENCE"`
}
