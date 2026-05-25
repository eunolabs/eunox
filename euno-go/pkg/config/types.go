// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

// Package config provides configuration models, loading, and validation helpers for Euno services.
package config

// Environment represents the deployment environment.
type Environment string

const (
	// EnvDevelopment is the local development environment.
	EnvDevelopment Environment = "development"
	// EnvStaging is the pre-production staging environment.
	EnvStaging Environment = "staging"
	// EnvProduction is the production environment.
	EnvProduction Environment = "production"
)

// DeploymentTier represents the deployment topology.
type DeploymentTier string

const (
	// TierSingleReplica runs the service as a single replica.
	TierSingleReplica DeploymentTier = "single-replica"
	// TierMultiReplica runs the service with multiple replicas in one region.
	TierMultiReplica DeploymentTier = "multi-replica"
	// TierMultiRegionActiveActive runs the service active-active across regions.
	TierMultiRegionActiveActive DeploymentTier = "multi-region-active-active"
)

// SigningProvider represents the KMS provider.
type SigningProvider string

const (
	// SigningProviderAzureKeyVault uses Azure Key Vault for signing.
	SigningProviderAzureKeyVault SigningProvider = "azure-keyvault"
	// SigningProviderAWSKMS uses AWS KMS for signing.
	SigningProviderAWSKMS SigningProvider = "aws-kms"
	// SigningProviderGCPCloudKMS uses Google Cloud KMS for signing.
	SigningProviderGCPCloudKMS SigningProvider = "gcp-cloudkms"
)

// IdentityProvider represents the identity provider type.
type IdentityProvider string

const (
	// IdentityProviderAzureAD uses Microsoft Entra ID / Azure AD.
	IdentityProviderAzureAD IdentityProvider = "azure-ad"
	// IdentityProviderAWSCognito uses AWS Cognito.
	IdentityProviderAWSCognito IdentityProvider = "aws-cognito"
	// IdentityProviderGCPIdentity uses Google Cloud identity.
	IdentityProviderGCPIdentity IdentityProvider = "gcp-identity"
	// IdentityProviderDID uses decentralized identifiers.
	IdentityProviderDID IdentityProvider = "did"
)
