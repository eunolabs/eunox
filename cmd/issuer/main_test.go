// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/edgeobs/eunox/pkg/config"
	"github.com/edgeobs/eunox/pkg/ratelimit"
)

func TestBuildRateLimiter_UsesRedisWhenConfigured(t *testing.T) {
	limiter := buildRateLimiter(&config.IssuerConfig{
		RateLimitPerMinute: 60,
		RedisURL:           "redis://localhost:6379/0",
	}, nil)

	_, isRedis := limiter.(*ratelimit.RedisLimiter)
	assert.True(t, isRedis)
}

func TestBuildRateLimiter_FallsBackToInMemoryOnInvalidRedisURL(t *testing.T) {
	limiter := buildRateLimiter(&config.IssuerConfig{
		RateLimitPerMinute: 60,
		RedisURL:           "://not-a-valid-redis-url",
	}, nil)

	_, isMemory := limiter.(*ratelimit.InMemoryLimiter)
	assert.True(t, isMemory)
}

func TestBuildSigner_SoftwareAllowedInDevelopment(t *testing.T) {
	cfg := &config.IssuerConfig{
		NodeEnv:         config.EnvDevelopment,
		SigningProvider:  "software",
	}
	signer, err := buildSigner(cfg)
	assert.NoError(t, err)
	assert.NotNil(t, signer)
	assert.Equal(t, "issuer-key-1", signer.KeyID())
}

func TestBuildSigner_EmptyProviderAllowedInDevelopment(t *testing.T) {
	cfg := &config.IssuerConfig{
		NodeEnv:         config.EnvDevelopment,
		SigningProvider:  "",
	}
	signer, err := buildSigner(cfg)
	assert.NoError(t, err)
	assert.NotNil(t, signer)
}

func TestBuildSigner_SoftwareRejectedInProduction(t *testing.T) {
	cfg := &config.IssuerConfig{
		NodeEnv:         config.EnvProduction,
		SigningProvider:  "software",
	}
	_, err := buildSigner(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not allowed in production")
}

func TestBuildSigner_EmptyProviderRejectedInProduction(t *testing.T) {
	cfg := &config.IssuerConfig{
		NodeEnv:         config.EnvProduction,
		SigningProvider:  "",
	}
	_, err := buildSigner(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not allowed in production")
}

func TestBuildSigner_AWSKMSMissingKeyID(t *testing.T) {
	cfg := &config.IssuerConfig{
		SigningProvider: "aws-kms",
		AWSKMSRegion:   "us-east-1",
	}
	_, err := buildSigner(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "AWS_KMS_KEY_ID is required")
}

func TestBuildSigner_AWSKMSMissingRegion(t *testing.T) {
	cfg := &config.IssuerConfig{
		SigningProvider: "aws-kms",
		AWSKMSKeyID:    "arn:aws:kms:us-east-1:123456789012:key/some-key-id",
	}
	_, err := buildSigner(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "AWS_KMS_REGION is required")
}

func TestBuildSigner_AzureMissingVaultURL(t *testing.T) {
	cfg := &config.IssuerConfig{
		SigningProvider:      "azure-keyvault",
		AzureKeyVaultKeyName: "my-key",
	}
	_, err := buildSigner(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "AZURE_KEYVAULT_URL is required")
}

func TestBuildSigner_AzureMissingKeyName(t *testing.T) {
	cfg := &config.IssuerConfig{
		SigningProvider:    "azure-keyvault",
		AzureKeyVaultURL:  "https://my-vault.vault.azure.net",
	}
	_, err := buildSigner(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "AZURE_KEYVAULT_KEY_NAME is required")
}

func TestBuildSigner_GCPMissingProjectID(t *testing.T) {
	cfg := &config.IssuerConfig{
		SigningProvider: "gcp-cloudkms",
		GCPKeyringID:   "my-ring",
		GCPCryptoKeyID: "my-key",
	}
	_, err := buildSigner(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "GCP_PROJECT_ID is required")
}

func TestBuildSigner_GCPMissingKeyring(t *testing.T) {
	cfg := &config.IssuerConfig{
		SigningProvider: "gcp-cloudkms",
		GCPProjectID:   "my-project",
		GCPCryptoKeyID: "my-key",
	}
	_, err := buildSigner(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "GCP_KEYRING_ID is required")
}

func TestBuildSigner_GCPMissingCryptoKeyID(t *testing.T) {
	cfg := &config.IssuerConfig{
		SigningProvider: "gcp-cloudkms",
		GCPProjectID:   "my-project",
		GCPKeyringID:   "my-ring",
	}
	_, err := buildSigner(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "GCP_CRYPTOKEY_ID is required")
}

func TestBuildSigner_UnknownProvider(t *testing.T) {
	cfg := &config.IssuerConfig{
		SigningProvider: "unknown-provider",
	}
	_, err := buildSigner(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown signing provider")
}

func TestGCPLocationOrDefault(t *testing.T) {
	assert.Equal(t, "us-central1", gcpLocationOrDefault(&config.IssuerConfig{GCPLocationID: "us-central1"}))
	assert.Equal(t, "global", gcpLocationOrDefault(&config.IssuerConfig{}))
}

func TestGCPKeyVersionOrDefault(t *testing.T) {
	assert.Equal(t, "3", gcpKeyVersionOrDefault(&config.IssuerConfig{GCPCryptoKeyVersion: "3"}))
	assert.Equal(t, "1", gcpKeyVersionOrDefault(&config.IssuerConfig{}))
}
