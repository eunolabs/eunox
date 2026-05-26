// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"context"
	"fmt"
	"sync"
)

// KMSClientFactory allows registration of KMS client constructors at init time.
// This enables cloud SDK integration without hard-wiring SDK imports into the crypto package.
// Adapters (e.g., in cmd/ or internal/platform/) register their factory functions
// and the issuer's main.go calls the NewEnv* constructors which delegate to the registered factory.
var (
	kmsFactoryMu            sync.RWMutex
	awsKMSClientFactory     func(region string) (AWSKMSClient, error)
	azureKVClientFactory    func() (AzureKeyVaultClient, error)
	gcpCloudKMSFactory      func() (GCPCloudKMSClient, error)
)

// RegisterAWSKMSClientFactory registers a factory for creating AWS KMS clients.
// Typically called from an init() function in the platform adapter package.
func RegisterAWSKMSClientFactory(factory func(region string) (AWSKMSClient, error)) {
	kmsFactoryMu.Lock()
	defer kmsFactoryMu.Unlock()
	awsKMSClientFactory = factory
}

// RegisterAzureKeyVaultClientFactory registers a factory for creating Azure Key Vault clients.
func RegisterAzureKeyVaultClientFactory(factory func() (AzureKeyVaultClient, error)) {
	kmsFactoryMu.Lock()
	defer kmsFactoryMu.Unlock()
	azureKVClientFactory = factory
}

// RegisterGCPCloudKMSClientFactory registers a factory for creating GCP Cloud KMS clients.
func RegisterGCPCloudKMSClientFactory(factory func() (GCPCloudKMSClient, error)) {
	kmsFactoryMu.Lock()
	defer kmsFactoryMu.Unlock()
	gcpCloudKMSFactory = factory
}

// NewEnvAWSKMSClient creates an AWS KMS client using registered factory or environment credentials.
// Returns an error-returning stub if no factory is registered.
func NewEnvAWSKMSClient(region string) AWSKMSClient {
	kmsFactoryMu.RLock()
	factory := awsKMSClientFactory
	kmsFactoryMu.RUnlock()

	if factory != nil {
		client, err := factory(region)
		if err == nil {
			return client
		}
		// Fall through to unimplemented client on factory error.
	}
	return &unimplementedAWSKMSClient{region: region}
}

// NewEnvAzureKeyVaultClient creates an Azure Key Vault client using registered factory or environment credentials.
// Returns an error-returning stub if no factory is registered.
func NewEnvAzureKeyVaultClient() AzureKeyVaultClient {
	kmsFactoryMu.RLock()
	factory := azureKVClientFactory
	kmsFactoryMu.RUnlock()

	if factory != nil {
		client, err := factory()
		if err == nil {
			return client
		}
	}
	return &unimplementedAzureKVClient{}
}

// NewEnvGCPCloudKMSClient creates a GCP Cloud KMS client using registered factory or environment credentials.
// Returns an error-returning stub if no factory is registered.
func NewEnvGCPCloudKMSClient() GCPCloudKMSClient {
	kmsFactoryMu.RLock()
	factory := gcpCloudKMSFactory
	kmsFactoryMu.RUnlock()

	if factory != nil {
		client, err := factory()
		if err == nil {
			return client
		}
	}
	return &unimplementedGCPKMSClient{}
}

// unimplementedAWSKMSClient returns an error on every Sign call.
type unimplementedAWSKMSClient struct {
	region string
}

// Sign returns an error indicating the AWS KMS client is not configured.
func (c *unimplementedAWSKMSClient) Sign(_ context.Context, _ *AWSKMSSignInput) (*AWSKMSSignOutput, error) {
	return nil, fmt.Errorf("crypto: AWS KMS client not configured for region %q; register a client factory via crypto.RegisterAWSKMSClientFactory", c.region)
}

// unimplementedAzureKVClient returns an error on every Sign call.
type unimplementedAzureKVClient struct{}

// Sign returns an error indicating the Azure Key Vault client is not configured.
func (c *unimplementedAzureKVClient) Sign(_ context.Context, _ *AzureKeyVaultSignInput) (*AzureKeyVaultSignOutput, error) {
	return nil, fmt.Errorf("crypto: Azure Key Vault client not configured; register a client factory via crypto.RegisterAzureKeyVaultClientFactory")
}

// unimplementedGCPKMSClient returns an error on every AsymmetricSign call.
type unimplementedGCPKMSClient struct{}

// AsymmetricSign returns an error indicating the GCP Cloud KMS client is not configured.
func (c *unimplementedGCPKMSClient) AsymmetricSign(_ context.Context, _ *GCPCloudKMSSignInput) (*GCPCloudKMSSignOutput, error) {
	return nil, fmt.Errorf("crypto: GCP Cloud KMS client not configured; register a client factory via crypto.RegisterGCPCloudKMSClientFactory")
}
