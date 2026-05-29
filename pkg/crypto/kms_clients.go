// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"fmt"
	"sync"
)

// KMSClientFactory allows registration of KMS client constructors at init time.
// This enables cloud SDK integration without hard-wiring SDK imports into the crypto package.
// Adapters (e.g., in cmd/ or internal/platform/) register their factory functions
// and the issuer's main.go calls the NewEnv* constructors which delegate to the registered factory.
var (
	kmsFactoryMu         sync.RWMutex
	awsKMSClientFactory  func(region string) (AWSKMSClient, error)
	azureKVClientFactory func() (AzureKeyVaultClient, error)
	gcpCloudKMSFactory   func() (GCPCloudKMSClient, error)
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

// NewEnvAWSKMSClient creates an AWS KMS client using a registered factory.
func NewEnvAWSKMSClient(region string) (AWSKMSClient, error) {
	kmsFactoryMu.RLock()
	factory := awsKMSClientFactory
	kmsFactoryMu.RUnlock()

	if factory == nil {
		return nil, fmt.Errorf("crypto: AWS KMS client factory is not registered")
	}

	client, err := factory(region)
	if err != nil {
		return nil, fmt.Errorf("crypto: AWS KMS client initialization failed for region %q: %w", region, err)
	}
	return client, nil
}

// NewEnvAzureKeyVaultClient creates an Azure Key Vault client using a registered factory.
func NewEnvAzureKeyVaultClient() (AzureKeyVaultClient, error) {
	kmsFactoryMu.RLock()
	factory := azureKVClientFactory
	kmsFactoryMu.RUnlock()

	if factory == nil {
		return nil, fmt.Errorf("crypto: Azure Key Vault client factory is not registered")
	}

	client, err := factory()
	if err != nil {
		return nil, fmt.Errorf("crypto: Azure Key Vault client initialization failed: %w", err)
	}
	return client, nil
}

// NewEnvGCPCloudKMSClient creates a GCP Cloud KMS client using a registered factory.
func NewEnvGCPCloudKMSClient() (GCPCloudKMSClient, error) {
	kmsFactoryMu.RLock()
	factory := gcpCloudKMSFactory
	kmsFactoryMu.RUnlock()

	if factory == nil {
		return nil, fmt.Errorf("crypto: GCP Cloud KMS client factory is not registered")
	}

	client, err := factory()
	if err != nil {
		return nil, fmt.Errorf("crypto: GCP Cloud KMS client initialization failed: %w", err)
	}
	return client, nil
}
