// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterAWSKMSClientFactory(t *testing.T) {
	kmsFactoryMu.Lock()
	orig := awsKMSClientFactory
	kmsFactoryMu.Unlock()
	t.Cleanup(func() {
		kmsFactoryMu.Lock()
		awsKMSClientFactory = orig
		kmsFactoryMu.Unlock()
	})

	mock := &mockAWSKMSClient{signFn: func(_ context.Context, _ *AWSKMSSignInput) (*AWSKMSSignOutput, error) {
		return &AWSKMSSignOutput{Signature: []byte("sig")}, nil
	}}
	RegisterAWSKMSClientFactory(func(region string) (AWSKMSClient, error) {
		assert.Equal(t, "us-east-1", region)
		return mock, nil
	})

	client, err := NewEnvAWSKMSClient("us-east-1")
	require.NoError(t, err)
	assert.Equal(t, mock, client)
}

func TestNewEnvAWSKMSClientNoFactory(t *testing.T) {
	kmsFactoryMu.Lock()
	orig := awsKMSClientFactory
	awsKMSClientFactory = nil
	kmsFactoryMu.Unlock()
	t.Cleanup(func() {
		kmsFactoryMu.Lock()
		awsKMSClientFactory = orig
		kmsFactoryMu.Unlock()
	})

	_, err := NewEnvAWSKMSClient("us-east-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "factory is not registered")
}

func TestNewEnvAWSKMSClientFactoryError(t *testing.T) {
	kmsFactoryMu.Lock()
	orig := awsKMSClientFactory
	kmsFactoryMu.Unlock()
	t.Cleanup(func() {
		kmsFactoryMu.Lock()
		awsKMSClientFactory = orig
		kmsFactoryMu.Unlock()
	})

	factoryErr := errors.New("init failed")
	RegisterAWSKMSClientFactory(func(region string) (AWSKMSClient, error) {
		return nil, factoryErr
	})

	_, err := NewEnvAWSKMSClient("us-west-2")
	require.Error(t, err)
	assert.ErrorIs(t, err, factoryErr)
}

func TestRegisterAzureKeyVaultClientFactory(t *testing.T) {
	kmsFactoryMu.Lock()
	orig := azureKVClientFactory
	kmsFactoryMu.Unlock()
	t.Cleanup(func() {
		kmsFactoryMu.Lock()
		azureKVClientFactory = orig
		kmsFactoryMu.Unlock()
	})

	mock := &mockAzureKeyVaultClient{signFn: func(_ context.Context, _ *AzureKeyVaultSignInput) (*AzureKeyVaultSignOutput, error) {
		return &AzureKeyVaultSignOutput{Signature: []byte("sig")}, nil
	}}
	RegisterAzureKeyVaultClientFactory(func() (AzureKeyVaultClient, error) {
		return mock, nil
	})

	client, err := NewEnvAzureKeyVaultClient()
	require.NoError(t, err)
	assert.Equal(t, mock, client)
}

func TestNewEnvAzureKeyVaultClientNoFactory(t *testing.T) {
	kmsFactoryMu.Lock()
	orig := azureKVClientFactory
	azureKVClientFactory = nil
	kmsFactoryMu.Unlock()
	t.Cleanup(func() {
		kmsFactoryMu.Lock()
		azureKVClientFactory = orig
		kmsFactoryMu.Unlock()
	})

	_, err := NewEnvAzureKeyVaultClient()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "factory is not registered")
}

func TestNewEnvAzureKeyVaultClientFactoryError(t *testing.T) {
	kmsFactoryMu.Lock()
	orig := azureKVClientFactory
	kmsFactoryMu.Unlock()
	t.Cleanup(func() {
		kmsFactoryMu.Lock()
		azureKVClientFactory = orig
		kmsFactoryMu.Unlock()
	})

	factoryErr := errors.New("azure init failed")
	RegisterAzureKeyVaultClientFactory(func() (AzureKeyVaultClient, error) {
		return nil, factoryErr
	})

	_, err := NewEnvAzureKeyVaultClient()
	require.Error(t, err)
	assert.ErrorIs(t, err, factoryErr)
}

func TestRegisterGCPCloudKMSClientFactory(t *testing.T) {
	kmsFactoryMu.Lock()
	orig := gcpCloudKMSFactory
	kmsFactoryMu.Unlock()
	t.Cleanup(func() {
		kmsFactoryMu.Lock()
		gcpCloudKMSFactory = orig
		kmsFactoryMu.Unlock()
	})

	mock := &mockGCPCloudKMSClient{asymmetricSignFn: func(_ context.Context, _ *GCPCloudKMSSignInput) (*GCPCloudKMSSignOutput, error) {
		return &GCPCloudKMSSignOutput{Signature: []byte("sig")}, nil
	}}
	RegisterGCPCloudKMSClientFactory(func() (GCPCloudKMSClient, error) {
		return mock, nil
	})

	client, err := NewEnvGCPCloudKMSClient()
	require.NoError(t, err)
	assert.Equal(t, mock, client)
}

func TestNewEnvGCPCloudKMSClientNoFactory(t *testing.T) {
	kmsFactoryMu.Lock()
	orig := gcpCloudKMSFactory
	gcpCloudKMSFactory = nil
	kmsFactoryMu.Unlock()
	t.Cleanup(func() {
		kmsFactoryMu.Lock()
		gcpCloudKMSFactory = orig
		kmsFactoryMu.Unlock()
	})

	_, err := NewEnvGCPCloudKMSClient()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "factory is not registered")
}

func TestNewEnvGCPCloudKMSClientFactoryError(t *testing.T) {
	kmsFactoryMu.Lock()
	orig := gcpCloudKMSFactory
	kmsFactoryMu.Unlock()
	t.Cleanup(func() {
		kmsFactoryMu.Lock()
		gcpCloudKMSFactory = orig
		kmsFactoryMu.Unlock()
	})

	factoryErr := errors.New("gcp init failed")
	RegisterGCPCloudKMSClientFactory(func() (GCPCloudKMSClient, error) {
		return nil, factoryErr
	})

	_, err := NewEnvGCPCloudKMSClient()
	require.Error(t, err)
	assert.ErrorIs(t, err, factoryErr)
}
