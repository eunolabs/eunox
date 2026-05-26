// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ErrKMSNotImplemented is returned by KMS stubs until cloud SDK integration in Stage 3.
var ErrKMSNotImplemented = errors.New("KMS signing not yet implemented; see Stage 3")

// AWSKMSSigner is a stub for AWS KMS signing (implemented in Stage 3).
type AWSKMSSigner struct {
	keyID     string
	algorithm Algorithm
	region    string
}

// NewAWSKMSSigner creates an AWS KMS signer stub.
func NewAWSKMSSigner(keyID, region string, algorithm Algorithm) *AWSKMSSigner {
	return &AWSKMSSigner{
		keyID:     keyID,
		algorithm: algorithm,
		region:    region,
	}
}

// Sign returns ErrKMSNotImplemented until cloud KMS integrations are added.
func (s *AWSKMSSigner) Sign(ctx context.Context, _ []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, ErrKMSNotImplemented
}

// Algorithm returns the configured signing algorithm.
func (s *AWSKMSSigner) Algorithm() Algorithm {
	return s.algorithm
}

// KeyID returns the configured AWS KMS key identifier.
func (s *AWSKMSSigner) KeyID() string {
	return s.keyID
}

// AzureKeyVaultSigner is a stub for Azure Key Vault signing (implemented in Stage 3).
type AzureKeyVaultSigner struct {
	vaultURL   string
	keyName    string
	keyVersion string
	algorithm  Algorithm
}

// NewAzureKeyVaultSigner creates an Azure Key Vault signer stub.
func NewAzureKeyVaultSigner(vaultURL, keyName, keyVersion string, algorithm Algorithm) *AzureKeyVaultSigner {
	return &AzureKeyVaultSigner{
		vaultURL:   vaultURL,
		keyName:    keyName,
		keyVersion: keyVersion,
		algorithm:  algorithm,
	}
}

// Sign returns ErrKMSNotImplemented until cloud KMS integrations are added.
func (s *AzureKeyVaultSigner) Sign(ctx context.Context, _ []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, ErrKMSNotImplemented
}

// Algorithm returns the configured signing algorithm.
func (s *AzureKeyVaultSigner) Algorithm() Algorithm {
	return s.algorithm
}

// KeyID returns the logical Azure Key Vault key identifier.
func (s *AzureKeyVaultSigner) KeyID() string {
	vaultURL := strings.TrimRight(s.vaultURL, "/")
	if s.keyVersion == "" {
		return fmt.Sprintf("%s/keys/%s", vaultURL, s.keyName)
	}
	return fmt.Sprintf("%s/keys/%s/%s", vaultURL, s.keyName, s.keyVersion)
}

// GCPCloudKMSSigner is a stub for GCP Cloud KMS signing (implemented in Stage 3).
type GCPCloudKMSSigner struct {
	projectID        string
	locationID       string
	keyRingID        string
	cryptoKeyID      string
	cryptoKeyVersion string
	algorithm        Algorithm
}

// NewGCPCloudKMSSigner creates a GCP Cloud KMS signer stub.
func NewGCPCloudKMSSigner(projectID, locationID, keyRingID, cryptoKeyID, cryptoKeyVersion string, algorithm Algorithm) *GCPCloudKMSSigner {
	return &GCPCloudKMSSigner{
		projectID:        projectID,
		locationID:       locationID,
		keyRingID:        keyRingID,
		cryptoKeyID:      cryptoKeyID,
		cryptoKeyVersion: cryptoKeyVersion,
		algorithm:        algorithm,
	}
}

// Sign returns ErrKMSNotImplemented until cloud KMS integrations are added.
func (s *GCPCloudKMSSigner) Sign(ctx context.Context, _ []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, ErrKMSNotImplemented
}

// Algorithm returns the configured signing algorithm.
func (s *GCPCloudKMSSigner) Algorithm() Algorithm {
	return s.algorithm
}

// KeyID returns the logical Cloud KMS key resource name.
func (s *GCPCloudKMSSigner) KeyID() string {
	if s.cryptoKeyVersion == "" {
		return fmt.Sprintf(
			"projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
			s.projectID,
			s.locationID,
			s.keyRingID,
			s.cryptoKeyID,
		)
	}
	return fmt.Sprintf(
		"projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s",
		s.projectID,
		s.locationID,
		s.keyRingID,
		s.cryptoKeyID,
		s.cryptoKeyVersion,
	)
}
