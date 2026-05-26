// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"context"
	"fmt"
	"strings"
)

// AzureKeyVaultSignInput holds the parameters for a single Azure Key Vault Sign API call.
type AzureKeyVaultSignInput struct {
	// VaultURL is the base URL of the vault (e.g., "https://myvault.vault.azure.net").
	VaultURL string
	// KeyName is the name of the key in the vault.
	KeyName string
	// KeyVersion is the key version (empty for latest).
	KeyVersion string
	// Algorithm is the Azure Key Vault signing algorithm identifier
	// (e.g., "RS256", "ES256", "PS256").
	Algorithm string
	// Digest is the pre-hashed digest to sign.
	Digest []byte
}

// AzureKeyVaultSignOutput holds the response from a single Azure Key Vault Sign API call.
type AzureKeyVaultSignOutput struct {
	// Signature is the raw signature bytes returned by Key Vault.
	// For ECDSA, Azure Key Vault returns the signature in JOSE R||S format.
	Signature []byte
}

// AzureKeyVaultClient abstracts the Azure Key Vault Sign API. Implementations may use
// the real Azure SDK, or a mock for testing.
type AzureKeyVaultClient interface {
	// Sign performs a signing operation using the specified Key Vault key.
	Sign(ctx context.Context, input *AzureKeyVaultSignInput) (*AzureKeyVaultSignOutput, error)
}

// RealAzureKeyVaultSignerConfig configures a production Azure Key Vault signer.
type RealAzureKeyVaultSignerConfig struct {
	// VaultURL is the base URL of the vault (e.g., "https://myvault.vault.azure.net").
	VaultURL string
	// KeyName is the name of the key in the vault.
	KeyName string
	// KeyVersion is the key version (empty for latest).
	KeyVersion string
	// Algorithm is the JOSE signing algorithm (e.g., RS256, ES256, PS256).
	Algorithm Algorithm
	// Client is the Azure Key Vault client used for signing operations.
	Client AzureKeyVaultClient
}

// RealAzureKeyVaultSigner implements Signer by delegating to Azure Key Vault
// for signing operations. It never holds private key material; all cryptographic
// operations are performed remotely by the Key Vault service.
type RealAzureKeyVaultSigner struct {
	vaultURL   string
	keyName    string
	keyVersion string
	algorithm  Algorithm
	client     AzureKeyVaultClient
}

// NewRealAzureKeyVaultSigner creates a production Azure Key Vault signer.
func NewRealAzureKeyVaultSigner(cfg *RealAzureKeyVaultSignerConfig) (*RealAzureKeyVaultSigner, error) {
	if cfg == nil {
		return nil, fmt.Errorf("crypto: Azure Key Vault signer config is required")
	}
	if cfg.VaultURL == "" {
		return nil, fmt.Errorf("crypto: Azure Key Vault URL is required")
	}
	if cfg.KeyName == "" {
		return nil, fmt.Errorf("crypto: Azure Key Vault key name is required")
	}
	if cfg.Algorithm == "" {
		return nil, fmt.Errorf("crypto: signing algorithm is required")
	}
	if cfg.Client == nil {
		return nil, fmt.Errorf("crypto: Azure Key Vault client is required")
	}
	if _, err := azureKeyVaultSigningAlgorithm(cfg.Algorithm); err != nil {
		return nil, err
	}

	return &RealAzureKeyVaultSigner{
		vaultURL:   strings.TrimRight(cfg.VaultURL, "/"),
		keyName:    cfg.KeyName,
		keyVersion: cfg.KeyVersion,
		algorithm:  cfg.Algorithm,
		client:     cfg.Client,
	}, nil
}

// Sign delegates the signing operation to Azure Key Vault.
// The digest must be pre-hashed using the hash function corresponding to the
// configured algorithm (e.g., SHA-256 for RS256/ES256/PS256).
func (s *RealAzureKeyVaultSigner) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	azureAlg, err := azureKeyVaultSigningAlgorithm(s.algorithm)
	if err != nil {
		return nil, err
	}

	output, err := s.client.Sign(ctx, &AzureKeyVaultSignInput{
		VaultURL:   s.vaultURL,
		KeyName:    s.keyName,
		KeyVersion: s.keyVersion,
		Algorithm:  azureAlg,
		Digest:     digest,
	})
	if err != nil {
		return nil, fmt.Errorf("crypto: Azure Key Vault sign: %w", err)
	}

	// Azure Key Vault returns ECDSA signatures in JOSE R||S format already,
	// and RSA/PSS signatures are raw. No conversion needed.
	return output.Signature, nil
}

// Algorithm returns the configured signing algorithm.
func (s *RealAzureKeyVaultSigner) Algorithm() Algorithm {
	return s.algorithm
}

// KeyID returns the logical Azure Key Vault key identifier.
func (s *RealAzureKeyVaultSigner) KeyID() string {
	if s.keyVersion == "" {
		return fmt.Sprintf("%s/keys/%s", s.vaultURL, s.keyName)
	}
	return fmt.Sprintf("%s/keys/%s/%s", s.vaultURL, s.keyName, s.keyVersion)
}

// azureKeyVaultSigningAlgorithm maps JOSE algorithm identifiers to Azure Key Vault algorithm values.
// Azure Key Vault uses the same JOSE algorithm names for its REST API.
func azureKeyVaultSigningAlgorithm(alg Algorithm) (string, error) {
	switch alg {
	case RS256:
		return "RS256", nil
	case RS384:
		return "RS384", nil
	case RS512:
		return "RS512", nil
	case PS256:
		return "PS256", nil
	case PS384:
		return "PS384", nil
	case PS512:
		return "PS512", nil
	case ES256:
		return "ES256", nil
	case ES384:
		return "ES384", nil
	case ES512:
		return "ES512", nil
	default:
		return "", fmt.Errorf("crypto: unsupported Azure Key Vault algorithm %q", alg)
	}
}
