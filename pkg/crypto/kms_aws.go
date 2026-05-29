// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"context"
	"fmt"
)

// AWSKMSSignInput holds the parameters for a single AWS KMS Sign API call.
type AWSKMSSignInput struct {
	// KeyID is the AWS KMS key ARN or alias.
	KeyID string
	// Message is the digest to sign.
	Message []byte
	// SigningAlgorithm is the AWS KMS signing algorithm identifier
	// (e.g., "RSASSA_PKCS1_V1_5_SHA_256", "ECDSA_SHA_256").
	SigningAlgorithm string
	// MessageType indicates whether Message is a raw message or a pre-hashed digest.
	// Use "DIGEST" when a pre-hashed digest is provided.
	MessageType string
}

// AWSKMSSignOutput holds the response from a single AWS KMS Sign API call.
type AWSKMSSignOutput struct {
	// Signature is the raw signature bytes returned by KMS.
	Signature []byte
}

// AWSKMSClient abstracts the AWS KMS Sign API. Implementations may use the
// real AWS SDK, or a mock for testing.
type AWSKMSClient interface {
	// Sign performs a signing operation using the specified KMS key.
	Sign(ctx context.Context, input *AWSKMSSignInput) (*AWSKMSSignOutput, error)
}

// RealAWSKMSSignerConfig configures a production AWS KMS signer.
type RealAWSKMSSignerConfig struct {
	// KeyID is the AWS KMS key ARN or alias ARN.
	KeyID string
	// Region is the AWS region where the key resides.
	Region string
	// Algorithm is the JOSE signing algorithm (e.g., RS256, ES256, PS256).
	Algorithm Algorithm
	// Client is the AWS KMS client used for signing operations.
	Client AWSKMSClient
}

// RealAWSKMSSigner implements Signer by delegating to AWS KMS for signing operations.
// It never holds private key material; all cryptographic operations are performed
// remotely by the KMS service.
type RealAWSKMSSigner struct {
	keyID     string
	region    string
	algorithm Algorithm
	client    AWSKMSClient
}

// NewRealAWSKMSSigner creates a production AWS KMS signer.
func NewRealAWSKMSSigner(cfg RealAWSKMSSignerConfig) (*RealAWSKMSSigner, error) {
	if cfg.KeyID == "" {
		return nil, fmt.Errorf("crypto: AWS KMS key ID is required")
	}
	if cfg.Region == "" {
		return nil, fmt.Errorf("crypto: AWS KMS region is required")
	}
	if cfg.Algorithm == "" {
		return nil, fmt.Errorf("crypto: signing algorithm is required")
	}
	if cfg.Client == nil {
		return nil, fmt.Errorf("crypto: AWS KMS client is required")
	}
	if _, err := awsKMSSigningAlgorithm(cfg.Algorithm); err != nil {
		return nil, err
	}

	return &RealAWSKMSSigner{
		keyID:     cfg.KeyID,
		region:    cfg.Region,
		algorithm: cfg.Algorithm,
		client:    cfg.Client,
	}, nil
}

// Sign delegates the signing operation to AWS KMS.
// The digest must be pre-hashed using the hash function corresponding to the
// configured algorithm (e.g., SHA-256 for RS256/ES256/PS256).
func (s *RealAWSKMSSigner) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	awsAlg, err := awsKMSSigningAlgorithm(s.algorithm)
	if err != nil {
		return nil, err
	}

	output, err := s.client.Sign(ctx, &AWSKMSSignInput{
		KeyID:            s.keyID,
		Message:          digest,
		SigningAlgorithm: awsAlg,
		MessageType:      "DIGEST",
	})
	if err != nil {
		return nil, fmt.Errorf("crypto: AWS KMS sign: %w", err)
	}

	// AWS KMS returns ECDSA signatures in DER/ASN.1 format.
	// Convert to the JOSE fixed-size R||S format for ECDSA algorithms.
	return normalizeKMSSignature(s.algorithm, output.Signature)
}

// Algorithm returns the configured signing algorithm.
func (s *RealAWSKMSSigner) Algorithm() Algorithm {
	return s.algorithm
}

// KeyID returns the configured AWS KMS key identifier.
func (s *RealAWSKMSSigner) KeyID() string {
	return s.keyID
}

// Region returns the configured AWS region.
func (s *RealAWSKMSSigner) Region() string {
	return s.region
}

// awsKMSSigningAlgorithm maps JOSE algorithm identifiers to AWS KMS SigningAlgorithm values.
func awsKMSSigningAlgorithm(alg Algorithm) (string, error) {
	switch alg {
	case RS256:
		return "RSASSA_PKCS1_V1_5_SHA_256", nil
	case RS384:
		return "RSASSA_PKCS1_V1_5_SHA_384", nil
	case RS512:
		return "RSASSA_PKCS1_V1_5_SHA_512", nil
	case PS256:
		return "RSASSA_PSS_SHA_256", nil
	case PS384:
		return "RSASSA_PSS_SHA_384", nil
	case PS512:
		return "RSASSA_PSS_SHA_512", nil
	case ES256:
		return "ECDSA_SHA_256", nil
	case ES384:
		return "ECDSA_SHA_384", nil
	case ES512:
		return "ECDSA_SHA_512", nil
	default:
		return "", fmt.Errorf("crypto: unsupported AWS KMS algorithm %q", alg)
	}
}
