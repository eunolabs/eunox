// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"context"
	"fmt"
)

// GCPCloudKMSSignInput holds the parameters for a single GCP Cloud KMS
// AsymmetricSign API call.
type GCPCloudKMSSignInput struct {
	// ResourceName is the full resource name of the CryptoKeyVersion
	// (e.g., "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1").
	ResourceName string
	// Digest is the pre-hashed digest to sign.
	Digest []byte
	// DigestAlgorithm identifies the hash algorithm used (e.g., "SHA256", "SHA384", "SHA512").
	DigestAlgorithm string
}

// GCPCloudKMSSignOutput holds the response from a single GCP Cloud KMS
// AsymmetricSign API call.
type GCPCloudKMSSignOutput struct {
	// Signature is the raw signature bytes returned by Cloud KMS.
	Signature []byte
}

// GCPCloudKMSClient abstracts the GCP Cloud KMS AsymmetricSign API.
// Implementations may use the real GCP SDK, or a mock for testing.
type GCPCloudKMSClient interface {
	// AsymmetricSign performs a signing operation using the specified Cloud KMS key version.
	AsymmetricSign(ctx context.Context, input *GCPCloudKMSSignInput) (*GCPCloudKMSSignOutput, error)
}

// RealGCPCloudKMSSignerConfig configures a production GCP Cloud KMS signer.
type RealGCPCloudKMSSignerConfig struct {
	// ProjectID is the GCP project ID.
	ProjectID string
	// LocationID is the Cloud KMS location (e.g., "global", "us-east1").
	LocationID string
	// KeyRingID is the key ring name.
	KeyRingID string
	// CryptoKeyID is the crypto key name.
	CryptoKeyID string
	// CryptoKeyVersion is the key version (e.g., "1").
	CryptoKeyVersion string
	// Algorithm is the JOSE signing algorithm (e.g., RS256, ES256, PS256).
	Algorithm Algorithm
	// Client is the GCP Cloud KMS client used for signing operations.
	Client GCPCloudKMSClient
}

// RealGCPCloudKMSSigner implements Signer by delegating to GCP Cloud KMS for
// signing operations. It never holds private key material; all cryptographic
// operations are performed remotely by the Cloud KMS service.
type RealGCPCloudKMSSigner struct {
	projectID        string
	locationID       string
	keyRingID        string
	cryptoKeyID      string
	cryptoKeyVersion string
	algorithm        Algorithm
	client           GCPCloudKMSClient
}

// NewRealGCPCloudKMSSigner creates a production GCP Cloud KMS signer.
func NewRealGCPCloudKMSSigner(cfg *RealGCPCloudKMSSignerConfig) (*RealGCPCloudKMSSigner, error) {
	if cfg == nil {
		return nil, fmt.Errorf("crypto: GCP Cloud KMS signer config is required")
	}
	if cfg.ProjectID == "" {
		return nil, fmt.Errorf("crypto: GCP project ID is required")
	}
	if cfg.LocationID == "" {
		return nil, fmt.Errorf("crypto: GCP Cloud KMS location is required")
	}
	if cfg.KeyRingID == "" {
		return nil, fmt.Errorf("crypto: GCP Cloud KMS key ring is required")
	}
	if cfg.CryptoKeyID == "" {
		return nil, fmt.Errorf("crypto: GCP Cloud KMS crypto key is required")
	}
	if cfg.CryptoKeyVersion == "" {
		return nil, fmt.Errorf("crypto: GCP Cloud KMS crypto key version is required")
	}
	if cfg.Algorithm == "" {
		return nil, fmt.Errorf("crypto: signing algorithm is required")
	}
	if cfg.Client == nil {
		return nil, fmt.Errorf("crypto: GCP Cloud KMS client is required")
	}
	if _, err := gcpCloudKMSDigestAlgorithm(cfg.Algorithm); err != nil {
		return nil, err
	}

	return &RealGCPCloudKMSSigner{
		projectID:        cfg.ProjectID,
		locationID:       cfg.LocationID,
		keyRingID:        cfg.KeyRingID,
		cryptoKeyID:      cfg.CryptoKeyID,
		cryptoKeyVersion: cfg.CryptoKeyVersion,
		algorithm:        cfg.Algorithm,
		client:           cfg.Client,
	}, nil
}

// Sign delegates the signing operation to GCP Cloud KMS.
// The digest must be pre-hashed using the hash function corresponding to the
// configured algorithm (e.g., SHA-256 for RS256/ES256/PS256).
func (s *RealGCPCloudKMSSigner) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	digestAlg, err := gcpCloudKMSDigestAlgorithm(s.algorithm)
	if err != nil {
		return nil, err
	}

	output, err := s.client.AsymmetricSign(ctx, &GCPCloudKMSSignInput{
		ResourceName: fmt.Sprintf(
			"projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s",
			s.projectID, s.locationID, s.keyRingID, s.cryptoKeyID, s.cryptoKeyVersion,
		),
		Digest:          digest,
		DigestAlgorithm: digestAlg,
	})
	if err != nil {
		return nil, fmt.Errorf("crypto: GCP Cloud KMS sign: %w", err)
	}

	// GCP Cloud KMS returns ECDSA signatures in DER/ASN.1 format.
	// Convert to the JOSE fixed-size R||S format for ECDSA algorithms.
	return normalizeKMSSignature(s.algorithm, output.Signature)
}

// Algorithm returns the configured signing algorithm.
func (s *RealGCPCloudKMSSigner) Algorithm() Algorithm {
	return s.algorithm
}

// KeyID returns the logical Cloud KMS key resource name.
func (s *RealGCPCloudKMSSigner) KeyID() string {
	return fmt.Sprintf(
		"projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s",
		s.projectID, s.locationID, s.keyRingID, s.cryptoKeyID, s.cryptoKeyVersion,
	)
}

// gcpCloudKMSDigestAlgorithm maps JOSE algorithm identifiers to GCP Cloud KMS digest algorithm names.
func gcpCloudKMSDigestAlgorithm(alg Algorithm) (string, error) {
	switch alg {
	case RS256, PS256, ES256:
		return "SHA256", nil
	case RS384, PS384, ES384:
		return "SHA384", nil
	case RS512, PS512, ES512:
		return "SHA512", nil
	default:
		return "", fmt.Errorf("crypto: unsupported GCP Cloud KMS algorithm %q", alg)
	}
}
