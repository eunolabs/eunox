// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// GenerateECDSASigner creates a new SoftwareSigner with a randomly generated ECDSA key.
// The algorithm must be ES256, ES384, or ES512.
func GenerateECDSASigner(keyID string, algorithm Algorithm) (*SoftwareSigner, error) {
	var curve elliptic.Curve
	switch algorithm {
	case ES256:
		curve = elliptic.P256()
	case ES384:
		curve = elliptic.P384()
	case ES512:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported ECDSA algorithm: %s", algorithm)
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ECDSA key: %w", err)
	}

	return &SoftwareSigner{
		privateKey: privateKey,
		algorithm:  algorithm,
		keyID:      keyID,
	}, nil
}

// GenerateRSASigner creates a new SoftwareSigner with a randomly generated RSA key.
func GenerateRSASigner(keyID string, bits int) (*SoftwareSigner, error) {
	if bits < 2048 {
		return nil, fmt.Errorf("RSA key size must be at least 2048 bits, got %d", bits)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}

	return &SoftwareSigner{
		privateKey: privateKey,
		algorithm:  RS256,
		keyID:      keyID,
	}, nil
}

// GenerateEdDSASigner creates a new SoftwareSigner with a randomly generated Ed25519 key.
func GenerateEdDSASigner(keyID string) (*SoftwareSigner, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate Ed25519 key: %w", err)
	}

	return &SoftwareSigner{
		privateKey: privateKey,
		algorithm:  EdDSA,
		keyID:      keyID,
	}, nil
}

// PublicKey returns the public key corresponding to the signer's private key.
func (s *SoftwareSigner) PublicKey() stdcrypto.PublicKey {
	switch k := s.privateKey.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public()
	default:
		return nil
	}
}
