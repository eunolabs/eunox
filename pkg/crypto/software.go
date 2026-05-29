// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

var errInvalidSignature = errors.New("invalid signature")

type ecdsaSignature struct {
	R *big.Int
	S *big.Int
}

// SoftwareSigner implements Signer using an in-memory private key loaded from PEM.
type SoftwareSigner struct {
	privateKey stdcrypto.PrivateKey
	algorithm  Algorithm
	keyID      string
}

// NewSoftwareSignerFromPEM creates a signer from a PEM-encoded private key.
// It auto-detects the key type and maps to the correct algorithm.
// If algorithm is empty, it selects a default based on key type (RSA→RS256, EC P-256→ES256, Ed25519→EdDSA).
func NewSoftwareSignerFromPEM(pemBytes []byte, keyID string, algorithm Algorithm) (*SoftwareSigner, error) {
	privateKey, err := parsePrivateKeyPEM(pemBytes)
	if err != nil {
		return nil, err
	}

	if algorithm == "" {
		algorithm, err = defaultAlgorithmForPrivateKey(privateKey)
		if err != nil {
			return nil, err
		}
	}

	if err := validateAlgorithmForPrivateKey(privateKey, algorithm); err != nil {
		return nil, err
	}

	return &SoftwareSigner{
		privateKey: privateKey,
		algorithm:  algorithm,
		keyID:      keyID,
	}, nil
}

// Algorithm returns the configured signing algorithm.
func (s *SoftwareSigner) Algorithm() Algorithm {
	return s.algorithm
}

// KeyID returns the configured key identifier.
func (s *SoftwareSigner) KeyID() string {
	return s.keyID
}

// Sign signs the provided digest.
//
// For EdDSA (Ed25519), pass the full message as digest because Ed25519 performs
// its own hashing internally and does not expect a pre-hashed digest.
func (s *SoftwareSigner) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	switch key := s.privateKey.(type) {
	case *rsa.PrivateKey:
		hash, err := hashForAlgorithm(s.algorithm)
		if err != nil {
			return nil, err
		}

		switch s.algorithm {
		case RS256, RS384, RS512:
			return rsa.SignPKCS1v15(rand.Reader, key, hash, digest)
		case PS256, PS384, PS512:
			return rsa.SignPSS(rand.Reader, key, hash, digest, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hash,
			})
		default:
			return nil, fmt.Errorf("unsupported RSA algorithm %q", s.algorithm)
		}
	case *ecdsa.PrivateKey:
		size, err := ecdsaCoordinateSize(s.algorithm)
		if err != nil {
			return nil, err
		}

		asn1Signature, err := ecdsa.SignASN1(rand.Reader, key, digest)
		if err != nil {
			return nil, err
		}

		return ecdsaSignatureToJOSE(asn1Signature, size)
	case ed25519.PrivateKey:
		if s.algorithm != EdDSA {
			return nil, fmt.Errorf("unsupported Ed25519 algorithm %q", s.algorithm)
		}
		return ed25519.Sign(key, digest), nil
	default:
		return nil, fmt.Errorf("unsupported private key type %T", s.privateKey)
	}
}

// Verifier returns a verifier derived from the signer's public key.
func (s *SoftwareSigner) Verifier() (*SoftwareVerifier, error) {
	publicKey, err := publicKeyFromPrivateKey(s.privateKey)
	if err != nil {
		return nil, err
	}

	return &SoftwareVerifier{
		publicKey: publicKey,
		algorithm: s.algorithm,
		keyID:     s.keyID,
	}, nil
}

// SoftwareVerifier implements Verifier using a public key.
type SoftwareVerifier struct {
	publicKey stdcrypto.PublicKey
	algorithm Algorithm
	keyID     string
}

// NewSoftwareVerifierFromPEM creates a verifier from a PEM-encoded public key.
func NewSoftwareVerifierFromPEM(pemBytes []byte, keyID string, algorithm Algorithm) (*SoftwareVerifier, error) {
	publicKey, err := parsePublicKeyPEM(pemBytes)
	if err != nil {
		return nil, err
	}

	if algorithm == "" {
		algorithm, err = defaultAlgorithmForPublicKey(publicKey)
		if err != nil {
			return nil, err
		}
	}

	if err := validateAlgorithmForPublicKey(publicKey, algorithm); err != nil {
		return nil, err
	}

	return &SoftwareVerifier{
		publicKey: publicKey,
		algorithm: algorithm,
		keyID:     keyID,
	}, nil
}

// Algorithm returns the configured verification algorithm.
func (v *SoftwareVerifier) Algorithm() Algorithm {
	return v.algorithm
}

// KeyID returns the configured key identifier.
func (v *SoftwareVerifier) KeyID() string {
	return v.keyID
}

// Verify checks that the signature is valid for the given digest.
func (v *SoftwareVerifier) Verify(ctx context.Context, digest, signature []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	switch key := v.publicKey.(type) {
	case *rsa.PublicKey:
		hash, err := hashForAlgorithm(v.algorithm)
		if err != nil {
			return err
		}

		switch v.algorithm {
		case RS256, RS384, RS512:
			return rsa.VerifyPKCS1v15(key, hash, digest, signature)
		case PS256, PS384, PS512:
			return rsa.VerifyPSS(key, hash, digest, signature, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hash,
			})
		default:
			return fmt.Errorf("unsupported RSA algorithm %q", v.algorithm)
		}
	case *ecdsa.PublicKey:
		size, err := ecdsaCoordinateSize(v.algorithm)
		if err != nil {
			return err
		}

		asn1Signature, err := ecdsaSignatureFromJOSE(signature, size)
		if err != nil {
			return err
		}
		if !ecdsa.VerifyASN1(key, digest, asn1Signature) {
			return errInvalidSignature
		}
		return nil
	case ed25519.PublicKey:
		if v.algorithm != EdDSA {
			return fmt.Errorf("unsupported Ed25519 algorithm %q", v.algorithm)
		}
		if !ed25519.Verify(key, digest, signature) {
			return errInvalidSignature
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type %T", v.publicKey)
	}
}

func parsePrivateKeyPEM(pemBytes []byte) (stdcrypto.PrivateKey, error) {
	var lastErr error
	for len(pemBytes) > 0 {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			break
		}
		pemBytes = rest

		switch block.Type {
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err == nil {
				return key, nil
			}
			lastErr = err
		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err == nil {
				return key, nil
			}
			lastErr = err
		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err == nil {
				return key, nil
			}
			lastErr = err
		default:
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err == nil {
				return key, nil
			}
			lastErr = err
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("parse private key PEM: %w", lastErr)
	}

	return nil, errors.New("parse private key PEM: no private key found")
}

func parsePublicKeyPEM(pemBytes []byte) (stdcrypto.PublicKey, error) {
	var lastErr error
	for len(pemBytes) > 0 {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			break
		}
		pemBytes = rest

		switch block.Type {
		case "PUBLIC KEY":
			key, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err == nil {
				return key, nil
			}
			lastErr = err
		case "RSA PUBLIC KEY":
			key, err := x509.ParsePKCS1PublicKey(block.Bytes)
			if err == nil {
				return key, nil
			}
			lastErr = err
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				return cert.PublicKey, nil
			}
			lastErr = err
		default:
			key, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err == nil {
				return key, nil
			}
			lastErr = err
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("parse public key PEM: %w", lastErr)
	}

	return nil, errors.New("parse public key PEM: no public key found")
}

func publicKeyFromPrivateKey(privateKey stdcrypto.PrivateKey) (stdcrypto.PublicKey, error) {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &key.PublicKey, nil
	case ed25519.PrivateKey:
		return key.Public(), nil
	default:
		return nil, fmt.Errorf("unsupported private key type %T", privateKey)
	}
}

func defaultAlgorithmForPrivateKey(privateKey stdcrypto.PrivateKey) (Algorithm, error) {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return RS256, nil
	case *ecdsa.PrivateKey:
		return defaultAlgorithmForCurve(key.Curve)
	case ed25519.PrivateKey:
		return EdDSA, nil
	default:
		return "", fmt.Errorf("unsupported private key type %T", privateKey)
	}
}

func defaultAlgorithmForPublicKey(publicKey stdcrypto.PublicKey) (Algorithm, error) {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return RS256, nil
	case *ecdsa.PublicKey:
		return defaultAlgorithmForCurve(key.Curve)
	case ed25519.PublicKey:
		return EdDSA, nil
	default:
		return "", fmt.Errorf("unsupported public key type %T", publicKey)
	}
}

func defaultAlgorithmForCurve(curve elliptic.Curve) (Algorithm, error) {
	switch curve {
	case elliptic.P256():
		return ES256, nil
	case elliptic.P384():
		return ES384, nil
	case elliptic.P521():
		return ES512, nil
	default:
		return "", fmt.Errorf("unsupported ECDSA curve %q", curve.Params().Name)
	}
}

func validateAlgorithmForPrivateKey(privateKey stdcrypto.PrivateKey, algorithm Algorithm) error {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		if isRSAAlgorithm(algorithm) {
			return nil
		}
		return fmt.Errorf("algorithm %q is incompatible with RSA private key", algorithm)
	case *ecdsa.PrivateKey:
		return validateAlgorithmForCurve(key.Curve, algorithm)
	case ed25519.PrivateKey:
		if algorithm == EdDSA {
			return nil
		}
		return fmt.Errorf("algorithm %q is incompatible with Ed25519 private key", algorithm)
	default:
		return fmt.Errorf("unsupported private key type %T", privateKey)
	}
}

func validateAlgorithmForPublicKey(publicKey stdcrypto.PublicKey, algorithm Algorithm) error {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		if isRSAAlgorithm(algorithm) {
			return nil
		}
		return fmt.Errorf("algorithm %q is incompatible with RSA public key", algorithm)
	case *ecdsa.PublicKey:
		return validateAlgorithmForCurve(key.Curve, algorithm)
	case ed25519.PublicKey:
		if algorithm == EdDSA {
			return nil
		}
		return fmt.Errorf("algorithm %q is incompatible with Ed25519 public key", algorithm)
	default:
		return fmt.Errorf("unsupported public key type %T", publicKey)
	}
}

func validateAlgorithmForCurve(curve elliptic.Curve, algorithm Algorithm) error {
	switch curve {
	case elliptic.P256():
		if algorithm == ES256 {
			return nil
		}
	case elliptic.P384():
		if algorithm == ES384 {
			return nil
		}
	case elliptic.P521():
		if algorithm == ES512 {
			return nil
		}
	default:
		return fmt.Errorf("unsupported ECDSA curve %q", curve.Params().Name)
	}

	if algorithm == ES256K {
		return errors.New("ES256K is not supported by the software signer")
	}

	return fmt.Errorf("algorithm %q is incompatible with ECDSA curve %q", algorithm, curve.Params().Name)
}

func isRSAAlgorithm(algorithm Algorithm) bool {
	switch algorithm {
	case RS256, RS384, RS512, PS256, PS384, PS512:
		return true
	default:
		return false
	}
}

func hashForAlgorithm(algorithm Algorithm) (stdcrypto.Hash, error) {
	switch algorithm {
	case RS256, PS256, ES256:
		return stdcrypto.SHA256, nil
	case RS384, PS384, ES384:
		return stdcrypto.SHA384, nil
	case RS512, PS512, ES512:
		return stdcrypto.SHA512, nil
	default:
		return 0, fmt.Errorf("algorithm %q does not use a standard pre-hash", algorithm)
	}
}

func ecdsaCoordinateSize(algorithm Algorithm) (int, error) {
	switch algorithm {
	case ES256:
		return 32, nil
	case ES384:
		return 48, nil
	case ES512:
		return 66, nil
	case ES256K:
		return 0, errors.New("ES256K is not supported by the software signer")
	default:
		return 0, fmt.Errorf("algorithm %q is not an ECDSA algorithm", algorithm)
	}
}

func ecdsaSignatureToJOSE(asn1Signature []byte, size int) ([]byte, error) {
	var signature ecdsaSignature
	if rest, err := asn1.Unmarshal(asn1Signature, &signature); err != nil {
		return nil, fmt.Errorf("unmarshal ECDSA ASN.1 signature: %w", err)
	} else if len(rest) != 0 {
		return nil, errors.New("ECDSA ASN.1 signature contains trailing data")
	}

	if signature.R == nil || signature.S == nil {
		return nil, errors.New("ECDSA ASN.1 signature is missing coordinates")
	}

	rBytes := signature.R.Bytes()
	sBytes := signature.S.Bytes()
	if len(rBytes) > size || len(sBytes) > size {
		return nil, errors.New("ECDSA signature coordinate exceeds expected size")
	}

	joseSignature := make([]byte, size*2)
	copy(joseSignature[size-len(rBytes):size], rBytes)
	copy(joseSignature[2*size-len(sBytes):], sBytes)
	return joseSignature, nil
}

func ecdsaSignatureFromJOSE(joseSignature []byte, size int) ([]byte, error) {
	if len(joseSignature) != size*2 {
		return nil, fmt.Errorf("invalid JOSE ECDSA signature length: got %d want %d", len(joseSignature), size*2)
	}

	asn1Signature, err := asn1.Marshal(ecdsaSignature{
		R: new(big.Int).SetBytes(joseSignature[:size]),
		S: new(big.Int).SetBytes(joseSignature[size:]),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal ECDSA ASN.1 signature: %w", err)
	}
	return asn1Signature, nil
}
