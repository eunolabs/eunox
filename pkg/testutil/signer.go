// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package testutil

import (
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"

	eunoxcrypto "github.com/eunolabs/eunox/pkg/crypto"
)

var errInvalidSignature = errors.New("invalid signature")

type inMemorySigner struct {
	algorithm eunoxcrypto.Algorithm
	keyID     string
	signFunc  func(digest []byte) ([]byte, error)
}

type inMemoryVerifier struct {
	algorithm  eunoxcrypto.Algorithm
	keyID      string
	verifyFunc func(digest, signature []byte) error
}

// MustGenerateRSASigner creates a test RSA signer with a random 2048-bit key.
func MustGenerateRSASigner(keyID string) (eunoxcrypto.Signer, eunoxcrypto.Verifier) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("generate RSA key: %v", err))
	}

	return &inMemorySigner{
			algorithm: eunoxcrypto.RS256,
			keyID:     keyID,
			signFunc: func(digest []byte) ([]byte, error) {
				return rsa.SignPKCS1v15(rand.Reader, privateKey, stdcrypto.SHA256, digest)
			},
		}, &inMemoryVerifier{
			algorithm: eunoxcrypto.RS256,
			keyID:     keyID,
			verifyFunc: func(digest, signature []byte) error {
				return rsa.VerifyPKCS1v15(&privateKey.PublicKey, stdcrypto.SHA256, digest, signature)
			},
		}
}

// MustGenerateECDSASigner creates a test ECDSA P-256 signer.
func MustGenerateECDSASigner(keyID string) (eunoxcrypto.Signer, eunoxcrypto.Verifier) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("generate ECDSA key: %v", err))
	}

	return &inMemorySigner{
			algorithm: eunoxcrypto.ES256,
			keyID:     keyID,
			signFunc: func(digest []byte) ([]byte, error) {
				return ecdsa.SignASN1(rand.Reader, privateKey, digest)
			},
		}, &inMemoryVerifier{
			algorithm: eunoxcrypto.ES256,
			keyID:     keyID,
			verifyFunc: func(digest, signature []byte) error {
				if !ecdsa.VerifyASN1(&privateKey.PublicKey, digest, signature) {
					return errInvalidSignature
				}
				return nil
			},
		}
}

// MustGenerateEdDSASigner creates a test Ed25519 signer.
func MustGenerateEdDSASigner(keyID string) (eunoxcrypto.Signer, eunoxcrypto.Verifier) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("generate Ed25519 key: %v", err))
	}

	return &inMemorySigner{
			algorithm: eunoxcrypto.EdDSA,
			keyID:     keyID,
			signFunc: func(digest []byte) ([]byte, error) {
				return ed25519.Sign(privateKey, digest), nil
			},
		}, &inMemoryVerifier{
			algorithm: eunoxcrypto.EdDSA,
			keyID:     keyID,
			verifyFunc: func(digest, signature []byte) error {
				if !ed25519.Verify(publicKey, digest, signature) {
					return errInvalidSignature
				}
				return nil
			},
		}
}

// Sign signs the digest using the in-memory private key.
func (s *inMemorySigner) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.signFunc(digest)
}

// Algorithm returns the signer algorithm.
func (s *inMemorySigner) Algorithm() eunoxcrypto.Algorithm {
	return s.algorithm
}

// KeyID returns the signer key identifier.
func (s *inMemorySigner) KeyID() string {
	return s.keyID
}

// Verify checks the signature against the digest using the in-memory public key.
func (v *inMemoryVerifier) Verify(ctx context.Context, digest, signature []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return v.verifyFunc(digest, signature)
}

// Algorithm returns the verifier algorithm.
func (v *inMemoryVerifier) Algorithm() eunoxcrypto.Algorithm {
	return v.algorithm
}

// KeyID returns the verifier key identifier.
func (v *inMemoryVerifier) KeyID() string {
	return v.keyID
}
