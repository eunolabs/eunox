// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package crypto

import "context"

// Algorithm constants for signing algorithms.
type Algorithm string

// Supported signing algorithm identifiers.
const (
	RS256  Algorithm = "RS256"
	RS384  Algorithm = "RS384"
	RS512  Algorithm = "RS512"
	PS256  Algorithm = "PS256"
	PS384  Algorithm = "PS384"
	PS512  Algorithm = "PS512"
	ES256  Algorithm = "ES256"
	ES384  Algorithm = "ES384"
	ES512  Algorithm = "ES512"
	ES256K Algorithm = "ES256K"
	EdDSA  Algorithm = "EdDSA"
)

// SupportedAlgorithms lists all supported signing algorithms.
var SupportedAlgorithms = []Algorithm{
	RS256, RS384, RS512, PS256, PS384, PS512,
	ES256, ES384, ES512, ES256K, EdDSA,
}

// Signer signs digests with a private key.
type Signer interface {
	// Sign signs the given digest and returns the signature bytes.
	Sign(ctx context.Context, digest []byte) ([]byte, error)
	// Algorithm returns the signing algorithm identifier.
	Algorithm() Algorithm
	// KeyID returns the key identifier for key selection/rotation.
	KeyID() string
}

// Verifier verifies signatures against a public key.
type Verifier interface {
	// Verify checks that the signature is valid for the given digest.
	Verify(ctx context.Context, digest, signature []byte) error
	// Algorithm returns the expected algorithm.
	Algorithm() Algorithm
	// KeyID returns the key identifier.
	KeyID() string
}

// KeyPair combines a Signer and Verifier for the same key.
type KeyPair interface {
	Signer
	Verifier
}

// PublicKeyInfo describes a public key for JWKS publication.
// D-2 fix: moved here from internal/issuer so that external consumers
// (e.g. additional keystore implementations) can reference it without
// creating an import cycle through internal/issuer.
type PublicKeyInfo struct {
	KeyID     string
	Algorithm Algorithm
	PublicKey interface{} // *rsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey
	Use       string      // "sig"
}

// KeyStore manages signing keys and JWKS publication.
// D-2 fix: moved here alongside PublicKeyInfo so that implementations
// (SingleKeyStore, RotatingKeyStore) and consumers live in sibling packages
// rather than creating an import from the implementation back to the issuer.
type KeyStore interface {
	// CurrentSigner returns the active signing key.
	CurrentSigner() Signer
	// PublicKeys returns all public keys for JWKS.
	PublicKeys() []PublicKeyInfo
}
