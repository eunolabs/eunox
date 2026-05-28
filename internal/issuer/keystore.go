// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package issuer

import (
	stdcrypto "crypto"

	"github.com/eunolabs/eunox/pkg/crypto"
)

// PublicKeyExporter is an optional interface for signers that can export their public key.
// Software signers implement this; KMS signers typically do not hold public key material locally.
type PublicKeyExporter interface {
	PublicKey() stdcrypto.PublicKey
}

// SingleKeyStore wraps a crypto.Signer as a KeyStore.
type SingleKeyStore struct {
	signer crypto.Signer
}

// NewSingleKeyStore creates a KeyStore backed by a single crypto.Signer.
// The signer may optionally implement PublicKeyExporter for JWKS publication.
func NewSingleKeyStore(signer crypto.Signer) *SingleKeyStore {
	return &SingleKeyStore{signer: signer}
}

// CurrentSigner returns the active signing key.
func (ks *SingleKeyStore) CurrentSigner() crypto.Signer {
	return ks.signer
}

// PublicKeys returns the public key info for JWKS endpoints.
// Returns nil if the signer does not implement PublicKeyExporter (e.g., KMS signers).
func (ks *SingleKeyStore) PublicKeys() []PublicKeyInfo {
	exporter, ok := ks.signer.(PublicKeyExporter)
	if !ok {
		return nil
	}
	pub := exporter.PublicKey()
	if pub == nil {
		return nil
	}
	return []PublicKeyInfo{
		{
			KeyID:     ks.signer.KeyID(),
			Algorithm: ks.signer.Algorithm(),
			PublicKey: pub,
			Use:       "sig",
		},
	}
}
