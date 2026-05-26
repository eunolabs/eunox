// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package issuer

import (
	"github.com/edgeobs/eunox/pkg/crypto"
)

// SingleKeyStore wraps a SoftwareSigner as a KeyStore.
type SingleKeyStore struct {
	signer *crypto.SoftwareSigner
}

// NewSingleKeyStore creates a KeyStore backed by a single SoftwareSigner.
func NewSingleKeyStore(signer *crypto.SoftwareSigner) *SingleKeyStore {
	return &SingleKeyStore{signer: signer}
}

// CurrentSigner returns the active signing key.
func (ks *SingleKeyStore) CurrentSigner() crypto.Signer {
	return ks.signer
}

// PublicKeys returns the public key info for JWKS endpoints.
func (ks *SingleKeyStore) PublicKeys() []PublicKeyInfo {
	pub := ks.signer.PublicKey()
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
