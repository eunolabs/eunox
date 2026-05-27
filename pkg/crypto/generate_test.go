// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateECDSASigner(t *testing.T) {
	for _, alg := range []Algorithm{ES256, ES384, ES512} {
		alg := alg
		t.Run(string(alg), func(t *testing.T) {
			signer, err := GenerateECDSASigner("test-key", alg)
			require.NoError(t, err)
			require.NotNil(t, signer)
			assert.Equal(t, "test-key", signer.KeyID())
			assert.Equal(t, alg, signer.Algorithm())

			pub := signer.PublicKey()
			assert.IsType(t, &ecdsa.PublicKey{}, pub)

			// Verify sign/verify round-trip
			digest := make([]byte, 32)
			sig, err := signer.Sign(context.Background(), digest)
			require.NoError(t, err)
			assert.NotEmpty(t, sig)
		})
	}
}

func TestGenerateECDSASignerUnsupportedAlgorithm(t *testing.T) {
	_, err := GenerateECDSASigner("test-key", RS256)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported ECDSA algorithm")
}

func TestGenerateRSASigner(t *testing.T) {
	signer, err := GenerateRSASigner("rsa-key", 2048)
	require.NoError(t, err)
	require.NotNil(t, signer)
	assert.Equal(t, "rsa-key", signer.KeyID())
	assert.Equal(t, RS256, signer.Algorithm())

	pub := signer.PublicKey()
	assert.IsType(t, &rsa.PublicKey{}, pub)

	digest := make([]byte, 32)
	sig, err := signer.Sign(context.Background(), digest)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)
}

func TestGenerateRSASignerTooSmall(t *testing.T) {
	_, err := GenerateRSASigner("rsa-key", 1024)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 2048 bits")
}

func TestGenerateEdDSASigner(t *testing.T) {
	signer, err := GenerateEdDSASigner("ed-key")
	require.NoError(t, err)
	require.NotNil(t, signer)
	assert.Equal(t, "ed-key", signer.KeyID())
	assert.Equal(t, EdDSA, signer.Algorithm())

	pub := signer.PublicKey()
	_, ok := pub.(ed25519.PublicKey)
	assert.True(t, ok)

	digest := make([]byte, 32)
	sig, err := signer.Sign(context.Background(), digest)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)
}
