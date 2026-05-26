// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package agentruntime

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDPoPProofGenerator(t *testing.T) {
	gen, err := NewDPoPProofGenerator()
	require.NoError(t, err)
	require.NotNil(t, gen)

	// Thumbprint should be non-empty base64url
	assert.NotEmpty(t, gen.Thumbprint())
}

func TestDPoPProofGenerator_GenerateProof(t *testing.T) {
	gen, err := NewDPoPProofGenerator()
	require.NoError(t, err)

	proof, err := gen.GenerateProof("POST", "https://gateway.example.com/api/v1/enforce")
	require.NoError(t, err)
	assert.NotEmpty(t, proof)

	// Proof should be a valid JWT with 3 parts
	parts := splitJWT(proof)
	assert.Len(t, parts, 3)
}

func TestDPoPProofGenerator_ProofVerification(t *testing.T) {
	gen, err := NewDPoPProofGenerator()
	require.NoError(t, err)

	proof, err := gen.GenerateProof("GET", "https://tools.example.com/api/read")
	require.NoError(t, err)

	// Verify the proof
	claims, err := VerifyDPoPProof(proof)
	require.NoError(t, err)

	assert.Equal(t, "GET", claims["htm"])
	assert.Equal(t, "https://tools.example.com/api/read", claims["htu"])
	assert.NotEmpty(t, claims["jti"])
	assert.NotNil(t, claims["iat"])
}

func TestDPoPProofGenerator_NonceHandling(t *testing.T) {
	gen, err := NewDPoPProofGenerator()
	require.NoError(t, err)

	// Without nonce
	proof1, err := gen.GenerateProof("POST", "https://example.com")
	require.NoError(t, err)
	claims1, err := VerifyDPoPProof(proof1)
	require.NoError(t, err)
	_, hasNonce := claims1["nonce"]
	assert.False(t, hasNonce)

	// Set nonce
	gen.SetNonce("server-nonce-123")

	proof2, err := gen.GenerateProof("POST", "https://example.com")
	require.NoError(t, err)
	claims2, err := VerifyDPoPProof(proof2)
	require.NoError(t, err)
	assert.Equal(t, "server-nonce-123", claims2["nonce"])
}

func TestDPoPProofGenerator_UniqueJTI(t *testing.T) {
	gen, err := NewDPoPProofGenerator()
	require.NoError(t, err)

	proof1, err := gen.GenerateProof("POST", "https://example.com")
	require.NoError(t, err)
	proof2, err := gen.GenerateProof("POST", "https://example.com")
	require.NoError(t, err)

	claims1, _ := VerifyDPoPProof(proof1)
	claims2, _ := VerifyDPoPProof(proof2)

	assert.NotEqual(t, claims1["jti"], claims2["jti"])
}

func TestDPoPProofGenerator_ThumbprintConsistency(t *testing.T) {
	gen, err := NewDPoPProofGenerator()
	require.NoError(t, err)

	// Thumbprint should be consistent across multiple calls
	tp1 := gen.Thumbprint()
	tp2 := gen.Thumbprint()
	assert.Equal(t, tp1, tp2)
}

func TestDPoPProofGenerator_ThumbprintFromProof(t *testing.T) {
	gen, err := NewDPoPProofGenerator()
	require.NoError(t, err)

	proof, err := gen.GenerateProof("POST", "https://example.com")
	require.NoError(t, err)

	// Extracting thumbprint from proof should match the generator's thumbprint
	tp, err := ThumbprintFromProof(proof)
	require.NoError(t, err)
	assert.Equal(t, gen.Thumbprint(), tp)
}

func TestVerifyDPoPProof_InvalidProof(t *testing.T) {
	tests := []struct {
		name  string
		proof string
	}{
		{"empty", ""},
		{"one_part", "abc"},
		{"two_parts", "abc.def"},
		{"invalid_header", "!!!.def.ghi"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyDPoPProof(tt.proof)
			assert.Error(t, err)
		})
	}
}

func TestComputeJWKThumbprint(t *testing.T) {
	gen, err := NewDPoPProofGenerator()
	require.NoError(t, err)

	// Compute directly
	tp, err := computeJWKThumbprint(&gen.privateKey.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, gen.Thumbprint(), tp)
}
