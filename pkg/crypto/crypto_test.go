// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package crypto tests signing and verification helpers.
package crypto

import (
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSoftwareSignerRSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer, err := NewSoftwareSignerFromPEM(mustMarshalRSAPrivateKeyPEM(t, privateKey), "rsa-key", RS256)
	require.NoError(t, err)

	verifier, err := NewSoftwareVerifierFromPEM(mustMarshalPublicKeyPEM(t, &privateKey.PublicKey), "rsa-key", RS256)
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("rsa signing payload"))
	signature, err := signer.Sign(context.Background(), digest[:])
	require.NoError(t, err)
	assert.NotEmpty(t, signature)

	require.NoError(t, verifier.Verify(context.Background(), digest[:], signature))
}

func TestSoftwareSignerEC256(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer, err := NewSoftwareSignerFromPEM(mustMarshalECPrivateKeyPEM(t, privateKey), "ec256-key", ES256)
	require.NoError(t, err)

	verifier, err := NewSoftwareVerifierFromPEM(mustMarshalPublicKeyPEM(t, &privateKey.PublicKey), "ec256-key", ES256)
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("ecdsa p-256 signing payload"))
	signature, err := signer.Sign(context.Background(), digest[:])
	require.NoError(t, err)
	assert.Len(t, signature, 64)

	require.NoError(t, verifier.Verify(context.Background(), digest[:], signature))
}

func TestSoftwareSignerEC384(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	signer, err := NewSoftwareSignerFromPEM(mustMarshalECPrivateKeyPEM(t, privateKey), "ec384-key", ES384)
	require.NoError(t, err)

	verifier, err := NewSoftwareVerifierFromPEM(mustMarshalPublicKeyPEM(t, &privateKey.PublicKey), "ec384-key", ES384)
	require.NoError(t, err)

	digest := sha512.Sum384([]byte("ecdsa p-384 signing payload"))
	signature, err := signer.Sign(context.Background(), digest[:])
	require.NoError(t, err)
	assert.Len(t, signature, 96)

	require.NoError(t, verifier.Verify(context.Background(), digest[:], signature))
}

func TestSoftwareSignerEdDSA(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signer, err := NewSoftwareSignerFromPEM(mustMarshalPKCS8PrivateKeyPEM(t, privateKey), "eddsa-key", EdDSA)
	require.NoError(t, err)

	verifier, err := NewSoftwareVerifierFromPEM(mustMarshalPublicKeyPEM(t, publicKey), "eddsa-key", EdDSA)
	require.NoError(t, err)

	message := []byte("eddsa signs the full message, not a pre-hash")
	signature, err := signer.Sign(context.Background(), message)
	require.NoError(t, err)
	assert.Len(t, signature, ed25519.SignatureSize)

	require.NoError(t, verifier.Verify(context.Background(), message, signature))
}

func TestSoftwareSignerInvalidPEM(t *testing.T) {
	_, err := NewSoftwareSignerFromPEM([]byte("not a pem"), "invalid", "")
	require.Error(t, err)

	_, err = NewSoftwareVerifierFromPEM([]byte("not a pem"), "invalid", "")
	require.Error(t, err)
}

func TestSoftwareSignerAlgorithmDetection(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rsaSigner, err := NewSoftwareSignerFromPEM(mustMarshalRSAPrivateKeyPEM(t, rsaKey), "rsa-auto", "")
	require.NoError(t, err)
	assert.Equal(t, RS256, rsaSigner.Algorithm())

	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	p256Signer, err := NewSoftwareSignerFromPEM(mustMarshalECPrivateKeyPEM(t, p256Key), "ec-auto", "")
	require.NoError(t, err)
	assert.Equal(t, ES256, p256Signer.Algorithm())

	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	eddsaSigner, err := NewSoftwareSignerFromPEM(mustMarshalPKCS8PrivateKeyPEM(t, ed25519Key), "eddsa-auto", "")
	require.NoError(t, err)
	assert.Equal(t, EdDSA, eddsaSigner.Algorithm())
}

func TestSoftwareVerifierRejectsInvalid(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer, err := NewSoftwareSignerFromPEM(mustMarshalECPrivateKeyPEM(t, privateKey), "reject-invalid", ES256)
	require.NoError(t, err)

	verifier, err := NewSoftwareVerifierFromPEM(mustMarshalPublicKeyPEM(t, &privateKey.PublicKey), "reject-invalid", ES256)
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("signature tampering test"))
	signature, err := signer.Sign(context.Background(), digest[:])
	require.NoError(t, err)

	signature[len(signature)-1] ^= 0x01
	assert.Error(t, verifier.Verify(context.Background(), digest[:], signature))
}

func TestSoftwareVerifierWrongKey(t *testing.T) {
	privateKeyA, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privateKeyB, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer, err := NewSoftwareSignerFromPEM(mustMarshalRSAPrivateKeyPEM(t, privateKeyA), "wrong-key-a", RS256)
	require.NoError(t, err)

	verifier, err := NewSoftwareVerifierFromPEM(mustMarshalPublicKeyPEM(t, &privateKeyB.PublicKey), "wrong-key-b", RS256)
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("wrong key verification"))
	signature, err := signer.Sign(context.Background(), digest[:])
	require.NoError(t, err)

	assert.Error(t, verifier.Verify(context.Background(), digest[:], signature))
}

func TestKMSStubsReturnNotImplemented(t *testing.T) {
	stubs := []Signer{
		NewAWSKMSSigner("aws-key", "us-east-1", RS256),
		NewAzureKeyVaultSigner("https://vault.example", "azure-key", "v1", ES256),
		NewGCPCloudKMSSigner("project", "global", "ring", "key", "1", PS256),
	}

	for _, stub := range stubs {
		_, err := stub.Sign(context.Background(), []byte("digest"))
		assert.ErrorIs(t, err, ErrKMSNotImplemented)
	}
}

func TestKeyIDAndAlgorithm(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	signer, err := NewSoftwareSignerFromPEM(mustMarshalECPrivateKeyPEM(t, privateKey), "software-key", ES512)
	require.NoError(t, err)
	assert.Equal(t, "software-key", signer.KeyID())
	assert.Equal(t, ES512, signer.Algorithm())

	verifier, err := NewSoftwareVerifierFromPEM(mustMarshalPublicKeyPEM(t, &privateKey.PublicKey), "software-key", ES512)
	require.NoError(t, err)
	assert.Equal(t, "software-key", verifier.KeyID())
	assert.Equal(t, ES512, verifier.Algorithm())

	assert.Equal(t, "aws-key", NewAWSKMSSigner("aws-key", "us-west-2", PS256).KeyID())
	assert.Equal(t, PS256, NewAWSKMSSigner("aws-key", "us-west-2", PS256).Algorithm())

	assert.Equal(t, "https://vault.example/keys/azure-key/version1", NewAzureKeyVaultSigner("https://vault.example", "azure-key", "version1", ES256).KeyID())
	assert.Equal(t, ES256, NewAzureKeyVaultSigner("https://vault.example", "azure-key", "version1", ES256).Algorithm())

	assert.Equal(t, "projects/project/locations/us/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/2", NewGCPCloudKMSSigner("project", "us", "ring", "key", "2", RS512).KeyID())
	assert.Equal(t, RS512, NewGCPCloudKMSSigner("project", "us", "ring", "key", "2", RS512).Algorithm())
}

func mustMarshalRSAPrivateKeyPEM(t *testing.T, privateKey *rsa.PrivateKey) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
}

func mustMarshalECPrivateKeyPEM(t *testing.T, privateKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	bytes, err := x509.MarshalECPrivateKey(privateKey)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: bytes})
}

func mustMarshalPKCS8PrivateKeyPEM(t *testing.T, privateKey stdcrypto.PrivateKey) []byte {
	t.Helper()
	bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: bytes})
}

func mustMarshalPublicKeyPEM(t *testing.T, publicKey stdcrypto.PublicKey) []byte {
	t.Helper()
	bytes, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: bytes})
}
