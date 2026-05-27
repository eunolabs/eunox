// Copyright 2026 Eunox Authors
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
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSoftwareSignerVerifierUsesPublicKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer, err := NewSoftwareSignerFromPEM(mustMarshalRSAPrivateKeyPEM(t, privateKey), "rsa-verifier", PS256)
	require.NoError(t, err)

	verifier, err := signer.Verifier()
	require.NoError(t, err)
	assert.Equal(t, signer.KeyID(), verifier.KeyID())
	assert.Equal(t, signer.Algorithm(), verifier.Algorithm())

	digest := sha256.Sum256([]byte("signer verifier round trip"))
	signature, err := signer.Sign(context.Background(), digest[:])
	require.NoError(t, err)
	require.NoError(t, verifier.Verify(context.Background(), digest[:], signature))
}

func TestParsePublicKeyPEMAndDefaultAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		publicKey stdcrypto.PublicKey
		wantAlg   Algorithm
		assertKey func(*testing.T, stdcrypto.PublicKey)
	}{
		{
			name:    "ec p384",
			wantAlg: ES384,
			publicKey: func() stdcrypto.PublicKey {
				privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)
				return &privateKey.PublicKey
			}(),
			assertKey: func(t *testing.T, key stdcrypto.PublicKey) {
				parsed, ok := key.(*ecdsa.PublicKey)
				require.True(t, ok)
				assert.Equal(t, elliptic.P384(), parsed.Curve)
			},
		},
		{
			name:    "ed25519",
			wantAlg: EdDSA,
			publicKey: func() stdcrypto.PublicKey {
				publicKey, _, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				return publicKey
			}(),
			assertKey: func(t *testing.T, key stdcrypto.PublicKey) {
				parsed, ok := key.(ed25519.PublicKey)
				require.True(t, ok)
				assert.Len(t, parsed, ed25519.PublicKeySize)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := parsePublicKeyPEM(mustMarshalPublicKeyPEM(t, tt.publicKey))
			require.NoError(t, err)
			tt.assertKey(t, parsed)

			algorithm, err := defaultAlgorithmForPublicKey(parsed)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAlg, algorithm)
		})
	}
}

func TestPublicKeyFromPrivateKey(t *testing.T) {
	ed25519Public, ed25519Private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name       string
		privateKey stdcrypto.PrivateKey
		assertKey  func(*testing.T, stdcrypto.PublicKey)
	}{
		{
			name: "rsa",
			privateKey: func() stdcrypto.PrivateKey {
				privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				return privateKey
			}(),
			assertKey: func(t *testing.T, key stdcrypto.PublicKey) {
				_, ok := key.(*rsa.PublicKey)
				assert.True(t, ok)
			},
		},
		{
			name: "ecdsa",
			privateKey: func() stdcrypto.PrivateKey {
				privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return privateKey
			}(),
			assertKey: func(t *testing.T, key stdcrypto.PublicKey) {
				parsed, ok := key.(*ecdsa.PublicKey)
				assert.True(t, ok)
				if ok {
					assert.Equal(t, elliptic.P256(), parsed.Curve)
				}
			},
		},
		{
			name:       "ed25519",
			privateKey: ed25519Private,
			assertKey: func(t *testing.T, key stdcrypto.PublicKey) {
				parsed, ok := key.(ed25519.PublicKey)
				assert.True(t, ok)
				assert.Equal(t, ed25519Public, parsed)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publicKey, err := publicKeyFromPrivateKey(tt.privateKey)
			require.NoError(t, err)
			tt.assertKey(t, publicKey)
		})
	}
}

func TestRSAPSSAlgorithms(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tests := []struct {
		name      string
		algorithm Algorithm
		digest    func() []byte
	}{
		{name: "ps256", algorithm: PS256, digest: func() []byte { digest := sha256.Sum256([]byte("ps256 payload")); return digest[:] }},
		{name: "ps384", algorithm: PS384, digest: func() []byte { digest := sha512.Sum384([]byte("ps384 payload")); return digest[:] }},
		{name: "ps512", algorithm: PS512, digest: func() []byte { digest := sha512.Sum512([]byte("ps512 payload")); return digest[:] }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := NewSoftwareSignerFromPEM(mustMarshalRSAPrivateKeyPEM(t, privateKey), tt.name, tt.algorithm)
			require.NoError(t, err)
			verifier, err := NewSoftwareVerifierFromPEM(mustMarshalPublicKeyPEM(t, &privateKey.PublicKey), tt.name, tt.algorithm)
			require.NoError(t, err)

			digest := tt.digest()
			signature, err := signer.Sign(context.Background(), digest)
			require.NoError(t, err)
			require.NoError(t, verifier.Verify(context.Background(), digest, signature))
		})
	}
}

func TestSoftwareSignerAdditionalECDSACurves(t *testing.T) {
	tests := []struct {
		name      string
		curve     elliptic.Curve
		algorithm Algorithm
		hash      func([]byte) []byte
		sigLen    int
	}{
		{
			name:      "p384",
			curve:     elliptic.P384(),
			algorithm: ES384,
			hash: func(message []byte) []byte {
				digest := sha512.Sum384(message)
				return digest[:]
			},
			sigLen: 96,
		},
		{
			name:      "p521",
			curve:     elliptic.P521(),
			algorithm: ES512,
			hash: func(message []byte) []byte {
				digest := sha512.Sum512(message)
				return digest[:]
			},
			sigLen: 132,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			require.NoError(t, err)

			signer, err := NewSoftwareSignerFromPEM(mustMarshalECPrivateKeyPEM(t, privateKey), tt.name, tt.algorithm)
			require.NoError(t, err)
			verifier, err := signer.Verifier()
			require.NoError(t, err)

			digest := tt.hash([]byte(tt.name + " digest"))
			signature, err := signer.Sign(context.Background(), digest)
			require.NoError(t, err)
			assert.Len(t, signature, tt.sigLen)
			require.NoError(t, verifier.Verify(context.Background(), digest, signature))
		})
	}
}

func TestECDSASignatureFromJOSEInvalidInputs(t *testing.T) {
	_, err := ecdsaSignatureFromJOSE([]byte{1, 2, 3}, 2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid JOSE ECDSA signature length")

	_, err = ecdsaSignatureFromJOSE(nil, 32)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid JOSE ECDSA signature length")
}

func TestHashForAlgorithm(t *testing.T) {
	tests := []struct {
		algorithm Algorithm
		wantHash  stdcrypto.Hash
		wantErr   string
	}{
		{algorithm: RS256, wantHash: stdcrypto.SHA256},
		{algorithm: RS384, wantHash: stdcrypto.SHA384},
		{algorithm: RS512, wantHash: stdcrypto.SHA512},
		{algorithm: PS256, wantHash: stdcrypto.SHA256},
		{algorithm: PS384, wantHash: stdcrypto.SHA384},
		{algorithm: PS512, wantHash: stdcrypto.SHA512},
		{algorithm: ES256, wantHash: stdcrypto.SHA256},
		{algorithm: ES384, wantHash: stdcrypto.SHA384},
		{algorithm: ES512, wantHash: stdcrypto.SHA512},
		{algorithm: ES256K, wantErr: "does not use a standard pre-hash"},
		{algorithm: EdDSA, wantErr: "does not use a standard pre-hash"},
	}

	for _, tt := range tests {
		t.Run(string(tt.algorithm), func(t *testing.T) {
			hash, err := hashForAlgorithm(tt.algorithm)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantHash, hash)
		})
	}
}

func TestParsePublicKeyPEMFromCertificate(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	publicKey, err := parsePublicKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	require.NoError(t, err)
	_, ok := publicKey.(*rsa.PublicKey)
	assert.True(t, ok)
}

func TestPEMParsingVariantsAndDefaults(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pkcs8RSA, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)
	parsedRSA, err := parsePrivateKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8RSA}))
	require.NoError(t, err)
	rsaAlgorithm, err := defaultAlgorithmForPrivateKey(parsedRSA)
	require.NoError(t, err)
	assert.Equal(t, RS256, rsaAlgorithm)

	ecdsaPKCS8, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	require.NoError(t, err)
	parsedECDSA, err := parsePrivateKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "CUSTOM PRIVATE KEY", Bytes: ecdsaPKCS8}))
	require.NoError(t, err)
	ecdsaAlgorithm, err := defaultAlgorithmForPrivateKey(parsedECDSA)
	require.NoError(t, err)
	assert.Equal(t, ES512, ecdsaAlgorithm)

	rsaPKCS1 := x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)
	parsedRSAPub, err := parsePublicKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: rsaPKCS1}))
	require.NoError(t, err)
	rsaPubAlgorithm, err := defaultAlgorithmForPublicKey(parsedRSAPub)
	require.NoError(t, err)
	assert.Equal(t, RS256, rsaPubAlgorithm)

	edPubPKIX, err := x509.MarshalPKIXPublicKey(edKey.Public())
	require.NoError(t, err)
	parsedEdPub, err := parsePublicKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "CUSTOM PUBLIC KEY", Bytes: edPubPKIX}))
	require.NoError(t, err)
	edAlgorithm, err := defaultAlgorithmForPublicKey(parsedEdPub)
	require.NoError(t, err)
	assert.Equal(t, EdDSA, edAlgorithm)
}

func TestValidationHelpersAndErrors(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	require.NoError(t, validateAlgorithmForPrivateKey(rsaKey, RS512))
	require.NoError(t, validateAlgorithmForPrivateKey(ecdsaKey, ES256))
	require.NoError(t, validateAlgorithmForPrivateKey(edKey, EdDSA))
	assert.Error(t, validateAlgorithmForPrivateKey(rsaKey, ES256))
	assert.Error(t, validateAlgorithmForPrivateKey(ecdsaKey, PS256))
	assert.Error(t, validateAlgorithmForPrivateKey(edKey, RS256))

	require.NoError(t, validateAlgorithmForPublicKey(&rsaKey.PublicKey, PS512))
	require.NoError(t, validateAlgorithmForPublicKey(&ecdsaKey.PublicKey, ES256))
	require.NoError(t, validateAlgorithmForPublicKey(edKey.Public(), EdDSA))
	assert.Error(t, validateAlgorithmForPublicKey(&rsaKey.PublicKey, ES256))
	assert.Error(t, validateAlgorithmForPublicKey(&ecdsaKey.PublicKey, ES256K))
	assert.Error(t, validateAlgorithmForPublicKey(edKey.Public(), RS256))

	assert.True(t, isRSAAlgorithm(RS256))
	assert.False(t, isRSAAlgorithm(ES256))

	algorithm, err := defaultAlgorithmForCurve(elliptic.P256())
	require.NoError(t, err)
	assert.Equal(t, ES256, algorithm)
	algorithm, err = defaultAlgorithmForCurve(elliptic.P384())
	require.NoError(t, err)
	assert.Equal(t, ES384, algorithm)
	algorithm, err = defaultAlgorithmForCurve(elliptic.P521())
	require.NoError(t, err)
	assert.Equal(t, ES512, algorithm)

	_, err = defaultAlgorithmForCurve(elliptic.P224())
	require.Error(t, err)
	_, err = ecdsaCoordinateSize(ES256K)
	require.Error(t, err)
	_, err = ecdsaCoordinateSize(Algorithm("not-ecdsa"))
	require.Error(t, err)
}

func TestECDSAHelpersAndContextErrors(t *testing.T) {
	_, err := ecdsaSignatureToJOSE([]byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00}, 32)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "trailing data")

	tooLarge, err := asn1.Marshal(ecdsaSignature{R: new(big.Int).Lsh(big.NewInt(1), 300), S: big.NewInt(1)})
	require.NoError(t, err)
	_, err = ecdsaSignatureToJOSE(tooLarge, 32)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds expected size")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer, err := NewSoftwareSignerFromPEM(mustMarshalRSAPrivateKeyPEM(t, privateKey), "ctx", RS256)
	require.NoError(t, err)
	verifier, err := NewSoftwareVerifierFromPEM(mustMarshalPublicKeyPEM(t, &privateKey.PublicKey), "ctx", "")
	require.NoError(t, err)
	assert.Equal(t, RS256, verifier.Algorithm())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = signer.Sign(ctx, make([]byte, sha256.Size))
	assert.ErrorIs(t, err, context.Canceled)
	assert.ErrorIs(t, verifier.Verify(ctx, make([]byte, sha256.Size), make([]byte, 1)), context.Canceled)
}
