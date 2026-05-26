// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"hash"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mock KMS Clients ---

// mockAWSKMSClient is a test double for AWSKMSClient.
type mockAWSKMSClient struct {
	signFn func(ctx context.Context, input *AWSKMSSignInput) (*AWSKMSSignOutput, error)
}

func (m *mockAWSKMSClient) Sign(ctx context.Context, input *AWSKMSSignInput) (*AWSKMSSignOutput, error) {
	return m.signFn(ctx, input)
}

// mockAzureKeyVaultClient is a test double for AzureKeyVaultClient.
type mockAzureKeyVaultClient struct {
	signFn func(ctx context.Context, input *AzureKeyVaultSignInput) (*AzureKeyVaultSignOutput, error)
}

func (m *mockAzureKeyVaultClient) Sign(ctx context.Context, input *AzureKeyVaultSignInput) (*AzureKeyVaultSignOutput, error) {
	return m.signFn(ctx, input)
}

// mockGCPCloudKMSClient is a test double for GCPCloudKMSClient.
type mockGCPCloudKMSClient struct {
	asymmetricSignFn func(ctx context.Context, input *GCPCloudKMSSignInput) (*GCPCloudKMSSignOutput, error)
}

func (m *mockGCPCloudKMSClient) AsymmetricSign(ctx context.Context, input *GCPCloudKMSSignInput) (*GCPCloudKMSSignOutput, error) {
	return m.asymmetricSignFn(ctx, input)
}

// --- Helper: sign with a local key to simulate KMS ---

type ecdsaSig struct {
	R *big.Int
	S *big.Int
}

func signLocalECDSA(key *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, key, digest)
}

func signLocalRSAPKCS1v15(key *rsa.PrivateKey, digest []byte, alg Algorithm) ([]byte, error) {
	h, err := hashForAlgorithm(alg)
	if err != nil {
		return nil, err
	}
	return rsa.SignPKCS1v15(rand.Reader, key, h, digest)
}

func signLocalRSAPSS(key *rsa.PrivateKey, digest []byte, alg Algorithm) ([]byte, error) {
	h, err := hashForAlgorithm(alg)
	if err != nil {
		return nil, err
	}
	return rsa.SignPSS(rand.Reader, key, h, digest, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       h,
	})
}

func hashDigest(data []byte, alg Algorithm) []byte {
	var h hash.Hash
	switch alg {
	case RS256, PS256, ES256:
		h = sha256.New()
	case RS384, PS384, ES384:
		h = sha512.New384()
	case RS512, PS512, ES512:
		h = sha512.New()
	default:
		return data
	}
	h.Write(data)
	return h.Sum(nil)
}

// --- AWS KMS Signer Tests ---

func TestNewRealAWSKMSSigner_Validation(t *testing.T) {
	client := &mockAWSKMSClient{signFn: func(context.Context, *AWSKMSSignInput) (*AWSKMSSignOutput, error) {
		return nil, nil
	}}

	tests := []struct {
		name    string
		cfg     RealAWSKMSSignerConfig
		wantErr string
	}{
		{
			name:    "missing key ID",
			cfg:     RealAWSKMSSignerConfig{Region: "us-east-1", Algorithm: RS256, Client: client},
			wantErr: "key ID is required",
		},
		{
			name:    "missing region",
			cfg:     RealAWSKMSSignerConfig{KeyID: "arn:aws:kms:us-east-1:123456:key/abc", Algorithm: RS256, Client: client},
			wantErr: "region is required",
		},
		{
			name:    "missing algorithm",
			cfg:     RealAWSKMSSignerConfig{KeyID: "arn:aws:kms:us-east-1:123456:key/abc", Region: "us-east-1", Client: client},
			wantErr: "algorithm is required",
		},
		{
			name:    "missing client",
			cfg:     RealAWSKMSSignerConfig{KeyID: "arn:aws:kms:us-east-1:123456:key/abc", Region: "us-east-1", Algorithm: RS256},
			wantErr: "client is required",
		},
		{
			name:    "unsupported algorithm",
			cfg:     RealAWSKMSSignerConfig{KeyID: "arn:aws:kms:us-east-1:123456:key/abc", Region: "us-east-1", Algorithm: EdDSA, Client: client},
			wantErr: "unsupported AWS KMS algorithm",
		},
		{
			name: "valid config",
			cfg:  RealAWSKMSSignerConfig{KeyID: "arn:aws:kms:us-east-1:123456:key/abc", Region: "us-east-1", Algorithm: RS256, Client: client},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := NewRealAWSKMSSigner(tt.cfg)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, signer)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, signer)
			}
		})
	}
}

func TestRealAWSKMSSigner_SignRSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	message := []byte("test message for AWS KMS RSA signing")
	digest := hashDigest(message, RS256)

	client := &mockAWSKMSClient{
		signFn: func(_ context.Context, input *AWSKMSSignInput) (*AWSKMSSignOutput, error) {
			assert.Equal(t, "arn:aws:kms:us-east-1:123456:key/rsa-key", input.KeyID)
			assert.Equal(t, "RSASSA_PKCS1_V1_5_SHA_256", input.SigningAlgorithm)
			assert.Equal(t, "DIGEST", input.MessageType)
			sig, err := signLocalRSAPKCS1v15(rsaKey, input.Message, RS256)
			if err != nil {
				return nil, err
			}
			return &AWSKMSSignOutput{Signature: sig}, nil
		},
	}

	signer, err := NewRealAWSKMSSigner(RealAWSKMSSignerConfig{
		KeyID:     "arn:aws:kms:us-east-1:123456:key/rsa-key",
		Region:    "us-east-1",
		Algorithm: RS256,
		Client:    client,
	})
	require.NoError(t, err)

	assert.Equal(t, RS256, signer.Algorithm())
	assert.Equal(t, "arn:aws:kms:us-east-1:123456:key/rsa-key", signer.KeyID())

	sig, err := signer.Sign(context.Background(), digest)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)

	// Verify with the public key.
	err = rsa.VerifyPKCS1v15(&rsaKey.PublicKey, stdcrypto.SHA256, digest, sig)
	assert.NoError(t, err)
}

func TestRealAWSKMSSigner_SignPSS(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	message := []byte("test message for AWS KMS PSS signing")
	digest := hashDigest(message, PS256)

	client := &mockAWSKMSClient{
		signFn: func(_ context.Context, input *AWSKMSSignInput) (*AWSKMSSignOutput, error) {
			assert.Equal(t, "RSASSA_PSS_SHA_256", input.SigningAlgorithm)
			sig, err := signLocalRSAPSS(rsaKey, input.Message, PS256)
			if err != nil {
				return nil, err
			}
			return &AWSKMSSignOutput{Signature: sig}, nil
		},
	}

	signer, err := NewRealAWSKMSSigner(RealAWSKMSSignerConfig{
		KeyID:     "arn:aws:kms:us-east-1:123456:key/pss-key",
		Region:    "us-east-1",
		Algorithm: PS256,
		Client:    client,
	})
	require.NoError(t, err)

	sig, err := signer.Sign(context.Background(), digest)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)

	// Verify with the public key.
	err = rsa.VerifyPSS(&rsaKey.PublicKey, stdcrypto.SHA256, digest, sig, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       stdcrypto.SHA256,
	})
	assert.NoError(t, err)
}

func TestRealAWSKMSSigner_SignECDSA(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	message := []byte("test message for AWS KMS ECDSA signing")
	digest := hashDigest(message, ES256)

	client := &mockAWSKMSClient{
		signFn: func(_ context.Context, input *AWSKMSSignInput) (*AWSKMSSignOutput, error) {
			assert.Equal(t, "ECDSA_SHA_256", input.SigningAlgorithm)
			// AWS KMS returns ECDSA in DER format.
			sig, err := signLocalECDSA(ecKey, input.Message)
			if err != nil {
				return nil, err
			}
			return &AWSKMSSignOutput{Signature: sig}, nil
		},
	}

	signer, err := NewRealAWSKMSSigner(RealAWSKMSSignerConfig{
		KeyID:     "arn:aws:kms:us-east-1:123456:key/ec-key",
		Region:    "us-east-1",
		Algorithm: ES256,
		Client:    client,
	})
	require.NoError(t, err)

	sig, err := signer.Sign(context.Background(), digest)
	require.NoError(t, err)
	assert.Len(t, sig, 64) // ES256 JOSE format: 32 + 32 bytes

	// Convert JOSE back to ASN.1 and verify.
	asn1Sig, err := ecdsaSignatureFromJOSE(sig, 32)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(&ecKey.PublicKey, digest, asn1Sig))
}

func TestRealAWSKMSSigner_ContextCancelled(t *testing.T) {
	client := &mockAWSKMSClient{
		signFn: func(context.Context, *AWSKMSSignInput) (*AWSKMSSignOutput, error) {
			t.Fatal("should not be called")
			return nil, nil
		},
	}

	signer, err := NewRealAWSKMSSigner(RealAWSKMSSignerConfig{
		KeyID:     "arn:aws:kms:us-east-1:123456:key/test",
		Region:    "us-east-1",
		Algorithm: RS256,
		Client:    client,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = signer.Sign(ctx, []byte("digest"))
	assert.ErrorIs(t, err, context.Canceled)
}

func TestRealAWSKMSSigner_ClientError(t *testing.T) {
	client := &mockAWSKMSClient{
		signFn: func(context.Context, *AWSKMSSignInput) (*AWSKMSSignOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	signer, err := NewRealAWSKMSSigner(RealAWSKMSSignerConfig{
		KeyID:     "arn:aws:kms:us-east-1:123456:key/test",
		Region:    "us-east-1",
		Algorithm: RS256,
		Client:    client,
	})
	require.NoError(t, err)

	_, err = signer.Sign(context.Background(), []byte("digest"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "AWS KMS sign")
	assert.Contains(t, err.Error(), "access denied")
}

// --- Azure Key Vault Signer Tests ---

func TestNewRealAzureKeyVaultSigner_Validation(t *testing.T) {
	client := &mockAzureKeyVaultClient{signFn: func(context.Context, *AzureKeyVaultSignInput) (*AzureKeyVaultSignOutput, error) {
		return nil, nil
	}}

	tests := []struct {
		name    string
		cfg     RealAzureKeyVaultSignerConfig
		wantErr string
	}{
		{
			name:    "missing vault URL",
			cfg:     RealAzureKeyVaultSignerConfig{KeyName: "key", Algorithm: RS256, Client: client},
			wantErr: "Vault URL is required",
		},
		{
			name:    "missing key name",
			cfg:     RealAzureKeyVaultSignerConfig{VaultURL: "https://vault.example", Algorithm: RS256, Client: client},
			wantErr: "key name is required",
		},
		{
			name:    "missing algorithm",
			cfg:     RealAzureKeyVaultSignerConfig{VaultURL: "https://vault.example", KeyName: "key", Client: client},
			wantErr: "algorithm is required",
		},
		{
			name:    "missing client",
			cfg:     RealAzureKeyVaultSignerConfig{VaultURL: "https://vault.example", KeyName: "key", Algorithm: RS256},
			wantErr: "client is required",
		},
		{
			name:    "unsupported algorithm",
			cfg:     RealAzureKeyVaultSignerConfig{VaultURL: "https://vault.example", KeyName: "key", Algorithm: EdDSA, Client: client},
			wantErr: "unsupported Azure Key Vault algorithm",
		},
		{
			name: "valid config without version",
			cfg:  RealAzureKeyVaultSignerConfig{VaultURL: "https://vault.example", KeyName: "key", Algorithm: ES256, Client: client},
		},
		{
			name: "valid config with version",
			cfg:  RealAzureKeyVaultSignerConfig{VaultURL: "https://vault.example", KeyName: "key", KeyVersion: "v1", Algorithm: ES256, Client: client},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := NewRealAzureKeyVaultSigner(&tt.cfg)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, signer)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, signer)
			}
		})
	}
}

func TestRealAzureKeyVaultSigner_SignRSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	message := []byte("test message for Azure Key Vault RSA signing")
	digest := hashDigest(message, RS256)

	client := &mockAzureKeyVaultClient{
		signFn: func(_ context.Context, input *AzureKeyVaultSignInput) (*AzureKeyVaultSignOutput, error) {
			assert.Equal(t, "https://vault.example", input.VaultURL)
			assert.Equal(t, "signing-key", input.KeyName)
			assert.Equal(t, "v1", input.KeyVersion)
			assert.Equal(t, "RS256", input.Algorithm)
			sig, err := signLocalRSAPKCS1v15(rsaKey, input.Digest, RS256)
			if err != nil {
				return nil, err
			}
			return &AzureKeyVaultSignOutput{Signature: sig}, nil
		},
	}

	signer, err := NewRealAzureKeyVaultSigner(&RealAzureKeyVaultSignerConfig{
		VaultURL:   "https://vault.example",
		KeyName:    "signing-key",
		KeyVersion: "v1",
		Algorithm:  RS256,
		Client:     client,
	})
	require.NoError(t, err)

	assert.Equal(t, RS256, signer.Algorithm())
	assert.Equal(t, "https://vault.example/keys/signing-key/v1", signer.KeyID())

	sig, err := signer.Sign(context.Background(), digest)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)

	// Verify with public key.
	err = rsa.VerifyPKCS1v15(&rsaKey.PublicKey, stdcrypto.SHA256, digest, sig)
	assert.NoError(t, err)
}

func TestRealAzureKeyVaultSigner_SignECDSA(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	message := []byte("test message for Azure Key Vault ECDSA signing")
	digest := hashDigest(message, ES256)

	client := &mockAzureKeyVaultClient{
		signFn: func(_ context.Context, input *AzureKeyVaultSignInput) (*AzureKeyVaultSignOutput, error) {
			assert.Equal(t, "ES256", input.Algorithm)
			// Azure returns ECDSA in JOSE R||S format directly.
			asn1Sig, err := signLocalECDSA(ecKey, input.Digest)
			if err != nil {
				return nil, err
			}
			joseSig, err := ecdsaSignatureToJOSE(asn1Sig, 32)
			if err != nil {
				return nil, err
			}
			return &AzureKeyVaultSignOutput{Signature: joseSig}, nil
		},
	}

	signer, err := NewRealAzureKeyVaultSigner(&RealAzureKeyVaultSignerConfig{
		VaultURL:  "https://vault.example",
		KeyName:   "ec-key",
		Algorithm: ES256,
		Client:    client,
	})
	require.NoError(t, err)

	assert.Equal(t, "https://vault.example/keys/ec-key", signer.KeyID())

	sig, err := signer.Sign(context.Background(), digest)
	require.NoError(t, err)
	assert.Len(t, sig, 64) // ES256 JOSE format: 32 + 32 bytes

	// Convert JOSE back to ASN.1 and verify.
	asn1Sig, err := ecdsaSignatureFromJOSE(sig, 32)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(&ecKey.PublicKey, digest, asn1Sig))
}

func TestRealAzureKeyVaultSigner_KeyIDFormats(t *testing.T) {
	client := &mockAzureKeyVaultClient{signFn: func(context.Context, *AzureKeyVaultSignInput) (*AzureKeyVaultSignOutput, error) {
		return nil, nil
	}}

	// Without version.
	signer, err := NewRealAzureKeyVaultSigner(&RealAzureKeyVaultSignerConfig{
		VaultURL:  "https://vault.example/",
		KeyName:   "key",
		Algorithm: RS256,
		Client:    client,
	})
	require.NoError(t, err)
	assert.Equal(t, "https://vault.example/keys/key", signer.KeyID())

	// With version.
	signer, err = NewRealAzureKeyVaultSigner(&RealAzureKeyVaultSignerConfig{
		VaultURL:   "https://vault.example",
		KeyName:    "key",
		KeyVersion: "v2",
		Algorithm:  RS256,
		Client:     client,
	})
	require.NoError(t, err)
	assert.Equal(t, "https://vault.example/keys/key/v2", signer.KeyID())
}

func TestRealAzureKeyVaultSigner_ContextCancelled(t *testing.T) {
	client := &mockAzureKeyVaultClient{
		signFn: func(context.Context, *AzureKeyVaultSignInput) (*AzureKeyVaultSignOutput, error) {
			t.Fatal("should not be called")
			return nil, nil
		},
	}

	signer, err := NewRealAzureKeyVaultSigner(&RealAzureKeyVaultSignerConfig{
		VaultURL:  "https://vault.example",
		KeyName:   "key",
		Algorithm: RS256,
		Client:    client,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = signer.Sign(ctx, []byte("digest"))
	assert.ErrorIs(t, err, context.Canceled)
}

func TestRealAzureKeyVaultSigner_ClientError(t *testing.T) {
	client := &mockAzureKeyVaultClient{
		signFn: func(context.Context, *AzureKeyVaultSignInput) (*AzureKeyVaultSignOutput, error) {
			return nil, errors.New("unauthorized")
		},
	}

	signer, err := NewRealAzureKeyVaultSigner(&RealAzureKeyVaultSignerConfig{
		VaultURL:  "https://vault.example",
		KeyName:   "key",
		Algorithm: RS256,
		Client:    client,
	})
	require.NoError(t, err)

	_, err = signer.Sign(context.Background(), []byte("digest"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Azure Key Vault sign")
	assert.Contains(t, err.Error(), "unauthorized")
}

// --- GCP Cloud KMS Signer Tests ---

func TestNewRealGCPCloudKMSSigner_Validation(t *testing.T) {
	client := &mockGCPCloudKMSClient{asymmetricSignFn: func(context.Context, *GCPCloudKMSSignInput) (*GCPCloudKMSSignOutput, error) {
		return nil, nil
	}}

	tests := []struct {
		name    string
		cfg     RealGCPCloudKMSSignerConfig
		wantErr string
	}{
		{
			name:    "missing project ID",
			cfg:     RealGCPCloudKMSSignerConfig{LocationID: "global", KeyRingID: "ring", CryptoKeyID: "key", CryptoKeyVersion: "1", Algorithm: RS256, Client: client},
			wantErr: "project ID is required",
		},
		{
			name:    "missing location",
			cfg:     RealGCPCloudKMSSignerConfig{ProjectID: "proj", KeyRingID: "ring", CryptoKeyID: "key", CryptoKeyVersion: "1", Algorithm: RS256, Client: client},
			wantErr: "location is required",
		},
		{
			name:    "missing key ring",
			cfg:     RealGCPCloudKMSSignerConfig{ProjectID: "proj", LocationID: "global", CryptoKeyID: "key", CryptoKeyVersion: "1", Algorithm: RS256, Client: client},
			wantErr: "key ring is required",
		},
		{
			name:    "missing crypto key",
			cfg:     RealGCPCloudKMSSignerConfig{ProjectID: "proj", LocationID: "global", KeyRingID: "ring", CryptoKeyVersion: "1", Algorithm: RS256, Client: client},
			wantErr: "crypto key is required",
		},
		{
			name:    "missing crypto key version",
			cfg:     RealGCPCloudKMSSignerConfig{ProjectID: "proj", LocationID: "global", KeyRingID: "ring", CryptoKeyID: "key", Algorithm: RS256, Client: client},
			wantErr: "crypto key version is required",
		},
		{
			name:    "missing algorithm",
			cfg:     RealGCPCloudKMSSignerConfig{ProjectID: "proj", LocationID: "global", KeyRingID: "ring", CryptoKeyID: "key", CryptoKeyVersion: "1", Client: client},
			wantErr: "algorithm is required",
		},
		{
			name:    "missing client",
			cfg:     RealGCPCloudKMSSignerConfig{ProjectID: "proj", LocationID: "global", KeyRingID: "ring", CryptoKeyID: "key", CryptoKeyVersion: "1", Algorithm: RS256},
			wantErr: "client is required",
		},
		{
			name:    "unsupported algorithm",
			cfg:     RealGCPCloudKMSSignerConfig{ProjectID: "proj", LocationID: "global", KeyRingID: "ring", CryptoKeyID: "key", CryptoKeyVersion: "1", Algorithm: EdDSA, Client: client},
			wantErr: "unsupported GCP Cloud KMS algorithm",
		},
		{
			name: "valid config",
			cfg:  RealGCPCloudKMSSignerConfig{ProjectID: "proj", LocationID: "global", KeyRingID: "ring", CryptoKeyID: "key", CryptoKeyVersion: "1", Algorithm: RS256, Client: client},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := NewRealGCPCloudKMSSigner(&tt.cfg)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, signer)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, signer)
			}
		})
	}
}

func TestRealGCPCloudKMSSigner_SignRSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	message := []byte("test message for GCP Cloud KMS RSA signing")
	digest := hashDigest(message, RS256)

	client := &mockGCPCloudKMSClient{
		asymmetricSignFn: func(_ context.Context, input *GCPCloudKMSSignInput) (*GCPCloudKMSSignOutput, error) {
			assert.Equal(t, "projects/proj/locations/global/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1", input.ResourceName)
			assert.Equal(t, "SHA256", input.DigestAlgorithm)
			sig, err := signLocalRSAPKCS1v15(rsaKey, input.Digest, RS256)
			if err != nil {
				return nil, err
			}
			return &GCPCloudKMSSignOutput{Signature: sig}, nil
		},
	}

	signer, err := NewRealGCPCloudKMSSigner(&RealGCPCloudKMSSignerConfig{
		ProjectID:        "proj",
		LocationID:       "global",
		KeyRingID:        "ring",
		CryptoKeyID:      "key",
		CryptoKeyVersion: "1",
		Algorithm:        RS256,
		Client:           client,
	})
	require.NoError(t, err)

	assert.Equal(t, RS256, signer.Algorithm())
	assert.Equal(t, "projects/proj/locations/global/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1", signer.KeyID())

	sig, err := signer.Sign(context.Background(), digest)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)

	// Verify with public key.
	err = rsa.VerifyPKCS1v15(&rsaKey.PublicKey, stdcrypto.SHA256, digest, sig)
	assert.NoError(t, err)
}

func TestRealGCPCloudKMSSigner_SignECDSA(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	message := []byte("test message for GCP Cloud KMS ECDSA signing")
	digest := hashDigest(message, ES256)

	client := &mockGCPCloudKMSClient{
		asymmetricSignFn: func(_ context.Context, input *GCPCloudKMSSignInput) (*GCPCloudKMSSignOutput, error) {
			assert.Equal(t, "SHA256", input.DigestAlgorithm)
			// GCP Cloud KMS returns ECDSA in DER format.
			sig, err := signLocalECDSA(ecKey, input.Digest)
			if err != nil {
				return nil, err
			}
			return &GCPCloudKMSSignOutput{Signature: sig}, nil
		},
	}

	signer, err := NewRealGCPCloudKMSSigner(&RealGCPCloudKMSSignerConfig{
		ProjectID:        "proj",
		LocationID:       "us-east1",
		KeyRingID:        "ring",
		CryptoKeyID:      "ec-key",
		CryptoKeyVersion: "2",
		Algorithm:        ES256,
		Client:           client,
	})
	require.NoError(t, err)

	sig, err := signer.Sign(context.Background(), digest)
	require.NoError(t, err)
	assert.Len(t, sig, 64) // ES256 JOSE format: 32 + 32 bytes

	// Convert JOSE back to ASN.1 and verify.
	asn1Sig, err := ecdsaSignatureFromJOSE(sig, 32)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(&ecKey.PublicKey, digest, asn1Sig))
}

func TestRealGCPCloudKMSSigner_SignEC384(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	message := []byte("test message for GCP Cloud KMS ECDSA P-384 signing")
	digest := hashDigest(message, ES384)

	client := &mockGCPCloudKMSClient{
		asymmetricSignFn: func(_ context.Context, input *GCPCloudKMSSignInput) (*GCPCloudKMSSignOutput, error) {
			assert.Equal(t, "SHA384", input.DigestAlgorithm)
			sig, err := signLocalECDSA(ecKey, input.Digest)
			if err != nil {
				return nil, err
			}
			return &GCPCloudKMSSignOutput{Signature: sig}, nil
		},
	}

	signer, err := NewRealGCPCloudKMSSigner(&RealGCPCloudKMSSignerConfig{
		ProjectID:        "proj",
		LocationID:       "global",
		KeyRingID:        "ring",
		CryptoKeyID:      "ec384-key",
		CryptoKeyVersion: "1",
		Algorithm:        ES384,
		Client:           client,
	})
	require.NoError(t, err)

	sig, err := signer.Sign(context.Background(), digest)
	require.NoError(t, err)
	assert.Len(t, sig, 96) // ES384 JOSE format: 48 + 48 bytes

	// Verify.
	asn1Sig, err := ecdsaSignatureFromJOSE(sig, 48)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(&ecKey.PublicKey, digest, asn1Sig))
}

func TestRealGCPCloudKMSSigner_ContextCancelled(t *testing.T) {
	client := &mockGCPCloudKMSClient{
		asymmetricSignFn: func(context.Context, *GCPCloudKMSSignInput) (*GCPCloudKMSSignOutput, error) {
			t.Fatal("should not be called")
			return nil, nil
		},
	}

	signer, err := NewRealGCPCloudKMSSigner(&RealGCPCloudKMSSignerConfig{
		ProjectID:        "proj",
		LocationID:       "global",
		KeyRingID:        "ring",
		CryptoKeyID:      "key",
		CryptoKeyVersion: "1",
		Algorithm:        RS256,
		Client:           client,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = signer.Sign(ctx, []byte("digest"))
	assert.ErrorIs(t, err, context.Canceled)
}

func TestRealGCPCloudKMSSigner_ClientError(t *testing.T) {
	client := &mockGCPCloudKMSClient{
		asymmetricSignFn: func(context.Context, *GCPCloudKMSSignInput) (*GCPCloudKMSSignOutput, error) {
			return nil, errors.New("permission denied")
		},
	}

	signer, err := NewRealGCPCloudKMSSigner(&RealGCPCloudKMSSignerConfig{
		ProjectID:        "proj",
		LocationID:       "global",
		KeyRingID:        "ring",
		CryptoKeyID:      "key",
		CryptoKeyVersion: "1",
		Algorithm:        RS256,
		Client:           client,
	})
	require.NoError(t, err)

	_, err = signer.Sign(context.Background(), []byte("digest"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "GCP Cloud KMS sign")
	assert.Contains(t, err.Error(), "permission denied")
}

// --- normalizeKMSSignature Tests ---

func TestNormalizeKMSSignature_RSA(t *testing.T) {
	// RSA signatures should pass through unchanged.
	input := []byte{1, 2, 3, 4, 5}
	output, err := normalizeKMSSignature(RS256, input)
	require.NoError(t, err)
	assert.Equal(t, input, output)
}

func TestNormalizeKMSSignature_PSS(t *testing.T) {
	// PSS signatures should pass through unchanged.
	input := []byte{1, 2, 3, 4, 5}
	output, err := normalizeKMSSignature(PS256, input)
	require.NoError(t, err)
	assert.Equal(t, input, output)
}

func TestNormalizeKMSSignature_ECDSA(t *testing.T) {
	// Create a valid ASN.1 ECDSA signature.
	sig := ecdsaSig{
		R: big.NewInt(12345),
		S: big.NewInt(67890),
	}
	asn1Bytes, err := asn1.Marshal(sig)
	require.NoError(t, err)

	output, err := normalizeKMSSignature(ES256, asn1Bytes)
	require.NoError(t, err)
	assert.Len(t, output, 64) // 32 + 32 for ES256
}

func TestNormalizeKMSSignature_InvalidECDSA(t *testing.T) {
	_, err := normalizeKMSSignature(ES256, []byte{0xFF, 0xFF})
	assert.Error(t, err)
}

// --- Algorithm mapping tests ---

func TestAWSKMSSigningAlgorithm(t *testing.T) {
	tests := []struct {
		alg     Algorithm
		want    string
		wantErr bool
	}{
		{RS256, "RSASSA_PKCS1_V1_5_SHA_256", false},
		{RS384, "RSASSA_PKCS1_V1_5_SHA_384", false},
		{RS512, "RSASSA_PKCS1_V1_5_SHA_512", false},
		{PS256, "RSASSA_PSS_SHA_256", false},
		{PS384, "RSASSA_PSS_SHA_384", false},
		{PS512, "RSASSA_PSS_SHA_512", false},
		{ES256, "ECDSA_SHA_256", false},
		{ES384, "ECDSA_SHA_384", false},
		{ES512, "ECDSA_SHA_512", false},
		{EdDSA, "", true},
		{ES256K, "", true},
	}

	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
			got, err := awsKMSSigningAlgorithm(tt.alg)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestAzureKeyVaultSigningAlgorithm(t *testing.T) {
	tests := []struct {
		alg     Algorithm
		want    string
		wantErr bool
	}{
		{RS256, "RS256", false},
		{RS384, "RS384", false},
		{RS512, "RS512", false},
		{PS256, "PS256", false},
		{PS384, "PS384", false},
		{PS512, "PS512", false},
		{ES256, "ES256", false},
		{ES384, "ES384", false},
		{ES512, "ES512", false},
		{EdDSA, "", true},
		{ES256K, "", true},
	}

	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
			got, err := azureKeyVaultSigningAlgorithm(tt.alg)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestGCPCloudKMSDigestAlgorithm(t *testing.T) {
	tests := []struct {
		alg     Algorithm
		want    string
		wantErr bool
	}{
		{RS256, "SHA256", false},
		{RS384, "SHA384", false},
		{RS512, "SHA512", false},
		{PS256, "SHA256", false},
		{PS384, "SHA384", false},
		{PS512, "SHA512", false},
		{ES256, "SHA256", false},
		{ES384, "SHA384", false},
		{ES512, "SHA512", false},
		{EdDSA, "", true},
		{ES256K, "", true},
	}

	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
			got, err := gcpCloudKMSDigestAlgorithm(tt.alg)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

// --- Signer interface conformance ---

func TestRealAWSKMSSigner_ImplementsSigner(t *testing.T) {
	client := &mockAWSKMSClient{signFn: func(context.Context, *AWSKMSSignInput) (*AWSKMSSignOutput, error) {
		return &AWSKMSSignOutput{Signature: []byte("sig")}, nil
	}}
	signer, err := NewRealAWSKMSSigner(RealAWSKMSSignerConfig{
		KeyID: "key", Region: "us-east-1", Algorithm: RS256, Client: client,
	})
	require.NoError(t, err)
	var _ Signer = signer
}

func TestRealAzureKeyVaultSigner_ImplementsSigner(t *testing.T) {
	client := &mockAzureKeyVaultClient{signFn: func(context.Context, *AzureKeyVaultSignInput) (*AzureKeyVaultSignOutput, error) {
		return &AzureKeyVaultSignOutput{Signature: []byte("sig")}, nil
	}}
	signer, err := NewRealAzureKeyVaultSigner(&RealAzureKeyVaultSignerConfig{
		VaultURL: "https://vault.example", KeyName: "key", Algorithm: RS256, Client: client,
	})
	require.NoError(t, err)
	var _ Signer = signer
}

func TestRealGCPCloudKMSSigner_ImplementsSigner(t *testing.T) {
	client := &mockGCPCloudKMSClient{asymmetricSignFn: func(context.Context, *GCPCloudKMSSignInput) (*GCPCloudKMSSignOutput, error) {
		return &GCPCloudKMSSignOutput{Signature: []byte("sig")}, nil
	}}
	signer, err := NewRealGCPCloudKMSSigner(&RealGCPCloudKMSSignerConfig{
		ProjectID: "p", LocationID: "l", KeyRingID: "r", CryptoKeyID: "k", CryptoKeyVersion: "1", Algorithm: RS256, Client: client,
	})
	require.NoError(t, err)
	var _ Signer = signer
}

// --- Multi-algorithm tests ---

func TestRealAWSKMSSigner_AllSupportedAlgorithms(t *testing.T) {
	supported := []Algorithm{RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512}
	for _, alg := range supported {
		t.Run(string(alg), func(t *testing.T) {
			client := &mockAWSKMSClient{
				signFn: func(_ context.Context, input *AWSKMSSignInput) (*AWSKMSSignOutput, error) {
					// Return a dummy signature. For ECDSA, return valid ASN.1.
					switch alg {
					case ES256, ES384, ES512:
						asn1Bytes, err := asn1.Marshal(ecdsaSig{R: big.NewInt(1), S: big.NewInt(1)})
						require.NoError(t, err)
						return &AWSKMSSignOutput{Signature: asn1Bytes}, nil
					default:
						return &AWSKMSSignOutput{Signature: []byte("rsa-sig")}, nil
					}
				},
			}

			signer, err := NewRealAWSKMSSigner(RealAWSKMSSignerConfig{
				KeyID: "key", Region: "us-east-1", Algorithm: alg, Client: client,
			})
			require.NoError(t, err)

			sig, err := signer.Sign(context.Background(), []byte("digest"))
			require.NoError(t, err)
			assert.NotEmpty(t, sig)
		})
	}
}
