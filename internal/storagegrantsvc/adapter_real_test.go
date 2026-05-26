// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package storagegrantsvc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

// --- AWS S3 Adapter Tests ---

func TestRealAWSS3Adapter_Name(t *testing.T) {
	adapter, err := NewRealAWSS3Adapter(RealAWSS3AdapterConfig{
		Region: "us-east-1",
		CredentialProvider: &StaticAWSCredentialProvider{
			Creds: AWSCredentials{AccessKeyID: "AKID", SecretAccessKey: "SECRET"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if adapter.Name() != "aws-s3" {
		t.Errorf("expected name 'aws-s3', got %q", adapter.Name())
	}
}

func TestRealAWSS3Adapter_MissingRegion(t *testing.T) {
	_, err := NewRealAWSS3Adapter(RealAWSS3AdapterConfig{
		CredentialProvider: &StaticAWSCredentialProvider{
			Creds: AWSCredentials{AccessKeyID: "A", SecretAccessKey: "B"},
		},
	})
	if err == nil {
		t.Fatal("expected error for missing region")
	}
}

func TestRealAWSS3Adapter_MissingCredentialProvider(t *testing.T) {
	_, err := NewRealAWSS3Adapter(RealAWSS3AdapterConfig{
		Region: "us-east-1",
	})
	if err == nil {
		t.Fatal("expected error for missing credential provider")
	}
}

func TestRealAWSS3Adapter_MintGrant_Success(t *testing.T) {
	adapter, err := NewRealAWSS3Adapter(RealAWSS3AdapterConfig{
		Region:        "us-west-2",
		DefaultBucket: "my-bucket",
		CredentialProvider: &StaticAWSCredentialProvider{
			Creds: AWSCredentials{
				AccessKeyID:    "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	grant, err := adapter.MintGrant(context.Background(), &MintStorageGrantRequest{
		UserID:     "user-1",
		TenantID:   "tenant-1",
		Path:       "data/file.txt",
		Permission: "read",
		TTL:        1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify URL format.
	if !strings.HasPrefix(grant.URL, "https://my-bucket.s3.us-west-2.amazonaws.com/data/file.txt?") {
		t.Errorf("unexpected URL prefix: %s", grant.URL[:min(80, len(grant.URL))])
	}

	// Parse query params.
	u, err := url.Parse(grant.URL)
	if err != nil {
		t.Fatalf("failed to parse URL: %v", err)
	}
	params := u.Query()

	if params.Get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256" {
		t.Errorf("expected AWS4-HMAC-SHA256, got %q", params.Get("X-Amz-Algorithm"))
	}
	if !strings.Contains(params.Get("X-Amz-Credential"), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("credential should contain access key ID")
	}
	if !strings.Contains(params.Get("X-Amz-Credential"), "/s3/aws4_request") {
		t.Errorf("credential should contain s3 service")
	}
	if params.Get("X-Amz-SignedHeaders") != "host" {
		t.Errorf("expected SignedHeaders=host")
	}
	if params.Get("X-Amz-Signature") == "" {
		t.Error("expected non-empty signature")
	}
	if params.Get("X-Amz-Expires") != "3600" {
		t.Errorf("expected expiry 3600, got %q", params.Get("X-Amz-Expires"))
	}

	// Verify metadata.
	if grant.Adapter != "aws-s3" {
		t.Errorf("expected adapter 'aws-s3', got %q", grant.Adapter)
	}
	if grant.Bucket != "my-bucket" {
		t.Errorf("expected bucket 'my-bucket', got %q", grant.Bucket)
	}
	if grant.Permission != "read" {
		t.Errorf("expected permission 'read', got %q", grant.Permission)
	}
}

func TestRealAWSS3Adapter_MintGrant_WritePermission(t *testing.T) {
	adapter, err := NewRealAWSS3Adapter(RealAWSS3AdapterConfig{
		Region:        "us-east-1",
		DefaultBucket: "uploads",
		CredentialProvider: &StaticAWSCredentialProvider{
			Creds: AWSCredentials{AccessKeyID: "AKID", SecretAccessKey: "SECRET"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	grant, err := adapter.MintGrant(context.Background(), &MintStorageGrantRequest{
		UserID: "u", TenantID: "t", Path: "uploads/file.bin", Permission: "write", TTL: 30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Write permission should use PUT method - verify via canonical request in the signature.
	// We can't directly verify the HTTP method from the URL, but the signature will differ.
	// At minimum, verify the URL is generated without error.
	if !strings.Contains(grant.URL, "uploads/file.bin") {
		t.Errorf("URL should contain the path: %s", grant.URL[:min(80, len(grant.URL))])
	}
}

func TestRealAWSS3Adapter_MintGrant_ExplicitBucket(t *testing.T) {
	adapter, err := NewRealAWSS3Adapter(RealAWSS3AdapterConfig{
		Region:        "us-east-1",
		DefaultBucket: "default-bucket",
		CredentialProvider: &StaticAWSCredentialProvider{
			Creds: AWSCredentials{AccessKeyID: "AKID", SecretAccessKey: "SECRET"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	grant, err := adapter.MintGrant(context.Background(), &MintStorageGrantRequest{
		UserID: "u", TenantID: "t", Bucket: "custom-bucket", Path: "file.txt", Permission: "read", TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if grant.Bucket != "custom-bucket" {
		t.Errorf("expected bucket 'custom-bucket', got %q", grant.Bucket)
	}
	if !strings.Contains(grant.URL, "custom-bucket.s3.us-east-1.amazonaws.com") {
		t.Errorf("URL should use custom bucket: %s", grant.URL[:min(80, len(grant.URL))])
	}
}

func TestRealAWSS3Adapter_MintGrant_NoBucket(t *testing.T) {
	adapter, err := NewRealAWSS3Adapter(RealAWSS3AdapterConfig{
		Region: "us-east-1",
		CredentialProvider: &StaticAWSCredentialProvider{
			Creds: AWSCredentials{AccessKeyID: "AKID", SecretAccessKey: "SECRET"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = adapter.MintGrant(context.Background(), &MintStorageGrantRequest{
		UserID: "u", TenantID: "t", Path: "file.txt", Permission: "read", TTL: time.Hour,
	})
	if err == nil {
		t.Fatal("expected error when no bucket available")
	}
	if !strings.Contains(err.Error(), "bucket is required") {
		t.Errorf("expected bucket error, got: %v", err)
	}
}

func TestRealAWSS3Adapter_MintGrant_TTLCapped(t *testing.T) {
	adapter, err := NewRealAWSS3Adapter(RealAWSS3AdapterConfig{
		Region:        "us-east-1",
		DefaultBucket: "b",
		CredentialProvider: &StaticAWSCredentialProvider{
			Creds: AWSCredentials{AccessKeyID: "AKID", SecretAccessKey: "SECRET"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// TTL > 7 days should be capped.
	grant, err := adapter.MintGrant(context.Background(), &MintStorageGrantRequest{
		UserID: "u", TenantID: "t", Path: "f.txt", Permission: "read", TTL: 8 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	u, _ := url.Parse(grant.URL)
	if u.Query().Get("X-Amz-Expires") != "604800" {
		t.Errorf("expected capped expiry 604800, got %q", u.Query().Get("X-Amz-Expires"))
	}
}

func TestRealAWSS3Adapter_MintGrant_WithSessionToken(t *testing.T) {
	adapter, err := NewRealAWSS3Adapter(RealAWSS3AdapterConfig{
		Region:        "us-east-1",
		DefaultBucket: "b",
		CredentialProvider: &StaticAWSCredentialProvider{
			Creds: AWSCredentials{
				AccessKeyID:    "AKID",
				SecretAccessKey: "SECRET",
				SessionToken:   "MY-SESSION-TOKEN",
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	grant, err := adapter.MintGrant(context.Background(), &MintStorageGrantRequest{
		UserID: "u", TenantID: "t", Path: "f.txt", Permission: "read", TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	u, _ := url.Parse(grant.URL)
	if u.Query().Get("X-Amz-Security-Token") != "MY-SESSION-TOKEN" {
		t.Errorf("expected session token in URL, got %q", u.Query().Get("X-Amz-Security-Token"))
	}
}

func TestRealAWSS3Adapter_MintGrant_CredentialError(t *testing.T) {
	adapter, err := NewRealAWSS3Adapter(RealAWSS3AdapterConfig{
		Region:             "us-east-1",
		DefaultBucket:      "b",
		CredentialProvider: &failingS3CredProvider{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = adapter.MintGrant(context.Background(), &MintStorageGrantRequest{
		UserID: "u", TenantID: "t", Path: "f.txt", Permission: "read", TTL: time.Hour,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "retrieve AWS credentials") {
		t.Errorf("expected credential error, got: %v", err)
	}
}

func TestRealAWSS3Adapter_NotStubAdapter(t *testing.T) {
	adapter, _ := NewRealAWSS3Adapter(RealAWSS3AdapterConfig{
		Region: "us-east-1",
		CredentialProvider: &StaticAWSCredentialProvider{
			Creds: AWSCredentials{AccessKeyID: "A", SecretAccessKey: "B"},
		},
	})
	type stubChecker interface{ IsStub() bool }
	if sc, ok := interface{}(adapter).(stubChecker); ok {
		t.Errorf("real adapter should not implement StubAdapter, IsStub=%v", sc.IsStub())
	}
}

// --- Azure Blob Adapter Tests ---

func TestRealAzureBlobAdapter_Name(t *testing.T) {
	adapter, err := NewRealAzureBlobAdapter(RealAzureBlobAdapterConfig{
		AccountName:           "myaccount",
		DelegationKeyProvider: &mockDelegationKeyProvider{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if adapter.Name() != "azure-blob" {
		t.Errorf("expected name 'azure-blob', got %q", adapter.Name())
	}
}

func TestRealAzureBlobAdapter_MissingAccountName(t *testing.T) {
	_, err := NewRealAzureBlobAdapter(RealAzureBlobAdapterConfig{
		DelegationKeyProvider: &mockDelegationKeyProvider{},
	})
	if err == nil {
		t.Fatal("expected error for missing account name")
	}
}

func TestRealAzureBlobAdapter_MissingDelegationKeyProvider(t *testing.T) {
	_, err := NewRealAzureBlobAdapter(RealAzureBlobAdapterConfig{
		AccountName: "myaccount",
	})
	if err == nil {
		t.Fatal("expected error for missing delegation key provider")
	}
}

func TestRealAzureBlobAdapter_MintGrant_Success(t *testing.T) {
	now := time.Now().UTC()
	keyProv := &mockDelegationKeyProvider{
		key: &AzureUserDelegationKey{
			Value:         base64.StdEncoding.EncodeToString([]byte("test-delegation-key-1234567890ab")),
			SignedStart:   now.Add(-1 * time.Hour),
			SignedExpiry:  now.Add(8 * time.Hour),
			SignedOID:     "oid-12345",
			SignedTID:     "tid-67890",
			SignedService: "b",
			SignedVersion: AzureStorageAPIVersion,
		},
	}

	adapter, err := NewRealAzureBlobAdapter(RealAzureBlobAdapterConfig{
		AccountName:           "myaccount",
		DefaultContainer:      "mycontainer",
		DelegationKeyProvider: keyProv,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	grant, err := adapter.MintGrant(context.Background(), &MintStorageGrantRequest{
		UserID:     "user-1",
		TenantID:   "tenant-1",
		Path:       "data/file.txt",
		Permission: "read",
		TTL:        1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify URL structure.
	if !strings.HasPrefix(grant.URL, "https://myaccount.blob.core.windows.net/mycontainer/data/file.txt?") {
		t.Errorf("unexpected URL prefix: %s", grant.URL[:min(100, len(grant.URL))])
	}

	// Verify SAS parameters.
	if !strings.Contains(grant.Token, "sp=r") {
		t.Errorf("SAS should contain sp=r for read permission, token: %s", grant.Token[:min(100, len(grant.Token))])
	}
	if !strings.Contains(grant.Token, "sr=b") {
		t.Errorf("SAS should contain sr=b for blob resource")
	}
	if !strings.Contains(grant.Token, "sig=") {
		t.Errorf("SAS should contain sig= for signature")
	}

	// Verify metadata.
	if grant.Adapter != "azure-blob" {
		t.Errorf("expected adapter 'azure-blob', got %q", grant.Adapter)
	}
	if grant.Bucket != "mycontainer" {
		t.Errorf("expected bucket 'mycontainer', got %q", grant.Bucket)
	}
}

func TestRealAzureBlobAdapter_MintGrant_WritePermission(t *testing.T) {
	now := time.Now().UTC()
	keyProv := &mockDelegationKeyProvider{
		key: &AzureUserDelegationKey{
			Value:         base64.StdEncoding.EncodeToString([]byte("key-data-32-chars-long-padding!!")),
			SignedStart:   now.Add(-1 * time.Hour),
			SignedExpiry:  now.Add(8 * time.Hour),
			SignedOID:     "oid-1",
			SignedTID:     "tid-1",
			SignedService: "b",
			SignedVersion: AzureStorageAPIVersion,
		},
	}

	adapter, err := NewRealAzureBlobAdapter(RealAzureBlobAdapterConfig{
		AccountName:           "acc",
		DefaultContainer:      "c",
		DelegationKeyProvider: keyProv,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	grant, err := adapter.MintGrant(context.Background(), &MintStorageGrantRequest{
		UserID: "u", TenantID: "t", Path: "f.txt", Permission: "write", TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(grant.Token, "sp=w") {
		t.Errorf("SAS should contain sp=w for write, got: %s", grant.Token[:min(60, len(grant.Token))])
	}
}

func TestRealAzureBlobAdapter_MintGrant_ExplicitContainer(t *testing.T) {
	now := time.Now().UTC()
	keyProv := &mockDelegationKeyProvider{
		key: &AzureUserDelegationKey{
			Value:         base64.StdEncoding.EncodeToString([]byte("key1234567890123456789012345678")),
			SignedStart:   now,
			SignedExpiry:  now.Add(8 * time.Hour),
			SignedOID:     "o",
			SignedTID:     "t",
			SignedService: "b",
			SignedVersion: AzureStorageAPIVersion,
		},
	}

	adapter, err := NewRealAzureBlobAdapter(RealAzureBlobAdapterConfig{
		AccountName:           "acc",
		DefaultContainer:      "default",
		DelegationKeyProvider: keyProv,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	grant, err := adapter.MintGrant(context.Background(), &MintStorageGrantRequest{
		UserID: "u", TenantID: "t", Bucket: "custom-container", Path: "f.txt", Permission: "read", TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if grant.Bucket != "custom-container" {
		t.Errorf("expected custom container, got %q", grant.Bucket)
	}
}

func TestRealAzureBlobAdapter_MintGrant_NoContainer(t *testing.T) {
	adapter, err := NewRealAzureBlobAdapter(RealAzureBlobAdapterConfig{
		AccountName:           "acc",
		DelegationKeyProvider: &mockDelegationKeyProvider{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = adapter.MintGrant(context.Background(), &MintStorageGrantRequest{
		UserID: "u", TenantID: "t", Path: "f.txt", Permission: "read", TTL: time.Hour,
	})
	if err == nil {
		t.Fatal("expected error for missing container")
	}
	if !strings.Contains(err.Error(), "container is required") {
		t.Errorf("expected container error, got: %v", err)
	}
}

func TestRealAzureBlobAdapter_MintGrant_DelegationKeyError(t *testing.T) {
	adapter, err := NewRealAzureBlobAdapter(RealAzureBlobAdapterConfig{
		AccountName:           "acc",
		DefaultContainer:      "c",
		DelegationKeyProvider: &mockDelegationKeyProvider{err: fmt.Errorf("auth failure")},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = adapter.MintGrant(context.Background(), &MintStorageGrantRequest{
		UserID: "u", TenantID: "t", Path: "f.txt", Permission: "read", TTL: time.Hour,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "get Azure delegation key") {
		t.Errorf("expected delegation key error, got: %v", err)
	}
}

// --- GCP GCS Adapter Tests ---

func TestRealGCPGCSAdapter_Name(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	adapter, err := NewRealGCPGCSAdapter(RealGCPGCSAdapterConfig{
		Signer: NewRSAServiceAccountSigner(key, "test@test.iam.gserviceaccount.com"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if adapter.Name() != "gcp-gcs" {
		t.Errorf("expected name 'gcp-gcs', got %q", adapter.Name())
	}
}

func TestRealGCPGCSAdapter_MissingSigner(t *testing.T) {
	_, err := NewRealGCPGCSAdapter(RealGCPGCSAdapterConfig{})
	if err == nil {
		t.Fatal("expected error for missing signer")
	}
}

func TestRealGCPGCSAdapter_MintGrant_Success(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	adapter, err := NewRealGCPGCSAdapter(RealGCPGCSAdapterConfig{
		DefaultBucket: "my-gcs-bucket",
		Signer:        NewRSAServiceAccountSigner(key, "sa@project.iam.gserviceaccount.com"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	grant, err := adapter.MintGrant(context.Background(), &MintStorageGrantRequest{
		UserID:     "user-1",
		TenantID:   "tenant-1",
		Path:       "data/file.json",
		Permission: "read",
		TTL:        2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify URL structure.
	if !strings.HasPrefix(grant.URL, "https://storage.googleapis.com/my-gcs-bucket/data/file.json?") {
		t.Errorf("unexpected URL prefix: %s", grant.URL[:min(100, len(grant.URL))])
	}

	// Parse query params.
	u, err := url.Parse(grant.URL)
	if err != nil {
		t.Fatalf("failed to parse URL: %v", err)
	}
	params := u.Query()

	if params.Get("X-Goog-Algorithm") != "GOOG4-RSA-SHA256" {
		t.Errorf("expected GOOG4-RSA-SHA256, got %q", params.Get("X-Goog-Algorithm"))
	}
	if !strings.Contains(params.Get("X-Goog-Credential"), "sa@project.iam.gserviceaccount.com") {
		t.Errorf("credential should contain SA email")
	}
	if !strings.Contains(params.Get("X-Goog-Credential"), "/storage/goog4_request") {
		t.Errorf("credential should contain storage service")
	}
	if params.Get("X-Goog-SignedHeaders") != "host" {
		t.Errorf("expected SignedHeaders=host")
	}
	if params.Get("X-Goog-Signature") == "" {
		t.Error("expected non-empty signature")
	}
	if params.Get("X-Goog-Expires") != "7200" {
		t.Errorf("expected expiry 7200, got %q", params.Get("X-Goog-Expires"))
	}

	// Verify metadata.
	if grant.Adapter != "gcp-gcs" {
		t.Errorf("expected adapter 'gcp-gcs', got %q", grant.Adapter)
	}
	if grant.Bucket != "my-gcs-bucket" {
		t.Errorf("expected bucket 'my-gcs-bucket', got %q", grant.Bucket)
	}
}

func TestRealGCPGCSAdapter_MintGrant_ExplicitBucket(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	adapter, err := NewRealGCPGCSAdapter(RealGCPGCSAdapterConfig{
		DefaultBucket: "default-bucket",
		Signer:        NewRSAServiceAccountSigner(key, "sa@p.iam.gserviceaccount.com"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	grant, err := adapter.MintGrant(context.Background(), &MintStorageGrantRequest{
		UserID: "u", TenantID: "t", Bucket: "explicit-bucket", Path: "f.txt", Permission: "read", TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if grant.Bucket != "explicit-bucket" {
		t.Errorf("expected explicit-bucket, got %q", grant.Bucket)
	}
	if !strings.Contains(grant.URL, "/explicit-bucket/") {
		t.Errorf("URL should contain explicit bucket")
	}
}

func TestRealGCPGCSAdapter_MintGrant_NoBucket(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	adapter, err := NewRealGCPGCSAdapter(RealGCPGCSAdapterConfig{
		Signer: NewRSAServiceAccountSigner(key, "sa@p.iam.gserviceaccount.com"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = adapter.MintGrant(context.Background(), &MintStorageGrantRequest{
		UserID: "u", TenantID: "t", Path: "f.txt", Permission: "read", TTL: time.Hour,
	})
	if err == nil {
		t.Fatal("expected error for missing bucket")
	}
	if !strings.Contains(err.Error(), "bucket is required") {
		t.Errorf("expected bucket error, got: %v", err)
	}
}

func TestRealGCPGCSAdapter_MintGrant_TTLCapped(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	adapter, err := NewRealGCPGCSAdapter(RealGCPGCSAdapterConfig{
		DefaultBucket: "b",
		Signer:        NewRSAServiceAccountSigner(key, "sa@p.iam.gserviceaccount.com"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	grant, err := adapter.MintGrant(context.Background(), &MintStorageGrantRequest{
		UserID: "u", TenantID: "t", Path: "f.txt", Permission: "read", TTL: 8 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	u, _ := url.Parse(grant.URL)
	if u.Query().Get("X-Goog-Expires") != "604800" {
		t.Errorf("expected capped expiry 604800, got %q", u.Query().Get("X-Goog-Expires"))
	}
}

func TestRealGCPGCSAdapter_MintGrant_WritePermission(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	adapter, err := NewRealGCPGCSAdapter(RealGCPGCSAdapterConfig{
		DefaultBucket: "b",
		Signer:        NewRSAServiceAccountSigner(key, "sa@p.iam.gserviceaccount.com"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	grant, err := adapter.MintGrant(context.Background(), &MintStorageGrantRequest{
		UserID: "u", TenantID: "t", Path: "upload.bin", Permission: "write", TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// URL should be generated without error for write.
	if !strings.Contains(grant.URL, "upload.bin") {
		t.Errorf("URL should contain the object path")
	}
}

func TestRealGCPGCSAdapter_NotStubAdapter(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	adapter, _ := NewRealGCPGCSAdapter(RealGCPGCSAdapterConfig{
		Signer: NewRSAServiceAccountSigner(key, "sa@p.iam.gserviceaccount.com"),
	})
	type stubChecker interface{ IsStub() bool }
	if sc, ok := interface{}(adapter).(stubChecker); ok {
		t.Errorf("real adapter should not implement StubAdapter, IsStub=%v", sc.IsStub())
	}
}

func TestRSAServiceAccountSigner_Email(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer := NewRSAServiceAccountSigner(key, "test@project.iam.gserviceaccount.com")
	if signer.Email() != "test@project.iam.gserviceaccount.com" {
		t.Errorf("expected email, got %q", signer.Email())
	}
}

func TestRSAServiceAccountSigner_Sign(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer := NewRSAServiceAccountSigner(key, "sa@p.iam.gserviceaccount.com")
	sig, err := signer.Sign(context.Background(), []byte("test data"))
	if err != nil {
		t.Fatalf("unexpected sign error: %v", err)
	}
	if len(sig) == 0 {
		t.Error("expected non-empty signature")
	}
}

// --- Helpers ---

type failingS3CredProvider struct{}

func (p *failingS3CredProvider) Retrieve(_ context.Context) (*AWSCredentials, error) {
	return nil, fmt.Errorf("simulated credential failure")
}

type mockDelegationKeyProvider struct {
	key *AzureUserDelegationKey
	err error
}

func (m *mockDelegationKeyProvider) GetUserDelegationKey(_ context.Context, _ string, _, _ time.Time) (*AzureUserDelegationKey, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.key, nil
}
