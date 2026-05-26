// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package dbtokensvc

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

// --- AWS RDS Adapter Tests ---

func TestRealAWSRDSAdapter_Name(t *testing.T) {
	adapter, err := NewRealAWSRDSAdapter(RealAWSRDSAdapterConfig{
		Endpoint: "mydb.cluster-abc123.us-east-1.rds.amazonaws.com",
		Port:     5432,
		Region:   "us-east-1",
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
	if adapter.Name() != "aws-rds" {
		t.Errorf("expected name 'aws-rds', got %q", adapter.Name())
	}
}

func TestRealAWSRDSAdapter_MissingRegion(t *testing.T) {
	_, err := NewRealAWSRDSAdapter(RealAWSRDSAdapterConfig{
		Endpoint: "mydb.cluster-abc123.us-east-1.rds.amazonaws.com",
		Port:     5432,
	})
	if err == nil {
		t.Fatal("expected error for missing region")
	}
}

func TestRealAWSRDSAdapter_MissingEndpoint(t *testing.T) {
	_, err := NewRealAWSRDSAdapter(RealAWSRDSAdapterConfig{
		Region: "us-east-1",
		Port:   5432,
		CredentialProvider: &StaticAWSCredentialProvider{
			Creds: AWSCredentials{AccessKeyID: "test", SecretAccessKey: "test"},
		},
	})
	if err == nil {
		t.Fatal("expected error for missing endpoint")
	}
}

func TestRealAWSRDSAdapter_MissingCredentialProvider(t *testing.T) {
	_, err := NewRealAWSRDSAdapter(RealAWSRDSAdapterConfig{
		Endpoint: "mydb.abc.rds.amazonaws.com",
		Region:   "us-east-1",
		Port:     5432,
	})
	if err == nil {
		t.Fatal("expected error for missing credential provider")
	}
}

func TestRealAWSRDSAdapter_DefaultPort(t *testing.T) {
	adapter, err := NewRealAWSRDSAdapter(RealAWSRDSAdapterConfig{
		Endpoint: "mydb.abc.rds.amazonaws.com",
		Region:   "us-east-1",
		CredentialProvider: &StaticAWSCredentialProvider{
			Creds: AWSCredentials{AccessKeyID: "test", SecretAccessKey: "test"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if adapter.port != 5432 {
		t.Errorf("expected default port 5432, got %d", adapter.port)
	}
}

func TestRealAWSRDSAdapter_MintCredential_Success(t *testing.T) {
	adapter, err := NewRealAWSRDSAdapter(RealAWSRDSAdapterConfig{
		Endpoint: "mydb.cluster-abc123.us-east-1.rds.amazonaws.com",
		Port:     5432,
		Region:   "us-east-1",
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

	req := &MintDBCredentialRequest{
		UserID:   "user-123",
		TenantID: "tenant-abc",
		DBUsername: "iam_user",
		Database: "mydb",
		TTL:      15 * time.Minute,
	}

	cred, err := adapter.MintCredential(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the token format: host:port/?queryparams
	if !strings.HasPrefix(cred.Token, "mydb.cluster-abc123.us-east-1.rds.amazonaws.com:5432/?") {
		t.Errorf("token should start with host:port/?, got %q", cred.Token[:min(80, len(cred.Token))])
	}

	// Parse the query parameters from the token.
	parts := strings.SplitN(cred.Token, "/?", 2)
	if len(parts) != 2 {
		t.Fatalf("token format invalid, expected host:port/?query, got %q", cred.Token[:min(80, len(cred.Token))])
	}
	params, err := url.ParseQuery(parts[1])
	if err != nil {
		t.Fatalf("failed to parse token query: %v", err)
	}

	// Verify required SigV4 parameters.
	if params.Get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256" {
		t.Errorf("expected AWS4-HMAC-SHA256 algorithm, got %q", params.Get("X-Amz-Algorithm"))
	}
	if params.Get("Action") != "connect" {
		t.Errorf("expected Action=connect, got %q", params.Get("Action"))
	}
	if params.Get("DBUser") != "iam_user" {
		t.Errorf("expected DBUser=iam_user, got %q", params.Get("DBUser"))
	}
	if !strings.Contains(params.Get("X-Amz-Credential"), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("credential should contain access key ID, got %q", params.Get("X-Amz-Credential"))
	}
	if !strings.Contains(params.Get("X-Amz-Credential"), "/rds-db/aws4_request") {
		t.Errorf("credential should contain rds-db service, got %q", params.Get("X-Amz-Credential"))
	}
	if params.Get("X-Amz-SignedHeaders") != "host" {
		t.Errorf("expected SignedHeaders=host, got %q", params.Get("X-Amz-SignedHeaders"))
	}
	if params.Get("X-Amz-Signature") == "" {
		t.Error("expected non-empty signature")
	}
	if params.Get("X-Amz-Expires") != "900" {
		t.Errorf("expected expiry 900, got %q", params.Get("X-Amz-Expires"))
	}

	// Verify metadata.
	if cred.Adapter != "aws-rds" {
		t.Errorf("expected adapter 'aws-rds', got %q", cred.Adapter)
	}
	if cred.Username != "iam_user" {
		t.Errorf("expected username 'iam_user', got %q", cred.Username)
	}
}

func TestRealAWSRDSAdapter_MintCredential_WithSessionToken(t *testing.T) {
	adapter, err := NewRealAWSRDSAdapter(RealAWSRDSAdapterConfig{
		Endpoint: "mydb.abc.rds.amazonaws.com",
		Port:     3306,
		Region:   "eu-west-1",
		CredentialProvider: &StaticAWSCredentialProvider{
			Creds: AWSCredentials{
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				SessionToken:    "FwoGZXIvYXdzEBYaDNZ4example",
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cred, err := adapter.MintCredential(context.Background(), &MintDBCredentialRequest{
		UserID:   "user-1",
		TenantID: "tenant-1",
		DBUsername: "admin",
		Database: "testdb",
		TTL:      5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parts := strings.SplitN(cred.Token, "/?", 2)
	params, _ := url.ParseQuery(parts[1])
	if params.Get("X-Amz-Security-Token") != "FwoGZXIvYXdzEBYaDNZ4example" {
		t.Errorf("expected session token in presigned URL, got %q", params.Get("X-Amz-Security-Token"))
	}
}

func TestRealAWSRDSAdapter_MintCredential_TTLCapped(t *testing.T) {
	adapter, err := NewRealAWSRDSAdapter(RealAWSRDSAdapterConfig{
		Endpoint: "mydb.abc.rds.amazonaws.com",
		Port:     5432,
		Region:   "us-west-2",
		CredentialProvider: &StaticAWSCredentialProvider{
			Creds: AWSCredentials{AccessKeyID: "AKID", SecretAccessKey: "SECRET"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// TTL > 15 minutes should be capped to 900s.
	cred, err := adapter.MintCredential(context.Background(), &MintDBCredentialRequest{
		UserID: "u", TenantID: "t", DBUsername: "user", Database: "db", TTL: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parts := strings.SplitN(cred.Token, "/?", 2)
	params, _ := url.ParseQuery(parts[1])
	if params.Get("X-Amz-Expires") != "900" {
		t.Errorf("expected capped expiry 900, got %q", params.Get("X-Amz-Expires"))
	}
}

func TestRealAWSRDSAdapter_MintCredential_CredentialProviderError(t *testing.T) {
	adapter, err := NewRealAWSRDSAdapter(RealAWSRDSAdapterConfig{
		Endpoint:           "mydb.abc.rds.amazonaws.com",
		Port:               5432,
		Region:             "us-east-1",
		CredentialProvider: &failingAWSCredProvider{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = adapter.MintCredential(context.Background(), &MintDBCredentialRequest{
		UserID: "u", TenantID: "t", DBUsername: "user", Database: "db", TTL: 5 * time.Minute,
	})
	if err == nil {
		t.Fatal("expected error from credential provider")
	}
	if !strings.Contains(err.Error(), "retrieve AWS credentials") {
		t.Errorf("expected credential retrieval error, got: %v", err)
	}
}

func TestRealAWSRDSAdapter_NotStubAdapter(t *testing.T) {
	adapter, _ := NewRealAWSRDSAdapter(RealAWSRDSAdapterConfig{
		Endpoint: "mydb.abc.rds.amazonaws.com",
		Port:     5432,
		Region:   "us-east-1",
		CredentialProvider: &StaticAWSCredentialProvider{
			Creds: AWSCredentials{AccessKeyID: "A", SecretAccessKey: "B"},
		},
	})
	// RealAWSRDSAdapter should NOT implement StubAdapter interface.
	type stubChecker interface {
		IsStub() bool
	}
	if sc, ok := interface{}(adapter).(stubChecker); ok {
		t.Errorf("real adapter should not implement StubAdapter, but IsStub=%v", sc.IsStub())
	}
}

// --- Azure SQL Adapter Tests ---

func TestRealAzureSQLAdapter_Name(t *testing.T) {
	adapter, err := NewRealAzureSQLAdapter(RealAzureSQLAdapterConfig{
		ServerName:    "myserver.database.windows.net",
		TokenProvider: &mockAzureTokenProvider{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if adapter.Name() != "azure-sql" {
		t.Errorf("expected name 'azure-sql', got %q", adapter.Name())
	}
}

func TestRealAzureSQLAdapter_MissingServerFQDN(t *testing.T) {
	_, err := NewRealAzureSQLAdapter(RealAzureSQLAdapterConfig{
		TokenProvider: &mockAzureTokenProvider{},
	})
	if err == nil {
		t.Fatal("expected error for missing server FQDN")
	}
}

func TestRealAzureSQLAdapter_MissingTokenProvider(t *testing.T) {
	_, err := NewRealAzureSQLAdapter(RealAzureSQLAdapterConfig{
		ServerName: "myserver.database.windows.net",
	})
	if err == nil {
		t.Fatal("expected error for missing token provider")
	}
}

func TestRealAzureSQLAdapter_MintCredential_Success(t *testing.T) {
	tokenProv := &mockAzureTokenProvider{
		token: &AzureToken{
			AccessToken: "******",
			ExpiresOn:   time.Now().Add(1 * time.Hour),
		},
	}
	adapter, err := NewRealAzureSQLAdapter(RealAzureSQLAdapterConfig{
		ServerName:    "myserver.database.windows.net",
		TokenProvider: tokenProv,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cred, err := adapter.MintCredential(context.Background(), &MintDBCredentialRequest{
		UserID:   "user-123",
		TenantID: "tenant-abc",
		DBUsername: "admin@myserver",
		Database: "mydb",
		TTL:      30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cred.Token != "******" {
		t.Errorf("expected token in credential, got %q", cred.Token)
	}
	if cred.Adapter != "azure-sql" {
		t.Errorf("expected adapter 'azure-sql', got %q", cred.Adapter)
	}
	if cred.Username != "admin@myserver" {
		t.Errorf("expected username 'admin@myserver', got %q", cred.Username)
	}
	if tokenProv.lastScope != AzureSQLResourceScope {
		t.Errorf("expected scope %q, got %q", AzureSQLResourceScope, tokenProv.lastScope)
	}
}

func TestRealAzureSQLAdapter_MintCredential_TokenProviderError(t *testing.T) {
	adapter, err := NewRealAzureSQLAdapter(RealAzureSQLAdapterConfig{
		ServerName:    "myserver.database.windows.net",
		TokenProvider: &mockAzureTokenProvider{err: fmt.Errorf("auth failure")},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = adapter.MintCredential(context.Background(), &MintDBCredentialRequest{
		UserID: "u", TenantID: "t", DBUsername: "user", Database: "db", TTL: 5 * time.Minute,
	})
	if err == nil {
		t.Fatal("expected error from token provider")
	}
	if !strings.Contains(err.Error(), "acquire Azure SQL token") {
		t.Errorf("expected token acquisition error, got: %v", err)
	}
}

// --- GCP Cloud SQL Adapter Tests ---

func TestRealGCPCloudSQLAdapter_Name(t *testing.T) {
	adapter, err := NewRealGCPCloudSQLAdapter(RealGCPCloudSQLAdapterConfig{
		InstanceConnection: "project:region:instance",
		TokenProvider:          &mockGCPTokenProvider{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if adapter.Name() != "gcp-cloudsql" {
		t.Errorf("expected name 'gcp-cloudsql', got %q", adapter.Name())
	}
}

func TestRealGCPCloudSQLAdapter_MissingInstanceConnection(t *testing.T) {
	_, err := NewRealGCPCloudSQLAdapter(RealGCPCloudSQLAdapterConfig{
		TokenProvider: &mockGCPTokenProvider{},
	})
	if err == nil {
		t.Fatal("expected error for missing instance connection name")
	}
}

func TestRealGCPCloudSQLAdapter_MissingTokenProvider(t *testing.T) {
	_, err := NewRealGCPCloudSQLAdapter(RealGCPCloudSQLAdapterConfig{
		InstanceConnection: "project:region:instance",
	})
	if err == nil {
		t.Fatal("expected error for missing token provider")
	}
}

func TestRealGCPCloudSQLAdapter_MintCredential_Success(t *testing.T) {
	tokenProv := &mockGCPTokenProvider{
		token: &GCPToken{
			AccessToken: "ya29.mock-gcp-token",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		},
	}
	adapter, err := NewRealGCPCloudSQLAdapter(RealGCPCloudSQLAdapterConfig{
		InstanceConnection: "my-project:us-central1:my-instance",
		TokenProvider:          tokenProv,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cred, err := adapter.MintCredential(context.Background(), &MintDBCredentialRequest{
		UserID:   "user-123",
		TenantID: "tenant-abc",
		DBUsername: "iam-user@my-project.iam",
		Database: "mydb",
		TTL:      30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cred.Token != "ya29.mock-gcp-token" {
		t.Errorf("expected token in credential, got %q", cred.Token)
	}
	if cred.Adapter != "gcp-cloudsql" {
		t.Errorf("expected adapter 'gcp-cloudsql', got %q", cred.Adapter)
	}
	if cred.Username != "iam-user@my-project.iam" {
		t.Errorf("expected username, got %q", cred.Username)
	}
	if len(tokenProv.lastScopes) != len(GCPCloudSQLScopes) || tokenProv.lastScopes[0] != GCPCloudSQLScopes[0] {
		t.Errorf("expected scopes %v, got %v", GCPCloudSQLScopes, tokenProv.lastScopes)
	}
}

func TestRealGCPCloudSQLAdapter_MintCredential_TokenProviderError(t *testing.T) {
	adapter, err := NewRealGCPCloudSQLAdapter(RealGCPCloudSQLAdapterConfig{
		InstanceConnection: "project:region:instance",
		TokenProvider:          &mockGCPTokenProvider{err: fmt.Errorf("token error")},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = adapter.MintCredential(context.Background(), &MintDBCredentialRequest{
		UserID: "u", TenantID: "t", DBUsername: "user", Database: "db", TTL: 5 * time.Minute,
	})
	if err == nil {
		t.Fatal("expected error from token provider")
	}
	if !strings.Contains(err.Error(), "acquire GCP Cloud SQL token") {
		t.Errorf("expected GCP token error, got: %v", err)
	}
}

// --- Helpers ---

type failingAWSCredProvider struct{}

func (p *failingAWSCredProvider) Retrieve(_ context.Context) (*AWSCredentials, error) {
	return nil, fmt.Errorf("simulated credential failure")
}

type mockAzureTokenProvider struct {
	token     *AzureToken
	err       error
	lastScope string
}

func (m *mockAzureTokenProvider) GetToken(_ context.Context, scope string) (*AzureToken, error) {
	m.lastScope = scope
	if m.err != nil {
		return nil, m.err
	}
	return m.token, nil
}

type mockGCPTokenProvider struct {
	token      *GCPToken
	err        error
	lastScopes []string
}

func (m *mockGCPTokenProvider) GetAccessToken(_ context.Context, scopes []string) (*GCPToken, error) {
	m.lastScopes = scopes
	if m.err != nil {
		return nil, m.err
	}
	return m.token, nil
}
