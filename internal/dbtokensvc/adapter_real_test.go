// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package dbtokensvc

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
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
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := &MintDBCredentialRequest{
		UserID:     "user-123",
		TenantID:   "tenant-abc",
		DBUsername: "iam_user",
		Database:   "mydb",
		TTL:        15 * time.Minute,
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
		UserID:     "user-1",
		TenantID:   "tenant-1",
		DBUsername: "admin",
		Database:   "testdb",
		TTL:        5 * time.Minute,
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
		UserID:     "user-123",
		TenantID:   "tenant-abc",
		DBUsername: "admin@myserver",
		Database:   "mydb",
		TTL:        30 * time.Minute,
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
		TokenProvider:      &mockGCPTokenProvider{},
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
		TokenProvider:      tokenProv,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cred, err := adapter.MintCredential(context.Background(), &MintDBCredentialRequest{
		UserID:     "user-123",
		TenantID:   "tenant-abc",
		DBUsername: "iam-user@my-project.iam",
		Database:   "mydb",
		TTL:        30 * time.Minute,
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
		TokenProvider:      &mockGCPTokenProvider{err: fmt.Errorf("token error")},
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

// --- Golden / deterministic tests for SigV4 signing (T-5) ---

// TestGenerateAuthTokenAt_Deterministic verifies that generateAuthTokenAt produces
// identical output for identical inputs, enabling golden-value assertions in CI.
func TestGenerateAuthTokenAt_Deterministic(t *testing.T) {
	creds := &AWSCredentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}
	fixedTime := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

	adapter, err := NewRealAWSRDSAdapter(RealAWSRDSAdapterConfig{
		Region:             "us-east-1",
		Endpoint:           "test.cluster.us-east-1.rds.amazonaws.com",
		Port:               5432,
		CredentialProvider: &StaticAWSCredentialProvider{Creds: *creds},
	})
	if err != nil {
		t.Fatalf("NewRealAWSRDSAdapter: %v", err)
	}

	got1 := adapter.generateAuthTokenAt(creds, "testuser", 900*time.Second, fixedTime)
	got2 := adapter.generateAuthTokenAt(creds, "testuser", 900*time.Second, fixedTime)

	if got1 != got2 {
		t.Errorf("generateAuthTokenAt is not deterministic:\n  call1: %q\n  call2: %q", got1, got2)
	}
}

// TestGenerateAuthTokenAt_Golden verifies the SigV4 presigned token format and
// that the signature produced matches an independently-derived reference value.
// The reference is computed by the testComputeRDSSignature helper below, which
// reimplements the same HMAC-SHA256 key hierarchy to guard against silent
// algorithm regressions that would cause real auth failures.
func TestGenerateAuthTokenAt_Golden(t *testing.T) {
	creds := &AWSCredentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}
	const (
		region   = "us-east-1"
		endpoint = "test.cluster.us-east-1.rds.amazonaws.com"
		port     = 5432
		dbUser   = "testuser"
		expiry   = 900
	)
	fixedTime := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

	adapter, err := NewRealAWSRDSAdapter(RealAWSRDSAdapterConfig{
		Region:             region,
		Endpoint:           endpoint,
		Port:               port,
		CredentialProvider: &StaticAWSCredentialProvider{Creds: *creds},
	})
	if err != nil {
		t.Fatalf("NewRealAWSRDSAdapter: %v", err)
	}

	token := adapter.generateAuthTokenAt(creds, dbUser, expiry*time.Second, fixedTime)

	// Structural checks.
	expectedPrefix := fmt.Sprintf("%s:%d/?", endpoint, port)
	if !strings.HasPrefix(token, expectedPrefix) {
		t.Errorf("token prefix: want %q, got %q", expectedPrefix, token[:min(80, len(token))])
	}

	parts := strings.SplitN(token, "/?", 2)
	if len(parts) != 2 {
		t.Fatalf("token missing /?  separator: %q", token)
	}
	params, err := url.ParseQuery(parts[1])
	if err != nil {
		t.Fatalf("parse token query: %v", err)
	}

	dateStamp := fixedTime.Format("20060102")
	amzDate := fixedTime.Format("20060102T150405Z")
	credentialScope := fmt.Sprintf("%s/%s/rds-db/aws4_request", dateStamp, region)

	checks := []struct{ key, want string }{
		{"X-Amz-Algorithm", "AWS4-HMAC-SHA256"},
		{"X-Amz-Date", amzDate},
		{"X-Amz-Expires", fmt.Sprintf("%d", expiry)},
		{"X-Amz-SignedHeaders", "host"},
		{"Action", "connect"},
		{"DBUser", dbUser},
		{"X-Amz-Credential", creds.AccessKeyID + "/" + credentialScope},
	}
	for _, c := range checks {
		if got := params.Get(c.key); got != c.want {
			t.Errorf("param %q: want %q, got %q", c.key, c.want, got)
		}
	}

	sig := params.Get("X-Amz-Signature")
	if len(sig) != 64 {
		t.Errorf("signature length: want 64, got %d (%q)", len(sig), sig)
	}

	// Cross-validate: independently derive the expected signature using only
	// the raw HMAC-SHA256 primitives. This guards against a silent regression
	// in the canonical-request or string-to-sign construction.
	expectedSig := testComputeRDSSignature(
		creds, dbUser, endpoint, port, region, expiry, fixedTime,
	)
	if sig != expectedSig {
		t.Errorf("signature mismatch with cross-validation reference:\n  want: %q\n   got: %q", expectedSig, sig)
	}
}

// TestGenerateAuthTokenAt_SessionToken ensures the security token is included
// in the presigned URL when temporary credentials are used.
func TestGenerateAuthTokenAt_SessionToken(t *testing.T) {
	creds := &AWSCredentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "AQoDYXdzEJr//SESSION/TOKEN",
	}
	adapter, err := NewRealAWSRDSAdapter(RealAWSRDSAdapterConfig{
		Region:             "eu-west-1",
		Endpoint:           "db.abc.eu-west-1.rds.amazonaws.com",
		Port:               5432,
		CredentialProvider: &StaticAWSCredentialProvider{Creds: *creds},
	})
	if err != nil {
		t.Fatalf("NewRealAWSRDSAdapter: %v", err)
	}

	fixedTime := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	token := adapter.generateAuthTokenAt(creds, "admin", 15*time.Minute, fixedTime)

	parts := strings.SplitN(token, "/?", 2)
	params, _ := url.ParseQuery(parts[1])
	if got := params.Get("X-Amz-Security-Token"); got != creds.SessionToken {
		t.Errorf("X-Amz-Security-Token: want %q, got %q", creds.SessionToken, got)
	}
}

// testComputeRDSSignature is an independent cross-validation reference for the
// SigV4 presigned token signature. It derives the canonical request and string-
// to-sign from first principles so that any divergence from the production
// generateAuthTokenAt will be caught as a test failure.
func testComputeRDSSignature(
	creds *AWSCredentials,
	dbUser, endpoint string, port int,
	region string, expirySeconds int,
	now time.Time,
) string {
	hmacSHA256 := func(key, data []byte) []byte {
		mac := hmac.New(sha256.New, key)
		mac.Write(data)
		return mac.Sum(nil)
	}
	sha256hex := func(data []byte) string {
		h := sha256.Sum256(data)
		return hex.EncodeToString(h[:])
	}
	percentEncode := func(value string) string {
		const hexChars = "0123456789ABCDEF"
		var b strings.Builder
		for i := 0; i < len(value); i++ {
			c := value[i]
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
				c == '-' || c == '_' || c == '.' || c == '~' {
				b.WriteByte(c)
			} else {
				b.WriteByte('%')
				b.WriteByte(hexChars[c>>4])
				b.WriteByte(hexChars[c&0x0F])
			}
		}
		return b.String()
	}

	datestamp := now.UTC().Format("20060102")
	amzdate := now.UTC().Format("20060102T150405Z")

	credentialScope := fmt.Sprintf("%s/%s/rds-db/aws4_request", datestamp, region)
	credential := fmt.Sprintf("%s/%s", creds.AccessKeyID, credentialScope)

	// Build canonical query string (sorted by key, then percent-encoded).
	rawParams := map[string]string{
		"Action":              "connect",
		"DBUser":              dbUser,
		"X-Amz-Algorithm":     "AWS4-HMAC-SHA256",
		"X-Amz-Credential":    credential,
		"X-Amz-Date":          amzdate,
		"X-Amz-Expires":       fmt.Sprintf("%d", expirySeconds),
		"X-Amz-SignedHeaders": "host",
	}
	sortedKeys := []string{
		"Action", "DBUser", "X-Amz-Algorithm", "X-Amz-Credential",
		"X-Amz-Date", "X-Amz-Expires", "X-Amz-SignedHeaders",
	}
	var pairs []string
	for _, k := range sortedKeys {
		pairs = append(pairs, percentEncode(k)+"="+percentEncode(rawParams[k]))
	}
	canonicalQueryString := strings.Join(pairs, "&")

	canonicalHeaders := fmt.Sprintf("host:%s:%d\n", endpoint, port)
	canonicalRequest := strings.Join([]string{
		"GET", "/", canonicalQueryString, canonicalHeaders, "host", "UNSIGNED-PAYLOAD",
	}, "\n")

	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzdate, credentialScope, sha256hex([]byte(canonicalRequest)),
	}, "\n")

	// Derive signing key.
	kDate := hmacSHA256([]byte("AWS4"+creds.SecretAccessKey), []byte(datestamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte("rds-db"))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))

	return hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))
}
