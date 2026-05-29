// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildAdapter(t *testing.T) {
	// aws-s3 requires bucket name and AWS credentials.
	t.Setenv("STORAGE_GRANT_SVC_BUCKET", "my-test-bucket")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

	adapter, err := buildAdapter("aws-s3")
	if err != nil {
		t.Fatalf("expected adapter, got error: %v", err)
	}
	if adapter.Name() != "aws-s3" {
		t.Fatalf("expected aws-s3 adapter, got %q", adapter.Name())
	}
}

func TestBuildAdapter_Azure(t *testing.T) {
	// azure-blob requires account name; IMDS/REST providers need no env vars to construct.
	t.Setenv("STORAGE_GRANT_SVC_AZURE_ACCOUNT", "myaccount")

	adapter, err := buildAdapter("azure-blob")
	if err != nil {
		t.Fatalf("expected adapter, got error: %v", err)
	}
	if adapter.Name() != "azure-blob" {
		t.Fatalf("expected azure-blob adapter, got %q", adapter.Name())
	}
}

func TestBuildAdapter_GCP(t *testing.T) {
	// gcp-gcs requires GOOGLE_APPLICATION_CREDENTIALS pointing to a service account key file.
	keyFile := writeTestServiceAccountKey(t)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", keyFile)
	t.Setenv("STORAGE_GRANT_SVC_GCP_BUCKET", "my-bucket")

	adapter, err := buildAdapter("gcp-gcs")
	if err != nil {
		t.Fatalf("expected adapter, got error: %v", err)
	}
	if adapter.Name() != "gcp-gcs" {
		t.Fatalf("expected gcp-gcs adapter, got %q", adapter.Name())
	}
}

func TestBuildAdapter_Unsupported(t *testing.T) {
	t.Parallel()

	if _, err := buildAdapter("unsupported"); err == nil {
		t.Fatal("expected error for unsupported adapter")
	}
}

func TestBuildAdapter_MissingBucket(t *testing.T) {
	t.Setenv("STORAGE_GRANT_SVC_BUCKET", "")

	_, err := buildAdapter("aws-s3")
	if err == nil || !strings.Contains(err.Error(), "STORAGE_GRANT_SVC_BUCKET") {
		t.Fatalf("expected missing bucket error, got %v", err)
	}
}

func TestBuildAdapter_MissingAzureAccount(t *testing.T) {
	t.Setenv("STORAGE_GRANT_SVC_AZURE_ACCOUNT", "")

	_, err := buildAdapter("azure-blob")
	if err == nil || !strings.Contains(err.Error(), "STORAGE_GRANT_SVC_AZURE_ACCOUNT") {
		t.Fatalf("expected missing account error, got %v", err)
	}
}

func TestBuildAdapter_MissingGCPCredentials(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")

	_, err := buildAdapter("gcp-gcs")
	if err == nil || !strings.Contains(err.Error(), "GOOGLE_APPLICATION_CREDENTIALS") {
		t.Fatalf("expected missing credentials error, got %v", err)
	}
}

func TestBuildVerifier_MissingJWKS(t *testing.T) {
	t.Setenv("ISSUER_JWKS_URL", "")
	if _, err := buildVerifier(); err == nil || !strings.Contains(err.Error(), "ISSUER_JWKS_URL") {
		t.Fatalf("expected missing ISSUER_JWKS_URL error, got %v", err)
	}
}

func TestBuildVerifier_ReturnsVerifier(t *testing.T) {
	t.Setenv("ISSUER_JWKS_URL", "https://issuer.example.com/.well-known/jwks.json")
	verifier, err := buildVerifier()
	if err != nil {
		t.Fatalf("expected verifier, got error: %v", err)
	}
	if verifier == nil {
		t.Fatal("expected non-nil verifier")
	}
}

func TestEnvOrDefault(t *testing.T) {
	t.Parallel()

	result := envOrDefault("UNLIKELY_ENV_VAR_QXYZ", "fallback")
	if result != "fallback" {
		t.Fatalf("expected fallback, got %q", result)
	}
}

func TestEnvOrDefault_Set(t *testing.T) {
	t.Setenv("TEST_ENV_VAR_STORAGE_GRANT", "custom-value")
	result := envOrDefault("TEST_ENV_VAR_STORAGE_GRANT", "fallback")
	if result != "custom-value" {
		t.Fatalf("expected custom-value, got %q", result)
	}
}

func TestEnvIntOrDefault(t *testing.T) {
	t.Parallel()

	if got := envIntOrDefault("UNLIKELY_ENV_VAR_INT_QXYZ", 42); got != 42 {
		t.Fatalf("expected 42, got %d", got)
	}
}

func TestEnvIntOrDefault_Set(t *testing.T) {
	t.Setenv("TEST_ENV_VAR_INT_STORAGE", "3306")
	if got := envIntOrDefault("TEST_ENV_VAR_INT_STORAGE", 0); got != 3306 {
		t.Fatalf("expected 3306, got %d", got)
	}
}

// writeTestServiceAccountKey generates a minimal GCP service account key JSON
// with a freshly generated RSA private key and writes it to a temp file.
func writeTestServiceAccountKey(t *testing.T) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test RSA key: %v", err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS8 key: %v", err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))

	saKeyJSON := struct {
		Type        string `json:"type"`
		PrivateKey  string `json:"private_key"`
		ClientEmail string `json:"client_email"`
	}{
		Type:        "service_account",
		PrivateKey:  keyPEM,
		ClientEmail: "test-sa@test-project.iam.gserviceaccount.com",
	}
	data, err := json.Marshal(saKeyJSON)
	if err != nil {
		t.Fatalf("marshal service account JSON: %v", err)
	}

	keyFile := filepath.Join(t.TempDir(), "key.json")
	if err := os.WriteFile(keyFile, data, 0o600); err != nil {
		t.Fatalf("write service account key file: %v", err)
	}
	return keyFile
}
