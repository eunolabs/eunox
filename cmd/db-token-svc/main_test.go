// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"strings"
	"testing"
)

func TestBuildAdapter(t *testing.T) {
	// aws-rds requires endpoint and AWS credentials.
	t.Setenv("DB_TOKEN_SVC_RDS_ENDPOINT", "mydb.cluster-abc.us-east-1.rds.amazonaws.com")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

	adapter, err := buildAdapter("aws-rds")
	if err != nil {
		t.Fatalf("expected adapter, got error: %v", err)
	}
	if adapter.Name() != "aws-rds" {
		t.Fatalf("expected aws-rds adapter, got %q", adapter.Name())
	}
}

func TestBuildAdapter_Azure(t *testing.T) {
	// azure-sql requires server name; IMDS token provider needs no env vars to construct.
	t.Setenv("DB_TOKEN_SVC_AZURE_SERVER", "myserver.database.windows.net")

	adapter, err := buildAdapter("azure-sql")
	if err != nil {
		t.Fatalf("expected adapter, got error: %v", err)
	}
	if adapter.Name() != "azure-sql" {
		t.Fatalf("expected azure-sql adapter, got %q", adapter.Name())
	}
}

func TestBuildAdapter_GCP(t *testing.T) {
	// gcp-cloudsql requires instance connection name; metadata token provider needs no env vars.
	t.Setenv("DB_TOKEN_SVC_GCP_INSTANCE", "my-project:us-east1:my-instance")

	adapter, err := buildAdapter("gcp-cloudsql")
	if err != nil {
		t.Fatalf("expected adapter, got error: %v", err)
	}
	if adapter.Name() != "gcp-cloudsql" {
		t.Fatalf("expected gcp-cloudsql adapter, got %q", adapter.Name())
	}
}

func TestBuildAdapter_Unsupported(t *testing.T) {
	t.Parallel()

	if _, err := buildAdapter("unsupported"); err == nil {
		t.Fatal("expected error for unsupported adapter")
	}
}

func TestBuildAdapter_MissingEndpoint(t *testing.T) {
	t.Setenv("DB_TOKEN_SVC_RDS_ENDPOINT", "")

	_, err := buildAdapter("aws-rds")
	if err == nil || !strings.Contains(err.Error(), "DB_TOKEN_SVC_RDS_ENDPOINT") {
		t.Fatalf("expected missing endpoint error, got %v", err)
	}
}

func TestBuildAdapter_MissingAzureServer(t *testing.T) {
	t.Setenv("DB_TOKEN_SVC_AZURE_SERVER", "")

	_, err := buildAdapter("azure-sql")
	if err == nil || !strings.Contains(err.Error(), "DB_TOKEN_SVC_AZURE_SERVER") {
		t.Fatalf("expected missing server error, got %v", err)
	}
}

func TestBuildAdapter_MissingGCPInstance(t *testing.T) {
	t.Setenv("DB_TOKEN_SVC_GCP_INSTANCE", "")

	_, err := buildAdapter("gcp-cloudsql")
	if err == nil || !strings.Contains(err.Error(), "DB_TOKEN_SVC_GCP_INSTANCE") {
		t.Fatalf("expected missing instance error, got %v", err)
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
	t.Setenv("TEST_ENV_VAR_DB_TOKEN", "custom-value")
	result := envOrDefault("TEST_ENV_VAR_DB_TOKEN", "fallback")
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
	t.Setenv("TEST_ENV_VAR_INT_DB_TOKEN", "5432")
	if got := envIntOrDefault("TEST_ENV_VAR_INT_DB_TOKEN", 0); got != 5432 {
		t.Fatalf("expected 5432, got %d", got)
	}
}

