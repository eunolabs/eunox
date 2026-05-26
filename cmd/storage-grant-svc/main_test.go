// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"strings"
	"testing"
)

func TestBuildAdapter(t *testing.T) {
	t.Parallel()

	adapter, err := buildAdapter("aws-s3")
	if err != nil {
		t.Fatalf("expected adapter, got error: %v", err)
	}
	if adapter.Name() != "aws-s3" {
		t.Fatalf("expected aws-s3 adapter, got %q", adapter.Name())
	}
}

func TestBuildAdapter_Azure(t *testing.T) {
	t.Parallel()

	adapter, err := buildAdapter("azure-blob")
	if err != nil {
		t.Fatalf("expected adapter, got error: %v", err)
	}
	if adapter.Name() != "azure-blob" {
		t.Fatalf("expected azure-blob adapter, got %q", adapter.Name())
	}
}

func TestBuildAdapter_GCP(t *testing.T) {
	t.Parallel()

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
