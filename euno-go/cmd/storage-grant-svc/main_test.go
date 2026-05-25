// Copyright 2024-2025 Euno Platform Authors
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

func TestBuildVerifier_NotImplemented(t *testing.T) {
	t.Setenv("ISSUER_JWKS_URL", "https://issuer.example.com/.well-known/jwks.json")
	if _, err := buildVerifier(); err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("expected not implemented error, got %v", err)
	}
}
