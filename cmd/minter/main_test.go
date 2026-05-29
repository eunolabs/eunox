// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"log/slog"
	"testing"

	"github.com/eunolabs/eunox/pkg/config"
)

func TestBuildPepper_Development(t *testing.T) {
	t.Parallel()

	cfg := &config.MinterConfig{PepperHex: ""}
	pepper, err := buildPepper(cfg)
	if err != nil {
		t.Fatalf("expected development pepper, got error: %v", err)
	}
	if pepper == nil {
		t.Fatal("expected non-nil pepper")
	}
}

func TestBuildPepper_Custom(t *testing.T) {
	t.Parallel()

	cfg := &config.MinterConfig{PepperHex: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}
	pepper, err := buildPepper(cfg)
	if err != nil {
		t.Fatalf("expected pepper, got error: %v", err)
	}
	if pepper == nil {
		t.Fatal("expected non-nil pepper")
	}
}

func TestBuildPepper_Invalid(t *testing.T) {
	t.Parallel()

	cfg := &config.MinterConfig{PepperHex: "not-hex"}
	_, err := buildPepper(cfg)
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

func TestBuildAdminAuth_NoJWT(t *testing.T) {
	t.Setenv("MINTER_ADMIN_JWKS_URI", "")

	cfg := &config.MinterConfig{AdminAPIKey: "test-admin-key-32-chars-minimum!"}
	logger := slog.Default()

	auth := buildAdminAuth(cfg, logger)
	if auth == nil {
		t.Fatal("expected non-nil admin authenticator")
	}
}

func TestBuildAdminAuth_WithJWT(t *testing.T) {
	t.Setenv("MINTER_ADMIN_JWKS_URI", "https://auth.example.com/.well-known/jwks.json")
	t.Setenv("MINTER_ADMIN_JWT_AUDIENCE", "minter-admin")

	cfg := &config.MinterConfig{AdminAPIKey: "test-admin-key-32-chars-minimum!"}
	logger := slog.Default()

	auth := buildAdminAuth(cfg, logger)
	if auth == nil {
		t.Fatal("expected non-nil admin authenticator")
	}
}
