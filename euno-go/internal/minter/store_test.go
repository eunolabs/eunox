// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package minter

import (
	"testing"
	"time"
)

func TestNewPepperFromHex(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		hex     string
		wantErr bool
	}{
		{
			name:    "valid 32 byte hex",
			hex:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			wantErr: false,
		},
		{
			name:    "invalid hex chars",
			hex:     "gg23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			wantErr: true,
		},
		{
			name:    "too short",
			hex:     "0123456789abcdef",
			wantErr: true,
		},
		{
			name:    "too long",
			hex:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123",
			wantErr: true,
		},
		{
			name:    "empty",
			hex:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, err := NewPepperFromHex(tt.hex)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(p.Current) != 32 {
				t.Fatalf("expected 32 byte pepper, got %d", len(p.Current))
			}
		})
	}
}

func TestPepper_HashAndVerify(t *testing.T) {
	t.Parallel()

	pepper, err := NewPepperFromHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}

	secret := "test-secret-value"
	hash := pepper.HashSecret(secret)

	if hash == "" {
		t.Fatal("hash should not be empty")
	}
	if hash == secret {
		t.Fatal("hash should not equal the plaintext")
	}

	// Verify with correct secret.
	if !pepper.VerifySecret(secret, hash) {
		t.Error("VerifySecret should return true for matching secret")
	}

	// Verify with wrong secret.
	if pepper.VerifySecret("wrong-secret", hash) {
		t.Error("VerifySecret should return false for wrong secret")
	}
}

func TestPepper_Rotation(t *testing.T) {
	t.Parallel()

	oldPepper, err := NewPepperFromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}

	newPepper, err := NewPepperFromHex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err != nil {
		t.Fatal(err)
	}

	// Hash with old pepper.
	secret := "my-secret"
	oldHash := oldPepper.HashSecret(secret)

	// New pepper should NOT verify old hash by itself.
	if newPepper.VerifySecret(secret, oldHash) {
		t.Error("new pepper alone should not verify old hash")
	}

	// Add old pepper for rotation.
	err = newPepper.AddOldPepper("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}

	// Now it should verify.
	if !newPepper.VerifySecret(secret, oldHash) {
		t.Error("new pepper with old pepper should verify old hash")
	}

	// New pepper's own hash should also verify.
	newHash := newPepper.HashSecret(secret)
	if !newPepper.VerifySecret(secret, newHash) {
		t.Error("new pepper should verify its own hash")
	}
}

func TestPepper_AddOldPepper_Invalid(t *testing.T) {
	t.Parallel()

	pepper, _ := NewPepperFromHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	if err := pepper.AddOldPepper("not-hex"); err == nil {
		t.Error("expected error for invalid hex")
	}
	if err := pepper.AddOldPepper("aabb"); err == nil {
		t.Error("expected error for too short")
	}
}

func TestMintKey(t *testing.T) {
	t.Parallel()

	pepper, _ := NewPepperFromHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	result, err := MintKey(pepper)
	if err != nil {
		t.Fatalf("MintKey failed: %v", err)
	}

	if result.KeyID == "" {
		t.Error("KeyID should not be empty")
	}
	if result.Secret == "" {
		t.Error("Secret should not be empty")
	}
	if result.SecretHash == "" {
		t.Error("SecretHash should not be empty")
	}
	if result.FullKey == "" {
		t.Error("FullKey should not be empty")
	}

	// Verify the format.
	expectedPrefix := "sk-" + result.KeyID + "."
	if result.FullKey[:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("FullKey should start with %q, got %q", expectedPrefix, result.FullKey[:len(expectedPrefix)])
	}

	// Verify hash matches.
	if !pepper.VerifySecret(result.Secret, result.SecretHash) {
		t.Error("pepper should verify minted key secret")
	}
}

func TestMintKey_Uniqueness(t *testing.T) {
	t.Parallel()

	pepper, _ := NewPepperFromHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	r1, _ := MintKey(pepper)
	r2, _ := MintKey(pepper)

	if r1.KeyID == r2.KeyID {
		t.Error("two minted keys should have different KeyIDs")
	}
	if r1.Secret == r2.Secret {
		t.Error("two minted keys should have different secrets")
	}
}

func TestParseKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		key       string
		wantKeyID string
		wantSec   string
		wantErr   bool
	}{
		{
			name:      "valid key",
			key:       "sk-abc123.secret456",
			wantKeyID: "abc123",
			wantSec:   "secret456",
		},
		{
			name:    "missing prefix",
			key:     "abc123.secret456",
			wantErr: true,
		},
		{
			name:    "no dot",
			key:     "sk-abc123secret456",
			wantErr: true,
		},
		{
			name:    "dot at start",
			key:     "sk-.secret",
			wantErr: true,
		},
		{
			name:    "dot at end",
			key:     "sk-abc123.",
			wantErr: true,
		},
		{
			name:    "too short",
			key:     "sk",
			wantErr: true,
		},
		{
			name:    "empty",
			key:     "",
			wantErr: true,
		},
		{
			name:      "complex key IDs with dashes",
			key:       "sk-abc-def_ghi.sec-ret_123",
			wantKeyID: "abc-def_ghi",
			wantSec:   "sec-ret_123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			keyID, secret, err := ParseKey(tt.key)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if keyID != tt.wantKeyID {
				t.Errorf("keyID = %q, want %q", keyID, tt.wantKeyID)
			}
			if secret != tt.wantSec {
				t.Errorf("secret = %q, want %q", secret, tt.wantSec)
			}
		})
	}
}

func TestAPIKey_IsRevoked(t *testing.T) {
	t.Parallel()

	k := &APIKey{}
	if k.IsRevoked() {
		t.Error("should not be revoked when RevokedAt is nil")
	}

	now := time.Now()
	k.RevokedAt = &now
	if !k.IsRevoked() {
		t.Error("should be revoked when RevokedAt is set")
	}
}

func TestAPIKey_IsExpired(t *testing.T) {
	t.Parallel()

	now := time.Now()

	k := &APIKey{}
	if k.IsExpired(now) {
		t.Error("should not be expired when ExpiresAt is nil")
	}

	past := now.Add(-24 * time.Hour)
	k.ExpiresAt = &past
	if !k.IsExpired(now) {
		t.Error("should be expired when ExpiresAt is in the past")
	}

	future := now.Add(24 * time.Hour)
	k.ExpiresAt = &future
	if k.IsExpired(now) {
		t.Error("should not be expired when ExpiresAt is in the future")
	}
}

