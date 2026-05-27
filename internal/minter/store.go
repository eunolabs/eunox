// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package minter implements the API-Key Minter HTTP service.
package minter

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Errors returned by the minter package.
var (
	ErrKeyNotFound      = errors.New("minter: key not found")
	ErrKeyRevoked       = errors.New("minter: key already revoked")
	ErrKeyExpired       = errors.New("minter: key expired")
	ErrPolicyNotFound   = errors.New("minter: policy not found")
	ErrPolicyExists     = errors.New("minter: policy already exists")
	ErrInvalidPepper    = errors.New("minter: invalid pepper hex")
	ErrInvalidKey       = errors.New("minter: invalid key format")
	ErrRateLimited      = errors.New("minter: rate limited")
	ErrUnauthorized     = errors.New("minter: unauthorized")
	ErrVelocityExceeded = errors.New("minter: velocity limit exceeded")
)

// APIKey represents a stored API key (without the plaintext secret).
type APIKey struct {
	KeyID       string            `json:"keyId"`
	SecretHash  string            `json:"-"`
	TenantID    string            `json:"tenantId"`
	Description string            `json:"description"`
	CreatedAt   time.Time         `json:"createdAt"`
	ExpiresAt   *time.Time        `json:"expiresAt,omitempty"`
	RevokedAt   *time.Time        `json:"revokedAt,omitempty"`
	CreatedBy   string            `json:"createdBy"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// IsRevoked returns true if the key has been revoked.
func (k *APIKey) IsRevoked() bool {
	return k.RevokedAt != nil
}

// IsExpired returns true if the key has expired.
func (k *APIKey) IsExpired(now time.Time) bool {
	return k.ExpiresAt != nil && now.After(*k.ExpiresAt)
}

// Policy represents a key policy with associated rules.
type Policy struct {
	PolicyID    string     `json:"policyId"`
	TenantID    string     `json:"tenantId"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Rules       PolicyRule `json:"rules"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
	CreatedBy   string     `json:"createdBy"`
}

// PolicyRule defines access rules for a policy.
type PolicyRule struct {
	AllowedTools      []string `json:"allowedTools,omitempty"`
	MaxCallsPerMinute int      `json:"maxCallsPerMinute,omitempty"`
	AllowedIPs        []string `json:"allowedIPs,omitempty"`
	ExpiresAfterDays  int      `json:"expiresAfterDays,omitempty"`
}

// KeyStore provides storage for API keys and policies.
type KeyStore interface {
	// CreateKey persists a new API key.
	CreateKey(ctx context.Context, key *APIKey) error
	// GetKey retrieves a key by ID.
	GetKey(ctx context.Context, keyID string) (*APIKey, error)
	// CountKeys returns the total number of keys for a tenant.
	CountKeys(ctx context.Context, tenantID string) (int, error)
	// ListKeys returns keys for a tenant with pagination.
	ListKeys(ctx context.Context, tenantID string, limit, offset int) ([]*APIKey, error)
	// RevokeKey marks a key as revoked and returns the revoked key.
	// The returned key reflects the state after revocation (RevokedAt is set).
	// Returns ErrKeyNotFound if the key does not exist, ErrKeyRevoked if already revoked.
	RevokeKey(ctx context.Context, keyID string, revokedAt time.Time) (*APIKey, error)

	// CreatePolicy persists a new policy.
	CreatePolicy(ctx context.Context, p *Policy) error
	// GetPolicy retrieves a policy by ID.
	GetPolicy(ctx context.Context, policyID string) (*Policy, error)
	// GetPolicyByName retrieves a policy by tenant and name.
	GetPolicyByName(ctx context.Context, tenantID, name string) (*Policy, error)
	// ListPolicies returns all policies for a tenant.
	ListPolicies(ctx context.Context, tenantID string) ([]*Policy, error)
	// UpdatePolicy updates an existing policy.
	UpdatePolicy(ctx context.Context, p *Policy) error
	// DeletePolicy removes a policy.
	DeletePolicy(ctx context.Context, policyID string) error
}

// MintResult is the result of minting a new API key.
type MintResult struct {
	KeyID      string `json:"keyId"`
	Secret     string `json:"secret"`
	FullKey    string `json:"key"` // sk-{keyId}.{secret}
	SecretHash string `json:"-"`
}

// Pepper holds the HMAC pepper for key hashing. Supports rotation with old peppers.
type Pepper struct {
	Current []byte
	Old     [][]byte // Previous peppers for transition-period verification.
}

// NewPepperFromHex creates a Pepper from a hex-encoded string.
func NewPepperFromHex(hexStr string) (*Pepper, error) {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPepper, err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("%w: expected 32 bytes, got %d", ErrInvalidPepper, len(b))
	}
	return &Pepper{Current: b}, nil
}

// AddOldPepper adds a previous pepper for rotation support.
func (p *Pepper) AddOldPepper(hexStr string) error {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPepper, err)
	}
	if len(b) != 32 {
		return fmt.Errorf("%w: expected 32 bytes, got %d", ErrInvalidPepper, len(b))
	}
	p.Old = append(p.Old, b)
	return nil
}

// HashSecret computes base64url(HMAC-SHA256(key: pepper, message: secret)).
func (p *Pepper) HashSecret(secret string) string {
	return hashWithPepper(p.Current, secret)
}

// VerifySecret checks if a secret matches a hash using current or old peppers.
func (p *Pepper) VerifySecret(secret, hash string) bool {
	// Try current pepper.
	if hashWithPepper(p.Current, secret) == hash {
		return true
	}
	// Try old peppers for rotation.
	for _, old := range p.Old {
		if hashWithPepper(old, secret) == hash {
			return true
		}
	}
	return false
}

func hashWithPepper(pepper []byte, secret string) string {
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte(secret))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// MintKey generates a new API key with a random keyId and secret.
func MintKey(pepper *Pepper) (*MintResult, error) {
	keyIDBytes := make([]byte, 16)
	if _, err := rand.Read(keyIDBytes); err != nil {
		return nil, fmt.Errorf("generate key id: %w", err)
	}
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, fmt.Errorf("generate secret: %w", err)
	}

	keyID := base64.RawURLEncoding.EncodeToString(keyIDBytes)
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	secretHash := pepper.HashSecret(secret)

	return &MintResult{
		KeyID:      keyID,
		Secret:     secret,
		FullKey:    fmt.Sprintf("sk-%s.%s", keyID, secret),
		SecretHash: secretHash,
	}, nil
}

// ParseKey parses a full key string "sk-{keyId}.{secret}" into components.
func ParseKey(fullKey string) (keyID, secret string, err error) {
	if len(fullKey) < 4 || fullKey[:3] != "sk-" {
		return "", "", ErrInvalidKey
	}
	rest := fullKey[3:]
	dotIdx := -1
	for i, c := range rest {
		if c == '.' {
			dotIdx = i
			break
		}
	}
	if dotIdx <= 0 || dotIdx == len(rest)-1 {
		return "", "", ErrInvalidKey
	}
	return rest[:dotIdx], rest[dotIdx+1:], nil
}
