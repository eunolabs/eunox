// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

// Package revocation provides token revocation checking and management.
package revocation

import (
	"context"
	"time"
)

// Store manages token revocation state.
type Store interface {
	// IsRevoked checks if a token (by its JTI) has been revoked.
	IsRevoked(ctx context.Context, jti string) (bool, error)

	// Revoke marks a token as revoked with an optional TTL.
	// If ttl is zero, the revocation persists indefinitely.
	Revoke(ctx context.Context, jti string, ttl time.Duration) error
}
