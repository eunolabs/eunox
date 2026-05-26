// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package circuitbreaker

import (
	"context"
)

// Signer is a minimal interface for signing operations, compatible with
// pkg/crypto.Signer but without importing it (avoids circular deps).
type Signer interface {
	Sign(ctx context.Context, digest []byte) ([]byte, error)
	Algorithm() string
	KeyID() string
}

// ProtectedSigner wraps a Signer with circuit breaker protection.
// When the breaker is open, Sign returns ErrOpen immediately without calling
// the underlying signer—useful for KMS calls that may hang or fail repeatedly.
type ProtectedSigner struct {
	inner   Signer
	breaker *Breaker
}

// NewProtectedSigner wraps a Signer with the given circuit breaker.
func NewProtectedSigner(inner Signer, breaker *Breaker) *ProtectedSigner {
	if inner == nil {
		panic("circuitbreaker: signer must not be nil")
	}
	if breaker == nil {
		panic("circuitbreaker: breaker must not be nil")
	}
	return &ProtectedSigner{inner: inner, breaker: breaker}
}

// Sign delegates to the inner signer, guarded by the circuit breaker.
func (ps *ProtectedSigner) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	return Do(ctx, ps.breaker, func(ctx context.Context) ([]byte, error) {
		return ps.inner.Sign(ctx, digest)
	})
}

// Algorithm returns the inner signer's algorithm.
func (ps *ProtectedSigner) Algorithm() string { return ps.inner.Algorithm() }

// KeyID returns the inner signer's key identifier.
func (ps *ProtectedSigner) KeyID() string { return ps.inner.KeyID() }
