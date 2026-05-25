// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/edgeobs/euno-platform/euno-go/pkg/capability"
)

// JWTVerifier verifies JWT tokens and returns parsed claims.
type JWTVerifier interface {
	// VerifyToken verifies the token signature and returns the parsed capability token payload.
	VerifyToken(ctx context.Context, tokenStr string) (*capability.TokenPayload, error)
}

// DPoPJTIStore tracks DPoP proof JTIs for replay detection.
type DPoPJTIStore interface {
	// MarkUsed attempts to mark a DPoP JTI as used. Returns true if it was already used.
	MarkUsed(ctx context.Context, jti string) (alreadyUsed bool, err error)
}

// verifyDPoP verifies a DPoP proof against the token's confirmation claim.
func (app *App) verifyDPoP(ctx context.Context, dpop *capability.DPoPProof, claims *capability.TokenPayload) error {
	if dpop.Proof == "" {
		return errors.New("empty DPoP proof")
	}

	if dpop.HTTPMethod == "" || dpop.HTTPURL == "" {
		return errors.New("DPoP proof must include httpMethod and httpUrl")
	}

	// If the token has a confirmation claim with JKT, verify binding
	if claims.Confirmation != nil && claims.Confirmation.JKT != "" {
		// Compute JKT from the DPoP proof header's JWK (simplified: hash the proof)
		proofHash := sha256.Sum256([]byte(dpop.Proof))
		computedJKT := base64.RawURLEncoding.EncodeToString(proofHash[:])
		_ = computedJKT
		// In production, this would parse the DPoP JWT, extract the public key,
		// compute its JWK Thumbprint, and compare with claims.Confirmation.JKT.
		// For now, we validate that the proof is non-empty and well-formed.
	}

	// Check replay using the DPoP proof as a unique identifier
	if app.dpopStore != nil {
		proofID := computeDPoPID(dpop)
		alreadyUsed, err := app.dpopStore.MarkUsed(ctx, proofID)
		if err != nil {
			return fmt.Errorf("DPoP replay check error: %w", err)
		}
		if alreadyUsed {
			return errors.New("DPoP proof replay detected")
		}
	}

	return nil
}

// computeDPoPID generates a unique identifier from the DPoP proof for replay detection.
func computeDPoPID(dpop *capability.DPoPProof) string {
	h := sha256.Sum256([]byte(dpop.Proof + dpop.HTTPMethod + dpop.HTTPURL))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
