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

	// If the token has a confirmation claim with JKT, verify binding.
	// Full DPoP JWT parsing and JWK thumbprint comparison is required for
	// proper binding verification; fail closed rather than silently skipping.
	if claims.Confirmation != nil && claims.Confirmation.JKT != "" {
		return errors.New("DPoP token binding (JKT) verification is not supported; request denied")
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
// Each field is length-prefixed to avoid hash collisions from field concatenation.
func computeDPoPID(dpop *capability.DPoPProof) string {
	input := fmt.Sprintf("%d:%s|%d:%s|%d:%s",
		len(dpop.Proof), dpop.Proof,
		len(dpop.HTTPMethod), dpop.HTTPMethod,
		len(dpop.HTTPURL), dpop.HTTPURL,
	)
	h := sha256.Sum256([]byte(input))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
