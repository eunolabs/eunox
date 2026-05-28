// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/eunolabs/eunox/pkg/capability"
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

// verifyDPoP verifies a DPoP proof against the token's confirmation claim and
// records the proof's JTI for replay detection (RFC 9449 §11.1).
//
// Replay protection uses the `jti` claim extracted from the proof JWT, not a
// hash of the full proof.  A hash of proof+method+URL incorrectly allows the
// same DPoP JWT to be replayed to a different URL (different hash = treated as
// new proof).  RFC 9449 requires `jti` to be unique and stored independently
// of the target URL.
func (app *App) verifyDPoP(ctx context.Context, dpop *capability.DPoPProof, claims *capability.TokenPayload) error {
	if dpop.Proof == "" {
		return errors.New("empty DPoP proof")
	}

	if dpop.HTTPMethod == "" || dpop.HTTPURL == "" {
		return errors.New("DPoP proof must include httpMethod and httpUrl")
	}

	// If the token has a confirmation claim with JKT, perform full binding
	// verification (signature + thumbprint + htm/htu + iat).
	if claims.Confirmation != nil && claims.Confirmation.JKT != "" {
		if err := verifyDPoPBinding(dpop.Proof, claims.Confirmation.JKT, dpop.HTTPMethod, dpop.HTTPURL); err != nil {
			return err
		}
	}

	// Replay protection: store the proof's JTI claim, not a hash of the full
	// proof.  This prevents the B-4 attack where the same DPoP JWT is replayed
	// to a different URL (which would produce a different hash).
	if app.dpopStore != nil {
		jti, err := parseDPoPJTI(dpop.Proof)
		if err != nil {
			return fmt.Errorf("DPoP replay check: cannot extract jti from proof: %w", err)
		}
		if jti == "" {
			return errors.New("DPoP proof missing required jti claim")
		}
		alreadyUsed, err := app.dpopStore.MarkUsed(ctx, jti)
		if err != nil {
			return fmt.Errorf("DPoP replay check error: %w", err)
		}
		if alreadyUsed {
			return errors.New("DPoP proof replay detected")
		}
	}

	return nil
}

// parseDPoPJTI decodes the payload of a DPoP proof JWT and returns the jti
// claim.  The signature is NOT verified here — when a token carries a JKT
// confirmation claim, verifyDPoPBinding has already verified it before this
// function is called.  When there is no JKT (unbound DPoP), signature
// verification is skipped entirely and replay detection via jti is the only
// protection; jti extraction is still valid in that case because we are only
// reading a public claim from the payload, not trusting it for authentication.
func parseDPoPJTI(proofJWT string) (string, error) {
	parts := strings.Split(proofJWT, ".")
	if len(parts) != 3 {
		return "", errors.New("DPoP proof is not a valid JWT (expected 3 parts)")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("DPoP proof payload decode error: %w", err)
	}
	var payload struct {
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return "", fmt.Errorf("DPoP proof payload parse error: %w", err)
	}
	return payload.JTI, nil
}
