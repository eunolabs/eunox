// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/eunolabs/eunox/pkg/capability"
	"github.com/eunolabs/eunox/pkg/federation"
)

// PartnerTokenVerifier verifies JWT tokens issued by trusted partner organizations.
// When the token carries a non-empty Proofs.Signatures field, ALL co-signatures are
// verified against each co-issuer's resolved public keys before the token is accepted.
type PartnerTokenVerifier struct {
	resolver      *federation.PartnerIssuerResolver
	coSigResolver capability.PublicKeyResolver
	audience      string
	now           func() time.Time
}

// PartnerTokenVerifierConfig configures the PartnerTokenVerifier.
type PartnerTokenVerifierConfig struct {
	Resolver *federation.PartnerIssuerResolver
	Audience string
	// CoSignatureResolver resolves public keys for co-signature verification.
	// When nil, Resolver is used — co-signers must therefore be approved partners in the
	// same federation registry. Provide an alternative resolver only when co-signers
	// should be permitted outside the approved partner list.
	CoSignatureResolver capability.PublicKeyResolver
}

// NewPartnerTokenVerifier creates a verifier for partner-issued tokens.
func NewPartnerTokenVerifier(cfg PartnerTokenVerifierConfig) *PartnerTokenVerifier {
	coSig := cfg.CoSignatureResolver
	if coSig == nil {
		coSig = cfg.Resolver // default: co-signers must be approved partners
	}
	return &PartnerTokenVerifier{
		resolver:      cfg.Resolver,
		coSigResolver: coSig,
		audience:      cfg.Audience,
		now:           time.Now,
	}
}

// PartnerVerifyResult contains the result of partner token verification.
type PartnerVerifyResult struct {
	Claims     *capability.TokenPayload
	PartnerDID string
	CrossOrg   bool
}

// VerifyPartnerToken verifies a JWT token that was issued by a trusted partner.
func (v *PartnerTokenVerifier) VerifyPartnerToken(ctx context.Context, tokenStr string) (*PartnerVerifyResult, error) {
	tok, err := jwt.ParseSigned(tokenStr, []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512,
		jose.ES256, jose.ES384, jose.ES512,
		jose.PS256, jose.PS384, jose.PS512,
		jose.EdDSA,
	})
	if err != nil {
		return nil, fmt.Errorf("parse partner token: %w", err)
	}

	if len(tok.Headers) == 0 {
		return nil, errors.New("partner token has no headers")
	}

	// Extract issuer from unverified claims to determine which DID to resolve.
	var rawClaims json.RawMessage
	if err := tok.UnsafeClaimsWithoutVerification(&rawClaims); err != nil {
		return nil, fmt.Errorf("extract unverified claims: %w", err)
	}

	var peek struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(rawClaims, &peek); err != nil {
		return nil, fmt.Errorf("parse issuer from claims: %w", err)
	}

	if !strings.HasPrefix(peek.Issuer, "did:") {
		return nil, fmt.Errorf("partner token issuer is not a DID: %q", peek.Issuer)
	}

	// Resolve the partner DID to get public keys.
	publicKeys, err := v.resolver.ResolvePublicKeys(ctx, peek.Issuer)
	if err != nil {
		return nil, fmt.Errorf("resolve partner issuer: %w", err)
	}

	// Try each resolved key until one verifies.
	var verifyErr error
	for _, pk := range publicKeys {
		var claims capability.TokenPayload
		if err := tok.Claims(pk, &claims); err != nil {
			verifyErr = err
			continue
		}

		// Validate standard JWT claims.
		now := v.now()
		if claims.ExpiresAt > 0 && now.Unix() >= claims.ExpiresAt {
			return nil, errors.New("partner token has expired")
		}
		if claims.IssuedAt > 0 && now.Unix() < claims.IssuedAt-300 {
			return nil, errors.New("partner token issued in the future")
		}
		if v.audience != "" {
			if claims.Audience == "" {
				return nil, errors.New("partner token audience missing")
			}
			if claims.Audience != v.audience {
				return nil, fmt.Errorf("partner token audience mismatch: got %q, want %q", claims.Audience, v.audience)
			}
		}

		// Verify co-signatures before accepting the token.
		// When Proofs.Signatures is non-empty, ALL entries must pass; if co-signature
		// verification fails, the whole token is rejected regardless of primary-issuer validity.
		if err := capability.VerifyCoSignatures(ctx, tokenStr, claims.Proofs, v.coSigResolver); err != nil {
			return nil, fmt.Errorf("co-signature verification: %w", err)
		}

		return &PartnerVerifyResult{
			Claims:     &claims,
			PartnerDID: peek.Issuer,
			CrossOrg:   true,
		}, nil
	}

	if verifyErr != nil {
		return nil, fmt.Errorf("partner token signature verification failed: %w", verifyErr)
	}
	return nil, errors.New("partner token could not be verified with any resolved key")
}

// MultiIssuerVerifier combines local JWT verification with partner DID verification.
type MultiIssuerVerifier struct {
	local   JWTVerifier
	partner *PartnerTokenVerifier
}

// MultiIssuerVerifierConfig configures the MultiIssuerVerifier.
type MultiIssuerVerifierConfig struct {
	LocalVerifier   JWTVerifier
	PartnerVerifier *PartnerTokenVerifier
}

// NewMultiIssuerVerifier creates a JWT verifier that supports both local and partner-issued tokens.
func NewMultiIssuerVerifier(cfg MultiIssuerVerifierConfig) *MultiIssuerVerifier {
	return &MultiIssuerVerifier{
		local:   cfg.LocalVerifier,
		partner: cfg.PartnerVerifier,
	}
}

// VerifyToken attempts local verification first, then falls back to partner verification.
// Returns the token payload and enriches it with cross-org metadata if from a partner.
func (v *MultiIssuerVerifier) VerifyToken(ctx context.Context, tokenStr string) (*capability.TokenPayload, error) {
	// Try local verification first when configured.
	var err error
	if v.local != nil {
		claims, localErr := v.local.VerifyToken(ctx, tokenStr)
		if localErr == nil {
			return claims, nil
		}
		err = localErr
	} else {
		err = errors.New("local JWT verifier not configured")
	}

	// If partner verifier is not configured, return the local error.
	if v.partner == nil {
		return nil, err
	}

	// Try partner verification.
	result, partnerErr := v.partner.VerifyPartnerToken(ctx, tokenStr)
	if partnerErr != nil {
		// Return the original local error as it's more likely the intended path.
		return nil, fmt.Errorf("local: %w; partner: %v", err, partnerErr)
	}

	return result.Claims, nil
}
