// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/eunolabs/eunox/pkg/did"
)

// DIDConfig configures a DID-based identity provider.
type DIDConfig struct {
	TrustedDIDs []string
	// Resolver resolves DID documents to obtain authoritative verification keys.
	// Required. Token signatures are verified against keys listed in the resolved
	// DID document — the embedded JWK in the token header is never trusted.
	Resolver did.Resolver
}

// DIDProvider verifies DID-auth JWT presentations.
//
// Security guarantee: signature verification uses keys from the resolved DID
// document only. Any JWK embedded in the token's JOSE header is ignored. This
// prevents the CR-1 attack where an attacker embeds an arbitrary keypair in the
// header, signs the token with the matching private key, and bypasses verification.
type DIDProvider struct {
	trustedDIDs map[string]struct{}
	resolver    did.Resolver
	now         func() time.Time
}

// NewDIDProvider creates a DID-based identity provider.
// Both TrustedDIDs and Resolver are required.
func NewDIDProvider(cfg DIDConfig) (*DIDProvider, error) {
	trusted := make(map[string]struct{}, len(cfg.TrustedDIDs))
	for _, d := range cfg.TrustedDIDs {
		normalized := strings.TrimSpace(d)
		if normalized == "" {
			continue
		}
		trusted[normalized] = struct{}{}
	}
	if len(trusted) == 0 {
		return nil, errors.New("at least one trusted DID is required")
	}
	if cfg.Resolver == nil {
		return nil, errors.New("DID resolver is required")
	}

	return &DIDProvider{
		trustedDIDs: trusted,
		resolver:    cfg.Resolver,
		now:         time.Now,
	}, nil
}

// VerifyToken validates a DID-auth presentation signed by a key in the issuer's
// DID document.
//
// The verification sequence:
//  1. Parse the token (no signature check yet).
//  2. Extract the issuer DID from unverified claims.
//  3. Reject if the DID is not in the trusted-DID allowlist.
//  4. Resolve the DID document via the configured Resolver.
//  5. Verify the token signature against each verificationMethod key in the document.
//  6. Reject if no key produces a valid signature.
//  7. Validate standard claims (iat, exp, leeway).
func (p *DIDProvider) VerifyToken(ctx context.Context, token string) (*UserContext, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("token is required")
	}

	parsed, err := jwt.ParseSigned(token, supportedSignatureAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	// Read the issuer DID from unverified claims. We need it to resolve the
	// authoritative public keys before we can perform signature verification.
	// The allowlist check immediately below ensures we only resolve documents
	// for pre-approved issuers.
	var unverified struct {
		Issuer  string `json:"iss"`
		Subject string `json:"sub"`
	}
	if err := parsed.UnsafeClaimsWithoutVerification(&unverified); err != nil {
		return nil, fmt.Errorf("extract unverified issuer: %w", err)
	}

	issuerDID := strings.TrimSpace(unverified.Issuer)
	if issuerDID == "" {
		issuerDID = strings.TrimSpace(unverified.Subject)
	}
	if issuerDID == "" || !strings.HasPrefix(issuerDID, "did:") {
		return nil, errors.New("verify DID token: missing DID issuer or subject")
	}
	if _, ok := p.trustedDIDs[issuerDID]; !ok {
		return nil, fmt.Errorf("verify DID token: untrusted DID %q", issuerDID)
	}

	// Resolve the authoritative DID document. The public keys here are the only
	// keys trusted for signature verification — the token header's embedded JWK
	// (if present) is not consulted.
	doc, err := p.resolver.Resolve(ctx, issuerDID)
	if err != nil {
		return nil, fmt.Errorf("resolve DID document for %q: %w", issuerDID, err)
	}
	if len(doc.VerificationMethod) == 0 {
		return nil, fmt.Errorf("DID document for %q contains no verification methods", issuerDID)
	}

	// Try each verificationMethod key in the document. Accept the first one that
	// produces a valid signature.
	var registered jwt.Claims
	rawClaims := make(map[string]interface{})
	verified := false
	for i := range doc.VerificationMethod {
		key, extractErr := extractDIDVerificationKey(&doc.VerificationMethod[i])
		if extractErr != nil || key == nil {
			continue
		}
		var reg jwt.Claims
		raw := make(map[string]interface{})
		if claimsErr := parsed.Claims(key, &reg, &raw); claimsErr == nil {
			registered = reg
			rawClaims = raw
			verified = true
			break
		}
	}
	if !verified {
		return nil, fmt.Errorf("verify DID token: signature does not match any key in the DID document for %q", issuerDID)
	}

	if registered.IssuedAt == nil {
		return nil, errors.New("token missing issued-at claim")
	}
	if registered.Expiry == nil {
		return nil, errors.New("token missing expiry claim")
	}
	if err := registered.ValidateWithLeeway(jwt.Expected{Time: p.now()}, defaultValidationSkew); err != nil {
		return nil, fmt.Errorf("validate token claims: %w", err)
	}

	subject := registered.Subject
	if subject == "" {
		subject = issuerDID
	}

	return &UserContext{
		Subject:  subject,
		Email:    firstNonEmptyString(rawClaims, "email"),
		Name:     firstNonEmptyString(rawClaims, "name"),
		Roles:    uniqueStrings(stringsFromClaim(rawClaims, "roles")),
		TenantID: firstNonEmptyString(rawClaims, "tenant_id"),
		Provider: string(ProviderTypeDID),
		Claims:   rawClaims,
	}, nil
}

// extractDIDVerificationKey converts a DID VerificationMethod to a usable
// crypto.PublicKey by delegating JWK parsing to go-jose. This supports all
// key types that go-jose understands (RSA, EC P-256/P-384/P-521, OKP Ed25519).
func extractDIDVerificationKey(vm *did.VerificationMethod) (interface{}, error) {
	if vm.PublicKeyJwk != nil {
		// Marshal the did.JWK to JSON and let go-jose parse it. This approach
		// handles all JWK key types without duplicating go-jose's parsing logic.
		jwkJSON, err := json.Marshal(vm.PublicKeyJwk)
		if err != nil {
			return nil, fmt.Errorf("marshal verification method JWK: %w", err)
		}
		var jwk jose.JSONWebKey
		if err := json.Unmarshal(jwkJSON, &jwk); err != nil {
			return nil, fmt.Errorf("parse verification method JWK: %w", err)
		}
		if jwk.Key == nil {
			return nil, errors.New("empty key in verification method JWK")
		}
		return jwk.Key, nil
	}
	if vm.PublicKeyMultibase != "" {
		return vm.ExtractPublicKey()
	}
	return nil, errors.New("verification method has no usable public key material")
}

var _ Provider = (*DIDProvider)(nil)
var _ Provider = (*OIDCProvider)(nil)
