// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
)

// DIDConfig configures a DID-based identity provider.
type DIDConfig struct {
	TrustedDIDs []string
}

// DIDProvider verifies simplified DID-auth JWT presentations.
type DIDProvider struct {
	trustedDIDs map[string]struct{}
	now         func() time.Time
}

// NewDIDProvider creates a DID-based identity provider.
func NewDIDProvider(cfg DIDConfig) (*DIDProvider, error) {
	trusted := make(map[string]struct{}, len(cfg.TrustedDIDs))
	for _, did := range cfg.TrustedDIDs {
		normalized := strings.TrimSpace(did)
		if normalized == "" {
			continue
		}
		trusted[normalized] = struct{}{}
	}
	if len(trusted) == 0 {
		return nil, errors.New("at least one trusted DID is required")
	}

	return &DIDProvider{
		trustedDIDs: trusted,
		now:         time.Now,
	}, nil
}

// VerifyToken validates a DID-auth presentation signed by the DID's embedded JWK.
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
	if len(parsed.Headers) == 0 {
		return nil, errors.New("parse token: missing JOSE headers")
	}

	header := parsed.Headers[0]
	if header.JSONWebKey == nil || !header.JSONWebKey.Valid() {
		return nil, errors.New("verify DID token: missing valid embedded JWK")
	}

	var registered jwt.Claims
	rawClaims := make(map[string]interface{})
	if err := parsed.Claims(header.JSONWebKey.Key, &registered, &rawClaims); err != nil {
		return nil, fmt.Errorf("verify DID token signature: %w", err)
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

	did := strings.TrimSpace(registered.Issuer)
	if did == "" {
		did = strings.TrimSpace(registered.Subject)
	}
	if did == "" || !strings.HasPrefix(did, "did:") {
		return nil, errors.New("verify DID token: missing DID issuer or subject")
	}
	if _, ok := p.trustedDIDs[did]; !ok {
		return nil, fmt.Errorf("verify DID token: untrusted DID %q", did)
	}

	subject := registered.Subject
	if subject == "" {
		subject = did
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

var _ Provider = (*DIDProvider)(nil)
var _ Provider = (*OIDCProvider)(nil)
