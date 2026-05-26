// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// AdminJWTVerifier validates admin JWTs against a JWKS endpoint.
type AdminJWTVerifier struct {
	jwksURI  string
	audience string
	client   *http.Client
	logger   *slog.Logger

	mu        sync.RWMutex
	jwks      *jose.JSONWebKeySet
	fetchedAt time.Time
	cacheTTL  time.Duration
}

// AdminJWTVerifierConfig configures the AdminJWTVerifier.
type AdminJWTVerifierConfig struct {
	JWKSURI  string
	Audience string
	CacheTTL time.Duration
	Client   *http.Client
	Logger   *slog.Logger
}

// NewAdminJWTVerifier creates an admin JWT verifier that validates tokens against a JWKS endpoint.
func NewAdminJWTVerifier(cfg AdminJWTVerifierConfig) *AdminJWTVerifier {
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 5 * time.Minute
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &AdminJWTVerifier{
		jwksURI:  cfg.JWKSURI,
		audience: cfg.Audience,
		client:   cfg.Client,
		logger:   cfg.Logger,
		cacheTTL: cfg.CacheTTL,
	}
}

// Verify validates a JWT string and returns the subject (operator ID).
func (v *AdminJWTVerifier) Verify(ctx context.Context, tokenStr string) (string, error) {
	tok, err := jwt.ParseSigned(tokenStr, []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512,
		jose.ES256, jose.ES384, jose.ES512,
		jose.PS256, jose.PS384, jose.PS512,
		jose.EdDSA,
	})
	if err != nil {
		return "", fmt.Errorf("parse JWT: %w", err)
	}

	keys, err := v.getKeys(ctx)
	if err != nil {
		return "", fmt.Errorf("fetch JWKS: %w", err)
	}

	// Find matching key by kid.
	headers := tok.Headers
	if len(headers) == 0 {
		return "", errors.New("JWT has no headers")
	}
	kid := headers[0].KeyID

	matchingKeys := keys.Key(kid)
	if len(matchingKeys) == 0 {
		// Refresh JWKS in case of key rotation.
		keys, err = v.refreshKeys(ctx)
		if err != nil {
			return "", fmt.Errorf("refresh JWKS: %w", err)
		}
		matchingKeys = keys.Key(kid)
		if len(matchingKeys) == 0 {
			return "", fmt.Errorf("no matching key for kid %q", kid)
		}
	}

	var claims jwt.Claims
	if err := tok.Claims(matchingKeys[0], &claims); err != nil {
		return "", fmt.Errorf("verify signature: %w", err)
	}

	// Validate standard claims.
	expected := jwt.Expected{
		Time: time.Now(),
	}
	if v.audience != "" {
		expected.AnyAudience = []string{v.audience}
	}
	if err := claims.Validate(expected); err != nil {
		return "", fmt.Errorf("validate claims: %w", err)
	}

	if claims.Subject == "" {
		return "", errors.New("JWT missing sub claim")
	}

	return claims.Subject, nil
}

func (v *AdminJWTVerifier) getKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
	v.mu.RLock()
	if v.jwks != nil && time.Since(v.fetchedAt) < v.cacheTTL {
		keys := v.jwks
		v.mu.RUnlock()
		return keys, nil
	}
	v.mu.RUnlock()
	return v.refreshKeys(ctx)
}

func (v *AdminJWTVerifier) refreshKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Double-check after acquiring write lock.
	if v.jwks != nil && time.Since(v.fetchedAt) < v.cacheTTL {
		return v.jwks, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURI, nil)
	if err != nil {
		return nil, err
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // Best-effort close on HTTP response body.

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}

	v.jwks = &jwks
	v.fetchedAt = time.Now()
	return &jwks, nil
}

// CombinedAdminAuth supports JWT-based auth (primary) with static key fallback (deprecated).
// Implements AdminAuthenticator interface.
type CombinedAdminAuth struct {
	jwtVerifier *AdminJWTVerifier
	staticAuth  *StaticKeyAdminAuth
	tenantID    string
	logger      *slog.Logger
}

// CombinedAdminAuthConfig configures the combined admin authenticator.
type CombinedAdminAuthConfig struct {
	// JWKSURI is the JWKS endpoint for admin JWT verification (optional).
	JWKSURI string
	// JWTAudience is the expected audience in admin JWTs.
	JWTAudience string
	// AdminKey is the static admin API key (deprecated fallback).
	AdminKey string
	// TenantID is the tenant scope for admin operations.
	TenantID string
	// Logger for audit/warning messages.
	Logger *slog.Logger
}

// NewCombinedAdminAuth creates a combined admin authenticator with JWT + static key fallback.
func NewCombinedAdminAuth(cfg CombinedAdminAuthConfig) *CombinedAdminAuth {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	auth := &CombinedAdminAuth{
		tenantID: cfg.TenantID,
		logger:   cfg.Logger,
	}

	if cfg.JWKSURI != "" {
		auth.jwtVerifier = NewAdminJWTVerifier(AdminJWTVerifierConfig{
			JWKSURI:  cfg.JWKSURI,
			Audience: cfg.JWTAudience,
			Logger:   cfg.Logger,
		})
	}

	if cfg.AdminKey != "" {
		auth.staticAuth = NewStaticKeyAdminAuth(cfg.AdminKey, cfg.TenantID, cfg.Logger)
	}

	return auth
}

// Authenticate checks the Authorization header for a Bearer <token> (JWT) first,
// then falls back to X-Admin-Api-Key (deprecated static key).
func (a *CombinedAdminAuth) Authenticate(ctx context.Context, r *http.Request) (*AdminIdentity, error) {
	// Try JWT first (primary path).
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if a.jwtVerifier == nil {
			return nil, fmt.Errorf("%w: JWT auth not configured", ErrAdminUnauthorized)
		}
		operatorID, err := a.jwtVerifier.Verify(ctx, token)
		if err != nil {
			return nil, fmt.Errorf("%w: JWT verification failed: %v", ErrAdminUnauthorized, err)
		}
		return &AdminIdentity{
			OperatorID: operatorID,
			TenantID:   a.tenantID,
		}, nil
	}

	// Fallback to static key (deprecated).
	headerName := "X-Admin-Api-Key"
	apiKey := r.Header.Get("X-Admin-Api-Key")
	if apiKey == "" {
		headerName = "X-Admin-Key"
		apiKey = r.Header.Get("X-Admin-Key")
	}
	if apiKey != "" {
		if a.staticAuth == nil {
			return nil, fmt.Errorf("%w: admin key not configured", ErrAdminUnauthorized)
		}
		identity, err := a.staticAuth.Authenticate(ctx, r)
		if err != nil {
			return nil, err
		}
		a.logger.WarnContext(ctx, "admin authenticated via deprecated static admin key; migrate to JWT",
			"header", headerName,
			"method", r.Method,
			"path", r.URL.Path,
		)
		return identity, nil
	}

	return nil, fmt.Errorf("%w: no admin credentials provided", ErrAdminUnauthorized)
}
