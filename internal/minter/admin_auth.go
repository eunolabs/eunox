// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package minter

import (
	"context"
	"crypto/subtle"
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

// AdminAuthenticator validates admin credentials from request headers.
type AdminAuthenticator interface {
	// Authenticate extracts and validates admin identity from the request.
	// Returns the operator ID or an error.
	Authenticate(ctx context.Context, r *http.Request) (operatorID string, err error)
}

// AdminJWTVerifier validates admin JWTs against a JWKS endpoint.
type AdminJWTVerifier struct {
	jwksURI  string
	audience string
	client   *http.Client
	logger   *slog.Logger

	mu   sync.RWMutex
	jwks *jose.JSONWebKeySet
	// fetchedAt tracks when JWKS was last fetched for cache invalidation.
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURI, http.NoBody) //nolint:gosec // G704: JWKS URI is operator-configured, not user-controlled
	if err != nil {
		return nil, err
	}

	resp, err := v.client.Do(req) //nolint:gosec // G704: JWKS URI is operator-configured, not user-controlled
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

// CombinedAdminAuth supports JWT-based auth (primary) with X-Admin-Key fallback (deprecated).
type CombinedAdminAuth struct {
	jwtVerifier *AdminJWTVerifier
	adminKey    string
	logger      *slog.Logger
}

// CombinedAdminAuthConfig configures the combined authenticator.
type CombinedAdminAuthConfig struct {
	JWTVerifier *AdminJWTVerifier // nil if JWT auth is not configured.
	AdminKey    string            // Static admin API key (deprecated fallback).
	Logger      *slog.Logger
}

// NewCombinedAdminAuth creates a combined authenticator with JWT + API key fallback.
func NewCombinedAdminAuth(cfg CombinedAdminAuthConfig) *CombinedAdminAuth {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &CombinedAdminAuth{
		jwtVerifier: cfg.JWTVerifier,
		adminKey:    cfg.AdminKey,
		logger:      cfg.Logger,
	}
}

// Authenticate checks Authorization: ****** first, then X-Admin-Key fallback.
func (a *CombinedAdminAuth) Authenticate(ctx context.Context, r *http.Request) (string, error) {
	// Try JWT first (primary path).
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if a.jwtVerifier != nil {
			operatorID, err := a.jwtVerifier.Verify(ctx, token)
			if err != nil {
				return "", fmt.Errorf("%w: JWT verification failed: %v", ErrUnauthorized, err)
			}
			return operatorID, nil
		}
		return "", fmt.Errorf("%w: JWT auth not configured", ErrUnauthorized)
	}

	// Fallback to X-Admin-Key (deprecated).
	apiKey := r.Header.Get("X-Admin-Key")
	if apiKey == "" {
		apiKey = r.Header.Get("X-Admin-Api-Key")
	}
	if apiKey != "" {
		if a.adminKey == "" {
			return "", fmt.Errorf("%w: admin key not configured", ErrUnauthorized)
		}
		if subtle.ConstantTimeCompare([]byte(apiKey), []byte(a.adminKey)) != 1 {
			return "", fmt.Errorf("%w: invalid admin key", ErrUnauthorized)
		}
		a.logger.WarnContext(ctx, "admin authenticated via deprecated X-Admin-Key header; migrate to JWT",
			"method", r.Method,
			"path", r.URL.Path,
		)
		return "admin-key-user", nil
	}

	return "", fmt.Errorf("%w: no credentials provided", ErrUnauthorized)
}
