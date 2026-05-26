// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package capability

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// JWKSClientConfig configures a JWKS-based token verifier.
type JWKSClientConfig struct {
	// JWKSURL is the endpoint serving the issuer's JSON Web Key Set.
	JWKSURL string
	// Audience is the expected audience in the token (optional).
	Audience string
	// RequireKID requires the JWT header to contain a kid for key selection.
	RequireKID bool
	// CacheTTL is how long JWKS responses are cached. Default: 5 minutes.
	CacheTTL time.Duration
	// Client is the HTTP client for JWKS fetching. Default: 10s timeout.
	Client *http.Client
	// Logger for operational messages.
	Logger *slog.Logger
}

// JWKSClient fetches and caches a JWKS and provides capability token verification.
type JWKSClient struct {
	jwksURI    string
	audience   string
	requireKID bool
	client     *http.Client
	logger     *slog.Logger

	mu        sync.RWMutex
	jwks      *jose.JSONWebKeySet
	fetchedAt time.Time
	cacheTTL  time.Duration
}

// NewJWKSClient creates a new JWKS client for verifying capability tokens.
func NewJWKSClient(cfg JWKSClientConfig) *JWKSClient {
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 5 * time.Minute
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &JWKSClient{
		jwksURI:    cfg.JWKSURL,
		audience:   cfg.Audience,
		requireKID: cfg.RequireKID,
		client:     cfg.Client,
		logger:     cfg.Logger,
		cacheTTL:   cfg.CacheTTL,
	}
}

// jwksAlgorithms lists all algorithms accepted for capability tokens.
var jwksAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

// VerifyToken verifies a capability token's signature and standard claims, returning the parsed payload.
func (c *JWKSClient) VerifyToken(ctx context.Context, tokenStr string) (*TokenPayload, error) {
	tok, err := jwt.ParseSigned(tokenStr, jwksAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("parse JWT: %w", err)
	}

	headers := tok.Headers
	if len(headers) == 0 {
		return nil, fmt.Errorf("JWT has no headers")
	}

	kid := headers[0].KeyID
	if c.requireKID && kid == "" {
		return nil, fmt.Errorf("JWT missing required kid header")
	}

	keys, err := c.getKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}

	matchingKeys := c.findKeys(keys, kid)
	if len(matchingKeys) == 0 {
		keys, err = c.refreshKeys(ctx)
		if err != nil {
			return nil, fmt.Errorf("refresh JWKS: %w", err)
		}
		matchingKeys = c.findKeys(keys, kid)
		if len(matchingKeys) == 0 {
			return nil, fmt.Errorf("no matching key for kid %q", kid)
		}
	}

	var lastErr error
	for i := range matchingKeys {
		var claims jwt.Claims
		var payload TokenPayload

		if err := tok.Claims(&matchingKeys[i], &claims, &payload); err != nil {
			lastErr = err
			continue
		}

		if claims.IssuedAt == nil {
			return nil, fmt.Errorf("validate claims: token missing iat claim")
		}
		if claims.Expiry == nil {
			return nil, fmt.Errorf("validate claims: token missing exp claim")
		}
		if claims.Subject == "" {
			return nil, fmt.Errorf("validate claims: token missing sub claim")
		}

		expected := jwt.Expected{
			Time: time.Now(),
		}
		if c.audience != "" {
			expected.AnyAudience = []string{c.audience}
		}
		if err := claims.ValidateWithLeeway(expected, time.Minute); err != nil {
			return nil, fmt.Errorf("validate claims: %w", err)
		}

		if payload.Issuer == "" {
			payload.Issuer = claims.Issuer
		}
		if payload.Subject == "" {
			payload.Subject = claims.Subject
		}
		if payload.JWTID == "" {
			payload.JWTID = claims.ID
		}
		if payload.IssuedAt == 0 && claims.IssuedAt != nil {
			payload.IssuedAt = claims.IssuedAt.Time().Unix()
		}
		if payload.ExpiresAt == 0 && claims.Expiry != nil {
			payload.ExpiresAt = claims.Expiry.Time().Unix()
		}
		if payload.Audience == "" && len(claims.Audience) > 0 {
			payload.Audience = claims.Audience[0]
		}

		return &payload, nil
	}

	return nil, fmt.Errorf("verify signature: %w", lastErr)
}

func (c *JWKSClient) findKeys(jwks *jose.JSONWebKeySet, kid string) []jose.JSONWebKey {
	if kid != "" {
		return jwks.Key(kid)
	}
	return jwks.Keys
}

func (c *JWKSClient) getKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
	c.mu.RLock()
	if c.jwks != nil && time.Since(c.fetchedAt) < c.cacheTTL {
		keys := c.jwks
		c.mu.RUnlock()
		return keys, nil
	}
	c.mu.RUnlock()
	return c.refreshKeys(ctx)
}

func (c *JWKSClient) refreshKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.jwks != nil && time.Since(c.fetchedAt) < c.cacheTTL {
		return c.jwks, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.jwksURI, http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("JWKS request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read JWKS body: %w", err)
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}

	c.jwks = &jwks
	c.fetchedAt = time.Now()
	c.logger.Info("refreshed JWKS", slog.Int("keys", len(jwks.Keys)))
	return &jwks, nil
}
