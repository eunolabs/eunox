// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package capability

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/eunolabs/eunox/pkg/circuitbreaker"
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
	// Breaker optionally protects JWKS refreshes from repeated upstream failures.
	Breaker *circuitbreaker.Breaker
}

// JWKSClient fetches and caches a JWKS and provides capability token verification.
type JWKSClient struct {
	jwksURI    string
	audience   string
	requireKID bool
	client     *http.Client
	logger     *slog.Logger
	breaker    *circuitbreaker.Breaker

	mu        sync.RWMutex
	jwks      *jose.JSONWebKeySet
	fetchedAt time.Time
	cacheTTL  time.Duration

	// sfGroup deduplicates concurrent JWKS refresh calls so that only one
	// HTTP round-trip is in flight at any time. I-3 fix: previously the write
	// lock was held for the entire fetch, serialising all token verifications
	// behind a single HTTP round-trip and causing P99 spikes on cache misses.
	sfGroup singleflight.Group
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
	client := &JWKSClient{
		jwksURI:    cfg.JWKSURL,
		audience:   cfg.Audience,
		requireKID: cfg.RequireKID,
		client:     cfg.Client,
		logger:     cfg.Logger,
		breaker:    cfg.Breaker,
		cacheTTL:   cfg.CacheTTL,
	}
	if cfg.Audience == "" {
		// H-6: Audience should always be set. Without it, tokens whose aud claim
		// is non-empty will be rejected (fail-closed), but a misconfigured gateway
		// accepting any empty-audience token is also insecure. Set GATEWAY_AUDIENCE.
		cfg.Logger.Warn("JWKSClient created without an Audience; all tokens with a non-empty aud claim will be rejected")
	}
	return client
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

		// H-6 fix: always set AnyAudience so that an unconfigured (empty) audience
		// causes all tokens to fail — fail-closed rather than accepting tokens for
		// any audience. When audience is empty the expected set is [""], which will
		// only match tokens whose aud claim is also ""; a real token with aud set to
		// a service name is rejected, preventing cross-audience replay.
		// NewJWKSClient logs a warning when audience is empty.
		expected := jwt.Expected{
			Time:        time.Now(),
			AnyAudience: []string{c.audience},
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

// refreshKeys fetches a fresh JWKS and stores it in the cache.
//
// I-3 fix: the write lock is no longer held during the HTTP fetch. Instead,
// a singleflight group ensures that only one fetch is in flight at any time;
// concurrent callers block on the group (not on c.mu) and share the result.
// The write lock is held only for the brief store-result step.
func (c *JWKSClient) refreshKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
	// Double-check under read lock: another goroutine may have refreshed while
	// we were waiting for the singleflight or after getKeys released the read lock.
	c.mu.RLock()
	if c.jwks != nil && time.Since(c.fetchedAt) < c.cacheTTL {
		keys := c.jwks
		c.mu.RUnlock()
		return keys, nil
	}
	c.mu.RUnlock()

	// Use singleflight to deduplicate concurrent fetches. All callers waiting
	// for the same refresh receive the same result without additional HTTP
	// round-trips. The context passed here is the first caller's — subsequent
	// callers share the result even if their context differs.
	v, err, _ := c.sfGroup.Do("refresh", func() (interface{}, error) {
		fetch := func(fetchCtx context.Context) (*jose.JSONWebKeySet, error) {
			return c.fetchKeys(fetchCtx)
		}

		var (
			jwks *jose.JSONWebKeySet
			ferr error
		)
		if c.breaker != nil {
			jwks, ferr = circuitbreaker.Do(ctx, c.breaker, fetch)
			if ferr != nil {
				if errors.Is(ferr, circuitbreaker.ErrOpen) {
					return nil, fmt.Errorf("JWKS fetch blocked by circuit breaker: %w", ferr)
				}
				return nil, ferr
			}
		} else {
			jwks, ferr = fetch(ctx)
			if ferr != nil {
				return nil, ferr
			}
		}
		return jwks, nil
	})
	if err != nil {
		return nil, err
	}

	jwks := v.(*jose.JSONWebKeySet)

	// Store the freshly fetched JWKS under a short write lock.
	c.mu.Lock()
	c.jwks = jwks
	c.fetchedAt = time.Now()
	c.mu.Unlock()

	c.logger.Info("refreshed JWKS", slog.Int("keys", len(jwks.Keys)))
	return jwks, nil
}

func (c *JWKSClient) fetchKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
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
	return &jwks, nil
}
