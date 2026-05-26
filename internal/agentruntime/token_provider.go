// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package agentruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/edgeobs/eunox/pkg/circuitbreaker"
)

// AuthTokenProvider acquires and refreshes capability tokens from the issuer.
// It implements proactive token refresh before expiry and caches the current token.
//
// Resilience features (CR-3):
//   - Circuit breaker protection against failing token endpoints
//   - Jitter on refresh intervals to prevent thundering herd on restart
//   - Stale-token grace period: serves last-known-good token during transient refresh failures
type AuthTokenProvider struct {
	mu sync.RWMutex

	issuerURL     string
	httpClient    HTTPClient
	dpop          *DPoPProofGenerator
	hintsProvider IssuanceHintsProvider
	retryConfig   RetryConfig
	refreshBefore time.Duration
	logger        *slog.Logger

	// Circuit breaker for token refresh (CR-3).
	breaker *circuitbreaker.Breaker
	// StaleGracePeriod is how long to serve a cached token after refresh failure.
	// Default: 60s.
	staleGracePeriod time.Duration

	// Mutable state
	identityToken         string
	identityTokenProvider func(ctx context.Context) (string, error)
	cachedToken           *TokenResponse
	refreshTimer          *time.Timer
	stopCh                chan struct{}
	stopped               bool
	lifecycleCtx          context.Context
	lifecycleCancel       context.CancelFunc

	// Metrics counters (CR-3).
	refreshFailures int64
	refreshSuccess  int64

	// nowFunc for testing
	nowFunc func() time.Time
	// jitterFunc for testing (returns jitter to add to refresh delay)
	jitterFunc func(base time.Duration) time.Duration
}

// AuthTokenProviderConfig configures the AuthTokenProvider.
type AuthTokenProviderConfig struct {
	IssuerURL             string
	HTTPClient            HTTPClient
	DPoP                  *DPoPProofGenerator
	HintsProvider         IssuanceHintsProvider
	RetryConfig           RetryConfig
	RefreshBefore         time.Duration
	IdentityToken         string
	IdentityTokenProvider func(ctx context.Context) (string, error)
	Logger                *slog.Logger
	// CircuitBreakerConfig configures the circuit breaker for token refresh.
	// If nil, a default config is used (5 failures, 30s cooldown).
	CircuitBreakerConfig *circuitbreaker.Config
	// StaleGracePeriod is how long to serve a stale cached token when refresh fails.
	// Default is 60 seconds.
	StaleGracePeriod time.Duration
}

// NewAuthTokenProvider creates a new AuthTokenProvider.
func NewAuthTokenProvider(cfg *AuthTokenProviderConfig) *AuthTokenProvider {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.RefreshBefore == 0 {
		cfg.RefreshBefore = 30 * time.Second
	}
	if cfg.RetryConfig == (RetryConfig{}) {
		cfg.RetryConfig = DefaultRetryConfig()
	}
	if cfg.StaleGracePeriod == 0 {
		cfg.StaleGracePeriod = 60 * time.Second
	}

	cbCfg := circuitbreaker.DefaultConfig()
	if cfg.CircuitBreakerConfig != nil {
		cbCfg = *cfg.CircuitBreakerConfig
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &AuthTokenProvider{
		issuerURL:             cfg.IssuerURL,
		httpClient:            cfg.HTTPClient,
		dpop:                  cfg.DPoP,
		hintsProvider:         cfg.HintsProvider,
		retryConfig:           cfg.RetryConfig,
		refreshBefore:         cfg.RefreshBefore,
		identityToken:         cfg.IdentityToken,
		identityTokenProvider: cfg.IdentityTokenProvider,
		logger:                cfg.Logger,
		breaker:               circuitbreaker.New(cbCfg),
		staleGracePeriod:      cfg.StaleGracePeriod,
		stopCh:                make(chan struct{}),
		lifecycleCtx:          ctx,
		lifecycleCancel:       cancel,
		nowFunc:               time.Now,
		jitterFunc:            defaultJitter,
	}
}

// defaultJitter adds 0-10% jitter to a duration to prevent thundering herd.
func defaultJitter(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	// Add 0-10% jitter
	maxJitter := int64(base) / 10
	if maxJitter <= 0 {
		return 0
	}
	jitter := time.Duration(rand.Int64N(maxJitter))
	return jitter
}

// RefreshFailures returns the total number of background token refresh failures (for metrics/testing).
func (p *AuthTokenProvider) RefreshFailures() int64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.refreshFailures
}

// CircuitBreakerState returns the current circuit breaker state (for metrics/testing).
func (p *AuthTokenProvider) CircuitBreakerState() circuitbreaker.State {
	return p.breaker.State()
}

// GetToken returns a valid capability token, acquiring or refreshing as needed.
// It returns a cached token if still valid, or acquires a new one.
// If refresh fails but a cached token exists within the stale grace period,
// the stale token is returned to provide graceful degradation (CR-3).
func (p *AuthTokenProvider) GetToken(ctx context.Context) (*TokenResponse, error) {
	p.mu.RLock()
	cached := p.cachedToken
	p.mu.RUnlock()

	if cached != nil && !p.isExpiringSoon(cached) {
		return cached, nil
	}

	token, err := p.refreshToken(ctx)
	if err != nil {
		// Stale-token grace: if we have a cached token that hasn't fully expired
		// plus the grace period, serve it rather than failing the caller.
		if cached != nil && p.isWithinGracePeriod(cached) {
			p.logger.Warn("serving stale token during refresh failure",
				"error", err,
				"token_expires_at", time.Unix(cached.ExpiresAt, 0).Format(time.RFC3339),
			)
			return cached, nil
		}
		return nil, err
	}
	return token, nil
}

// Stop cancels any pending background refresh and releases resources.
func (p *AuthTokenProvider) Stop() {
	// Cancel the lifecycle context first (before acquiring the lock) so that
	// any in-flight refreshToken call holding the lock will have its context
	// cancelled and can return promptly.
	p.lifecycleCancel()

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.stopped {
		return
	}
	p.stopped = true
	close(p.stopCh)

	if p.refreshTimer != nil {
		p.refreshTimer.Stop()
	}
}

func (p *AuthTokenProvider) isExpiringSoon(token *TokenResponse) bool {
	now := p.nowFunc()
	expiresAt := time.Unix(token.ExpiresAt, 0)
	return now.Add(p.refreshBefore).After(expiresAt)
}

// isWithinGracePeriod returns true if the token is within the stale grace period
// (i.e., expired less than staleGracePeriod ago).
func (p *AuthTokenProvider) isWithinGracePeriod(token *TokenResponse) bool {
	now := p.nowFunc()
	expiresAt := time.Unix(token.ExpiresAt, 0)
	graceDeadline := expiresAt.Add(p.staleGracePeriod)
	return now.Before(graceDeadline)
}

func (p *AuthTokenProvider) refreshToken(ctx context.Context) (*TokenResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if p.cachedToken != nil && !p.isExpiringSoon(p.cachedToken) {
		return p.cachedToken, nil
	}

	// Wrap token acquisition in circuit breaker (CR-3).
	token, err := circuitbreaker.Do(ctx, p.breaker, func(ctx context.Context) (*TokenResponse, error) {
		return RetryFunc(ctx, p.retryConfig, func(ctx context.Context) (*TokenResponse, error) {
			return p.acquireToken(ctx)
		})
	})
	if err != nil {
		p.refreshFailures++
		return nil, fmt.Errorf("acquire capability token: %w", err)
	}

	p.refreshSuccess++
	p.cachedToken = token
	p.scheduleRefreshLocked(token)

	return token, nil
}

//nolint:contextcheck // scheduleRefreshLocked creates its own context from lifecycleCtx when the timer fires; passing a caller context is inappropriate for deferred async work.
func (p *AuthTokenProvider) scheduleRefreshLocked(token *TokenResponse) {
	if p.refreshTimer != nil {
		p.refreshTimer.Stop()
	}

	expiresAt := time.Unix(token.ExpiresAt, 0)
	now := p.nowFunc()
	refreshAt := expiresAt.Add(-p.refreshBefore)
	delay := refreshAt.Sub(now)

	if delay <= 0 {
		return // Already needs refresh
	}

	// Add jitter to prevent thundering herd on synchronized restarts (CR-3).
	delay += p.jitterFunc(delay)

	p.refreshTimer = time.AfterFunc(delay, func() {
		select {
		case <-p.stopCh:
			return
		default:
		}

		// Derive from lifecycle context: cancelled when Stop() is called,
		// preventing zombie refresh attempts during shutdown.
		ctx, cancel := context.WithTimeout(p.lifecycleCtx, 30*time.Second)
		defer cancel()

		if _, err := p.refreshToken(ctx); err != nil {
			// Only log if we weren't stopped (context cancellation during shutdown is expected).
			if p.lifecycleCtx.Err() == nil {
				p.logger.Warn("background token refresh failed",
					"error", err,
					"circuit_breaker_state", string(p.breaker.State()),
				)
			}
		}
	})
}

func (p *AuthTokenProvider) acquireToken(ctx context.Context) (*TokenResponse, error) {
	// Get identity token
	idToken := p.identityToken
	if p.identityTokenProvider != nil {
		var err error
		idToken, err = p.identityTokenProvider(ctx)
		if err != nil {
			return nil, fmt.Errorf("get identity token: %w", err)
		}
	}

	if idToken == "" {
		return nil, fmt.Errorf("no identity token available")
	}

	// Get issuance hints
	var hints *IssuanceHints
	if p.hintsProvider != nil {
		var err error
		hints, err = p.hintsProvider.GetHints(ctx)
		if err != nil {
			return nil, fmt.Errorf("get issuance hints: %w", err)
		}
	}

	// Build request body
	reqBody := issueRequestBody{
		Token: idToken,
	}
	if hints != nil {
		reqBody.Capabilities = hints.Capabilities
		reqBody.TTL = hints.TTL
		reqBody.Audience = hints.Audience
	}

	// Add DPoP binding if enabled
	if p.dpop != nil {
		reqBody.DPoP = &dpopBindingBody{JKT: p.dpop.Thumbprint()}
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal issue request: %w", err)
	}

	url := p.issuerURL + "/api/v1/issue"
	headers := map[string]string{
		"Content-Type": "application/json",
	}

	// Add DPoP proof header if enabled
	if p.dpop != nil {
		proof, err := p.dpop.GenerateProof("POST", url)
		if err != nil {
			return nil, fmt.Errorf("generate DPoP proof: %w", err)
		}
		headers["DPoP"] = proof
	}

	resp, err := p.httpClient.Do(&HTTPRequest{
		Context: ctx,
		Method:  "POST",
		URL:     url,
		Headers: headers,
		Body:    bodyBytes,
	})
	if err != nil {
		return nil, &TransientError{Err: fmt.Errorf("HTTP request to issuer: %w", err)}
	}

	// Handle DPoP nonce from server
	if nonceHeader, ok := resp.Headers["Dpop-Nonce"]; ok && p.dpop != nil {
		p.dpop.SetNonce(nonceHeader)
	}

	if resp.StatusCode == 429 || resp.StatusCode >= 500 {
		return nil, &TransientError{
			Err:        fmt.Errorf("issuer returned status %d: %s", resp.StatusCode, string(resp.Body)),
			StatusCode: resp.StatusCode,
		}
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("issuer returned status %d: %s", resp.StatusCode, string(resp.Body))
	}

	var issueResp TokenResponse
	if err := json.Unmarshal(resp.Body, &issueResp); err != nil {
		return nil, fmt.Errorf("unmarshal issue response: %w", err)
	}

	return &issueResp, nil
}

// issueRequestBody is the request body for the issuer's POST /api/v1/issue endpoint.
type issueRequestBody struct {
	Token        string           `json:"token"`
	Capabilities interface{}      `json:"capabilities,omitempty"`
	TTL          int              `json:"ttl,omitempty"`
	Audience     string           `json:"audience,omitempty"`
	DPoP         *dpopBindingBody `json:"dpop,omitempty"`
}

type dpopBindingBody struct {
	JKT string `json:"jkt"`
}
