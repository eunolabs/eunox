// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package agentruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// AuthTokenProvider acquires and refreshes capability tokens from the issuer.
// It implements proactive token refresh before expiry and caches the current token.
type AuthTokenProvider struct {
	mu sync.RWMutex

	issuerURL     string
	httpClient    HTTPClient
	dpop          *DPoPProofGenerator
	hintsProvider IssuanceHintsProvider
	retryConfig   RetryConfig
	refreshBefore time.Duration
	logger        *slog.Logger

	// Mutable state
	identityToken         string
	identityTokenProvider func(ctx context.Context) (string, error)
	cachedToken           *TokenResponse
	refreshTimer          *time.Timer
	stopCh                chan struct{}
	stopped               bool

	// nowFunc for testing
	nowFunc func() time.Time
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
}

// NewAuthTokenProvider creates a new AuthTokenProvider.
func NewAuthTokenProvider(cfg AuthTokenProviderConfig) *AuthTokenProvider {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.RefreshBefore == 0 {
		cfg.RefreshBefore = 30 * time.Second
	}
	if cfg.RetryConfig == (RetryConfig{}) {
		cfg.RetryConfig = DefaultRetryConfig()
	}

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
		stopCh:                make(chan struct{}),
		nowFunc:               time.Now,
	}
}

// GetToken returns a valid capability token, acquiring or refreshing as needed.
// It returns a cached token if still valid, or acquires a new one.
func (p *AuthTokenProvider) GetToken(ctx context.Context) (*TokenResponse, error) {
	p.mu.RLock()
	cached := p.cachedToken
	p.mu.RUnlock()

	if cached != nil && !p.isExpiringSoon(cached) {
		return cached, nil
	}

	return p.refreshToken(ctx)
}

// Stop cancels any pending background refresh.
func (p *AuthTokenProvider) Stop() {
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

func (p *AuthTokenProvider) refreshToken(ctx context.Context) (*TokenResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if p.cachedToken != nil && !p.isExpiringSoon(p.cachedToken) {
		return p.cachedToken, nil
	}

	token, err := RetryFunc(ctx, p.retryConfig, func(ctx context.Context) (*TokenResponse, error) {
		return p.acquireToken(ctx)
	})
	if err != nil {
		return nil, fmt.Errorf("acquire capability token: %w", err)
	}

	p.cachedToken = token
	p.scheduleRefreshLocked(token)

	return token, nil
}

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

	p.refreshTimer = time.AfterFunc(delay, func() {
		select {
		case <-p.stopCh:
			return
		default:
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if _, err := p.refreshToken(ctx); err != nil {
			p.logger.Warn("background token refresh failed", "error", err)
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
	Token        string      `json:"token"`
	Capabilities interface{} `json:"capabilities,omitempty"`
	TTL          int         `json:"ttl,omitempty"`
	Audience     string      `json:"audience,omitempty"`
	DPoP         *dpopBindingBody `json:"dpop,omitempty"`
}

type dpopBindingBody struct {
	JKT string `json:"jkt"`
}
