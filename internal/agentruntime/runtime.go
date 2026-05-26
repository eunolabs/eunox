// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package agentruntime

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// Runtime manages the token lifecycle and tool invocation for agent applications.
// It is the primary entry point for embedding the Euno agent runtime.
type Runtime struct {
	config        Config
	tokenProvider *AuthTokenProvider
	toolInvoker   *ToolInvoker
	dpop          *DPoPProofGenerator
	hintsProvider IssuanceHintsProvider
	logger        *slog.Logger
}

// Option configures the Runtime.
type Option func(*Runtime)

// WithLogger sets the logger for the runtime.
func WithLogger(logger *slog.Logger) Option {
	return func(r *Runtime) {
		r.logger = logger
	}
}

// WithHintsProvider sets the issuance hints provider.
func WithHintsProvider(provider IssuanceHintsProvider) Option {
	return func(r *Runtime) {
		r.hintsProvider = provider
	}
}

// New creates a new agent Runtime with the given configuration.
// The runtime manages DPoP key generation, token acquisition, caching,
// proactive refresh, and tool invocation through the gateway.
func New(cfg *Config, opts ...Option) (*Runtime, error) {
	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("IssuerURL is required")
	}
	if cfg.GatewayURL == "" {
		return nil, fmt.Errorf("GatewayURL is required")
	}
	if cfg.IdentityToken == "" && cfg.IdentityTokenProvider == nil {
		return nil, fmt.Errorf("either IdentityToken or IdentityTokenProvider is required")
	}

	r := &Runtime{
		config: *cfg,
		logger: slog.Default(),
	}

	for _, opt := range opts {
		opt(r)
	}

	// Initialize HTTP client
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = NewDefaultHTTPClient()
	}

	// Initialize DPoP
	dpopEnabled := true
	if cfg.DPoPEnabled != nil {
		dpopEnabled = *cfg.DPoPEnabled
	}

	var dpop *DPoPProofGenerator
	if dpopEnabled {
		var err error
		dpop, err = NewDPoPProofGenerator()
		if err != nil {
			return nil, fmt.Errorf("create DPoP generator: %w", err)
		}
	}
	r.dpop = dpop

	// Set defaults
	refreshBefore := cfg.RefreshBeforeExpiry
	if refreshBefore == 0 {
		refreshBefore = 30 * time.Second
	}

	retryConfig := RetryConfig{
		MaxRetries: cfg.MaxRetries,
		BaseDelay:  cfg.RetryBaseDelay,
		MaxDelay:   cfg.RetryMaxDelay,
	}
	if retryConfig.MaxRetries == 0 {
		retryConfig = DefaultRetryConfig()
	}

	// Create token provider
	r.tokenProvider = NewAuthTokenProvider(&AuthTokenProviderConfig{
		IssuerURL:             cfg.IssuerURL,
		HTTPClient:            httpClient,
		DPoP:                  dpop,
		HintsProvider:         r.hintsProvider,
		RetryConfig:           retryConfig,
		RefreshBefore:         refreshBefore,
		IdentityToken:         cfg.IdentityToken,
		IdentityTokenProvider: cfg.IdentityTokenProvider,
		Logger:                r.logger,
	})

	// Create tool invoker
	r.toolInvoker = NewToolInvoker(&ToolInvokerConfig{
		GatewayURL:    cfg.GatewayURL,
		HTTPClient:    httpClient,
		TokenProvider: r.tokenProvider,
		DPoP:          dpop,
		RetryConfig:   retryConfig,
		Logger:        r.logger,
	})

	return r, nil
}

// InvokeTool executes a tool request through the gateway enforcement layer.
func (r *Runtime) InvokeTool(ctx context.Context, req *ToolRequest) (*ToolResponse, error) {
	return r.toolInvoker.Invoke(ctx, req)
}

// GetToken returns the current capability token, acquiring or refreshing as needed.
func (r *Runtime) GetToken(ctx context.Context) (*TokenResponse, error) {
	return r.tokenProvider.GetToken(ctx)
}

// DPoPThumbprint returns the DPoP JWK Thumbprint used for key binding.
// Returns empty string if DPoP is disabled.
func (r *Runtime) DPoPThumbprint() string {
	if r.dpop == nil {
		return ""
	}
	return r.dpop.Thumbprint()
}

// Stop shuts down the runtime, cancelling background refresh timers.
func (r *Runtime) Stop() {
	r.tokenProvider.Stop()
}
