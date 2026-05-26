// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package main is the entry point for the capability issuer service.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/edgeobs/eunox/internal/issuer"
	"github.com/edgeobs/eunox/internal/issuer/policy"
	"github.com/edgeobs/eunox/pkg/config"
	"github.com/edgeobs/eunox/pkg/crypto"
	"github.com/edgeobs/eunox/pkg/identity"
	"github.com/edgeobs/eunox/pkg/observability"
	"github.com/edgeobs/eunox/pkg/ratelimit"
	"github.com/redis/go-redis/v9"
)

// These variables are set by GoReleaser via -X ldflags at build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const (
	shutdownTimeout = 10 * time.Second
)

func main() {
	cfg := config.LoadOrExit[config.IssuerConfig]("")
	logger := observability.NewLogger(&observability.LogConfig{
		Level:       os.Getenv("LOG_LEVEL"),
		ServiceName: "issuer",
	})

	logger.Info("starting capability issuer",
		slog.Int("port", cfg.Port),
		slog.String("issuer_did", cfg.IssuerDID),
		slog.String("signing_provider", string(cfg.SigningProvider)),
		slog.String("identity_provider", string(cfg.IdentityProvider)),
	)

	// Build signing key
	signer, err := buildSigner(&cfg)
	if err != nil {
		logger.Error("failed to build signer", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Build identity verifier
	idVerifier, err := buildIdentityVerifier(&cfg, logger)
	if err != nil {
		logger.Error("failed to build identity verifier", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Build rate limiter
	limiter := buildRateLimiter(&cfg, logger)

	// Build policy engine
	policyEngine := policy.New(
		policy.WithPollInterval(30*time.Second),
		policy.WithOnReloadError(func(err error) {
			logger.Error("failed to hot-reload role policies", slog.String("error", err.Error()))
		}),
	)
	if cfg.RolePolicyFile != "" {
		if loadErr := policyEngine.LoadFromFile(cfg.RolePolicyFile); loadErr != nil {
			logger.Error("failed to load role policy file",
				slog.String("file", cfg.RolePolicyFile),
				slog.String("error", loadErr.Error()),
			)
			os.Exit(1)
		}
		policyEngine.StartHotReload()
		logger.Info("loaded role policies", slog.String("file", cfg.RolePolicyFile))
	}

	// Build key store
	keyStore := issuer.NewSingleKeyStore(signer)

	// Build metrics
	metrics := observability.NewMetricsRegistry("issuer", "http")

	// Determine issuer URL
	issuerURL := cfg.IssuerURL
	if issuerURL == "" {
		issuerURL = fmt.Sprintf("http://localhost:%d", cfg.Port)
	}

	// Build app config
	appCfg := issuer.Config{
		IssuerDID:       cfg.IssuerDID,
		IssuerURL:       issuerURL,
		DefaultTokenTTL: cfg.DefaultTokenTTL,
		MaxTokenTTL:     cfg.MaxTokenTTL,
		Audience:        cfg.Audience,
		AdminAPIKey:     cfg.AdminAPIKey,
	}

	// Build issuer app
	deps := issuer.Dependencies{
		PolicyEngine: policyEngine,
		Identity:     idVerifier,
		KeyStore:     keyStore,
		RateLimiter:  limiter,
		Logger:       logger,
		Metrics:      metrics,
	}

	app := issuer.New(&appCfg, &deps)

	// Start HTTP server
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           app.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		logger.Info("listening", slog.String("addr", srv.Addr))
		if listenErr := srv.ListenAndServe(); listenErr != nil && !errors.Is(listenErr, http.ErrServerClosed) {
			logger.Error("server error", slog.String("error", listenErr.Error()))
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("shutting down")

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)

	if shutdownErr := srv.Shutdown(ctx); shutdownErr != nil {
		cancel()
		logger.Error("shutdown error", slog.String("error", shutdownErr.Error()))
		os.Exit(1)
	}
	cancel()

	policyEngine.Stop()
	logger.Info("shutdown complete")
}

func buildSigner(cfg *config.IssuerConfig) (*crypto.SoftwareSigner, error) {
	switch cfg.SigningProvider {
	case "software", "":
		return crypto.GenerateECDSASigner("issuer-key-1", crypto.ES256)
	case "azure-keyvault":
		// KMS stubs: in production, wire Azure Key Vault SDK here.
		return crypto.GenerateECDSASigner("azure-"+cfg.AzureKeyVaultKeyName, crypto.ES256)
	case "aws-kms":
		return crypto.GenerateECDSASigner("aws-"+cfg.AWSKMSKeyID, crypto.ES256)
	case "gcp-cloudkms":
		return crypto.GenerateECDSASigner("gcp-"+cfg.GCPCryptoKeyID, crypto.ES256)
	default:
		return nil, fmt.Errorf("unknown signing provider: %s", cfg.SigningProvider)
	}
}

func buildIdentityVerifier(cfg *config.IssuerConfig, logger *slog.Logger) (identity.Provider, error) {
	switch cfg.IdentityProvider {
	case "oidc", "":
		return identity.NewOIDCProvider(&identity.OIDCConfig{
			IssuerURL: cfg.OIDCIssuerURL,
			Audience:  cfg.Audience,
		}, nil)
	case "aws-cognito":
		return identity.NewCognitoProvider(identity.CognitoConfig{
			UserPoolID:  cfg.AWSCognitoUserPoolID,
			Region:      cfg.AWSCognitoRegion,
			AppClientID: cfg.Audience,
		}, nil)
	case "azure-ad":
		return identity.NewAzureADProvider(identity.AzureADConfig{
			TenantID: cfg.AzureADTenantID,
			ClientID: cfg.AzureADClientID,
		}, nil)
	case "gcp-identity":
		audience := cfg.GCPIdentityAudience
		if audience == "" {
			audience = cfg.Audience
		}
		return identity.NewGCPProvider(identity.GCPConfig{Audience: audience}, nil)
	case "did":
		trustedDIDs := make([]string, 0, 1)
		if cfg.IssuerDID != "" {
			trustedDIDs = append(trustedDIDs, cfg.IssuerDID)
		}
		return identity.NewDIDProvider(identity.DIDConfig{TrustedDIDs: trustedDIDs})
	default:
		logger.Warn("unknown identity provider, using OIDC",
			slog.String("provider", string(cfg.IdentityProvider)),
		)
		return identity.NewOIDCProvider(&identity.OIDCConfig{
			IssuerURL: cfg.OIDCIssuerURL,
			Audience:  cfg.Audience,
		}, nil)
	}
}

func buildRateLimiter(cfg *config.IssuerConfig, logger *slog.Logger) issuer.RateLimiter {
	limiterCfg := ratelimit.Config{
		Rate:   cfg.RateLimitPerMinute,
		Window: time.Minute,
	}

	if cfg.RedisURL != "" {
		opts, err := redis.ParseURL(cfg.RedisURL)
		if err != nil {
			if logger != nil {
				logger.Warn("invalid redis URL, falling back to in-memory rate limiter",
					slog.String("error", err.Error()),
				)
			}
		} else {
			return ratelimit.NewRedis(redis.NewClient(opts), limiterCfg)
		}
	}

	return ratelimit.NewInMemory(limiterCfg)
}
