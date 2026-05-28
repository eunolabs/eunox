// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package main is the entry point for the capability issuer service.
package main

import (
	"context"
	stdcrypto "crypto"
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
	"github.com/prometheus/client_golang/prometheus"
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
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.LoadOrExit[config.IssuerConfig]("")
	logger := observability.NewLogger(&observability.LogConfig{
		Level:       os.Getenv("LOG_LEVEL"),
		ServiceName: "issuer",
	})

	logger.Info("starting capability issuer",
		slog.Int("port", cfg.Port),
		slog.String("version", version),
		slog.String("commit", commit),
		slog.String("date", date),
		slog.String("issuer_did", cfg.IssuerDID),
		slog.String("signing_provider", string(cfg.SigningProvider)),
		slog.String("identity_provider", string(cfg.IdentityProvider)),
	)

	// Initialize distributed tracing. No-op when OTEL_EXPORTER_OTLP_ENDPOINT is unset.
	tracerShutdown, err := observability.InitTracer(ctx, observability.TracingConfigFromEnv("issuer", version))
	if err != nil {
		return fmt.Errorf("init tracer: %w", err)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer shutdownCancel()
		_ = tracerShutdown(shutdownCtx)
	}()

	// Build signing key
	signer, err := buildSigner(&cfg)
	if err != nil {
		return fmt.Errorf("build signer: %w", err)
	}

	// Build identity verifier
	idVerifier, err := buildIdentityVerifier(&cfg, logger)
	if err != nil {
		return fmt.Errorf("build identity verifier: %w", err)
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
			return fmt.Errorf("load role policy file %q: %w", cfg.RolePolicyFile, loadErr)
		}
		policyEngine.StartHotReload()
		logger.Info("loaded role policies", slog.String("file", cfg.RolePolicyFile))
	}

	// Build key store
	var keyStore issuer.KeyStore
	if softwareSigner, ok := signer.(*crypto.SoftwareSigner); ok {
		rotatingKeyStore := issuer.NewRotatingKeyStore(softwareSigner)
		keyAgeGauge := prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "issuer_signing_key_age_seconds",
			Help: "Seconds since the current issuer signing key was last rotated.",
		})
		if err := prometheus.DefaultRegisterer.Register(keyAgeGauge); err != nil {
			if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
				existing, ok := are.ExistingCollector.(prometheus.Gauge)
				if !ok {
					return fmt.Errorf("register signing key age gauge: existing collector is not a Gauge (got %T)", are.ExistingCollector)
				}
				keyAgeGauge = existing
			} else {
				return fmt.Errorf("register signing key age gauge: %w", err)
			}
		}
		rotationInterval := time.Duration(cfg.KeyRotationIntervalDays) * 24 * time.Hour
		maxTTL := time.Duration(cfg.MaxTokenTTL) * time.Second
		if err := rotatingKeyStore.StartAutoRotation(ctx, rotationInterval, maxTTL, logger, keyAgeGauge); err != nil {
			return fmt.Errorf("start key auto-rotation: %w", err)
		}
		keyStore = rotatingKeyStore
	} else {
		// KMS-backed providers rotate keys externally; readiness checks should add a DB ping here when a policy DB is introduced.
		keyStore = issuer.NewSingleKeyStore(signer)
	}

	// Build metrics
	metrics := observability.NewMetricsRegistry("issuer", "http")

	// Determine issuer URL
	issuerURL := cfg.IssuerURL
	if issuerURL == "" {
		issuerURL = fmt.Sprintf("http://localhost:%d", cfg.Port)
	}

	// Build app config
	appCfg := issuer.Config{
		IssuerDID:          cfg.IssuerDID,
		IssuerURL:          issuerURL,
		DefaultTokenTTL:    cfg.DefaultTokenTTL,
		MaxTokenTTL:        cfg.MaxTokenTTL,
		Audience:           cfg.Audience,
		AdminAPIKey:        cfg.AdminAPIKey,
		ReadinessChecks:    nil, // Add a DB ping here when issuer policy state moves into a database.
		MaxRequestBodySize: int64(cfg.MaxRequestBodySize),
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

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", slog.String("addr", srv.Addr))
		if listenErr := srv.ListenAndServe(); listenErr != nil && !errors.Is(listenErr, http.ErrServerClosed) {
			errCh <- fmt.Errorf("server: %w", listenErr)
		}
	}()

	// Wait for shutdown signal or server error.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		logger.Info("received shutdown signal", slog.String("signal", sig.String()))
	case err := <-errCh:
		return err
	}

	logger.Info("shutting down")
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()

	if shutdownErr := srv.Shutdown(shutdownCtx); shutdownErr != nil {
		return fmt.Errorf("shutdown: %w", shutdownErr)
	}

	policyEngine.Stop()
	logger.Info("shutdown complete")
	return nil
}

func buildSigner(cfg *config.IssuerConfig) (crypto.Signer, error) {
	switch cfg.SigningProvider {
	case "software", "":
		if cfg.NodeEnv == config.EnvProduction {
			return nil, fmt.Errorf("signing provider %q is not allowed in production; use aws-kms, azure-keyvault, or gcp-cloudkms", cfg.SigningProvider)
		}
		return crypto.GenerateECDSASigner("issuer-key-1", crypto.ES256)
	case "azure-keyvault":
		if cfg.AzureKeyVaultURL == "" {
			return nil, fmt.Errorf("AZURE_KEYVAULT_URL is required for azure-keyvault signing provider")
		}
		if cfg.AzureKeyVaultKeyName == "" {
			return nil, fmt.Errorf("AZURE_KEYVAULT_KEY_NAME is required for azure-keyvault signing provider")
		}
		client, err := crypto.NewEnvAzureKeyVaultClient()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize Azure Key Vault client: %w", err)
		}
		signer, err := crypto.NewRealAzureKeyVaultSigner(&crypto.RealAzureKeyVaultSignerConfig{
			VaultURL:  cfg.AzureKeyVaultURL,
			KeyName:   cfg.AzureKeyVaultKeyName,
			Algorithm: crypto.ES256,
			Client:    client,
		})
		if err != nil {
			return nil, err
		}
		if err := ensureProductionSignerPublishesPublicKey(cfg, signer); err != nil {
			return nil, err
		}
		return signer, nil
	case "aws-kms":
		if cfg.AWSKMSKeyID == "" {
			return nil, fmt.Errorf("AWS_KMS_KEY_ID is required for aws-kms signing provider")
		}
		if cfg.AWSKMSRegion == "" {
			return nil, fmt.Errorf("AWS_KMS_REGION is required for aws-kms signing provider")
		}
		client, err := crypto.NewEnvAWSKMSClient(cfg.AWSKMSRegion)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize AWS KMS client: %w", err)
		}
		signer, err := crypto.NewRealAWSKMSSigner(crypto.RealAWSKMSSignerConfig{
			KeyID:     cfg.AWSKMSKeyID,
			Region:    cfg.AWSKMSRegion,
			Algorithm: crypto.ES256,
			Client:    client,
		})
		if err != nil {
			return nil, err
		}
		if err := ensureProductionSignerPublishesPublicKey(cfg, signer); err != nil {
			return nil, err
		}
		return signer, nil
	case "gcp-cloudkms":
		if cfg.GCPProjectID == "" {
			return nil, fmt.Errorf("GCP_PROJECT_ID is required for gcp-cloudkms signing provider")
		}
		if cfg.GCPKeyringID == "" {
			return nil, fmt.Errorf("GCP_KEYRING_ID is required for gcp-cloudkms signing provider")
		}
		if cfg.GCPCryptoKeyID == "" {
			return nil, fmt.Errorf("GCP_CRYPTOKEY_ID is required for gcp-cloudkms signing provider")
		}
		client, err := crypto.NewEnvGCPCloudKMSClient()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize GCP Cloud KMS client: %w", err)
		}
		signer, err := crypto.NewRealGCPCloudKMSSigner(&crypto.RealGCPCloudKMSSignerConfig{
			ProjectID:        cfg.GCPProjectID,
			LocationID:       gcpLocationOrDefault(cfg),
			KeyRingID:        cfg.GCPKeyringID,
			CryptoKeyID:      cfg.GCPCryptoKeyID,
			CryptoKeyVersion: gcpKeyVersionOrDefault(cfg),
			Algorithm:        crypto.ES256,
			Client:           client,
		})
		if err != nil {
			return nil, err
		}
		if err := ensureProductionSignerPublishesPublicKey(cfg, signer); err != nil {
			return nil, err
		}
		return signer, nil
	default:
		return nil, fmt.Errorf("unknown signing provider: %s", cfg.SigningProvider)
	}
}

type publicKeyExporter interface {
	PublicKey() stdcrypto.PublicKey
}

func ensureProductionSignerPublishesPublicKey(cfg *config.IssuerConfig, signer crypto.Signer) error {
	if cfg.NodeEnv != config.EnvProduction {
		return nil
	}
	exporter, ok := signer.(publicKeyExporter)
	if !ok || exporter.PublicKey() == nil {
		return fmt.Errorf("signing provider %q must expose a public key in production for JWKS publication", cfg.SigningProvider)
	}
	return nil
}

func gcpLocationOrDefault(cfg *config.IssuerConfig) string {
	if cfg.GCPLocationID != "" {
		return cfg.GCPLocationID
	}
	return "global"
}

func gcpKeyVersionOrDefault(cfg *config.IssuerConfig) string {
	if cfg.GCPCryptoKeyVersion != "" {
		return cfg.GCPCryptoKeyVersion
	}
	return "1"
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
