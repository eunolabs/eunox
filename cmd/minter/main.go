// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package main is the entry point for the API-Key Minter service.
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

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/eunolabs/eunox/internal/minter"
	"github.com/eunolabs/eunox/pkg/config"
	"github.com/eunolabs/eunox/pkg/database"
	"github.com/eunolabs/eunox/pkg/observability"
	"github.com/eunolabs/eunox/pkg/ratelimit"
)

// These variables are set by GoReleaser via -X ldflags at build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const shutdownTimeout = 10 * time.Second

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := config.LoadOrExit[config.MinterConfig]("")
	logger := observability.NewLogger(&observability.LogConfig{
		Level:       os.Getenv("LOG_LEVEL"),
		ServiceName: "minter",
	})

	logger.Info("starting API-Key minter",
		slog.String("version", version),
		slog.String("commit", commit),
		slog.String("date", date),
		slog.Int("port", cfg.Port),
		slog.String("environment", string(cfg.NodeEnv)),
	)

	// Initialize distributed tracing. No-op when OTEL_EXPORTER_OTLP_ENDPOINT is unset.
	ctx := context.Background()
	tracerShutdown, err := observability.InitTracer(ctx, observability.TracingConfigFromEnv("minter", version))
	if err != nil {
		return fmt.Errorf("init tracer: %w", err)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer shutdownCancel()
		_ = tracerShutdown(shutdownCtx)
	}()

	// Build pepper.
	pepper, err := buildPepper(&cfg)
	if err != nil {
		return fmt.Errorf("build pepper: %w", err)
	}

	// Build admin authenticator.
	auth := buildAdminAuth(&cfg, logger)

	// Build anomaly detector.
	anomaly := minter.NewInMemoryAnomalyDetector(minter.VelocityConfig{
		MaxMintsPerWindow: cfg.RateLimitMax,
		Window:            time.Duration(cfg.RateLimitWindowSecs) * time.Second,
	}, logger)

	// Build rate limiter for ping endpoint.
	pingLimiter := ratelimit.NewInMemory(ratelimit.Config{
		Rate:   cfg.RateLimitMax,
		Window: time.Duration(cfg.RateLimitWindowSecs) * time.Second,
	})

	// Build metrics.
	metrics := observability.NewMetricsRegistry("minter", "http")

	// Build store: PostgreSQL when MINTER_API_KEY_DB_URL is set (production);
	// in-memory fallback for development/testing only.
	var store minter.KeyStore
	var readinessChecks []func(context.Context) error
	if cfg.APIKeyDBURL != "" {
		db, err := database.OpenPool("pgx", cfg.APIKeyDBURL, &cfg.DBPool)
		if err != nil {
			return fmt.Errorf("open API key database pool: %w", err)
		}
		defer func() { _ = db.Close() }()
		if _, err := database.PoolMetrics(db, metrics.Registry, "minter"); err != nil {
			return fmt.Errorf("register pool metrics: %w", err)
		}
		store = minter.NewPostgresKeyStore(db)
		readinessChecks = append(readinessChecks, func(ctx context.Context) error {
			return db.PingContext(ctx)
		})
		logger.Info("using PostgreSQL key store")
	} else {
		if cfg.NodeEnv == config.EnvProduction {
			return fmt.Errorf("MINTER_API_KEY_DB_URL is required in production")
		}
		store = minter.NewInMemoryStore()
		logger.Warn("using in-memory key store (development only — data is not persisted)")
	}

	// Build app.
	appCfg := minter.Config{
		Pepper:             pepper,
		DefaultTenantID:    "default",
		ReadinessChecks:    readinessChecks,
		MaxRequestBodySize: int64(cfg.MaxRequestBodySize),
		TrustedProxyCIDRs:  cfg.TrustedProxyCIDRs,
	}

	deps := minter.Dependencies{
		Store:       store,
		Auth:        auth,
		Anomaly:     anomaly,
		PingLimiter: pingLimiter,
		Logger:      logger,
		Metrics:     metrics,
	}

	app, err := minter.New(&appCfg, &deps)
	if err != nil {
		return fmt.Errorf("create minter app: %w", err)
	}

	// Start HTTP server.
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
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if shutdownErr := srv.Shutdown(ctx); shutdownErr != nil {
		return fmt.Errorf("shutdown: %w", shutdownErr)
	}

	logger.Info("shutdown complete")
	return nil
}

func buildPepper(cfg *config.MinterConfig) (*minter.Pepper, error) {
	if cfg.PepperHex == "" {
		// Development mode: use a deterministic pepper.
		return minter.NewPepperFromHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	}
	return minter.NewPepperFromHex(cfg.PepperHex)
}

func buildAdminAuth(cfg *config.MinterConfig, logger *slog.Logger) minter.AdminAuthenticator {
	var jwtVerifier *minter.AdminJWTVerifier
	jwksURI := os.Getenv("MINTER_ADMIN_JWKS_URI")
	if jwksURI != "" {
		jwtVerifier = minter.NewAdminJWTVerifier(minter.AdminJWTVerifierConfig{
			JWKSURI:  jwksURI,
			Audience: os.Getenv("MINTER_ADMIN_JWT_AUDIENCE"),
			Logger:   logger,
		})
	}

	return minter.NewCombinedAdminAuth(minter.CombinedAdminAuthConfig{
		JWTVerifier: jwtVerifier,
		AdminKey:    cfg.AdminAPIKey,
		Logger:      logger,
	})
}
