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

	"github.com/edgeobs/eunox/internal/minter"
	"github.com/edgeobs/eunox/pkg/config"
	"github.com/edgeobs/eunox/pkg/observability"
	"github.com/edgeobs/eunox/pkg/ratelimit"
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

	// Build store (in-memory for development; PostgreSQL for production).
	store := minter.NewInMemoryStore()

	// Build metrics.
	metrics := observability.NewMetricsRegistry("minter", "http")

	// Build app.
	appCfg := minter.Config{
		Pepper:             pepper,
		DefaultTenantID:    "default",
		MaxRequestBodySize: int64(cfg.MaxRequestBodySize),
	}

	deps := minter.Dependencies{
		Store:       store,
		Auth:        auth,
		Anomaly:     anomaly,
		PingLimiter: pingLimiter,
		Logger:      logger,
		Metrics:     metrics,
	}

	app := minter.New(appCfg, &deps)

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
