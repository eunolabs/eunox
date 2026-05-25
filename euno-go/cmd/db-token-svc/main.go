// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

// Package main is the entry point for the DB Token Service.
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

	"github.com/edgeobs/euno-platform/euno-go/internal/dbtokensvc"
	"github.com/edgeobs/euno-platform/euno-go/pkg/observability"
)

const shutdownTimeout = 10 * time.Second

func main() {
	port := envOrDefault("DB_TOKEN_SVC_PORT", "3005")
	adapter := envOrDefault("DB_TOKEN_SVC_ADAPTER", "aws-rds")

	logger := observability.NewLogger(observability.LogConfig{
		Level:       os.Getenv("LOG_LEVEL"),
		ServiceName: "db-token-svc",
	})

	logger.Info("starting DB token service",
		slog.String("port", port),
		slog.String("adapter", adapter),
	)

	// Build cloud adapter.
	cloudAdapter := buildAdapter(adapter)

	// Build token verifier (stub for now; production would use JWKS-based verifier).
	verifier := &stubTokenVerifier{}

	// Build capability mapping.
	mapping := &dbtokensvc.CapabilityMapping{
		ResourceToUsername: map[string]string{
			"db://default": "app_user",
		},
	}

	// Build metrics.
	metrics := observability.NewMetricsRegistry("dbtokensvc", "http")

	// Build app.
	cfg := dbtokensvc.Config{
		DefaultTTL: 15 * time.Minute,
		MaxTTL:     60 * time.Minute,
		Adapter:    adapter,
	}

	deps := dbtokensvc.Dependencies{
		Adapter:  cloudAdapter,
		Verifier: verifier,
		Mapping:  mapping,
		Logger:   logger,
		Metrics:  metrics,
	}

	app := dbtokensvc.New(cfg, deps)

	// Start HTTP server.
	srv := &http.Server{
		Addr:              ":" + port,
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

	// Wait for shutdown signal.
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
	logger.Info("shutdown complete")
}

func buildAdapter(name string) dbtokensvc.CloudDBAdapter {
	switch name {
	case "aws-rds":
		return dbtokensvc.NewAWSRDSAdapter(
			envOrDefault("AWS_REGION", "us-east-1"),
			envOrDefault("DB_TOKEN_SVC_RDS_ENDPOINT", "localhost"),
			5432,
		)
	case "azure-sql":
		return dbtokensvc.NewAzureSQLAdapter(
			envOrDefault("DB_TOKEN_SVC_AZURE_SERVER", "localhost.database.windows.net"),
			1433,
		)
	case "gcp-cloudsql":
		return dbtokensvc.NewGCPCloudSQLAdapter(
			envOrDefault("DB_TOKEN_SVC_GCP_INSTANCE", "project:region:instance"),
			5432,
		)
	default:
		return dbtokensvc.NewAWSRDSAdapter("us-east-1", "localhost", 5432)
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// stubTokenVerifier is a development-mode verifier that extracts claims without cryptographic verification.
type stubTokenVerifier struct{}

func (s *stubTokenVerifier) VerifyAndExtractCaps(_ context.Context, _ string) (*dbtokensvc.TokenClaims, error) {
	// In production, this would verify the JWT against the issuer's JWKS.
	return nil, fmt.Errorf("JWT verification not configured: use ISSUER_JWKS_URL env var")
}
