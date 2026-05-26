// Copyright 2026 Eunox Authors
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

	"github.com/edgeobs/eunox/internal/dbtokensvc"
	"github.com/edgeobs/eunox/pkg/observability"
)

const shutdownTimeout = 10 * time.Second

func main() {
	port := envOrDefault("DB_TOKEN_SVC_PORT", "3005")
	adapter := envOrDefault("DB_TOKEN_SVC_ADAPTER", "aws-rds")

	logger := observability.NewLogger(&observability.LogConfig{
		Level:       os.Getenv("LOG_LEVEL"),
		ServiceName: "db-token-svc",
	})

	logger.Info("starting DB token service",
		slog.String("port", port),
		slog.String("adapter", adapter),
	)

	// Build cloud adapter.
	cloudAdapter, err := buildAdapter(adapter)
	if err != nil {
		logger.Error("failed to build cloud adapter", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Require a concrete JWT verifier before starting the service.
	verifier, err := buildVerifier()
	if err != nil {
		logger.Error("failed to configure JWT verification", slog.String("error", err.Error()))
		os.Exit(1)
	}

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
		DefaultTTL:     15 * time.Minute,
		MaxTTL:         60 * time.Minute,
		Adapter:        adapter,
		ProductionMode: os.Getenv("NODE_ENV") == "production",
	}

	deps := dbtokensvc.Dependencies{
		Adapter:  cloudAdapter,
		Verifier: verifier,
		Mapping:  mapping,
		Logger:   logger,
		Metrics:  metrics,
	}

	app, appErr := dbtokensvc.New(cfg, deps)
	if appErr != nil {
		logger.Error("failed to create application", slog.String("error", appErr.Error()))
		os.Exit(1)
	}

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

func buildAdapter(name string) (dbtokensvc.CloudDBAdapter, error) {
	switch name {
	case "aws-rds":
		return dbtokensvc.NewAWSRDSAdapter(
			envOrDefault("AWS_REGION", "us-east-1"),
			envOrDefault("DB_TOKEN_SVC_RDS_ENDPOINT", "localhost"),
			5432,
		), nil
	case "azure-sql":
		return dbtokensvc.NewAzureSQLAdapter(
			envOrDefault("DB_TOKEN_SVC_AZURE_SERVER", "localhost.database.windows.net"),
			1433,
		), nil
	case "gcp-cloudsql":
		return dbtokensvc.NewGCPCloudSQLAdapter(
			envOrDefault("DB_TOKEN_SVC_GCP_INSTANCE", "project:region:instance"),
			5432,
		), nil
	default:
		return nil, fmt.Errorf("unsupported DB_TOKEN_SVC_ADAPTER %q", name)
	}
}

//nolint:unparam // placeholder until external verifier is configured
func buildVerifier() (dbtokensvc.TokenVerifier, error) {
	if os.Getenv("ISSUER_JWKS_URL") == "" {
		return nil, errors.New("ISSUER_JWKS_URL must be set")
	}
	return nil, errors.New("JWT verification via ISSUER_JWKS_URL is not implemented yet")
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
