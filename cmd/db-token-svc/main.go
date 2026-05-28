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
	"strconv"
	"syscall"
	"time"

	"github.com/edgeobs/eunox/internal/dbtokensvc"
	"github.com/edgeobs/eunox/pkg/observability"
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
	port := envOrDefault("DB_TOKEN_SVC_PORT", "3005")
	adapter := envOrDefault("DB_TOKEN_SVC_ADAPTER", "aws-rds")

	logger := observability.NewLogger(&observability.LogConfig{
		Level:       os.Getenv("LOG_LEVEL"),
		ServiceName: "db-token-svc",
	})

	logger.Info("starting DB token service",
		slog.String("version", version),
		slog.String("commit", commit),
		slog.String("date", date),
		slog.String("port", port),
		slog.String("adapter", adapter),
	)

	// Build cloud adapter.
	cloudAdapter, err := buildAdapter(adapter)
	if err != nil {
		return fmt.Errorf("build cloud adapter: %w", err)
	}

	// Require a concrete JWT verifier before starting the service.
	verifier, err := buildVerifier()
	if err != nil {
		return fmt.Errorf("configure JWT verification: %w", err)
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
		return fmt.Errorf("create application: %w", appErr)
	}

	// Start HTTP server.
	srv := &http.Server{
		Addr:              ":" + port,
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

func buildAdapter(name string) (dbtokensvc.CloudDBAdapter, error) {
	switch name {
	case "aws-rds":
		endpoint := os.Getenv("DB_TOKEN_SVC_RDS_ENDPOINT")
		if endpoint == "" {
			return nil, errors.New("DB_TOKEN_SVC_RDS_ENDPOINT must be set for aws-rds adapter")
		}
		return dbtokensvc.NewRealAWSRDSAdapter(dbtokensvc.RealAWSRDSAdapterConfig{
			Region:             envOrDefault("AWS_REGION", "us-east-1"),
			Endpoint:           endpoint,
			Port:               envIntOrDefault("DB_TOKEN_SVC_RDS_PORT", 5432),
			CredentialProvider: &envAWSCredentialProvider{},
		})
	case "azure-sql":
		serverName := os.Getenv("DB_TOKEN_SVC_AZURE_SERVER")
		if serverName == "" {
			return nil, errors.New("DB_TOKEN_SVC_AZURE_SERVER must be set for azure-sql adapter")
		}
		return dbtokensvc.NewRealAzureSQLAdapter(dbtokensvc.RealAzureSQLAdapterConfig{
			ServerName:    serverName,
			Port:          envIntOrDefault("DB_TOKEN_SVC_AZURE_PORT", 1433),
			TokenProvider: newIMDSAzureTokenProvider(),
		})
	case "gcp-cloudsql":
		instanceConn := os.Getenv("DB_TOKEN_SVC_GCP_INSTANCE")
		if instanceConn == "" {
			return nil, errors.New("DB_TOKEN_SVC_GCP_INSTANCE must be set for gcp-cloudsql adapter (format: project:region:instance)")
		}
		return dbtokensvc.NewRealGCPCloudSQLAdapter(dbtokensvc.RealGCPCloudSQLAdapterConfig{
			InstanceConnection: instanceConn,
			Port:               envIntOrDefault("DB_TOKEN_SVC_GCP_PORT", 5432),
			TokenProvider:      newMetadataGCPTokenProvider(),
		})
	default:
		return nil, fmt.Errorf("unsupported DB_TOKEN_SVC_ADAPTER %q", name)
	}
}

// envIntOrDefault parses an integer from the named environment variable.
// If the variable is unset or cannot be parsed, fallback is returned.
func envIntOrDefault(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func buildVerifier() (dbtokensvc.TokenVerifier, error) {
	jwksURL := os.Getenv("ISSUER_JWKS_URL")
	if jwksURL == "" {
		return nil, errors.New("ISSUER_JWKS_URL must be set")
	}
	return dbtokensvc.NewJWKSTokenVerifier(dbtokensvc.JWKSTokenVerifierConfig{
		JWKSURL:  jwksURL,
		Audience: os.Getenv("ISSUER_JWT_AUDIENCE"),
	}), nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
