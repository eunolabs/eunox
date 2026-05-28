// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package main is the entry point for the Storage Grant Service.
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

	"github.com/edgeobs/eunox/internal/storagegrantsvc"
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
	port := envOrDefault("STORAGE_GRANT_SVC_PORT", "3006")
	adapter := envOrDefault("STORAGE_GRANT_SVC_ADAPTER", "aws-s3")

	logger := observability.NewLogger(&observability.LogConfig{
		Level:       os.Getenv("LOG_LEVEL"),
		ServiceName: "storage-grant-svc",
	})

	logger.Info("starting storage grant service",
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

	// Build metrics.
	metrics := observability.NewMetricsRegistry("storagegrantsvc", "http")

	// Build app.
	cfg := storagegrantsvc.Config{
		DefaultTTL:     15 * time.Minute,
		MaxTTL:         60 * time.Minute,
		Adapter:        adapter,
		ProductionMode: os.Getenv("NODE_ENV") == "production",
	}

	deps := storagegrantsvc.Dependencies{
		Adapter:  cloudAdapter,
		Verifier: verifier,
		Logger:   logger,
		Metrics:  metrics,
	}

	app, appErr := storagegrantsvc.New(cfg, deps)
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

func buildAdapter(name string) (storagegrantsvc.CloudStorageAdapter, error) {
	switch name {
	case "aws-s3":
		bucket := os.Getenv("STORAGE_GRANT_SVC_BUCKET")
		if bucket == "" {
			return nil, errors.New("STORAGE_GRANT_SVC_BUCKET must be set for aws-s3 adapter")
		}
		return storagegrantsvc.NewRealAWSS3Adapter(storagegrantsvc.RealAWSS3AdapterConfig{
			Region:             envOrDefault("AWS_REGION", "us-east-1"),
			DefaultBucket:      bucket,
			CredentialProvider: &envAWSCredentialProvider{},
		})
	case "azure-blob":
		accountName := os.Getenv("STORAGE_GRANT_SVC_AZURE_ACCOUNT")
		if accountName == "" {
			return nil, errors.New("STORAGE_GRANT_SVC_AZURE_ACCOUNT must be set for azure-blob adapter")
		}
		tokenProvider := newIMDSAzureStorageTokenProvider()
		return storagegrantsvc.NewRealAzureBlobAdapter(storagegrantsvc.RealAzureBlobAdapterConfig{
			AccountName:           accountName,
			DefaultContainer:      os.Getenv("STORAGE_GRANT_SVC_AZURE_CONTAINER"),
			DelegationKeyProvider: newRESTAzureDelegationKeyProvider(tokenProvider),
		})
	case "gcp-gcs":
		signer, err := loadServiceAccountSigner()
		if err != nil {
			return nil, fmt.Errorf("gcp-gcs adapter: %w", err)
		}
		return storagegrantsvc.NewRealGCPGCSAdapter(storagegrantsvc.RealGCPGCSAdapterConfig{
			DefaultBucket: os.Getenv("STORAGE_GRANT_SVC_GCP_BUCKET"),
			Signer:        signer,
		})
	default:
		return nil, fmt.Errorf("unsupported STORAGE_GRANT_SVC_ADAPTER %q", name)
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

func buildVerifier() (storagegrantsvc.TokenVerifier, error) {
	jwksURL := os.Getenv("ISSUER_JWKS_URL")
	if jwksURL == "" {
		return nil, errors.New("ISSUER_JWKS_URL must be set")
	}
	return storagegrantsvc.NewJWKSTokenVerifier(storagegrantsvc.JWKSTokenVerifierConfig{
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
