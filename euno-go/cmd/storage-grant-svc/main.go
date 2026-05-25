// Copyright 2024-2025 Euno Platform Authors
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
	"syscall"
	"time"

	"github.com/edgeobs/euno-platform/euno-go/internal/storagegrantsvc"
	"github.com/edgeobs/euno-platform/euno-go/pkg/observability"
)

const shutdownTimeout = 10 * time.Second

func main() {
	port := envOrDefault("STORAGE_GRANT_SVC_PORT", "3006")
	adapter := envOrDefault("STORAGE_GRANT_SVC_ADAPTER", "aws-s3")

	logger := observability.NewLogger(observability.LogConfig{
		Level:       os.Getenv("LOG_LEVEL"),
		ServiceName: "storage-grant-svc",
	})

	logger.Info("starting storage grant service",
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

	// Build metrics.
	metrics := observability.NewMetricsRegistry("storagegrantsvc", "http")

	// Build app.
	cfg := storagegrantsvc.Config{
		DefaultTTL: 15 * time.Minute,
		MaxTTL:     60 * time.Minute,
		Adapter:    adapter,
	}

	deps := storagegrantsvc.Dependencies{
		Adapter:  cloudAdapter,
		Verifier: verifier,
		Logger:   logger,
		Metrics:  metrics,
	}

	app := storagegrantsvc.New(cfg, deps)

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

func buildAdapter(name string) (storagegrantsvc.CloudStorageAdapter, error) {
	switch name {
	case "aws-s3":
		return storagegrantsvc.NewAWSS3Adapter(
			envOrDefault("AWS_REGION", "us-east-1"),
			envOrDefault("STORAGE_GRANT_SVC_BUCKET", "my-bucket"),
		), nil
	case "azure-blob":
		return storagegrantsvc.NewAzureBlobAdapter(
			envOrDefault("STORAGE_GRANT_SVC_AZURE_ACCOUNT", "myaccount"),
			envOrDefault("STORAGE_GRANT_SVC_AZURE_CONTAINER", "mycontainer"),
		), nil
	case "gcp-gcs":
		return storagegrantsvc.NewGCPGCSAdapter(
			envOrDefault("GCP_PROJECT_ID", "my-project"),
			envOrDefault("STORAGE_GRANT_SVC_GCP_BUCKET", "my-bucket"),
		), nil
	default:
		return nil, fmt.Errorf("unsupported STORAGE_GRANT_SVC_ADAPTER %q", name)
	}
}

func buildVerifier() (storagegrantsvc.TokenVerifier, error) {
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
