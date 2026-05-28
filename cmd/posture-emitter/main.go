// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Binary posture-emitter is the Eunox Posture Emitter service for AI asset
// inventory reporting to cloud security platforms (CSPM).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/edgeobs/eunox/internal/posture"
	"github.com/edgeobs/eunox/pkg/config"
	"github.com/edgeobs/eunox/pkg/observability"
)

// These variables are set by GoReleaser via -X ldflags at build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const (
	shutdownTimeout = 10 * time.Second
	readTimeout     = 10 * time.Second
	writeTimeout    = 30 * time.Second
	idleTimeout     = 60 * time.Second
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := config.LoadOrExit[config.EmitterConfig]("")

	logger := observability.NewLogger(&observability.LogConfig{
		Level:       levelFromEnv(cfg.NodeEnv),
		Format:      "json",
		ServiceName: "posture-emitter",
		Version:     version,
	})

	slog.SetDefault(logger)
	logger.Info("starting posture emitter",
		slog.String("version", version),
		slog.String("commit", commit),
		slog.String("date", date),
		slog.Int("port", cfg.Port),
		slog.String("commit", commit),
		slog.String("date", date),
		slog.Bool("enabled", cfg.Enabled),
		slog.String("plugins", cfg.Plugins),
		slog.String("queuePath", cfg.QueuePath),
	)

	// Initialize metrics.
	metrics := observability.NewMetricsRegistry("eunox", "posture")

	// Initialize distributed tracing. No-op when OTEL_EXPORTER_OTLP_ENDPOINT is unset.
	ctx := context.Background()
	tracerShutdown, err := observability.InitTracer(ctx, observability.TracingConfigFromEnv("posture-emitter", version))
	if err != nil {
		return fmt.Errorf("init tracer: %w", err)
	}
	defer func() { _ = tracerShutdown(context.Background()) }()

	// Build plugins from configuration.
	plugins, err := buildPlugins(&cfg, logger)
	if err != nil {
		return fmt.Errorf("build plugins: %w", err)
	}

	logger.Info("plugins configured", slog.Int("count", len(plugins)))

	// Build posture emitter app.
	appCfg := posture.Config{
		Enabled:             cfg.Enabled,
		QueuePath:           cfg.QueuePath,
		FlushIntervalMS:     cfg.FlushIntervalMS,
		MaxAttempts:         cfg.MaxAttempts,
		BatchSize:           cfg.BatchSize,
		PluginTimeoutMS:     cfg.PluginTimeoutMS,
		BackoffBaseMS:       cfg.BackoffBaseMS,
		BackoffMaxMS:        cfg.BackoffMaxMS,
		DedupeWindowMS:      cfg.DedupeWindowMS,
		HealthMaxQueueDepth: int64(cfg.HealthMaxQueueDepth),
	}

	deps := posture.Dependencies{
		Logger:  logger,
		Metrics: metrics,
	}

	app, err := posture.New(&appCfg, plugins, &deps)
	if err != nil {
		return fmt.Errorf("create posture emitter: %w", err)
	}

	// Start the delivery worker.
	app.Start()

	// Create HTTP server.
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           app.Handler(),
		ReadHeaderTimeout: readTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	// Start server.
	errCh := make(chan error, 1)
	go func() {
		logger.Info("server listening", slog.String("addr", srv.Addr))
		if listenErr := srv.ListenAndServe(); listenErr != nil && !errors.Is(listenErr, http.ErrServerClosed) {
			errCh <- fmt.Errorf("server: %w", listenErr)
		}
	}()

	// Wait for shutdown signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-sigCh:
		logger.Info("received shutdown signal", slog.String("signal", sig.String()))
	case err := <-errCh:
		return err
	}

	// Graceful shutdown.
	logger.Info("shutting down gracefully", slog.Duration("timeout", shutdownTimeout))

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown: %w", err)
	}

	// Stop delivery worker (drains in-flight events).
	app.Stop()

	logger.Info("shutdown complete")
	return nil
}

func buildPlugins(cfg *config.EmitterConfig, logger *slog.Logger) ([]posture.Plugin, error) {
	pluginNames := strings.Split(cfg.Plugins, ",")
	var plugins []posture.Plugin

	for _, name := range pluginNames {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}

		switch name {
		case "stdout":
			plugins = append(plugins, posture.NewStdoutPlugin(nil))
			logger.Info("registered plugin", slog.String("name", "stdout"))

		case "defender":
			if cfg.DefenderSubscriptionID == "" {
				return nil, fmt.Errorf("defender plugin requires DEFENDER_SUBSCRIPTION_ID")
			}
			return nil, fmt.Errorf("defender plugin selected but no SDK client is configured in this build")

		case "security-hub":
			if cfg.AWSAccountID == "" || cfg.AWSRegion == "" || cfg.SecurityHubArn == "" {
				return nil, fmt.Errorf("security-hub plugin requires AWS_ACCOUNT_ID, AWS_REGION, and SECURITY_HUB_PRODUCT_ARN")
			}
			return nil, fmt.Errorf("security-hub plugin selected but no SDK client is configured in this build")

		case "scc":
			if cfg.GCPSourceName == "" || cfg.GCPProjectID == "" {
				return nil, fmt.Errorf("scc plugin requires GCP_SCC_SOURCE_NAME and GCP_PROJECT_ID")
			}
			return nil, fmt.Errorf("scc plugin selected but no SDK client is configured in this build")

		default:
			return nil, fmt.Errorf("unknown plugin: %s", name)
		}
	}

	if len(plugins) == 0 {
		return nil, fmt.Errorf("at least one posture emitter plugin must be configured")
	}

	return plugins, nil
}

func levelFromEnv(env config.Environment) string {
	switch env {
	case config.EnvProduction:
		return "info"
	case config.EnvStaging:
		return "info"
	default:
		return "debug"
	}
}
