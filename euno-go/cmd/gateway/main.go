// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

// Binary gateway is the Euno Tool Gateway service.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/edgeobs/euno-platform/euno-go/internal/gateway"
	"github.com/edgeobs/euno-platform/euno-go/pkg/callcounter"
	"github.com/edgeobs/euno-platform/euno-go/pkg/capability"
	"github.com/edgeobs/euno-platform/euno-go/pkg/config"
	"github.com/edgeobs/euno-platform/euno-go/pkg/enforcement"
	"github.com/edgeobs/euno-platform/euno-go/pkg/killswitch"
	"github.com/edgeobs/euno-platform/euno-go/pkg/observability"
	"github.com/edgeobs/euno-platform/euno-go/pkg/revocation"
)

const (
	shutdownTimeout = 30 * time.Second
	readTimeout     = 10 * time.Second
	writeTimeout    = 60 * time.Second
	idleTimeout     = 120 * time.Second
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Load config
	cfg := config.LoadOrExit[config.GatewayConfig]("GATEWAY")

	// Initialize logger
	logger := observability.NewLogger(observability.LogConfig{
		Level:       levelFromEnv(cfg.NodeEnv),
		Format:      "json",
		ServiceName: "gateway",
		Version:     "0.1.0",
	})

	slog.SetDefault(logger)
	logger.Info("starting gateway",
		slog.Int("port", cfg.Port),
		slog.Int("adminPort", cfg.AdminPort),
		slog.String("env", string(cfg.NodeEnv)),
	)

	// Initialize metrics
	metrics := observability.NewMetricsRegistry("euno", "gateway")

	// Initialize backends (in-memory for Stage 2)
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ks := killswitch.NewInMemory()
	revStore := revocation.NewInMemory()
	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)

	// JWT verifier (noop for Stage 2; will be JWKS-based in integration)
	var jwtVerifier gateway.JWTVerifier = &noopVerifier{}
	if cfg.IssuerJWKSURL != "" {
		logger.Info("JWKS URL configured", slog.String("url", cfg.IssuerJWKSURL))
		// In production, this would be a JWKS-based verifier
	}

	// Build gateway app
	deps := gateway.Dependencies{
		Engine:      engine,
		KillSwitch:  ks,
		Revocation:  revStore,
		JWTVerifier: jwtVerifier,
		DPoPStore:   dpopStore,
		Logger:      logger,
		Metrics:     metrics,
	}

	var allowedOrigins []string
	if cfg.AllowedOrigins != "" {
		allowedOrigins = strings.Split(cfg.AllowedOrigins, ",")
	}

	appCfg := gateway.Config{
		BackendURL:        cfg.BackendServiceURL,
		GatewayAudience:   cfg.GatewayAudience,
		IssuerJWKSURL:     cfg.IssuerJWKSURL,
		RequireKID:        cfg.RequireKID,
		AllowedOrigins:    allowedOrigins,
		RateLimitRequests: cfg.RateLimitMaxRequests,
		RateLimitWindow:   time.Duration(cfg.RateLimitWindowMS) * time.Millisecond,
		AdminAPIKey:       cfg.AdminAPIKey,
	}

	app := gateway.New(appCfg, deps)

	// Create main server
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      app.Handler(),
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	// Create admin server (bound to localhost)
	adminAddr := fmt.Sprintf("127.0.0.1:%d", cfg.AdminPort)
	if cfg.AdminHost != "" {
		adminAddr = fmt.Sprintf("%s:%d", cfg.AdminHost, cfg.AdminPort)
	}

	adminSrv := &http.Server{
		Addr:         adminAddr,
		Handler:      app.Handler(), // TODO: separate admin router in Stage 6
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	// Start servers
	errCh := make(chan error, 2)

	go func() {
		logger.Info("public server listening", slog.String("addr", srv.Addr))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("public server: %w", err)
		}
	}()

	go func() {
		ln, err := net.Listen("tcp", adminSrv.Addr)
		if err != nil {
			errCh <- fmt.Errorf("admin listener: %w", err)
			return
		}
		logger.Info("admin server listening", slog.String("addr", adminSrv.Addr))
		if err := adminSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("admin server: %w", err)
		}
	}()

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-sigCh:
		logger.Info("received shutdown signal", slog.String("signal", sig.String()))
	case err := <-errCh:
		return err
	}

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	logger.Info("shutting down gracefully", slog.Duration("timeout", shutdownTimeout))

	// Shutdown both servers
	shutdownErr := srv.Shutdown(ctx)
	if err := adminSrv.Shutdown(ctx); err != nil && shutdownErr == nil {
		shutdownErr = err
	}

	if shutdownErr != nil {
		return fmt.Errorf("shutdown: %w", shutdownErr)
	}

	logger.Info("shutdown complete")
	return nil
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

// noopVerifier is a placeholder JWT verifier for development without JWKS.
type noopVerifier struct{}

func (v *noopVerifier) VerifyToken(_ context.Context, _ string) (*capability.TokenPayload, error) {
	return nil, fmt.Errorf("JWT verification not configured (set ISSUER_JWKS_URL)")
}
