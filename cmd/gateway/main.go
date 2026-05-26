// Copyright 2026 Eunox Authors
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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/edgeobs/eunox/internal/gateway"
	"github.com/edgeobs/eunox/pkg/callcounter"
	"github.com/edgeobs/eunox/pkg/capability"
	"github.com/edgeobs/eunox/pkg/config"
	"github.com/edgeobs/eunox/pkg/enforcement"
	"github.com/edgeobs/eunox/pkg/killswitch"
	"github.com/edgeobs/eunox/pkg/observability"
	"github.com/edgeobs/eunox/pkg/revocation"
)

// These variables are set by GoReleaser via -X ldflags at build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
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
	logger := observability.NewLogger(&observability.LogConfig{
		Level:       levelFromEnv(cfg.NodeEnv),
		Format:      "json",
		ServiceName: "gateway",
		Version:     version,
	})

	slog.SetDefault(logger)
	logger.Info("starting gateway",
		slog.Int("port", cfg.Port),
		slog.Int("adminPort", cfg.AdminPort),
		slog.String("commit", commit),
		slog.String("date", date),
		slog.String("env", string(cfg.NodeEnv)),
	)

	// Production Redis HA validation
	if cfg.NodeEnv == config.EnvProduction {
		if err := config.CheckGatewayRedisHA(&cfg); err != nil {
			return fmt.Errorf("redis HA validation: %w", err)
		}
		logger.Info("redis HA validation passed")
	}

	// Initialize metrics
	metrics := observability.NewMetricsRegistry("euno", "gateway")

	// Initialize backends (in-memory for Stage 2)
	counter := callcounter.NewInMemory()
	engine := enforcement.New(enforcement.WithCallCounter(counter))
	ks := killswitch.NewInMemory()
	revStore := revocation.NewInMemory()
	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)

	// JWT verifier — JWKS-based when configured; noop fallback for development.
	var jwtVerifier gateway.JWTVerifier
	if cfg.IssuerJWKSURL != "" {
		logger.Info("configuring JWKS-based JWT verification", slog.String("url", cfg.IssuerJWKSURL))
		jwtVerifier = gateway.NewJWKSVerifier(gateway.JWKSVerifierConfig{
			JWKSURL:    cfg.IssuerJWKSURL,
			Audience:   cfg.GatewayAudience,
			RequireKID: cfg.RequireKID,
			CacheTTL:   time.Duration(cfg.JWKSCacheTTL) * time.Second,
			Logger:     logger,
		})
	} else {
		jwtVerifier = &noopVerifier{}
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

	tenantID := strings.TrimSpace(cfg.TenantID)
	if tenantID == "" {
		tenantID = strings.TrimSpace(os.Getenv("TENANT_ID"))
	}
	if cfg.AdminAPIKey != "" && tenantID == "" {
		return fmt.Errorf("TENANT_ID (or GATEWAY_TENANT_ID) is required when admin API is enabled")
	}

	telemetryEnabled := cfg.TelemetryEnabled
	if raw, ok := os.LookupEnv("EUNO_TELEMETRY"); ok {
		switch strings.TrimSpace(raw) {
		case "0":
			telemetryEnabled = false
		case "1":
			telemetryEnabled = true
		default:
			parsed, err := strconv.ParseBool(raw)
			if err != nil {
				return fmt.Errorf("invalid EUNO_TELEMETRY value: %w", err)
			}
			telemetryEnabled = parsed
		}
	}

	// Production admin auth validation: JWT must be configured in production (CR-3).
	if err := validateAdminAuth(&cfg); err != nil {
		return err
	}
	if cfg.NodeEnv == config.EnvProduction && cfg.AdminAPIKey != "" {
		logger.Warn("static ADMIN_API_KEY is deprecated in production; use JWT admin auth (ADMIN_JWKS_URI) exclusively. The static key will be removed in a future release")
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
		AdminJWKSURI:      cfg.AdminJWKSURI,
		AdminJWTAudience:  cfg.AdminJWTAudience,
		TenantID:          tenantID,
		TelemetryEnabled:        telemetryEnabled,
		TelemetryFlushMS:        cfg.TelemetryFlushMS,
		AdminRateLimitPerMinute: cfg.AdminRateLimitPerMinute,
	}

	app := gateway.New(&appCfg, &deps)

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
		Handler:      app.AdminHandler(),
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

	listenConfig := net.ListenConfig{}

	go func() {
		ln, err := listenConfig.Listen(context.Background(), "tcp", adminSrv.Addr)
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
	return nil, fmt.Errorf("JWT verification not configured (set GATEWAY_ISSUER_JWKS_URL)")
}

// validateAdminAuth checks that admin authentication is properly configured for the
// deployment environment. In production, JWT auth via JWKS is required (CR-3).
func validateAdminAuth(cfg *config.GatewayConfig) error {
	if cfg.NodeEnv != config.EnvProduction {
		return nil
	}
	if cfg.AdminJWKSURI == "" {
		return fmt.Errorf("GATEWAY_ADMIN_JWKS_URI is required in production; static admin key alone is insecure (see CR-3 in ARCHITECTURE_REVIEW.md)")
	}
	return nil
}
