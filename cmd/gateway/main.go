// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Binary gateway is the Euno Tool Gateway service.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/edgeobs/eunox/internal/gateway"
	"github.com/edgeobs/eunox/pkg/callcounter"
	"github.com/edgeobs/eunox/pkg/capability"
	"github.com/edgeobs/eunox/pkg/circuitbreaker"
	"github.com/edgeobs/eunox/pkg/config"
	"github.com/edgeobs/eunox/pkg/enforcement"
	"github.com/edgeobs/eunox/pkg/killswitch"
	"github.com/edgeobs/eunox/pkg/lifecycle"
	"github.com/edgeobs/eunox/pkg/observability"
	"github.com/edgeobs/eunox/pkg/redisfailover"
	"github.com/edgeobs/eunox/pkg/revocation"
)

// These variables are set by GoReleaser via -X ldflags at build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const (
	drainDelay      = 5 * time.Second
	shutdownTimeout = 30 * time.Second
	readTimeout     = 10 * time.Second
	writeTimeout    = 60 * time.Second
	idleTimeout     = 120 * time.Second
)

var loadGatewayConfig = func() config.GatewayConfig {
	return config.LoadOrExit[config.GatewayConfig]("GATEWAY")
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Root context — cancel() is called explicitly after the shutdown signal is
	// received to unblock all in-flight operations tied to this context.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Load config
	cfg := loadGatewayConfig()

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
	logger.Info("deployment tier", slog.String("tier", string(cfg.DeploymentTier)))

	if cfg.NodeEnv == config.EnvProduction && cfg.IssuerJWKSURL == "" {
		return fmt.Errorf("GATEWAY_ISSUER_JWKS_URL is required in production; missing JWKS URL means every enforcement call will fail (DI-2 in docs/architecture-review.md)")
	}

	// Production Redis HA validation (requires Sentinel/Cluster URLs; single-node is rejected).
	if cfg.NodeEnv == config.EnvProduction {
		if err := config.CheckGatewayRedisHA(&cfg); err != nil {
			return fmt.Errorf("redis HA validation: %w", err)
		}
		logger.Info("redis HA validation passed")
	}

	// Production requires Redis to be configured for stateful security components (CR-1).
	if err := validateRedisConfig(&cfg); err != nil {
		return err
	}

	// Initialize metrics
	metrics := observability.NewMetricsRegistry("euno", "gateway")

	// Build stateful backends (Redis-backed when URLs are configured; in-memory fallback for dev).
	backends, err := buildGatewayBackends(&cfg, logger)
	if err != nil {
		return fmt.Errorf("build gateway backends: %w", err)
	}

	// Start the kill switch (connects to Redis and performs initial state load).
	// The type assertion handles both ResilientRedis (Redis-backed) and InMemory (no Start needed).
	if starter, ok := backends.killSwitch.(interface{ Start(context.Context) }); ok {
		starter.Start(ctx)
	}

	engine := enforcement.New(enforcement.WithCallCounter(backends.counter))
	dpopStore := gateway.NewInMemoryDPoPStore(5 * time.Minute)
	if cfg.NodeEnv == config.EnvProduction {
		logger.Warn("DPoP replay protection: using in-memory store; DPoP nonces are not shared across replicas — deploy a single gateway replica or add a Redis-backed DPoP store")
	}
	dpopStore.Start(ctx)

	// JWT verifier — JWKS-based when configured; noop fallback for development.
	var jwtVerifier gateway.JWTVerifier
	if cfg.IssuerJWKSURL != "" {
		logger.Info("configuring JWKS-based JWT verification", slog.String("url", cfg.IssuerJWKSURL))
		jwksBreaker := circuitbreaker.New(circuitbreaker.Config{
			FailureThreshold:  5,
			CooldownDuration:  30 * time.Second,
			HalfOpenMaxProbes: 2,
		})
		jwtVerifier = gateway.NewJWKSVerifier(gateway.JWKSVerifierConfig{
			JWKSURL:    cfg.IssuerJWKSURL,
			Audience:   cfg.GatewayAudience,
			RequireKID: cfg.RequireKID,
			CacheTTL:   time.Duration(cfg.JWKSCacheTTL) * time.Second,
			Logger:     logger,
			Breaker:    jwksBreaker,
		})
	} else {
		jwtVerifier = &noopVerifier{}
	}

	// Build gateway app
	deps := gateway.Dependencies{
		Engine:          engine,
		KillSwitch:      backends.killSwitch,
		Revocation:      backends.revocation,
		JWTVerifier:     jwtVerifier,
		DPoPStore:       dpopStore,
		PartnerDIDStore: backends.partnerDIDs,
		Logger:          logger,
		Metrics:         metrics,
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
	if err := validateAdminAuth(&cfg, tenantID); err != nil {
		return err
	}
	if cfg.NodeEnv == config.EnvProduction && cfg.AdminAPIKey != "" {
		logger.Warn("static ADMIN_API_KEY is deprecated in production; use JWT admin auth (GATEWAY_ADMIN_JWKS_URI) exclusively. The static key will be removed in a future release")
	}

	// Build lifecycle manager with drain delay so that load balancers stop
	// routing traffic before connections are torn down.
	lm := lifecycle.New(
		lifecycle.WithDrainDelay(drainDelay),
		lifecycle.WithShutdownTimeout(shutdownTimeout),
		lifecycle.WithLogger(logger),
	)

	appCfg := gateway.Config{
		BackendURL:              cfg.BackendServiceURL,
		GatewayAudience:         cfg.GatewayAudience,
		IssuerJWKSURL:           cfg.IssuerJWKSURL,
		RequireKID:              cfg.RequireKID,
		AllowedOrigins:          allowedOrigins,
		RateLimitRequests:       cfg.RateLimitMaxRequests,
		RateLimitWindow:         time.Duration(cfg.RateLimitWindowMS) * time.Millisecond,
		AdminAPIKey:             cfg.AdminAPIKey,
		AdminJWKSURI:            cfg.AdminJWKSURI,
		AdminJWTAudience:        cfg.AdminJWTAudience,
		TenantID:                tenantID,
		TelemetryEnabled:        telemetryEnabled,
		TelemetryFlushMS:        cfg.TelemetryFlushMS,
		AdminRateLimitPerMinute: cfg.AdminRateLimitPerMinute,
		MaxRequestBodySize:      int64(cfg.MaxRequestBodySize),
		Environment:             string(cfg.NodeEnv),
		TrustedProxyCIDRs:       cfg.TrustedProxyCIDRs,
		// IsReady lets handleReady reflect the lifecycle drain state so that load
		// balancers remove this instance from rotation before connections drain.
		// It also incorporates Redis health: a degraded backend marks the instance
		// as not-ready so that load balancers avoid routing to a degraded gateway.
		IsReady: func() bool {
			return lm.IsReady() && backends.monitor.IsReady()
		},
	}

	app, err := gateway.New(&appCfg, &deps)
	if err != nil {
		return fmt.Errorf("gateway configuration error: %w", err)
	}

	// Create main server
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           app.Handler(),
		ReadHeaderTimeout: readTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	// Create admin server (bound to localhost). Pre-bind the listener so that
	// we can restrict it to the loopback interface before handing it to the
	// lifecycle manager's Serve call.
	adminAddr := fmt.Sprintf("127.0.0.1:%d", cfg.AdminPort)
	if cfg.AdminHost != "" {
		adminAddr = fmt.Sprintf("%s:%d", cfg.AdminHost, cfg.AdminPort)
	}

	adminLn, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", adminAddr)
	if err != nil {
		return fmt.Errorf("admin listener: %w", err)
	}

	adminSrv := &http.Server{
		Addr:              adminAddr,
		Handler:           app.AdminHandler(),
		ReadHeaderTimeout: readTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	lm.AddServer("public", srv)
	lm.AddServerWithListener("admin", adminSrv, adminLn)

	// Mark the service ready only after all initialization is complete.  The
	// lifecycle manager's SetNotReady → drain → shutdown sequence will flip
	// IsReady back to false before connections are drained on shutdown.
	lm.SetReady()

	// Cancel the root context (stopping background goroutines like dpopStore)
	// when the lifecycle manager shuts down.
	lm.OnStop(cancel)
	// Close the in-memory rate limiters to stop their background cleanup goroutines.
	lm.OnStop(app.Close)

	return lm.Run(context.Background())
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

// resolveRedisURL returns specificURL if non-empty, otherwise fallbackURL.
// Use this to let per-service Redis URLs override the shared REDIS_URL.
func resolveRedisURL(specificURL, fallbackURL string) string {
	if specificURL != "" {
		return specificURL
	}
	return fallbackURL
}

// hasSecurityRedisConfigured returns true when the stateful security backends
// (kill-switch, revocation, call-counter) are covered by a Redis URL.
// REDIS_URL alone is sufficient; alternatively all three per-service URLs must
// be set. PartnerDIDsRedisURL alone does not satisfy this requirement because
// it does not cover the kill-switch, revocation, or call-counter stores.
func hasSecurityRedisConfigured(cfg *config.GatewayConfig) bool {
	return cfg.RedisURL != "" ||
		(cfg.KillSwitchRedisURL != "" && cfg.RevocationRedisURL != "" && cfg.CallCounterRedisURL != "")
}

// validateRedisConfig enforces tier-aware Redis requirements for the gateway.
//
// Single-replica deployments may run entirely in memory outside production. For
// multi-replica and multi-region-active-active tiers, the stateful security
// backends (kill-switch, revocation, call-counter) must be backed by Redis so
// they are not silently split per replica. Production remains stricter: every
// stateful security backend must resolve to a Redis URL, either via REDIS_URL
// or all required per-service URLs.
func validateRedisConfig(cfg *config.GatewayConfig) error {
	if cfg.NodeEnv != config.EnvProduction {
		switch cfg.DeploymentTier {
		case config.TierMultiReplica, config.TierMultiRegionActiveActive:
			if !hasSecurityRedisConfigured(cfg) {
				return fmt.Errorf("deployment tier %q requires Redis; multi-replica gateway state cannot fall back to per-replica memory", cfg.DeploymentTier)
			}
		}
		return nil
	}
	// Shared URL covers every service.
	if cfg.RedisURL != "" {
		return nil
	}
	// All per-service URLs cover every service without requiring REDIS_URL.
	if cfg.KillSwitchRedisURL != "" && cfg.RevocationRedisURL != "" && cfg.CallCounterRedisURL != "" {
		return nil
	}
	return fmt.Errorf(
		"in production, either REDIS_URL (shared fallback) or all per-service Redis URLs " +
			"(KILL_SWITCH_REDIS_URL, REVOCATION_REDIS_URL, CALL_COUNTER_REDIS_URL) must be set; " +
			"kill-switch and revocation state is lost on restart without Redis (CR-1 in ARCHITECTURE_REVIEW.md)",
	)
}

// gatewayBackends holds the stateful backends for the gateway.
type gatewayBackends struct {
	killSwitch  killswitch.Manager
	revocation  revocation.Store
	counter     callcounter.Store
	partnerDIDs gateway.PartnerDIDStore
	monitor     *redisfailover.Monitor
}

// buildGatewayBackends creates stateful backends for the gateway.
//
// When per-service Redis URLs (e.g. KILL_SWITCH_REDIS_URL) or the shared
// REDIS_URL are set, resilient Redis-backed implementations are returned with
// proper fail-closed (kill-switch, revocation) or fail-open (call counter)
// semantics. When no Redis URL is configured the function falls back to
// in-memory stores (suitable for development only).
func buildGatewayBackends(cfg *config.GatewayConfig, logger *slog.Logger) (*gatewayBackends, error) {
	if logger == nil {
		logger = slog.Default()
	}
	monitor := redisfailover.NewMonitor()

	// Kill-switch — fail-closed: block all requests when Redis state is unknown.
	var ks killswitch.Manager
	ksURL := resolveRedisURL(cfg.KillSwitchRedisURL, cfg.RedisURL)
	if ksURL != "" {
		client, err := newRedisClientFromURL(ksURL)
		if err != nil {
			return nil, fmt.Errorf("kill-switch redis URL: %w", err)
		}
		inner := killswitch.NewRedis(client).WithLogger(logger)
		ks = killswitch.NewResilientRedis(inner, monitor.Register("kill-switch"))
		logger.Info("kill-switch: using Redis-backed store")
	} else {
		logger.Warn("kill-switch: using in-memory store; kill-switch state will be lost on restart or scale-out")
		ks = killswitch.NewInMemory()
	}

	// Revocation — fail-closed: treat tokens as revoked when Redis is unreachable.
	var rev revocation.Store
	revURL := resolveRedisURL(cfg.RevocationRedisURL, cfg.RedisURL)
	if revURL != "" {
		client, err := newRedisClientFromURL(revURL)
		if err != nil {
			return nil, fmt.Errorf("revocation redis URL: %w", err)
		}
		inner := revocation.NewRedis(client)
		rev = revocation.NewResilientRedis(inner, monitor.Register("revocation"), nil)
		logger.Info("revocation: using Redis-backed store")
	} else {
		logger.Warn("revocation: using in-memory store; revoked tokens will be re-accepted after restart")
		rev = revocation.NewInMemory()
	}

	// Call counter — fail-open: return 0 count when Redis is unreachable.
	var cc callcounter.Store
	ccURL := resolveRedisURL(cfg.CallCounterRedisURL, cfg.RedisURL)
	if ccURL != "" {
		client, err := newRedisClientFromURL(ccURL)
		if err != nil {
			return nil, fmt.Errorf("call-counter redis URL: %w", err)
		}
		cc = callcounter.NewResilientRedis(callcounter.NewRedis(client), monitor.Register("call-counter"))
		logger.Info("call-counter: using Redis-backed store")
	} else {
		cc = callcounter.NewInMemory()
	}

	var partnerDIDs gateway.PartnerDIDStore
	partnerDIDsURL := resolveRedisURL(cfg.PartnerDIDsRedisURL, cfg.RedisURL)
	if partnerDIDsURL != "" {
		client, err := newRedisClientFromURL(partnerDIDsURL)
		if err != nil {
			return nil, fmt.Errorf("partner-dids redis URL: %w", err)
		}
		partnerDIDs = gateway.NewRedisPartnerDIDStore(client)
		logger.Info("partner-dids: using Redis-backed store")
	}

	return &gatewayBackends{
		killSwitch:  ks,
		revocation:  rev,
		counter:     cc,
		partnerDIDs: partnerDIDs,
		monitor:     monitor,
	}, nil
}

// validateAdminAuth checks that admin authentication is properly configured for the
// deployment environment.
//
// JWT auth via JWKS is required in production AND staging (CR-3): staging often
// shares infrastructure with production data, so a stolen static admin key grants
// the same kill-switch and revocation powers.  Only the development environment
// may omit GATEWAY_ADMIN_JWKS_URI and fall back to a static API key.
func validateAdminAuth(cfg *config.GatewayConfig, tenantID string) error {
	adminJWKSURI := strings.TrimSpace(cfg.AdminJWKSURI)
	adminJWTAudience := strings.TrimSpace(cfg.AdminJWTAudience)
	tenantID = strings.TrimSpace(tenantID)

	// Development is the only environment exempt from JWT admin auth.
	// In development, a static admin key is acceptable; but if a JWKS URI is
	// provided, the tenant ID is still required for routing.
	if cfg.NodeEnv == config.EnvDevelopment {
		if adminJWKSURI != "" && tenantID == "" {
			return fmt.Errorf("TENANT_ID (or GATEWAY_TENANT_ID) is required when admin JWT auth is enabled")
		}
		return nil
	}

	// Production and staging both require JWT auth (CR-3).
	if adminJWKSURI == "" {
		return fmt.Errorf("GATEWAY_ADMIN_JWKS_URI is required in %q; static admin key alone is insecure (see CR-3 in docs/architecture-review.md)", cfg.NodeEnv)
	}
	if adminJWTAudience == "" {
		return fmt.Errorf("GATEWAY_ADMIN_JWT_AUDIENCE is required in %q when admin JWT auth is enabled", cfg.NodeEnv)
	}
	if tenantID == "" {
		return fmt.Errorf("TENANT_ID (or GATEWAY_TENANT_ID) is required in %q when admin JWT auth is enabled", cfg.NodeEnv)
	}
	return nil
}
