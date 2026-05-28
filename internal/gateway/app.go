// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package gateway implements the Tool Gateway HTTP service.
package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/edgeobs/eunox/pkg/capability"
	"github.com/edgeobs/eunox/pkg/did"
	"github.com/edgeobs/eunox/pkg/enforcement"
	"github.com/edgeobs/eunox/pkg/federation"
	"github.com/edgeobs/eunox/pkg/killswitch"
	"github.com/edgeobs/eunox/pkg/observability"
	"github.com/edgeobs/eunox/pkg/ratelimit"
	"github.com/edgeobs/eunox/pkg/revocation"
	"github.com/prometheus/client_golang/prometheus"
)

const defaultAdminRateLimitPerMinute = 10
const defaultPublicRateLimitPerMinute = 600

// RateLimiter extends [ratelimit.DetailedLimiter] with lifecycle management.
// Both [ratelimit.InMemoryLimiter] and [ratelimit.ResilientRedisLimiter]
// satisfy this interface.
type RateLimiter interface {
	ratelimit.DetailedLimiter
	// Close stops any background goroutines started by the limiter.
	Close()
}

// Config holds the gateway application configuration.
type Config struct {
	BackendURL        string
	GatewayAudience   string
	IssuerJWKSURL     string
	RequireKID        bool
	AllowedOrigins    []string
	RateLimitRequests int
	RateLimitWindow   time.Duration
	AdminAPIKey       string
	TenantID          string
	TelemetryEnabled  bool
	TelemetryFlushMS  int

	// Environment is the deployment environment (development, staging, production).
	// Used for security validation warnings (e.g., CORS wildcard in production).
	Environment string

	// AdminJWKSURI is the JWKS endpoint for admin JWT verification.
	// When set, admin JWT auth is preferred over static key auth.
	AdminJWKSURI string
	// AdminJWTAudience is the expected audience in admin JWTs.
	AdminJWTAudience string

	// AdminRateLimitPerMinute is the maximum number of admin requests per source IP per minute.
	// Defaults to 10 if not set.
	AdminRateLimitPerMinute int

	// MaxRequestBodySize is the maximum size of request bodies in bytes.
	// Defaults to 1 MB (1048576) if not set.
	MaxRequestBodySize int64

	// TrustedProxyCIDRs is the list of CIDR blocks (e.g. "10.0.0.0/8") whose
	// requests are permitted to set the X-Forwarded-For header.  When this list
	// is non-empty and the immediate peer (RemoteAddr) matches one of the CIDRs,
	// the rightmost untrusted IP in XFF is used as the client IP for enforcement.
	// When the list is empty, XFF is ignored and RemoteAddr is always used.
	TrustedProxyCIDRs []string

	// IsReady is an optional function consulted by the GET /health/ready handler.
	// When nil the handler always returns 200; when non-nil it returns 503 while
	// the function returns false (e.g. during the lifecycle drain delay).
	IsReady func() bool

	// TokenCacheTTL controls the maximum duration a verified capability token
	// payload is retained in the in-process cache. On a cache hit the gateway
	// skips JWKS re-verification and the Redis revocation round-trip, reducing
	// enforce-path latency for repeated calls in pipeline-agent workloads.
	//
	// Set to 0 to disable the token cache entirely (full verification on every
	// request). Set to a positive value to enable caching; values above 60 s
	// are not recommended because they widen the window during which a revoked
	// token continues to be accepted.
	//
	// Default when unset: token caching is disabled.
	TokenCacheTTL time.Duration

	// TokenCacheSize is the maximum number of entries in the token cache.
	// Defaults to 4096 when TokenCacheTTL > 0.
	TokenCacheSize int

	// SidecarMode enables sidecar deployment mode (P3-2). When true the gateway
	// rejects enforcement requests for agents other than SidecarAgentID with 403.
	// SidecarAgentID is required when SidecarMode is true.
	SidecarMode    bool
	SidecarAgentID string
}

// Dependencies holds the injected backends for the gateway.
type Dependencies struct {
	Engine          *enforcement.Engine
	KillSwitch      killswitch.Manager
	Revocation      revocation.Store
	JWTVerifier     JWTVerifier
	DPoPStore       DPoPJTIStore
	PartnerDIDStore PartnerDIDStore
	Logger          *slog.Logger
	Metrics         *observability.MetricsRegistry
	Audit           *AuditDependencies

	// PublicRateLimiter is used for the /api/v1/enforce and /validate endpoints.
	// When nil, New() creates an in-memory limiter using Config.RateLimitRequests
	// and Config.RateLimitWindow.  Supply a [ratelimit.ResilientRedisLimiter] in
	// multi-replica deployments so that rate-limit state is shared across replicas.
	PublicRateLimiter RateLimiter

	// Partner federation (Stage 7).
	PartnerResolver   *federation.PartnerIssuerResolver
	IONResolver       *did.IONResolver
	FederationMetrics *federation.Metrics
}

// App is the gateway HTTP application.
type App struct {
	config            Config
	deps              Dependencies
	router            chi.Router
	adminRouter       chi.Router
	proxy             *httputil.ReverseProxy
	metrics           *gatewayMetrics
	dpopStore         DPoPJTIStore
	adminAuth         AdminAuthenticator
	adminRateLimiter  *ratelimit.InMemoryLimiter
	publicRateLimiter RateLimiter
	idempotency       *IdempotencyStore
	usageTracker      *UsageTracker
	adminDeps         AdminDependencies
	ionHealthChecker  *IONHealthChecker
	trustedProxyNets  []*net.IPNet
	tokenCache        *capability.TokenCache
}

type gatewayMetrics struct {
	enforceDuration *prometheus.HistogramVec
	enforceTotal    *prometheus.CounterVec
	proxyDuration   *prometheus.HistogramVec
	proxyTotal      *prometheus.CounterVec
}

// New creates a new gateway App with the given configuration and dependencies.
// Returns an error if the configuration is invalid for the runtime environment
// (e.g. CORS wildcard is not permitted in production).
func New(cfg *Config, deps *Dependencies) (*App, error) {
	// Finding 4: Fail-closed on CORS wildcard in production.
	if cfg.Environment == "production" {
		for _, origin := range cfg.AllowedOrigins {
			if origin == "*" {
				return nil, fmt.Errorf("CORS wildcard (*) not allowed in production; configure explicit AllowedOrigins")
			}
		}
	}

	// Sidecar mode validation (P3-2): SidecarAgentID is required when SidecarMode is enabled.
	if cfg.SidecarMode && cfg.SidecarAgentID == "" {
		return nil, fmt.Errorf("GATEWAY_SIDECAR_AGENT_ID is required when GATEWAY_SIDECAR_MODE=true")
	}

	app := &App{
		config: *cfg,
		deps:   *deps,
	}

	// Finding 1: Parse trusted proxy CIDRs for X-Forwarded-For handling.
	// Malformed CIDRs are treated as fatal configuration errors so that a
	// typo in this security-critical setting causes a clear startup failure
	// rather than silently disabling XFF handling.
	for _, cidr := range cfg.TrustedProxyCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid TrustedProxyCIDR %q: %w", cidr, err)
		}
		app.trustedProxyNets = append(app.trustedProxyNets, ipNet)
	}

	app.metrics = app.initMetrics()
	app.dpopStore = deps.DPoPStore
	app.usageTracker = NewUsageTracker()
	app.idempotency = NewIdempotencyStore()

	// Initialize the in-process token cache when enabled (P2-2).
	// When TokenCacheTTL > 0 the enforcement hot path skips JWKS re-verification
	// and the Redis revocation round-trip for tokens seen within the cache window.
	if cfg.TokenCacheTTL > 0 {
		app.tokenCache = capability.NewTokenCache(capability.TokenCacheConfig{
			MaxEntryTTL:     cfg.TokenCacheTTL,
			MaxSize:         cfg.TokenCacheSize,
			CleanupInterval: cfg.TokenCacheTTL,
		})
	}

	// Set up admin authentication.
	if cfg.AdminJWKSURI != "" || cfg.AdminAPIKey != "" {
		if cfg.TenantID == "" {
			if deps.Logger != nil {
				deps.Logger.Error("admin authentication disabled: tenant ID is required when admin auth is configured")
			}
		} else {
			app.adminAuth = NewCombinedAdminAuth(CombinedAdminAuthConfig{
				JWKSURI:     cfg.AdminJWKSURI,
				JWTAudience: cfg.AdminJWTAudience,
				AdminKey:    cfg.AdminAPIKey,
				TenantID:    cfg.TenantID,
				Logger:      deps.Logger,
			})
		}
	}

	// Initialize partner DID store.
	partnerDIDStore := deps.PartnerDIDStore
	if partnerDIDStore == nil {
		partnerDIDStore = NewInMemoryPartnerDIDStore()
	}
	app.adminDeps = AdminDependencies{
		PartnerDIDs: partnerDIDStore,
	}

	// Initialize partner token verifier if resolver is configured.
	if deps.PartnerResolver != nil {
		partnerVerifier := NewPartnerTokenVerifier(PartnerTokenVerifierConfig{
			Resolver: deps.PartnerResolver,
			Audience: cfg.GatewayAudience,
		})

		app.deps.JWTVerifier = NewMultiIssuerVerifier(MultiIssuerVerifierConfig{
			LocalVerifier:   app.deps.JWTVerifier,
			PartnerVerifier: partnerVerifier,
		})
	}

	// Initialize ION health checker if resolver is configured.
	if deps.IONResolver != nil {
		app.ionHealthChecker = NewIONHealthChecker(deps.IONResolver)
	}

	// Initialize admin rate limiter.
	adminRateLimit := cfg.AdminRateLimitPerMinute
	if adminRateLimit <= 0 {
		adminRateLimit = defaultAdminRateLimitPerMinute
	}
	app.adminRateLimiter = ratelimit.NewInMemory(ratelimit.Config{
		Rate:   adminRateLimit,
		Window: time.Minute,
		Burst:  adminRateLimit,
	})

	// Initialize public API rate limiter.
	// Keyed on client IP (respects trusted proxy CIDRs for XFF) to defend
	// against unauthenticated callers hammering /api/v1/enforce or /validate.
	// When deps.PublicRateLimiter is provided (e.g. a ResilientRedisLimiter in
	// multi-replica deployments) it is used as-is; otherwise we construct an
	// in-memory limiter (suitable for single-replica / development only).
	if deps.PublicRateLimiter != nil {
		app.publicRateLimiter = deps.PublicRateLimiter
	} else {
		publicRateLimit := cfg.RateLimitRequests
		if publicRateLimit <= 0 {
			publicRateLimit = defaultPublicRateLimitPerMinute
		}
		publicRateLimitWindow := cfg.RateLimitWindow
		if publicRateLimitWindow <= 0 {
			publicRateLimitWindow = time.Minute
		}
		app.publicRateLimiter = ratelimit.NewInMemory(ratelimit.Config{
			Rate:   publicRateLimit,
			Window: publicRateLimitWindow,
			Burst:  publicRateLimit,
		})
	}

	app.router = app.buildRouter()
	app.adminRouter = app.buildAdminRouter()

	if cfg.BackendURL != "" {
		target, err := url.Parse(cfg.BackendURL)
		if err == nil {
			app.proxy = httputil.NewSingleHostReverseProxy(target)
		}
	}

	return app, nil
}

// Handler returns the http.Handler for the gateway public API.
func (app *App) Handler() http.Handler {
	return app.router
}

// AdminHandler returns the http.Handler for the admin API (bind to localhost).
func (app *App) AdminHandler() http.Handler {
	return app.adminRouter
}

// Start launches background goroutines required by the App, including the
// idempotency store's periodic cleanup.  ctx controls the lifetime of these
// goroutines — they stop when ctx is cancelled.
//
// Start should be called once after [New] and before serving requests.
func (app *App) Start(ctx context.Context) {
	if app.idempotency != nil {
		app.idempotency.Start(ctx)
	}
	if app.tokenCache != nil {
		app.tokenCache.Start(ctx)
	}
}

// Close releases resources held by the App, stopping background goroutines
// started by the in-memory rate limiters and the token cache.
func (app *App) Close() {
	if app.adminRateLimiter != nil {
		app.adminRateLimiter.Close()
	}
	if app.publicRateLimiter != nil {
		app.publicRateLimiter.Close()
	}
	if app.tokenCache != nil {
		app.tokenCache.Stop()
	}
}

func (app *App) initMetrics() *gatewayMetrics {
	if app.deps.Metrics == nil {
		return nil
	}
	return &gatewayMetrics{
		enforceDuration: app.deps.Metrics.NewHistogram(
			"enforce_duration_seconds",
			"Duration of enforce decisions",
			observability.DefaultHTTPBuckets,
			"decision",
		),
		enforceTotal: app.deps.Metrics.NewCounter(
			"enforce_total",
			"Total enforce decisions",
			"decision",
		),
		proxyDuration: app.deps.Metrics.NewHistogram(
			"proxy_duration_seconds",
			"Duration of proxied requests",
			observability.DefaultHTTPBuckets,
			"method", "status",
		),
		proxyTotal: app.deps.Metrics.NewCounter(
			"proxy_total",
			"Total proxied requests",
			"method", "status",
		),
	}
}

func (app *App) buildRouter() chi.Router {
	r := chi.NewRouter()

	// Global middleware
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.RequestID)
	r.Use(observability.TracePropagation("gateway"))

	if app.deps.Logger != nil {
		r.Use(observability.RequestLogging(app.deps.Logger))
	}

	// CORS
	if len(app.config.AllowedOrigins) > 0 {
		r.Use(app.corsMiddleware)
	}

	// Health endpoints (no auth required)
	r.Get("/health/live", app.handleLive)
	r.Get("/health/ready", app.handleReady)
	r.Get("/healthz/did-ion", app.handleDIDIONHealth)

	// Public API routes
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(app.publicRateLimitMiddleware)

		// Sidecar mode (P3-2): enforce that requests are only for the configured agent.
		if app.config.SidecarMode {
			r.Use(app.sidecarAgentMiddleware)
		}

		r.Post("/enforce", app.handleEnforce)
		r.Post("/validate", app.handleValidate)

		// Audit routes (read-only) — auth enforced by auditAuthMiddleware.
		r.Route("/audit", func(r chi.Router) {
			r.Use(app.auditAuthMiddleware)
			r.Get("/records", app.handleAuditRecords)
			r.Get("/export", app.handleAuditExport)
			r.Get("/signing-keys", app.handleAuditSigningKeys)
			r.Get("/chain-proof", app.handleAuditChainProof)
		})
	})

	// Proxy route
	r.HandleFunc("/proxy/*", app.handleProxy)

	return r
}

func (app *App) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && app.isAllowedOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-ID, DPoP, X-Session-ID, X-Tool-Name")
			w.Header().Set("Access-Control-Max-Age", "86400")
			w.Header().Set("Vary", "Origin")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (app *App) isAllowedOrigin(origin string) bool {
	for _, allowed := range app.config.AllowedOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}
	return false
}
