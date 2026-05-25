// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

// Package gateway implements the Tool Gateway HTTP service.
package gateway

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/edgeobs/euno-platform/euno-go/pkg/enforcement"
	"github.com/edgeobs/euno-platform/euno-go/pkg/killswitch"
	"github.com/edgeobs/euno-platform/euno-go/pkg/observability"
	"github.com/edgeobs/euno-platform/euno-go/pkg/revocation"
	"github.com/prometheus/client_golang/prometheus"
)

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
}

// Dependencies holds the injected backends for the gateway.
type Dependencies struct {
	Engine      *enforcement.Engine
	KillSwitch  killswitch.Manager
	Revocation  revocation.Store
	JWTVerifier JWTVerifier
	DPoPStore   DPoPJTIStore
	Logger      *slog.Logger
	Metrics     *observability.MetricsRegistry
}

// App is the gateway HTTP application.
type App struct {
	config    Config
	deps      Dependencies
	router    chi.Router
	proxy     *httputil.ReverseProxy
	metrics   *gatewayMetrics
	dpopStore DPoPJTIStore
}

type gatewayMetrics struct {
	enforceDuration *prometheus.HistogramVec
	enforceTotal    *prometheus.CounterVec
	proxyDuration   *prometheus.HistogramVec
	proxyTotal      *prometheus.CounterVec
}

// New creates a new gateway App with the given configuration and dependencies.
func New(cfg Config, deps Dependencies) *App {
	app := &App{
		config: cfg,
		deps:   deps,
	}

	app.metrics = app.initMetrics()
	app.dpopStore = deps.DPoPStore
	app.router = app.buildRouter()

	if cfg.BackendURL != "" {
		target, err := url.Parse(cfg.BackendURL)
		if err == nil {
			app.proxy = httputil.NewSingleHostReverseProxy(target)
		}
	}

	return app
}

// Handler returns the http.Handler for the gateway.
func (app *App) Handler() http.Handler {
	return app.router
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

	// Public API routes
	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/enforce", app.handleEnforce)
		r.Post("/validate", app.handleValidate)
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
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-ID, DPoP")
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
