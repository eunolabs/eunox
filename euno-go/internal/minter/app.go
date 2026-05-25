// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package minter

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/edgeobs/euno-platform/euno-go/pkg/observability"
	"github.com/edgeobs/euno-platform/euno-go/pkg/ratelimit"
)

const maxBodySize = 1 << 20 // 1 MB

// Config holds the minter application configuration.
type Config struct {
	Pepper          *Pepper
	DefaultTenantID string
	AdminAPIKey     string
}

// Dependencies holds the injected backends for the minter.
type Dependencies struct {
	Store         KeyStore
	Auth          AdminAuthenticator
	Anomaly       AnomalyDetector
	PingLimiter   ratelimit.Limiter
	Logger        *slog.Logger
	Metrics       *observability.MetricsRegistry
}

// App is the API-Key Minter HTTP application.
type App struct {
	config  Config
	deps    Dependencies
	router  chi.Router
	metrics *minterMetrics
}

type minterMetrics struct {
	keysCreated  *prometheus.CounterVec
	keysRevoked  *prometheus.CounterVec
	pingTotal    *prometheus.CounterVec
	pingDuration *prometheus.HistogramVec
}

// New creates a new minter App.
func New(cfg Config, deps Dependencies) *App {
	app := &App{
		config: cfg,
		deps:   deps,
	}
	app.metrics = app.initMetrics()
	app.router = app.buildRouter()
	return app
}

// Handler returns the http.Handler for the minter.
func (app *App) Handler() http.Handler {
	return app.router
}

func (app *App) initMetrics() *minterMetrics {
	if app.deps.Metrics == nil {
		return nil
	}
	return &minterMetrics{
		keysCreated: app.deps.Metrics.NewCounter(
			"minter_keys_created_total",
			"Total API keys created",
			"tenant_id",
		),
		keysRevoked: app.deps.Metrics.NewCounter(
			"minter_keys_revoked_total",
			"Total API keys revoked",
			"tenant_id",
		),
		pingTotal: app.deps.Metrics.NewCounter(
			"minter_ping_total",
			"Total ping requests",
			"status",
		),
		pingDuration: app.deps.Metrics.NewHistogram(
			"minter_ping_duration_seconds",
			"Duration of ping verification",
			observability.DefaultHTTPBuckets,
			"status",
		),
	}
}

func (app *App) buildRouter() chi.Router {
	r := chi.NewRouter()

	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.RequestID)

	if app.deps.Logger != nil {
		r.Use(observability.RequestLogging(app.deps.Logger))
	}

	// Health endpoints.
	r.Get("/health/live", app.handleLive)
	r.Get("/health/ready", app.handleReady)

	// Public API routes.
	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/ping", app.handlePing)
	})

	// Admin routes (require authentication).
	r.Route("/admin/v1", func(r chi.Router) {
		r.Use(app.adminAuthMiddleware)

		r.Post("/keys", app.handleCreateKey)
		r.Get("/keys", app.handleListKeys)
		r.Delete("/keys/{keyId}", app.handleRevokeKey)

		r.Post("/policies", app.handleCreatePolicy)
		r.Get("/policies", app.handleListPolicies)
	})

	return r
}

func (app *App) adminAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		operatorID, err := app.deps.Auth.Authenticate(r.Context(), r)
		if err != nil {
			app.writeError(w, http.StatusUnauthorized, "unauthorized", err.Error())
			return
		}
		// Store operator ID in context for audit logging.
		ctx := withOperatorID(r.Context(), operatorID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// handleLive returns 200 if the service is alive.
func (app *App) handleLive(w http.ResponseWriter, _ *http.Request) {
	app.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReady returns 200 if the service is ready to accept requests.
func (app *App) handleReady(w http.ResponseWriter, _ *http.Request) {
	app.writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// handlePing verifies an API key without revealing the secret hash.
func (app *App) handlePing(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Rate limit by IP.
	if app.deps.PingLimiter != nil {
		clientIP := extractClientIP(r)
		allowed, err := app.deps.PingLimiter.Allow(r.Context(), clientIP)
		if err != nil {
			app.writeError(w, http.StatusInternalServerError, "internal_error", "rate limiter error")
			return
		}
		if !allowed {
			app.recordPingMetric("rate_limited", start)
			app.writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
			return
		}
	}

	var req struct {
		Key string `json:"key"`
	}
	if err := app.readJSON(r, &req); err != nil {
		app.recordPingMetric("invalid_request", start)
		app.writeError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}

	keyID, secret, err := ParseKey(req.Key)
	if err != nil {
		app.recordPingMetric("invalid_key", start)
		app.writeError(w, http.StatusBadRequest, "invalid_key", "invalid key format")
		return
	}

	key, err := app.deps.Store.GetKey(r.Context(), keyID)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			app.recordPingMetric("not_found", start)
			app.writeError(w, http.StatusUnauthorized, "invalid_key", "key not found")
			return
		}
		app.recordPingMetric("error", start)
		app.writeError(w, http.StatusInternalServerError, "internal_error", "key lookup failed")
		return
	}

	if key.IsRevoked() {
		app.recordPingMetric("revoked", start)
		app.writeError(w, http.StatusForbidden, "key_revoked", "key has been revoked")
		return
	}

	if key.IsExpired(time.Now()) {
		app.recordPingMetric("expired", start)
		app.writeError(w, http.StatusForbidden, "key_expired", "key has expired")
		return
	}

	if !app.config.Pepper.VerifySecret(secret, key.SecretHash) {
		app.recordPingMetric("invalid_secret", start)
		app.writeError(w, http.StatusUnauthorized, "invalid_key", "invalid key")
		return
	}

	app.recordPingMetric("valid", start)
	app.writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":    true,
		"keyId":    key.KeyID,
		"tenantId": key.TenantID,
	})
}

// handleCreateKey mints a new API key.
func (app *App) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	operatorID := getOperatorID(r.Context())
	tenantID := app.config.DefaultTenantID

	var req struct {
		TenantID    string            `json:"tenantId"`
		Description string            `json:"description"`
		ExpiresIn   int               `json:"expiresInSeconds"`
		Metadata    map[string]string `json:"metadata"`
	}
	if err := app.readJSON(r, &req); err != nil {
		app.writeError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}
	if req.TenantID != "" {
		tenantID = req.TenantID
	}

	// Check velocity.
	if err := app.deps.Anomaly.CheckVelocity(r.Context(), tenantID); err != nil {
		app.writeError(w, http.StatusTooManyRequests, "velocity_exceeded",
			"mint rate exceeds configured threshold")
		return
	}

	// Mint the key.
	result, err := MintKey(app.config.Pepper)
	if err != nil {
		app.writeError(w, http.StatusInternalServerError, "mint_failed", "failed to generate key")
		return
	}

	// Compute expiry.
	var expiresAt *time.Time
	if req.ExpiresIn > 0 {
		t := time.Now().Add(time.Duration(req.ExpiresIn) * time.Second)
		expiresAt = &t
	}

	apiKey := &APIKey{
		KeyID:       result.KeyID,
		SecretHash:  result.SecretHash,
		TenantID:    tenantID,
		Description: req.Description,
		CreatedAt:   time.Now(),
		ExpiresAt:   expiresAt,
		CreatedBy:   operatorID,
		Metadata:    req.Metadata,
	}

	if err := app.deps.Store.CreateKey(r.Context(), apiKey); err != nil {
		app.writeError(w, http.StatusInternalServerError, "store_failed", "failed to store key")
		return
	}

	// Record for anomaly detection.
	_ = app.deps.Anomaly.RecordMint(r.Context(), tenantID)

	if app.metrics != nil {
		app.metrics.keysCreated.WithLabelValues(tenantID).Inc()
	}

	if app.deps.Logger != nil {
		app.deps.Logger.InfoContext(r.Context(), "API key created",
			"keyId", result.KeyID,
			"tenantId", tenantID,
			"operatorId", operatorID,
		)
	}

	app.writeJSON(w, http.StatusCreated, map[string]interface{}{
		"keyId":       result.KeyID,
		"key":         result.FullKey,
		"tenantId":    tenantID,
		"description": req.Description,
		"createdAt":   apiKey.CreatedAt,
		"expiresAt":   expiresAt,
	})
}

// handleListKeys lists API keys for a tenant (metadata only, no secrets).
func (app *App) handleListKeys(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenantId")
	if tenantID == "" {
		tenantID = app.config.DefaultTenantID
	}

	keys, err := app.deps.Store.ListKeys(r.Context(), tenantID, 100, 0)
	if err != nil {
		app.writeError(w, http.StatusInternalServerError, "list_failed", "failed to list keys")
		return
	}

	if keys == nil {
		keys = []*APIKey{}
	}
	app.writeJSON(w, http.StatusOK, map[string]interface{}{
		"keys": keys,
	})
}

// handleRevokeKey revokes an API key.
func (app *App) handleRevokeKey(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "keyId")
	operatorID := getOperatorID(r.Context())

	err := app.deps.Store.RevokeKey(r.Context(), keyID, time.Now())
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			app.writeError(w, http.StatusNotFound, "not_found", "key not found")
			return
		}
		if errors.Is(err, ErrKeyRevoked) {
			app.writeError(w, http.StatusConflict, "already_revoked", "key already revoked")
			return
		}
		app.writeError(w, http.StatusInternalServerError, "revoke_failed", "failed to revoke key")
		return
	}

	// Get key for tenant ID metric.
	key, _ := app.deps.Store.GetKey(r.Context(), keyID)
	tenantID := ""
	if key != nil {
		tenantID = key.TenantID
	}

	if app.metrics != nil && tenantID != "" {
		app.metrics.keysRevoked.WithLabelValues(tenantID).Inc()
	}

	if app.deps.Logger != nil {
		app.deps.Logger.InfoContext(r.Context(), "API key revoked",
			"keyId", keyID,
			"operatorId", operatorID,
		)
	}

	app.writeJSON(w, http.StatusOK, map[string]string{
		"status": "revoked",
		"keyId":  keyID,
	})
}

// handleCreatePolicy creates a new key policy.
func (app *App) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	operatorID := getOperatorID(r.Context())

	var req struct {
		TenantID    string     `json:"tenantId"`
		Name        string     `json:"name"`
		Description string     `json:"description"`
		Rules       PolicyRule `json:"rules"`
	}
	if err := app.readJSON(r, &req); err != nil {
		app.writeError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}
	if req.Name == "" {
		app.writeError(w, http.StatusBadRequest, "invalid_request", "name is required")
		return
	}

	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = app.config.DefaultTenantID
	}

	now := time.Now()
	p := &Policy{
		PolicyID:    fmt.Sprintf("pol_%s", generateShortID()),
		TenantID:    tenantID,
		Name:        req.Name,
		Description: req.Description,
		Rules:       req.Rules,
		CreatedAt:   now,
		UpdatedAt:   now,
		CreatedBy:   operatorID,
	}

	if err := app.deps.Store.CreatePolicy(r.Context(), p); err != nil {
		if errors.Is(err, ErrPolicyExists) {
			app.writeError(w, http.StatusConflict, "policy_exists",
				"a policy with this name already exists for the tenant")
			return
		}
		app.writeError(w, http.StatusInternalServerError, "create_failed", "failed to create policy")
		return
	}

	if app.deps.Logger != nil {
		app.deps.Logger.InfoContext(r.Context(), "policy created",
			"policyId", p.PolicyID,
			"name", p.Name,
			"tenantId", tenantID,
			"operatorId", operatorID,
		)
	}

	app.writeJSON(w, http.StatusCreated, p)
}

// handleListPolicies lists policies for a tenant.
func (app *App) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenantId")
	if tenantID == "" {
		tenantID = app.config.DefaultTenantID
	}

	policies, err := app.deps.Store.ListPolicies(r.Context(), tenantID)
	if err != nil {
		app.writeError(w, http.StatusInternalServerError, "list_failed", "failed to list policies")
		return
	}

	if policies == nil {
		policies = []*Policy{}
	}
	app.writeJSON(w, http.StatusOK, map[string]interface{}{
		"policies": policies,
	})
}

// --- Helpers ---

func (app *App) writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (app *App) writeError(w http.ResponseWriter, status int, code, message string) {
	app.writeJSON(w, status, map[string]string{
		"error":   code,
		"message": message,
	})
}

func (app *App) readJSON(r *http.Request, v interface{}) error {
	r.Body = http.MaxBytesReader(nil, r.Body, maxBodySize)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (app *App) recordPingMetric(status string, start time.Time) {
	if app.metrics == nil {
		return
	}
	app.metrics.pingTotal.WithLabelValues(status).Inc()
	app.metrics.pingDuration.WithLabelValues(status).Observe(time.Since(start).Seconds())
}

func extractClientIP(r *http.Request) string {
	// Check X-Forwarded-For first.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	// Fall back to RemoteAddr.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func generateShortID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
