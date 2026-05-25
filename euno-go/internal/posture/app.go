// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package posture

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/edgeobs/euno-platform/euno-go/pkg/observability"
)

// Config holds the posture emitter application configuration.
type Config struct {
	// Enabled controls whether the emitter processes events.
	Enabled bool
	// QueuePath is the SQLite database path for the durable queue.
	QueuePath string
	// FlushIntervalMS is the delivery worker poll interval in milliseconds.
	FlushIntervalMS int
	// MaxAttempts is the maximum delivery attempts before dead-lettering.
	MaxAttempts int
	// BatchSize is the number of events processed per tick.
	BatchSize int
	// PluginTimeoutMS is the per-plugin delivery timeout in milliseconds.
	PluginTimeoutMS int
	// BackoffBaseMS is the base backoff duration in milliseconds.
	BackoffBaseMS int
	// BackoffMaxMS is the maximum backoff duration in milliseconds.
	BackoffMaxMS int
	// DedupeWindowMS is the deduplication window in milliseconds.
	DedupeWindowMS int
	// HealthMaxQueueDepth is the queue depth above which the service reports unhealthy.
	HealthMaxQueueDepth int64
}

// DefaultConfig returns sensible defaults for the posture emitter.
func DefaultConfig() Config {
	return Config{
		Enabled:             true,
		QueuePath:           ":memory:",
		FlushIntervalMS:     1000,
		MaxAttempts:         10,
		BatchSize:           50,
		PluginTimeoutMS:     5000,
		BackoffBaseMS:       1000,
		BackoffMaxMS:        300000,
		DedupeWindowMS:      300000, // 5 minutes
		HealthMaxQueueDepth: 10000,
	}
}

// Dependencies holds the injected backends for the posture emitter.
type Dependencies struct {
	Logger  *slog.Logger
	Metrics *observability.MetricsRegistry
}

// App is the posture emitter HTTP application and service coordinator.
type App struct {
	config      Config
	deps        Dependencies
	router      chi.Router
	queue       Queue
	recordStore RecordStore
	worker      *DeliveryWorker
	plugins     []Plugin
	metrics     *emitterMetrics
	started     atomic.Bool
}

type emitterMetrics struct {
	queueDepth    prometheus.Gauge
	delivered     *prometheus.CounterVec
	deliveryError *prometheus.CounterVec
	deadLettered  *prometheus.CounterVec
	enqueued      *prometheus.CounterVec
}

// New creates a new posture emitter App with the given configuration, plugins, and dependencies.
func New(cfg Config, plugins []Plugin, deps Dependencies) (*App, error) {
	// Create durable queue.
	queue, err := NewSQLiteQueue(cfg.QueuePath)
	if err != nil {
		return nil, fmt.Errorf("posture emitter: create queue: %w", err)
	}

	dedupeWindow := time.Duration(cfg.DedupeWindowMS) * time.Millisecond
	recordStore := NewRecordStore(dedupeWindow)

	app := &App{
		config:      cfg,
		deps:        deps,
		queue:       queue,
		recordStore: recordStore,
		plugins:     plugins,
	}

	app.metrics = app.initMetrics()
	app.router = app.buildRouter()

	return app, nil
}

// Start begins the delivery worker.
func (app *App) Start() {
	if !app.config.Enabled || app.started.Load() {
		return
	}

	workerCfg := DeliveryWorkerConfig{
		MaxAttempts:   app.config.MaxAttempts,
		BackoffBase:   time.Duration(app.config.BackoffBaseMS) * time.Millisecond,
		BackoffMax:    time.Duration(app.config.BackoffMaxMS) * time.Millisecond,
		BatchSize:     app.config.BatchSize,
		PollInterval:  time.Duration(app.config.FlushIntervalMS) * time.Millisecond,
		PluginTimeout: time.Duration(app.config.PluginTimeoutMS) * time.Millisecond,
	}

	app.worker = NewDeliveryWorker(app.queue, app.plugins, workerCfg, app.deps.Logger, app)
	app.worker.Start()
	app.started.Store(true)

	if app.deps.Logger != nil {
		app.deps.Logger.Info("posture emitter started",
			slog.Int("plugins", len(app.plugins)),
			slog.String("queuePath", app.config.QueuePath),
		)
	}
}

// Stop gracefully shuts down the delivery worker and closes the queue.
func (app *App) Stop() {
	if app.worker != nil {
		app.worker.Stop()
	}
	if app.queue != nil {
		_ = app.queue.Close()
	}
	app.started.Store(false)
}

// Handler returns the http.Handler for the posture emitter.
func (app *App) Handler() http.Handler {
	return app.router
}

// EmitObserved enqueues an observed agent record for delivery to CSPM plugins.
// This is called synchronously by the issuer during token issuance/renewal.
func (app *App) EmitObserved(record AgentInventoryRecord) error {
	if !app.config.Enabled {
		return nil
	}

	// Apply deduplication.
	if !app.recordStore.Upsert(record) {
		return nil
	}

	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("posture emitter: marshal record: %w", err)
	}

	if _, err := app.queue.Push(EventObserved, payload); err != nil {
		return fmt.Errorf("posture emitter: enqueue observed: %w", err)
	}

	if app.metrics != nil {
		app.metrics.enqueued.WithLabelValues("observed").Inc()
	}

	return nil
}

// EmitRevoked enqueues a revocation event for delivery to CSPM plugins.
func (app *App) EmitRevoked(agentID string, revokedAt time.Time) error {
	if !app.config.Enabled {
		return nil
	}

	// Update record store.
	app.recordStore.MarkRevoked(agentID, revokedAt)

	payload, err := json.Marshal(RevokedPayload{
		AgentID:   agentID,
		RevokedAt: revokedAt,
	})
	if err != nil {
		return fmt.Errorf("posture emitter: marshal revocation: %w", err)
	}

	if _, err := app.queue.Push(EventRevoked, payload); err != nil {
		return fmt.Errorf("posture emitter: enqueue revoked: %w", err)
	}

	if app.metrics != nil {
		app.metrics.enqueued.WithLabelValues("revoked").Inc()
	}

	return nil
}

// QueueDepth returns the current number of events in the queue.
func (app *App) QueueDepth() int64 {
	depth, _ := app.queue.Depth()
	return depth
}

// --- DeliveryMetrics implementation ---

// OnDelivered records a successful delivery metric.
func (app *App) OnDelivered(eventType EventType, pluginName string) {
	if app.metrics != nil {
		app.metrics.delivered.WithLabelValues(string(eventType), pluginName).Inc()
	}
}

// OnDeliveryError records a delivery error metric.
func (app *App) OnDeliveryError(eventType EventType, pluginName string) {
	if app.metrics != nil {
		app.metrics.deliveryError.WithLabelValues(string(eventType), pluginName).Inc()
	}
}

// OnDeadLettered records a dead-lettered event metric.
func (app *App) OnDeadLettered(eventType EventType) {
	if app.metrics != nil {
		app.metrics.deadLettered.WithLabelValues(string(eventType)).Inc()
	}
}

// --- HTTP Handlers ---

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

	// API endpoints.
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/status", app.handleStatus)
		r.Post("/emit", app.handleEmit)
		r.Post("/revoke", app.handleRevoke)
	})

	return r
}

func (app *App) handleLive(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (app *App) handleReady(w http.ResponseWriter, _ *http.Request) {
	depth := app.QueueDepth()

	if depth > app.config.HealthMaxQueueDepth {
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"status":     "degraded",
			"queueDepth": depth,
			"maxDepth":   app.config.HealthMaxQueueDepth,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "ready",
		"queueDepth": depth,
	})
}

func (app *App) handleStatus(w http.ResponseWriter, _ *http.Request) {
	depth := app.QueueDepth()
	activeRecords := app.recordStore.ListActive()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":       app.config.Enabled,
		"queueDepth":    depth,
		"activeAgents":  len(activeRecords),
		"plugins":       pluginNames(app.plugins),
		"started":       app.started.Load(),
		"totalTracked":  app.recordStore.Size(),
	})
}

// EmitRequest is the request body for POST /api/v1/emit.
type EmitRequest struct {
	AgentID                string   `json:"agentId"`
	OwningTeam             string   `json:"owningTeam"`
	CapabilityManifestHash string   `json:"capabilityManifestHash"`
	Runtime                string   `json:"runtime"`
	Region                 string   `json:"region"`
	Capabilities           []string `json:"capabilities"`
}

func (app *App) handleEmit(w http.ResponseWriter, r *http.Request) {
	var req EmitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.AgentID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agentId is required"})
		return
	}

	now := time.Now().UTC()
	record := AgentInventoryRecord{
		AgentID:                req.AgentID,
		OwningTeam:             req.OwningTeam,
		CapabilityManifestHash: req.CapabilityManifestHash,
		Runtime:                req.Runtime,
		Region:                 req.Region,
		Capabilities:           req.Capabilities,
		FirstSeen:              now,
		LastSeen:               now,
	}

	if err := app.EmitObserved(record); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{"status": "queued"})
}

// RevokeRequest is the request body for POST /api/v1/revoke.
type RevokeRequest struct {
	AgentID string `json:"agentId"`
}

func (app *App) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var req RevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.AgentID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agentId is required"})
		return
	}

	if err := app.EmitRevoked(req.AgentID, time.Now().UTC()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{"status": "queued"})
}

// --- Metrics ---

func (app *App) initMetrics() *emitterMetrics {
	if app.deps.Metrics == nil {
		return nil
	}

	m := &emitterMetrics{}

	// Queue depth gauge (set periodically by the app, or pulled on /health/ready).
	queueDepthGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: app.deps.Metrics.Namespace,
		Subsystem: "posture",
		Name:      "queue_depth",
		Help:      "Number of events in the posture durable queue",
	})
	app.deps.Metrics.Registry.MustRegister(queueDepthGauge)
	m.queueDepth = queueDepthGauge

	m.delivered = app.deps.Metrics.NewCounter(
		"posture_delivered_total",
		"Total posture events successfully delivered",
		"event_type", "plugin",
	)

	m.deliveryError = app.deps.Metrics.NewCounter(
		"posture_delivery_errors_total",
		"Total posture event delivery failures",
		"event_type", "plugin",
	)

	m.deadLettered = app.deps.Metrics.NewCounter(
		"posture_dead_lettered_total",
		"Total posture events dead-lettered after max retries",
		"event_type",
	)

	m.enqueued = app.deps.Metrics.NewCounter(
		"posture_enqueued_total",
		"Total posture events enqueued",
		"event_type",
	)

	return m
}

// UpdateMetrics refreshes the queue depth gauge from the current queue state.
func (app *App) UpdateMetrics() {
	if app.metrics == nil {
		return
	}
	depth, _ := app.queue.Depth()
	app.metrics.queueDepth.Set(float64(depth))
}

// --- Helpers ---

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func pluginNames(plugins []Plugin) []string {
	names := make([]string, len(plugins))
	for i, p := range plugins {
		names[i] = p.Name()
	}
	return names
}
