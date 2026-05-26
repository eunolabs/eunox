// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package lifecycle provides graceful startup and shutdown management for
// Euno services, including connection draining, readiness gates, and
// coordinated multi-server lifecycle.
package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Manager coordinates the lifecycle of multiple HTTP servers with graceful
// startup, readiness gates, and shutdown procedures.
type Manager struct {
	logger          *slog.Logger
	shutdownTimeout time.Duration
	drainDelay      time.Duration

	ready   atomic.Bool
	healthy atomic.Bool

	servers []*serverEntry
	onStop  []func()

	mu       sync.Mutex
	stopOnce sync.Once
	stopCh   chan struct{}
}

type serverEntry struct {
	name   string
	server *http.Server
}

// Option configures the Manager.
type Option func(*Manager)

// WithLogger sets the logger for lifecycle events.
func WithLogger(l *slog.Logger) Option {
	return func(m *Manager) { m.logger = l }
}

// WithShutdownTimeout sets the maximum time to wait for graceful shutdown.
func WithShutdownTimeout(d time.Duration) Option {
	return func(m *Manager) { m.shutdownTimeout = d }
}

// WithDrainDelay sets the delay between receiving shutdown signal and
// starting to drain connections. This allows load balancers to update
// their endpoint list before the server stops accepting new connections.
func WithDrainDelay(d time.Duration) Option {
	return func(m *Manager) { m.drainDelay = d }
}

// New creates a new lifecycle Manager.
func New(opts ...Option) *Manager {
	m := &Manager{
		logger:          slog.Default(),
		shutdownTimeout: 30 * time.Second,
		drainDelay:      5 * time.Second,
		stopCh:          make(chan struct{}),
	}
	m.healthy.Store(true)
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// AddServer registers an HTTP server for lifecycle management.
func (m *Manager) AddServer(name string, srv *http.Server) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.servers = append(m.servers, &serverEntry{name: name, server: srv})
}

// OnStop registers a callback to be invoked during shutdown (after servers
// are stopped). Useful for closing database connections, flushing buffers, etc.
func (m *Manager) OnStop(fn func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onStop = append(m.onStop, fn)
}

// SetReady marks the service as ready to receive traffic. Should be called
// after all initialization (DB migrations, cache warm-up, etc.) is complete.
func (m *Manager) SetReady() {
	m.ready.Store(true)
	m.logger.Info("service is ready")
}

// SetNotReady marks the service as not ready (e.g., during shutdown drain).
func (m *Manager) SetNotReady() {
	m.ready.Store(false)
}

// IsReady returns whether the service is ready.
func (m *Manager) IsReady() bool {
	return m.ready.Load()
}

// IsHealthy returns whether the service is healthy.
func (m *Manager) IsHealthy() bool {
	return m.healthy.Load()
}

// SetUnhealthy marks the service as unhealthy.
func (m *Manager) SetUnhealthy() {
	m.healthy.Store(false)
}

// HealthHandler returns an http.HandlerFunc for liveness probes.
func (m *Manager) HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if m.IsHealthy() {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"status":"healthy"}`)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprint(w, `{"status":"unhealthy"}`)
		}
	}
}

// ReadyHandler returns an http.HandlerFunc for readiness probes.
func (m *Manager) ReadyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if m.IsReady() {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"status":"ready"}`)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprint(w, `{"status":"not_ready"}`)
		}
	}
}

// Run starts all registered servers and blocks until a shutdown signal is
// received (SIGTERM, SIGINT) or a server fails to start. It then performs
// graceful shutdown with connection draining.
func (m *Manager) Run(ctx context.Context) error {
	errCh := make(chan error, len(m.servers))

	// Start servers.
	for _, entry := range m.servers {
		go func(e *serverEntry) {
			m.logger.Info("starting server", slog.String("name", e.name), slog.String("addr", e.server.Addr))
			if err := e.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("server %s: %w", e.name, err)
			}
		}(entry)
	}

	// Wait for shutdown signal or server error.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigCh)

	select {
	case sig := <-sigCh:
		m.logger.Info("received shutdown signal", slog.String("signal", sig.String()))
	case err := <-errCh:
		m.logger.Error("server failed", slog.String("error", err.Error()))
		shutdownErr := m.shutdown()
		if shutdownErr != nil {
			return errors.Join(err, shutdownErr)
		}
		return err
	case <-ctx.Done():
		m.logger.Info("context cancelled")
	}

	return m.shutdown()
}

func (m *Manager) shutdown() error {
	var shutdownErr error
	m.stopOnce.Do(func() {
		close(m.stopCh)

		// Mark not ready immediately (K8s readiness probe will fail).
		m.SetNotReady()

		// Drain delay: allow load balancer to remove this endpoint.
		if m.drainDelay > 0 {
			m.logger.Info("drain delay", slog.Duration("delay", m.drainDelay))
			time.Sleep(m.drainDelay)
		}

		// Shutdown servers with timeout.
		ctx, cancel := context.WithTimeout(context.Background(), m.shutdownTimeout)
		defer cancel()

		for _, entry := range m.servers {
			m.logger.Info("shutting down server", slog.String("name", entry.name))
			if err := entry.server.Shutdown(ctx); err != nil {
				m.logger.Error("shutdown error", slog.String("name", entry.name), slog.String("error", err.Error()))
				if shutdownErr == nil {
					shutdownErr = err
				}
			}
		}

		// Run onStop callbacks.
		for _, fn := range m.onStop {
			fn()
		}

		m.logger.Info("shutdown complete")
	})
	return shutdownErr
}

// Stopped returns a channel that is closed when shutdown begins.
func (m *Manager) Stopped() <-chan struct{} {
	return m.stopCh
}
