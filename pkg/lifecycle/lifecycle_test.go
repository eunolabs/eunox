// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package lifecycle

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManager_ReadyHealthy(t *testing.T) {
	m := New()

	// Initially not ready, but healthy.
	assert.False(t, m.IsReady())
	assert.True(t, m.IsHealthy())

	m.SetReady()
	assert.True(t, m.IsReady())

	m.SetNotReady()
	assert.False(t, m.IsReady())

	m.SetUnhealthy()
	assert.False(t, m.IsHealthy())
}

func TestManager_HealthHandler(t *testing.T) {
	m := New()

	rec := httptest.NewRecorder()
	m.HealthHandler()(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", http.NoBody))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "healthy")

	m.SetUnhealthy()
	rec = httptest.NewRecorder()
	m.HealthHandler()(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", http.NoBody))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestManager_ReadyHandler(t *testing.T) {
	m := New()

	rec := httptest.NewRecorder()
	m.ReadyHandler()(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", http.NoBody))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	m.SetReady()
	rec = httptest.NewRecorder()
	m.ReadyHandler()(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", http.NoBody))
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestManager_OnStop(t *testing.T) {
	m := New(WithDrainDelay(0), WithShutdownTimeout(5*time.Second))

	called := false
	m.OnStop(func() { called = true })

	// Trigger shutdown directly.
	err := m.shutdown()
	require.NoError(t, err)
	assert.True(t, called)
	assert.False(t, m.IsReady())
}

func TestManager_Stopped(t *testing.T) {
	m := New(WithDrainDelay(0))

	select {
	case <-m.Stopped():
		t.Fatal("should not be stopped yet")
	default:
	}

	_ = m.shutdown()

	select {
	case <-m.Stopped():
		// OK
	case <-time.After(time.Second):
		t.Fatal("should be stopped")
	}
}

func TestManager_RunContextCancel(t *testing.T) {
	m := New(WithDrainDelay(0), WithShutdownTimeout(2*time.Second))

	srv := &http.Server{Addr: "127.0.0.1:0", Handler: http.NewServeMux(), ReadHeaderTimeout: 10 * time.Second}
	m.AddServer("test", srv)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- m.Run(ctx)
	}()

	// Give server time to start.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for shutdown")
	}
}

func TestManager_MultipleShutdownIdempotent(t *testing.T) {
	m := New(WithDrainDelay(0))
	counter := 0
	m.OnStop(func() { counter++ })

	_ = m.shutdown()
	_ = m.shutdown()
	assert.Equal(t, 1, counter, "OnStop should only be called once")
}

func TestManager_RunServerStartFailureTriggersShutdown(t *testing.T) {
	m := New(WithDrainDelay(0), WithShutdownTimeout(2*time.Second))

	healthyListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	healthyAddr := healthyListener.Addr().String()
	require.NoError(t, healthyListener.Close())

	conflictListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() {
		_ = conflictListener.Close()
	}()

	m.AddServer("healthy", &http.Server{
		Addr:              healthyAddr,
		Handler:           http.NewServeMux(),
		ReadHeaderTimeout: time.Second,
	})
	m.AddServer("conflict", &http.Server{
		Addr:              conflictListener.Addr().String(),
		Handler:           http.NewServeMux(),
		ReadHeaderTimeout: time.Second,
	})

	err = m.Run(context.Background())
	require.Error(t, err)

	select {
	case <-m.Stopped():
	case <-time.After(time.Second):
		t.Fatal("expected manager shutdown to start after server start failure")
	}
}

func TestManager_AddServerWithListener(t *testing.T) {
	t.Parallel()

	// Pre-bind a listener on an ephemeral port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()

	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	m := New(WithDrainDelay(0), WithShutdownTimeout(2*time.Second))
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}
	m.AddServerWithListener("test-srv", srv, ln)
	m.SetReady()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- m.Run(ctx)
	}()

	// Give the server time to accept connections.
	time.Sleep(50 * time.Millisecond)

	// The server should be reachable on the pre-bound address.
	resp, httpErr := http.Get("http://" + addr + "/ping")
	require.NoError(t, httpErr)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Trigger shutdown.
	cancel()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for shutdown")
	}
}
