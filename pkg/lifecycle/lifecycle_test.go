// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package lifecycle

import (
	"context"
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
	m.HealthHandler()(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "healthy")

	m.SetUnhealthy()
	rec = httptest.NewRecorder()
	m.HealthHandler()(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestManager_ReadyHandler(t *testing.T) {
	m := New()

	rec := httptest.NewRecorder()
	m.ReadyHandler()(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	m.SetReady()
	rec = httptest.NewRecorder()
	m.ReadyHandler()(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil))
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
