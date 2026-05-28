// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eunolabs/eunox/pkg/observability"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestMetricsRegistry() *observability.MetricsRegistry {
	return observability.NewMetricsRegistry("eunox", "audit")
}

func getCounterValue(t *testing.T, counter *prometheus.CounterVec, labels ...string) float64 {
	t.Helper()
	m := &dto.Metric{}
	err := counter.WithLabelValues(labels...).Write(m)
	require.NoError(t, err)
	return m.GetCounter().GetValue()
}

func getGaugeValue(t *testing.T, gauge *prometheus.GaugeVec, labels ...string) float64 {
	t.Helper()
	m := &dto.Metric{}
	err := gauge.WithLabelValues(labels...).Write(m)
	require.NoError(t, err)
	return m.GetGauge().GetValue()
}

func getHistogramCount(t *testing.T, hist *prometheus.HistogramVec, labels ...string) uint64 {
	t.Helper()
	m := &dto.Metric{}
	observer := hist.WithLabelValues(labels...)
	// HistogramVec.WithLabelValues returns an Observer; cast to prometheus.Histogram for Write.
	err := observer.(prometheus.Metric).Write(m)
	require.NoError(t, err)
	return m.GetHistogram().GetSampleCount()
}

func TestNewTransportMetrics_NilRegistry(t *testing.T) {
	t.Parallel()
	m := NewTransportMetrics(nil)
	assert.Nil(t, m)
}

func TestNewTransportMetrics_RegistersAllMetrics(t *testing.T) {
	t.Parallel()
	reg := newTestMetricsRegistry()
	m := NewTransportMetrics(reg)
	require.NotNil(t, m)
	assert.NotNil(t, m.BufferUtilization)
	assert.NotNil(t, m.EnqueueTotal)
	assert.NotNil(t, m.FlushBatchSize)
	assert.NotNil(t, m.DeliveryTotal)
	assert.NotNil(t, m.DeliveryDurationSeconds)
}

func TestTransportMetrics_ObserveEnqueue_NilSafe(t *testing.T) {
	t.Parallel()
	// Should not panic.
	var m *TransportMetrics
	m.observeEnqueue("http", "success")
}

func TestTransportMetrics_ObserveBufferUtilization_NilSafe(t *testing.T) {
	t.Parallel()
	var m *TransportMetrics
	m.observeBufferUtilization("http", 50, 100)
}

func TestTransportMetrics_ObserveFlushBatch_NilSafe(t *testing.T) {
	t.Parallel()
	var m *TransportMetrics
	m.observeFlushBatch("http", 10)
}

func TestTransportMetrics_ObserveDelivery_NilSafe(t *testing.T) {
	t.Parallel()
	var m *TransportMetrics
	m.observeDelivery("http", "success", 1.0)
}

func TestHTTPTransport_Enqueue_MetricsRecorded(t *testing.T) {
	t.Parallel()

	reg := newTestMetricsRegistry()
	metrics := NewTransportMetrics(reg)

	transport := NewHTTPTransport(&HTTPTransportConfig{
		TransportConfig: TransportConfig{
			BatchSize:     10,
			FlushInterval: 1 * time.Hour,
			MaxRetries:    1,
			RetryBackoff:  10 * time.Millisecond,
			BufferSize:    5,
		},
		Endpoint: "http://localhost:9999",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithHTTPTransportMetrics(metrics))
	defer func() { _ = transport.Close() }()

	ev := &SignedAuditEvidence{
		Record:    LogEntry{ID: "1", EventType: "test", Action: "a"},
		Signature: "sig",
		ChainHash: "hash",
	}

	// Successful enqueue.
	err := transport.Enqueue(ev)
	require.NoError(t, err)

	assert.Equal(t, float64(1), getCounterValue(t, metrics.EnqueueTotal, "http", "success"))
	assert.Greater(t, getGaugeValue(t, metrics.BufferUtilization, "http"), float64(0))

	// Fill the buffer to trigger a drop.
	for i := 0; i < 10; i++ {
		_ = transport.Enqueue(ev)
	}

	assert.Greater(t, getCounterValue(t, metrics.EnqueueTotal, "http", "dropped"), float64(0))
}

func TestHTTPTransport_Delivery_MetricsRecorded(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	reg := newTestMetricsRegistry()
	metrics := NewTransportMetrics(reg)

	transport := NewHTTPTransport(&HTTPTransportConfig{
		TransportConfig: TransportConfig{
			BatchSize:     10,
			FlushInterval: 1 * time.Hour,
			MaxRetries:    1,
			RetryBackoff:  10 * time.Millisecond,
			BufferSize:    100,
		},
		Endpoint: server.URL,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithHTTPTransportMetrics(metrics))
	defer func() { _ = transport.Close() }()

	records := []SignedAuditEvidence{
		{Record: LogEntry{ID: "1", EventType: "test", Action: "a"}, Signature: "s", ChainHash: "h"},
		{Record: LogEntry{ID: "2", EventType: "test", Action: "a"}, Signature: "s", ChainHash: "h"},
	}

	err := transport.Send(context.Background(), records)
	require.NoError(t, err)

	assert.Equal(t, float64(1), getCounterValue(t, metrics.DeliveryTotal, "http", "success"))
	assert.Equal(t, uint64(1), getHistogramCount(t, metrics.DeliveryDurationSeconds, "http"))
}

func TestHTTPTransport_DeliveryFailure_MetricsRecorded(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	reg := newTestMetricsRegistry()
	metrics := NewTransportMetrics(reg)

	transport := NewHTTPTransport(&HTTPTransportConfig{
		TransportConfig: TransportConfig{
			BatchSize:     10,
			FlushInterval: 1 * time.Hour,
			MaxRetries:    0,
			RetryBackoff:  1 * time.Millisecond,
			BufferSize:    100,
		},
		Endpoint: server.URL,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithHTTPTransportMetrics(metrics))
	defer func() { _ = transport.Close() }()

	records := []SignedAuditEvidence{
		{Record: LogEntry{ID: "1", EventType: "test", Action: "a"}, Signature: "s", ChainHash: "h"},
	}

	err := transport.Send(context.Background(), records)
	require.Error(t, err)

	assert.Equal(t, float64(1), getCounterValue(t, metrics.DeliveryTotal, "http", "failure"))
}

func TestHTTPTransport_FlushBatchSize_MetricsRecorded(t *testing.T) {
	t.Parallel()

	var receivedBatches int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch []json.RawMessage
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &batch)
		receivedBatches++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	reg := newTestMetricsRegistry()
	metrics := NewTransportMetrics(reg)

	transport := NewHTTPTransport(&HTTPTransportConfig{
		TransportConfig: TransportConfig{
			BatchSize:     2,
			FlushInterval: 50 * time.Millisecond,
			MaxRetries:    1,
			RetryBackoff:  1 * time.Millisecond,
			BufferSize:    100,
		},
		Endpoint: server.URL,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithHTTPTransportMetrics(metrics))

	ev := &SignedAuditEvidence{
		Record:    LogEntry{ID: "1", EventType: "test", Action: "a"},
		Signature: "s",
		ChainHash: "h",
	}

	// Enqueue 3 events — should trigger at least one batch.
	for i := 0; i < 3; i++ {
		require.NoError(t, transport.Enqueue(ev))
	}

	// Wait for flush.
	time.Sleep(200 * time.Millisecond)
	_ = transport.Close()

	assert.Greater(t, getHistogramCount(t, metrics.FlushBatchSize, "http"), uint64(0))
}

func TestAzureSentinelTransport_Enqueue_MetricsRecorded(t *testing.T) {
	t.Parallel()

	reg := newTestMetricsRegistry()
	metrics := NewTransportMetrics(reg)

	transport := NewAzureSentinelTransport(&AzureSentinelConfig{
		TransportConfig: TransportConfig{
			BatchSize:     10,
			FlushInterval: 1 * time.Hour,
			MaxRetries:    1,
			RetryBackoff:  10 * time.Millisecond,
			BufferSize:    3,
		},
		WorkspaceID: "test-workspace",
		SharedKey:   "",
		Endpoint:    "http://localhost:9999",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithAzureSentinelTransportMetrics(metrics))
	defer func() { _ = transport.Close() }()

	ev := &SignedAuditEvidence{
		Record:    LogEntry{ID: "1", EventType: "test", Action: "a"},
		Signature: "sig",
		ChainHash: "hash",
	}

	err := transport.Enqueue(ev)
	require.NoError(t, err)

	assert.Equal(t, float64(1), getCounterValue(t, metrics.EnqueueTotal, "azure_sentinel", "success"))

	// Fill and overflow.
	for i := 0; i < 5; i++ {
		_ = transport.Enqueue(ev)
	}
	assert.Greater(t, getCounterValue(t, metrics.EnqueueTotal, "azure_sentinel", "dropped"), float64(0))
}

func TestAzureSentinelTransport_Delivery_MetricsRecorded(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	reg := newTestMetricsRegistry()
	metrics := NewTransportMetrics(reg)

	transport := NewAzureSentinelTransport(&AzureSentinelConfig{
		TransportConfig: TransportConfig{
			BatchSize:     10,
			FlushInterval: 1 * time.Hour,
			MaxRetries:    1,
			RetryBackoff:  1 * time.Millisecond,
			BufferSize:    100,
		},
		WorkspaceID: "test-workspace",
		SharedKey:   "",
		Endpoint:    server.URL,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithAzureSentinelTransportMetrics(metrics))
	defer func() { _ = transport.Close() }()

	records := []SignedAuditEvidence{
		{Record: LogEntry{ID: "1", EventType: "test", Action: "a"}, Signature: "s", ChainHash: "h"},
	}

	err := transport.Send(context.Background(), records)
	require.NoError(t, err)

	assert.Equal(t, float64(1), getCounterValue(t, metrics.DeliveryTotal, "azure_sentinel", "success"))
	assert.Equal(t, uint64(1), getHistogramCount(t, metrics.DeliveryDurationSeconds, "azure_sentinel"))
}

func TestTransportMetrics_BufferUtilization_ZeroCapacity(t *testing.T) {
	t.Parallel()
	reg := newTestMetricsRegistry()
	m := NewTransportMetrics(reg)
	// Should not panic or set value for zero capacity.
	m.observeBufferUtilization("http", 5, 0)
	// Gauge should not have been set — we verify by checking it doesn't exist yet.
	// Since WithLabelValues creates the metric, we just verify no panic.
}

func TestHTTPTransport_NoMetrics_NoPanic(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// No metrics option — should work without panicking.
	transport := NewHTTPTransport(&HTTPTransportConfig{
		TransportConfig: TransportConfig{
			BatchSize:     10,
			FlushInterval: 1 * time.Hour,
			MaxRetries:    1,
			RetryBackoff:  10 * time.Millisecond,
			BufferSize:    100,
		},
		Endpoint: server.URL,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer func() { _ = transport.Close() }()

	ev := &SignedAuditEvidence{
		Record:    LogEntry{ID: "1", EventType: "test", Action: "a"},
		Signature: "s",
		ChainHash: "h",
	}

	require.NoError(t, transport.Enqueue(ev))

	records := []SignedAuditEvidence{*ev}
	require.NoError(t, transport.Send(context.Background(), records))
}
