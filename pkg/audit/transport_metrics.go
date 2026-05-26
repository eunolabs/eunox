// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"github.com/edgeobs/eunox/pkg/observability"
	"github.com/prometheus/client_golang/prometheus"
)

// TransportMetrics holds Prometheus metrics for audit transport backpressure
// and delivery observability. All metrics are optional — if nil, instrumentation
// is silently skipped.
type TransportMetrics struct {
	// BufferUtilization reports the current buffer fill ratio (0.0–1.0).
	BufferUtilization *prometheus.GaugeVec

	// EnqueueTotal counts enqueue attempts by outcome ("success" or "dropped").
	EnqueueTotal *prometheus.CounterVec

	// FlushBatchSize observes the number of records in each delivered batch.
	FlushBatchSize *prometheus.HistogramVec

	// DeliveryTotal counts delivery attempts by outcome ("success" or "failure").
	DeliveryTotal *prometheus.CounterVec

	// DeliveryDurationSeconds observes the wall-clock time of each delivery call.
	DeliveryDurationSeconds *prometheus.HistogramVec
}

// DefaultBatchSizeBuckets provides histogram buckets for batch size observations.
var DefaultBatchSizeBuckets = []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000}

// DefaultDeliveryDurationBuckets provides histogram buckets for delivery duration (seconds).
var DefaultDeliveryDurationBuckets = []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}

// NewTransportMetrics registers and returns a TransportMetrics instance using
// the provided MetricsRegistry. The transport label allows distinguishing
// between multiple transport instances (e.g., "http", "azure_sentinel").
func NewTransportMetrics(reg *observability.MetricsRegistry) *TransportMetrics {
	if reg == nil {
		return nil
	}

	return &TransportMetrics{
		BufferUtilization: reg.NewGauge(
			"transport_buffer_utilization_ratio",
			"Current buffer fill ratio (0.0 to 1.0).",
			"transport",
		),
		EnqueueTotal: reg.NewCounter(
			"transport_enqueue_total",
			"Total enqueue attempts by outcome.",
			"transport", "outcome",
		),
		FlushBatchSize: reg.NewHistogram(
			"transport_flush_batch_size",
			"Number of records per delivered batch.",
			DefaultBatchSizeBuckets,
			"transport",
		),
		DeliveryTotal: reg.NewCounter(
			"transport_delivery_total",
			"Total delivery attempts by outcome.",
			"transport", "outcome",
		),
		DeliveryDurationSeconds: reg.NewHistogram(
			"transport_delivery_duration_seconds",
			"Duration of batch delivery operations in seconds.",
			DefaultDeliveryDurationBuckets,
			"transport",
		),
	}
}

// observeEnqueue records an enqueue outcome.
func (m *TransportMetrics) observeEnqueue(transport, outcome string) {
	if m == nil || m.EnqueueTotal == nil {
		return
	}
	m.EnqueueTotal.WithLabelValues(transport, outcome).Inc()
}

// observeBufferUtilization records the current buffer fill ratio.
func (m *TransportMetrics) observeBufferUtilization(transport string, used, capacity int) {
	if m == nil || m.BufferUtilization == nil {
		return
	}
	if capacity <= 0 {
		return
	}
	m.BufferUtilization.WithLabelValues(transport).Set(float64(used) / float64(capacity))
}

// observeFlushBatch records the batch size of a flush operation.
func (m *TransportMetrics) observeFlushBatch(transport string, size int) {
	if m == nil || m.FlushBatchSize == nil {
		return
	}
	m.FlushBatchSize.WithLabelValues(transport).Observe(float64(size))
}

// observeDelivery records a delivery outcome and duration.
func (m *TransportMetrics) observeDelivery(transport, outcome string, durationSeconds float64) {
	if m == nil {
		return
	}
	if m.DeliveryTotal != nil {
		m.DeliveryTotal.WithLabelValues(transport, outcome).Inc()
	}
	if m.DeliveryDurationSeconds != nil {
		m.DeliveryDurationSeconds.WithLabelValues(transport).Observe(durationSeconds)
	}
}
