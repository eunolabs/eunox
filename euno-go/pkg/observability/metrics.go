// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package observability

import (
	"github.com/prometheus/client_golang/prometheus"
)

// MetricsRegistry wraps a Prometheus registry with helper methods for common metric types.
type MetricsRegistry struct {
	Registry  *prometheus.Registry
	Namespace string
	Subsystem string
}

// NewMetricsRegistry creates a new metrics registry with the given namespace.
func NewMetricsRegistry(namespace, subsystem string) *MetricsRegistry {
	return &MetricsRegistry{
		Registry:  prometheus.NewRegistry(),
		Namespace: namespace,
		Subsystem: subsystem,
	}
}

// NewCounter creates and registers a new counter.
func (m *MetricsRegistry) NewCounter(name, help string, labels ...string) *prometheus.CounterVec {
	c := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: m.Namespace,
		Subsystem: m.Subsystem,
		Name:      name,
		Help:      help,
	}, labels)
	m.Registry.MustRegister(c)
	return c
}

// NewHistogram creates and registers a new histogram.
func (m *MetricsRegistry) NewHistogram(name, help string, buckets []float64, labels ...string) *prometheus.HistogramVec {
	h := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: m.Namespace,
		Subsystem: m.Subsystem,
		Name:      name,
		Help:      help,
		Buckets:   buckets,
	}, labels)
	m.Registry.MustRegister(h)
	return h
}

// NewGauge creates and registers a new gauge.
func (m *MetricsRegistry) NewGauge(name, help string, labels ...string) *prometheus.GaugeVec {
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: m.Namespace,
		Subsystem: m.Subsystem,
		Name:      name,
		Help:      help,
	}, labels)
	m.Registry.MustRegister(g)
	return g
}

// DefaultHTTPBuckets provides standard HTTP request duration buckets (in seconds).
var DefaultHTTPBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
