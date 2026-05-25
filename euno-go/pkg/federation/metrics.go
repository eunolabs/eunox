// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package federation

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds Prometheus metrics for the federation package.
type Metrics struct {
	CircuitBreakerState *prometheus.GaugeVec
	ResolutionTotal     *prometheus.CounterVec
	ResolutionDuration  *prometheus.HistogramVec
}

// NewMetrics creates and registers federation Prometheus metrics.
func NewMetrics(registry prometheus.Registerer) *Metrics {
	m := &Metrics{
		CircuitBreakerState: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "euno",
			Subsystem: "partner_did",
			Name:      "circuit_breaker_state",
			Help:      "Current circuit breaker state per DID method as one-hot gauges by state label (1=current state, 0=other states)",
		}, []string{"did_method", "state"}),
		ResolutionTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "euno",
			Subsystem: "partner_did",
			Name:      "resolution_total",
			Help:      "Total DID resolution attempts by method and outcome",
		}, []string{"did_method", "outcome"}),
		ResolutionDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "euno",
			Subsystem: "partner_did",
			Name:      "resolution_duration_seconds",
			Help:      "Duration of DID resolution requests",
			Buckets:   []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		}, []string{"did_method"}),
	}

	if registry != nil {
		registry.MustRegister(m.CircuitBreakerState)
		registry.MustRegister(m.ResolutionTotal)
		registry.MustRegister(m.ResolutionDuration)
	}

	return m
}

// UpdateCircuitBreakerMetrics updates the circuit breaker state gauge from the resolver's states.
func (m *Metrics) UpdateCircuitBreakerMetrics(states map[string]CircuitBreakerState) {
	if m == nil || m.CircuitBreakerState == nil {
		return
	}

	for method, state := range states {
		// Reset all states for this method.
		m.CircuitBreakerState.WithLabelValues(method, "closed").Set(0)
		m.CircuitBreakerState.WithLabelValues(method, "open").Set(0)
		m.CircuitBreakerState.WithLabelValues(method, "half-open").Set(0)

		// Set the current state.
		m.CircuitBreakerState.WithLabelValues(method, string(state)).Set(1)
	}
}

// RecordResolution records a DID resolution attempt.
func (m *Metrics) RecordResolution(method, outcome string, durationSeconds float64) {
	if m == nil {
		return
	}
	if m.ResolutionTotal != nil {
		m.ResolutionTotal.WithLabelValues(method, outcome).Inc()
	}
	if m.ResolutionDuration != nil {
		m.ResolutionDuration.WithLabelValues(method).Observe(durationSeconds)
	}
}
