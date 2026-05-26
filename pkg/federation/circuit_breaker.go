// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package federation

import (
	"time"

	"github.com/edgeobs/eunox/pkg/circuitbreaker"
)

// CircuitBreakerState represents the state of a circuit breaker.
type CircuitBreakerState = circuitbreaker.State

const (
	// StateClosed means the circuit is operating normally.
	StateClosed = circuitbreaker.StateClosed
	// StateOpen means the circuit has tripped due to failures.
	StateOpen = circuitbreaker.StateOpen
	// StateHalfOpen means the circuit is testing with limited probes.
	StateHalfOpen = circuitbreaker.StateHalfOpen
)

// CircuitBreakerConfig configures a circuit breaker.
type CircuitBreakerConfig struct {
	// FailureThreshold is the number of consecutive failures before opening.
	FailureThreshold int
	// CooldownDuration is how long to remain open before transitioning to half-open.
	CooldownDuration time.Duration
	// HalfOpenMaxProbes is the number of probe requests allowed in half-open state.
	HalfOpenMaxProbes int
}

// CircuitBreaker wraps the shared circuitbreaker.Breaker.
type CircuitBreaker = circuitbreaker.Breaker

// NewCircuitBreaker creates a new circuit breaker with the given configuration.
func NewCircuitBreaker(cfg CircuitBreakerConfig) *CircuitBreaker {
	return circuitbreaker.New(circuitbreaker.Config{
		FailureThreshold:  cfg.FailureThreshold,
		CooldownDuration:  cfg.CooldownDuration,
		HalfOpenMaxProbes: cfg.HalfOpenMaxProbes,
	})
}

// newCircuitBreakerWithClock creates a circuit breaker with a custom time source (for testing).
func newCircuitBreakerWithClock(cfg CircuitBreakerConfig, clock func() time.Time) *CircuitBreaker {
	return circuitbreaker.New(circuitbreaker.Config{
		FailureThreshold:  cfg.FailureThreshold,
		CooldownDuration:  cfg.CooldownDuration,
		HalfOpenMaxProbes: cfg.HalfOpenMaxProbes,
	}, circuitbreaker.WithClock(clock))
}

// CircuitBreakerStats holds circuit breaker statistics.
type CircuitBreakerStats = circuitbreaker.Stats
