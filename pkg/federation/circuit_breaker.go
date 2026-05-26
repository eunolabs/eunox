// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package federation

import (
	"sync"
	"time"
)

// CircuitBreakerState represents the state of a circuit breaker.
type CircuitBreakerState string

const (
	// StateClosed means the circuit is operating normally.
	StateClosed CircuitBreakerState = "closed"
	// StateOpen means the circuit has tripped due to failures.
	StateOpen CircuitBreakerState = "open"
	// StateHalfOpen means the circuit is testing with limited probes.
	StateHalfOpen CircuitBreakerState = "half-open"
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

// CircuitBreaker implements the circuit breaker pattern for DID resolution.
type CircuitBreaker struct {
	config CircuitBreakerConfig

	mu                sync.Mutex
	state             CircuitBreakerState
	consecutiveFails  int
	lastFailureTime   time.Time
	halfOpenProbes    int
	lastTransitionAt  time.Time
	totalFailures     int64
	totalSuccesses    int64

	now func() time.Time
}

// NewCircuitBreaker creates a new circuit breaker with the given configuration.
func NewCircuitBreaker(cfg CircuitBreakerConfig) *CircuitBreaker {
	return &CircuitBreaker{
		config: cfg,
		state:  StateClosed,
		now:    time.Now,
	}
}

// Allow returns true if the circuit breaker permits a request.
// In closed state: always allows.
// In open state: denies unless cooldown has elapsed (transitions to half-open).
// In half-open state: allows up to HalfOpenMaxProbes.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		return true
	case StateOpen:
		if cb.now().Sub(cb.lastFailureTime) >= cb.config.CooldownDuration {
			cb.state = StateHalfOpen
			cb.halfOpenProbes = 1 // The transition itself counts as the first probe.
			cb.lastTransitionAt = cb.now()
			return true
		}
		return false
	case StateHalfOpen:
		if cb.halfOpenProbes < cb.config.HalfOpenMaxProbes {
			cb.halfOpenProbes++
			return true
		}
		return false
	default:
		return false
	}
}

// RecordSuccess records a successful request.
// In half-open state, transitions to closed.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.totalSuccesses++
	cb.consecutiveFails = 0

	if cb.state == StateHalfOpen {
		cb.state = StateClosed
		cb.lastTransitionAt = cb.now()
	}
}

// RecordFailure records a failed request.
// If consecutive failures exceed the threshold, opens the circuit.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.totalFailures++
	cb.consecutiveFails++
	cb.lastFailureTime = cb.now()

	switch cb.state {
	case StateClosed:
		if cb.consecutiveFails >= cb.config.FailureThreshold {
			cb.state = StateOpen
			cb.lastTransitionAt = cb.now()
		}
	case StateHalfOpen:
		// Any failure in half-open re-opens.
		cb.state = StateOpen
		cb.lastTransitionAt = cb.now()
	}
}

// State returns the current circuit breaker state.
func (cb *CircuitBreaker) State() CircuitBreakerState {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// Check if open circuit should transition to half-open.
	if cb.state == StateOpen && cb.now().Sub(cb.lastFailureTime) >= cb.config.CooldownDuration {
		return StateHalfOpen
	}
	return cb.state
}

// Stats returns circuit breaker statistics.
func (cb *CircuitBreaker) Stats() CircuitBreakerStats {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	return CircuitBreakerStats{
		State:            cb.state,
		ConsecutiveFails: cb.consecutiveFails,
		TotalFailures:    cb.totalFailures,
		TotalSuccesses:   cb.totalSuccesses,
		LastFailureTime:  cb.lastFailureTime,
		LastTransitionAt: cb.lastTransitionAt,
	}
}

// CircuitBreakerStats holds circuit breaker statistics.
type CircuitBreakerStats struct {
	State            CircuitBreakerState `json:"state"`
	ConsecutiveFails int                 `json:"consecutiveFails"`
	TotalFailures    int64               `json:"totalFailures"`
	TotalSuccesses   int64               `json:"totalSuccesses"`
	LastFailureTime  time.Time           `json:"lastFailureTime,omitempty"`
	LastTransitionAt time.Time           `json:"lastTransitionAt,omitempty"`
}
