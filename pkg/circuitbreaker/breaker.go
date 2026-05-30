// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Package circuitbreaker provides a generic, thread-safe circuit breaker
// implementation for protecting calls to external dependencies.
//
// The breaker transitions through three states:
//   - Closed: requests flow normally. Consecutive failures are counted.
//   - Open: requests are rejected immediately. After a cooldown period
//     the breaker transitions to half-open.
//   - HalfOpen: a limited number of probe requests are allowed. A success
//     closes the breaker; a failure re-opens it.
package circuitbreaker

import (
	"errors"
	"sync"
	"time"
)

// State represents the state of a circuit breaker.
type State string

const (
	// StateClosed means the circuit is operating normally.
	StateClosed State = "closed"
	// StateOpen means the circuit has tripped due to failures.
	StateOpen State = "open"
	// StateHalfOpen means the circuit is testing with limited probes.
	StateHalfOpen State = "half-open"
)

// ErrOpen is returned when a request is rejected because the circuit is open.
var ErrOpen = errors.New("circuit breaker is open")

// Config configures a circuit breaker.
type Config struct {
	// FailureThreshold is the number of consecutive failures before opening.
	FailureThreshold int
	// CooldownDuration is how long to remain open before transitioning to half-open.
	CooldownDuration time.Duration
	// HalfOpenMaxProbes is the number of probe requests allowed in half-open state.
	HalfOpenMaxProbes int
}

// DefaultConfig returns a reasonable default configuration.
func DefaultConfig() Config {
	return Config{
		FailureThreshold:  5,
		CooldownDuration:  30 * time.Second,
		HalfOpenMaxProbes: 1,
	}
}

// Breaker implements the circuit breaker pattern.
type Breaker struct {
	config Config

	mu               sync.Mutex
	state            State
	consecutiveFails int
	lastFailureTime  time.Time
	halfOpenProbes   int
	lastTransitionAt time.Time
	totalFailures    int64
	totalSuccesses   int64

	now func() time.Time
}

// Option configures a Breaker.
type Option func(*Breaker)

// WithClock overrides the time source (useful for testing).
func WithClock(fn func() time.Time) Option {
	return func(b *Breaker) { b.now = fn }
}

// New creates a new circuit breaker with the given configuration.
func New(cfg Config, opts ...Option) *Breaker {
	b := &Breaker{
		config: cfg,
		state:  StateClosed,
		now:    time.Now,
	}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// Allow returns true if the circuit breaker permits a request.
// In closed state: always allows.
// In open state: denies unless cooldown has elapsed (transitions to half-open).
// In half-open state: allows up to HalfOpenMaxProbes.
func (b *Breaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	switch b.state {
	case StateClosed:
		return true
	case StateOpen:
		if b.now().Sub(b.lastFailureTime) >= b.config.CooldownDuration {
			b.state = StateHalfOpen
			b.halfOpenProbes = 1
			b.lastTransitionAt = b.now()
			return true
		}
		return false
	case StateHalfOpen:
		if b.halfOpenProbes < b.config.HalfOpenMaxProbes {
			b.halfOpenProbes++
			return true
		}
		return false
	default:
		return false
	}
}

// RecordSuccess records a successful request.
// In half-open state, transitions to closed.
func (b *Breaker) RecordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.totalSuccesses++
	b.consecutiveFails = 0

	if b.state == StateHalfOpen {
		b.state = StateClosed
		b.lastTransitionAt = b.now()
	}
}

// RecordFailure records a failed request.
// If consecutive failures exceed the threshold, opens the circuit.
func (b *Breaker) RecordFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.totalFailures++
	b.consecutiveFails++
	b.lastFailureTime = b.now()

	switch b.state {
	case StateClosed:
		if b.consecutiveFails >= b.config.FailureThreshold {
			b.state = StateOpen
			b.lastTransitionAt = b.now()
		}
	case StateHalfOpen:
		b.state = StateOpen
		b.lastTransitionAt = b.now()
	}
}

// State returns the current circuit breaker state. If the breaker is open
// and the cooldown has elapsed it reports HalfOpen (but does not mutate).
func (b *Breaker) State() State {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.state == StateOpen && b.now().Sub(b.lastFailureTime) >= b.config.CooldownDuration {
		return StateHalfOpen
	}
	return b.state
}

// Stats returns circuit breaker statistics.
func (b *Breaker) Stats() Stats {
	b.mu.Lock()
	defer b.mu.Unlock()

	return Stats{
		State:            b.state,
		ConsecutiveFails: b.consecutiveFails,
		TotalFailures:    b.totalFailures,
		TotalSuccesses:   b.totalSuccesses,
		LastFailureTime:  b.lastFailureTime,
		LastTransitionAt: b.lastTransitionAt,
	}
}

// Reset forces the breaker back to closed state and clears failure counters.
func (b *Breaker) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.state = StateClosed
	b.consecutiveFails = 0
	b.lastFailureTime = time.Time{}
	b.halfOpenProbes = 0
	b.lastTransitionAt = b.now()
}

// Stats holds circuit breaker statistics.
type Stats struct {
	State            State     `json:"state"`
	ConsecutiveFails int       `json:"consecutiveFails"`
	TotalFailures    int64     `json:"totalFailures"`
	TotalSuccesses   int64     `json:"totalSuccesses"`
	LastFailureTime  time.Time `json:"lastFailureTime,omitempty"`
	LastTransitionAt time.Time `json:"lastTransitionAt,omitempty"`
}
