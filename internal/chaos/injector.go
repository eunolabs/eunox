// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package chaos

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"time"
)

// FaultType identifies the kind of fault injected.
type FaultType int

const (
	// FaultLatency introduces artificial delay.
	FaultLatency FaultType = iota
	// FaultError returns an error unconditionally.
	FaultError
	// FaultTimeout simulates a context deadline exceeded.
	FaultTimeout
	// FaultPartition simulates a network partition (connection refused).
	FaultPartition
)

// Fault describes a fault injection rule.
type Fault struct {
	// Type is the kind of fault to inject.
	Type FaultType
	// Probability is the likelihood of fault injection (0.0–1.0).
	// 1.0 means always inject.
	Probability float64
	// Latency is the delay to add (only for FaultLatency).
	Latency time.Duration
	// Error is the error to return (only for FaultError).
	Error error
}

// Injector manages fault injection state for chaos tests.
type Injector struct {
	mu     sync.RWMutex
	faults map[string]Fault
	active bool
}

// NewInjector creates a new fault injector.
func NewInjector() *Injector {
	return &Injector{
		faults: make(map[string]Fault),
		active: true,
	}
}

// SetFault registers a fault for the given operation name.
func (inj *Injector) SetFault(operation string, f Fault) {
	inj.mu.Lock()
	defer inj.mu.Unlock()
	inj.faults[operation] = f
}

// ClearFault removes the fault for the given operation.
func (inj *Injector) ClearFault(operation string) {
	inj.mu.Lock()
	defer inj.mu.Unlock()
	delete(inj.faults, operation)
}

// ClearAll removes all registered faults.
func (inj *Injector) ClearAll() {
	inj.mu.Lock()
	defer inj.mu.Unlock()
	inj.faults = make(map[string]Fault)
}

// Disable deactivates all fault injection without removing rules.
func (inj *Injector) Disable() {
	inj.mu.Lock()
	defer inj.mu.Unlock()
	inj.active = false
}

// Enable reactivates fault injection.
func (inj *Injector) Enable() {
	inj.mu.Lock()
	defer inj.mu.Unlock()
	inj.active = true
}

// ErrFaultInjected is returned when a fault is triggered.
var ErrFaultInjected = errors.New("chaos: fault injected")

// ErrPartition is returned when a network partition is simulated.
var ErrPartition = errors.New("chaos: network partition")

// ErrTimeout is returned when a timeout fault is simulated.
var ErrTimeout = errors.New("chaos: operation timed out")

// MaybeInject checks if a fault should be injected for the given operation.
// Returns nil if no fault is triggered.
func (inj *Injector) MaybeInject(ctx context.Context, operation string) error {
	inj.mu.RLock()
	if !inj.active {
		inj.mu.RUnlock()
		return nil
	}
	f, ok := inj.faults[operation]
	inj.mu.RUnlock()

	if !ok {
		return nil
	}

	if f.Probability < 1.0 && rand.Float64() > f.Probability {
		return nil
	}

	switch f.Type {
	case FaultLatency:
		select {
		case <-time.After(f.Latency):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	case FaultError:
		if f.Error != nil {
			return f.Error
		}
		return ErrFaultInjected
	case FaultTimeout:
		return ErrTimeout
	case FaultPartition:
		return ErrPartition
	default:
		return nil
	}
}

// HasFault returns true if a fault is registered for the operation.
func (inj *Injector) HasFault(operation string) bool {
	inj.mu.RLock()
	defer inj.mu.RUnlock()
	_, ok := inj.faults[operation]
	return ok
}
