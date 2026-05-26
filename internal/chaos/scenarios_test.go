// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package chaos

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Resilience Pattern: Circuit Breaker ---

// CircuitState represents the state of a circuit breaker.
type CircuitState int

const (
	// CircuitClosed means the circuit is operating normally.
	CircuitClosed CircuitState = iota
	// CircuitOpen means the circuit is broken and requests are rejected.
	CircuitOpen
	// CircuitHalfOpen means the circuit is testing if the backend recovered.
	CircuitHalfOpen
)

// CircuitBreaker implements the circuit breaker pattern for chaos testing.
type CircuitBreaker struct {
	mu               sync.Mutex
	state            CircuitState
	failures         int
	successes        int
	threshold        int
	halfOpenMax      int
	resetTimeout     time.Duration
	lastFailureTime  time.Time
}

// NewCircuitBreaker creates a circuit breaker with the given threshold
// (number of failures before opening) and reset timeout.
func NewCircuitBreaker(threshold int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		threshold:    threshold,
		halfOpenMax:  1,
		resetTimeout: resetTimeout,
	}
}

// State returns the current circuit state.
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.state == CircuitOpen && time.Since(cb.lastFailureTime) >= cb.resetTimeout {
		cb.state = CircuitHalfOpen
		cb.successes = 0
	}
	return cb.state
}

// Execute runs the operation through the circuit breaker.
func (cb *CircuitBreaker) Execute(ctx context.Context, op func(ctx context.Context) error) error {
	state := cb.State()
	if state == CircuitOpen {
		return errors.New("circuit open: request rejected")
	}

	err := op(ctx)

	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil {
		cb.failures++
		cb.lastFailureTime = time.Now()
		if cb.failures >= cb.threshold {
			cb.state = CircuitOpen
		}
		return err
	}

	if cb.state == CircuitHalfOpen {
		cb.successes++
		if cb.successes >= cb.halfOpenMax {
			cb.state = CircuitClosed
			cb.failures = 0
		}
	} else {
		cb.failures = 0
	}
	return nil
}

// Reset resets the circuit breaker to closed state.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.state = CircuitClosed
	cb.failures = 0
	cb.successes = 0
}

// --- Scenario Tests ---

func TestScenario_RedisPartition_CircuitBreaker(t *testing.T) {
	// Simulate: Redis becomes unreachable, circuit breaker opens,
	// then recovers and circuit closes.
	inj := NewInjector()
	cb := NewCircuitBreaker(3, 100*time.Millisecond)

	// Set up partition fault
	inj.SetFault("redis.get", Fault{Type: FaultPartition, Probability: 1.0})

	// Operations fail, tripping the circuit breaker
	for range 3 {
		err := cb.Execute(context.Background(), func(ctx context.Context) error {
			return inj.MaybeInject(ctx, "redis.get")
		})
		require.Error(t, err)
	}

	// Circuit is now open — no calls go through
	assert.Equal(t, CircuitOpen, cb.State())
	err := cb.Execute(context.Background(), func(_ context.Context) error {
		t.Fatal("should not be called when circuit is open")
		return nil
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "circuit open")

	// Simulate recovery
	inj.ClearFault("redis.get")
	time.Sleep(110 * time.Millisecond)

	// Circuit should be half-open now
	assert.Equal(t, CircuitHalfOpen, cb.State())

	// Success in half-open closes the circuit
	err = cb.Execute(context.Background(), func(ctx context.Context) error {
		return inj.MaybeInject(ctx, "redis.get")
	})
	assert.NoError(t, err)
	assert.Equal(t, CircuitClosed, cb.State())
}

func TestScenario_ConcurrentKillSwitchActivation(t *testing.T) {
	// Simulate: Multiple concurrent requests try to check kill-switch state
	// while it's being toggled — verify no data races or panics.
	inj := NewInjector()
	var active atomic.Bool

	toggleKillSwitch := func() {
		if active.CompareAndSwap(false, true) {
			inj.SetFault("killswitch.check", Fault{Type: FaultError, Probability: 1.0, Error: errors.New("kill switch active")})
		} else {
			inj.ClearFault("killswitch.check")
			active.Store(false)
		}
	}

	var wg sync.WaitGroup
	errCount := atomic.Int64{}

	// Toggler
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 100 {
			toggleKillSwitch()
			time.Sleep(time.Millisecond)
		}
	}()

	// Readers
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				err := inj.MaybeInject(context.Background(), "killswitch.check")
				if err != nil {
					errCount.Add(1)
				}
			}
		}()
	}

	wg.Wait()
	// Test passes if no race condition detected (run with -race flag)
	t.Logf("total errors observed: %d", errCount.Load())
}

func TestScenario_ServiceRestart_GracefulDegradation(t *testing.T) {
	// Simulate: A backend service restarts. During the restart window,
	// all calls fail. After restart, they succeed again.
	inj := NewInjector()

	// Normal operation
	err := inj.MaybeInject(context.Background(), "backend.call")
	require.NoError(t, err)

	// Simulate service going down
	inj.SetFault("backend.call", Fault{
		Type:        FaultError,
		Probability: 1.0,
		Error:       errors.New("connection refused"),
	})

	// All calls during outage fail
	for range 5 {
		err = inj.MaybeInject(context.Background(), "backend.call")
		assert.Error(t, err)
	}

	// Simulate service coming back
	inj.ClearFault("backend.call")
	err = inj.MaybeInject(context.Background(), "backend.call")
	assert.NoError(t, err)
}

func TestScenario_CascadingFailures(t *testing.T) {
	// Simulate: Redis fails, causing auth to fail, causing gateway to reject requests.
	inj := NewInjector()

	// Redis goes down
	inj.SetFault("redis.revocation.check", Fault{
		Type:        FaultPartition,
		Probability: 1.0,
	})

	// Token revocation check depends on Redis
	checkRevocation := func(ctx context.Context) error {
		if err := inj.MaybeInject(ctx, "redis.revocation.check"); err != nil {
			return errors.New("revocation check failed: " + err.Error())
		}
		return nil
	}

	// Gateway request processing
	processRequest := func(ctx context.Context) error {
		// Step 1: Verify token (works fine)
		if err := inj.MaybeInject(ctx, "jwt.verify"); err != nil {
			return err
		}
		// Step 2: Check revocation (fails due to Redis)
		return checkRevocation(ctx)
	}

	err := processRequest(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revocation check failed")

	// Fix Redis
	inj.ClearFault("redis.revocation.check")
	err = processRequest(context.Background())
	assert.NoError(t, err)
}

func TestScenario_SplitBrain(t *testing.T) {
	// Simulate: Two replicas see different state due to a partition.
	// Each replica has its own injector simulating network to state store.
	injReplica1 := NewInjector()
	injReplica2 := NewInjector()

	// Replica 1 can reach state store
	// Replica 2 cannot (partition)
	injReplica2.SetFault("state.read", Fault{
		Type:        FaultPartition,
		Probability: 1.0,
	})

	// Replica 1 reads fresh state
	err := injReplica1.MaybeInject(context.Background(), "state.read")
	assert.NoError(t, err)

	// Replica 2 gets partition error — must serve stale data or reject
	err = injReplica2.MaybeInject(context.Background(), "state.read")
	assert.ErrorIs(t, err, ErrPartition)

	// Partition heals
	injReplica2.ClearFault("state.read")
	err = injReplica2.MaybeInject(context.Background(), "state.read")
	assert.NoError(t, err)
}

func TestScenario_HighLatency_TimeoutPropagation(t *testing.T) {
	// Simulate: A downstream service is slow, and the request context
	// has a tight deadline that propagates correctly.
	inj := NewInjector()
	inj.SetFault("downstream.call", Fault{
		Type:        FaultLatency,
		Probability: 1.0,
		Latency:     500 * time.Millisecond,
	})

	// Client timeout is shorter than injected latency
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := inj.MaybeInject(ctx, "downstream.call")
	elapsed := time.Since(start)

	assert.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	// Should have cancelled early, not waited for full 500ms
	assert.Less(t, elapsed, 200*time.Millisecond)
}

func TestScenario_PartialFailure_MultiStep(t *testing.T) {
	// Simulate: A multi-step operation where only one step fails.
	// The overall operation should fail but prior steps succeed.
	inj := NewInjector()

	// Step 3 of 4 fails
	inj.SetFault("step.3", Fault{Type: FaultError, Probability: 1.0})

	steps := []string{"step.1", "step.2", "step.3", "step.4"}
	completedSteps := 0

	for _, step := range steps {
		if err := inj.MaybeInject(context.Background(), step); err != nil {
			break
		}
		completedSteps++
	}

	assert.Equal(t, 2, completedSteps, "should complete 2 steps before failure")
}

func TestScenario_RetryWithBackoff(t *testing.T) {
	// Simulate: A transient failure that resolves after N retries.
	inj := NewInjector()
	callCount := 0

	inj.SetFault("flaky.op", Fault{Type: FaultError, Probability: 1.0})

	// After 3 attempts, "fix" the fault
	retryOp := func() error {
		for attempt := range 5 {
			callCount++
			err := inj.MaybeInject(context.Background(), "flaky.op")
			if err == nil {
				return nil
			}
			if attempt == 2 {
				// Simulate transient issue resolving
				inj.ClearFault("flaky.op")
			}
			time.Sleep(time.Millisecond) // backoff
		}
		return errors.New("exhausted retries")
	}

	err := retryOp()
	assert.NoError(t, err)
	assert.Equal(t, 4, callCount, "should succeed on 4th attempt (after 3 failures)")
}

func TestScenario_RateLimiting_UnderLoad(t *testing.T) {
	// Simulate: High concurrent load with rate limiting.
	// Verify that rate limiting correctly rejects excess requests.
	var (
		mu       sync.Mutex
		accepted int
		rejected int
		limit    = 10
	)

	rateLimiter := func() bool {
		mu.Lock()
		defer mu.Unlock()
		if accepted >= limit {
			return false
		}
		accepted++
		return true
	}

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !rateLimiter() {
				mu.Lock()
				rejected++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, 10, accepted)
	assert.Equal(t, 40, rejected)
}
