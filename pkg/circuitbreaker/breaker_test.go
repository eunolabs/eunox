// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package circuitbreaker_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/eunolabs/eunox/pkg/circuitbreaker"
)

func TestDefaultConfig(t *testing.T) {
	cfg := circuitbreaker.DefaultConfig()
	if cfg.FailureThreshold != 5 {
		t.Errorf("expected FailureThreshold=5, got %d", cfg.FailureThreshold)
	}
	if cfg.CooldownDuration != 30*time.Second {
		t.Errorf("expected CooldownDuration=30s, got %v", cfg.CooldownDuration)
	}
	if cfg.HalfOpenMaxProbes != 1 {
		t.Errorf("expected HalfOpenMaxProbes=1, got %d", cfg.HalfOpenMaxProbes)
	}
}

func TestBreaker_StartsInClosedState(t *testing.T) {
	b := circuitbreaker.New(circuitbreaker.DefaultConfig())
	if s := b.State(); s != circuitbreaker.StateClosed {
		t.Errorf("expected StateClosed, got %q", s)
	}
}

func TestBreaker_AllowsInClosedState(t *testing.T) {
	b := circuitbreaker.New(circuitbreaker.DefaultConfig())
	for i := 0; i < 100; i++ {
		if !b.Allow() {
			t.Fatalf("expected Allow() = true in closed state, iteration %d", i)
		}
	}
}

func TestBreaker_OpensAfterThreshold(t *testing.T) {
	cfg := circuitbreaker.Config{
		FailureThreshold:  3,
		CooldownDuration:  10 * time.Second,
		HalfOpenMaxProbes: 1,
	}
	b := circuitbreaker.New(cfg)

	// 2 failures should not open.
	b.RecordFailure()
	b.RecordFailure()
	if !b.Allow() {
		t.Fatal("breaker should still be closed after 2 failures")
	}

	// 3rd failure opens.
	b.RecordFailure()
	if b.Allow() {
		t.Fatal("breaker should be open after 3 failures")
	}
	if s := b.State(); s != circuitbreaker.StateOpen {
		t.Errorf("expected StateOpen, got %q", s)
	}
}

func TestBreaker_SuccessResetsCounter(t *testing.T) {
	cfg := circuitbreaker.Config{
		FailureThreshold:  3,
		CooldownDuration:  10 * time.Second,
		HalfOpenMaxProbes: 1,
	}
	b := circuitbreaker.New(cfg)

	b.RecordFailure()
	b.RecordFailure()
	b.RecordSuccess() // Resets consecutive failures.
	b.RecordFailure()
	b.RecordFailure()
	// Only 2 consecutive failures at this point, should still allow.
	if !b.Allow() {
		t.Fatal("expected breaker to remain closed after success reset")
	}
}

func TestBreaker_TransitionsToHalfOpenAfterCooldown(t *testing.T) {
	var mu sync.Mutex
	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return current
	}
	advanceClock := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		current = current.Add(d)
	}

	cfg := circuitbreaker.Config{
		FailureThreshold:  2,
		CooldownDuration:  5 * time.Second,
		HalfOpenMaxProbes: 2,
	}
	b := circuitbreaker.New(cfg, circuitbreaker.WithClock(clock))
	b.RecordFailure()
	b.RecordFailure()
	if b.Allow() {
		t.Fatal("expected denial while open")
	}

	advanceClock(6 * time.Second)

	// Should transition to half-open and allow a probe.
	if !b.Allow() {
		t.Fatal("expected Allow() after cooldown (half-open)")
	}
	if s := b.State(); s != circuitbreaker.StateHalfOpen {
		t.Errorf("expected StateHalfOpen, got %q", s)
	}

	// Second probe should also be allowed (HalfOpenMaxProbes=2).
	if !b.Allow() {
		t.Fatal("expected second probe allowed")
	}

	// Third should be denied.
	if b.Allow() {
		t.Fatal("expected denial after max probes exhausted")
	}
}

func TestBreaker_HalfOpenSuccessCloses(t *testing.T) {
	var mu sync.Mutex
	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return current
	}
	advanceClock := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		current = current.Add(d)
	}

	cfg := circuitbreaker.Config{
		FailureThreshold:  2,
		CooldownDuration:  5 * time.Second,
		HalfOpenMaxProbes: 1,
	}
	b := circuitbreaker.New(cfg, circuitbreaker.WithClock(clock))

	b.RecordFailure()
	b.RecordFailure()
	advanceClock(6 * time.Second)
	b.Allow() // Transitions to half-open.
	b.RecordSuccess()

	if s := b.State(); s != circuitbreaker.StateClosed {
		t.Errorf("expected StateClosed after half-open success, got %q", s)
	}
	// Should allow freely again.
	if !b.Allow() {
		t.Fatal("expected Allow() after close")
	}
}

func TestBreaker_HalfOpenFailureReopens(t *testing.T) {
	var mu sync.Mutex
	current := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return current
	}
	advanceClock := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		current = current.Add(d)
	}

	cfg := circuitbreaker.Config{
		FailureThreshold:  2,
		CooldownDuration:  5 * time.Second,
		HalfOpenMaxProbes: 1,
	}
	b := circuitbreaker.New(cfg, circuitbreaker.WithClock(clock))

	b.RecordFailure()
	b.RecordFailure()
	advanceClock(6 * time.Second)
	b.Allow() // Transitions to half-open.
	b.RecordFailure()

	if s := b.State(); s != circuitbreaker.StateOpen {
		t.Errorf("expected StateOpen after half-open failure, got %q", s)
	}
	if b.Allow() {
		t.Fatal("expected denial after re-open")
	}
}

func TestBreaker_Reset(t *testing.T) {
	cfg := circuitbreaker.Config{
		FailureThreshold:  2,
		CooldownDuration:  5 * time.Second,
		HalfOpenMaxProbes: 1,
	}
	b := circuitbreaker.New(cfg)
	b.RecordFailure()
	b.RecordFailure()
	// Open.
	beforeReset := b.Stats()
	if beforeReset.LastFailureTime.IsZero() {
		t.Fatal("expected non-zero LastFailureTime before reset")
	}
	b.Reset()
	if s := b.State(); s != circuitbreaker.StateClosed {
		t.Errorf("expected StateClosed after reset, got %q", s)
	}
	if !b.Allow() {
		t.Fatal("expected Allow() after reset")
	}
	afterReset := b.Stats()
	if !afterReset.LastFailureTime.IsZero() {
		t.Fatal("expected LastFailureTime to be cleared on reset")
	}
}

func TestBreaker_Stats(t *testing.T) {
	cfg := circuitbreaker.Config{
		FailureThreshold:  3,
		CooldownDuration:  5 * time.Second,
		HalfOpenMaxProbes: 1,
	}
	b := circuitbreaker.New(cfg)

	b.RecordSuccess()
	b.RecordFailure()
	b.RecordSuccess()
	b.RecordFailure()
	b.RecordFailure()

	stats := b.Stats()
	if stats.TotalSuccesses != 2 {
		t.Errorf("expected 2 successes, got %d", stats.TotalSuccesses)
	}
	if stats.TotalFailures != 3 {
		t.Errorf("expected 3 failures, got %d", stats.TotalFailures)
	}
	if stats.ConsecutiveFails != 2 {
		t.Errorf("expected 2 consecutive fails, got %d", stats.ConsecutiveFails)
	}
}

func TestBreaker_ConcurrentAccess(t *testing.T) {
	cfg := circuitbreaker.Config{
		FailureThreshold:  100,
		CooldownDuration:  time.Second,
		HalfOpenMaxProbes: 10,
	}
	b := circuitbreaker.New(cfg)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.Allow()
			b.RecordFailure()
			b.Allow()
			b.RecordSuccess()
			_ = b.State()
			_ = b.Stats()
		}()
	}
	wg.Wait()
	// No race condition = test passes.
}

// Do tests

func TestDo_SuccessfulCall(t *testing.T) {
	b := circuitbreaker.New(circuitbreaker.DefaultConfig())
	ctx := context.Background()

	result, err := circuitbreaker.Do(ctx, b, func(_ context.Context) (string, error) {
		return "hello", nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "hello" {
		t.Errorf("expected 'hello', got %q", result)
	}
}

func TestDo_FailureRecorded(t *testing.T) {
	cfg := circuitbreaker.Config{
		FailureThreshold:  2,
		CooldownDuration:  time.Minute,
		HalfOpenMaxProbes: 1,
	}
	b := circuitbreaker.New(cfg)
	ctx := context.Background()
	testErr := errors.New("remote failure")

	for i := 0; i < 2; i++ {
		_, err := circuitbreaker.Do(ctx, b, func(_ context.Context) (int, error) {
			return 0, testErr
		})
		if !errors.Is(err, testErr) {
			t.Fatalf("expected testErr, got %v", err)
		}
	}

	// Breaker should now be open.
	_, err := circuitbreaker.Do(ctx, b, func(_ context.Context) (int, error) {
		t.Fatal("should not be called when breaker is open")
		return 0, nil
	})
	if !errors.Is(err, circuitbreaker.ErrOpen) {
		t.Fatalf("expected ErrOpen, got %v", err)
	}
}

func TestDo_CancelledContext(t *testing.T) {
	b := circuitbreaker.New(circuitbreaker.DefaultConfig())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := circuitbreaker.Do(ctx, b, func(_ context.Context) (int, error) {
		t.Fatal("fn should not be called with cancelled context")
		return 0, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestDo_NilBreakerPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for nil breaker")
		}
	}()
	_, _ = circuitbreaker.Do(context.Background(), nil, func(_ context.Context) (int, error) {
		return 0, nil
	})
}

func TestDoVoid_NilBreakerPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for nil breaker")
		}
	}()
	_ = circuitbreaker.DoVoid(context.Background(), nil, func(_ context.Context) error {
		return nil
	})
}

func TestDoVoid_Success(t *testing.T) {
	b := circuitbreaker.New(circuitbreaker.DefaultConfig())
	called := false

	err := circuitbreaker.DoVoid(context.Background(), b, func(_ context.Context) error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("expected fn to be called")
	}
}

func TestDoVoid_OpenBreaker(t *testing.T) {
	cfg := circuitbreaker.Config{
		FailureThreshold:  1,
		CooldownDuration:  time.Minute,
		HalfOpenMaxProbes: 1,
	}
	b := circuitbreaker.New(cfg)
	b.RecordFailure() // Opens.

	err := circuitbreaker.DoVoid(context.Background(), b, func(_ context.Context) error {
		t.Fatal("should not be called")
		return nil
	})
	if !errors.Is(err, circuitbreaker.ErrOpen) {
		t.Fatalf("expected ErrOpen, got %v", err)
	}
}

// ProtectedSigner tests

type mockSigner struct {
	signFn func(ctx context.Context, digest []byte) ([]byte, error)
}

func (m *mockSigner) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	return m.signFn(ctx, digest)
}
func (m *mockSigner) Algorithm() string { return "ES256" }
func (m *mockSigner) KeyID() string     { return "test-key-1" }

func TestProtectedSigner_Delegates(t *testing.T) {
	b := circuitbreaker.New(circuitbreaker.DefaultConfig())
	inner := &mockSigner{
		signFn: func(_ context.Context, digest []byte) ([]byte, error) {
			return append([]byte("sig:"), digest...), nil
		},
	}
	ps := circuitbreaker.NewProtectedSigner(inner, b)

	sig, err := ps.Sign(context.Background(), []byte("data"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(sig) != "sig:data" {
		t.Errorf("unexpected signature: %q", sig)
	}
	if ps.Algorithm() != "ES256" {
		t.Errorf("unexpected algorithm: %q", ps.Algorithm())
	}
	if ps.KeyID() != "test-key-1" {
		t.Errorf("unexpected key ID: %q", ps.KeyID())
	}
}

func TestProtectedSigner_RejectsWhenOpen(t *testing.T) {
	cfg := circuitbreaker.Config{
		FailureThreshold:  1,
		CooldownDuration:  time.Minute,
		HalfOpenMaxProbes: 1,
	}
	b := circuitbreaker.New(cfg)
	inner := &mockSigner{
		signFn: func(_ context.Context, _ []byte) ([]byte, error) {
			return nil, errors.New("kms error")
		},
	}
	ps := circuitbreaker.NewProtectedSigner(inner, b)

	// First call fails and opens breaker.
	_, err := ps.Sign(context.Background(), []byte("data"))
	if err == nil || err.Error() != "kms error" {
		t.Fatalf("expected kms error, got %v", err)
	}

	// Second call should be rejected by breaker.
	_, err = ps.Sign(context.Background(), []byte("data"))
	if !errors.Is(err, circuitbreaker.ErrOpen) {
		t.Fatalf("expected ErrOpen, got %v", err)
	}
}

func TestProtectedSigner_CancelledContext(t *testing.T) {
	b := circuitbreaker.New(circuitbreaker.DefaultConfig())
	inner := &mockSigner{
		signFn: func(_ context.Context, _ []byte) ([]byte, error) {
			t.Fatal("should not be called")
			return nil, nil
		},
	}
	ps := circuitbreaker.NewProtectedSigner(inner, b)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := ps.Sign(ctx, []byte("data"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestProtectedSigner_NilInputsPanic(t *testing.T) {
	b := circuitbreaker.New(circuitbreaker.DefaultConfig())
	inner := &mockSigner{
		signFn: func(_ context.Context, digest []byte) ([]byte, error) {
			return append([]byte("sig:"), digest...), nil
		},
	}

	t.Run("nil breaker", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("expected panic for nil breaker")
			}
		}()
		_ = circuitbreaker.NewProtectedSigner(inner, nil)
	})

	t.Run("nil signer", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("expected panic for nil signer")
			}
		}()
		_ = circuitbreaker.NewProtectedSigner(nil, b)
	})
}
