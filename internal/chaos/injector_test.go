// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package chaos

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInjector_NoFault(t *testing.T) {
	inj := NewInjector()
	err := inj.MaybeInject(context.Background(), "redis.get")
	assert.NoError(t, err)
}

func TestInjector_ErrorFault(t *testing.T) {
	inj := NewInjector()
	customErr := errors.New("redis connection refused")
	inj.SetFault("redis.get", Fault{
		Type:        FaultError,
		Probability: 1.0,
		Error:       customErr,
	})

	err := inj.MaybeInject(context.Background(), "redis.get")
	assert.ErrorIs(t, err, customErr)
}

func TestInjector_ErrorFault_DefaultError(t *testing.T) {
	inj := NewInjector()
	inj.SetFault("redis.get", Fault{
		Type:        FaultError,
		Probability: 1.0,
	})

	err := inj.MaybeInject(context.Background(), "redis.get")
	assert.ErrorIs(t, err, ErrFaultInjected)
}

func TestInjector_TimeoutFault(t *testing.T) {
	inj := NewInjector()
	inj.SetFault("http.call", Fault{
		Type:        FaultTimeout,
		Probability: 1.0,
	})

	err := inj.MaybeInject(context.Background(), "http.call")
	assert.ErrorIs(t, err, ErrTimeout)
}

func TestInjector_PartitionFault(t *testing.T) {
	inj := NewInjector()
	inj.SetFault("redis.set", Fault{
		Type:        FaultPartition,
		Probability: 1.0,
	})

	err := inj.MaybeInject(context.Background(), "redis.set")
	assert.ErrorIs(t, err, ErrPartition)
}

func TestInjector_LatencyFault(t *testing.T) {
	inj := NewInjector()
	inj.SetFault("db.query", Fault{
		Type:        FaultLatency,
		Probability: 1.0,
		Latency:     50 * time.Millisecond,
	})

	start := time.Now()
	err := inj.MaybeInject(context.Background(), "db.query")
	elapsed := time.Since(start)

	assert.NoError(t, err)
	assert.GreaterOrEqual(t, elapsed, 50*time.Millisecond)
}

func TestInjector_LatencyFault_ContextCancelled(t *testing.T) {
	inj := NewInjector()
	inj.SetFault("db.query", Fault{
		Type:        FaultLatency,
		Probability: 1.0,
		Latency:     5 * time.Second, // long delay
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	err := inj.MaybeInject(ctx, "db.query")
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestInjector_Probability_Zero(t *testing.T) {
	inj := NewInjector()
	inj.SetFault("redis.get", Fault{
		Type:        FaultError,
		Probability: 0.0,
	})

	// With 0 probability, fault should never trigger
	for range 100 {
		err := inj.MaybeInject(context.Background(), "redis.get")
		assert.NoError(t, err)
	}
}

func TestInjector_ClearFault(t *testing.T) {
	inj := NewInjector()
	inj.SetFault("redis.get", Fault{
		Type:        FaultError,
		Probability: 1.0,
	})

	inj.ClearFault("redis.get")
	err := inj.MaybeInject(context.Background(), "redis.get")
	assert.NoError(t, err)
}

func TestInjector_ClearAll(t *testing.T) {
	inj := NewInjector()
	inj.SetFault("redis.get", Fault{Type: FaultError, Probability: 1.0})
	inj.SetFault("redis.set", Fault{Type: FaultError, Probability: 1.0})

	inj.ClearAll()
	assert.NoError(t, inj.MaybeInject(context.Background(), "redis.get"))
	assert.NoError(t, inj.MaybeInject(context.Background(), "redis.set"))
}

func TestInjector_Disable(t *testing.T) {
	inj := NewInjector()
	inj.SetFault("redis.get", Fault{Type: FaultError, Probability: 1.0})

	inj.Disable()
	err := inj.MaybeInject(context.Background(), "redis.get")
	assert.NoError(t, err)
}

func TestInjector_Enable(t *testing.T) {
	inj := NewInjector()
	inj.SetFault("redis.get", Fault{Type: FaultError, Probability: 1.0})

	inj.Disable()
	inj.Enable()
	err := inj.MaybeInject(context.Background(), "redis.get")
	assert.ErrorIs(t, err, ErrFaultInjected)
}

func TestInjector_HasFault(t *testing.T) {
	inj := NewInjector()
	assert.False(t, inj.HasFault("redis.get"))

	inj.SetFault("redis.get", Fault{Type: FaultError, Probability: 1.0})
	assert.True(t, inj.HasFault("redis.get"))
}

func TestInjector_ConcurrentAccess(t *testing.T) {
	inj := NewInjector()
	inj.SetFault("op", Fault{Type: FaultError, Probability: 1.0})

	var wg sync.WaitGroup
	errCount := 0
	var mu sync.Mutex

	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := inj.MaybeInject(context.Background(), "op")
			if err != nil {
				mu.Lock()
				errCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, 100, errCount)
}

func TestInjector_ConcurrentSetAndInject(t *testing.T) {
	inj := NewInjector()
	var wg sync.WaitGroup

	// Writer goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 50 {
			if i%2 == 0 {
				inj.SetFault("op", Fault{Type: FaultError, Probability: 1.0})
			} else {
				inj.ClearFault("op")
			}
		}
	}()

	// Reader goroutines
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				_ = inj.MaybeInject(context.Background(), "op")
			}
		}()
	}

	wg.Wait()
	// No race or panic — test passes if it completes
}

func TestInjector_UnknownFaultType(t *testing.T) {
	inj := NewInjector()
	inj.SetFault("op", Fault{Type: FaultType(99), Probability: 1.0})

	err := inj.MaybeInject(context.Background(), "op")
	assert.NoError(t, err, "unknown fault type should be a no-op")
}

func TestInjector_DifferentOperations(t *testing.T) {
	inj := NewInjector()
	inj.SetFault("redis.get", Fault{Type: FaultError, Probability: 1.0})

	// Fault only on "redis.get", not "redis.set"
	require.Error(t, inj.MaybeInject(context.Background(), "redis.get"))
	require.NoError(t, inj.MaybeInject(context.Background(), "redis.set"))
}
