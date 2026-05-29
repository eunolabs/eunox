// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package agentruntime

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRetryFunc_Success(t *testing.T) {
	cfg := RetryConfig{MaxRetries: 3, BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond}

	result, err := RetryFunc(context.Background(), cfg, func(_ context.Context) (string, error) {
		return "ok", nil
	})

	require.NoError(t, err)
	assert.Equal(t, "ok", result)
}

func TestRetryFunc_TransientThenSuccess(t *testing.T) {
	cfg := RetryConfig{MaxRetries: 3, BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond}

	attempt := 0
	result, err := RetryFunc(context.Background(), cfg, func(_ context.Context) (string, error) {
		attempt++
		if attempt < 3 {
			return "", &TransientError{Err: errors.New("temporary")}
		}
		return "ok", nil
	})

	require.NoError(t, err)
	assert.Equal(t, "ok", result)
	assert.Equal(t, 3, attempt)
}

func TestRetryFunc_NonTransientError(t *testing.T) {
	cfg := RetryConfig{MaxRetries: 3, BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond}

	attempt := 0
	_, err := RetryFunc(context.Background(), cfg, func(_ context.Context) (string, error) {
		attempt++
		return "", errors.New("permanent error")
	})

	require.Error(t, err)
	assert.Equal(t, "permanent error", err.Error())
	assert.Equal(t, 1, attempt) // No retry for non-transient errors
}

func TestRetryFunc_MaxRetriesExhausted(t *testing.T) {
	cfg := RetryConfig{MaxRetries: 2, BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond}

	attempt := 0
	_, err := RetryFunc(context.Background(), cfg, func(_ context.Context) (string, error) {
		attempt++
		return "", &TransientError{Err: errors.New("still failing")}
	})

	require.Error(t, err)
	assert.Equal(t, 3, attempt) // initial + 2 retries
}

func TestRetryFunc_ContextCancelled(t *testing.T) {
	cfg := RetryConfig{MaxRetries: 10, BaseDelay: time.Second, MaxDelay: 10 * time.Second}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := RetryFunc(ctx, cfg, func(_ context.Context) (string, error) {
		return "", &TransientError{Err: errors.New("transient")}
	})

	require.Error(t, err)
}

func TestBackoffDelay(t *testing.T) {
	base := 100 * time.Millisecond
	maxDelay := 5 * time.Second

	assert.Equal(t, 100*time.Millisecond, backoffDelay(0, base, maxDelay))
	assert.Equal(t, 200*time.Millisecond, backoffDelay(1, base, maxDelay))
	assert.Equal(t, 400*time.Millisecond, backoffDelay(2, base, maxDelay))
	assert.Equal(t, 800*time.Millisecond, backoffDelay(3, base, maxDelay))
	assert.Equal(t, 1600*time.Millisecond, backoffDelay(4, base, maxDelay))
	assert.Equal(t, 3200*time.Millisecond, backoffDelay(5, base, maxDelay))
	assert.Equal(t, 5*time.Second, backoffDelay(6, base, maxDelay))  // capped
	assert.Equal(t, 5*time.Second, backoffDelay(10, base, maxDelay)) // still capped
}

func TestIsTransient(t *testing.T) {
	assert.True(t, IsTransient(&TransientError{Err: errors.New("temp")}))
	assert.False(t, IsTransient(errors.New("permanent")))
	assert.False(t, IsTransient(nil))
}

func TestTransientError_Unwrap(t *testing.T) {
	inner := errors.New("inner error")
	te := &TransientError{Err: inner, StatusCode: 503}

	assert.ErrorIs(t, te, inner)
	assert.Equal(t, "inner error", te.Error())
}
