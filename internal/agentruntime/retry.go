// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package agentruntime

import (
	"context"
	"errors"
	"time"
)

// TransientError indicates a transient failure that may succeed on retry.
type TransientError struct {
	Err        error
	StatusCode int
}

func (e *TransientError) Error() string {
	return e.Err.Error()
}

func (e *TransientError) Unwrap() error {
	return e.Err
}

// IsTransient returns true if the error is a transient error suitable for retry.
func IsTransient(err error) bool {
	var te *TransientError
	return errors.As(err, &te)
}

// RetryConfig holds retry configuration parameters.
type RetryConfig struct {
	MaxRetries int
	BaseDelay  time.Duration
	MaxDelay   time.Duration
}

// DefaultRetryConfig returns a sensible default retry configuration.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries: 3,
		BaseDelay:  100 * time.Millisecond,
		MaxDelay:   5 * time.Second,
	}
}

// RetryFunc executes fn with exponential backoff retry on transient errors.
// It returns immediately on non-transient errors or context cancellation.
func RetryFunc[T any](ctx context.Context, cfg RetryConfig, fn func(ctx context.Context) (T, error)) (T, error) {
	var zero T
	var lastErr error

	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return zero, lastErr
			}
			return zero, err
		}

		result, err := fn(ctx)
		if err == nil {
			return result, nil
		}

		lastErr = err

		if !IsTransient(err) {
			return zero, err
		}

		if attempt < cfg.MaxRetries {
			delay := backoffDelay(attempt, cfg.BaseDelay, cfg.MaxDelay)
			select {
			case <-ctx.Done():
				return zero, lastErr
			case <-time.After(delay):
			}
		}
	}

	return zero, lastErr
}

// backoffDelay computes exponential backoff: baseDelay * 2^attempt, capped at maxDelay.
func backoffDelay(attempt int, baseDelay, maxDelay time.Duration) time.Duration {
	delay := baseDelay
	for i := 0; i < attempt; i++ {
		delay *= 2
		if delay > maxDelay {
			return maxDelay
		}
	}
	return delay
}
