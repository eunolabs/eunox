// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package circuitbreaker

import "context"

// Do executes fn only if the breaker allows it. It records success/failure
// based on the returned error (nil = success). If the breaker is open it
// returns ErrOpen without calling fn. Context cancellation is respected.
func Do[T any](ctx context.Context, b *Breaker, fn func(ctx context.Context) (T, error)) (T, error) {
	var zero T

	if err := ctx.Err(); err != nil {
		return zero, err
	}

	if !b.Allow() {
		return zero, ErrOpen
	}

	result, err := fn(ctx)
	if err != nil {
		b.RecordFailure()
		return zero, err
	}

	b.RecordSuccess()
	return result, nil
}

// DoVoid is like Do but for operations that return only an error.
func DoVoid(ctx context.Context, b *Breaker, fn func(ctx context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if !b.Allow() {
		return ErrOpen
	}

	if err := fn(ctx); err != nil {
		b.RecordFailure()
		return err
	}

	b.RecordSuccess()
	return nil
}
