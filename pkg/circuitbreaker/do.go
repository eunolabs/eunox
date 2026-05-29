// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package circuitbreaker

import "context"

// Do executes fn only if the breaker allows it. It records success/failure
// based on the returned error (nil = success). If the breaker is open it
// returns ErrOpen without calling fn. Context cancellation is respected.
//
// Invariants (programming errors that panic):
//   - b must not be nil; pass a properly constructed [Breaker] from [New].
//   - fn must not be nil; provide the function to guard.
//
// These panics are intentional constructor-guard invariants. They surface
// misuse at call-site rather than producing silent misbehaviour at runtime.
// Callers initialising the breaker during service start-up should treat a
// panic here as a fatal configuration error.
func Do[T any](ctx context.Context, b *Breaker, fn func(ctx context.Context) (T, error)) (T, error) {
	var zero T
	if b == nil {
		panic("circuitbreaker: breaker must not be nil")
	}
	if fn == nil {
		panic("circuitbreaker: fn must not be nil")
	}

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
//
// Invariants (programming errors that panic):
//   - b must not be nil; pass a properly constructed [Breaker] from [New].
//   - fn must not be nil; provide the function to guard.
func DoVoid(ctx context.Context, b *Breaker, fn func(ctx context.Context) error) error {
	if b == nil {
		panic("circuitbreaker: breaker must not be nil")
	}
	if fn == nil {
		panic("circuitbreaker: fn must not be nil")
	}

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
