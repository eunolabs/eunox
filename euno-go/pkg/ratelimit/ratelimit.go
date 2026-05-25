// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

// Package ratelimit provides pluggable rate-limiting backends.
package ratelimit

import (
	"context"
	"errors"
	"time"
)

var (
	errInvalidRate   = errors.New("ratelimit: rate must be greater than zero")
	errInvalidWindow = errors.New("ratelimit: window must be greater than zero")
)

// Limiter provides rate-limiting decisions.
type Limiter interface {
	// Allow checks if a request identified by key is allowed.
	// Returns true if allowed, false if rate-limited.
	Allow(ctx context.Context, key string) (bool, error)
}

// Config configures a rate limiter.
type Config struct {
	Rate   int           // Maximum number of requests.
	Window time.Duration // Time window for the rate limit.
	Burst  int           // Maximum burst size (for token bucket).
}

// Result provides detailed rate limit information.
type Result struct {
	Allowed    bool
	Remaining  int
	ResetAfter time.Duration
	RetryAfter time.Duration
}

// DetailedLimiter provides rate-limiting with detailed result info.
type DetailedLimiter interface {
	// Check checks rate limit and returns detailed result.
	Check(ctx context.Context, key string) (*Result, error)
}

func (c Config) validate() error {
	if c.limit() <= 0 {
		return errInvalidRate
	}
	if c.Window <= 0 {
		return errInvalidWindow
	}
	return nil
}

func (c Config) limit() int {
	if c.Rate > 0 {
		return c.Rate
	}
	return c.Burst
}

func clampDuration(d time.Duration) time.Duration {
	if d < 0 {
		return 0
	}
	return d
}
