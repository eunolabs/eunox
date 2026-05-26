// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package ratelimit

import (
	"context"

	"github.com/edgeobs/eunox/pkg/redisfailover"
)

// ResilientRedisLimiter wraps a Redis rate limiter with fail-open semantics.
// When Redis is unreachable, it falls back to an in-memory rate limiter to
// provide best-effort rate limiting without blocking legitimate traffic.
//
// Failure policy: FAIL-OPEN — if Redis is unreachable, requests are allowed
// subject to the local in-memory rate limiter (which tracks per-instance
// limits rather than global distributed limits). This means the effective
// limit may temporarily be multiplied by the number of instances.
type ResilientRedisLimiter struct {
	primary  *RedisLimiter
	fallback *InMemoryLimiter
	reporter *redisfailover.Reporter
}

// NewResilientRedis creates a fail-open resilient rate limiter that falls
// back to in-memory limiting when Redis is unreachable.
func NewResilientRedis(primary *RedisLimiter, cfg Config, reporter *redisfailover.Reporter) *ResilientRedisLimiter {
	return &ResilientRedisLimiter{
		primary:  primary,
		fallback: NewInMemory(cfg),
		reporter: reporter,
	}
}

// Allow checks rate limit, falling back to in-memory limiter on Redis failure.
func (r *ResilientRedisLimiter) Allow(ctx context.Context, key string) (bool, error) {
	allowed, err := r.primary.Allow(ctx, key)
	if err != nil {
		r.reporter.MarkDegraded()
		// Fail-open: use local fallback
		return r.fallback.Allow(ctx, key)
	}
	r.reporter.MarkHealthy()
	return allowed, nil
}

// Check checks rate limit with detailed results, falling back on Redis failure.
func (r *ResilientRedisLimiter) Check(ctx context.Context, key string) (*Result, error) {
	result, err := r.primary.Check(ctx, key)
	if err != nil {
		r.reporter.MarkDegraded()
		// Fail-open: use local fallback
		return r.fallback.Check(ctx, key)
	}
	r.reporter.MarkHealthy()
	return result, nil
}

// Close stops the fallback limiter's cleanup loop.
func (r *ResilientRedisLimiter) Close() {
	r.fallback.Close()
}
