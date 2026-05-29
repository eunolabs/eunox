// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package ratelimit

import (
	"context"

	"github.com/eunolabs/eunox/pkg/redisfailover"
	"github.com/prometheus/client_golang/prometheus"
)

// ResilientRedisOption is a functional option for [NewResilientRedis].
type ResilientRedisOption func(*ResilientRedisLimiter)

// WithPrometheusRegisterer registers a Prometheus gauge that tracks the
// degradation state of the [ResilientRedisLimiter].
//
// The gauge is exported as:
//
//	ratelimit_redis_degraded{component="<component>"}
//
// Value 1 means Redis is unavailable and the limiter is in degraded (fail-open)
// mode; value 0 means Redis is reachable and operating normally.
func WithPrometheusRegisterer(reg prometheus.Registerer, component string) ResilientRedisOption {
	return func(r *ResilientRedisLimiter) {
		g := prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Namespace: "ratelimit",
				Name:      "redis_degraded",
				Help:      "1 when the Redis rate-limiter is operating in degraded (fail-open) mode, 0 when healthy.",
				ConstLabels: prometheus.Labels{
					"component": component,
				},
			},
			func() float64 {
				if r.reporter.State() == redisfailover.Degraded {
					return 1
				}
				return 0
			},
		)
		// Ignore registration errors — a duplicate registration means the
		// gauge is already being tracked (e.g. in tests with shared registries).
		_ = reg.Register(g)
		r.degradedGauge = g
	}
}

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

	// degradedGauge is optionally registered by WithPrometheusRegisterer.
	degradedGauge prometheus.Collector
}

// NewResilientRedis creates a fail-open resilient rate limiter that falls
// back to in-memory limiting when Redis is unreachable.
// Optional [ResilientRedisOption] functions can be used to extend behaviour,
// for example adding Prometheus metrics with [WithPrometheusRegisterer].
func NewResilientRedis(primary *RedisLimiter, cfg Config, reporter *redisfailover.Reporter, opts ...ResilientRedisOption) *ResilientRedisLimiter {
	r := &ResilientRedisLimiter{
		primary:  primary,
		fallback: NewInMemory(cfg),
		reporter: reporter,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
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
