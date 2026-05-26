// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package ratelimit_test

import (
	"context"
	"testing"
	"time"

	"github.com/edgeobs/eunox/pkg/ratelimit"
	"github.com/edgeobs/eunox/pkg/redisfailover"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResilientRedisLimiter_FallsBackOnFailure(t *testing.T) {
	monitor := redisfailover.NewMonitor()
	reporter := monitor.Register("ratelimit")

	cfg := ratelimit.Config{Rate: 5, Window: time.Minute}

	// Create a Redis limiter with nil client (will fail immediately)
	primary := ratelimit.NewRedis(nil, cfg)
	resilient := ratelimit.NewResilientRedis(primary, cfg, reporter)
	defer resilient.Close()

	// Should fall back to in-memory limiter (fail-open)
	allowed, err := resilient.Allow(context.Background(), "test-key")
	require.NoError(t, err)
	assert.True(t, allowed, "should fail-open and allow request via in-memory fallback")

	// Health should be degraded
	assert.Equal(t, redisfailover.Degraded, reporter.State())
	assert.False(t, monitor.IsReady())
}

func TestResilientRedisLimiter_InMemoryEnforcesLimits(t *testing.T) {
	monitor := redisfailover.NewMonitor()
	reporter := monitor.Register("ratelimit")

	cfg := ratelimit.Config{Rate: 3, Window: time.Minute}

	// nil client forces immediate fallback to in-memory
	primary := ratelimit.NewRedis(nil, cfg)
	resilient := ratelimit.NewResilientRedis(primary, cfg, reporter)
	defer resilient.Close()

	ctx := context.Background()

	// First 3 should be allowed
	for i := range 3 {
		allowed, err := resilient.Allow(ctx, "key")
		require.NoError(t, err)
		assert.True(t, allowed, "request %d should be allowed", i+1)
	}

	// 4th should be rate-limited
	allowed, err := resilient.Allow(ctx, "key")
	require.NoError(t, err)
	assert.False(t, allowed, "4th request should be rate-limited by in-memory fallback")
}

func TestResilientRedisLimiter_Check_FallsBack(t *testing.T) {
	monitor := redisfailover.NewMonitor()
	reporter := monitor.Register("ratelimit")

	cfg := ratelimit.Config{Rate: 10, Window: time.Minute}
	primary := ratelimit.NewRedis(nil, cfg)
	resilient := ratelimit.NewResilientRedis(primary, cfg, reporter)
	defer resilient.Close()

	result, err := resilient.Check(context.Background(), "key")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.Equal(t, 9, result.Remaining)

	_ = monitor // suppress unused
}
