// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package callcounter_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/redisfailover"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResilientRedis_ErrorPath_MarksDegraded verifies that a real Redis connection
// error (not a panic) causes IncrementAndGet to mark the reporter degraded and
// return (0, nil) — fail-open semantics without propagating the error.
func TestResilientRedis_ErrorPath_MarksDegraded(t *testing.T) {
	t.Parallel()
	// A non-nil client pointing at a port that refuses connections: this causes
	// IncrementAndGet to return a real error rather than panicking (nil-client path).
	client := redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:1",
		DialTimeout: 50 * time.Millisecond,
	})
	t.Cleanup(func() { _ = client.Close() })

	monitor := redisfailover.NewMonitor()
	reporter := monitor.Register("err-path")
	inner := callcounter.NewRedis(client)
	resilient := callcounter.NewResilientRedis(inner, reporter)

	count, err := resilient.IncrementAndGet(context.Background(), "key", 60)
	require.NoError(t, err, "fail-open: error must be swallowed")
	assert.Equal(t, int64(0), count, "fail-open: count must be 0 on inner error")
	assert.False(t, monitor.IsReady(), "reporter must be degraded after inner Redis error")
}

func TestResilientRedis_FailOpen_ReturnsZero(t *testing.T) {
	monitor := redisfailover.NewMonitor()
	reporter := monitor.Register("callcounter")

	// Create with nil Redis client (will fail on call)
	inner := callcounter.NewRedis(nil)
	resilient := callcounter.NewResilientRedis(inner, reporter)

	count, err := resilient.IncrementAndGet(context.Background(), "test-key", 60)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count, "should return 0 on Redis failure (fail-open)")

	assert.Equal(t, redisfailover.Degraded, reporter.State())
	assert.False(t, monitor.IsReady())
}

func TestResilientRedis_SuccessMarkHealthy(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	monitor := redisfailover.NewMonitor()
	reporter := monitor.Register("callcounter-healthy")

	inner := callcounter.NewRedis(client)
	resilient := callcounter.NewResilientRedis(inner, reporter)

	count, err := resilient.IncrementAndGet(context.Background(), "test-key", 60)
	require.NoError(t, err)
	assert.Greater(t, count, int64(0), "count must be positive after successful increment")
	assert.True(t, monitor.IsReady(), "monitor must be ready after successful Redis call")
}
