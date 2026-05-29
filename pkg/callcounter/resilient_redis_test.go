// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package callcounter_test

import (
	"context"
	"testing"

	"github.com/eunolabs/eunox/pkg/callcounter"
	"github.com/eunolabs/eunox/pkg/redisfailover"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
