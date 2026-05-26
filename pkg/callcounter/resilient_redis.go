// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package callcounter

import (
	"context"

	"github.com/edgeobs/eunox/pkg/redisfailover"
)

// ResilientRedis wraps a Redis call counter with fail-open semantics.
// When Redis is unreachable, it returns a zero count (allowing the request)
// rather than blocking traffic. Call counters are used for usage tracking
// and billing, not security enforcement, so temporary under-counting during
// a Redis outage is acceptable.
//
// Failure policy: FAIL-OPEN — if Redis is unreachable, the counter returns 0
// (allowing the request through). Usage data may be under-counted during
// outages; reconciliation should happen when Redis recovers.
type ResilientRedis struct {
	inner    *Redis
	reporter *redisfailover.Reporter
}

// NewResilientRedis creates a fail-open resilient call counter.
func NewResilientRedis(inner *Redis, reporter *redisfailover.Reporter) *ResilientRedis {
	return &ResilientRedis{
		inner:    inner,
		reporter: reporter,
	}
}

// IncrementAndGet atomically increments and returns the new count.
// On Redis failure, returns 0 (fail-open: allows the request).
func (r *ResilientRedis) IncrementAndGet(ctx context.Context, key string, windowSec int) (count int64, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			r.reporter.MarkDegraded()
			count = 0
			err = nil
		}
	}()

	count, err = r.inner.IncrementAndGet(ctx, key, windowSec)
	if err != nil {
		r.reporter.MarkDegraded()
		return 0, nil
	}
	r.reporter.MarkHealthy()
	return count, nil
}
