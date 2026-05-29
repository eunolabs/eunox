// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package callcounter

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis is a Redis-backed call counter using atomic MULTI/EXEC increment with TTL.
type Redis struct {
	client redis.Cmdable
	// seq is an atomic monotonic counter appended to each ZADD member so that
	// two calls arriving in the same nanosecond produce distinct members.
	// Without this suffix, concurrent calls at the same UnixNano timestamp
	// would collide in the sorted set (ZADD updates the score instead of
	// inserting a new entry), causing the counter to undercount.
	seq atomic.Int64
}

// NewRedis creates a Redis-backed call counter.
func NewRedis(client redis.Cmdable) *Redis {
	return &Redis{client: client}
}

// IncrementAndGet atomically increments the counter for the given key and window
// using a Redis MULTI/EXEC transaction, then returns the new count. Uses a Redis
// sorted set with timestamps as scores for accurate sliding window counting.
func (r *Redis) IncrementAndGet(ctx context.Context, key string, windowSec int) (int64, error) {
	now := time.Now()
	windowKey := fmt.Sprintf("callcounter:%s:%d", key, windowSec)
	nowUnixMicro := float64(now.UnixMicro())
	cutoff := float64(now.Add(-time.Duration(windowSec) * time.Second).UnixMicro())
	member := fmt.Sprintf("%d-%d", now.UnixNano(), r.seq.Add(1))

	// Use a transactional pipeline (MULTI/EXEC) for atomicity
	pipe := r.client.TxPipeline()

	// Remove expired entries
	pipe.ZRemRangeByScore(ctx, windowKey, "-inf", fmt.Sprintf("%f", cutoff))

	// Add current timestamp
	pipe.ZAdd(ctx, windowKey, redis.Z{Score: nowUnixMicro, Member: member})

	// Count entries in window
	countCmd := pipe.ZCard(ctx, windowKey)

	// Set TTL for cleanup. M-6 fix: use a 2× safety margin instead of +1 s so
	// that entries at the start of the window are not evicted before the
	// ZREMRANGEBYSCORE cleanup fires under high clock skew (>1 s between app
	// and Redis). The TTL is used only for key cleanup; the margin has negligible
	// storage cost.
	pipe.Expire(ctx, windowKey, time.Duration(windowSec)*2*time.Second)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("redis pipeline: %w", err)
	}

	return countCmd.Val(), nil
}
