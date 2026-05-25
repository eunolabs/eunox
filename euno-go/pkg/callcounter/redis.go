// Copyright 2024-2025 Euno Platform Authors
// SPDX-License-Identifier: BUSL-1.1

package callcounter

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis is a Redis-backed call counter using atomic MULTI/EXEC increment with TTL.
type Redis struct {
	client redis.Cmdable
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
	member := fmt.Sprintf("%d", now.UnixNano())

	// Use a transactional pipeline (MULTI/EXEC) for atomicity
	pipe := r.client.TxPipeline()

	// Remove expired entries
	pipe.ZRemRangeByScore(ctx, windowKey, "-inf", fmt.Sprintf("%f", cutoff))

	// Add current timestamp
	pipe.ZAdd(ctx, windowKey, redis.Z{Score: nowUnixMicro, Member: member})

	// Count entries in window
	countCmd := pipe.ZCard(ctx, windowKey)

	// Set TTL for cleanup
	pipe.Expire(ctx, windowKey, time.Duration(windowSec)*time.Second+time.Second)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("redis pipeline: %w", err)
	}

	return countCmd.Val(), nil
}
