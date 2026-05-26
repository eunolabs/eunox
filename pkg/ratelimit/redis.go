// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package ratelimit

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

const redisSlidingWindowScript = `
local key = KEYS[1]
local now_us = tonumber(ARGV[1])
local window_us = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
local cutoff = now_us - window_us

redis.call("ZREMRANGEBYSCORE", key, "-inf", cutoff)

local count = redis.call("ZCARD", key)
local allowed = 0
if count < limit then
    redis.call("ZADD", key, now_us, member)
    count = count + 1
    allowed = 1
end

local earliest = 0
if count > 0 then
    local oldest = redis.call("ZRANGE", key, 0, 0, "WITHSCORES")
    if oldest[2] ~= nil then
        earliest = tonumber(oldest[2])
    end
    local ttl_ms = math.floor(window_us / 1000) + 1000
    redis.call("PEXPIRE", key, ttl_ms)
end

return {allowed, count, earliest}
`

type redisEvaler interface {
	Eval(ctx context.Context, script string, keys []string, args ...interface{}) ([]interface{}, error)
}

type redisClientAdapter struct {
	client *redis.Client
}

func (a *redisClientAdapter) Eval(ctx context.Context, script string, keys []string, args ...interface{}) ([]interface{}, error) {
	result, err := a.client.Eval(ctx, script, keys, args...).Result()
	if err != nil {
		return nil, err
	}
	values, ok := result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("ratelimit: unexpected redis result type %T", result)
	}
	return values, nil
}

// RedisLimiter implements distributed rate limiting using Redis sorted sets.
type RedisLimiter struct {
	client redisEvaler
	cfg    Config
	now    func() time.Time
	seq    atomic.Uint64
}

// NewRedis creates a Redis-backed distributed rate limiter.
func NewRedis(client *redis.Client, cfg Config) *RedisLimiter {
	limiter := &RedisLimiter{
		cfg: cfg,
		now: time.Now,
	}
	if client != nil {
		limiter.client = &redisClientAdapter{client: client}
	}
	return limiter
}

// Allow checks whether the request for key is allowed.
func (l *RedisLimiter) Allow(ctx context.Context, key string) (bool, error) {
	result, err := l.Check(ctx, key)
	if err != nil {
		return false, err
	}
	return result.Allowed, nil
}

// Check checks the rate limit for key and returns detailed result information.
func (l *RedisLimiter) Check(ctx context.Context, key string) (*Result, error) {
	if err := l.cfg.validate(); err != nil {
		return nil, err
	}
	if l.client == nil {
		return nil, fmt.Errorf("ratelimit: redis client is nil")
	}

	now := l.now()
	limit := l.cfg.limit()
	windowMicros := l.cfg.Window.Microseconds()
	member := fmt.Sprintf("%d-%d", now.UnixNano(), l.seq.Add(1))

	values, err := l.client.Eval(ctx, redisSlidingWindowScript, []string{l.redisKey(key)}, now.UnixMicro(), windowMicros, limit, member)
	if err != nil {
		return nil, fmt.Errorf("ratelimit: redis eval: %w", err)
	}
	if len(values) != 3 {
		return nil, fmt.Errorf("ratelimit: unexpected redis response length %d", len(values))
	}

	allowed, err := parseRedisInt(values[0])
	if err != nil {
		return nil, err
	}
	count, err := parseRedisInt(values[1])
	if err != nil {
		return nil, err
	}
	earliest, err := parseRedisInt(values[2])
	if err != nil {
		return nil, err
	}

	resetAfter := time.Duration(0)
	if earliest > 0 {
		resetAfter = clampDuration(time.UnixMicro(earliest).Add(l.cfg.Window).Sub(now))
	}

	remaining := 0
	if count < int64(limit) {
		remainingCount, err := safeInt64ToInt(count)
		if err != nil {
			return nil, err
		}
		remaining = limit - remainingCount
	}

	result := &Result{
		Allowed:    allowed == 1,
		Remaining:  remaining,
		ResetAfter: resetAfter,
	}
	if !result.Allowed {
		result.Remaining = 0
		result.RetryAfter = resetAfter
	}

	return result, nil
}

func (l *RedisLimiter) redisKey(key string) string {
	return fmt.Sprintf("ratelimit:%d:%d:%s", l.cfg.limit(), l.cfg.Window.Microseconds(), key)
}

func parseRedisInt(value interface{}) (int64, error) {
	switch v := value.(type) {
	case int64:
		return v, nil
	case int:
		return int64(v), nil
	case float64:
		if v > math.MaxInt64 || v < math.MinInt64 {
			return 0, fmt.Errorf("ratelimit: redis float %v out of int64 range", v)
		}
		return int64(v), nil
	case string:
		return strconv.ParseInt(v, 10, 64)
	default:
		return 0, fmt.Errorf("ratelimit: unexpected redis numeric type %T", value)
	}
}

func safeInt64ToInt(value int64) (int, error) {
	maxInt := int64(int(^uint(0) >> 1))
	minInt := -maxInt - 1
	if value > maxInt || value < minInt {
		return 0, fmt.Errorf("ratelimit: integer %d out of int range", value)
	}
	return int(value), nil
}
