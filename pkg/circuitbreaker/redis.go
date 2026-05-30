// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package circuitbreaker

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// ProtectedRedis wraps a redis.Cmdable with circuit breaker protection.
// When the breaker is open, commands return ErrOpen immediately. This is
// suitable for Redis dependencies where a failing connection should not
// cause cascading latency.
type ProtectedRedis struct {
	inner   redis.Cmdable
	breaker *Breaker
}

// NewProtectedRedis creates a Redis client wrapper protected by a circuit breaker.
func NewProtectedRedis(inner redis.Cmdable, breaker *Breaker) *ProtectedRedis {
	if inner == nil {
		panic("circuitbreaker: redis client must not be nil")
	}
	if breaker == nil {
		panic("circuitbreaker: breaker must not be nil")
	}
	return &ProtectedRedis{inner: inner, breaker: breaker}
}

// Breaker returns the underlying circuit breaker for status inspection.
func (pr *ProtectedRedis) Breaker() *Breaker { return pr.breaker }

// Get executes a Redis GET command with circuit breaker protection.
func (pr *ProtectedRedis) Get(ctx context.Context, key string) *redis.StringCmd {
	if !pr.breaker.Allow() {
		cmd := redis.NewStringCmd(ctx, "get", key)
		cmd.SetErr(ErrOpen)
		return cmd
	}
	cmd := pr.inner.Get(ctx, key)
	pr.recordResult(cmd.Err())
	return cmd
}

// Set executes a Redis SET command with circuit breaker protection.
func (pr *ProtectedRedis) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	if !pr.breaker.Allow() {
		cmd := redis.NewStatusCmd(ctx, "set", key, value)
		cmd.SetErr(ErrOpen)
		return cmd
	}
	cmd := pr.inner.Set(ctx, key, value, expiration)
	pr.recordResult(cmd.Err())
	return cmd
}

// Del executes a Redis DEL command with circuit breaker protection.
func (pr *ProtectedRedis) Del(ctx context.Context, keys ...string) *redis.IntCmd {
	if !pr.breaker.Allow() {
		args := make([]interface{}, 0, 1+len(keys))
		args = append(args, "del")
		for _, k := range keys {
			args = append(args, k)
		}
		cmd := redis.NewIntCmd(ctx, args...)
		cmd.SetErr(ErrOpen)
		return cmd
	}
	cmd := pr.inner.Del(ctx, keys...)
	pr.recordResult(cmd.Err())
	return cmd
}

// Exists executes a Redis EXISTS command with circuit breaker protection.
func (pr *ProtectedRedis) Exists(ctx context.Context, keys ...string) *redis.IntCmd {
	if !pr.breaker.Allow() {
		args := make([]interface{}, 0, 1+len(keys))
		args = append(args, "exists")
		for _, k := range keys {
			args = append(args, k)
		}
		cmd := redis.NewIntCmd(ctx, args...)
		cmd.SetErr(ErrOpen)
		return cmd
	}
	cmd := pr.inner.Exists(ctx, keys...)
	pr.recordResult(cmd.Err())
	return cmd
}

// Incr executes a Redis INCR command with circuit breaker protection.
func (pr *ProtectedRedis) Incr(ctx context.Context, key string) *redis.IntCmd {
	if !pr.breaker.Allow() {
		cmd := redis.NewIntCmd(ctx, "incr", key)
		cmd.SetErr(ErrOpen)
		return cmd
	}
	cmd := pr.inner.Incr(ctx, key)
	pr.recordResult(cmd.Err())
	return cmd
}

// Expire executes a Redis EXPIRE command with circuit breaker protection.
func (pr *ProtectedRedis) Expire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd {
	if !pr.breaker.Allow() {
		cmd := redis.NewBoolCmd(ctx, "expire", key)
		cmd.SetErr(ErrOpen)
		return cmd
	}
	cmd := pr.inner.Expire(ctx, key, expiration)
	pr.recordResult(cmd.Err())
	return cmd
}

// Publish executes a Redis PUBLISH command with circuit breaker protection.
func (pr *ProtectedRedis) Publish(ctx context.Context, channel string, message interface{}) *redis.IntCmd {
	if !pr.breaker.Allow() {
		cmd := redis.NewIntCmd(ctx, "publish", channel, message)
		cmd.SetErr(ErrOpen)
		return cmd
	}
	cmd := pr.inner.Publish(ctx, channel, message)
	pr.recordResult(cmd.Err())
	return cmd
}

// Eval executes a Redis EVAL command with circuit breaker protection.
func (pr *ProtectedRedis) Eval(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd {
	if !pr.breaker.Allow() {
		evalArgs := make([]interface{}, 0, 3+len(keys)+len(args))
		evalArgs = append(evalArgs, "eval", script, len(keys))
		for _, key := range keys {
			evalArgs = append(evalArgs, key)
		}
		evalArgs = append(evalArgs, args...)
		cmd := redis.NewCmd(ctx, evalArgs...)
		cmd.SetErr(ErrOpen)
		return cmd
	}
	cmd := pr.inner.Eval(ctx, script, keys, args...)
	pr.recordResult(cmd.Err())
	return cmd
}

// recordResult records success or failure based on the command error.
// redis.Nil is treated as a success (key not found is not a connection failure).
func (pr *ProtectedRedis) recordResult(err error) {
	if err == nil || err == redis.Nil {
		pr.breaker.RecordSuccess()
	} else {
		pr.breaker.RecordFailure()
	}
}
