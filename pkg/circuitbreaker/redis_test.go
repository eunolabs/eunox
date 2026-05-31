// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package circuitbreaker_test

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/eunolabs/eunox/pkg/circuitbreaker"
	"github.com/redis/go-redis/v9"
)

func newFailingRedisClient(t *testing.T) *redis.Client {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	client := redis.NewClient(&redis.Options{
		Addr: addr,
	})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestProtectedRedis_OpensOnFailures(t *testing.T) {
	cfg := circuitbreaker.Config{
		FailureThreshold:  2,
		CooldownDuration:  time.Minute,
		HalfOpenMaxProbes: 1,
	}
	b := circuitbreaker.New(cfg)
	client := newFailingRedisClient(t)
	pr := circuitbreaker.NewProtectedRedis(client, b)

	ctx := context.Background()

	// First two calls fail (connection refused) - opens breaker.
	_ = pr.Get(ctx, "key1")
	_ = pr.Get(ctx, "key2")

	// Third call should be rejected by circuit breaker.
	cmd := pr.Get(ctx, "key3")
	if !errors.Is(cmd.Err(), circuitbreaker.ErrOpen) {
		t.Fatalf("expected ErrOpen, got %v", cmd.Err())
	}
}

func TestProtectedRedis_SetOpensOnFailures(t *testing.T) {
	cfg := circuitbreaker.Config{
		FailureThreshold:  1,
		CooldownDuration:  time.Minute,
		HalfOpenMaxProbes: 1,
	}
	b := circuitbreaker.New(cfg)
	client := newFailingRedisClient(t)
	pr := circuitbreaker.NewProtectedRedis(client, b)

	ctx := context.Background()

	// First call fails - opens breaker.
	_ = pr.Set(ctx, "key", "value", time.Minute)

	// Second call should be rejected.
	cmd := pr.Set(ctx, "key", "value", time.Minute)
	if !errors.Is(cmd.Err(), circuitbreaker.ErrOpen) {
		t.Fatalf("expected ErrOpen, got %v", cmd.Err())
	}
}

func TestProtectedRedis_DelOpensOnFailures(t *testing.T) {
	cfg := circuitbreaker.Config{
		FailureThreshold:  1,
		CooldownDuration:  time.Minute,
		HalfOpenMaxProbes: 1,
	}
	b := circuitbreaker.New(cfg)
	client := newFailingRedisClient(t)
	pr := circuitbreaker.NewProtectedRedis(client, b)

	ctx := context.Background()
	_ = pr.Del(ctx, "key")

	cmd := pr.Del(ctx, "key")
	if !errors.Is(cmd.Err(), circuitbreaker.ErrOpen) {
		t.Fatalf("expected ErrOpen, got %v", cmd.Err())
	}
}

func TestProtectedRedis_ExistsOpensOnFailures(t *testing.T) {
	cfg := circuitbreaker.Config{
		FailureThreshold:  1,
		CooldownDuration:  time.Minute,
		HalfOpenMaxProbes: 1,
	}
	b := circuitbreaker.New(cfg)
	client := newFailingRedisClient(t)
	pr := circuitbreaker.NewProtectedRedis(client, b)

	ctx := context.Background()
	_ = pr.Exists(ctx, "key")

	cmd := pr.Exists(ctx, "key")
	if !errors.Is(cmd.Err(), circuitbreaker.ErrOpen) {
		t.Fatalf("expected ErrOpen, got %v", cmd.Err())
	}
}

func TestProtectedRedis_IncrOpensOnFailures(t *testing.T) {
	cfg := circuitbreaker.Config{
		FailureThreshold:  1,
		CooldownDuration:  time.Minute,
		HalfOpenMaxProbes: 1,
	}
	b := circuitbreaker.New(cfg)
	client := newFailingRedisClient(t)
	pr := circuitbreaker.NewProtectedRedis(client, b)

	ctx := context.Background()
	_ = pr.Incr(ctx, "key")

	cmd := pr.Incr(ctx, "key")
	if !errors.Is(cmd.Err(), circuitbreaker.ErrOpen) {
		t.Fatalf("expected ErrOpen, got %v", cmd.Err())
	}
}

func TestProtectedRedis_PublishOpensOnFailures(t *testing.T) {
	cfg := circuitbreaker.Config{
		FailureThreshold:  1,
		CooldownDuration:  time.Minute,
		HalfOpenMaxProbes: 1,
	}
	b := circuitbreaker.New(cfg)
	client := newFailingRedisClient(t)
	pr := circuitbreaker.NewProtectedRedis(client, b)

	ctx := context.Background()
	_ = pr.Publish(ctx, "chan", "msg")

	cmd := pr.Publish(ctx, "chan", "msg")
	if !errors.Is(cmd.Err(), circuitbreaker.ErrOpen) {
		t.Fatalf("expected ErrOpen, got %v", cmd.Err())
	}
}

func TestProtectedRedis_BreakerAccessor(t *testing.T) {
	cfg := circuitbreaker.DefaultConfig()
	b := circuitbreaker.New(cfg)
	client := newFailingRedisClient(t)
	pr := circuitbreaker.NewProtectedRedis(client, b)

	if pr.Breaker() != b {
		t.Fatal("Breaker() should return the underlying breaker")
	}
}

func TestProtectedRedis_EvalOpenIncludesAllArgs(t *testing.T) {
	cfg := circuitbreaker.Config{
		FailureThreshold:  1,
		CooldownDuration:  time.Minute,
		HalfOpenMaxProbes: 1,
	}
	b := circuitbreaker.New(cfg)
	b.RecordFailure()
	client := newFailingRedisClient(t)
	pr := circuitbreaker.NewProtectedRedis(client, b)

	cmd := pr.Eval(context.Background(), "return ARGV[1]", []string{"k1", "k2"}, "a1", 2)
	if !errors.Is(cmd.Err(), circuitbreaker.ErrOpen) {
		t.Fatalf("expected ErrOpen, got %v", cmd.Err())
	}

	want := []interface{}{"eval", "return ARGV[1]", 2, "k1", "k2", "a1", 2}
	if !reflect.DeepEqual(cmd.Args(), want) {
		t.Fatalf("unexpected args: got %v want %v", cmd.Args(), want)
	}
}

func TestProtectedRedis_NilInputsPanic(t *testing.T) {
	b := circuitbreaker.New(circuitbreaker.DefaultConfig())
	client := newFailingRedisClient(t)

	t.Run("nil breaker", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("expected panic for nil breaker")
			}
		}()
		_ = circuitbreaker.NewProtectedRedis(client, nil)
	})

	t.Run("nil client", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("expected panic for nil client")
			}
		}()
		_ = circuitbreaker.NewProtectedRedis(nil, b)
	})
}
