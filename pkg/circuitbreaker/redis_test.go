// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package circuitbreaker_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/edgeobs/eunox/pkg/circuitbreaker"
	"github.com/redis/go-redis/v9"
)

func newMiniredis(t *testing.T) *redis.Client {
	t.Helper()
	// Use a client pointing at nothing - we'll test error behavior.
	// For success tests, we use a real miniredis.
	client := redis.NewClient(&redis.Options{
		Addr: "127.0.0.1:1", // Guaranteed to fail connections.
	})
	t.Cleanup(func() { client.Close() })
	return client
}

func TestProtectedRedis_OpensOnFailures(t *testing.T) {
	cfg := circuitbreaker.Config{
		FailureThreshold:  2,
		CooldownDuration:  time.Minute,
		HalfOpenMaxProbes: 1,
	}
	b := circuitbreaker.New(cfg)
	client := newMiniredis(t)
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
	client := newMiniredis(t)
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
	client := newMiniredis(t)
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
	client := newMiniredis(t)
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
	client := newMiniredis(t)
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
	client := newMiniredis(t)
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
	client := newMiniredis(t)
	pr := circuitbreaker.NewProtectedRedis(client, b)

	if pr.Breaker() != b {
		t.Fatal("Breaker() should return the underlying breaker")
	}
}
