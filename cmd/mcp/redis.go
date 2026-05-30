// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

// Redis client construction for the eunox-mcp proxy (T-04).
//
// When --redis-addr is set the proxy replaces its default in-memory call
// counter and kill-switch manager with Redis-backed implementations so that
// state persists across restarts and is shared between multiple proxy
// instances.

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// buildRedisClient constructs a Redis client from simple host:port parameters.
// Unlike the gateway's URL-based factory, the proxy only needs a single-node
// client; sentinel and cluster modes can be added in a future task if needed.
//
// The returned client is not yet connected — callers must Ping before use.
func buildRedisClient(addr, password string, useTLS bool) (*goredis.Client, error) {
	if addr == "" {
		return nil, fmt.Errorf("redis address must not be empty")
	}
	opts := &goredis.Options{
		Addr:         addr,
		Password:     password,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}
	if useTLS {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return goredis.NewClient(opts), nil
}

// pingRedis checks connectivity to the Redis server.  Returns a descriptive
// error that is safe to print to stderr on startup failure.
func pingRedis(ctx context.Context, client *goredis.Client) error {
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		return fmt.Errorf("redis ping failed: %w (check --redis-addr, --redis-password, --redis-tls)", err)
	}
	return nil
}
