// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/edgeobs/eunox/pkg/config"
	"github.com/edgeobs/eunox/pkg/ratelimit"
)

func TestBuildRateLimiter_UsesRedisWhenConfigured(t *testing.T) {
	limiter := buildRateLimiter(config.IssuerConfig{
		RateLimitPerMinute: 60,
		RedisURL:           "redis://localhost:6379/0",
	}, nil)

	_, isRedis := limiter.(*ratelimit.RedisLimiter)
	assert.True(t, isRedis)
}

func TestBuildRateLimiter_FallsBackToInMemoryOnInvalidRedisURL(t *testing.T) {
	limiter := buildRateLimiter(config.IssuerConfig{
		RateLimitPerMinute: 60,
		RedisURL:           "://not-a-valid-redis-url",
	}, nil)

	_, isMemory := limiter.(*ratelimit.InMemoryLimiter)
	assert.True(t, isMemory)
}
