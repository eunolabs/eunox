// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package revocation

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis is a Redis-backed revocation store.
type Redis struct {
	client redis.Cmdable
	prefix string
}

// NewRedis creates a Redis-backed revocation store.
func NewRedis(client redis.Cmdable) *Redis {
	return &Redis{
		client: client,
		prefix: "revocation:",
	}
}

// IsRevoked checks if a token has been revoked by looking up its JTI in Redis.
func (r *Redis) IsRevoked(ctx context.Context, jti string) (bool, error) {
	exists, err := r.client.Exists(ctx, r.prefix+jti).Result()
	if err != nil {
		return false, err
	}
	return exists > 0, nil
}

// Revoke marks a token as revoked in Redis with an optional TTL.
func (r *Redis) Revoke(ctx context.Context, jti string, ttl time.Duration) error {
	key := r.prefix + jti
	if ttl > 0 {
		return r.client.Set(ctx, key, "1", ttl).Err()
	}
	return r.client.Set(ctx, key, "1", 0).Err()
}
