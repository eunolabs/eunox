// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	redisPartnerDIDHashKey = "partner_dids"
)

// RedisPartnerDIDStore provides a Redis-backed implementation of PartnerDIDStore.
// It uses a Redis hash map for persistent storage of partner DID registrations,
// enabling multi-replica consistency without data loss on pod restart.
type RedisPartnerDIDStore struct {
	client redis.Cmdable
	now    func() time.Time
	logger *slog.Logger
}

// NewRedisPartnerDIDStore creates a new Redis-backed partner DID store.
func NewRedisPartnerDIDStore(client redis.Cmdable) *RedisPartnerDIDStore {
	return &RedisPartnerDIDStore{
		client: client,
		now:    time.Now,
	}
}

// WithLogger sets an optional structured logger on the store for operational visibility.
func (s *RedisPartnerDIDStore) WithLogger(logger *slog.Logger) *RedisPartnerDIDStore {
	s.logger = logger
	return s
}

// Register adds a new partner DID to the store.
func (s *RedisPartnerDIDStore) Register(did, name, description string) error {
	now := s.now()
	p := &PartnerDID{
		DID:          did,
		Name:         name,
		Description:  description,
		Status:       "pending",
		RegisteredAt: now,
		UpdatedAt:    now,
	}

	data, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("partner DID store: marshal: %w", err)
	}

	ctx := context.Background()
	if err := s.client.HSet(ctx, redisPartnerDIDHashKey, did, data).Err(); err != nil {
		return fmt.Errorf("partner DID store: register: %w", err)
	}
	return nil
}

// Unregister removes a partner DID from the store.
func (s *RedisPartnerDIDStore) Unregister(did string) error {
	ctx := context.Background()
	n, err := s.client.HDel(ctx, redisPartnerDIDHashKey, did).Result()
	if err != nil {
		return fmt.Errorf("partner DID store: unregister: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("%w: %s", ErrPartnerDIDNotFound, did)
	}
	return nil
}

// List returns all registered partner DIDs.
func (s *RedisPartnerDIDStore) List() []PartnerDID {
	ctx := context.Background()
	result, err := s.client.HGetAll(ctx, redisPartnerDIDHashKey).Result()
	if err != nil {
		if s.logger != nil {
			s.logger.Error("partner DID store: list failed", slog.String("error", err.Error()))
		}
		return []PartnerDID{}
	}

	partners := make([]PartnerDID, 0, len(result))
	for _, data := range result {
		var p PartnerDID
		if err := json.Unmarshal([]byte(data), &p); err != nil {
			if s.logger != nil {
				s.logger.Error("partner DID store: unmarshal failed", slog.String("error", err.Error()))
			}
			continue
		}
		partners = append(partners, p)
	}
	return partners
}

// Get retrieves a partner DID by its identifier.
func (s *RedisPartnerDIDStore) Get(did string) (*PartnerDID, bool) {
	ctx := context.Background()
	data, err := s.client.HGet(ctx, redisPartnerDIDHashKey, did).Result()
	if err != nil {
		if err != redis.Nil && s.logger != nil {
			s.logger.Error("partner DID store: get failed", slog.String("did", did), slog.String("error", err.Error()))
		}
		return nil, false
	}

	var p PartnerDID
	if err := json.Unmarshal([]byte(data), &p); err != nil {
		return nil, false
	}
	return &p, true
}

// SetStatus updates the status of a partner DID.
func (s *RedisPartnerDIDStore) SetStatus(did, status string) error {
	ctx := context.Background()
	data, err := s.client.HGet(ctx, redisPartnerDIDHashKey, did).Result()
	if err != nil {
		if err == redis.Nil {
			return fmt.Errorf("%w: %s", ErrPartnerDIDNotFound, did)
		}
		return fmt.Errorf("partner DID store: get for status update: %w", err)
	}

	var p PartnerDID
	if err := json.Unmarshal([]byte(data), &p); err != nil {
		return fmt.Errorf("partner DID store: unmarshal for status update: %w", err)
	}

	p.Status = status
	p.UpdatedAt = s.now()

	updated, err := json.Marshal(&p)
	if err != nil {
		return fmt.Errorf("partner DID store: marshal for status update: %w", err)
	}

	if err := s.client.HSet(ctx, redisPartnerDIDHashKey, did, updated).Err(); err != nil {
		return fmt.Errorf("partner DID store: set status: %w", err)
	}
	return nil
}

// Compile-time interface check.
var _ PartnerDIDStore = (*RedisPartnerDIDStore)(nil)
