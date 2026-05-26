// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package testutil

import (
	"context"
	"fmt"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"
)

// PostgresContainer wraps a testcontainers PostgreSQL instance.
type PostgresContainer struct {
	Container *postgres.PostgresContainer
	DSN       string
}

// PostgresContainerConfig configures the PostgreSQL test container.
type PostgresContainerConfig struct {
	// Image is the Docker image to use (default: "postgres:16-alpine").
	Image string
	// Database is the database name (default: "eunox_test").
	Database string
	// Username (default: "eunox").
	Username string
	// Password (default: "eunox_test_password").
	Password string
	// InitScripts are SQL files to run on startup.
	InitScripts []string
}

// StartPostgres starts a PostgreSQL container for integration testing.
// The returned container must be terminated by calling Terminate.
func StartPostgres(ctx context.Context, cfg PostgresContainerConfig) (*PostgresContainer, error) {
	if cfg.Image == "" {
		cfg.Image = "postgres:16-alpine"
	}
	if cfg.Database == "" {
		cfg.Database = "eunox_test"
	}
	if cfg.Username == "" {
		cfg.Username = "eunox"
	}
	if cfg.Password == "" {
		cfg.Password = "eunox_test_password"
	}

	opts := []testcontainers.ContainerCustomizer{
		postgres.WithDatabase(cfg.Database),
		postgres.WithUsername(cfg.Username),
		postgres.WithPassword(cfg.Password),
		testcontainers.WithImage(cfg.Image),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30 * time.Second),
		),
	}

	for _, script := range cfg.InitScripts {
		opts = append(opts, postgres.WithInitScripts(script))
	}

	container, err := postgres.Run(ctx, cfg.Image, opts...)
	if err != nil {
		return nil, fmt.Errorf("testutil: start postgres container: %w", err)
	}

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("testutil: get postgres connection string: %w", err)
	}

	return &PostgresContainer{
		Container: container,
		DSN:       dsn,
	}, nil
}

// Terminate stops and removes the PostgreSQL container.
func (p *PostgresContainer) Terminate(ctx context.Context) error {
	if p.Container == nil {
		return nil
	}
	return p.Container.Terminate(ctx)
}

// RedisContainer wraps a testcontainers Redis instance.
type RedisContainer struct {
	Container *redis.RedisContainer
	Addr      string
}

// RedisContainerConfig configures the Redis test container.
type RedisContainerConfig struct {
	// Image is the Docker image to use (default: "redis:7-alpine").
	Image string
}

// StartRedis starts a Redis container for integration testing.
// The returned container must be terminated by calling Terminate.
func StartRedis(ctx context.Context, cfg RedisContainerConfig) (*RedisContainer, error) {
	if cfg.Image == "" {
		cfg.Image = "redis:7-alpine"
	}

	container, err := redis.Run(ctx, cfg.Image,
		testcontainers.WithWaitStrategy(
			wait.ForLog("Ready to accept connections").
				WithStartupTimeout(15*time.Second),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("testutil: start redis container: %w", err)
	}

	endpoint, err := container.Endpoint(ctx, "")
	if err != nil {
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("testutil: get redis endpoint: %w", err)
	}

	return &RedisContainer{
		Container: container,
		Addr:      endpoint,
	}, nil
}

// Terminate stops and removes the Redis container.
func (r *RedisContainer) Terminate(ctx context.Context) error {
	if r.Container == nil {
		return nil
	}
	return r.Container.Terminate(ctx)
}
