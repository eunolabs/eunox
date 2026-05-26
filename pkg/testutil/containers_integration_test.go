// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package testutil

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStartPostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pg, err := StartPostgres(ctx, PostgresContainerConfig{})
	require.NoError(t, err)
	defer func() { _ = pg.Terminate(ctx) }()

	assert.NotEmpty(t, pg.DSN)
	assert.Contains(t, pg.DSN, "eunox_test")
}

func TestStartRedis(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	rc, err := StartRedis(ctx, RedisContainerConfig{})
	require.NoError(t, err)
	defer func() { _ = rc.Terminate(ctx) }()

	assert.NotEmpty(t, rc.Addr)
}

func TestStartPostgres_CustomConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pg, err := StartPostgres(ctx, PostgresContainerConfig{
		Database: "custom_db",
		Username: "custom_user",
		Password: "custom_pass",
	})
	require.NoError(t, err)
	defer func() { _ = pg.Terminate(ctx) }()

	assert.Contains(t, pg.DSN, "custom_db")
	assert.Contains(t, pg.DSN, "custom_user")
}
