// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// Package testutil provides shared test infrastructure for the Euno platform.
// The containers.go file provides testcontainers-go helpers for PostgreSQL and Redis.
// These are gated behind the "integration" build tag because they require Docker.
//
// Usage:
//
//	go test -tags=integration ./...
//
// To use in Stage 2+, add the following to go.mod:
//
//	github.com/testcontainers/testcontainers-go v0.38.0
//	github.com/testcontainers/testcontainers-go/modules/postgres v0.38.0
//	github.com/testcontainers/testcontainers-go/modules/redis v0.38.0
package testutil

// TODO(Stage 2): Uncomment and add testcontainers-go dependency when integration tests are needed.
//
// import (
//     "context"
//     "fmt"
//     "testing"
//     "time"
//
//     "github.com/testcontainers/testcontainers-go"
//     "github.com/testcontainers/testcontainers-go/modules/postgres"
//     "github.com/testcontainers/testcontainers-go/modules/redis"
//     "github.com/testcontainers/testcontainers-go/wait"
// )
//
// // PostgresContainer starts a PostgreSQL testcontainer and returns the connection URL.
// // The container is automatically cleaned up when the test finishes.
// func PostgresContainer(t *testing.T, ctx context.Context) string {
//     t.Helper()
//     container, err := postgres.Run(ctx,
//         "postgres:16-alpine",
//         postgres.WithDatabase("test"),
//         postgres.WithUsername("test"),
//         postgres.WithPassword("test"),
//         testcontainers.WithWaitStrategy(
//             wait.ForListeningPort("5432/tcp").WithStartupTimeout(30*time.Second),
//         ),
//     )
//     if err != nil {
//         t.Fatalf("start postgres container: %v", err)
//     }
//     t.Cleanup(func() {
//         if err := container.Terminate(ctx); err != nil {
//             t.Errorf("terminate postgres container: %v", err)
//         }
//     })
//     connStr, err := container.ConnectionString(ctx, "sslmode=disable")
//     if err != nil {
//         t.Fatalf("postgres connection string: %v", err)
//     }
//     return connStr
// }
//
// // RedisContainer starts a Redis testcontainer and returns the connection URL.
// // The container is automatically cleaned up when the test finishes.
// func RedisContainer(t *testing.T, ctx context.Context) string {
//     t.Helper()
//     container, err := redis.Run(ctx,
//         "redis:7-alpine",
//         testcontainers.WithWaitStrategy(
//             wait.ForListeningPort("6379/tcp").WithStartupTimeout(30*time.Second),
//         ),
//     )
//     if err != nil {
//         t.Fatalf("start redis container: %v", err)
//     }
//     t.Cleanup(func() {
//         if err := container.Terminate(ctx); err != nil {
//             t.Errorf("terminate redis container: %v", err)
//         }
//     })
//     host, err := container.Host(ctx)
//     if err != nil {
//         t.Fatalf("redis host: %v", err)
//     }
//     port, err := container.MappedPort(ctx, "6379/tcp")
//     if err != nil {
//         t.Fatalf("redis port: %v", err)
//     }
//     return fmt.Sprintf("redis://%s:%s", host, port.Port())
// }
