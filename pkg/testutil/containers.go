// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

// Package testutil provides shared test infrastructure for the Eunox platform.
// The containers_integration.go file provides testcontainers-go helpers for PostgreSQL and Redis.
// These are gated behind the "integration" build tag because they require Docker.
//
// Usage:
//
//	go test -tags=integration ./...
//
// Prerequisites (add to go.mod when enabling):
//
//	github.com/testcontainers/testcontainers-go v0.38.0
//	github.com/testcontainers/testcontainers-go/modules/postgres v0.38.0
//	github.com/testcontainers/testcontainers-go/modules/redis v0.38.0
package testutil
