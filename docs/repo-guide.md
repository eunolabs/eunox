# eunox — repository guide

> **Looking for a quick overview?** See the project [README](../README.md).
> This document covers how the repo is laid out, how to build it, and how to
> test changes.

## Overview

eunox is a Go repository for `eunox-mcp`, a policy-enforcement proxy for MCP servers,
built on the [Model Context Protocol](https://spec.modelcontextprotocol.io/).

## Prerequisites

- Go 1.25+
- golangci-lint v2.12+
- Docker (for integration tests and local deployment)

## Build & Test

```bash
# Build eunox-mcp
make build

# Run all tests with race detector
make test

# Run linter (go vet + golangci-lint)
make lint

# Generate coverage report
make coverage

# Check BSL license headers
make check-license
```

## Repository Layout

```
eunox/
├── cmd/
│   └── mcp/                # eunox-mcp proxy binary (Apache-2.0)
├── internal/
│   └── agentruntime/       # Manifest parsing and token management
├── pkg/                    # Importable packages
│   ├── capability/         # Constraint types, conditions, JWKS verification
│   ├── callcounter/        # Rate-limit call counting (in-memory and Redis)
│   ├── circuitbreaker/     # Circuit-breaker for upstream calls
│   ├── enforcement/        # PDP enforcement engine
│   ├── killswitch/         # Emergency kill switch (in-memory and Redis)
│   └── redisfailover/      # Redis fail-open/fail-closed policies
├── demo/                   # Runnable demo stack (Docker Compose + scripts)
├── deploy/docker/          # Dockerfiles for eunox-mcp
├── docs/                   # Documentation
└── scripts/                # Development scripts (benchmarks, etc.)
```

## CI

The GitHub Actions workflow (`.github/workflows/go-ci.yml`) runs:

- `go vet` + `golangci-lint`
- Tests with race detector and 80% coverage threshold for `pkg/`
- Apache-2.0 license header check
- Cross-compilation (linux/amd64, linux/arm64, windows/amd64, windows/arm64)

## Local Development Stack

```bash
# Start local demo stack
docker compose -f demo/docker-compose.yml up --build
```

## License

All code is licensed under the Apache License 2.0. See [`cmd/mcp/LICENSE`](../cmd/mcp/LICENSE).
