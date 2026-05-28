# eunox — repository guide

> **Looking for a quick overview?** See the project [README](../README.md).
> This document covers how the repo is laid out, how to build it, and how to
> test changes.

## Overview

eunox is a Go monorepo containing all enterprise platform services for AI agent
policy enforcement via the [Model Context Protocol](https://spec.modelcontextprotocol.io/).

## Prerequisites

- Go 1.25+
- golangci-lint v2.12+
- Docker (for integration tests and local deployment)

## Build & Test

```bash
# Build all services
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
├── cmd/                    # Service binaries (main packages)
│   ├── gateway/            # Enforcement Gateway
│   ├── issuer/             # Capability Issuer
│   ├── minter/             # API-Key Minter
│   ├── db-token-svc/       # DB Token Service
│   ├── storage-grant-svc/  # Storage Grant Service
│   ├── posture-emitter/    # Posture Emitter
│   └── mcp/                # MCP proxy PDP/PEP (Apache-2.0 license)
├── internal/               # Private application logic (not importable)
│   ├── gateway/
│   ├── issuer/
│   ├── minter/
│   ├── dbtokensvc/
│   ├── storagegrantsvc/
│   ├── agentruntime/
│   ├── posture/
│   └── integration/
├── pkg/                    # Public importable packages
│   ├── capability/         # Token payload types, constraints, conditions, JWKS verification
│   ├── callcounter/        # Rate-limit call counting
│   ├── config/             # Struct-tag validated config loading
│   ├── crypto/             # Signing adapters (software PEM, KMS)
│   ├── enforcement/        # PDP enforcement logic
│   ├── identity/           # Identity/DID resolution
│   ├── killswitch/         # Emergency kill switch
│   ├── observability/      # Logging (slog), metrics (Prometheus), tracing (OTel)
│   ├── ratelimit/          # Rate limiting
│   ├── revocation/         # Token revocation
│   ├── audit/              # Audit logging and anchoring
│   ├── did/                # W3C DID support
│   ├── federation/         # Cross-org federation
│   ├── ocsf/               # OCSF event format
│   └── testutil/           # Shared test helpers
├── migrations/             # SQL migrations (golang-migrate format)
├── k8s/                    # Kubernetes manifests & Helm charts
├── infra/                  # Docker Compose, Terraform, cloud configs
├── docs/                   # Documentation (all filenames lowercase kebab-case)
├── site/                   # Astro site (landing page, blog, docs hub)
└── blogs/                  # Blog content
```

## CI

The GitHub Actions workflow (`.github/workflows/go-ci.yml`) runs:

- `go vet` + `golangci-lint`
- Tests with race detector and 80% coverage threshold for `pkg/`
- BSL license header check
- Cross-compilation (linux/amd64, linux/arm64, windows/amd64, windows/arm64)

## Local Development Stack

```bash
# Start full local stack with Docker Compose
docker compose -f infra/docker-compose.yml --profile full up --build
```

## License

All code is licensed under Business Source License 1.1 (BUSL-1.1).
