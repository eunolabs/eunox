# Euno Platform — Go Implementation

> **Version:** 0.1.0  
> **License:** Business Source License 1.1 (BUSL-1.1)

## Overview

This is the Go reimplementation of the Euno Platform enterprise services. It targets feature-parity with the TypeScript implementation while providing improved performance, lower memory usage, and simplified deployment.

## Current Status: Stage 1 — Foundation & Shared Libraries

### Completed Packages

| Package | Description | Status |
|---------|-------------|--------|
| `pkg/capability` | Domain types: token payload, constraints, conditions, obligations, enforce request/response | ✅ |
| `pkg/config` | Configuration framework: struct-tag validation, env loading, per-service configs | ✅ |
| `pkg/crypto` | Signing adapters: Signer/Verifier interfaces, software PEM signer, KMS stubs | ✅ |
| `pkg/observability` | Logging (slog), metrics (Prometheus), tracing (OTel), HTTP middleware | ✅ |
| `pkg/testutil` | Test helpers: in-memory signers, fake clock, HTTP test server | ✅ |

### Deferred to Stage 2+

- `pkg/testutil/containers.go` — Testcontainers helpers (PostgreSQL, Redis) are documented but gated behind `integration` build tag pending dependency resolution
- `cmd/*` — Service binaries (Stage 2+)
- `internal/*` — Service domain logic (Stage 2+)
- `api/` — OpenAPI specs (Stage 2)
- `migrations/` — SQL migrations (Stage 2+)
- `deploy/` — Docker/Helm/K8s/Terraform (Stage 7)

## Development

### Prerequisites

- Go 1.24+
- golangci-lint v2.1.6+

### Commands

```bash
# Run all tests with race detector
make test

# Run linter (go vet + golangci-lint)
make lint

# Build all packages
make build

# Generate coverage report
make coverage

# Check BSL license headers
make check-license

# Clean build artifacts
make clean
```

### Project Structure

```
euno-go/
├── cmd/                    # Service entry points (Stage 2+)
├── internal/               # Private application code (Stage 2+)
├── pkg/                    # Public importable packages
│   ├── capability/         # Token payload types, constraints, conditions
│   ├── config/             # Schema-validated config loading
│   ├── crypto/             # Signing adapters (software, KMS stubs)
│   ├── observability/      # Logging, metrics, tracing, middleware
│   └── testutil/           # Shared test helpers
├── api/                    # OpenAPI specs (Stage 2)
├── migrations/             # SQL migrations (Stage 2+)
├── deploy/                 # Deployment artifacts (Stage 7)
├── .golangci.yml           # Linter configuration
├── Makefile                # Build targets
├── go.mod                  # Module definition
└── go.sum                  # Dependency checksums
```

## Technology Choices

| Concern | Choice |
|---------|--------|
| HTTP framework | `net/http` (`chi` router planned for Stage 2+) |
| Config | Struct-tag-based validation (custom, Zod-equivalent) |
| JWT/JWS | Planned for Stage 2+: `go-jose/v4` |
| Database | Planned for Stage 2+: `pgx/v5` (PostgreSQL), `go-redis/v9` |
| Migrations | Planned for Stage 2+: `github.com/golang-migrate/migrate/v4` |
| Metrics | `prometheus/client_golang` |
| Tracing | `go.opentelemetry.io/otel` |
| Logging | `log/slog` (stdlib) |
| Testing | `testing` + `testify` (`testcontainers-go` planned for Stage 2+) |
| Linting | `golangci-lint` v2 |

## License

Business Source License 1.1 — See [LICENSE](../LICENSE) for details.
