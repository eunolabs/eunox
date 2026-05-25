# Euno Platform — Go Implementation

> **Version:** 0.1.0  
> **License:** Business Source License 1.1 (BUSL-1.1)

## Overview

This is the Go reimplementation of the Euno Platform enterprise services. It targets feature-parity with the TypeScript implementation while providing improved performance, lower memory usage, and simplified deployment.

## Current Status: Stage 4 — API-Key Minter & Credential Services

### Completed Stages

| Stage | Description | Status |
|-------|-------------|--------|
| Stage 1 | Foundation & Shared Libraries | ✅ |
| Stage 2 | Capability Issuer | ✅ |
| Stage 3 | Enforcement Gateway | ✅ |
| Stage 4 | API-Key Minter & Credential Services | ✅ |

### Stage 4 Packages

| Package | Description | Status |
|---------|-------------|--------|
| `internal/minter` | API-Key Minter: key lifecycle, admin auth, anomaly detection | ✅ |
| `internal/dbtokensvc` | DB Token Service: short-lived DB credentials (AWS RDS, Azure SQL, GCP Cloud SQL) | ✅ |
| `internal/storagegrantsvc` | Storage Grant Service: presigned URLs (AWS S3, Azure Blob, GCP GCS) | ✅ |
| `cmd/minter` | Minter binary entry point | ✅ |
| `cmd/db-token-svc` | DB Token Service binary entry point | ✅ |
| `cmd/storage-grant-svc` | Storage Grant Service binary entry point | ✅ |
| `migrations/minter` | SQL migrations for API keys and policies tables | ✅ |

### Foundation Packages (Stage 1)

| Package | Description | Status |
|---------|-------------|--------|
| `pkg/capability` | Domain types: token payload, constraints, conditions, obligations, enforce request/response | ✅ |
| `pkg/config` | Configuration framework: struct-tag validation, env loading, per-service configs | ✅ |
| `pkg/crypto` | Signing adapters: Signer/Verifier interfaces, software PEM signer, KMS stubs | ✅ |
| `pkg/observability` | Logging (slog), metrics (Prometheus), tracing (OTel), HTTP middleware | ✅ |
| `pkg/testutil` | Test helpers: in-memory signers, fake clock, HTTP test server | ✅ |

### Deferred Work

- `pkg/testutil/containers.go` — Testcontainers helpers (PostgreSQL, Redis) gated behind `integration` build tag
- KMS stubs (AWS/GCP/Azure) — placeholder until cloud SDK integration (Stage 7)
- Integration test: minter → gateway enforcement (key-based auth flow) — Stage 6
- Cloud adapter real implementations (currently stub/mock; awaiting cloud SDK wiring in Stage 7)

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
├── cmd/                    # Service entry points
│   ├── gateway/            # Enforcement Gateway
│   ├── issuer/             # Capability Issuer
│   ├── minter/             # API-Key Minter
│   ├── db-token-svc/       # DB Token Service
│   └── storage-grant-svc/  # Storage Grant Service
├── internal/               # Private application code
│   ├── gateway/            # Gateway domain logic
│   ├── issuer/             # Issuer domain logic
│   ├── minter/             # Minter: key store, admin auth, anomaly detection
│   ├── dbtokensvc/         # DB Token Service: cloud adapters, token verification
│   └── storagegrantsvc/    # Storage Grant Service: cloud adapters, grant minting
├── pkg/                    # Public importable packages
│   ├── capability/         # Token payload types, constraints, conditions
│   ├── callcounter/        # Call counting (rate limit tracking)
│   ├── config/             # Schema-validated config loading
│   ├── crypto/             # Signing adapters (software, KMS stubs)
│   ├── enforcement/        # PDP enforcement logic
│   ├── identity/           # DID/identity resolution
│   ├── killswitch/         # Kill switch (emergency disable)
│   ├── observability/      # Logging, metrics, tracing, middleware
│   ├── ratelimit/          # Rate limiting
│   ├── revocation/         # Token revocation
│   └── testutil/           # Shared test helpers
├── migrations/             # SQL migrations
│   └── minter/             # API keys and policies tables
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
