# Deferred Work

This document tracks intentionally deferred functionality that will be addressed in future stages.

## KMS Integrations (Stage 2)

**Location:** `pkg/crypto/kms_stub.go`

The platform supports pluggable KMS (Key Management Service) backends for production key material. Currently, stub implementations exist for:

- **AWS KMS** (`NewAWSKMSSigner`)
- **Azure Key Vault** (`NewAzureKeyVaultSigner`)
- **GCP Cloud KMS** (`NewGCPCloudKMSSigner`)

Each stub satisfies the `crypto.Signer` interface and panics with a clear message directing implementers to the correct SDK dependency. These stubs are excluded from lint analysis (`.golangci.yml`).

**Prerequisites to enable:**
- Add cloud SDK dependencies to `go.mod`
- Implement real key fetching and signing operations
- Add integration tests gated behind `//go:build integration`
- See `docs/OPEN_QUESTIONS.md` §3 for key rotation design decisions

## Cloud Database Adapters (Stage 2)

**Location:** `internal/dbtokensvc/adapter.go`, `internal/storagegrantsvc/adapter.go`

The adapter pattern uses `IsStub() bool` to distinguish real adapters from placeholder stubs:

- `dbtokensvc`: Cloud Spanner, DynamoDB, CockroachDB stubs
- `storagegrantsvc`: S3, GCS, Azure Blob Storage stubs

In production mode (`NODE_ENV=production`), the services reject stub adapters at startup.

**Prerequisites to enable:**
- Add cloud SDK dependencies per adapter
- Implement connection pooling and health checks
- Add retry logic and circuit breakers
- Gate behind `//go:build integration` for CI

## Testcontainers Integration Tests (Stage 2)

**Location:** `pkg/testutil/containers.go`

Scaffolding for `testcontainers-go` helpers (PostgreSQL, Redis) is prepared but commented out, gated behind `//go:build integration`.

**Prerequisites to enable:**
- Add `testcontainers-go` dependency
- Docker available in CI runner
- See `docs/OPEN_QUESTIONS.md` §6

## Partner Federation Circuit Breaker Metrics

**Location:** Referenced in partner federation design

The circuit breaker state tracking for partner DID resolvers is designed but not yet instrumented with Prometheus metrics. The `getCircuitBreakerStates()` pattern is ready for metric emission.

## Migration Tooling

**Location:** `internal/migrate/`

Database migrations use `golang-migrate/migrate/v4`. The migration runner exists but production-grade features are deferred:

- Rollback safety checks
- Migration locking for multi-instance deploys
- Pre-migration backup hooks

See `docs/golang-reimplementation-plan.md` §Migrations for the full design.
