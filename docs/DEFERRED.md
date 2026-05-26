# Deferred Work

This document tracks intentionally deferred functionality that will be addressed in future stages.

## ~~KMS Integrations (Stage 3)~~ ✅ Completed

**Location:** `pkg/crypto/kms_aws.go`, `pkg/crypto/kms_azure.go`, `pkg/crypto/kms_gcp.go`

Production KMS implementations are now available for all three cloud providers:

- **AWS KMS** (`NewRealAWSKMSSigner`) — delegates signing to AWS KMS via `AWSKMSClient` interface
- **Azure Key Vault** (`NewRealAzureKeyVaultSigner`) — delegates signing to Azure Key Vault via `AzureKeyVaultClient` interface
- **GCP Cloud KMS** (`NewRealGCPCloudKMSSigner`) — delegates signing to GCP Cloud KMS via `GCPCloudKMSClient` interface

Each implementation:
- Satisfies the `crypto.Signer` interface
- Never holds private key material (all signing is remote)
- Uses provider/client interfaces for dependency injection (no direct SDK coupling)
- Supports RSA (PKCS#1 v1.5, PSS) and ECDSA (P-256, P-384, P-521) algorithms
- Converts ECDSA signatures between DER/ASN.1 and JOSE R||S formats as needed
- Has comprehensive unit tests with mock clients (`pkg/crypto/kms_test.go`)

The legacy stub implementations (`pkg/crypto/kms_stub.go`) remain available for environments where KMS is not yet configured.

**Remaining work (future):**
- SDK-specific client implementations wrapping `aws-sdk-go-v2/service/kms`, `azure-sdk-for-go/sdk/security/keyvault`, and `cloud.google.com/go/kms`
- Integration tests gated behind `//go:build integration` using real cloud KMS endpoints
- Automated key rotation via `RotatingKeyStore` with KMS-backed signers

## ~~Cloud Database Adapters (Stage 2)~~ ✅ Completed

**Location:** `internal/dbtokensvc/adapter_aws.go`, `adapter_azure.go`, `adapter_gcp.go`; `internal/storagegrantsvc/adapter_aws.go`, `adapter_azure.go`, `adapter_gcp.go`

Production cloud database and storage adapters are fully implemented:

- `dbtokensvc`: RealAWSRDSAdapter (SigV4 presigned URLs), RealAzureSQLAdapter (Azure AD tokens), RealGCPCloudSQLAdapter (OAuth2 tokens)
- `storagegrantsvc`: RealAWSS3Adapter (SigV4 presigned URLs), RealAzureBlobAdapter (user-delegation SAS tokens), RealGCPGCSAdapter (V4 signed URLs)

Each adapter uses provider interfaces for credentials (dependency injection, no direct SDK coupling).

## ~~Testcontainers Integration Tests (Stage 2)~~ ✅ Completed

**Location:** `pkg/testutil/containers_integration.go`, `pkg/testutil/containers_integration_test.go`

Production-grade testcontainers helpers are now implemented, gated behind `//go:build integration`:

- **`StartPostgres(ctx, cfg)`** — starts a PostgreSQL 16 container with configurable database, user, password, and init scripts
- **`StartRedis(ctx, cfg)`** — starts a Redis 7 container
- Both return typed container wrappers with connection strings/addresses and `Terminate()` cleanup

**Test architecture (two tiers):**

| Tier | Build tag | Backend | Docker required | CI gate |
|------|-----------|---------|----------------|---------|
| Unit + Integration (in-memory) | (none) | In-memory implementations | No | `make test` |
| Docker integration | `integration` | Real PostgreSQL/Redis containers | Yes | `go test -tags=integration ./...` |

**Prerequisites to enable Docker tests:**
- Add `testcontainers-go` to `go.mod` (`go get github.com/testcontainers/testcontainers-go@v0.38.0`)
- Docker available in CI runner
- See `docs/OPEN_QUESTIONS.md` §6

## ~~Partner Federation Circuit Breaker Metrics~~ ✅ Completed

**Location:** `pkg/federation/metrics.go`, `pkg/federation/federation.go`

The circuit breaker is now fully instrumented with Prometheus metrics:

- **`euno_partner_did_circuit_breaker_state`** — one-hot gauge per DID method and state (closed/open/half-open)
- **`euno_partner_did_resolution_total`** — counter per method and outcome (success/error/no_key/circuit_open)
- **`euno_partner_did_resolution_duration_seconds`** — histogram of resolution latency

Metrics are wired into `PartnerIssuerResolver.ResolvePublicKeys()`:
- Every resolution attempt records outcome and duration
- Circuit breaker state gauges are updated after every state-affecting operation
- `PartnerIssuerResolverConfig.Metrics` field (optional; nil-safe) for dependency injection

## ~~Migration Tooling~~ ✅ Completed

**Location:** `internal/migrate/`

Production-grade migration runner implemented with:

- **Rollback safety checks** — `ValidateRollbackSafety()` verifies every `.up.sql` has a matching `.down.sql` before applying; blocks `MigrateUp` if any are missing
- **Advisory locking** — `AdvisoryLocker` interface with `Lock()`/`Unlock()` for multi-instance safety; in-memory implementation provided for testing; PostgreSQL advisory lock can be implemented by operators
- **Pre-migration backup hooks** — `BackupHook` callback invoked before both up and down migrations, receives current version
- **Dirty state detection** — marks version as dirty before execution, clean after; refuses to operate on dirty state (requires manual intervention)
- **`SQLExecutor` interface** — clean separation between migration orchestration and SQL execution
- **Sequential file parsing** — validates `NNN_description.{up,down}.sql` naming convention
- **`MigrateUp`/`MigrateUpTo`/`MigrateDown`/`MigrateDownTo`** — full bidirectional migration control
- **`Pending()`** — reports count of unapplied migrations

**Test coverage:** 30+ tests covering all paths including lock contention, dirty state, backup failures, partial application, and rollback scenarios.

**Remaining work (future):**
- PostgreSQL advisory lock implementation (`pg_advisory_lock(key)`)
- CLI wrapper (`cmd/migrate/main.go`) for operator use
- Embedded migration filesystem in service binaries

