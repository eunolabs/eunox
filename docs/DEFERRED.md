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

## Testcontainers Integration Tests (Stage 2)

**Location:** `pkg/testutil/containers.go`

Scaffolding for `testcontainers-go` helpers (PostgreSQL, Redis) is not yet implemented, gated behind `//go:build integration`.

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
