# STATUS — db-token-service

**Status: GA (General Availability) — Stage-5 Task 7.**

This package provides a database-backed token service that mints short-lived
database IAM credentials (Azure SQL AAD tokens, AWS RDS IAM auth tokens, GCP
Cloud SQL IAM tokens) from a verified capability JWT. It graduated to GA as
part of [Stage 5 — Enterprise Deployment](../../docs/self-host.md#126-db-token-service).

## What this means for contributors

- **New features** are welcome via the normal PR process.
- **CI must keep this package building and all tests passing.**
- **Breaking API changes** require a major-version bump and a corresponding
  update to `docs/self-host.md` §12.6.

## Reference

See [docs/self-host.md §12.6](../../docs/self-host.md#126-db-token-service)
for configuration and integration guidance.
