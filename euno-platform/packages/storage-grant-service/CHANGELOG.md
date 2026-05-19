# Changelog — @euno/storage-grant-service

All notable changes to this package will be documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.0.0] — Stage 5 GA

**Milestone:** Storage-grant service promoted from quarantine to General
Availability (Stage 5, Task 7).

### Changed

- Package status updated from **Quarantined** to **GA**.  The `STATUS.md`
  quarantine notice has been replaced with a production-ready status block.
- Version bumped from `0.1.0` to `1.0.0`.

### Added

- `POST /api/v1/storage-grants` — exchanges a verified capability JWT for
  presigned URLs (AWS S3) or SAS tokens (Azure Blob Storage), or short-lived
  GCP Cloud Storage signed URLs.
- `STORAGE_GRANTS_ENABLED` environment variable (must be `true` to enable
  the grant endpoint).
- `STORAGE_BUCKETS_FILE` — path to a JSON file enumerating the buckets /
  containers the service is authorised to issue grants for.
- `STORAGE_GRANT_MAX_TTL_SECONDS` — maximum grant lifetime (default: 900 s).
- Service added to the docker-compose `full` profile
  (`infra/docker-compose.yml`).
- Helm values schema at `k8s/helm/storage-grant-service/values.schema.json`.
- 10 integration tests in
  `euno-platform/packages/integration-tests/tests/storage-grant-service.test.ts`
  covering the happy path, invalid-token rejection, disabled-service
  rejection, and bucket-allow-list enforcement.
- `docs/self-host.md` §12.7 "Storage Grant Service" — configuration and
  integration guide.

## [0.1.0] — Initial prototype

Initial quarantined prototype.  Not production-ready; held pending a named
enterprise customer request requiring short-lived cloud-storage credential
minting from agent capability tokens.
