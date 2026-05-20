# Changelog — @euno/db-token-service

All notable changes to this package will be documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.0.0] — Stage 5 GA

**Milestone:** DB-token service promoted from quarantine to General Availability
(Stage 5, Task 7).

### Changed

- Package status updated from **Quarantined** to **GA**.  The `STATUS.md`
  quarantine notice has been replaced with a production-ready status block.
- Version bumped from `0.1.0` to `1.0.0`.

### Added

- `POST /api/v1/db-tokens` — exchanges a verified capability JWT for
  short-lived, scoped database IAM credentials.  Supports Azure SQL AAD
  tokens, AWS RDS IAM auth tokens, and GCP Cloud SQL IAM tokens.
- `DB_TOKENS_ENABLED` environment variable (must be `true` to enable the
  exchange endpoint).
- `DB_INSTANCES_FILE` — path to a JSON file enumerating the database
  instances the service is authorised to issue credentials for.
- `DB_USERNAME_POLICY_FILE` — path to a JSON file mapping capability JWT
  claims to database usernames (blast-radius containment).
- `DB_TOKEN_MAX_TTL_SECONDS` — maximum credential lifetime (default: 900 s).
- Blast-radius analysis documented in
  `docs/security/enterprise-federation-threat-model.md` §"DB credential
  blast radius".
- Service added to the docker-compose `full` profile
  (`infra/docker-compose.yml`).
- Helm values schema at `k8s/helm/db-token-service/values.schema.json`.
- 12 integration tests in
  `euno-platform/packages/integration-tests/tests/db-token-service.test.ts`
  covering the happy path, invalid-token rejection, disabled-service
  rejection, and allow-list enforcement.
- `docs/self-host.md` §12.6 "DB Token Service" — configuration and
  integration guide.

## [0.1.0] — Initial prototype

Initial quarantined prototype.  Not production-ready; held pending a named
enterprise customer request requiring short-lived DB credential minting from
agent capability tokens.
