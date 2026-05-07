# @euno/common-infra

Redis, Postgres, and KMS-backed infrastructure implementations for Euno agent
governance. Depends on `@euno/common-core`; the reverse dependency is forbidden.

Licensed under **BSL 1.1** (change date 2030-05-07 → Apache-2.0).

## Contents

- `RedisCircuitBreaker` — per-surface circuit breaker for Redis calls
- `RedisKillSwitchManager` + `PostgresKillSwitchBackend` — distributed kill switches
- `RedisCallCounterStore` + `createCallCounterStoreFromEnv` — distributed `maxCalls` enforcement
- `RedisIssuanceRateLimiter` + `createIssuanceRateLimiterFromEnv` — distributed issuance rate limiting
- `PostgresLedgerBackend` + `LedgerAuditEvidenceSigner` — tamper-evident audit ledger
- Log transports (AWS CloudWatch, GCP Cloud Logging) — moved to `@euno/common-core` due to dependency constraints

## Dependency rule

`@euno/common-infra` depends on `@euno/common-core`. The reverse is
**forbidden**: no Apache-2.0 package may import from a BSL package.

## License

[Business Source License 1.1](./LICENSE) — change date 2030-05-07, change
license Apache-2.0.
