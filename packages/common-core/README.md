# @euno/common-core

Core types, interfaces, in-memory stores, and the four interface seams for
Euno agent governance.

Licensed under **Apache-2.0** — freely adoptable, redistributable, and
embeddable in commercial products.

## Contents

- Wire-format types (`wire.ts`)
- Runtime interfaces: `EvidenceSigner`, `KillSwitchManager`, `TokenSigner`, `IdentityProvider`
- In-memory stores: `InMemoryCallCounterStore`, `ShardLocalCallCounterStore`, `InMemoryIssuanceRateLimiter`, `DefaultKillSwitchManager`
- Config schema (Zod, env-var driven)
- Cryptographic helpers: DPoP, JWKS, evidence signing, issuance proofs
- Observability: logger, metrics, tracing, OCSF
- Policy backends (OPA HTTP)
- Audit pipeline, gateway quota engine, condition registry

## Dependency rule

`@euno/common-core` must **never** depend on `@euno/common-infra` or any BSL
package. Apache-2.0 packages may only depend on other Apache-2.0 (or more
permissive) packages.

## License

[Apache-2.0](./LICENSE)
