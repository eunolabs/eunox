# euno-platform — private BUSL-1.1 surface

This directory contains the BUSL-1.1 packages that form the private
operational layer of Euno: Redis/Postgres/KMS implementations, the
tool gateway, the capability issuer, the agent runtime, and supporting
services.

All packages here are registered as npm workspaces via the root
`package.json` glob `euno-platform/packages/*`.

## Packages

| Package | npm name | Notes |
|---|---|---|
| `packages/common-infra/` | `@euno/common-infra` | Redis / Postgres / KMS implementations. |
| `packages/common/` | `@euno/common` | Compat shim (re-exports `common-core` + `common-infra`). Deprecated. |
| `packages/tool-gateway/` | `@euno/tool-gateway` | JWT verification, policy enforcement gateway. |
| `packages/capability-issuer/` | `@euno/capability-issuer` | Capability token issuance service. |
| `packages/agent-runtime/` | `@euno/agent-runtime` | Sandboxed agent execution runtime. |
| `packages/framework-adapters/` | `@euno/framework-adapters` | LangChain, AutoGen, and other framework adapters. |
| `packages/posture-emitter/` | `@euno/posture-emitter` | Posture inventory emitter. |
| `packages/partner-issuer-sim/` | `@euno/partner-issuer-sim` | Partner issuer simulator for testing. |
| `packages/db-token-service/` | `@euno/db-token-service` | Database token service. |
| `packages/storage-grant-service/` | `@euno/storage-grant-service` | Storage grant service. |
| `packages/integration-tests/` | `@euno/integration-tests` | Integration test suite. |

See [`MANIFEST.md`](./MANIFEST.md) for the full inventory.

## Scope

BUSL-1.1 only. Every package listed above is licensed under Business
Source License 1.1 with a four-year change date to Apache-2.0 (see
[`docs/mvp.md § License boundary`](../docs/mvp.md#license-boundary)).

## Rules

This is the operational layer. It may depend on any Apache-2.0 package
from `euno-mcp/` (most importantly `@euno/common-core`). The reverse
direction is forbidden and enforced by `scripts/check-license-boundary.mjs`.
