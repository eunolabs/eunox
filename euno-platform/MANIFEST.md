# euno-platform package manifest

This file is the authoritative list of packages that belong to the
private BUSL-1.1 surface, living under `euno-platform/packages/` in
this monorepo.

## Packages

| Package | License | Path | Notes |
|---|---|---|---|
| `@euno/common-infra` | BUSL-1.1 | `euno-platform/packages/common-infra/` | Redis / Postgres / KMS implementations. |
| `@euno/common` | BUSL-1.1 | `euno-platform/packages/common/` | Compat shim re-exporting `common-core` + `common-infra` for platform back-compat. New public packages must depend on `@euno/common-core` directly. |
| `@euno/tool-gateway` | BUSL-1.1 | `euno-platform/packages/tool-gateway/` | |
| `@euno/capability-issuer` | BUSL-1.1 | `euno-platform/packages/capability-issuer/` | |
| `@euno/agent-runtime` | BUSL-1.1 | `euno-platform/packages/agent-runtime/` | |
| `@euno/framework-adapters` | BUSL-1.1 | `euno-platform/packages/framework-adapters/` | |
| `@euno/posture-emitter` | BUSL-1.1 | `euno-platform/packages/posture-emitter/` | Quarantined per `docs/stage-0-freeze.md`. |
| `@euno/partner-issuer-sim` | BUSL-1.1 | `euno-platform/packages/partner-issuer-sim/` | Quarantined. |
| `@euno/db-token-service` | BUSL-1.1 | `euno-platform/packages/db-token-service/` | Quarantined. |
| `@euno/storage-grant-service` | BUSL-1.1 | `euno-platform/packages/storage-grant-service/` | Quarantined. |
| `@euno/integration-tests` | BUSL-1.1 | `euno-platform/packages/integration-tests/` | |

## Allowed dependencies

Every package listed above may depend on:

- Any `Apache-2.0`-licensed package from `euno-mcp/` (most importantly
  `@euno/common-core`).
- Any other BUSL-1.1 package in this manifest.
- External npm packages with compatible licenses.

The reverse direction (Apache-2.0 → BUSL-1.1) is **forbidden** and is
enforced mechanically by `scripts/check-license-boundary.mjs`.
