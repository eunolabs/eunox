# euno-platform package manifest

This file is the authoritative list of packages that belong to the
private BUSL-1.1 repo (`github.com/edgeobs/euno-platform`). It is the
companion to [`docs/repo-split.md`](../docs/repo-split.md); if the two
ever disagree, `docs/repo-split.md` controls and this file should be
updated to match.

## Packages currently in this monorepo that will move here

| Package | License | Current path | Notes |
|---|---|---|---|
| `@euno/common-infra` | BUSL-1.1 | `packages/common-infra/` | Redis / Postgres / KMS implementations. |
| `@euno/common` | BUSL-1.1 | `packages/common/` | Compat shim re-exporting `common-core` + `common-infra`. Deprecated; will be removed once `@euno/cli` no longer depends on it. |
| `@euno/tool-gateway` | BUSL-1.1 | `packages/tool-gateway/` | |
| `@euno/capability-issuer` | BUSL-1.1 | `packages/capability-issuer/` | |
| `@euno/agent-runtime` | BUSL-1.1 | `packages/agent-runtime/` | |
| `@euno/framework-adapters` | BUSL-1.1 | `packages/framework-adapters/` | |
| `@euno/posture-emitter` | BUSL-1.1 | `packages/posture-emitter/` | Quarantined per `docs/stage-0-freeze.md`. |
| `@euno/partner-issuer-sim` | BUSL-1.1 | `packages/partner-issuer-sim/` | Quarantined. |
| `@euno/db-token-service` | BUSL-1.1 | `packages/db-token-service/` | Quarantined. |
| `@euno/storage-grant-service` | BUSL-1.1 | `packages/storage-grant-service/` | Quarantined. |
| `@euno/integration-tests` | BUSL-1.1 | `packages/integration-tests/` | |

## Allowed dependencies

Every package listed above may depend on:

- Any `Apache-2.0`-licensed package from `euno-mcp/` (most importantly
  `@euno/common-core`).
- Any other BUSL-1.1 package in this manifest.
- External npm packages with compatible licenses.

The reverse direction (Apache-2.0 → BUSL-1.1) is **forbidden** and is
enforced mechanically by `scripts/check-license-boundary.mjs`.
