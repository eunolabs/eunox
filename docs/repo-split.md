# Repository Structure: Public + Private Folders

**Status:** Implemented (Substage 0.4 / Stage 1). Top-level
[`euno-mcp/`](../euno-mcp/) and [`euno-platform/`](../euno-platform/)
folders contain the actual packages under their respective `packages/`
subdirectories. Both are declared as npm workspaces in the root
`package.json`.

This document records the two-folder strategy introduced in
[`docs/mvp.md § Repository structure`](./mvp.md#repository-structure-public--private),
lists which packages belong to each folder, defines the `common-core` release
checklist, and flags the known dependency violations that must be resolved
before any public GitHub Packages publish.

---

## Current structure

```
edgeobs/euno  (this monorepo)
│
├── euno-mcp/packages/              # public surface — Apache-2.0
│     common-core/                  # types, interfaces, in-memory fakes
│     cli/                          # developer CLI
│     euno-mcp/                     # MCP proxy (@euno/mcp)
│
└── euno-platform/packages/         # private surface — BUSL-1.1
      common-infra/                 # Redis / Postgres / KMS implementations
      common/                       # compat shim (re-exports both above)
      tool-gateway/
      capability-issuer/
      agent-runtime/
      framework-adapters/
      posture-emitter/
      partner-issuer-sim/
      db-token-service/
      storage-grant-service/
      integration-tests/
```

**How the dependency works.** `common-core` lives in `euno-mcp/packages/`
and is consumed by the platform packages in `euno-platform/packages/` as a
workspace dependency. When published to npm, `common-core` becomes the public
API contract that external consumers install as a regular npm dependency. The
interface seams in `common-core` are the published contract; platform
implementations are completely invisible.

---

## Packages in the public surface (`euno-mcp/`)

| Package | License | Notes |
|---|---|---|
| `@euno/common-core` | Apache-2.0 | Core types, interfaces, in-memory stores. Published to GitHub Packages. |
| `@euno/cli` | Apache-2.0 | Developer CLI. Published to GitHub Packages. |
| `@euno/mcp` | Apache-2.0 | MCP proxy with local policy enforcement. Published to GitHub Packages. |
| `@euno/langchain` | Apache-2.0 | Stage 2 — not yet created. |

All other packages live in the platform surface.

---

## License boundary — current status

The `lint:license-boundary` script (`scripts/check-license-boundary.mjs`)
currently reports **zero violations**. The allowlist is empty.

The historical violation (`@euno/cli` depending on `@euno/common` (BUSL-1.1))
has been resolved: `@euno/cli` now imports directly from `@euno/common-core`
(Apache-2.0). The allowlist entries were removed.

---

## `common-core` GitHub Packages release checklist

Run this checklist before every `@euno/common-core` publish. Because
`common-core` is the shared API contract between the public and platform
surfaces, a bad release causes breakage in the platform packages that can only
be fixed by another publish.

### Pre-release

- [ ] All platform-layer tests pass against the candidate version of
      `common-core` (bump the version in `package.json`, run `npm install`,
      run `npm run test`).
- [ ] No interface seams in `common-core` have been removed or renamed without
      a deprecation cycle. Check `CHANGELOG.md` for `BREAKING CHANGE` entries.
- [ ] `npm run lint:license-boundary` is green with zero allowlisted violations
      involving `common-core`.
- [ ] Version follows semver strictly:
  - **patch** -- bug fixes only, no API changes.
  - **minor** -- new exports added, no existing exports changed.
  - **major** -- any breaking change to existing exports.
- [ ] `CHANGELOG.md` has an entry for this version with a migration note for
      any interface changes.
- [ ] `euno-mcp/packages/common-core/package.json` `"version"` field is bumped.

### Publish

```sh
# From the repo root
cd euno-mcp/packages/common-core
npm run build
npm publish
```

The package's `publishConfig.registry` points to
`https://npm.pkg.github.com`; configure `//npm.pkg.github.com/:_authToken`
or use the release workflow so publishing and installs resolve through
GitHub Packages.

### Post-release

- [ ] Update `euno-platform/packages/common-infra/package.json` to pin the
      new `@euno/common-core` version.
- [ ] Run `npm install && npm run build && npm run test` from the repo root.
- [ ] Tag the release: `git tag common-core@<version> && git push --tags`.

---

## Rules for the public surface (`euno-mcp/`)

The following rules apply to every PR that touches `euno-mcp/`:

1. **No references to the platform layer.** No comments, no README text, no
   `package.json` peer-dependency ranges pointing at BUSL-1.1 packages. The
   public surface must read as complete and self-contained.
2. **No BUSL-licensed code.** Every file must be either Apache-2.0 or a
   non-code asset (docs, config). The `lint:license-boundary` CI step enforces
   this mechanically.
3. **In-memory-only implementations.** Any interface from `common-core` that
   needs a concrete implementation in the public surface must use the in-memory
   fakes already in `common-core`. No Redis, no Postgres, no KMS.
4. **No `@euno/common` dependency.** That package is the BUSL compat shim and
   belongs to the platform surface. Depend on `@euno/common-core` directly.

---

## Timeline

| Milestone | When |
|---|---|
| `common-core` and `cli` migrated off `@euno/common` | ✅ Done (Stage 1) |
| `@euno/mcp` and `@euno/common-core` published to GitHub Packages | Stage 1 gate |
| `@euno/langchain` package created | Stage 2 |
