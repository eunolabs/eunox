# Repository Split Strategy: Public + Private

**Status:** Decided, documented, and scaffolded (Substage 0.4). Top-level
[`euno-mcp/`](../euno-mcp/) and [`euno-platform/`](../euno-platform/)
folders are initialised in this monorepo with `LICENSE`, `README.md`,
and `MANIFEST.md` declaring scope and ownership. Physical GitHub repo
creation and the actual package moves are Stage 1 follow-ups.

This document records the two-repo strategy introduced in
[`docs/mvp.md § Repository structure`](./mvp.md#repository-structure-public--private),
lists which packages belong to each repo, defines the `common-core` release
checklist, and flags the known dependency violations that must be resolved
before any public npm publish.

---

## Target structure

```
github.com/edgeobs/euno-mcp          # public -- Apache-2.0
  packages/common-core/              # types, interfaces, in-memory fakes
  packages/cli/                      # developer CLI
  packages/euno-mcp/                 # (Stage 1 -- not yet created)
  packages/langchain/                # (Stage 2 -- not yet created)

github.com/edgeobs/euno-platform     # private -- BUSL-1.1
  packages/common-infra/             # Redis / Postgres / KMS implementations
  packages/common/                   # compat shim (re-exports both above)
  packages/tool-gateway/
  packages/capability-issuer/
  packages/agent-runtime/
  packages/framework-adapters/
  packages/posture-emitter/
  packages/partner-issuer-sim/
  packages/db-token-service/
  packages/storage-grant-service/
  packages/integration-tests/
```

**How the dependency works.** `common-core` is published to npm from the
public repo. The private repo installs it as a regular npm dependency and
adds BUSL-1.1 implementations on top. The interface seams in `common-core` become
the published API contract; private implementations are completely invisible.

---

## Packages moving to the public repo

| Package | License | Notes |
|---|---|---|
| `@euno/common-core` | Apache-2.0 | Core types, interfaces, in-memory stores. Published to npm. |
| `@euno/cli` | Apache-2.0 | Developer CLI. Published to npm. **Blocker: must remove `@euno/common` dep (see below).** |
| `@euno/mcp` | Apache-2.0 | Stage 1 -- greenfield, not yet created. |
| `@euno/langchain` | Apache-2.0 | Stage 2 -- greenfield, not yet created. |

All other packages remain in the private repo.

---

## Dependency violations to fix before public publish

The `lint:license-boundary` script (`scripts/check-license-boundary.mjs`)
currently has two allowlisted violations that must be resolved before any
Apache-2.0 package is published to npm:

| Violation | Allowlist key | Fix |
|---|---|---|
| `@euno/cli` depends on `@euno/common` (BUSL-1.1) | `@euno/cli->@euno/common` | Update `cli/package.json` to depend on `@euno/common-core` instead. Update all `import` statements that currently pull from `@euno/common` to use `@euno/common-core`. |
| `@euno/cli` transitively reaches `@euno/common-infra` via `@euno/common` | `@euno/cli->@euno/common-infra` | Resolved automatically when the above fix is applied. |

Once both allowlist entries are removed and `npm run lint:license-boundary`
still passes, the CLI is safe to publish.

---

## `common-core` npm release checklist

Run this checklist before every `@euno/common-core` npm publish. Because
`common-core` is the shared API contract between the public and private repos,
a bad release causes breakage in the private repo that can only be fixed by
another publish.

### Pre-release

- [ ] All tests pass in the private repo against the candidate version of
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
- [ ] `packages/common-core/package.json` `"version"` field is bumped.

### Publish

```sh
# From the public repo root
cd packages/common-core
npm run build
npm publish --access public
```

### Post-release

- [ ] Update `packages/common-infra/package.json` (private repo) to pin the
      new `@euno/common-core` version.
- [ ] Run `npm install && npm run build && npm run test` in the private repo.
- [ ] Tag the public repo: `git tag common-core@<version> && git push --tags`.

---

## Rules for the public repo

The following rules apply to every PR merged into `edgeobs/euno-mcp`:

1. **No references to the private repo.** No comments, no README text, no
   `package.json` peer-dependency ranges pointing at private packages. The
   public repo must read as complete and self-contained.
2. **No BUSL-licensed code.** Every file must be either Apache-2.0 or a
   non-code asset (docs, config). The `lint:license-boundary` CI step enforces
   this mechanically.
3. **In-memory-only implementations.** Any interface from `common-core` that
   needs a concrete implementation in the public repo must use the in-memory
   fakes already in `common-core`. No Redis, no Postgres, no KMS.
4. **No `@euno/common` dependency.** That package is the BUSL compat shim and
   will not exist in the public repo. Depend on `@euno/common-core` directly.

---

## Timeline

| Milestone | When |
|---|---|
| `common-core` and `cli` fully migrated off `@euno/common` | Before Stage 1 begins |
| `euno-mcp` package created and published | Stage 1 gate |
| `euno-mcp` repo physically created on GitHub | Stage 1 (follow-up PR after this one) |
| `langchain` package created | Stage 2 |
