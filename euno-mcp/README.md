# euno-mcp -- public Apache-2.0 surface (scaffold)

**Status:** Scaffold initialised in Substage 0.4. Physical repo
(`github.com/edgeobs/euno-mcp`) and package moves are a Stage 1 follow-up.

This directory exists so the two-repo split documented in
[`docs/mvp.md § Repository structure`](../docs/mvp.md#repository-structure-public--private)
and [`docs/repo-split.md`](../docs/repo-split.md) is **physically present
in the tree**, not just on paper. The Stage 0 gate requires the two-repo
structure to be initialised; this folder satisfies that requirement.

It is not a workspace -- the root `package.json` only globs
`packages/*` -- so nothing here is built, linted, or tested yet. When
Stage 1 begins, the packages listed in [`MANIFEST.md`](./MANIFEST.md) will
either move under this folder (if the public repo is bootstrapped via
`git subtree split`/`git filter-repo` from this monorepo) or be copied
into a freshly created `github.com/edgeobs/euno-mcp` repository. Either
way, the contents of this directory are the authoritative inventory of
what belongs in the public repo.

## Scope

Apache-2.0 only. Every file under this folder, and every package listed
in [`MANIFEST.md`](./MANIFEST.md), is or will be Apache-2.0 licensed.

## Rules

The rules in [`docs/repo-split.md § Rules for the public repo`](../docs/repo-split.md#rules-for-the-public-repo)
apply to anything that lands here:

1. No references to the private repo (no comments, no README text, no
   `package.json` peer-dependency ranges pointing at private packages).
2. No BUSL-licensed code.
3. In-memory-only implementations -- no Redis, no Postgres, no KMS.
4. No `@euno/common` dependency. Depend on `@euno/common-core` directly.

## Why a scaffold and not the actual move?

The license-boundary lint allowlist in
`scripts/check-license-boundary.mjs` still has two `@euno/cli` →
`@euno/common` violations. Those are tracked in
[`docs/repo-split.md § Dependency violations to fix before public publish`](../docs/repo-split.md#dependency-violations-to-fix-before-public-publish)
and must be resolved before any package physically moves into this
folder or before the public repo is created on GitHub. Until then, the
scaffold makes the target structure unambiguous and gives the boundary
check a stable target.
