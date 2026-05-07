# euno-platform -- private BUSL-1.1 surface (scaffold)

**Status:** Scaffold initialised in Substage 0.4. Physical repo
(`github.com/edgeobs/euno-platform`) and package moves are a Stage 1
follow-up.

This directory exists so the two-repo split documented in
[`docs/mvp.md § Repository structure`](../docs/mvp.md#repository-structure-public--private)
and [`docs/repo-split.md`](../docs/repo-split.md) is **physically present
in the tree**, not just on paper. The Stage 0 gate requires the two-repo
structure to be initialised; this folder satisfies that requirement.

It is not a workspace -- the root `package.json` only globs
`packages/*` -- so nothing here is built, linted, or tested yet. When
Stage 1 begins, this monorepo will either be renamed/repurposed as the
private repo with `packages/` already in place, or the packages listed
in [`MANIFEST.md`](./MANIFEST.md) will be moved under this folder. Either
way, the contents of this directory are the authoritative inventory of
what belongs in the private repo.

## Scope

BUSL-1.1 only. Every package listed in [`MANIFEST.md`](./MANIFEST.md) is
licensed under Business Source License 1.1 with a four-year change date
to Apache-2.0 (see [`docs/mvp.md § License boundary`](../docs/mvp.md#license-boundary)).

## Rules

This is the operational layer. It is allowed to depend on any
`Apache-2.0` package from the public repo (most importantly
`@euno/common-core`). The reverse direction is forbidden and is
enforced mechanically by `scripts/check-license-boundary.mjs`.
