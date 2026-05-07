# euno-mcp package manifest

This file is the authoritative list of packages that belong to the
public Apache-2.0 repo (`github.com/edgeobs/euno-mcp`). It is the
companion to [`docs/repo-split.md`](../docs/repo-split.md); if the two
ever disagree, `docs/repo-split.md` controls and this file should be
updated to match.

## Packages currently in this monorepo that will move here

| Package | License | Current path | Notes |
|---|---|---|---|
| `@euno/common-core` | Apache-2.0 | `packages/common-core/` | Core types, interfaces, in-memory stores. Will be published to npm from here. |
| `@euno/cli` | Apache-2.0 | `packages/cli/` | Developer CLI. Blocker: must drop `@euno/common` dependency before the move. |

## Packages not yet created

| Package | License | When | Notes |
|---|---|---|---|
| `@euno/mcp` | Apache-2.0 | Stage 1 | Greenfield MCP proxy. See `docs/mvp.md § Stage 1: MCP Proxy MVP`. |
| `@euno/langchain` | Apache-2.0 | Stage 2 | Greenfield LangChain.js adapter. |

## Move checklist

Before physically moving any package into this directory (or the
eventual `github.com/edgeobs/euno-mcp` repo):

- [ ] `@euno/cli` no longer depends on `@euno/common` (uses
      `@euno/common-core` directly).
- [ ] `npm run lint:license-boundary` is green with **zero**
      allowlisted violations involving the moving package.
- [ ] The moving package's `package.json` `"license"` field is
      `Apache-2.0`.
- [ ] No file in the package contains a comment, TODO, or string
      literal naming a BUSL-1.1 package or referring to the private
      repo (see [§ Rules](./README.md#rules)).
