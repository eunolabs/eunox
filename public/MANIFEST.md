# public package manifest

This file is the authoritative list of packages that belong to the
public Apache-2.0 surface, living under `public/packages/` in this
monorepo.

## Packages

| Package | License | Path | Notes |
|---|---|---|---|
| `@euno/common-core` | Apache-2.0 | `public/packages/common/` | Core types, interfaces, in-memory stores. Published to GitHub Packages. |
| `@euno/mcp` | Apache-2.0 | `public/packages/mcp/` | MCP proxy with local policy enforcement. |
| `@euno/cli` | Apache-2.0 | `public/packages/cli/` | Developer CLI. Migrated to `@euno/common-core`; no BUSL dependency blocker remains. |

## Planned packages (not yet created)

| Package | License | When | Notes |
|---|---|---|---|
| `@euno/langchain` | Apache-2.0 | Stage 2 | Greenfield LangChain.js adapter. |

## Move checklist

Before publishing any package from this surface to GitHub Packages:

- [x] `@euno/cli` no longer depends on `@euno/common` (uses
      `@euno/common-core` directly).
- [x] `npm run lint:license-boundary` is green with **zero**
      allowlisted violations involving the package being published.
- [ ] The package's `package.json` `"license"` field is `Apache-2.0`.
- [ ] The package's `package.json` `publishConfig.registry` is
      `https://npm.pkg.github.com`.
- [ ] No file in the package contains a comment, TODO, or string
      literal naming a BUSL-1.1 package or referring to the private
      surface (see [§ Rules](./README.md#rules)).
