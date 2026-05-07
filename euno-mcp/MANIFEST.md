# euno-mcp package manifest

This file is the authoritative list of packages that belong to the
public Apache-2.0 surface, living under `euno-mcp/packages/` in this
monorepo.

## Packages

| Package | License | Path | Notes |
|---|---|---|---|
| `@euno/common-core` | Apache-2.0 | `euno-mcp/packages/common-core/` | Core types, interfaces, in-memory stores. Published to npm. |
| `@euno/mcp` | Apache-2.0 | `euno-mcp/packages/euno-mcp/` | MCP proxy with local policy enforcement. |
| `@euno/cli` | Apache-2.0 | `euno-mcp/packages/cli/` | Developer CLI. **Blocker: must drop `@euno/common` dependency before public npm publish.** |

## Planned packages (not yet created)

| Package | License | When | Notes |
|---|---|---|---|
| `@euno/langchain` | Apache-2.0 | Stage 2 | Greenfield LangChain.js adapter. |

## Move checklist

Before publishing any package from this surface to npm:

- [ ] `@euno/cli` no longer depends on `@euno/common` (uses
      `@euno/common-core` directly).
- [ ] `npm run lint:license-boundary` is green with **zero**
      allowlisted violations involving the package being published.
- [ ] The package's `package.json` `"license"` field is `Apache-2.0`.
- [ ] No file in the package contains a comment, TODO, or string
      literal naming a BUSL-1.1 package or referring to the private
      surface (see [§ Rules](./README.md#rules)).
