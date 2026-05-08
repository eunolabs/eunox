# public — public Apache-2.0 surface

This directory contains the Apache-2.0 packages that form the public
surface of Euno: the types and interfaces (`@euno/common-core`), the
MCP proxy (`@euno/mcp`), and the developer CLI (`@euno/cli`).

All packages here are registered as npm workspaces via the root
`package.json` glob `public/packages/*`.

## Packages

| Package | npm name | Notes |
|---|---|---|
| `packages/common/` | `@euno/common-core` | Core types, interfaces, in-memory stores. The published API contract consumed by the platform layer. |
| `packages/mcp/` | `@euno/mcp` | MCP proxy with local policy enforcement. |
| `packages/cli/` | `@euno/cli` | Developer CLI. |

See [`MANIFEST.md`](./MANIFEST.md) for the full inventory including planned packages.

## Scope

Apache-2.0 only. Every file and package under this directory is or will
be Apache-2.0 licensed.

## Rules

1. No references to the platform layer (`euno-platform/`): no comments,
   no README text, no `package.json` peer-dependency ranges pointing at
   BUSL-1.1 packages.
2. No BUSL-licensed code.
3. In-memory-only implementations — no Redis, no Postgres, no KMS.
4. No `@euno/common` dependency. Depend on `@euno/common-core` directly.

These rules are enforced mechanically by
`scripts/check-license-boundary.mjs` (`npm run lint:license-boundary`).
