# MCP SDK Support Policy

> **Status:** Decision record — Stage 0.  
> **Context:** See [docs/mvp.md § Stage 0](./mvp.md#stage-0-stop-the-bleeding-on-the-existing-codebase), bullet 3.

---

## Why this document exists

The Model Context Protocol (MCP) is pre-1.0.  Its wire format, capability
negotiation, and lifecycle events are still evolving.  Silently following
the latest SDK release causes breakage for anyone pinned to an older host
(Claude Desktop, Cursor, Windsurf, etc.).  Explicitly recording the version
we commit to support — and the policy for bumping it — makes the trade-off
visible and auditable.

---

## Pinned version for Stage 1

| Artefact | Value |
|---|---|
| npm package | `@modelcontextprotocol/sdk` |
| **Pinned version** | **`1.26.0`** |
| Primary protocol revision | `2025-11-25` |
| Constant | `MCP_PROTOCOL_VERSION` in `euno-mcp/packages/euno-mcp/src/protocol.ts` |

Stage 1 installs `@modelcontextprotocol/sdk@1.26.0` (exact pin, not a
range) in `euno-mcp/packages/euno-mcp/package.json`.  No other package in the workspace
should add a direct dependency on `@modelcontextprotocol/sdk` without a
corresponding update to this document.

`@euno/mcp` targets the `2025-11-25` revision (SDK 1.26.0 `LATEST_PROTOCOL_VERSION`).
It also accepts connections from clients advertising any revision in the SDK's
`SUPPORTED_PROTOCOL_VERSIONS` list (`2025-06-18`, `2025-03-26`, `2024-11-05`,
`2024-10-07`) so users on older hosts are not locked out.  The proxy's
`initialize` handshake validates the revision and rejects unknown strings.

> **Note:** The original Stage 0 decision recorded `1.11.0` and protocol
> revision `2025-03-26`.  `1.11.0` is affected by three published CVEs
> (ReDoS, DNS-rebinding, cross-client data leak — all patched in `1.26.0`).
> The pin was advanced to `1.26.0` during the Stage 1 scaffold (May 2026).
> SDK 1.26.0 promotes `2025-11-25` as `LATEST_PROTOCOL_VERSION`; this
> document was updated to match.

---

## Protocol revision

MCP uses a date-based revision string in the `protocolVersion` field of the
`initialize` / `initialized` handshake.  The **primary** revision for Stage 1 is:

```
2025-11-25
```

This is exported as `MCP_PROTOCOL_VERSION` from `euno-mcp/packages/euno-mcp/src/protocol.ts`
and referenced at proxy startup.  `@euno/mcp` also negotiates downward to any
revision in `MCP_SUPPORTED_PROTOCOL_VERSIONS` (also exported from that file) so
older hosts continue to work within the support window.

`@euno/mcp` will:
- advertise `2025-11-25` as its preferred revision in the `initialize` response.
- accept any revision from `MCP_SUPPORTED_PROTOCOL_VERSIONS` in an incoming
  `initialize` request.
- reject `initialize` requests carrying an unrecognised revision string (hard-fail,
  not silent downgrade) — the error message names the offending revision and lists
  the accepted ones.

---

## Support window policy

| Event | Action |
|---|---|
| New MCP SDK **patch** release (`1.26.x`) | Update within 2 weeks; no breaking changes expected. |
| New MCP SDK **minor** release (`1.x.0`) | Evaluate within 4 weeks; adopt if protocol revision is unchanged and no breaking surface changes. |
| New MCP **protocol revision** published | Requires a named Stage gate or explicit `@edgeobs/euno-leads` approval; update this document before merging. |
| New MCP SDK **major** release (`2.0.0`) | Treat as a new protocol revision; requires full compatibility review and a new entry in this table. |
| A host (Claude Desktop, Cursor, etc.) **drops** support for `2025-03-26` | Triggers an expedited bump regardless of the schedule above.  Create an incident issue and tag `@edgeobs/euno-leads`. |

### How long is a revision supported?

A protocol revision is supported **until the last major host drops it**.
"Last major host" means any of: Claude Desktop, Cursor, Windsurf, or another
host with ≥ 1 000 documented euno users.  Once all tracked hosts have moved
to a newer revision, the old revision enters a 30-day deprecation window and
is then removed.

### What triggers a bump to a new revision?

Any of the following:

1. A new revision is required by ≥ 1 tracked host (i.e. the host no longer
   accepts our current revision string).
2. The new revision adds a capability that is required to implement a
   committed Stage deliverable.
3. `@edgeobs/euno-leads` decides to adopt the new revision proactively.

All bumps require:

- A PR updating this file (new pinned version + new revision string).
- A corresponding `CHANGELOG` entry in `euno-mcp/packages/euno-mcp/CHANGELOG.md`.
- CI passing (the integration test suite exercises the MCP handshake).

---

## Cross-references

- [docs/mvp.md § Stage 0](./mvp.md#stage-0-stop-the-bleeding-on-the-existing-codebase) — freeze rationale
- [docs/stage-0-freeze.md](./stage-0-freeze.md) — PR-review checklist for frozen packages
- MCP specification: <https://spec.modelcontextprotocol.io/>
- `@modelcontextprotocol/sdk` on npm: <https://www.npmjs.com/package/@modelcontextprotocol/sdk>
