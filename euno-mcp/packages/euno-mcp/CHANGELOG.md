# Changelog — @euno/mcp

All notable changes to this package are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2026-05-07 (Stage 1 scaffold)

### Added

- **`src/protocol.ts`** — `MCP_PROTOCOL_VERSION` (`'2025-11-25'`) and
  `MCP_SUPPORTED_PROTOCOL_VERSIONS` constants.  These are the single source of
  truth for the protocol revision that `@euno/mcp` advertises and accepts.
  See [docs/mcp-support.md](../../docs/mcp-support.md) for the full support
  window policy.

- **`src/pdp.ts`** — `PolicyDecisionPoint` interface, `PdpContext`,
  `PdpDecision`, and `AlwaysAllowPDP` (transparent passthrough for Stage 1).
  The PDP is the single enforcement seam; Phase B wires in the real
  condition-registry backed enforcer here.

- **`src/transport/stdio.ts`** — `StdioProxy` class.  Spawns an upstream MCP
  server as a child process and bridges stdin/stdout, forwarding all MCP
  requests.  Intercepts `tools/call` through the PDP.  Bridges notifications
  in both directions.  Propagates upstream stderr.  Handles SIGINT/SIGTERM.

- **`src/cli.ts`** — `euno-mcp proxy` command and `euno-mcp validate` stub.

### SDK pin

`@modelcontextprotocol/sdk` pinned at `1.26.0` (exact).  Protocol revision:
`2025-11-25` (primary); `2025-06-18`, `2025-03-26`, `2024-11-05`, `2024-10-07`
also accepted within the support window.

> **Note:** The original Stage 0 decision recorded `1.11.0` and revision
> `2025-03-26`.  `1.11.0` was affected by three CVEs (ReDoS, DNS-rebinding,
> cross-client data leak).  The pin was advanced to `1.26.0` and the primary
> revision updated to `2025-11-25` (SDK 1.26.0 `LATEST_PROTOCOL_VERSION`).
