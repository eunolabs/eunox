# Changelog — @euno/mcp

All notable changes to this package are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] — 2026-05-08 (Stage 1 initial release)

First public release of `@euno/mcp`. Published to GitHub Packages
(`@euno` scope). Full Stage 1 feature set.

### Added

**Transports**

- **`src/transport/stdio.ts`** — `StdioProxy`: spawns an upstream MCP server
  as a child process, bridges stdin/stdout, forwards `tools/list` /
  `resources/list` / `prompts/list` verbatim, intercepts `tools/call` through
  the PDP. Propagates upstream stderr. Handles SIGINT/SIGTERM. Drop-in
  replacement for any upstream in `claude_desktop_config.json` / Cursor
  `mcpServers` config.

- **`src/transport/http.ts`** — `HttpProxy`: streamable HTTP transport for
  LangChain.js and in-process clients. Binds to `127.0.0.1` by default;
  rejects `0.0.0.0` unless `--unsafe-bind-all` is passed. One session per
  MCP `initialize` / `shutdown` cycle, keyed by `clientInfo` + server-minted
  session ID. Concurrent sessions fully isolated.

**Policy engine**

- **`src/policy/source.ts`** — `FilePolicySource` / `LocalPolicySource`
  interface: loads YAML or JSON policy files and validates them against
  `AgentCapabilityManifest` from `@euno/common-core`. Rejects deferred
  Stage-2 types (`ipRange`, `recipientDomain`, `redactFields`, `policy`,
  `custom`) with explicit error messages naming the Stage and JSON path.

- **`src/pdp.ts`** — `ConditionEnforcerPDP`: real policy decision point
  wiring `condition-registry` from `@euno/common-core`,
  `InMemoryCallCounterStore`, and `DefaultKillSwitchManager`. Supported
  conditions: `maxCalls`, `timeWindow`, `allowedOperations`,
  `allowedExtensions`, `allowedTables`, `argumentSchema`. Unknown types
  deny by default (fail-closed).

**Audit log**

- **`src/audit/`** — OCSF-shaped JSONL at `~/.euno/audit.jsonl`
  (configurable). HMAC-SHA-256 signed with a key generated at first run,
  stored at `~/.euno/key` (mode `0600`). Rotates at 100 MiB. Format
  identical to the Stage-3 gateway evidence stream; only the signer differs.

**Telemetry**

- **`src/telemetry/`** — opt-in, off by default. First-run consent prompt,
  persisted to `~/.euno/telemetry`. Counts only — no tool names, no argument
  values, no file paths. Anonymous install ID regenerated per install.
  `EUNO_TELEMETRY=0` disables outbound. `EUNO_TELEMETRY_LOCAL=1` writes to
  `~/.euno/telemetry.jsonl` and sends nothing. Schema documented in
  `TELEMETRY.md`.

**CLI**

- `euno-mcp proxy` — stdio or HTTP proxy with `--policy`, `--transport`,
  `--port`, `--bind`, `--audit-log`, `--unsafe-bind-all` flags.
  `-- <cmd> [args]` upstream syntax.
- `euno-mcp validate <file>` — validates a policy file; reuses the same
  `validateManifest` codepath as `@euno/cli` and the production issuer.
- `euno-mcp kill <sessionId|all>` — flips the in-memory kill switch.

**Protocol**

- **`src/protocol.ts`** — `MCP_PROTOCOL_VERSION` (`'2025-11-25'`) and
  `MCP_SUPPORTED_PROTOCOL_VERSIONS` constants.

### SDK pin

`@modelcontextprotocol/sdk` pinned at `1.26.0` (exact). Protocol revision:
`2025-11-25` (primary); `2025-06-18`, `2025-03-26`, `2024-11-05`, `2024-10-07`
also accepted within the support window.
See [docs/mcp-support.md](../../docs/mcp-support.md).
