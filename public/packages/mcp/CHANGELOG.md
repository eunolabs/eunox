# Changelog — @euno/mcp

All notable changes to this package are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.0] — Unreleased (Stage 3: Remote-Enforcer Mode)

### Added

- **Remote-enforcer mode** (`--enforcer-url` / `--enforcer-api-key`).
  When `--enforcer-url <url>` is supplied together with `--enforcer-api-key
  <key>`, the proxy switches from local in-process enforcement to the hosted
  Euno gateway.  Every `tools/call` is forwarded to `POST /api/v1/enforce`
  at the configured gateway URL; the gateway's `EnforceResponse` is
  translated into a `PdpDecision` that the existing transport layer processes
  without modification.

  Key properties of remote-enforcer mode:
  - **Fail-closed**: any network error, HTTP error response, or malformed
    body results in a `deny` decision with code `GATEWAY_UNAVAILABLE`.
    The upstream tool is never called when the gateway is unreachable.
  - **No local infrastructure**: `FilePolicySource`, `LocalHmacSigner`,
    `InMemoryCallCounterStore`, and the in-memory kill switch are not
    constructed in remote mode.  The gateway is the sole enforcement authority.
  - **Obligations**: `redactFields` obligations returned by the gateway are
    applied to the upstream response before forwarding to the MCP client,
    using the same redaction engine as local mode.  `annotate` obligations
    are captured as `annotateValues` key/value pairs in the local audit record
    (they do not modify the upstream response).
  - **Configurable timeout**: `--enforcer-timeout <ms>` (default 10 s) bounds
    each enforce request; exceeded requests are denied fail-closed.

- **`RemoteEnforcerPDP`** — new public class exported from `@euno/mcp` (and
  `src/enforcer/remote.ts`).  Implements `PolicyDecisionPoint`.  Accepts an
  injectable `EnforceFetcher` for unit-test isolation.

- **`PdpDecision.obligations`** — new optional field (`readonly Obligation[]`)
  carrying response-path obligations returned by the remote enforcer.  The
  transport layer checks this field first; if absent it falls back to the
  existing `matchedConditions`-based local path.

- **`applyRemoteObligations`** — new export from `src/transport/obligations.ts`.
  Applies `Obligation[]` (gateway wire type) to an upstream tool-call result:
  `redactFields` obligations strip fields from the response; `annotate`
  obligations capture key/value metadata in the caller's audit record (the
  response is not modified).

- **`McpAuditRecord.annotateValues`** — new optional field on the audit record
  type.  Carries annotation key/value pairs from the gateway's `annotate`
  obligations, stored in the OCSF `unmapped` block as `"annotateValues"`.
  Covered by the HMAC signature.

- **New CLI options**:
  - `--enforcer-url <url>` — gateway base URL (e.g. `https://gateway.euno.example`)
  - `--enforcer-api-key <key>` — API key sent as Bearer token in each enforce request
  - `--enforcer-timeout <ms>` — timeout for each gateway call (default: 10000 ms)

### Design note

The Stage-3 architectural boundary is at the *enforcer call*, not at the
policy-reader seam.  Swapping only `LocalPolicySource` for a JWT loader would
leave local counters and kill-switch infrastructure running in-process.
`RemoteEnforcerPDP` skips all local enforcement infrastructure and delegates
the entire enforcement decision to the gateway.  The `LocalPolicySource` seam
is retained for the Task-10 minter JWT loader.

- **Reference materials and migration guide (Task 18)** — new document
  `docs/migrating-from-local.md` covering:
  - Before/after configuration: what replaces `--policy` in hosted mode and
    exactly what each config flag does.
  - The cryptographic story: why `sk-...` is not a JWT capability token and
    why the minter façade is needed to preserve the cryptographic-token
    invariant.
  - Explicit data-boundary analysis for SOC2/GDPR review: which fields leave
    the customer's network on every `tools/call` (notably `arguments`),
    which data stays local (upstream responses, raw API key material, HSM
    key material), and the network topology diagram.
  - Step-by-step migration guide with optional parallel smoke-test phase.
  - Manual migration recipe using the admin API directly.
  - Rollback procedure (instantaneous — restore `--policy` flag).
  - Self-host alternative for teams that cannot transmit tool-call arguments
    to an external service.
  - FAQ: policy file reuse, fail-closed behaviour, self-issued JWTs,
    local audit log fate, custom conditions in hosted mode.

---

## [0.2.0] — 2026-05-09 (Stage 2: General Tool Enforcement)

Full Stage 2 feature set. Expands the supported condition matrix to the complete
`CapabilityCondition` discriminated union, adds new CLI subcommands, and ships a
reference policy library for common upstream MCP servers.

### Upgrade from 0.1.x

Users on `@euno/mcp@0.1.x` whose policy file uses only Stage-1 conditions
(`maxCalls`, `timeWindow`, `allowedOperations`, `allowedExtensions`,
`allowedTables`, `argumentSchema`) will see **no behavioural change** after
upgrading to 0.2.0. All existing policy files continue to load and enforce
identically. The only user-visible change is that conditions which previously
raised a load-time error ("deferred to Stage 2") are now accepted.

### Added

**New condition types (Stage 1 gate lifted)**

- **`ipRange`** — allows or denies a tool call based on the client's source IP
  address.  Accepts a list of CIDR strings (`cidrs`).  Wired to the real socket
  address on the HTTP transport; stdio calls have no source IP and are denied
  when `ipRange` is present.  CLI flag: `--trust-forwarded-for` allows trusting
  `X-Forwarded-For` when the proxy is bound to a loopback address.

- **`recipientDomain`** — extracts recipient e-mail / handle arguments from the
  tool call and checks each against the configured `allowedDomains` list.
  Recipients not in an allowed domain are denied before the upstream is reached.

- **`redactFields`** — allows the tool call but rewrites the upstream response,
  replacing the values at the listed JSON paths with `[REDACTED]`.  The audit
  log records `obligationsApplied: ['redactFields']` on the allow decision.

- **`policy`** — delegates enforcement to an external policy engine loaded via
  `--policy-backend <module>`.  The module registers a named backend with
  `registerPolicyBackend`; the condition references that backend by name.
  See [`docs/policy-backends.md`](./docs/policy-backends.md) for the full
  interface reference and an OPA HTTP worked example.

- **`custom`** — loads arbitrary condition handlers via `--custom-condition
  <module>` (repeatable).  Each module registers one or more handler names with
  `registerCustomCondition`.  See [`docs/custom-conditions.md`](./docs/custom-conditions.md)
  for the contract.

**Structured error reporting (Task 1)**

- `PdpDecision` now carries an optional `details?: Record<string, unknown>`
  field populated when `argumentSchema` validation fails.  The JSON-RPC error
  response includes `{ code: 'ARGUMENT_VALIDATION_FAILED', conditionType:
  'argumentSchema', details: { path, expected, got } }`.  The audit record
  writes the same `details` into the `unmapped` block.

**New CLI subcommands**

- `euno-mcp validate-token --request-id <id>` — look up an audit record by
  request ID and verify its HMAC-SHA-256 signature.  Exits 0 on success, 2 on
  tampered/invalid signature.
- `euno-mcp validate-token --since <ISO>` — scan the audit log from a timestamp
  and verify every record.  Reports the first tampered record, if any.
- `euno-mcp stats [--since <ISO>] [--audit-log <path>]` — reads the local audit
  log (including rotated segments) and prints an ASCII histogram of denial
  events grouped by `conditionType` and `denialCode`.  Useful for understanding
  why calls are being denied without running a separate query tool.

**New CLI flags**

- `proxy --policy-backend <module>` — load a policy backend module (repeatable;
  already documented, now fully wired to the `policy` condition type).
- `proxy --custom-condition <module>` — load a custom condition handler module
  (repeatable; wires the `custom` condition type).
- `proxy --trust-forwarded-for` — trust the first value in `X-Forwarded-For`
  for `ipRange` enforcement (HTTP transport only; requires loopback bind address).

**Reference policy library (`policies/`)**

Five pre-built policy files for the most common upstream MCP servers — drop one
in your project and run with no additional code:

| File | Upstream | Enforces |
|------|----------|----------|
| `filesystem.policy.yaml` | `@modelcontextprotocol/server-filesystem` | Writes/deletes confined to `/data/`; executable types blocked |
| `postgres.policy.yaml` | `@modelcontextprotocol/server-postgres` | Non-SELECT SQL blocked; credential and audit tables blocked |
| `github.policy.yaml` | `@modelcontextprotocol/server-github` | Write tools rate-limited to prevent runaway automation |
| `slack.policy.yaml` | `@modelcontextprotocol/server-slack` | Direct messages restricted to `company.com` via `recipientDomain` |
| `fetch.policy.yaml` | `mcp-server-fetch` | HTTP URLs blocked; private RFC-1918 addresses blocked (SSRF guard) |

### Changed

- `FilePolicySource` no longer rejects `ipRange`, `recipientDomain`,
  `redactFields`, `policy`, or `custom` condition types.  These are now
  accepted and validated via `validateManifest` from `@euno/common-core`.
- `ConditionEnforcerPDP` now populates `sourceIp` from the HTTP request socket
  and passes it through the `ConditionContext` for `ipRange` enforcement.
- Audit records now include a `details` field in `unmapped` for
  `argumentSchema` denial decisions.

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
  `AgentCapabilityManifest` from `@euno/common-core`. In Stage 1, five
  condition types (`ipRange`, `recipientDomain`, `redactFields`, `policy`,
  `custom`) were rejected at load time with an explicit "deferred to Stage 2"
  error; this gate is lifted in 0.2.0.

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
