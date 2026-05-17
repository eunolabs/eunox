# @euno/mcp

**Add guardrails to any MCP server in 5 minutes. No infrastructure required.**

`@euno/mcp` is a policy proxy for the [Model Context Protocol](https://spec.modelcontextprotocol.io/).
It sits between your MCP host (Claude Desktop, Cursor, Windsurf, LangChain.js, …) and your upstream
MCP server, enforcing a declarative capability policy before any tool call reaches your backend.
Apache-2.0 licensed, zero cloud dependencies, runs entirely on your machine.

---

## Before / After

**Without `@euno/mcp`** — the agent sends whatever arguments it likes:

```
Agent  →  tools/call: query_db { query: "DROP TABLE users" }
                                     ↓
                          Upstream MCP server executes it
                                     ↓
Agent  ←  result: OK  (table is gone)
```

**With `@euno/mcp`** — the policy fires before the upstream is ever contacted:

```
Agent  →  tools/call: query_db { query: "DROP TABLE users" }
                                     ↓
                          @euno/mcp: policy says SELECT only
                          upstream never called
                                     ↓
Agent  ←  CapabilityDenied: operation not permitted
```

One YAML file. No code changes to your agent or your server.

---

**Second example — HTTP transport, recipient guard:**

An agent connected over HTTP tries to send a Slack DM to an external address.
The `recipientDomain` condition fires before the upstream is reached:

```
Agent  →  tools/call: send_message { to: "attacker@evil.com", text: "..." }
                                     ↓
                          @euno/mcp (HTTP): recipientDomain check fails
                          upstream never called
                                     ↓
Agent  ←  CapabilityDenied: recipient domain not in allowlist
```

The same policy file works for both stdio and HTTP transports.

---

## Drop-in usage

### stdio — Claude Desktop / Cursor / Windsurf

Add `euno-mcp proxy` as a wrapper in your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "filesystem-governed": {
      "command": "npx",
      "args": [
        "-y", "@euno/mcp", "proxy",
        "--policy", "/path/to/euno.policy.yaml",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"
      ]
    }
  }
}
```

Without a policy file the proxy is transparent — useful for auditing before you add rules:

```json
{
  "mcpServers": {
    "filesystem-audited": {
      "command": "npx",
      "args": ["-y", "@euno/mcp", "proxy", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
}
```

### HTTP — LangChain.js / in-process clients

```bash
npx -y @euno/mcp proxy \
  --transport http --port 7391 \
  --policy ./euno.policy.yaml \
  -- node ./my-mcp-server.js
```

Connect your LangChain.js agent to `http://127.0.0.1:7391/mcp`.

### Validate a policy without running anything

```bash
npx -y @euno/mcp validate ./euno.policy.yaml
```

---

## Reference policies

Pre-built policy files for the most popular upstream MCP servers are in
[`policies/`](./policies/). Drop one in your project and run it immediately.

| Policy file | Upstream server | What it enforces |
|-------------|-----------------|-----------------|
| [`filesystem.policy.yaml`](./policies/filesystem.policy.yaml) | `@modelcontextprotocol/server-filesystem` | Writes/deletes confined to `/data/`; executable file types blocked |
| [`postgres.policy.yaml`](./policies/postgres.policy.yaml) | `@modelcontextprotocol/server-postgres` | Non-SELECT SQL blocked; credential and audit tables blocked |
| [`github.policy.yaml`](./policies/github.policy.yaml) | `@modelcontextprotocol/server-github` | Write tools rate-limited to prevent runaway automation |
| [`slack.policy.yaml`](./policies/slack.policy.yaml) | `@modelcontextprotocol/server-slack` | Direct messages restricted to `company.com` via recipientDomain |
| [`fetch.policy.yaml`](./policies/fetch.policy.yaml) | `mcp-server-fetch` | HTTP URLs blocked; userinfo authority blocked; private RFC-1918 and metadata endpoint blocked (lexical SSRF guard) |

> **Note:** euno-mcp allows tool calls that match no constraint in the manifest. Policies restrict only the tools they list. For tools not listed, use additional constraints or network-level controls.

See [`policies/README.md`](./policies/README.md) for quick-start instructions and adaptation guidance.

---

## Example policy (`euno.policy.yaml`)

```yaml
agentId: my-db-agent
name: My Database Agent
version: 0.1.0
requiredCapabilities:
  - resource: "tool://query_db"
    actions: [call]
    conditions:
      - type: allowedOperations
        operations: [SELECT]
      - type: maxCalls
        limit: 100
        windowSeconds: 60
```

### Supported condition types

| Condition | What it enforces | Notes |
|-----------|-----------------|-------|
| `argumentSchema` | JSON Schema validation on tool arguments | Structured error details surfaced in the MCP response |
| `allowedOperations` | SQL verb allowlist (`SELECT`, `INSERT`, …) | First-word extraction — see [prompt injection note](#allowedoperations--first-word-extraction-not-sql-parsing) |
| `allowedExtensions` | File extension allowlist (`.csv`, `.json`, …) | Checks the `filePath` / `path` / `file` argument |
| `allowedTables` | Database table allowlist | Checks `table` / `tables` arguments |
| `allowedValues` | Enum allowlist on any argument field | |
| `maxCalls` | Per-session rate limit (count + time window) | Counter resets when the window expires |
| `timeWindow` | `notBefore` / `notAfter` wall-clock gate | |
| `ipRange` | Source IP CIDR allowlist | HTTP transport only — stdio sessions have no source IP¹ |
| `recipientDomain` | E-mail / handle recipient domain allowlist | Checks `to`, `recipients`, `cc`, `bcc` arguments |
| `redactFields` | Strip named JSON paths from the upstream response | Response-path obligation — enforcement always allows |
| `policy` | Delegate to a named external policy backend | Loaded via `--policy-backend`; see [`docs/policy-backends.md`](./docs/policy-backends.md) |
| `custom` | Arbitrary handler registered by name | Loaded via `--custom-condition`; see [`docs/custom-conditions.md`](./docs/custom-conditions.md) |

¹ `ipRange` with a stdio session is denied with `IP_RANGE_DENIED` and the reason
`"ipRange requires sourceIp in request context"`. Use the HTTP transport when IP-based enforcement is required.

---

## Custom policy backends

The `policy` condition type lets you delegate enforcement to an external policy
engine (OPA, Cedar, a custom rules database, or any service callable from Node.js).

Write a module that exports a default registrar function, then pass it with
`--policy-backend`:

```js
// my-policy-backend.js
module.exports = function register(api) {
  api.registerPolicyBackend('my-engine', {
    validate(config) { /* check config is valid */ },
    async enforce(config, input, ctx) {
      const allowed = await askMyEngine(config, input, ctx.sourceIp);
      return allowed
        ? { allow: true }
        : { allow: false, reason: 'my-engine: request denied' };
    },
  });
};
```

```yaml
# euno.policy.yaml  (partial — required top-level fields omitted for brevity)
agentId: my-agent
name: My Agent
version: 0.1.0
requiredCapabilities:
  - resource: "mcp-tool://sensitive_tool"
    actions: [call]
    conditions:
      - type: policy
        backend: my-engine        # must match the name passed to registerPolicyBackend
        config: { key: value }    # any static config your engine needs
```

```bash
euno-mcp proxy \
  --policy ./euno.policy.yaml \
  --policy-backend ./my-policy-backend.js \
  -- node ./upstream-server.js
```

The flag is **repeatable** — pass `--policy-backend` multiple times to load
several modules.  Module errors fail fast before the proxy starts.

See [docs/policy-backends.md](./docs/policy-backends.md) for the full interface
reference, an OPA HTTP worked example, and Stage-3 compatibility notes.

## Custom conditions

Load custom condition handlers with repeatable `--custom-condition` flags:

```bash
npx -y @euno/mcp proxy \
  --policy ./euno.policy.yaml \
  --custom-condition ./custom-conditions/my-handler.js \
  --custom-condition ./custom-conditions/another-handler.js \
  -- node ./my-mcp-server.js
```

Each module must default-export a function that receives
`{ registerCustomCondition }` and registers one or more handlers.
See [`docs/custom-conditions.md`](./docs/custom-conditions.md) for the full contract.

---

## Enforcement guarantee

Enforcement runs on the arguments **the agent actually sent** — before the upstream is called.
The guarantee is: "the agent sent this tool call with these arguments, and it was
allowed/denied by this policy." It is not a guarantee about what the upstream server did
internally. For the strongest guarantees, instrument the upstream as well.

### Schema parity — one shape, zero drift

The policy file `@euno/mcp` consumes is a **literal subset** of `AgentCapabilityManifest`
from `@euno/common-core` (Apache-2.0). `@euno/mcp` imports types from `@euno/common-core` and
never defines its own condition or constraint types.

**Unknown condition types are denied** at two points — at policy-validation time (`euno-mcp validate`)
and at enforcement time (the PDP). Both layers refuse unknown types, so a typo in a condition type
name is a **fail-closed error**, not a silent pass-through.

### `allowedOperations` — first-word extraction, not SQL parsing

The `allowedOperations` condition extracts the **first whitespace-delimited token** from
the SQL argument and uppercases it (e.g. `"SELECT * FROM users"` → `"SELECT"`).  This
catches the most common prompt injection shapes, but can be bypassed by adversaries who
control the query string:

| Bypass vector | Example |
|---|---|
| Semicolon-chained statements | `SELECT 1; DELETE FROM orders` — second statement may execute if the DB driver allows multi-statement queries |
| Block comment before verb | `/* comment */ SELECT * FROM ...` — first token is `/*` which is not an allowed operation, so the call is **denied** (fail-closed). Note: this also blocks legitimate comment-prefixed queries. |

**Recommended defense-in-depth** (stack all layers):
1. `allowedOperations` — first-line gate on the SQL verb
2. `argumentSchema` `pattern` — regex to anchor the verb and reject `;` and `/*`
3. Disable multi-statement execution in the database driver
4. Read-only database credentials matching your allowed operations
5. Parameterized queries in the upstream MCP server

See [`docs/prompt-injection-demo.md`](./docs/prompt-injection-demo.md) for a full
walkthrough of the attack and all defense layers, including a step-by-step demo you can
run yourself.

### Prompt injection

Prompt injection is the primary real-world motivation for `@euno/mcp`.  An attacker
embeds a malicious instruction in content the agent reads (a PDF, a web page, a
database record) and the LLM may execute it.  `@euno/mcp` blocks the resulting tool
call before it reaches the upstream server, independent of what the LLM decided to do.

See [`docs/prompt-injection-demo.md`](./docs/prompt-injection-demo.md) for a live demo.

### HTTP transport — securing the proxy endpoint

When running in `--transport http` mode, the `/mcp` endpoint listens on `127.0.0.1`
by default.  Any process on the same machine can call it without authentication.  Use
`--auth-token` to require a Bearer token:

```bash
TOKEN=$(openssl rand -hex 32)
euno-mcp proxy --transport http --port 7391 --auth-token "$TOKEN" \
  --policy ./euno.policy.yaml -- node ./my-mcp-server.js
```

Configure your MCP client to send `Authorization: Bearer $TOKEN`. Without this flag, a
warning is printed at startup.

### Upstream timeouts

By default the proxy waits indefinitely for the upstream to respond to a `tools/call`.
Pass `--upstream-timeout <ms>` to bound the wait:

```bash
euno-mcp proxy --upstream-timeout 30000 -- node ./my-mcp-server.js
```

On timeout the proxy returns a structured `CapabilityDenied` result with
`code: "UPSTREAM_TIMEOUT"` rather than hanging the MCP host.

---

## Stage-3 remote-enforcer mode

`@euno/mcp` can delegate enforcement to the hosted Euno gateway instead of
evaluating policy in-process.  Pass `--enforcer-url` and `--enforcer-api-key`
in place of `--policy`:

```bash
euno-mcp proxy \
  --enforcer-url https://gateway.euno.example \
  --enforcer-api-key sk-... \
  -- node ./my-mcp-server.js
```

Every intercepted `tools/call` is forwarded to the gateway's
`POST /api/v1/enforce` endpoint.  The gateway evaluates the full policy (including
`maxCalls` rate limits, kill-switch state, and KMS-signed audit) and returns either
an **allow** decision (optionally with response-path obligations such as
`redactFields`) or a **deny** decision.

> **Migrating from local mode?**  See
> [`docs/migrating-from-local.md`](../../../docs/migrating-from-local.md) for the
> step-by-step guide, the cryptographic story behind the `sk-...` API key, and
> the explicit data-boundary analysis (what leaves your network in hosted mode —
> required reading for SOC2 / GDPR review).

### What changes in remote mode

| Feature | Local mode | Remote mode |
|---|---|---|
| Policy file | Required (`--policy`) | Not used |
| In-process counters | `InMemoryCallCounterStore` | Gateway Redis/DB |
| Kill switch | In-memory (per process) | Gateway global |
| Audit signing | Local HMAC key file | Gateway KMS |
| Custom conditions | Loaded via `--custom-condition` | Registered on gateway |
| Policy backends | Loaded via `--policy-backend` | Registered on gateway |

### Fail-closed guarantee

Any network error, HTTP error response, or malformed response body from the gateway
results in a `deny` decision with code `GATEWAY_UNAVAILABLE`.  The upstream tool is
never called when the gateway is unreachable.

### Obligations

When the gateway allows a call it may return response-path obligations.  The proxy
applies them automatically before forwarding the upstream response to the MCP client:

| Obligation type | Effect |
|---|---|
| `redactFields` | Strips listed dotted-path fields from JSON text content and `structuredContent` |
| `annotate` | Captures key/value metadata in the local audit record for this tool call (response unchanged) |

### Options

| Option | Description | Default |
|---|---|---|
| `--enforcer-url <url>` | Gateway base URL | *(required)* |
| `--enforcer-api-key <key>` | API key (Bearer token) | *(required)* |
| `--enforcer-timeout <ms>` | Timeout per gateway call | 10000 ms |

`--enforcer-url` and `--policy` are mutually exclusive.

---

## Commands

| Command | Description |
|---------|-------------|
| `euno-mcp proxy [--policy <file>] [--transport stdio\|http] [--port <n>] -- <upstream-cmd>` | Start the proxy (local enforcement) |
| `euno-mcp proxy --enforcer-url <url> --enforcer-api-key <key> -- <upstream-cmd>` | Start the proxy (remote-enforcer mode) |
| `euno-mcp proxy --auth-token <token>` | Require Bearer token auth on /mcp (HTTP transport) |
| `euno-mcp proxy --upstream-timeout <ms>` | Timeout for upstream tool calls |
| `euno-mcp proxy --enforcer-timeout <ms>` | Timeout per remote enforce request (default: 10000 ms) |
| `euno-mcp proxy --policy-backend <module>` | Load a policy backend module (repeatable) |
| `euno-mcp proxy --custom-condition <module>` | Load a custom condition handler module (repeatable) |
| `euno-mcp proxy --trust-forwarded-for` | Trust `X-Forwarded-For` for `ipRange` (HTTP transport, loopback bind only) |
| `euno-mcp validate <policy-file>` | Validate a policy file — exits 0 on success |
| `euno-mcp validate-token --request-id <id>` | Look up an audit record by request ID and verify its HMAC signature |
| `euno-mcp validate-token --since <ISO>` | Scan the audit log from a timestamp and verify all records |
| `euno-mcp stats [--since <ISO>] [--audit-log <path>]` | Print a denial-reason histogram from the local audit log |
| `euno-mcp kill <sessionId\|all> [--port <n>]` | Activate the kill switch in a running HTTP proxy |
| `euno-mcp --help` | Show all options |

---

## Installation

`@euno/mcp` is published to [GitHub Packages](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-npm-registry).

GitHub Packages requires authentication even for public packages.
You will need a [Personal Access Token](https://github.com/settings/tokens) (classic or fine-grained)
with at least **read:packages** scope.

Configure the `@euno` scope to use GitHub Packages — this keeps the default npm registry in place
for all other dependencies (`commander`, `js-yaml`, etc.):

```bash
# Point the @euno scope at GitHub Packages (one-time, per machine or project)
npm config set @euno:registry https://npm.pkg.github.com

# Authenticate for the GitHub Packages host
npm login --registry=https://npm.pkg.github.com
# Username: your GitHub username
# Password: your GitHub PAT (read:packages scope)
# Email: your GitHub email

# Install globally
npm install -g @euno/mcp

# Or use with npx
npx @euno/mcp --help
```

For CI or project-level use, add an `.npmrc` file instead of running the above commands:

```
@euno:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

---

## Compatibility

| | Version |
|---|---|
| `@modelcontextprotocol/sdk` (dependency range) | `^1.26.0` (semver range) |
| MCP protocol (primary) | `2025-11-25` |
| MCP protocol (also accepted) | `2025-06-18`, `2025-03-26`, `2024-11-05`, `2024-10-07` |
| Node.js | ≥ 18 |

The pinned version constant is exported from the package:

```ts
import { MCP_PROTOCOL_VERSION, MCP_SUPPORTED_PROTOCOL_VERSIONS } from '@euno/mcp';
```

See [docs/mcp-support.md](../../docs/mcp-support.md) for the full version policy, support window,
and upgrade procedure.

---

## Telemetry

`@euno/mcp` optionally collects anonymous, aggregate usage counts to help prioritize improvements.
**Telemetry is off by default.** On the first interactive run you are asked:

```
Enable anonymous telemetry? [y/N]
```

Disable at any time with `EUNO_TELEMETRY=0`. See [TELEMETRY.md](./TELEMETRY.md) for the full
schema, where data goes, and all opt-out mechanisms.

---

## Development

### Prerequisites

```bash
npm install        # install all workspace dependencies
npm run build      # build all workspaces (common-core → common-infra → common → posture-emitter → mcp → langchain → …)
npm run test       # run all test suites
npm run lint       # eslint + license-boundary check
```

### VSCode

The repository ships ready-to-use VSCode configuration in `.vscode/`:

| File | Purpose |
|------|---------|
| `launch.json` | Debug configurations for the CLI (`proxy`, `validate`, `stats`, `validate-token`), Jest tests, and the Stage 3 readiness script |
| `tasks.json` | Build, watch, test, and lint tasks for each public package and the monorepo root |
| `settings.json` | TypeScript workspace SDK, ESLint working directories, and search/file excludes |
| `extensions.json` | Recommended extensions (ESLint, vscode-jest, YAML, GitLens) |

Open the repo in VSCode and press **F5** to launch a debug session (the
"euno-mcp: proxy (stdio)" configuration is selected by default — you will be
prompted for a policy file and upstream script path).  Press **Ctrl+Shift+B**
(macOS: ⌘⇧B) to run the default build task (`build: all`).

### Build order

The monorepo build sequence is:

```
@euno/common-core  →  @euno/common-infra  →  @euno/common
     ↓
@euno/posture-emitter  →  @euno/mcp  →  @euno/langchain  →  platform packages
```

The `build: @euno/mcp` VSCode task automatically pre-builds `@euno/common-core`.

---

## License

Apache-2.0 — see [LICENSE](./LICENSE).
