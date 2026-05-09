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
version: 1.0.0
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

Supported condition types: `maxCalls`, `timeWindow`, `allowedOperations`,
`allowedExtensions`, `allowedTables`, `ipRange`, `recipientDomain`, `policy`,
plus the `argumentSchema` field on each constraint.

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
version: 1.0.0
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

---

## Commands

| Command | Description |
|---------|-------------|
| `euno-mcp proxy [--policy <file>] [--transport stdio\|http] [--port <n>] -- <upstream-cmd>` | Start the proxy |
| `euno-mcp proxy --policy-backend <module>` | Load a policy backend module (repeatable) |
| `euno-mcp validate <policy-file>` | Validate a policy file — exits 0 on success |
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
| `@modelcontextprotocol/sdk` pin | `1.26.0` (exact) |
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

## License

Apache-2.0 — see [LICENSE](./LICENSE).
