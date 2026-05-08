# How I stopped my LangChain agent from destroying my dev database

*Draft — owned by marketing for final editing and posting.*

---

Last week my LangChain agent ran a `DROP TABLE users` against my dev database.

Not a typo. Not a test fixture. The actual table, gone, because I gave the agent access to a `query_db` MCP tool and it decided the most efficient way to complete a task was to clear the table first.

The tool worked exactly as documented. The agent used it exactly as intended. Nobody was surprised except me.

## The problem with "just don't give it dangerous tools"

The advice is everywhere: scope your tools, use read-only credentials, sandbox the agent. All true. All incomplete.

The problem is that "read-only" is a property of the database credential, not of the tool call. The MCP server enforces it — if you configured it correctly, in your infra, for this specific agent, this specific deployment. The agent itself has no idea whether the tool it's calling is scoped or not. It just calls it.

What I actually wanted was: **the agent cannot call `query_db` with a non-SELECT statement, full stop, regardless of what the database allows.**

That's not a database permission. It's a policy on the tool call itself.

## What `@euno/mcp` does

`@euno/mcp` is a proxy that sits between your MCP host and your MCP server. You give it a YAML policy file. It enforces the policy on every `tools/call` before the upstream server is ever contacted.

```
Agent  →  tools/call: query_db { query: "DROP TABLE users" }
                                     ↓
              @euno/mcp: policy says allowedOperations: [SELECT]
              upstream never called
                                     ↓
Agent  ←  CapabilityDenied: operation not permitted
```

The upstream never sees the call. The database never sees the query. The agent gets a structured denial it can reason about.

Here's the policy that would have saved my table:

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

And here's how I drop it in front of my existing MCP server without changing a line of agent or server code:

```json
{
  "mcpServers": {
    "db-governed": {
      "command": "npx",
      "args": [
        "-y", "@euno/mcp", "proxy",
        "--policy", "./euno.policy.yaml",
        "--",
        "node", "./my-mcp-server.js"
      ]
    }
  }
}
```

Five minutes. No infrastructure. No new services. No vendor lock-in.

## What it enforces

`@euno/mcp` v0.1.0 ships six enforcement mechanisms:

- **`allowedOperations`** — SQL verb allowlist (SELECT, INSERT, …), file operation allowlist, etc.
- **`allowedTables`** — restrict which tables a query may touch
- **`allowedExtensions`** — restrict which file extensions a file tool may access
- **`maxCalls`** — sliding-window call-rate limit per session
- **`timeWindow`** — restrict tool use to a time range (`notBefore` / `notAfter`)
- **`argumentSchema`** — JSON Schema validation on the tool's arguments

Everything runs locally. No network calls, no tokens, no cloud.

## The enforcement guarantee (and its limits)

The guarantee is: *the agent sent this tool call with these arguments, and it was
blocked before the upstream was called.* That's it.

`@euno/mcp` enforces on arguments **as the agent sent them**. It is not a guarantee about what the upstream server does internally — if your upstream has its own side effects, `@euno/mcp` does not reach inside it. For the strongest guarantees, instrument the upstream too. `@euno/mcp` is the layer that catches what the agent does before it gets there.

## Try it

```bash
# Validate your policy file first
npx -y @euno/mcp validate ./euno.policy.yaml

# Run it in front of any MCP server
npx -y @euno/mcp proxy --policy ./euno.policy.yaml -- node ./my-mcp-server.js
```

The audit log lands at `~/.euno/audit.jsonl` — OCSF-shaped, locally HMAC-signed, append-only. Every allow and every deny, with the arguments (redacted from telemetry, kept in the local log).

Source: [github.com/edgeobs/euno](https://github.com/edgeobs/euno), Apache-2.0.

---

*Feedback welcome — open an issue or reply to the launch thread.*
