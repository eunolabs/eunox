---
title: "Deploying eunox OSS: from npm install to a governed agent in five minutes"
description: "Step-by-step guide for the Apache-2.0 OSS tier. Install @eunox/mcp, write a minimal YAML policy, wire the proxy into Claude Desktop or a Go agent, enable the local audit log, and know when to upgrade to a self-hosted gateway."
pubDate: "2026-05-28"
---

_This is the deployment guide for the **OSS (Apache-2.0)** tier. If you need shared state across multiple agents — shared kill-switch, shared call counters, queryable audit ledger — see [post 34: deploying the self-host stack](./34-deploy-self-host.md). For a full tier comparison, see [`docs/pricing.md`](https://github.com/edgeobs/eunox/blob/main/docs/pricing.md)._

---

The OSS tier is the simplest way to run eunox. All enforcement happens in-process inside the `@eunox/mcp` proxy — no server, no Redis, no Postgres. You get:

- A policy decision point (PDP) that wraps any MCP server and enforces capability conditions on every tool call, before the upstream is ever contacted.
- A local HMAC-chained audit log written to disk.
- `eunox-mcp validate-token` and `eunox-mcp stats` CLI commands for local inspection.
- Unlimited agents and enforcement events — the only limit is your machine.

**License:** Apache-2.0. No usage restrictions, no server-side component required.

---

## Prerequisites

- Node.js ≥ 18 (for `@eunox/mcp`)
- An MCP server you want to wrap (the eunox proxy sits in front of it)

---

## Step 1 — Install the proxy

```bash
npm install -g @eunox/mcp
```

Or as a project dependency:

```bash
npm install @eunox/mcp
```

---

## Step 2 — Write a policy file

Create `policy.yaml` in your project or home directory. This is the only file eunox needs at runtime.

```yaml
# policy.yaml — minimal example for a filesystem MCP server
version: "1"

capabilities:
  - id: allow-read-only-filesystem
    tools:
      - name: read_file
      - name: list_directory
    conditions:
      - type: path_prefix
        prefix: "/home/user/projects"
    audit:
      required: true

  - id: deny-write-ops
    tools:
      - name: write_file
      - name: delete_file
    effect: deny
```

The policy engine is default-deny: any tool not covered by an `allow` capability is blocked. See [`docs/capability-manifest-guide.md`](https://github.com/edgeobs/eunox/blob/main/docs/capability-manifest-guide.md) for the full schema including all condition types (`time_window`, `call_budget`, `require_approval`, and more).

---

## Step 3 — Wire into your MCP client

### Claude Desktop

Open `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows) and wrap your existing MCP server entry:

```json
{
  "mcpServers": {
    "filesystem-governed": {
      "command": "npx",
      "args": [
        "@eunox/mcp",
        "--policy", "/path/to/policy.yaml",
        "--upstream", "npx",
        "--upstream-args", "@modelcontextprotocol/server-filesystem,/home/user/projects"
      ]
    }
  }
}
```

Restart Claude Desktop. The proxy intercepts every tool call, evaluates `policy.yaml`, and forwards allowed calls to the upstream filesystem server.

### Cursor / Windsurf

The same `mcpServers` config format applies. Add the entry to your IDE's MCP configuration file and reload.

### HTTP proxy mode

If your MCP client connects over HTTP/SSE rather than stdio, start the proxy in server mode:

```bash
eunox-mcp proxy \
  --transport http \
  --port 3002 \
  --policy ./policy.yaml \
  -- node ./my-mcp-server.js
```

Point your agent at `http://localhost:3002` instead of the upstream directly.

### Go agent (in-process)

If you are writing a Go agent, you can embed the enforcement engine directly using the agent runtime SDK:

```go
import "github.com/edgeobs/eunox/internal/agentruntime"

rt, err := agentruntime.New(&agentruntime.Config{
    IssuerURL:     "https://issuer.example.com",
    GatewayURL:    "https://gateway.example.com",
    IdentityToken: getIdentityToken(), // Your OIDC/Azure AD token
})
if err != nil {
    log.Fatal(err)
}
defer rt.Stop()

// Every tool call goes through the runtime:
result, err := rt.InvokeTool(ctx, &agentruntime.ToolRequest{
    ToolName:  "read_file",
    Arguments: map[string]interface{}{"path": "/home/user/projects/main.go"},
})
```

See [`docs/agent-sdk.md`](https://github.com/edgeobs/eunox/blob/main/docs/agent-sdk.md) for the full SDK reference.

---

## Step 4 — Enable the local audit log

The proxy automatically writes HMAC-chained audit records to `~/.eunox/audit.jsonl`. Each enforcement event is appended as a newline-delimited JSON record. Records are HMAC-chained: each record's `prev_hash` field covers the previous record, producing a tamper-evident append-only log.

To write the log to a custom path, pass `--audit-log`:

```bash
eunox-mcp proxy --policy ./policy.yaml --audit-log ./audit.jsonl -- npx @modelcontextprotocol/server-filesystem /home/user/projects
```

Inspect individual records at any time:

```bash
eunox-mcp validate-token --since 2026-05-01
```

---

## Step 5 — Inspect enforcement stats

```bash
eunox-mcp stats
```

Outputs a summary of enforcement decisions (allow/deny counts, top tool calls, condition hit rates) since the proxy started.

---

## When to upgrade

The OSS tier is the right choice when:

- You have one agent process (or a few independent agents that don't share state).
- You don't need a kill-switch that spans multiple agent processes simultaneously.
- File-based audit retention is sufficient for your compliance needs.

You should consider the **Self-Host** tier when:

- You need a shared kill-switch that kills all agent processes simultaneously.
- You want centralized, queryable audit records across multiple agents.
- You need call-budget enforcement that's shared across agent instances (not per-process).

To upgrade, run:

```bash
eunox-mcp upgrade-to-hosted \
  --gateway-url https://your-gateway.example.com \
  --api-key sk-<prefix>.<secret>
```

This command patches your existing `policy.yaml` to use the remote enforcer and migrates local audit records. See [`docs/upgrade-to-hosted.md`](https://github.com/edgeobs/eunox/blob/main/docs/upgrade-to-hosted.md) for the full upgrade walkthrough.

---

## Troubleshooting

**Tool call blocked unexpectedly**

The proxy logs every enforcement decision at `DEBUG` level. Set `EUNOX_LOG_LEVEL=debug` to see which capability matched (or failed to match) and why.

**Policy parse error on startup**

Run `eunox-mcp validate ./policy.yaml` to get a structured error report before starting the proxy.

**Audit log grows unbounded**

The local audit log is a plain append-only file — set up log rotation with `logrotate` or a similar tool. The HMAC chain is preserved across rotated files as long as you keep the `prev_hash` of the last record of the previous file.

---

_Next: [post 34 — deploying the self-host stack (Redis, Postgres, KMS, Helm)](./34-deploy-self-host.md). For the full series index, see [`docs/blog-articles.md`](https://github.com/edgeobs/eunox/blob/main/docs/blog-articles.md)._
