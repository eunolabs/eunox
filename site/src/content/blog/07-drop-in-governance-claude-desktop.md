---
title: "Drop-in governance: adding `eunox-mcp` to Claude Desktop in 5 minutes"
description: "individual developers who want agent security without a DevOps project"
pubDate: "2026-05-26"
---
# Drop-in governance: adding `eunox-mcp` to Claude Desktop in 5 minutes

_Audience: individual developers who want agent security without a DevOps project_

---

Let me set the scene. You've been using Claude Desktop with a handful of MCP servers — maybe the filesystem server for your documents folder, maybe the Postgres server for your analytics database, possibly a GitHub integration. It's genuinely great. The agent can read files, query your database, look at your repo. You feel productive in a way that a chat interface alone never quite achieves.

Then you have a thought that most people have around the three-week mark: "wait, does Claude have unrestricted access to my entire `/home` directory right now?" And the answer is yes, because that's what you put in the filesystem server's args. And then: "could it send an email to anyone if I ask it to?" Probably. "Could a malicious PDF I feed it convince it to do something I wouldn't want it to do?" You've read enough security posts to know the answer to that one too.

The typical next step is to just... not think about it, and carry on. The typical alternative is to start reading about capability tokens and cryptographic policy enforcement and suddenly it looks like a three-week infrastructure project and you close the tabs.

This post is the middle path. I'm going to walk you through adding real, substantive governance to your Claude Desktop MCP setup in the time it takes to write a short YAML file and edit one JSON config. The governance layer we're adding is `eunox-mcp` — a policy proxy that sits between Claude and your MCP servers, checks every tool call against a policy you define, and blocks anything that doesn't match.

If you want to understand the theory behind why this architecture works, [the policy proxy design post](./06-mcp-policy-proxy.md) covers that in depth. This post is the hands-on tutorial.

---

## What you'll end up with

By the end of this, you'll have:

- Claude Desktop routing all tool calls through `eunox-mcp` before they reach your MCP servers
- A policy YAML file that defines exactly what Claude is allowed to do with each tool
- Denied calls getting logged with the reason, so you can see if anything interesting is being blocked
- A local audit trail of every approved call, with the arguments, for review or debugging

The whole thing runs in-process — no Docker, no Redis, no separate service to start. It's a single config change and a YAML file.

---

## Prerequisites

- Claude Desktop installed (or Cursor, Windsurf — anything that reads an MCP config JSON)
- Go 1.25+ installed (check with `go version`) so you can install `eunox-mcp` via `go install github.com/edgeobs/eunox/cmd/eunox-mcp@latest` or use a downloaded release binary
- An existing MCP server you're using — I'll use the filesystem server as the example throughout

If you're not sure what MCP servers you have configured, open your Claude Desktop config file. On macOS it's at `~/Library/Application Support/Claude/claude_desktop_config.json`. On Windows it's `%APPDATA%\Claude\claude_desktop_config.json`. Take a look at what's in there.

---

## Step 1: Understand your current config

Here's what a typical Claude Desktop config looks like with the filesystem server:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/Users/you/Documents"
      ]
    }
  }
}
```

Simple enough. Claude spawns the filesystem server as a subprocess, communicates over stdio, and has direct access to everything in `/Users/you/Documents`. No policy evaluation, no audit log, no rate limiting.

What we're going to do is insert `eunox-mcp` between Claude and the filesystem server. Claude talks to the proxy; the proxy evaluates policy and, if approved, forwards the call to the real server. Claude doesn't know the difference — it still sees all the same tools. The only change from Claude's perspective is that some calls might come back denied.

---

## Step 2: Write your policy file

Create a file at `~/.euno/euno.policy.yaml`. (Or anywhere really — I'll reference this path in the config.) This is the file that defines what Claude is allowed to do.

Here's a sensible starting policy for a filesystem server:

```yaml
# ~/.euno/euno.policy.yaml

agentId: "claude-desktop"
name: "Claude Desktop (local)"
version: "1.0.0"

requiredCapabilities:
  - resource: "read_file"
    actions: [call]
    conditions:
      - type: allowedExtensions
        extensions:
          [".md", ".txt", ".json", ".yaml", ".yml", ".py", ".ts", ".js", ".go"]
      - type: maxCalls
        count: 200
        windowSeconds: 3600

  - resource: "write_file"
    actions: [call]
    conditions:
      - type: allowedExtensions
        extensions: [".md", ".txt", ".json"]
      - type: maxCalls
        count: 20
        windowSeconds: 3600

metadata:
  description: "Local Claude Desktop session with policy enforcement"
  owner: "you@local"
```

Let me walk through the decisions in here.

**`allowedExtensions` on reads.** I'm allowing Claude to read source files, documents, and config files, but not, say, `.pem` files, `.env` files, or `.key` files. This is a first line of defence against a scenario where a prompt injection in a document I open tries to redirect Claude to read my SSH keys or API credentials. It won't catch everything, but it immediately shrinks the blast radius.

**Separate `write` capability with narrower scope.** Reads and writes are separate capabilities with separate rate limits. Claude can read 200 files per hour; it can only write 20 per hour. This is deliberate — an automated loop that starts writing files will hit the wall quickly. Read access is broader than write access. These should almost never be the same.

**`maxCalls` conditions.** We covered this in [the failure modes post](./03-agent-governance-failure-modes.md) — the accounts reconciliation agent that sent 847 emails. The same failure mode applies to file writes. If Claude misunderstands a task and starts writing dozens of files in a loop, you want it to stop at 20, not continue indefinitely.

If you're using multiple MCP servers, you add more capabilities here. For a Postgres server, it might look like:

```yaml
- resource: "execute_sql"
  actions: [call]
  conditions:
    - type: allowedOperations
      operations: ["SELECT"]
    - type: maxCalls
      count: 50
      windowSeconds: 3600
```

That `allowedOperations: ["SELECT"]` is the condition that blocks the `DROP TABLE` attack from [the prompt injection post](./01-prompt-injection-policy-layer.md). It checks the first keyword of any SQL query and rejects anything that isn't `SELECT`. One condition, one line in YAML, enormous blast radius reduction.

---

## Step 3: Update your Claude Desktop config

Now we wire up the proxy. Here's the updated config:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "eunox-mcp",
      "args": [
        "proxy",
        "--policy",
        "/Users/you/.euno/euno.policy.yaml",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/Users/you/Documents"
      ]
    }
  }
}
```

The key change: instead of calling the filesystem server directly, we're calling `eunox-mcp proxy` with the path to our policy file, and then passing the original server command as arguments after the `--` separator.

The proxy will:

1. Start the filesystem server as a subprocess
2. Register itself as an MCP server to Claude (advertising the same tools the filesystem server exposes)
3. Intercept every tool call from Claude
4. Evaluate the call against the policy YAML
5. If allowed, forward it to the filesystem server and return the result
6. If denied, return an error explaining what was blocked and why

If you have multiple MCP servers, you wrap each one the same way — separate config entries, each wrapped with its own policy reference:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "eunox-mcp",
      "args": [
        "proxy",
        "--policy",
        "/Users/you/.euno/euno.policy.yaml",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/Users/you/Documents"
      ]
    },
    "database": {
      "command": "eunox-mcp",
      "args": [
        "proxy",
        "--policy",
        "/Users/you/.euno/euno.policy.yaml",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-postgres",
        "postgresql://localhost:5432/analytics"
      ]
    }
  }
}
```

Both server entries reference the same policy file. The policy file covers capabilities for both.

---

## Step 4: Restart Claude Desktop and verify

Close and reopen Claude Desktop. The proxy starts automatically when Claude initialises its MCP connections.

To verify it's working, try a tool call that should work: ask Claude to read a `.md` file in your Documents folder. It should work normally.

Now try one that should be blocked: if you have access to your database, ask Claude to run a `DELETE FROM` query on a table. You should get back an error — something like `operation DELETE is not permitted by policy`. That's the proxy in action.

Check your local audit log:

```bash
tail -20 ~/.euno/audit.jsonl | jq .
```

You'll see JSONL records — one per tool call. Both allowed and denied calls are there. Each record has the tool name and resource, the decision, the denial code/condition type when denied, and the timestamp. This is the record that tells you what Claude has been doing and whether any of it looked unusual.

The format is OCSF (Open Cybersecurity Schema Framework) API Activity events — structured enough that if you wanted to, you could feed these into Splunk, Datadog, or any other SIEM without writing a custom parser.

---

## Step 5: Iterate on your policy

The policy you wrote in step 2 is a starting point, not a finished product. The right workflow is: run Claude Desktop with the proxy for a few days, review the audit log, and tighten the policy where you see capabilities being used that you didn't expect.

A few things I've found useful during this iteration phase:

**Watch for denied calls that should have been allowed.** If Claude is getting blocked on something legitimate, either your policy is too narrow or you haven't modelled a capability the agent genuinely needs. Add it explicitly rather than widening the policy.

**Watch for call patterns that look unusual.** A session that has 80 file reads in it might be fine — Claude is doing a comprehensive analysis. Or it might be a loop. The timestamp spread between calls tells you which: tight cluster in 30 seconds is probably not what you intended.

**Don't expand `allowedExtensions` lazily.** The temptation when a read gets blocked is to add the extension to the allowed list. Sometimes that's right. But sometimes the right question is "why is Claude trying to read that kind of file in the first place?" A `.env` file being requested is worth investigating before you just permit it.

**Add an `allowedOperations` condition to any SQL tool.** I can't stress this enough. If you have a Postgres or SQLite MCP server, a single condition — `type: allowedOperations, operations: [SELECT]` — is the most impactful security improvement you can make. It blocks every destructive SQL operation regardless of how the instruction to run it was produced.

---

## What this doesn't cover

I want to be straight about the limits of the local mode setup.

**Rate limits are per-process.** The `maxCalls` counters in local mode are in-memory in the proxy process. If you restart Claude Desktop, the counters reset. This is fine for a single-user local setup. For a shared or multi-user deployment, you need shared Redis-backed counters — which is what the hosted gateway provides. [The migration post](./08-local-yaml-to-hosted-gateway.md) covers that transition when you get there.

**The audit log is local and mutable.** `~/.euno/audit.jsonl` is HMAC-chained, so tampering is detectable, but it's a file on your local machine. If someone has access to your machine, they have access to the audit log. For compliance use cases — SOC 2, regulatory requirements — you want a durable, centralised audit store, which again requires the hosted gateway.

**Token signing is not in play in local mode.** The full euno security model involves signed JWT capability tokens issued by a capability issuer, which is a separate service. Local mode uses a simplified path: the policy YAML is evaluated directly without a cryptographically signed token. This is fine for individual developer use. It's not the full security model. When you migrate to the hosted gateway, you get the full cryptographic enforcement chain.

**It won't catch everything.** A prompt injection that convinces Claude to call a permitted tool with permitted arguments will get through. If your policy allows `SELECT` queries on the `orders` table and an injection produces a `SELECT * FROM orders WHERE 1=1`, that passes. The policy constrains the blast radius; it doesn't eliminate it. Defence in depth — narrow schemas, careful data classification, prompt hardening — still matters.

---

## The bigger picture

What you've done here is meaningful, even in its simple form. You've established a policy-as-code document that describes exactly what Claude is permitted to do with your tools. It's version-controllable, diffable, reviewable. You can commit it to a repo and have a record of how it's changed over time. If something odd happens, you have an audit log of every call that was made and every call that was blocked.

For most individual developers, this is enough — or at least enough to start. As your agent usage grows more sophisticated, or you move from personal tools to shared infrastructure, or you have compliance requirements, the path to the hosted gateway is a single config change: swap `--policy` for `--enforcer-url` and `--enforcer-api-key`. The policy YAML is identical; nothing needs to be rewritten.

The principle of "start with the policy in a YAML file, enforce at the tool call, make it fail closed" scales from a single developer's local setup to a multi-tenant enterprise deployment. The platform evolves. The principle doesn't.

---

_Previous in this series: [Building a policy proxy for MCP: design choices and trade-offs](./06-mcp-policy-proxy.md)_

_Next: [From local YAML to hosted policy store: eunox's migration story](./08-local-yaml-to-hosted-gateway.md)_
