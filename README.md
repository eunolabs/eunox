<p align="center">
  <img src="https://github.com/eunolabs/eunox/blob/main/img/eunolabs.png?raw=true" alt="eunox" height="160">
</p>

<h1 align="center">eunox-mcp</h1>

<p align="center">
  <strong>Policy-enforcement proxy for MCP servers</strong><br>
  Sits between your MCP host and any MCP server — local subprocess or remote HTTPS. Every <code>tools/call</code> is checked against a YAML capability manifest before it is forwarded, and every decision is written to a tamper-evident OCSF audit log.
</p>

<p align="center">
  <a href="https://github.com/eunolabs/eunox/blob/main/cmd/mcp/LICENSE"><img alt="eunox-mcp: Apache-2.0" src="https://img.shields.io/badge/eunox--mcp-Apache--2.0-green.svg"></a>
  <a href="https://go.dev/"><img alt="Go 1.25+" src="https://img.shields.io/badge/go-%E2%89%A51.25-00ADD8"></a>
  <a href="https://spec.modelcontextprotocol.io/"><img alt="MCP" src="https://img.shields.io/badge/MCP-supported-7c3aed"></a>
</p>

---

## Quick start

Prerequisites: Docker 24+, docker compose 2.20+, `curl`, `jq`.

```bash
git clone https://github.com/eunolabs/eunox.git
cd eunox
make -C demo up        # start mock MCP server + eunox-mcp proxy (~10 s)
make -C demo allow     # allowed: read_file /reports/q3.pdf
make -C demo deny      # denied:  write_file (not in manifest)
make -C demo audit     # live tamper-evident audit log
```

The full walkthrough — including JWT/IdP-issued capability claims — is in [`demo/README.md`](./demo/README.md).

---

## Install

```bash
go install github.com/eunolabs/eunox/cmd/mcp@latest
```

Or pull the Docker image:

```bash
docker pull ghcr.io/eunolabs/eunox-mcp:latest
```

---

## How it works

```
MCP host (Claude Desktop, LangChain, CrewAI, ...)
        │
        │  JSON-RPC  tools/call
        ▼
┌─────────────────────────────────────┐
│          eunox-mcp proxy            │
│                                     │
│  1. Parse tool name + arguments     │
│  2. Evaluate capability manifest    │
│     · AllowedValues, MaxCalls,      │
│       AllowedOperations, TimeWindow │
│     · Session-aware rate limits     │
│     · IdP JWT claims (optional)     │
│  3. Write OCSF audit record         │
│     (HMAC-SHA256 signed)            │
└──────────┬──────────────────────────┘
           │
   ALLOW ──┼──► upstream MCP server
           │       local subprocess  or  remote HTTPS endpoint
   DENY ───┼──► structured JSON-RPC error returned to host
           │    (upstream is never called)
```

**Two upstream modes — no code changes needed to switch:**

```bash
# Local subprocess (stdio or HTTP transport)
eunox-mcp proxy --policy manifest.yaml -- node ./server.js

# Remote MCP server (HTTP transport, no subprocess)
eunox-mcp proxy \
  --transport http \
  --upstream-url https://mcp.stripe.com \
  --upstream-auth-header "Authorization: Bearer sk-..." \
  --policy manifest.yaml
```

---

## Capability manifest

The manifest is a YAML file that declares exactly what the agent may call, and under what conditions. Unlisted tools are denied by default.

```yaml
name: my-agent
version: "1.0"

capabilities:
  - resource: read_file
    actions: [call]
    conditions:
      - type: allowedValues
        field: path
        values: ["/reports/*"] # deny read_file outside /reports/

  - resource: query_db
    actions: [call]
    conditions:
      - type: maxCalls
        limit: 5 # at most 5 calls per session
      - type: allowedOperations
        operations: [SELECT] # no INSERT / UPDATE / DELETE


  # write_file intentionally absent → denied by default
```

Validate without running:

```bash
eunox-mcp validate manifest.yaml
```

See [`docs/capability-manifest-guide.md`](./docs/capability-manifest-guide.md) for the full condition reference (11 built-in condition types).

---

## Why not OPA or Envoy?

OPA and Envoy enforce access control at the HTTP layer — they see the HTTP request but have no concept of the session, what the agent has already done this session, or what individual tool arguments mean. Three failure modes they cannot address:

| Scenario                                                                                                                                                                   | OPA / Envoy                           | eunox-mcp                                                                    |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------- | ---------------------------------------------------------------------------- |
| **Sequential credential exfiltration** — agent calls `read_credentials` then `write_to_external`. Each call is individually permitted; together they exfiltrate secrets.   | Both calls pass — no session context  | Second call blocked by session-aware policy                                  |
| **Parameter-dependent authorization at scale** — `read_file` allowed for `/reports/*`, blocked for `/internal/*`. Must be expressed per-parameter across every tool shape. | Complex Rego; rules multiply per tool | `allowedValues` condition: 3 lines per tool, all enforced by the same engine |
| **Task-lifecycle credential scope** — AWS STS minimum session is 15 minutes. A credential-reading tool should be callable once per task, not for the full token lifetime.  | Time-based expiry only (15 min floor) | `maxCalls: 1` blocks after the first use, regardless of token TTL            |

Runnable demos for all three scenarios: [`demo/opa-comparison/`](./demo/opa-comparison/).

---

## Commands

| Command                                                                 | Description                                                  |
| ----------------------------------------------------------------------- | ------------------------------------------------------------ |
| `eunox-mcp proxy --policy <file> -- <cmd> [args...]`                    | Start the proxy wrapping a local subprocess (stdio)          |
| `eunox-mcp proxy --transport http --upstream-url <url> --policy <file>` | Start the proxy forwarding to a remote MCP server            |
| `eunox-mcp validate <manifest.yaml>`                                    | Validate a capability manifest without running               |
| `eunox-mcp kill --session <id>`                                         | Immediately revoke an active session                         |
| `eunox-mcp stats`                                                       | Print per-tool call counts from the audit log                |
| `eunox-mcp validate-token`                                              | Verify HMAC-SHA256 signatures in the audit log               |
| `eunox-mcp profiles`                                                    | List built-in server profiles (GitHub, Slack, filesystem, …) |

---

## Claude Desktop integration

Add this to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "eunox-mcp",
      "args": [
        "proxy",
        "--policy",
        "/path/to/manifest.yaml",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/data"
      ]
    }
  }
}
```

---

## Advanced: JWT / IdP-issued capability claims

When `--jwks-uri` is set, every incoming request must carry a Bearer JWT issued by your IdP. The proxy validates the signature, expiry, issuer, and audience; extracts `eunox.capabilities` claims; and intersects them with the manifest (JWT can only restrict — never expand beyond what the manifest permits).

```bash
eunox-mcp proxy \
  --transport http \
  --jwks-uri https://idp.example.com/.well-known/jwks.json \
  --jwt-issuer https://idp.example.com \
  --jwt-audience eunox \
  --policy manifest.yaml \
  --upstream-url https://mcp.example.com
```

See the JWT mode walkthrough in [`demo/README.md`](./demo/README.md#step-3--jwt-mode-manifest--idp-claims).

---

## Documentation

- 🚀 **Demo — first enforcement in 10 minutes** — [`demo/README.md`](./demo/README.md)
- 📋 **Capability manifest guide** — [`docs/capability-manifest-guide.md`](./docs/capability-manifest-guide.md)
- 🛡 **Threat model** — [`docs/threat-model-mcp.md`](./docs/threat-model-mcp.md)
- ⚡ **Benchmarks** — [`docs/benchmarks.md`](./docs/benchmarks.md)

---

## License

**Apache License 2.0** — free to use, embed, redistribute, and build on.
