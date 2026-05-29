<p align="center">
  <img src="https://github.com/eunolabs/eunox/blob/main/site/public/eunolabs.png?raw=true" alt="eunox" height="160">
</p>

<h1 align="center">eunox-mcp</h1>

<p align="center">
  <strong>Policy-enforcement proxy for MCP servers</strong><br>
  Sits between your MCP host and any MCP server subprocess. Every <code>tools/call</code> is checked against a YAML policy before it is forwarded — and every decision is written to a tamper-evident audit log.
</p>

<p align="center">
  <a href="https://github.com/eunolabs/eunox/blob/main/cmd/mcp/LICENSE"><img alt="eunox-mcp: Apache-2.0" src="https://img.shields.io/badge/eunox--mcp-Apache--2.0-green.svg"></a>
  <a href="https://go.dev/"><img alt="Go 1.25+" src="https://img.shields.io/badge/go-%E2%89%A51.25-00ADD8"></a>
  <a href="https://spec.modelcontextprotocol.io/"><img alt="MCP" src="https://img.shields.io/badge/MCP-supported-7c3aed"></a>
</p>

---

## Install

```bash
go install github.com/eunolabs/eunox/cmd/mcp@latest
```

Or pull the Docker image:

```bash
docker pull ghcr.io/eunolabs/eunox-mcp:latest
```

## One-minute example

**`policy.yaml`** — define which tools the model may call:

```yaml
version: "1"
tools:
  - name: read_file
    allow: true
  - name: write_file
    allow: true
    conditions:
      - path_prefix: /data/
  - name: execute_command
    allow: false        # deny — model cannot run arbitrary shell commands
```

**Run it** — wrap your existing MCP server subprocess:

```bash
eunox-mcp proxy --policy policy.yaml -- npx -y @modelcontextprotocol/server-filesystem /data
```

That's it. `eunox-mcp` starts the subprocess, negotiates the MCP handshake, and filters every tool call through the policy. Denied calls return a structured error to the model; allowed calls are forwarded transparently. All decisions are appended to `~/.eunox/audit.jsonl` (HMAC-SHA256 signed, OCSF format).

## How it works

- **Intercepts** every `tools/call` JSON-RPC request over `stdio` (default) or HTTP.
- **Evaluates** the call against your capability manifest — tool name, argument constraints, rate limits, session scope.
- **Forwards** allowed calls to the upstream MCP server and streams the response back.
- **Blocks** denied calls and returns a structured error without touching the upstream.
- **Audits** every decision to `~/.eunox/audit.jsonl` with a cryptographic HMAC chain.

## Commands

| Command | Description |
|---|---|
| `eunox-mcp proxy --policy <file> -- <cmd> [args...]` | Start the proxy wrapping a subprocess |
| `eunox-mcp validate --policy <file>` | Validate a capability manifest without running |
| `eunox-mcp kill --session <id>` | Immediately revoke an active session |
| `eunox-mcp stats` | Print per-tool call counts from the audit log |
| `eunox-mcp validate-token --token <jwt>` | Inspect and verify a capability token |

## Claude Desktop integration

Add this to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "eunox-mcp",
      "args": [
        "proxy",
        "--policy", "/path/to/policy.yaml",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"
      ]
    }
  }
}
```

## Documentation

- 📋 **Capability manifest guide** — [`docs/capability-manifest-guide.md`](./docs/capability-manifest-guide.md)
- 🔍 **Audit log & compliance** — [`docs/audit-retention-compliance.md`](./docs/audit-retention-compliance.md)
- 🏗 **Full platform architecture** — [`docs/architecture.md`](./docs/architecture.md)
- 🚀 **Deployment (gateway, Helm, EKS, GKE)** — [`docs/deployment.md`](./docs/deployment.md)
- ⚖️ **Licensing FAQ** — [`docs/licensing-faq.md`](./docs/licensing-faq.md)

## License

**`cmd/mcp/`** (`eunox-mcp` binary) — **Apache License 2.0** — free to use, embed,
redistribute, and build on. See [`cmd/mcp/LICENSE`](./cmd/mcp/LICENSE).

**The rest of the eunox platform** (gateway, issuer, minter, enforcement packages) —
**Business Source License 1.1**. See [`docs/licensing-faq.md`](./docs/licensing-faq.md)
for a plain-English breakdown of what you can and cannot do.
