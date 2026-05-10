<p align="center">
  <img src="https://github.com/user-attachments/assets/c1bf707c-85dd-4f5d-aeff-a77188af871e" alt="euno" height="96">
</p>

<h1 align="center">euno</h1>

<p align="center">
  <strong>Policy proxy for AI agents.</strong><br>
  One YAML file enforces what every agent is allowed to do —
  <em>before</em> the tool call reaches your backend.
</p>

<p align="center">
  <a href="https://github.com/edgeobs/euno/blob/main/LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg"></a>
  <a href="https://nodejs.org/"><img alt="Node 18+" src="https://img.shields.io/badge/node-%E2%89%A518-339933"></a>
  <a href="https://spec.modelcontextprotocol.io/"><img alt="MCP" src="https://img.shields.io/badge/MCP-supported-7c3aed"></a>
  <a href="https://github.com/edgeobs/euno/stargazers"><img alt="GitHub stars" src="https://img.shields.io/github/stars/edgeobs/euno?style=social"></a>
</p>

<p align="center">
  <a href="./web/index.html"><strong>Website</strong></a> •
  <a href="./web/quickstart.html"><strong>Quick start</strong></a> •
  <a href="./web/features.html"><strong>Features</strong></a> •
  <a href="./web/how-it-works.html"><strong>How it works</strong></a> •
  <a href="./public/packages/mcp/README.md"><strong>@euno/mcp docs</strong></a>
</p>

---

## What is euno?

euno is an **open-source policy proxy** for AI agents that speak the
[Model Context Protocol](https://spec.modelcontextprotocol.io/). It sits
between your MCP host (Claude Desktop, Cursor, Windsurf, LangChain.js, …)
and your upstream MCP server, and enforces a declarative capability policy
on every `tools/call` — **before** the upstream is ever contacted.

```
Agent  →  tools/call: query_db { sql: "DROP TABLE users" }
                                    ↓
                       @euno/mcp: policy says SELECT only
                       upstream never called
                                    ↓
Agent  ←  CapabilityDenied: operation DROP not in [SELECT]
```

One YAML file. No code changes to your agent or your server. No cloud
account. No telemetry. Apache-2.0.

## Quick start

Run the proxy in front of any MCP server:

```bash
npx -y @euno/mcp proxy \
  --policy ./euno.policy.yaml \
  -- npx -y @modelcontextprotocol/server-filesystem /data
```

A minimal `euno.policy.yaml`:

```yaml
agentId: filesystem-agent
name:    Filesystem Agent
version: 1.0.0

requiredCapabilities:
  - resource: read_file
    actions: [call]
    conditions:
      - type: allowedExtensions
        extensions: [".csv", ".json", ".txt", ".md"]
      - type: maxCalls
        count: 50
        windowSeconds: 60
```

That's it. Read the [full quick start](./web/quickstart.html) for the
Claude Desktop / Cursor / Windsurf / LangChain.js / HTTP-transport setups.

## What you get

- 🛡️  **Full condition matrix.** `maxCalls`, `allowedOperations`,
  `allowedExtensions`, `allowedTables`, `argumentSchema`,
  `timeWindow`, `ipRange`, `recipientDomain`, `redactFields`, `policy`,
  and `custom` — all enforced before the upstream is contacted.
- 📋 **OCSF audit log.** Every decision is recorded as a
  cryptographically signed OCSF API Activity event in
  `~/.euno/audit.jsonl`. Aggregate denials with `euno-mcp stats`.
- 🔌 **Drop-in for every host.** stdio for Claude Desktop / Cursor /
  Windsurf, HTTP for LangChain.js and other in-process clients.
- 🪢 **`@euno/langchain` companion.** The same engine inside the
  LangChain.js tool wrapper — no proxy process, same YAML.
- 📦 **Reference policies.** Drop-in YAML for filesystem, Postgres,
  GitHub, Slack, and fetch (with a lexical SSRF guard).
- 🧩 **Custom backends.** Plug in OPA, Cedar, or your own engine via
  `--policy-backend`. Domain-specific guards via `--custom-condition`.
- 🔒 **Zero infra. Zero cloud.** Runs entirely on your machine.

See [the website](./web/features.html) for worked demos of every
condition type.

## Project status

euno follows a [staged execution plan](./docs/mvp.md):

| Stage | Ships | Status |
|-------|-------|--------|
| 0 | Common types, CLI, license boundary, repo structure | ✅ Done |
| 1 | `@euno/mcp` 0.1.x — local MCP proxy, policy engine, OCSF audit | ✅ Done |
| 2 | `@euno/mcp` 0.2.0 — full condition matrix, `@euno/langchain`, reference policies | ✅ **Current MVP** |
| 3 | Hosted Tool Gateway, API-key façade, signed JWT capability tokens | ⏳ Gate: see [docs/mvp.md §Gate to Stage 3](./docs/mvp.md#gate-to-stage-3--measurable) |
| 4 | Capability Issuer + IdP integration (Entra ID, Cognito, Cloud Identity) | Planned |
| 5 | Enterprise: DID federation, KMS, SOC 2, multi-cloud | Planned |

The platform packages (`tool-gateway`, `capability-issuer`, `agent-runtime`,
`framework-adapters`) are **feature-frozen** during Stages 0–2 — accepting
only security fixes and dependency bumps.

## Packages

| Package | Path | What it does |
|---------|------|--------------|
| [`@euno/mcp`](./public/packages/mcp/README.md) | `public/packages/mcp/` | MCP policy proxy (stdio + HTTP) — the wedge product. |
| [`@euno/langchain`](./public/packages/langchain/README.md) | `public/packages/langchain/` | In-process LangChain.js companion, same YAML. |
| [`@euno/cli`](./public/packages/cli/README.md) | `public/packages/cli/` | Developer CLI (`euno` binary). |
| [`@euno/common-core`](./public/packages/common/) | `public/packages/common/` | Shared types, validators, in-memory implementations. |

`public/` ships under **Apache-2.0**. The `euno-platform/` packages
(self-host and hosted product) ship under **BUSL-1.1**. The
`lint:license-boundary` CI step enforces that Apache packages depend only
on Apache packages — see [`docs/repo-split.md`](./docs/repo-split.md).

## Documentation

- 🌐 **Website:** [`web/`](./web/) — landing page, quick start,
  features, how-it-works, reference policies.
- 📦 **Package docs:** [`@euno/mcp`](./public/packages/mcp/README.md) ·
  [`@euno/langchain`](./public/packages/langchain/README.md).
- 🏗  **Architecture:** [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) ·
  [`docs/capability-model.md`](./docs/capability-model.md) ·
  [`docs/enforcement.md`](./docs/enforcement.md).
- 🗺️ **Roadmap:** [`docs/mvp.md`](./docs/mvp.md).
- 🔧 **Repository guide (build, lint, test, structure):**
  [`docs/repo-guide.md`](./docs/repo-guide.md).
- 📚 **Full doc index:** [`docs/README.md`](./docs/README.md).

## Contributing

Issues and pull requests are welcome on
[github.com/edgeobs/euno](https://github.com/edgeobs/euno). See
[`docs/repo-guide.md`](./docs/repo-guide.md) for build, lint, and test
instructions, and [`CODEOWNERS`](./CODEOWNERS) for area ownership.

## License

- `public/` (public surface): **Apache-2.0**
- `euno-platform/` (platform surface): **BUSL-1.1**

See [`LICENSE`](./LICENSE) and [`docs/repo-split.md`](./docs/repo-split.md)
for the full boundary.

## References

- [Model Context Protocol specification](https://spec.modelcontextprotocol.io/)
- [OCSF — Open Cybersecurity Schema Framework](https://schema.ocsf.io/)
- [Building an Auditable Security Layer for Agentic AI](https://azurefeeds.com/2026/04/22/building-an-auditable-security-layer-for-agentic-ai/)
- [Zero-Trust Agents: Adding Identity and Access to Multi-Agent Workflows](https://techcommunity.microsoft.com/blog/azure-ai-foundry-blog/zero-trust-agents-adding-identity-and-access-to-multi-agent-workflows/4427790)
