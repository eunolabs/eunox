# Euno

A capability-based agent governance system. Stop your AI agents from doing
things they shouldn't — before the tool call reaches your backend.

## Stage 1: `@euno/mcp` is available now

The entry point for individual developers is [`@euno/mcp`](euno-mcp/packages/euno-mcp/README.md):
a drop-in policy proxy for any [Model Context Protocol](https://spec.modelcontextprotocol.io/)
server. No infrastructure required. For now, `@euno/*` packages publish to
GitHub Packages rather than the public npm registry; see the package README for
the scoped `.npmrc` setup.

```bash
npx -y @euno/mcp proxy \
  --policy ./euno.policy.yaml \
  -- npx -y @modelcontextprotocol/server-filesystem /data
```

The proxy sits between your MCP host and upstream server. When an agent sends
`tools/call: query_db { query: "DROP TABLE users" }`, the policy fires before
the upstream is called — if the constraint says `allowedOperations: [SELECT]`,
the upstream is never contacted and the agent receives a structured denial.
One YAML file. No code changes to your agent or server.

See the [**`@euno/mcp` README**](euno-mcp/packages/euno-mcp/README.md) for
quickstart, policy authoring, and drop-in Claude Desktop / Cursor / LangChain.js usage.

## Project status

Euno follows a [staged execution plan](docs/mvp.md). **Stage 1 has shipped.**

| Stage | Ships | Status |
|-------|-------|--------|
| 0 | Common types, CLI, license boundary, repo structure | ✅ Done |
| 1 | `@euno/mcp` — local MCP proxy, policy engine, OCSF audit log | ✅ Done |
| 2 | Cross-process shared state (Redis counters, shared enforcement state) | ⏳ Gate: see [docs/mvp.md §Gate to Stage 2](docs/mvp.md) |
| 3 | Hosted gateway service, signed JWT capability tokens | Planned |
| 4–5 | Enterprise: DID federation, KMS, SOC2, multi-cloud | Planned |

The platform packages (`tool-gateway`, `capability-issuer`, `agent-runtime`,
`framework-adapters`) are **feature-frozen** during Stages 0–2 — accepting
only security fixes and dependency bumps. See [`docs/stage-0-freeze.md`](docs/stage-0-freeze.md).

## Repository structure

```
edgeobs/euno
├── euno-mcp/packages/       Apache-2.0 — ships to GitHub Packages
│     common-core/           Core types, interfaces, in-memory implementations
│     cli/                   Developer CLI  (`euno` binary)
│     euno-mcp/              MCP proxy      (`euno-mcp` binary)  ← Stage 1 product
│
└── euno-platform/packages/  BUSL-1.1 — self-host and hosted product
      common-infra/          Redis / Postgres / KMS implementations
      common/                Compat shim (re-exports both surfaces)
      tool-gateway/          HTTP enforcement gateway  (frozen)
      capability-issuer/     JWT token issuer          (frozen)
      agent-runtime/         In-process guard          (frozen)
      framework-adapters/    LangChain / MAF / CrewAI  (frozen)
      ...
```

Apache-2.0 packages depend only on other Apache-2.0 packages.
The `lint:license-boundary` CI step enforces this mechanically.
See [`docs/repo-split.md`](docs/repo-split.md).

## Development

### Prerequisites

- Node.js >= 18.0.0
- npm >= 9.0.0

### Setup

```bash
npm install
npm run build
npm test
```

### Lint

```bash
npm run lint                    # license boundary + all package ESLint
npm run lint:license-boundary   # just the Apache/BUSL boundary check
```

### Test

```bash
npm test               # all workspaces
npm test -w @euno/mcp  # single workspace
```

## Documentation

| Doc | What it is |
|-----|-----------|
| [`docs/mvp.md`](docs/mvp.md) | Staged execution plan, gate criteria, business model |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | C4 views, sequence diagrams, cross-cutting concerns |
| [`docs/capability-model.md`](docs/capability-model.md) | Security model and capability design |
| [`docs/enforcement.md`](docs/enforcement.md) | Policy decision point design, enforcement guarantees |
| [`docs/CAPABILITY_MANIFEST_GUIDE.md`](docs/CAPABILITY_MANIFEST_GUIDE.md) | Policy authoring guide |
| [`docs/mcp-support.md`](docs/mcp-support.md) | MCP SDK pin, protocol support window |
| [`docs/repo-split.md`](docs/repo-split.md) | Two-folder structure, license boundary rules |
| [`docs/stage-0-freeze.md`](docs/stage-0-freeze.md) | Platform package freeze policy |

Full index at [`docs/README.md`](docs/README.md).

## Contributing

See [`docs/README.md`](docs/README.md) for conventions.
Code ownership is in [`CODEOWNERS`](CODEOWNERS).

## License

- `euno-mcp/` (public surface): **Apache-2.0**
- `euno-platform/` (platform surface): **BUSL-1.1**

See [`LICENSE`](LICENSE) and [`docs/repo-split.md`](docs/repo-split.md) for details.

## References

- [Building an Auditable Security Layer for Agentic AI](https://azurefeeds.com/2026/04/22/building-an-auditable-security-layer-for-agentic-ai/)
- [Zero-Trust Agents: Adding Identity and Access to Multi-Agent Workflows](https://techcommunity.microsoft.com/blog/azure-ai-foundry-blog/zero-trust-agents-adding-identity-and-access-to-multi-agent-workflows/4427790)
- [Model Context Protocol specification](https://spec.modelcontextprotocol.io/)
