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
version: 0.1.0

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

### Hosted gateway (Stage 3)

When your team outgrows a single process, one config change routes
enforcement through the hosted Euno gateway — shared call counters, a
global kill switch, and a persistent queryable audit ledger, all backed
by KMS-signed JWT tokens and a Postgres ledger:

```diff
- euno-mcp proxy --policy ./euno.policy.yaml -- node ./my-mcp-server.js
+ euno-mcp proxy --enforcer-url https://gateway.euno.example \
+                --enforcer-api-key sk-... \
+                -- node ./my-mcp-server.js
```

The policy file format is unchanged — the same YAML you wrote for local
mode uploads verbatim to the hosted policy store.
See [`docs/migrating-from-local.md`](./docs/migrating-from-local.md) for the
step-by-step guide, the cryptographic story behind the `sk-...` key, and the
explicit data-boundary analysis (what leaves your network in hosted mode).

### Hosted issuer (Stage 4)

Stage 4 adds the **Capability Issuer** — a token-issuance service that ties
agent capabilities to real user identities through your existing identity
provider (Entra ID, AWS Cognito, or GCP Cloud Identity). Instead of a shared
API key, each agent token is bound to the user who requested it:

```bash
# Request a capability token via your IdP (PKCE flow)
euno request \
  --agent my-agent \
  --idp-auth-url  https://login.microsoftonline.com/<tenant>/oauth2/v2.0/authorize \
  --idp-token-url https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token \
  --idp-client-id <client-id>

# Validate the issued token
euno validate-token --agent-id my-agent
```

The resulting token carries the user's IdP identity (`authorizedBy.userId`),
a role-to-capability mapping from the admin role-policy store, and optional
capability manifest templates that a tech lead authors once and assigns to
many agents.

See [`docs/quickstart-stage-4.md`](./docs/quickstart-stage-4.md) for the
full flow, [`docs/issuer-idp-setup.md`](./docs/issuer-idp-setup.md) for IdP
configuration, and [`docs/self-host.md §11`](./docs/self-host.md) for
self-hosting the issuer alongside the gateway.

### Enterprise deployment (Stage 5)

Stage 5 adds the full enterprise compliance and federation tier. All four
quarantined packages are now GA:

```bash
# Verify a partner-issued capability token (EdDSA, did:web or did:ion)
euno validate-token eyJ... \
  --iss did:web:partner.example.com \
  --jwks-url https://partner.example.com/.well-known/jwks.json

# Export a SOC 2 audit bundle (CC7 controls, signed OCSF evidence)
euno audit export \
  --gateway-url https://gateway.euno.example \
  --admin-key $EUNO_ADMIN_API_KEY \
  --scope soc2-cc7 \
  --out ./audit-bundle.jsonl

# Check Stage-5 service discovery document
euno discover --issuer-url https://issuer.euno.example
```

Key capabilities added in Stage 5:

- 🏛️  **Partner DID federation.** Cross-org trust via W3C DIDs (`did:web`,
  `did:ion`) with per-DID circuit breakers, two-eyes approval workflow, and
  pin attestation.  See [`docs/ADAPTERS.md §Partner Federation`](./docs/ADAPTERS.md).
- ⛓️  **Cross-chain audit anchor.** `CrossChainAnchor` commits an HMAC root
  hash of every N audit records to S3 Object-Lock, giving you a tamper-evident
  ledger even across Postgres replicas.
- 📋 **SOC 2 audit export.** `GET /api/v1/audit/export` returns a
  cursor-paginated, cryptographically signed OCSF evidence bundle filterable
  by SOC 2 CC6/CC7 controls.
- 🛡️  **AGT in-process guard.** `createAgtGuard()` adds a defense-in-depth
  layer inside the agent process — policy is checked *before* the gateway
  is ever called.
- 👤 **SCIM 2.0 provisioning.** Automatic role-to-capability mapping from
  your enterprise IdP directory via the SCIM 2.0 protocol.
- 🔍 **Discovery endpoint v1.0.0.** `/.well-known/capability-issuer` now
  returns Stage-5 fields (`partnerFederation`, `scim`, `auditExport`,
  `capabilities`) with ETag caching.
- 📦 **On-prem Helm bundle.** A single umbrella chart deploys all six
  services; `k8s/air-gap-images.txt` + `scripts/pull-air-gap-images.sh`
  support fully air-gapped installations.

See [`docs/self-host.md §12`](./docs/self-host.md) for the complete
self-hosting runbook and [`docs/security/soc2-mapping.md`](./docs/security/soc2-mapping.md)
for the SOC 2 control mapping.

See [the website](./web/features.html) for worked demos of every
condition type.

## Project status

euno follows a [staged execution plan](./docs/mvp.md):

| Stage | Ships | Status |
|-------|-------|--------|
| 0 | Common types, CLI, license boundary, repo structure | ✅ Done |
| 1 | `@euno/mcp` 0.1.x — local MCP proxy, policy engine, OCSF audit | ✅ Done |
| 2 | `@euno/mcp` 0.1.0 — full condition matrix, `@euno/langchain`, reference policies | ✅ Done |
| 3 | Hosted Tool Gateway, API-key façade, signed JWT capability tokens | ✅ Done |
| 4 | Capability Issuer + IdP integration (Entra ID, Cognito, Cloud Identity) | ✅ Done |
| 5 | Enterprise: DID federation, KMS, SOC 2, multi-cloud | ✅ **Done** — see [docs/mvp.md §Stage 5](./docs/mvp.md#stage-5-enterprise--full-vision) |

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
- 🔀 **Hosted mode:** [`docs/migrating-from-local.md`](./docs/migrating-from-local.md) ·
  [`docs/self-host.md`](./docs/self-host.md).
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
