# euno Documentation Index

Design and operational documentation for euno. Docs are organized by purpose.

---

## 1. Start here

| Doc | What it is |
| --- | ---------- |
| [../README.md](../README.md) | Project README — value prop, quick start, links. |
| [repo-guide.md](./repo-guide.md) | Repository structure, build / lint / test, contributor setup. |
| [agent-sdk.md](./agent-sdk.md) | Agent SDK quickstart and condition reference. |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | Current package map and architecture overview. |

## 2. Architecture

| Doc | What it is |
| --- | ---------- |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | C4 views, sequence diagrams, deployment view. |
| [capability-model.md](./capability-model.md) | Security model, capability design. |
| [enforcement.md](./enforcement.md) | Policy decision point, enforcement guarantees. |
| [diagrams.md](./diagrams.md) | Mermaid architecture diagrams. |
| [architecture-follow-up-tasks-2026-05.md](./architecture-follow-up-tasks-2026-05.md) | Numbered architecture review follow-up task list. |
| [mvp.md](./mvp.md) | Implementation history, gate criteria, business model. |

## 3. Design references

| Doc | What it is |
| --- | ---------- |
| [ADAPTERS.md](./ADAPTERS.md) | Pluggable identity / signing adapter pattern. |
| [CAPABILITY_MANIFEST_GUIDE.md](./CAPABILITY_MANIFEST_GUIDE.md) | Manifest authoring: structure, conditions, anti-patterns. |
| [SCHEMA_VERSIONING.md](./SCHEMA_VERSIONING.md) | Schema versioning, deployment ordering. |
| [DISTRIBUTED_STATE.md](./DISTRIBUTED_STATE.md) | Redis-backed shared state for multi-agent deployments. |
| [sandboxing.md](./sandboxing.md) | Sandbox reference architecture. |
| [stage-3-design.md](./stage-3-design.md) | Hosted gateway design: KMS, Postgres, Redis, API-key scheme, enforcer wire protocol. |

## 4. Deployment and operations

| Doc | What it is |
| --- | ---------- |
| [DEPLOYMENT.md](./DEPLOYMENT.md) | Current deployment notes and platform service paths. |
| [self-host.md](./self-host.md) | BYO-GW guide: running the full gateway stack on your own infrastructure. |
| [upgrade-to-hosted.md](./upgrade-to-hosted.md) | Interactive CLI command (`euno-mcp upgrade-to-hosted`) reference: flags, examples, dry-run, rollback. |
| [migrating-from-local.md](./migrating-from-local.md) | Upgrading from `@euno/mcp` local mode to the hosted gateway: before/after, cryptographic story, data-boundary analysis. |

## 5. Repository conventions

| Doc | What it is |
| --- | ---------- |
| [repo-split.md](./repo-split.md) | Two-folder structure, license boundary rules. |
| [stage-0-freeze.md](./stage-0-freeze.md) | Platform package freeze policy. |
| [mcp-support.md](./mcp-support.md) | MCP SDK pin, protocol support window. |

## 6. Launch resources

| Doc | What it is |
| --- | ---------- |
| [promotion.md](./promotion.md) | Launch copy and messaging for @euno/mcp. |
| [promotion.md](./promotion.md) | Launch copy and messaging. |
| [blog-articles.md](./blog-articles.md) | Suggested blog article list: background, architecture, UX, technology, design principles. |

## 7. Roadmap and planning

| Doc | What it is |
| --- | ---------- |
| [mvp.md](./mvp.md) | Implementation history, gate criteria, business model. |
| [multi-cloud-plan.md](./multi-cloud-plan.md) | Plan for deepening AWS and GCP ecosystem support alongside Azure. |

---

## Maintenance

Update the matching doc in the same PR when behaviour changes.
Update OpenAPI specs under [openapi/](./openapi/) for endpoint changes.
