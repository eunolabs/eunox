# Euno Documentation Index

Design and operational documentation for Euno. Docs are organized by purpose.

---

## 1. Start here

| Doc | What it is |
| --- | ---------- |
| [../README.md](../README.md) | Root README: project status, quickstart, development setup. |
| [euno-mcp README](../euno-mcp/packages/euno-mcp/README.md) | Stage 1 developer product: @euno/mcp quickstart. |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | Current package map and architecture overview. |

## 2. Architecture

| Doc | What it is |
| --- | ---------- |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | C4 views, sequence diagrams, deployment view. |
| [capability-model.md](./capability-model.md) | Security model, capability design. |
| [enforcement.md](./enforcement.md) | Policy decision point, enforcement guarantees. |
| [diagrams.md](./diagrams.md) | Mermaid architecture diagrams. |
| [mvp.md](./mvp.md) | Staged execution plan, gate criteria, business model. |

## 3. Design references

| Doc | What it is |
| --- | ---------- |
| [ADAPTERS.md](./ADAPTERS.md) | Pluggable identity / signing adapter pattern. |
| [CAPABILITY_MANIFEST_GUIDE.md](./CAPABILITY_MANIFEST_GUIDE.md) | Manifest authoring: structure, conditions, anti-patterns. |
| [SCHEMA_VERSIONING.md](./SCHEMA_VERSIONING.md) | Schema versioning, deployment ordering. |
| [DISTRIBUTED_STATE.md](./DISTRIBUTED_STATE.md) | Redis-backed shared state (Stage 3+). |
| [sandboxing.md](./sandboxing.md) | Sandbox reference architecture (Stage 2+). |

## 4. Deployment and operations

| Doc | What it is |
| --- | ---------- |
| [DEPLOYMENT.md](./DEPLOYMENT.md) | Current deployment notes and platform service paths. |

## 5. Repository conventions

| Doc | What it is |
| --- | ---------- |
| [repo-split.md](./repo-split.md) | Two-folder structure, license boundary rules. |
| [stage-0-freeze.md](./stage-0-freeze.md) | Platform package freeze policy. |
| [mcp-support.md](./mcp-support.md) | MCP SDK pin, protocol support window. |

## 6. Stage 1 launch

| Doc | What it is |
| --- | ---------- |
| [promotion.md](./promotion.md) | Launch copy and messaging for @euno/mcp. |
| [launch-post.md](../euno-mcp/packages/euno-mcp/docs/launch-post.md) | Draft Show HN post. |

---

## Maintenance

Update the matching doc in the same PR when behaviour changes.
Update OpenAPI specs under [openapi/](./openapi/) for endpoint changes.
