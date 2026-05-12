# euno Documentation Index

Design and operational documentation for euno. Docs are organized by purpose.

---

## 1. Start here

| Doc | What it is |
| --- | ---------- |
| [../README.md](../README.md) | Project README — value prop, quick start, links. |
| [repo-guide.md](./repo-guide.md) | Repository structure, build / lint / test, contributor setup. |
| [euno-mcp README](../public/packages/mcp/README.md) | Stage 2 developer product: @euno/mcp quickstart and condition reference. |
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
| [stage-3-design.md](./stage-3-design.md) | Stage 3 design freeze RFC: KMS, Postgres, Redis, API-key scheme, enforcer wire protocol. |

## 4. Deployment and operations

| Doc | What it is |
| --- | ---------- |
| [DEPLOYMENT.md](./DEPLOYMENT.md) | Current deployment notes and platform service paths. |
| [self-host.md](./self-host.md) | BYO-GW guide: running the full gateway stack on your own infrastructure. |
| [migrating-from-local.md](./migrating-from-local.md) | Upgrading from `@euno/mcp` local mode to the hosted gateway: before/after, cryptographic story, data-boundary analysis. |

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
| [launch-post.md](../public/packages/mcp/docs/launch-post.md) | Draft Show HN post. |

---

## Maintenance

Update the matching doc in the same PR when behaviour changes.
Update OpenAPI specs under [openapi/](./openapi/) for endpoint changes.
