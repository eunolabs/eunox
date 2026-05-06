# Euno: From MVP to Full Vision
## Strategic Summary & Staged Execution Plan

---

## Context

**What Euno is:** A production-ready capability-based security system for AI agent governance — cryptographically signed tokens, fine-grained tool enforcement, comprehensive audit trails, multi-cloud identity, and W3C DID support.

**The problem with the current state:** The system is architected for enterprise platform teams responding to compliance mandates. Seven packages, multi-cloud KMS, Redis distributed kill-switches — that's a procurement conversation. There is no grassroots entry point.

**The core insight:** The framework adapters are the only grassroots surface in the current codebase. Everything else is buried under infrastructure. The wedge is `npm install @euno/mcp` — not the full system.

**Language:** Stay in TypeScript. LangChain.js is real, the audience is valid, and a Python rewrite is how the project dies. Python becomes relevant only if traction data demands it.

**Licensing:** Open source the developer-facing npm package. Keep the gateway, issuer, and enterprise infrastructure under BSL or Elastic License 2.0. This is the Infisical/Airbyte playbook — open entry point, commercial operational layer.

---

## The Staged Approach

Each stage has a **gate condition** — a specific user behavior that must be observed before moving forward. Stages are pulled by demand, not pushed by roadmap.

---

## Stage 1: MCP Proxy MVP

**The pitch:** *"Add guardrails to any MCP server in 5 minutes. No infrastructure required."*

**The pain:** Developers building agents with LangChain.js, Cursor, Claude Desktop, or any MCP-compatible client have no runtime enforcement on tool calls. Agents can run destructive SQL, hammer APIs, write to arbitrary paths. Nothing stops them before the call executes. LangSmith gives you observability after the fact. Euno stops it before.

**Why MCP over LangChain adapter:** MCP is now the dominant tool protocol across Claude Desktop, Cursor, Windsurf, and every serious agent framework. One package works with every MCP-compatible client, not just one framework. The enforcement boundary is the protocol itself — the agent has no import path, no function reference, no escape route.

### What to Deliver

**`@euno/mcp` — standalone npm package**

A proxy MCP server that sits between any agent and any upstream MCP server. It forwards `tools/list` verbatim, intercepts every `tools/call`, enforces the policy, then either forwards to upstream or returns a structured denial.

```
Agent → tools/list  → Euno Proxy → Upstream MCP Server
Agent ← tool schemas ← Euno Proxy ← Upstream MCP Server

Agent → tools/call: query_db { query: "DROP TABLE users" }
                        ↓
                  Policy: SELECT only
                  Pattern check fails
                        ↓
Agent ← CapabilityDenied: operation not permitted
        (upstream never called)
```

**Core API:**

```typescript
import { createEunoMcpProxy } from "@euno/mcp";

createEunoMcpProxy({
  upstream: "npx @modelcontextprotocol/server-filesystem /data",
  port: 7391,
  policies: {
    "read_file": {
      maxCallsPerSession: 100,
      allowedPaths: ["/data/public/**"]
    },
    "write_file": {
      allowedPaths: ["/data/output/**"],
      timeWindow: { start: "09:00", end: "18:00" }
    },
    "*": {
      maxCallsPerSession: 200
    }
  }
});
```

**Or via CLI:**

```bash
euno proxy \
  --upstream "npx @modelcontextprotocol/server-filesystem /data" \
  --policy ./euno.policy.json \
  --port 7391
```

**What to include:**
- `tools/list` passthrough from upstream
- `tools/call` interception with enforcement
- Policy conditions: `maxCallsPerSession`, `allowedPaths`, `allowedOperations`, `argumentSchema`, `timeWindow`
- In-memory call counters and enforcement state (no Redis)
- Local jsonl audit log (`~/.euno/audit.log`)
- Structured `CapabilityDeniedError` with reason
- `euno proxy` CLI command
- `euno validate` — validate a policy config file locally

**What to cut:**
- Token issuance (no UI, no service)
- Azure Key Vault / KMS / any cloud dependency
- W3C DID
- Redis
- MAF adapter
- Multi-cloud identity providers

**What to extract from existing packages:**
- `CapabilityCondition` discriminated union from `packages/common`
- Argument validators (SQL, path, schema) from `packages/common`
- In-memory call counter store from `packages/common`
- MCP interception logic from `packages/framework-adapters` (reshape, don't rewrite)

**Enforcement guarantee to document explicitly:**  
Enforcement is on arguments *as the agent sent them*, not on what the upstream server does with them. The guarantee is "the agent called the tool with these arguments" — not "the underlying operation was constrained." This is correct behavior for a proxy model. Wrapping (for servers you own) gives stronger guarantees; proxying (for servers you don't own) gives broad coverage.

### Execution Plan

**Weeks 1–2: Extract and stub**
- Create `packages/euno-mcp` as a standalone package
- Strip all service dependencies from extracted common utilities
- Implement `tools/list` passthrough and `tools/call` interception
- Wire in-memory enforcement (no Redis)
- Local jsonl audit logging

**Weeks 3–4: Policy engine and CLI**
- Implement policy loader from JSON config
- Wire `CapabilityCondition` types: `maxCallsPerSession`, `allowedPaths`, `argumentSchema`, `timeWindow`
- `euno proxy` CLI command
- `euno validate` CLI command
- Lightweight integration test (no heavy infra — mock upstream MCP server)

**Weeks 5–6: Ship and distribute**
- Publish to npm: `@euno/mcp`
- README with a single 15-line before/after: agent blocked from a destructive SQL call
- One concrete post: *"How I stopped my LangChain agent from destroying my dev database"*
- Targets: LangChain Discord `#tools-and-integrations`, r/LocalLLaMA, Hacker News Show HN
- GitHub repo title: includes "MCP" and "guardrails" — not "capability-based security"

**Gate condition to Stage 2:**  
Users running this in production ask: *"Can I enforce this on other tools too?"* Stars and downloads are vanity. This specific question means the enforcement model clicked and they want broader surface area.

---

## Stage 2: General Tool Enforcement

**What changes:** Expand from SQL-specific conditions to the full `CapabilityCondition` discriminated union. Users get richer policy primitives across any tool type.

**What to deliver:**
- Additional condition types exposed in policy config: IP allowlists, argument schema validation, rate limiting by time window
- `euno validate-token` CLI for debugging enforcement decisions
- LangChain.js adapter (`@euno/langchain`) as a companion — for developers who prefer in-process wrapping over the MCP proxy

Nothing architecturally new. The proxy handles it unchanged because enforcement is still at `tools/call`. Policy config gets richer, validators get more types.

**Gate condition to Stage 3:**  
Users ask: *"How do I share this policy across my team?"* or *"How do I audit what my agents did last week?"* In-memory enforcement and local logs start feeling inadequate. This is the moment the gateway becomes a real ask.

---

## Stage 3: The Gateway as Managed Boundary

**What changes:** Move enforcement out of the local proxy process into a persistent service. This is `packages/tool-gateway` — it stops being overengineered and starts being exactly right.

**The upgrade pitch to existing users:**  
Same policy config. Same MCP proxy interface. But now audit logs persist across sessions, kill-switch works across multiple agent processes, and team members can inspect and modify policies without redeploying.

**The upgrade path must be a single config change:**

```json
// Stage 1-2: local enforcement
{ "enforcer": "local" }

// Stage 3: gateway enforcement
{ "enforcer": "https://your-euno-gateway.com", "apiKey": "sk-..." }
```

Nothing in the agent or policy config changes. This is the retention mechanic.

**What to deliver:**
- `packages/tool-gateway` exposed as a hosted service (or self-hosted Docker image)
- Persistent audit log with query interface
- Admin API: kill-switch (global, session, agent-level), revocation list
- Redis-backed distributed state for multi-process deployments
- Managed gateway option (this is where revenue begins)

**Gate condition to Stage 4:**  
Teams using it. Someone mentions audit compliance, SOC2, or "our security team wants to review how tokens are issued."

---

## Stage 4: Capability Issuer + Identity

**What changes:** Multiple agents, multiple users, multiple policies tied to real identities rather than config files. Token issuance becomes necessary.

This is where Azure AD, JWT signing, and pluggable identity providers stop being over-engineering and become the answer to a question users are actually asking.

**What to deliver:**
- `packages/capability-issuer` shipped and integrated
- Azure AD and at minimum one other identity provider
- Token attenuation and renewal endpoints
- Role-to-capability mapping
- `euno request` and `euno validate-token` CLI commands fully wired to live issuer

**Gate condition to Stage 5:**  
Enterprise inbound. A company with a security team contacts you. They mention compliance, on-prem deployment, or "our CISO needs to review this."

---

## Stage 5: Enterprise + Full Vision

The system as currently architected. W3C DID (`did:web`, `did:ion`, `did:key`), multi-cloud KMS (Azure Key Vault, AWS KMS, GCP Cloud KMS), BSL licensing, on-prem deployment options, SOC2 audit trail export.

At this stage you have a sales process, not a developer tools play. The `/.well-known/capability-issuer` discovery endpoints, `did:ion` resolution, and cryptographic evidence generation — all of it becomes relevant when a security team is reviewing the system, not before.

---

## Buyer Map

| Stage | Buyer | Motivation |
|---|---|---|
| 1–2 | Individual developer | Fear of agent mistakes, curiosity |
| 3 | Tech lead / small team | Operational control, shared visibility |
| 4 | Engineering org | Compliance, multi-agent coordination |
| 5 | Enterprise | Security mandate, audit requirements |

The current architecture optimizes for Stage 5 buyers. The current entry point doesn't reach Stage 1 buyers. Stages 1–2 are the on-ramp. Build them first, make the upgrade path frictionless, let users pull themselves forward.

---

## Critical Risks

**LangChain.js API churn.** LangChain's API surface changes constantly. Pin to a tested version range and be explicit. Test against both stable and latest in CI from day one.

**The Stage 1-2 ceiling.** Some developers will use local enforcement forever and never need the gateway. That's fine — they're your distribution channel, not necessarily your revenue. The ones who hit the ceiling are your customers.

**Scope creep disguised as focus.** A token issuance UI, a database proxy, RAG access control — all reasonable ideas, all wrong for Stage 1. The MVP is the MCP proxy with SQL policy enforcement. Nothing else.

**Selling the architecture before selling the value.** "Capability-based security" and "zero-trust agents" are not search terms developers use. "Stop your agent from dropping your database" is.
