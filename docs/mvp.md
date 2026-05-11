# euno: From MVP to Full Vision

## Strategic Summary & Staged Execution Plan

> **Status of this document:** strategy / planning. Not implementation.
> Reviewed against the actual state of the workspace packages and the rest of
> `docs/` (April 2026). A second pass (May 2026) identified four additional
> problems — `euno-platform/packages/common` split, dependency-direction enforcement,
> minter threat model, and the two-folder structure — addressed in this
> revision. See [§ Analysis](#analysis-where-the-prior-plan-needed-tightening)
> for what changed and why.
> Current package workspaces live under `public/packages/*` and
> `euno-platform/packages/*`; there is no root `packages/` workspace.

---

## Context

**What euno is today.** A capability-native zero-trust governance plane
for AI agents: cryptographically signed capability tokens (JWT,
versioned schema), a Tool Gateway that acts as the reference monitor
in front of every protected backend, typed `CapabilityCondition`
enforcement, distributed kill-switch and revocation (Redis + Postgres
backends, with a cross-chain anchor for tamper-evident audit), W3C DID
support (`did:web`, `did:ion`, `did:key`), pluggable identity
providers (Entra ID, AWS Cognito, GCP Cloud Identity), pluggable
signers (Azure Key Vault, AWS KMS, GCP Cloud KMS), framework adapters
for LangChain / MAF / CrewAI, and ~37k LOC across 11 packages. See
[`ARCHITECTURE.md`](./ARCHITECTURE.md) and
[`capability-model.md`](./capability-model.md) for the authoritative
implementation reference.

**The problem with the current state.** The system is architected for
the Stage-5 buyer — an enterprise platform team responding to a
compliance mandate. Multi-cloud KMS, Redis-backed kill switches,
partner-issuer DID resolution with per-DID circuit breakers,
cross-chain audit anchors. That is a procurement conversation.
There is no grassroots entry point: today, an individual developer
who wants to stop their LangChain agent from running `DROP TABLE`
finds nothing they can `npm install` and use in five minutes.

**The core insight.** The framework adapters are the closest thing the
current codebase has to a grassroots surface, but they still depend on
`@euno/agent-runtime` → Tool Gateway → Capability Issuer → KMS. The
wedge has to be **a single, dependency-light npm package that runs
locally and enforces something useful before any infrastructure is
introduced**. MCP — now the dominant tool protocol across Claude
Desktop, Cursor, Windsurf, and most agent frameworks — is the right
protocol surface for that wedge.

**Language.** Stay in TypeScript. LangChain.js is real, the audience
is valid, and a Python rewrite is how the project dies. Python becomes
relevant only if traction data demands it (Stage 4, at the earliest).

**Licensing.** Open source the developer-facing npm package
(`@euno/mcp` and any companion adapters). Keep the gateway, issuer,
and enterprise infrastructure under BSL 1.1 with an explicit four-year
change date to Apache-2.0, or under Elastic License 2.0. This is the
Infisical / Airbyte / Sentry playbook — open entry point, commercial
operational layer. The license boundary must be drawn in the
repository now, not later (see [§ License boundary](#license-boundary)).

---

## Analysis: where the prior plan needed tightening

The previous version of this document was directionally correct on
strategy (pull-through staging, MCP wedge, TS, source-available
operational layer). It had four substantive problems and one
material factual error that this revision fixes.

1. **Factual error.** The prior plan said Stage 1 would *extract* MCP
   interception logic from `euno-platform/packages/framework-adapters`. There is no
   MCP code in `euno-platform/packages/framework-adapters` — only LangChain, MAF,
   and CrewAI adapters. Stage 1 is **greenfield**, not extraction.
   What can be extracted is the `CapabilityCondition` discriminated
   union, `condition-registry`, `capability-validators`,
   `argument-validator`, the in-memory `CallCounterStore`, and the
   in-memory `KillSwitchManager` from `euno-platform/packages/common`. The MCP
   protocol layer itself has to be built.

2. **The Stage 3 upgrade is not "a single config change."** The prior
   plan said upgrading from local enforcement to the gateway is a
   one-line config flip (`{"enforcer": "https://..."}`) and "nothing
   in the agent or policy config changes." That is impossible against
   the actual gateway, which requires a *signed JWT capability token*
   verified against an issuer's public key (or DID document). API
   keys do not pass the gateway's verifier. The bridge needs to be
   designed up front (see [§ Stage 3 upgrade bridge](#stage-3-the-gateway-as-managed-boundary))
   or the upgrade promise will break the first time a real user tries it.

3. **Policy and audit schema parity were unaddressed.** The local
   proxy uses an ad-hoc JSON DSL (`{ "read_file": { "allowedPaths": ... } }`).
   The production system uses signed `AgentCapabilityManifest` +
   `CapabilityConstraint[]` + typed `CapabilityCondition` (see
   [`CAPABILITY_MANIFEST_GUIDE.md`](./CAPABILITY_MANIFEST_GUIDE.md)).
   If these diverge, the upgrade path is structurally broken from
   day one — every customer who hits the ceiling has to rewrite their
   policy, exactly when you can least afford friction. **The local DSL
   must be an isomorphic subset of, or compile target for, the
   production manifest.** Same applies to the local jsonl audit log
   vs. signed OCSF evidence: same schema, different signer.

4. **MCP transport reality was missing.** The prior design ran an HTTP
   server on `port: 7391`. Claude Desktop and Cursor — the headline
   audience for the pitch — spawn MCP servers as **stdio child
   processes** via their `mcpServers` config. An HTTP-only proxy
   doesn't reach them. The MVP must support stdio-as-transport
   (`euno proxy` as an `npx`-runnable wrapper command), with HTTP /
   streamable HTTP as a secondary transport for LangChain.js use cases.

5. **Gate conditions were anecdotal.** "Users ask: can I share the
   policy across my team?" is not a measurable trigger. Without
   opt-in telemetry built into `@euno/mcp` from day one, "stages
   pulled by demand" reduces to guessing. Telemetry is a foundational
   design decision: it cannot be retrofitted into a security tool
   without burning trust. See [§ Telemetry & gate instrumentation](#telemetry--gate-instrumentation).

6. **`euno-platform/packages/common` mixes open and operational code.** The package
   currently contains both Apache-2.0-compatible things (types,
   interfaces, in-memory stores, the four interface seams) and
   operational things (Redis/Postgres/KMS-backed implementations).
   You cannot license it Apache-2.0 without open-sourcing the
   operational layer. You cannot license it BSL without contaminating
   `@euno/mcp`. The fix is a hard split into two packages:
   `common-core` (Apache-2.0, the open seams) and `common-infra`
   (BSL, the Redis/Postgres/KMS implementations). See
   [§ License boundary](#license-boundary).

7. **Minter threat model is unaddressed.** The API-key façade
   introduced in Stage 3 holds a managed signing key with authority
   to mint any JWT for any policy. If that key is compromised, the
   entire cryptographic invariant collapses — not just one tenant.
   The prior plan spent significant effort on the gateway's verifier
   path but said nothing about this. A threat model for the minter
   must be written and reviewed before Stage 3 ships. See
   [§ Minter threat model](#minter-threat-model-required-before-stage-3-ships).

Three additional concerns — not errors, but gaps — are addressed
in the new sections below: **what happens to the existing 11 packages
during Stage 1** ([§ Stage 0](#stage-0-stop-the-bleeding-on-the-existing-codebase)),
**what the business model actually is at Stage 3+** ([§ Pricing](#pricing--business-model-sketch)),
and **competitive timing** ([§ Critical risks](#critical-risks)).

The May 2026 revision also adds the two-folder structure (public / private)
that follows from the decision to keep BSL code entirely invisible, not
just differently licensed. See [§ Repository structure](#repository-structure-public--private).

---

## The Staged Approach

Each stage has a **gate condition** — a specific, *measurable*
behavior that must be observed before moving forward. Stages are
pulled by demand, not pushed by roadmap. The current architecture is
Stage 5 work that was built first; Stages 0–2 are a deliberate
walk-back to the on-ramp.

**Important:** stages map to *npm publish gates and hosted-service
availability*, not to when code is written or merged. All packages
can coexist in the monorepo from day one. What changes at each stage
gate is what gets published publicly and what gets deployed. Keeping
all code together prevents drift and lets integration tests in the
private repo cover unreleased stages without a branch-per-stage
strategy.

| Stage | Buyer | What ships | Gate to next |
|---|---|---|---|
| 0 | (internal) | Codebase triage; freeze the Stage-5 surface | Stage-1 work green-lit |
| 1 | Individual dev | `@euno/mcp` (stdio + HTTP), local enforcement, jsonl audit | ≥10 inbound asks for richer conditions / cross-process state |
| 2 | Individual dev / IC | Full `CapabilityCondition` set in proxy, `@euno/langchain` companion, `validate-token` CLI | ≥5 teams (≥3 users each) running it; ≥3 ask for shared audit / policy |
| 3 | Tech lead / small team | Hosted Tool Gateway with API-key façade + auto-mint shim → real signed token | ≥1 paying team; security/compliance question raised |
| 4 | Engineering org | Capability Issuer + IdP integration (Entra ID + 1 other) | Enterprise inbound: SOC2, on-prem, CISO review |
| 5 | Enterprise | Full vision (DID, multi-cloud KMS, federation, ledger, BSL operational tier) | Sales motion |

---

## Stage 0: Stop the bleeding on the existing codebase

> **Stage 0 status** (updated Substage 0.4, May 2026)
>
> - [x] **Substage 0.1** -- Feature-freeze and quarantine policy written;
>   [`docs/stage-0-freeze.md`](./stage-0-freeze.md) merged.
> - [x] **Substage 0.2** -- MCP SDK version pinned; support window recorded in
>   [`docs/mcp-support.md`](./mcp-support.md).
> - [x] **Substage 0.3** -- `euno-platform/packages/common` split into `common-core`
>   (Apache-2.0) and `common-infra` (BUSL-1.1); package-level `LICENSE` files
>   added; compat shim kept as `@euno/common` (BUSL-1.1) for back-compat.
> - [x] **Substage 0.4** -- CI dependency-direction enforcement landed:
>   `scripts/check-license-boundary.mjs` walks the full workspace dependency
>   graph (including transitive edges and all dep fields), fails on any
>   Apache-2.0 -> BUSL-1.1 edge, and is wired into `npm run lint` and the
>   GitHub Actions CI workflow (`.github/workflows/ci.yml`). The `@euno/cli`
>   migration to `@euno/common-core` is complete; the allowlist is empty
>   (zero violations). Two-folder strategy decided and documented; top-level
>   folders [`public/`](../public/) and [`euno-platform/`](../euno-platform/)
>   contain the actual packages under their respective `packages/`
>   subdirectories. Apache-2.0 packages live under `public/packages/` and
>   BUSL-1.1 packages live under `euno-platform/packages/`.
>
> **All six Stage 0 gate conditions are now met. Stage 1 may begin.**

**Why this stage exists.** The repository today contains ~37k LOC of
Stage-5 infrastructure with no Stage-1 buyers using it. Every
maintenance hour spent on `partner-issuer-sim`, the cross-chain
anchor, multi-region issuer, or the per-DID circuit breaker is an
hour not spent on the wedge. Without an explicit triage decision the
default behavior is to keep building outwards.

**Decisions to make and write down before Stage 1 begins:**

- **Feature-freeze** `euno-platform/packages/{tool-gateway, capability-issuer, common, common-infra, agent-runtime, framework-adapters}` to security fixes, dependency bumps, and design-partner-driven changes only. No new features without a named user. Policy and PR-review checklist: [`docs/stage-0-freeze.md`](./stage-0-freeze.md).
- **Quarantine** `euno-platform/packages/{partner-issuer-sim, db-token-service, storage-grant-service, posture-emitter}`: keep them building in CI, do not invest further until a Stage-4 customer pays for it. Each package carries a `STATUS.md` marking it "design-partner driven, not on the roadmap."
- **Pin the MCP SDK version** the project will support (`@modelcontextprotocol/sdk`), document the protocol revision, and decide the support window. MCP is still pre-1.0; pretending otherwise causes silent breakage. Decision recorded in [`docs/mcp-support.md`](./mcp-support.md).
- **Draw the license boundary** (see below) and add `LICENSE` files at the package level so the boundary is mechanical, not editorial. This includes splitting `euno-platform/packages/common` into `common-core` (Apache-2.0) and `common-infra` (BSL) and organising packages into the two-folder structure described in [§ Repository structure](#repository-structure-public--private).

**Gate to Stage 1:** the freeze is announced (internal note is fine),
the Stage-1 package layout is approved, the license boundary is in
the tree, the `common-core` / `common-infra` split is done, and the
two-folder structure is in place.

---

## License boundary

| Package(s) | License | Rationale |
|---|---|---|
| `@euno/mcp` (new) | Apache-2.0 | Wedge. Must be trivially adoptable, redistributable, embeddable in commercial products. Apache-2.0 (not MIT) for the patent grant. |
| `@euno/langchain` (new) | Apache-2.0 | Same reason. |
| `public/packages/common` (split from `common`) | Apache-2.0 | Types, interfaces, in-memory stores, the four interface seams. Imported by the open packages; cannot be more restrictive than them. |
| `public/packages/cli` | Apache-2.0 | Developer surface. |
| `euno-platform/packages/common-infra` (split from `common`) | BSL 1.1 | Redis, Postgres, KMS-backed implementations. Operational layer. Depends on `common-core`; the reverse dependency is forbidden (see below). |
| `euno-platform/packages/{tool-gateway, capability-issuer, agent-runtime, framework-adapters}` | BSL 1.1, change date = today + 4 years → Apache-2.0 | The operational layer. BSL allows non-production use, source review, and self-host for non-competing use; blocks a hyperscaler from launching "Managed euno Gateway" against you. |
| `euno-platform/packages/{partner-issuer-sim, db-token-service, storage-grant-service, posture-emitter, integration-tests}` | BSL 1.1 | Same. |

**Dependency direction rule.** BSL packages may depend on Apache-2.0
packages. Apache-2.0 packages must never depend on BSL packages.
`@euno/mcp` imports from `common-core`. `tool-gateway` imports from
both. This is enforced mechanically: a CI lint script walks the full
workspace dependency graph — including transitive edges and all
dependency field types (`dependencies`, `devDependencies`,
`peerDependencies`, `optionalDependencies`, `workspace:*` references)
— and fails the build on any Apache-2.0 → BSL edge. Without this
check, a well-intentioned contributor can introduce the violation
silently via an indirect transitive dependency.

The boundary must be drawn before `@euno/mcp` ships. Re-licensing
later is contentious; doing it now is paperwork. For the publish-gate
model see [§ The Staged Approach](#the-staged-approach).

---

## Repository structure: public + private

Licensing code under BSL does not hide it — source is still visible to
anyone who reads the repo. The public/private boundary is enforced by
organising packages into two top-level folders within this single
monorepo, mirroring the logical separation without requiring a second
repository.

**Two top-level folders:**

```
public/                          # public — Apache-2.0
  packages/
    common/
    mcp/
    cli/

euno-platform/                     # private — BUSL-1.1
  packages/
    common-infra/
    common/
    tool-gateway/
    capability-issuer/
    agent-runtime/
    framework-adapters/
    partner-issuer-sim/
    ... etc
```

Both folder trees are npm workspaces declared in the root `package.json`
(`public/packages/*` and `euno-platform/packages/*`).

**How the dependency works.** The `common` package (`@euno/common-core`) lives in `public/packages/`
and is consumed by the platform packages in `euno-platform/packages/` as
a normal workspace dependency. When published to npm, `@euno/common-core`
becomes the public API contract that external consumers (and the future
hosted platform) install as a regular npm dependency. The interface seams
in `common-core` are the published contract. Platform implementations are
completely invisible to consumers of the public surface.

**Tradeoffs introduced by this structure:**

| Concern | Implication |
|---|---|
| Versioning discipline | A breaking change to `common-core` requires coordinated updates across the platform packages. Treat it like a public API contract: proper semver, a CHANGELOG entry, and a migration note before merging. |
| External contributor coverage | Contributors working only in `public/` cannot validate that their `common-core` changes don't break the platform layer. That review is owned internally and must happen before every `common-core` release. |

**The one thing to avoid.** No comments in the `public/` subtree
pointing at the platform layer — no `// see tool-gateway for the
production implementation`, no `// Stage 3 replaces this`, no TODOs
naming a BUSL-1.1 package. The public surface must read as complete and
self-contained. Local enforcement is the product, not a stepping stone
to something hidden.

---

## Stage 1: MCP Proxy MVP

> **Stage 1 status** (May 2026)
>
> - [x] Task 1 — `public/packages/mcp` scaffolded; build, lint, test all pass
> - [x] Task 2 — `MCP_PROTOCOL_VERSION` constant; `docs/mcp-support.md` updated
> - [x] Task 3 — `StdioProxy` with full passthrough + `tools/call` interception
> - [x] Task 4 — Mock upstream + stdio integration tests (transport-stdio.test.ts)
> - [x] Task 5 — `HttpProxy` streamable HTTP transport + integration tests
> - [x] Task 6 — OCSF audit log, HMAC-SHA-256 signer, key at `~/.euno/key` (0600)
> - [x] Task 7 — `FilePolicySource` loading YAML/JSON; Stage-2 types rejected
> - [x] Task 8 — `ConditionEnforcerPDP` wiring condition-registry; in-memory counters + kill-switch
> - [x] Task 9 — `euno-mcp proxy`, `euno-mcp validate`, `euno-mcp kill` CLI commands
> - [x] Task 10 — Opt-in telemetry (off by default; counts only; `EUNO_TELEMETRY=0` disables)
> - [x] Task 11 — e2e test: destructive SQL blocked before upstream is called
> - [x] Task 12 — Apache→BSL dependency lint covers `@euno/mcp`; `@euno/cli` migration complete
> - [x] Task 13 — `release-mcp.yml` workflow; `publishConfig` to GitHub Packages
> - [x] Task 14 — `@euno/mcp` README with before/after, drop-in config, enforcement guarantee
> - [x] Task 15 — `scripts/stage2-readiness.ts`; `.github/ISSUE_TEMPLATE/feature-ask.md`
>
> **All 15 Stage 1 tasks are complete. `@euno/mcp` 0.1.0 is ready to publish.**

**The pitch:** *"Add guardrails to any MCP server in 5 minutes.
No infrastructure required."*

**The pain.** Developers building agents with LangChain.js, Cursor,
Claude Desktop, or any MCP-compatible client have no runtime
enforcement on tool calls. Agents can run destructive SQL, hammer
APIs, write to arbitrary paths. Nothing stops them before the call
executes. LangSmith gives observability *after the fact*. euno stops
it *before*.

**Why MCP and not the LangChain adapter.** MCP is the dominant tool
protocol across Claude Desktop, Cursor, Windsurf, and every serious
agent framework. One package works with every MCP-compatible client,
not just one framework. The enforcement boundary is the protocol
itself — the agent has no import path, no function reference, no
escape route.

**Why not extract from `euno-platform/packages/framework-adapters`.** There is no
MCP code there. The MCP transport, JSON-RPC framing, and request
routing are new code. What *can* be reused from the repository:

- `CapabilityCondition` discriminated union and `condition-registry` from `public/packages/common`
- `argument-validator` and `capability-validators` (path / SQL / table-name validators) from `public/packages/common`
- `InMemoryCallCounterStore` (with in-memory per-key expiry tracking) from `public/packages/common/src/call-counter-store.ts`
- `KillSwitchManager` in-memory backend from `public/packages/common/src/kill-switch.ts`
- `AgentCapabilityManifest` types and the `euno validate` codepath from `public/packages/cli`

That reuse is the keystone of [§ Schema parity](#policy-and-audit-schema-parity-non-negotiable).

### What ships

**`@euno/mcp` — standalone npm package, dual-transport.**

A proxy MCP server that sits between any MCP client and any upstream
MCP server. It forwards `tools/list`, `resources/list`, and
`prompts/list` verbatim, intercepts every `tools/call`, enforces the
policy, then either forwards to upstream or returns a structured
denial.

```
Client → tools/list  → euno Proxy → Upstream MCP Server
Client ← tool schemas ← euno Proxy ← Upstream MCP Server

Client → tools/call: query_db { query: "DROP TABLE users" }
                        ↓
                  Policy: SELECT only
                  Pattern check fails
                        ↓
Client ← CapabilityDenied: operation not permitted
        (upstream never called)
```

**Both transports must work in v0:**

- **stdio (primary).** Drop-in replacement for an upstream stdio server in `claude_desktop_config.json` / Cursor's `mcpServers`. The proxy spawns the upstream as a child process and pipes JSON-RPC frames through itself. *Without this, the headline audience cannot use the package.*
- **streamable HTTP (secondary).** For LangChain.js, in-process clients, and the "show HN" demo. Defaults to a local port; explicitly does not bind to `0.0.0.0`.

**Programmatic API (for embedders):**

```typescript
import { createEunoMcpProxy } from "@euno/mcp";

createEunoMcpProxy({
  upstream: { command: "npx", args: ["@modelcontextprotocol/server-filesystem", "/data"] },
  transport: "stdio",                    // or "http", port: 7391
  policyFile: "./euno.policy.yaml",      // or `policy: AgentCapabilityManifest`
  auditLog: "~/.euno/audit.jsonl",       // jsonl, OCSF-shaped, locally signed
});
```

**CLI (the actual usage shape for Claude Desktop / Cursor / npx):**

```bash
# Drop-in stdio wrapper — paste this command into mcpServers
npx -y @euno/mcp proxy \
  --policy ./euno.policy.yaml \
  -- npx -y @modelcontextprotocol/server-filesystem /data

# HTTP mode for LangChain.js
npx -y @euno/mcp proxy --transport http --port 7391 \
  --policy ./euno.policy.yaml \
  -- node ./my-mcp-server.js

# Validate a policy without running anything
npx -y @euno/mcp validate ./euno.policy.yaml
```

**`CapabilityCondition` variants supported in v0** (a strict subset of
the production `CapabilityCondition` discriminated union in
`public/packages/common/src/wire.ts`, so policies upgrade without rewriting):

- `maxCalls` (sliding window — the `CallCounterStore` already supports both per-session and per-window)
- `timeWindow` (`notBefore` / `notAfter`)
- `allowedOperations` (e.g. SQL verb allowlist; further enforced by `argument-validator`)
- `allowedExtensions` (file extension allowlist; delegated to existing `capability-validators`)
- `allowedTables` (DB table / column allowlist; delegated to existing `capability-validators`)

**Plus the `argumentSchema` field on `CapabilityConstraint`** (not a
condition variant — a sibling field on the constraint itself, defined
as the `ArgumentSchema` type in `common/src/wire.ts`). v0 honours it for the same
reason the production gateway does: it's the structural argument
allowlist for a capability and is the natural carrier for the kind of
"only these arg shapes" enforcement the MCP wedge needs.

`ipRange`, `recipientDomain`, `redactFields`, `policy`, and `custom`
are deferred to Stage 2. **Stage 2 (`@euno/mcp` 0.2.0) ships all five;**
see the Stage 2 status block below for per-task detail.

**Session identity** (the prior plan punted on this). Define a
**`session`** as one MCP client connection: for stdio, the lifetime of
the spawned proxy process; for HTTP, one MCP `initialize` → `shutdown`
cycle, keyed by the client-supplied `clientInfo` plus a server-minted
session ID. Counter keys are `<sessionId>|<toolName>|<resource>`. This
is the local-fallback equivalent of the production `IssuanceRateLimitSubject`
key shape — same components, different identity source.

### What is explicitly cut from Stage 1

> **Stage 2 delta:** `ipRange`, `recipientDomain`, `redactFields`, `policy`,
> and `custom` — all deferred below — are fully shipped in Stage 2 (0.2.0).
> `@euno/langchain` and the `policies/` reference library also land in Stage 2.
> Everything else in this list remains Stage 3 or later.

- Token issuance (no UI, no service, no signing key)
- Any KMS / Key Vault / cloud dependency
- W3C DID, partner federation, cross-chain anchor
- Redis, Postgres, anything multi-process
- MAF and CrewAI adapters (LangChain comes at Stage 2 if pulled)
- The `posture-emitter`, `db-token-service`, `storage-grant-service`, `partner-issuer-sim` packages
- Multi-cloud identity providers
- Network-policy / sandbox guidance from [`sandboxing.md`](./sandboxing.md) — relevant later, not here

### Enforcement guarantee — document explicitly

Enforcement is on arguments **as the agent sent them**, not on what
the upstream server does with them. The guarantee is "the agent
called the tool with these arguments" — not "the underlying
operation was constrained." For an upstream you control, wrapping
gives stronger guarantees than proxying. The README must say this in
the same breath as the pitch, or the first hostile HN comment will
say it for you.

### Execution plan

**Weeks 1–2 — Skeleton + transport.**
- Create `public/packages/mcp` (publishes as `@euno/mcp`).
- Implement stdio and HTTP MCP transports with `tools/list` / `resources/list` / `prompts/list` passthrough and `tools/call` interception. Do not reimplement JSON-RPC; use `@modelcontextprotocol/sdk`.
- Wire the in-memory `CallCounterStore` and `KillSwitchManager` from `@euno/common-core` (no Redis, no Postgres).
- Local jsonl audit log (`~/.euno/audit.jsonl`), OCSF-shaped, locally HMAC-signed (key generated at first run, stored in `~/.euno/key`). Format identical to the Stage-3+ signed evidence; signer is the only thing that changes.

**Weeks 3–4 — Policy engine + CLI.**
- Implement YAML/JSON policy loader producing the existing `AgentCapabilityManifest` in memory (one isomorphic shape, see [§ schema parity](#policy-and-audit-schema-parity-non-negotiable)).
- Wire the `CapabilityCondition` types listed above through `condition-registry`.
- `euno-mcp proxy` and `euno-mcp validate` CLI commands. Reuse the existing `euno validate` codepath from `public/packages/cli` so a manifest validates identically locally and in the issuer.
- Lightweight integration test using a mock upstream MCP server (a 30-line stdio echo server is enough).

**Weeks 5–6 — Ship and distribute.**
- Publish `@euno/mcp` to npm. Pin `@modelcontextprotocol/sdk` to a specific revision.
- README leads with one 15-line before/after: agent blocked from a destructive SQL call. Second snippet: the exact paste-into-`claude_desktop_config.json` line.
- One concrete post: *"How I stopped my LangChain agent from destroying my dev database."*
- Targets: LangChain Discord `#tools-and-integrations`, r/LocalLLaMA, Hacker News Show HN, the MCP servers list (`modelcontextprotocol/servers` README).
- Repo title and tagline include "MCP" and "guardrails" — not "capability-based security."
- **Telemetry** (see [§ below](#telemetry--gate-instrumentation)) ships in v0, not bolted on later.

### Gate to Stage 2 — measurable

Move when **all three** are true:

1. ≥10 unsolicited inbound asks (issues / Discord / email) for richer condition types or for cross-process state.
2. Telemetry shows ≥50 distinct installs running ≥1 enforcement event per day for ≥7 consecutive days.
3. ≥1 design-partner conversation with a team that's already self-rolling something equivalent.

Stars and downloads are vanity. The asks are the signal that the enforcement model clicked.

---

## Policy and audit schema parity (non-negotiable)

This is the single most important architectural decision in the
entire staged plan. Get it wrong and every later stage compounds the
mistake.

**Rule.** The policy file `@euno/mcp` consumes is a literal subset of
`AgentCapabilityManifest` (`public/packages/common/src/types.ts`). The
condition types it understands are a literal subset of
`CapabilityCondition`. The audit records it writes are
OCSF-formatted, identical in shape to what the gateway writes to
SIEM. The only differences across stages are:

| Concern | Stage 1–2 | Stage 3+ |
|---|---|---|
| Policy storage | Local YAML/JSON file | Signed JWT minted by Capability Issuer |
| Policy verifier | None (file is trusted local input) | `JWTTokenVerifier` against issuer JWKS / DID |
| Counter store | `InMemoryCallCounterStore` | `RedisCallCounterStore` (with circuit breaker) |
| Audit signer | Local HMAC, key in `~/.euno/key` | KMS-backed signer (Azure Key Vault / AWS KMS / GCP) |
| Audit sink | `~/.euno/audit.jsonl` | OCSF stream → SIEM + ledger backend |
| Kill switch | In-memory | Redis + Postgres dual-write |

That is the entire Stage 3 migration: swap the implementations of
four interfaces that already exist as seams in `@euno/common-core` —
[`TokenVerifier`](../public/packages/common/src/runtime.ts),
[`CallCounterStore`](../public/packages/common/src/condition-registry.ts),
[`EvidenceSigner`](../public/packages/common/src/runtime.ts), and
[`KillSwitchManager`](../public/packages/common/src/runtime.ts) (with its
optional [`KillSwitchPersistenceBackend`](../euno-platform/packages/common-infra/src/redis-kill-switch.ts)
for Postgres dual-write). Policy storage is the only seam that is
genuinely new in Stage 3: in Stage 1 the policy is a local file read
once at startup; in Stage 3 it's a signed JWT verified per request via
`TokenVerifier`. Stage 1 must therefore wrap its file loader behind a
small `LocalPolicySource` interface in `@euno/mcp` so the Stage 3
hosted-token loader is a drop-in replacement. Nothing in the agent's
policy file shape or the audit stream's shape changes.

**Concrete obligation.** In Stage 1, the
`@euno/mcp` package does not define new policy types. It imports
`AgentCapabilityManifest`, `CapabilityConstraint`, and
`CapabilityCondition` from `@euno/common-core` and rejects anything else.
Unknown condition types are **rejected at policy-validation time**
(fail-fast at `euno-mcp validate` and at proxy startup), and if one
ever reaches the registry it is **denied at enforcement time** — the
same posture the production gateway already takes (see
[`capability-model.md`](./capability-model.md) §6, "unknown types are
denied by default"). There is no "unrecognized condition = no-op"
path at any layer.

---

## Stage 2: General Tool Enforcement

> **Stage 2 status** (May 2026)
>
> - [x] Task 1 — `argumentSchema` structured error reporting: `details` field in `PdpDecision` and audit `unmapped`
> - [x] Task 2 — `ipRange` condition: gate lifted; `sourceIp` wired from HTTP transport socket; `--trust-forwarded-for` flag
> - [x] Task 3 — `recipientDomain` condition: gate lifted; recipients extracted from tool args
> - [x] Task 4 — `redactFields` condition: gate lifted; response-path rewrite obligation in proxy; `obligationsApplied` in audit
> - [x] Task 5 — `policy` condition: gate lifted; `--policy-backend <module>` loader wired
> - [x] Task 6 — `custom` condition: gate lifted; `--custom-condition <module>` loader wired
> - [x] Task 7 — `euno-mcp validate-token` CLI (audit log explainer, HMAC verifier)
> - [x] Task 8 — `euno-mcp stats` CLI (denial-reason histograms from local audit log)
> - [x] Task 9 — `@euno/langchain` companion package — `wrapAsLangChainTool` over local-only `CapabilityRuntime`
> - [x] Task 10 — Reference policy library under `public/packages/mcp/policies/`
> - [x] Task 11 — README + docs updates: condition matrix, before/after, schema-parity claim
> - [x] Task 12 — Stage 3 readiness script + signal collection update
> - [x] Post-Stage-2 — VSCode build/debug configs (`.vscode/launch.json`, `tasks.json`, `settings.json`, `extensions.json`); CODEOWNERS and LICENSE updated to reflect `public/packages/common/` rename
>
> **All 12 Stage 2 tasks are complete. `@euno/mcp` 0.2.0 is ready to publish.**

**What changes.** Expand from the v0 condition subset to the full
`CapabilityCondition` discriminated union exposed in policy config.
Add a LangChain.js companion. Nothing architecturally new — the proxy
handles richer conditions unchanged because enforcement is still at
`tools/call`.

### What ships

- Additional condition types in policy config: IP allowlists, argument-schema validation with structured error reporting, rate limiting by time window, the existing `capability-validators` for SQL `SELECT`-only / table allowlists / column allowlists.
- `euno-mcp validate-token` CLI for inspecting why a request was denied (reads the local audit log, reconstructs the decision).
- `@euno/langchain` companion package — wraps a `Tool` / `StructuredTool` so LangChain.js users who don't want to introduce an MCP transport into a Node process can adopt euno in-process. Uses the same `AgentCapabilityManifest` and the same enforcement core. **Not a separate enforcer — the same `CapabilityRuntime` shape used by `euno-platform/packages/agent-runtime`, just with a local-only backend.**
- A reference policy library: 3–5 pre-baked `euno.policy.yaml` files for common upstream MCP servers (filesystem, Postgres, GitHub, Slack), in a `public/packages/mcp/policies/` directory. This is what makes the 5-minute pitch real.
- Continued telemetry; expose denial-reason histograms in the local CLI (`euno-mcp stats`).

### Gate to Stage 3 — measurable

- ≥5 teams (≥3 users each) confirmed running it (telemetry + at least one direct conversation per team)
- ≥3 unsolicited asks for "how do I share this policy across the team" or "how do I see what the agent did last week from my laptop"
- ≥1 conversation with a team that has already implemented some hand-rolled cross-process audit

Run `npx ts-node scripts/stage3-readiness.ts` to check current status (exits 0 when all three criteria are met, 1 when definitively not met, 2 when UNKNOWN).  Report team-sharing or cross-process-audit asks via [`.github/ISSUE_TEMPLATE/stage-3-signal.md`](../.github/ISSUE_TEMPLATE/stage-3-signal.md).

---

## Stage 3: The Gateway as Managed Boundary

> **Stage 3 status** (May 2026)
>
> - [x] Task 0 — Stage 3 design freeze & RFC: `docs/stage3executionplan.md` authored; KMS provider, Postgres/Redis deployment shape, API-key format, and wire contract captured; pending final merge review
> - [x] Task 1 — API-key minter threat model: `docs/security/minter-threat-model.md` produced; all seven MVP questions answered; pending engineer + security sign-off
> - [ ] Task 2 — `@euno/mcp` enforcer mode dispatch (remote-enforcer client)
> - [ ] Task 3 — `JWTTokenVerifier` wiring (consume seam from `@euno/common-core`)
> - [ ] Task 4 — `RedisCallCounterStore` for the gateway
> - [ ] Task 5 — KMS-backed `EvidenceSigner`
> - [ ] Task 6 — `RedisKillSwitchManager` with Postgres dual-write
> - [ ] Task 7 — Persistent audit query API
> - [ ] Task 8 — Admin API hardening
> - [ ] Task 9 — Hosted enforcement HTTP contract
> - [ ] Task 10 — Minter service skeleton *(blocked on Task 1 sign-off)*
> - [ ] Task 11 — Minter HSM integration *(blocked on Task 1 sign-off)*
> - [ ] Task 12 — Minter monitoring & alerting *(blocked on Task 1 sign-off)*
> - [ ] Task 13 — Self-hostable Docker image
> - [x] Task 14 — BYO-GW path documentation: `docs/self-host.md` produced; covers component list, what self-hosters give up, minimum viable issuer recipe (DID-based identity, local-PEM dev path, KMS production path), full production docker-compose, audit query API, admin ops, and security checklist
> - [ ] Task 15 — `@euno/mcp` upgrade UX
> - [ ] Task 16 — Telemetry continuity + `scripts/stage4-readiness.ts`
> - [ ] Task 17 — Pricing & billing plumbing
> - [ ] Task 18 — Reference materials & migration guide
> - [ ] Task 19 — Cross-stage parity test suite
> - [ ] Task 20 — Gate-to-Stage-4 instrumentation

**What changes.** Move enforcement out of the local proxy process
into a persistent service. `euno-platform/packages/tool-gateway` stops being
overengineered and starts being exactly right for the population
that's pulled this far.

### The Stage 3 upgrade bridge — the part the prior plan skipped

The prior plan promised that flipping `{"enforcer": "https://..."}`
would route through the production gateway with no other change.
That doesn't work as stated: the gateway requires a *signed JWT
capability token*, not an API key. Three options, one acceptable:

| Option | Verdict |
|---|---|
| Make the gateway accept API keys directly | **Reject.** Breaks the cryptographic-token invariant the entire system rests on (`enforcement.md`, `capability-model.md`). Forks the verifier into two modes. |
| Document a multi-step onboarding flow (issuer → token → gateway) at upgrade time | **Reject.** Kills the "single config change" promise — and that promise *is* the retention mechanic. |
| Ship a thin **API-key façade** in front of the gateway that mints a short-lived signed token from the API key on each session, using a *managed* signing key, then proxies to the real gateway | **Accept.** Same cryptographic invariant. Single config change for the user. The façade is what the hosted service sells. |

This means Stage 3 includes a new component: an **API-key minter**
that lives in front of the hosted gateway, holds a managed signing
key, and translates `apiKey` → `AgentCapabilityManifest` (looked up
from the team's stored policy) → signed JWT. From the developer's
perspective the upgrade really is one config change:

```jsonc
// Stage 1–2: local enforcement
{ "enforcer": "local" }

// Stage 3: hosted gateway
{ "enforcer": "https://gateway.euno.example", "apiKey": "sk-..." }
```

From the operator's perspective the API-key minter is the new
service. The Stage-3 gateway code is the existing
`euno-platform/packages/tool-gateway` with its existing verifier path; nothing
about the security model has to be relaxed.

### What ships

- `euno-platform/packages/tool-gateway` exposed as a hosted service and as a
  self-hosted Docker image (the latter under BSL).
- The API-key minter described above (lives in the hosted offering;
  not part of the self-host bundle initially — that decision can flip
  later based on demand).
- Persistent audit log with a query interface (start with the
  existing `PerReplicaPostgresLedgerBackend`; the cross-chain anchor
  stays off until Stage 5).
- Admin API: kill-switch (global / session / agent), revocation list.
  All of this code already exists.
- Redis-backed distributed state for multi-process deployments
  (existing implementation).
- A "Bring your own gateway" path for teams who want to self-host the
  whole thing — same Docker image, same config, no managed minter
  (they have to issue their own tokens, but they're at the engineering
  scale where that's acceptable).

### Minter threat model (required before Stage 3 ships)

The API-key minter holds a managed signing key with authority to mint
any JWT for any policy on the platform. If that key is compromised,
the attacker can issue tokens for any team, any agent, any capability.
This is the highest-value target in the entire system, and the prior
plan does not acknowledge it.

A written threat model must be completed and reviewed before the
minter ships. At minimum it must address:

| Question | Notes |
|---|---|
| Key storage | Managed HSM (Azure Managed HSM, AWS CloudHSM, GCP Cloud KMS with HSM protection level / Cloud HSM) — never software-resident. Key is non-exportable; verify non-exportability is enforced at the HSM level, not just by policy configuration. |
| Blast radius per key compromise | Which tokens were minted? How many teams? Requires a per-issuance audit trail. |
| Key rotation | How are previously minted tokens revoked when the signing key is rotated? The existing revocation list covers this for tokens, but the key rotation procedure itself must be documented and tested. |
| Scope isolation | Can the minter be constrained to mint tokens only within a tenant's allowed capability set? Or is it platform-wide? The answer shapes the damage model. |
| Credential access path | Who/what can call the minter's signing API? Is it network-isolated? Does it require a second factor or hardware attestation from the caller? |
| Audit trail | Every mint call logged with caller identity, tenant, policy fingerprint, and resulting JWT `jti`. This log must be immutable (append-only store, separate credentials from the minter itself). |
| Monitoring and alerting | Anomalous mint volume (e.g., >N mints/minute for a tenant) triggers an alert. Minting outside business hours for a low-activity tenant is a signal. |

This is not exotic security engineering — it is the same threat model
a managed certificate authority or an OAuth server operates under.
The difference is that euno's managed key signs capability tokens
that authorize agent actions directly, making it a more operationally
sensitive target than most token services. The gateway's verifier path
is already solid; the minter's key-management posture must match it.

**Implication for Stage 3 scope.** The minter is not a
"we'll tighten it later" component. Do not ship it to a paying
customer before the threat model is written. If completing the
threat model delays Stage 3, that is the correct trade.

### Gate to Stage 4 — measurable

- ≥1 paying team (any plan)
- A security or compliance question raised in writing (audit retention, SSO, SOC2, GDPR)

---

## Stage 4: Capability Issuer + Identity

**What changes.** Multiple agents, multiple users, multiple policies
tied to real identities rather than config files. Token issuance
becomes necessary as a first-class user-visible service rather than
an internal API-key minter.

### What ships

- `euno-platform/packages/capability-issuer` shipped as part of the hosted product
  and self-host bundle.
- Entra ID + at minimum one other identity provider (AWS Cognito or
  GCP Cloud Identity — pick whichever the design partners ask for).
- Token attenuation and renewal endpoints (already implemented).
- Role-to-capability mapping (already implemented).
- `euno request` and `euno validate-token` CLI commands fully wired
  to a live issuer (the CLI wiring exists; the live issuer is what
  was missing for these to be useful).
- Capability-manifest *templates* surfaced in the UI: a way for a
  tech lead to author a manifest once and assign it to many agents.

### Gate to Stage 5 — measurable

- Enterprise inbound from a company with a security team, mentioning
  compliance, on-prem, or "our CISO needs to review this."

---

## Stage 5: Enterprise + Full Vision

The system as currently architected. W3C DID (`did:web`, `did:ion`,
`did:key`), multi-cloud KMS (Azure Key Vault, AWS KMS, GCP Cloud
KMS), partner federation with per-DID circuit breakers, cross-chain
audit anchors, distributed Postgres ledger, BSL operational tier,
on-prem deployment, SOC2 audit-trail export, AGT-style in-process
guard for defense-in-depth (see [`diagrams.md`](./diagrams.md) Set D
for the AGT integration diagrams).

This is a sales motion, not a developer-tools play. The
`/.well-known/capability-issuer` discovery endpoints, `did:ion`
resolution, and signed-evidence generation become relevant when a
security team is reviewing the system, not before.

The strong signal you've reached Stage 5 successfully: a customer
asks for a feature that's *already in the repository* but was
quarantined back in Stage 0 (`partner-issuer-sim`,
`db-token-service`, `storage-grant-service`, the cross-chain
anchor). That is the moment to un-quarantine, polish, and ship.

---

## Telemetry & gate instrumentation

The staged plan promises gates pulled by demand. Without
instrumentation that promise is wishful thinking. The design
constraints, in priority order:

1. **Opt-in, off by default.** First-run prompt, single yes/no, no
   nags. A security tool that exfiltrates by default is dead on
   arrival on HN.
2. **No payload contents, ever.** No tool names, no argument values,
   no file paths, no SQL fragments. Counts only. The schema is
   public and small enough to fit in the README.
3. **Documented schema** in `public/packages/mcp/TELEMETRY.md`. What's
   sent, where, why, how to disable.
4. **Anonymous install ID** (random UUID, regenerated per install).
   No machine fingerprint. No IP retention beyond aggregation.
5. **Local-mirror flag**: `EUNO_TELEMETRY_LOCAL=1` writes the
   telemetry payload to `~/.euno/telemetry.jsonl` and sends nothing.
   Builds trust and gives security-conscious users a way to inspect.

**What's measured (counts only):**
- Installs, version, OS family, Node major.
- Sessions started; sessions with ≥1 enforcement event.
- Per-condition-type denial counts (just the type name, e.g. `pathPattern`).
- Upstream MCP server name *if and only if* it matches a known
  open-source server (`@modelcontextprotocol/server-filesystem`,
  `server-postgres`, etc.). Otherwise reported as `custom`.
- CLI subcommand invocation counts.

These metrics directly feed the measurable gate conditions. Without
them, "Stage 1 → 2" is a feeling.

---

## Pricing & business model sketch

The prior plan said "managed gateway option (this is where revenue
begins)" and stopped. That's not enough — pricing shapes the Stage 3
service surface. A first-cut sketch (subject to design-partner
contact, not a commitment):

| Tier | Audience | Price hint | Boundary |
|---|---|---|---|
| OSS / self-host (`@euno/mcp` only) | Individual dev | Free | Local enforcement, no hosted services |
| OSS + self-host gateway (BSL) | Small team running their own infra | Free for non-competing use | All packages, BYO Redis / Postgres / KMS |
| Cloud Free | Hobby / evaluation | Free up to N agents and M enforcement events / month | Hosted gateway + API-key façade, 7-day audit retention |
| Cloud Team | Tech lead | Per-seat or per-enforcement-event | 90-day retention, kill-switch UI, SSO via OIDC |
| Cloud Enterprise | Engineering org | Contract | Long retention, on-prem option, evidence export, SOC2 attestation |

The wedge from Free → Team is **shared audit and shared kill-switch
across processes**. The wedge from Team → Enterprise is **compliance
artifacts** (signed evidence export, on-prem signing key, SSO with
SCIM).

Don't ship pricing in Stage 1. Do know what the curve looks like
before you ship Stage 3, because the curve dictates which Stage-3
features go in the hosted product vs. the self-host bundle.

---

## Buyer Map

| Stage | Buyer | Motivation |
|---|---|---|
| 1–2 | Individual developer | Fear of agent mistakes; curiosity; one bad demo |
| 3 | Tech lead / small team | Operational control, shared visibility, audit |
| 4 | Engineering org | Compliance, multi-agent coordination, identity |
| 5 | Enterprise | Security mandate, audit requirements, federation |

The current architecture optimizes for Stage 5. The current entry
point doesn't reach Stage 1. Stages 0–2 are the on-ramp. Build them
first, make the upgrade path frictionless via [§ schema parity](#policy-and-audit-schema-parity-non-negotiable),
let users pull themselves forward.

---

## Critical risks

**MCP spec churn.** MCP is pre-1.0 and the protocol revision changes
on the order of months. Pin `@modelcontextprotocol/sdk` and the
revision string; gate updates behind the integration tests. Without
this you'll ship a broken proxy the first week the spec rev moves.

**First-party MCP guardrails.** Anthropic and the MCP working group
will eventually ship some form of in-protocol guardrail (probably
weak, probably permission-prompt-shaped). Position euno as
*deterministic, code-defined, audit-grade* enforcement — adjacent to,
not competing with, an interactive permission prompt. The plan is
fine; the messaging needs to be ready.

**Existing MCP-proxy projects.** `mcp-proxy` and similar tools
already exist and are more popular than zero. The differentiator is
**typed conditions, denial-by-default on unknown condition types,
audit shape parity with a real production gateway**. Lead with that
in the README.

**LangChain.js API churn.** Pin to a tested version range. Test
against both stable and latest in CI from day one. Nothing about this
has changed from the prior plan.

**The Stage 1–2 ceiling.** Some developers will use local enforcement
forever and never need the gateway. That's fine — they're your
distribution channel, not necessarily your revenue. The ones who hit
the ceiling are your customers. The risk is conflating them in the
funnel and over-investing in a Stage 3 surface that the silent
majority will never use.

**Scope creep disguised as focus.** A token issuance UI, a database
proxy, a RAG access-control layer, an in-process AGT-style guard —
all reasonable, all wrong for Stage 1. The MVP is the MCP proxy with
the existing typed conditions. Nothing else.

**Selling the architecture before selling the value.**
"Capability-based security" and "zero-trust agents" are not search
terms developers use. *"Stop your agent from dropping your database"*
is. The repo description, README first paragraph, and Show HN title
all conform.

**Schema drift between the local DSL and the gateway manifest.** This
is the silent-killer risk. If a contributor adds a condition type to
`@euno/mcp` that doesn't exist in `@euno/common-core`, every Stage-3
upgrade for users of that condition type breaks. **Mechanical
prevention:** `@euno/mcp` has zero local condition definitions; it
imports them all from `@euno/common-core`. CI fails the build if it
doesn't.

**Minter key compromise.** The API-key minter in Stage 3 holds the
platform's managed signing key. Compromise of that key gives an
attacker the ability to mint valid tokens for any tenant, any policy,
on demand — bypassing every enforcement guarantee the rest of the
system provides. This is the single highest-value attack target in the
platform, and it does not have a local blast-radius limit. The minter
threat model (see [§ above](#minter-threat-model-required-before-stage-3-ships))
must be completed before Stage 3 ships. Shipping without it is the
security equivalent of running a certificate authority with no HSM.

**`common-core` breaking changes.** With the two-folder monorepo setup, a breaking
change to `common-core` silently breaks the private platform until a
coordinated update is done. Treat every `common-core` release like a
public library release: semver, CHANGELOG, migration note, and a platform-layer
upgrade PR opened before the public release is tagged.

**Quarantined packages becoming maintenance debt.** `partner-issuer-sim`,
`storage-grant-service`, `db-token-service`, `posture-emitter`,
`capability-issuer` (multi-region active/active component) will rot in
the freezer. Budget one week per quarter to rebase them on schema
changes, or accept that un-quarantining later will be a real project,
not a dust-off. Decide which up front.
