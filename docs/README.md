# Euno Documentation Index

This directory holds the complete design, execution, and operational
documentation for **Euno** — the capability-native agent governance
system in this repository. The docs are organised below by purpose so
new readers can navigate without having to skim every file.

## Status legend

| Symbol | Meaning |
| ------ | ------- |
| ✅ | Implemented and covered by tests in `packages/` |
| ⚠️ | Partially implemented or with documented limitations |
| 🔄 | Designed / proposed but not yet implemented |
| 📚 | Reference / background material (not a build target) |

The status column below reflects the **current state of the code**, not
the historical state at the time each doc was first written. Where a
doc was written before its feature shipped, the doc itself has been
annotated in-place.

---

## 1. Start here

| Doc | What it is | Status |
| --- | ---------- | ------ |
| [`IMPLEMENTATION.md`](./IMPLEMENTATION.md) | High-level "what is Euno, what's in each package" overview. The fastest way to understand the system. | ✅ |
| [`../README.md`](../README.md) | Repository-level README: getting started, install, quickstart commands. | ✅ |

## 2. Problem space and architecture

These docs frame *why* Euno exists and the security model it implements.
They are the foundation everything else builds on.

| Doc | What it is | Status |
| --- | ---------- | ------ |
| [`ARCHITECTURE.md`](./ARCHITECTURE.md) | Consolidated architecture reference for the code in `packages/`: C4 context/container/component views, sequence diagrams (issuance, enforcement, attenuation, renewal, kill switch, posture), dataflow diagrams (control vs. data plane, cross-org), deployment view, and cross-cutting concerns. Authoritative for the implementation; see `diagrams.md` for the abstract/pattern view. | ✅ |
| [`IMPROVEMENTS_AND_REFACTORING.md`](./IMPROVEMENTS_AND_REFACTORING.md) | Evaluation of the architecture & design (scoring, strengths, prioritised issue list), refactoring proposals (R-1 … R-9), feature-shaped improvements (F-1 … F-10), and a four-wave execution plan with dependency graph and risk register. Companion to `NEXT_STEPS_BACKLOG.md` (which is feature-only). | ✅ |
| [`capability-model.md`](./capability-model.md) | Gap analysis of the capability model and the recommendations that closed those gaps. Includes an in-place implementation note pointing at the code that delivers each recommendation. | ✅ |
| [`enforcement.md`](./enforcement.md) | Why the gateway (not individual tools or the framework) is the policy decision point. | ✅ |
| [`sandboxing.md`](./sandboxing.md) | Reference architecture for the sandbox boundary: threat models, design principles, layered defence. | ✅ |
| [`did-iam-integration.md`](./did-iam-integration.md) | Rationale for combining decentralised identity (DIDs) with enterprise IAM in a single capability model. | ✅ |
| [`diagrams.md`](./diagrams.md) | Mermaid diagram set (engineering / product / executive views of the architecture). | 📚 |
| [`agt-integration-diagrams.md`](./agt-integration-diagrams.md) | Diagrams showing the layered defence between AGT (in-process semantic guard) and the gateway (cryptographic outer guard). | 📚 |
| [`agt-comparison.md`](./agt-comparison.md) | Comparison of agent governance approaches. | 📚 |
| [`cross-organizations.md`](./cross-organizations.md) | Cross-organization trust model (federation, delegation chains). Reference guidance for future federation adoption; not part of the current MVP runtime. | 📚 |

## 3. Design references

Detailed design for specific subsystems.

| Doc | What it is | Status |
| --- | ---------- | ------ |
| [`ADAPTER_PATTERN.md`](./ADAPTER_PATTERN.md) | Pluggable identity / signing adapter pattern. | ✅ |
| [`THIRD_PARTY_PROVIDERS.md`](./THIRD_PARTY_PROVIDERS.md) | How to register custom identity providers and signers (Okta, HSM, custom). | ✅ |
| [`FRAMEWORK_ADAPTERS.md`](./FRAMEWORK_ADAPTERS.md) | Design of the LangChain / MAF / CrewAI middleware in `packages/framework-adapters`. | ✅ |
| [`SCHEMA_VERSIONING.md`](./SCHEMA_VERSIONING.md) | Capability-token schema versioning, deployment ordering, and downgrade-attack mitigation. | ✅ |
| [`DISTRIBUTED_KILL_SWITCH.md`](./DISTRIBUTED_KILL_SWITCH.md) | Redis-backed kill switch for multi-replica gateways. | ✅ |
| [`DISTRIBUTED_REVOCATION.md`](./DISTRIBUTED_REVOCATION.md) | Redis-backed token revocation list for multi-replica gateways. | ✅ |
| [`FUTURE_DEVELOPMENT_IMPLEMENTATION.md`](./FUTURE_DEVELOPMENT_IMPLEMENTATION.md) | Implementation summary for DID resolution (`did:web` / `did:ion` / `did:key`) and specialised capability validators. | ✅ |
| [`openapi/`](./openapi/) | OpenAPI 3.0 specs for the Capability Issuer and Tool Gateway HTTP services. | ✅ |

## 4. Execution plan and sprint summaries

| Doc | What it is | Status |
| --- | ---------- | ------ |
| [`execution-plan.md`](./execution-plan.md) | Multi-cloud, multi-milestone execution plan (Milestones 1-4, Sprints 1-8). The single source of truth for *what* should ship and *when*. | ✅ planning doc |
| [`sandboxing-execution-plan.md`](./sandboxing-execution-plan.md) | 90-day roadmap specifically for sandbox hardening (MVP → pilot → production). | ✅ planning doc |
| [`SPRINT_1_2_SUMMARY.md`](./SPRINT_1_2_SUMMARY.md) | What landed in Sprints 1 & 2 (foundation, hardening). | ✅ |
| [`SPRINT_3_4_IMPLEMENTATION_SUMMARY.md`](./SPRINT_3_4_IMPLEMENTATION_SUMMARY.md) | What landed in Sprints 3 & 4 (delegation, renewal, sandbox hardening, kill switch, revocation, operational docs). Includes a status-reconciliation table at the top showing every "partial" item that has since shipped. | ✅ |
| [`SPRINT_5_PILOT_LAUNCH.md`](./SPRINT_5_PILOT_LAUNCH.md) | Operational readiness for production pilot (Bicep IaC, Sentinel rules, HA/HPA, Go/No-Go checklist, hypercare plan). | ✅ |
| [`SPRINT_6_STABILIZATION_HANDOFF.md`](./SPRINT_6_STABILIZATION_HANDOFF.md) | Pilot stabilization & hand-off: hypercare exit gate, bug-fix/tuning playbook, finalized Sentinel thresholds, ownership/on-call, final-pilot-report template. | ✅ |
| [`CAPABILITY_MANIFEST_GUIDE.md`](./CAPABILITY_MANIFEST_GUIDE.md) | Sprint 6 cookbook: required structure, four golden manifest patterns, wildcard rules, conditions, TTL guidance, anti-patterns, CLI tooling. | ✅ |
| [`CROSS_CLOUD_DEMO.md`](./CROSS_CLOUD_DEMO.md) | Sprint 6 cross-cloud demonstration runbook (AWS / GCP) using `infra/terraform/aws` and `infra/terraform/gcp`; proves Milestone 3 cross-cloud exit criterion. | ✅ |
| [`NEXT_STEPS_BACKLOG.md`](./NEXT_STEPS_BACKLOG.md) | Sprint 6 hand-off backlog for Sprints 7+ (self-service UI, dynamic policy engine, federation depth, standards contributions). | ✅ |

## 5. Operations and deployment

| Doc | What it is | Status |
| --- | ---------- | ------ |
| [`DEPLOYMENT.md`](./DEPLOYMENT.md) | Step-by-step Azure deployment guide (Resource Group → Key Vault → AAD → ACR → AKS). | ✅ |
| [`PILOT_PLAYBOOK.md`](./PILOT_PLAYBOOK.md) | Operational playbook for the 4-8 week pilot phase (pre-flight, monitoring, error handling, daily / weekly checklists). | ✅ |
| [`PRODUCTION_DEPLOYMENT_CHECKLIST.md`](./PRODUCTION_DEPLOYMENT_CHECKLIST.md) | The Go / No-Go gate for production: managed KMS, distributed Redis, kill-switch drill, audit evidence, admin-API hardening. | ✅ |
| [`INCIDENT_RESPONSE_RUNBOOK.md`](./INCIDENT_RESPONSE_RUNBOOK.md) | Runbook for runaway agents, leaked tokens, insider threats, and false positives. Includes severity tiers and quick-reference card. | ✅ |

---

## How to read these docs

1. New to Euno? Read **[`IMPLEMENTATION.md`](./IMPLEMENTATION.md)** for
   the system overview, then **[`ARCHITECTURE.md`](./ARCHITECTURE.md)**
   for the implementation-level architecture (diagrams, dataflows,
   sequence diagrams), then **[`capability-model.md`](./capability-model.md)**
   for the security model.
2. Adopting Euno from an agent framework? Read
   **[`FRAMEWORK_ADAPTERS.md`](./FRAMEWORK_ADAPTERS.md)** and
   **[`enforcement.md`](./enforcement.md)**.
3. Deploying to production? Read
   **[`DEPLOYMENT.md`](./DEPLOYMENT.md)** then walk
   **[`PRODUCTION_DEPLOYMENT_CHECKLIST.md`](./PRODUCTION_DEPLOYMENT_CHECKLIST.md)**.
4. Running an incident? Open
   **[`INCIDENT_RESPONSE_RUNBOOK.md`](./INCIDENT_RESPONSE_RUNBOOK.md)**.
5. Evaluating the project's roadmap or sprint deltas? Read
   **[`execution-plan.md`](./execution-plan.md)** and the matching
   `SPRINT_*_SUMMARY.md` files.
6. Planning the next quarter of engineering work (refactors + hardening,
   not just new features)? Read
   **[`IMPROVEMENTS_AND_REFACTORING.md`](./IMPROVEMENTS_AND_REFACTORING.md)**
   alongside **[`NEXT_STEPS_BACKLOG.md`](./NEXT_STEPS_BACKLOG.md)**.

## Maintenance

When you change behaviour in `packages/`:

- If the change matches an existing doc, update the doc in the same PR.
- If the change exposes a new HTTP endpoint or changes a payload, update
  the matching file under [`openapi/`](./openapi/) so the generated
  clients and the spec keep parity.
- If the change closes a gap that an existing doc currently calls out
  as "partial" or "future", update the status note in that doc rather
  than leaving the doc to drift.
- If the change adds a substantial new package, link it from this index
  and from [`IMPLEMENTATION.md`](./IMPLEMENTATION.md).
- If a previously deferred feature ships, add a short reconciliation note
  near the original claim and update the matching sprint summary so readers
  can distinguish historical plan language from current code status.
