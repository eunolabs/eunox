# Euno Documentation Index

This directory holds the design and operational documentation for
**Euno** — the capability-native agent governance system in this
repository. The docs are organised below by purpose so new readers can
navigate without having to skim every file.

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

| Doc | What it is | Status |
| --- | ---------- | ------ |
| [`ARCHITECTURE.md`](./ARCHITECTURE.md) | Consolidated architecture reference for the code in `packages/`: C4 context/container/component views, sequence diagrams (issuance, enforcement, attenuation, renewal, kill switch, posture), dataflow diagrams (control vs. data plane, cross-org), deployment view, and cross-cutting concerns. | ✅ |
| [`capability-model.md`](./capability-model.md) | Gap analysis of the capability model and the recommendations that closed those gaps. Includes in-place implementation notes pointing at the code that delivers each recommendation. | ✅ |
| [`enforcement.md`](./enforcement.md) | Why the gateway (not individual tools or the framework) is the policy decision point; network-level enforcement strategies and OS-level sandbox controls. | ✅ |
| [`sandboxing.md`](./sandboxing.md) | Reference architecture for the sandbox boundary: threat models, design principles, layered defence, Kubernetes and non-Kubernetes implementations. | ✅ |
| [`diagrams.md`](./diagrams.md) | Mermaid diagram set (engineering / product / executive views of the architecture, plus AGT integration diagrams). | 📚 |
| [`mvp.md`](./mvp.md) | Strategic direction: current MVP scope, targeted enhancements, and production-readiness roadmap. | 📚 |

## 3. Design references

Detailed design for specific subsystems.

| Doc | What it is | Status |
| --- | ---------- | ------ |
| [`ADAPTERS.md`](./ADAPTERS.md) | Pluggable identity / signing adapter pattern, built-in providers (Azure, AWS, GCP, DID), and how to register custom adapters. | ✅ |
| [`FRAMEWORK_ADAPTERS.md`](./FRAMEWORK_ADAPTERS.md) | Design of the LangChain / MAF / CrewAI middleware in `packages/framework-adapters`. | ✅ |
| [`SCHEMA_VERSIONING.md`](./SCHEMA_VERSIONING.md) | Capability-token schema versioning, deployment ordering, and downgrade-attack mitigation. | ✅ |
| [`DISTRIBUTED_STATE.md`](./DISTRIBUTED_STATE.md) | Redis-backed kill switch and token revocation for multi-replica gateways: architecture, failure semantics, configuration, monitoring. | ✅ |
| [`CAPABILITY_MANIFEST_GUIDE.md`](./CAPABILITY_MANIFEST_GUIDE.md) | Canonical guide to writing capability manifests: required structure, golden patterns, wildcard rules, conditions, TTL guidance, anti-patterns, CLI tooling. | ✅ |
| [`SCALING.md`](./SCALING.md) | Horizontal gateway sharding (H-1, eliminates Redis hot-key pressure) and multi-region active/active deployment (F-7). | ✅ |
| [`openapi/`](./openapi/) | OpenAPI 3.0 specs for the Capability Issuer and Tool Gateway HTTP services. | ✅ |

## 4. Operations and deployment

| Doc | What it is | Status |
| --- | ---------- | ------ |
| [`DEPLOYMENT.md`](./DEPLOYMENT.md) | Step-by-step Azure deployment guide (Resource Group → Key Vault → AAD → ACR → AKS). | ✅ |
| [`PILOT_PLAYBOOK.md`](./PILOT_PLAYBOOK.md) | Operational playbook for the 4-8 week pilot phase (pre-flight, monitoring, error handling, daily / weekly checklists). | ✅ |
| [`PRODUCTION_DEPLOYMENT_CHECKLIST.md`](./PRODUCTION_DEPLOYMENT_CHECKLIST.md) | The Go / No-Go gate for production: managed KMS, distributed Redis, kill-switch drill, audit evidence, admin-API hardening. | ✅ |
| [`INCIDENT_RESPONSE_RUNBOOK.md`](./INCIDENT_RESPONSE_RUNBOOK.md) | Runbook for runaway agents, leaked tokens, insider threats, and false positives. Includes severity tiers and quick-reference card. | ✅ |
| [`OPERATOR_RUNBOOK_PARTNER_DIDS.md`](./OPERATOR_RUNBOOK_PARTNER_DIDS.md) | Operational procedures for onboarding and managing partner DIDs. | ✅ |

---

## How to read these docs

1. New to Euno? Read **[`IMPLEMENTATION.md`](./IMPLEMENTATION.md)** for
   the system overview, then **[`ARCHITECTURE.md`](./ARCHITECTURE.md)**
   for the implementation-level architecture, then
   **[`capability-model.md`](./capability-model.md)** for the security model.
2. Adopting Euno from an agent framework? Read
   **[`FRAMEWORK_ADAPTERS.md`](./FRAMEWORK_ADAPTERS.md)** and
   **[`enforcement.md`](./enforcement.md)**.
3. Deploying to production? Read
   **[`DEPLOYMENT.md`](./DEPLOYMENT.md)** then walk
   **[`PRODUCTION_DEPLOYMENT_CHECKLIST.md`](./PRODUCTION_DEPLOYMENT_CHECKLIST.md)**.
4. Scaling beyond a single replica or to multiple regions? Read
   **[`SCALING.md`](./SCALING.md)**.
5. Running an incident? Open
   **[`INCIDENT_RESPONSE_RUNBOOK.md`](./INCIDENT_RESPONSE_RUNBOOK.md)**.

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

