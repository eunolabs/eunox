# eunox Documentation Index

Design and operational documentation for eunox. Docs are organized by purpose.

---

## 1. Start here

| Doc | What it is |
| --- | ---------- |
| [../README.md](../README.md) | Project README — value prop, quick start, links. |
| [repo-guide.md](./repo-guide.md) | Repository structure, build / lint / test, contributor setup. |
| [agent-sdk.md](./agent-sdk.md) | Agent Runtime SDK: token management, tool invocation, attenuate/renew endpoints. |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | Current package map and architecture overview. |
| [golang-reimplementation-plan.md](./golang-reimplementation-plan.md) | Go re-implementation execution plan (all stages). |
| [pricing.md](./pricing.md) | Pricing tiers, feature matrix, and billing reference (OSS → Enterprise). |

## 2. Architecture

| Doc | What it is |
| --- | ---------- |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | C4 views, sequence diagrams, deployment view. |
| [capability-model.md](./capability-model.md) | Security model, capability design. |
| [enforcement.md](./enforcement.md) | Policy decision point, enforcement guarantees. |
| [diagrams.md](./diagrams.md) | Mermaid architecture diagrams. |
| [DISTRIBUTED_STATE.md](./DISTRIBUTED_STATE.md) | Redis-backed shared state for multi-agent deployments. |

## 3. Design references

| Doc | What it is |
| --- | ---------- |
| [ADAPTERS.md](./ADAPTERS.md) | Pluggable identity provider and token signer adapter pattern (Go implementation). |
| [CAPABILITY_MANIFEST_GUIDE.md](./CAPABILITY_MANIFEST_GUIDE.md) | Manifest authoring: structure, conditions, anti-patterns. |
| [SCHEMA_VERSIONING.md](./SCHEMA_VERSIONING.md) | Schema versioning, deployment ordering. |
| [sandboxing.md](./sandboxing.md) | Sandbox reference architecture. |
| [stage-3-design.md](./stage-3-design.md) | Hosted gateway design: KMS, Postgres, Redis, API-key scheme, enforcer wire protocol. |
| [stage-4-design.md](./stage-4-design.md) | Capability issuer + identity federation design. |
| [stage-5-design.md](./stage-5-design.md) | Enterprise platform and full-vision design. |
| [stage-3-gateway-protocol.md](./stage-3-gateway-protocol.md) | Gateway enforcement wire protocol specification. |

## 4. Deployment and operations

| Doc | What it is |
| --- | ---------- |
| [self-host.md](./self-host.md) | BYO-GW guide: running the full gateway stack on your own infrastructure. |
| [deploy-eks.md](./deploy-eks.md) | Amazon EKS deployment guide. |
| [deploy-gke.md](./deploy-gke.md) | Google GKE deployment guide. |
| [multi-cloud.md](./multi-cloud.md) | Multi-cloud deployment runbook. |
| [secrets-aws.md](./secrets-aws.md) | AWS Secrets Manager integration. |
| [secrets-gcp.md](./secrets-gcp.md) | GCP Secret Manager integration. |
| [issuer-idp-setup.md](./issuer-idp-setup.md) | Identity provider setup (Entra ID, Cognito, GCP). |
| [issuer-operator-runbook.md](./issuer-operator-runbook.md) | Issuer operational runbook. |
| [ADMIN_API_CURL_RECIPES.md](./ADMIN_API_CURL_RECIPES.md) | Admin API cURL recipes. |
| [upgrade-to-hosted.md](./upgrade-to-hosted.md) | Migration from local to hosted enforcement. |

## 5. Security

| Doc | What it is |
| --- | ---------- |
| [security/](./security/) | Threat models, SOC2 mapping, sandbox architecture. |
| [runbooks/](./runbooks/) | Operational runbooks (pepper rotation, HMAC rotation). |

## 6. Architecture reviews

| Doc | What it is |
| --- | ---------- |
| [architecture-review-2026-05.md](./architecture-review-2026-05.md) | Stage 3 architecture review. |
| [architecture-review-2026-05-v2.md](./architecture-review-2026-05-v2.md) | Post-hardening review. |
| [architecture-review-2026-05-stage4.md](./architecture-review-2026-05-stage4.md) | Stage 4 review. |
| [architecture-follow-up-tasks-2026-05.md](./architecture-follow-up-tasks-2026-05.md) | Follow-up task list. |
| [architecture-follow-up-tasks-2026-05-v2.md](./architecture-follow-up-tasks-2026-05-v2.md) | Follow-up task list v2. |
| [change-risk-report-2026-05.md](./change-risk-report-2026-05.md) | Change risk assessment. |
| [release-readiness-report-stage5.md](./release-readiness-report-stage5.md) | Stage 5 release readiness. |

## 7. Planning and roadmap

| Doc | What it is |
| --- | ---------- |
| [multi-cloud-plan.md](./multi-cloud-plan.md) | Multi-cloud support plan. |
| [stage-0-freeze.md](./stage-0-freeze.md) | Platform package freeze policy. |
| [stage3executionplan.md](./stage3executionplan.md) | Stage 3 execution plan. |
| [stage4executionplan.md](./stage4executionplan.md) | Stage 4 execution plan. |
| [stage5executionplan.md](./stage5executionplan.md) | Stage 5 execution plan. |

## 8. API specifications

| Doc | What it is |
| --- | ---------- |
| [openapi/](./openapi/) | OpenAPI 3.0 specifications for all HTTP services. |

---

## Maintenance

Update the matching doc in the same PR when behaviour changes.
Update OpenAPI specs under [openapi/](./openapi/) for endpoint changes.
