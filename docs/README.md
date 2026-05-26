# eunox Documentation Index

Design and operational documentation for eunox. Docs are organized by purpose.

---

## 1. Start here

| Doc                                                                  | What it is                                                                       |
| -------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| [../README.md](../README.md)     | Project README — value prop, quick start, links.                                 |
| [repo-guide.md](./repo-guide.md) | Repository structure, build / lint / test, contributor setup.                    |
| [agent-sdk.md](./agent-sdk.md)   | Agent Runtime SDK: token management, tool invocation, attenuate/renew endpoints. |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | Current package map and architecture overview.                               |
| [pricing.md](./pricing.md)       | Pricing tiers, feature matrix, and billing reference (OSS → Enterprise).         |

## 2. Architecture

| Doc                                            | What it is                                             |
| ---------------------------------------------- | ------------------------------------------------------ |
| [ARCHITECTURE.md](./ARCHITECTURE.md)           | C4 views, sequence diagrams, deployment view.          |
| [ARCHITECTURE_REVIEW.md](./ARCHITECTURE_REVIEW.md) | Formal architecture review and execution plan.     |
| [capability-model.md](./capability-model.md)   | Security model, capability design.                     |
| [enforcement.md](./enforcement.md)             | Policy decision point, enforcement guarantees.         |
| [diagrams.md](./diagrams.md)                   | Mermaid architecture diagrams.                         |
| [DISTRIBUTED_STATE.md](./DISTRIBUTED_STATE.md) | Redis-backed shared state for multi-agent deployments. |
| [MULTI_TENANCY.md](./MULTI_TENANCY.md)         | Multi-tenancy isolation model, boundaries, and threat model. |
| [FEDERATION_TRUST_LIFECYCLE.md](./FEDERATION_TRUST_LIFECYCLE.md) | Partner federation trust lifecycle (onboarding → revocation). |

## 3. Design references

| Doc                                                            | What it is                                                                        |
| -------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| [ADAPTERS.md](./ADAPTERS.md)                                   | Pluggable identity provider and token signer adapter pattern (Go implementation). |
| [CAPABILITY_MANIFEST_GUIDE.md](./CAPABILITY_MANIFEST_GUIDE.md) | Manifest authoring: structure, conditions, anti-patterns.                         |
| [SCHEMA_VERSIONING.md](./SCHEMA_VERSIONING.md)                 | Schema versioning, deployment ordering.                                           |
| [SCHEMA_MIGRATIONS.md](./SCHEMA_MIGRATIONS.md)                 | Database schema reference, migration conventions, CI validation.                  |
| [AUDIT_CHAIN_ARCHITECTURE.md](./AUDIT_CHAIN_ARCHITECTURE.md)   | Audit chain architecture, single-writer vs per-replica trade-offs.                |
| [AUDIT_RETENTION_COMPLIANCE.md](./AUDIT_RETENTION_COMPLIANCE.md) | Audit retention policy, chain pruning, compliance targets (SOC 2, GDPR, HIPAA). |
| [POLICY_HOT_RELOAD.md](./POLICY_HOT_RELOAD.md)                 | Policy lifecycle, hot-reload mechanism, safe update procedures.                   |
| [sandboxing.md](./sandboxing.md)                               | Sandbox reference architecture.                                                   |

## 4. Deployment and operations

| Doc                                                        | What it is                                                               |
| ---------------------------------------------------------- | ------------------------------------------------------------------------ |
| [self-host.md](./self-host.md)                             | BYO-GW guide: running the full gateway stack on your own infrastructure. |
| [deploy-eks.md](./deploy-eks.md)                           | Amazon EKS deployment guide.                                             |
| [deploy-gke.md](./deploy-gke.md)                           | Google GKE deployment guide.                                             |
| [multi-cloud.md](./multi-cloud.md)                         | Multi-cloud deployment runbook.                                          |
| [secrets-aws.md](./secrets-aws.md)                         | AWS Secrets Manager integration.                                         |
| [secrets-gcp.md](./secrets-gcp.md)                         | GCP Secret Manager integration.                                          |
| [issuer-idp-setup.md](./issuer-idp-setup.md)               | Identity provider setup (Entra ID, Cognito, GCP).                        |
| [issuer-operator-runbook.md](./issuer-operator-runbook.md) | Issuer operational runbook.                                              |
| [ADMIN_API_CURL_RECIPES.md](./ADMIN_API_CURL_RECIPES.md)   | Admin API cURL recipes.                                                  |
| [upgrade-to-hosted.md](./upgrade-to-hosted.md)             | Migration from local to hosted enforcement.                              |

## 5. Security

| Doc                      | What it is                                             |
| ------------------------ | ------------------------------------------------------ |
| [security/](./security/) | Threat models, SOC2 mapping, sandbox architecture.     |
| [HEALTH_CHECKS.md](./HEALTH_CHECKS.md) | Health check conventions, Kubernetes probes.  |
| [runbooks/](./runbooks/) | Operational runbooks (DR, key rotation, HMAC rotation). |

## 8. API specifications

| Doc                    | What it is                                        |
| ---------------------- | ------------------------------------------------- |
| [openapi/](./openapi/) | OpenAPI 3.0 specifications for all HTTP services. |

---

## Maintenance

Update the matching doc in the same PR when behaviour changes.
Update OpenAPI specs under [openapi/](./openapi/) for endpoint changes.
