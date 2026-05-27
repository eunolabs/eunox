# eunox Documentation Index

Design and operational documentation for eunox. Docs are organized by purpose.

---

## 1. Start here

| Doc                                                                  | What it is                                                                       |
| -------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| [../README.md](../README.md)     | Project README — value prop, quick start, links.                                 |
| [repo-guide.md](./repo-guide.md) | Repository structure, build / lint / test, contributor setup.                    |
| [agent-sdk.md](./agent-sdk.md)   | Agent Runtime SDK: token management, tool invocation, attenuate/renew endpoints. |
| [architecture.md](./architecture.md) | Current package map and architecture overview.                               |
| [pricing.md](./pricing.md)       | Pricing tiers, feature matrix, and billing reference (OSS → Enterprise).         |

## 2. Architecture

| Doc                                            | What it is                                             |
| ---------------------------------------------- | ------------------------------------------------------ |
| [architecture.md](./architecture.md)           | C4 views, sequence diagrams, deployment view.          |
| [architecture-review.md](./architecture-review.md) | Formal architecture review and execution plan.     |
| [capability-model.md](./capability-model.md)   | Security model, capability design.                     |
| [enforcement.md](./enforcement.md)             | Policy decision point, enforcement guarantees.         |
| [diagrams.md](./diagrams.md)                   | Mermaid architecture diagrams.                         |
| [distributed-state.md](./distributed-state.md) | Redis-backed shared state for multi-agent deployments. |
| [multi-tenancy.md](./multi-tenancy.md)         | Multi-tenancy isolation model, boundaries, and threat model. |
| [federation-trust-lifecycle.md](./federation-trust-lifecycle.md) | Partner federation trust lifecycle (onboarding → revocation). |
| [db-token-architecture.md](./db-token-architecture.md) | Database credential issuance architecture.       |
| [storage-grant-architecture.md](./storage-grant-architecture.md) | Storage-grant issuance architecture.          |
| [audit-chain-architecture.md](./audit-chain-architecture.md)   | Audit chain architecture, single-writer vs per-replica trade-offs. |

## 3. Design references

| Doc                                                            | What it is                                                                        |
| -------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| [adapters.md](./adapters.md)                                   | Pluggable identity provider and token signer adapter pattern (Go implementation). |
| [capability-manifest-guide.md](./capability-manifest-guide.md) | Manifest authoring: structure, conditions, anti-patterns.                         |
| [schema-versioning.md](./schema-versioning.md)                 | Schema versioning, deployment ordering.                                           |
| [schema-migrations.md](./schema-migrations.md)                 | Database schema reference, migration conventions, CI validation.                  |
| [audit-retention-compliance.md](./audit-retention-compliance.md) | Audit retention policy, chain pruning, compliance targets (SOC 2, GDPR, HIPAA). |
| [policy-hot-reload.md](./policy-hot-reload.md)                 | Policy lifecycle, hot-reload mechanism, safe update procedures.                   |
| [multi-region-consistency.md](./multi-region-consistency.md)   | Multi-region consistency model and trade-offs.                                    |
| [posture-scaling.md](./posture-scaling.md)                     | Posture emitter scaling and CSPM plugin delivery.                                 |
| [sandboxing.md](./sandboxing.md)                               | Sandbox reference architecture.                                                   |

## 4. Deployment and operations

| Doc                                                        | What it is                                                               |
| ---------------------------------------------------------- | ------------------------------------------------------------------------ |
| [deployment.md](./deployment.md)                           | Build, configuration, and production requirements reference.             |
| [self-host.md](./self-host.md)                             | BYO-GW guide: running the full gateway stack on your own infrastructure. |
| [deploy-eks.md](./deploy-eks.md)                           | Amazon EKS deployment guide.                                             |
| [deploy-gke.md](./deploy-gke.md)                           | Google GKE deployment guide.                                             |
| [multi-cloud.md](./multi-cloud.md)                         | Multi-cloud deployment runbook.                                          |
| [secrets-aws.md](./secrets-aws.md)                         | AWS Secrets Manager integration.                                         |
| [secrets-gcp.md](./secrets-gcp.md)                         | GCP Secret Manager integration.                                          |
| [issuer-idp-setup.md](./issuer-idp-setup.md)               | Identity provider setup (Entra ID, Cognito, GCP).                        |
| [issuer-operator-runbook.md](./issuer-operator-runbook.md) | Issuer operational runbook.                                              |
| [admin-api-curl-recipes.md](./admin-api-curl-recipes.md)   | Admin API cURL recipes.                                                  |
| [upgrade-to-hosted.md](./upgrade-to-hosted.md)             | Migration from local to hosted enforcement.                              |

## 5. Hosted service

| Doc                                            | What it is                                                                        |
| ---------------------------------------------- | --------------------------------------------------------------------------------- |
| [hosted-service.md](./hosted-service.md)       | Hosted service architecture, subscription model, payment components, and execution plan. |
| [pricing.md](./pricing.md)                     | Pricing tiers, feature matrix, and billing reference (OSS → Enterprise).          |

## 6. Security

| Doc                                              | What it is                                              |
| ------------------------------------------------ | ------------------------------------------------------- |
| [security/](./security/)                         | Threat models, SOC2 mapping, sandbox architecture.      |
| [health-checks.md](./health-checks.md)           | Health check conventions, Kubernetes probes.            |
| [agent-runtime-security.md](./agent-runtime-security.md) | Agent runtime security model and controls.       |
| [redis-failure-modes.md](./redis-failure-modes.md) | Redis failure modes and gateway behaviour.            |
| [security-audit.md](./security-audit.md)         | External security audit findings and resolutions.       |
| [audit-retention-compliance.md](./audit-retention-compliance.md) | Audit retention policy, chain pruning, and compliance targets (SOC 2, GDPR, HIPAA). |
| [chaos-testing-strategy.md](./chaos-testing-strategy.md) | Chaos engineering strategy and failure injection scenarios. |
| [runbooks/](./runbooks/)                         | Operational runbooks (DR, key rotation, HMAC rotation). |

## 7. API specifications

| Doc                    | What it is                                        |
| ---------------------- | ------------------------------------------------- |
| [openapi/](./openapi/) | OpenAPI 3.0 specifications for all HTTP services. |

---

## Maintenance

Update the matching doc in the same PR when behaviour changes.
Update OpenAPI specs under [openapi/](./openapi/) for endpoint changes.

## Filename convention

All doc filenames in `docs/` use **lowercase kebab-case** (e.g. `deployment.md`,
`multi-tenancy.md`). Subdirectory files (`runbooks/`, `security/`, `openapi/`)
follow the same convention. `README.md` files are the only exception.
