# Multi-Cloud Deployment Runbook

This document is the **index** for all cloud-provider-specific deployment,
secrets management, observability, and identity-provider guides for eunox.
It also describes the migration path from a single-cloud deployment to a
multi-cloud architecture.

---

## Quick comparison table

| Capability             | Azure                              | AWS                               | GCP                                                                 |
| ---------------------- | ---------------------------------- | --------------------------------- | ------------------------------------------------------------------- |
| Identity provider      | Entra ID (`azure-ad`)              | Cognito (`aws-cognito`)           | Cloud Identity (`gcp-identity`)                                     |
| Token signing (KMS)    | Key Vault (`azure-keyvault`)       | KMS (`aws-kms`)                   | Cloud KMS (`gcp-cloudkms`)                                          |
| Secrets management     | Key Vault secrets + ESO/CSI        | Secrets Manager + ESO/ASCP        | Secret Manager + ESO/Add-on                                         |
| Audit ledger storage   | Azure Blob (`azure-blob`)          | S3 Object Lock (`s3`)             | GCS (`gcs`) with `temporaryHold`                                    |
| Container registry     | ACR                                | ECR                               | Artifact Registry                                                   |
| Kubernetes platform    | AKS                                | EKS                               | GKE                                                                 |
| Pod identity           | Azure Workload Identity            | IRSA                              | GKE Workload Identity                                               |
| Managed DB             | Azure Database for PostgreSQL      | RDS for PostgreSQL                | Cloud SQL for PostgreSQL                                            |
| Managed Redis          | Azure Cache for Redis              | ElastiCache for Redis             | Memorystore for Redis                                               |
| Observability          | Azure Monitor / Microsoft Sentinel | CloudWatch / Security Hub         | Cloud Monitoring / Security Command Center                          |
| Helm values file       | `values-azure.yaml`                | `values-aws.yaml`                 | `values-gcp.yaml`                                                   |
| Infrastructure-as-code | `infra/bicep/`                     | `infra/terraform/aws/` (monolith) | `infra/terraform/gcp/` (monolith), `infra/gcp/terraform/` (modular) |

---

## Per-cloud deployment guides

### Azure

| Guide                                                                     | Description                                               |
| ------------------------------------------------------------------------- | --------------------------------------------------------- |
| [`infra/bicep/main.bicep`](../infra/bicep/main.bicep)                     | Azure Bicep template — AKS, Key Vault, ACR, Log Analytics |
| [`k8s/helm/eunox/values-azure.yaml`](../k8s/helm/eunox/values-azure.yaml) | Helm overrides for AKS                                    |
| [`docs/DEPLOYMENT.md §Stage-5`](DEPLOYMENT.md)                            | Full on-premises and AKS deployment guide                 |
| [`docs/issuer-idp-setup.md §1`](issuer-idp-setup.md)                      | Azure AD / Entra ID setup                                 |
| [`docs/issuer-idp-setup.md §9`](issuer-idp-setup.md)                      | Entra ID SCIM bridge                                      |

### AWS

| Guide                                                                 | Description                                             |
| --------------------------------------------------------------------- | ------------------------------------------------------- |
| [`infra/terraform/aws/main.tf`](../infra/terraform/aws/main.tf)       | AWS Terraform module — EKS, KMS, RDS, ElastiCache, ECR  |
| [`k8s/helm/eunox/values-aws.yaml`](../k8s/helm/eunox/values-aws.yaml) | Helm overrides for EKS                                  |
| [`docs/deploy-eks.md`](deploy-eks.md)                                 | Full EKS deployment guide (IRSA, ALB, CloudWatch)       |
| [`docs/secrets-aws.md`](secrets-aws.md)                               | AWS Secrets Manager integration (ESO, ASCP, native SDK) |
| [`docs/issuer-idp-setup.md §3`](issuer-idp-setup.md)                  | AWS Cognito setup                                       |
| [`docs/issuer-idp-setup.md §10`](issuer-idp-setup.md)                 | Cognito SCIM bridge (IAM Identity Center)               |

### GCP

| Guide                                                                 | Description                                                                           |
| --------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| [`infra/terraform/gcp/main.tf`](../infra/terraform/gcp/main.tf)       | GCP Terraform monolith — GKE, Cloud KMS, Artifact Registry                            |
| [`infra/gcp/terraform/`](../infra/gcp/terraform/)                     | GCP modular Terraform (network, compute, data, security, observability)               |
| [`infra/gcp/config-connector/`](../infra/gcp/config-connector/)       | Config Connector KRM manifests (Cloud SQL, Memorystore, Cloud KMS, Artifact Registry) |
| [`k8s/helm/eunox/values-gcp.yaml`](../k8s/helm/eunox/values-gcp.yaml) | Helm overrides for GKE                                                                |
| [`docs/deploy-gke.md`](deploy-gke.md)                                 | Full GKE deployment guide (Workload Identity, GKE Ingress, Cloud Monitoring)          |
| [`docs/secrets-gcp.md`](secrets-gcp.md)                               | GCP Secret Manager integration (ESO, Add-on)                                          |
| [`docs/issuer-idp-setup.md §4`](issuer-idp-setup.md)                  | GCP Cloud Identity setup                                                              |
| [`docs/issuer-idp-setup.md §11`](issuer-idp-setup.md)                 | Google Workspace SCIM bridge                                                          |

---

## Shared infrastructure

The following components are provider-agnostic and work across all three clouds:

| Component               | Description                                                                                                                   |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `SecretStore` interface | Abstraction over Key Vault / Secrets Manager / Secret Manager (see [`docs/ADAPTERS.md §Secret Store`](ADAPTERS.md))           |
| `ObjectStore` interface | Abstraction over Azure Blob / S3 / GCS for the cross-chain anchor (see [`docs/ADAPTERS.md §Object Store`](ADAPTERS.md))       |
| Helm umbrella chart     | [`k8s/helm/eunox/`](../k8s/helm/eunox/) with provider-specific values files                                                   |
| Air-gap image bundle    | [`k8s/air-gap-images.txt`](../k8s/air-gap-images.txt) + [`scripts/pull-air-gap-images.sh`](../scripts/pull-air-gap-images.sh) |

---

## Migration paths

### Single-cloud to multi-cloud (primary + cross-chain anchor)

The most common multi-cloud pattern is a **primary cloud deployment with a
cross-chain anchor in a secondary cloud** for disaster recovery and SOC 2
CC7.4 compliance.

**Example: Azure primary + S3 cross-chain anchor**

```yaml
# values-azure.yaml (or as --set overrides)
gateway:
  env:
    SIGNING_PROVIDER: azure-keyvault
    AZURE_KEYVAULT_URL: "https://my-eunox-kv.vault.azure.net/"
    # Cross-chain anchor: S3 Object Lock
    ENABLE_CROSS_CHAIN_ANCHOR: "true"
    AUDIT_LEDGER_OBJECT_STORE_PROVIDER: s3
    AUDIT_LEDGER_S3_BUCKET: "eunox-audit-anchor-prod"
    AUDIT_LEDGER_S3_REGION: "us-east-1"
```

**Example: GCP primary + Azure Blob cross-chain anchor**

```yaml
# values-gcp.yaml additions
gateway:
  env:
    SIGNING_PROVIDER: gcp-cloudkms
    # Cross-chain anchor: Azure Blob
    ENABLE_CROSS_CHAIN_ANCHOR: "true"
    AUDIT_LEDGER_OBJECT_STORE_PROVIDER: azure-blob
    AUDIT_LEDGER_AZURE_CONTAINER: "eunox-audit-anchor-prod"
    AUDIT_LEDGER_AZURE_ACCOUNT_NAME: "myeunosa"
```

### Migrating secrets management from environment variables to native SDK

1. Deploy the initial workload with secrets in `secretEnv:` (Kubernetes Secret).
2. Create the equivalent secrets in Secrets Manager / Secret Manager / Key Vault.
3. Set `SECRET_STORE_PROVIDER=aws-secrets-manager` (or `gcp-secretmanager` /
   `azure-keyvault`) and add the provider-specific lookup env vars.
4. Remove `secretEnv:` entries one at a time, verifying the pod restarts
   cleanly after each removal.

See [`docs/ADAPTERS.md §Secret Store`](ADAPTERS.md) for the full `SecretStore`
interface documentation and supported providers.

---

## Observability integration

Each cloud has a corresponding observability guide with Prometheus → metrics
forwarding, OCSF audit event → security platform mapping, and log-based
denial histogram queries:

| Cloud | Metrics forwarding                         | Security events                   | Log queries              |
| ----- | ------------------------------------------ | --------------------------------- | ------------------------ |
| Azure | Azure Monitor (Container Insights)         | Microsoft Sentinel analytic rules | Log Analytics KQL        |
| AWS   | CloudWatch (ADOT Collector)                | Security Hub findings             | CloudWatch Logs Insights |
| GCP   | Cloud Monitoring (OpenTelemetry Collector) | Security Command Center           | Cloud Logging            |

For denial histogram queries by `denial_reason`, see the relevant deployment
guide (`docs/deploy-eks.md §7`, `docs/deploy-gke.md §7`).

---

## See also

- [`docs/multi-cloud-plan.md`](multi-cloud-plan.md) — implementation plan and progress
- [`docs/ADAPTERS.md`](ADAPTERS.md) — adapter interface documentation
- [`docs/DEPLOYMENT.md`](DEPLOYMENT.md) — on-premises and self-hosted guide
- [`docs/self-host.md`](self-host.md) — self-hosted deployment guide (Stage 5)
