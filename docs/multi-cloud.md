# Multi-Cloud Runbook Index

This page is the navigation hub for Euno multi-cloud deployments.  Use it to
find the right guide for your cloud provider and task.

---

## Cloud-provider deployment guides

| Cloud | Kubernetes service | Guide |
|---|---|---|
| AWS | Amazon EKS | [docs/deploy-eks.md](deploy-eks.md) |
| GCP | Google Kubernetes Engine | [docs/deploy-gke.md](deploy-gke.md) |
| Azure | Azure Kubernetes Service | `docs/deploy-aks.md` (coming in a future release) |

---

## Secrets management

| Cloud | Guide |
|---|---|
| AWS Secrets Manager + ESO/ASCP | [docs/secrets-aws.md](secrets-aws.md) |
| GCP Secret Manager + ESO/Add-on | [docs/secrets-gcp.md](secrets-gcp.md) |
| Azure Key Vault + ESO/CSI | `docs/secrets-azure.md` (coming in a future release) |

---

## Infrastructure-as-code

| Cloud | IaC tool | Location |
|---|---|---|
| AWS | CDK (TypeScript) | [`infra/aws/cdk/`](../infra/aws/cdk/) |
| AWS | Terraform (modular) | [`infra/aws/terraform/`](../infra/aws/terraform/) |
| AWS | Terraform (monolithic, Sprint 1) | [`infra/terraform/aws/`](../infra/terraform/aws/) |
| GCP | Terraform | [`infra/terraform/gcp/`](../infra/terraform/gcp/) |
| Azure | Bicep | [`infra/bicep/main.bicep`](../infra/bicep/main.bicep) |

---

## Helm chart — cloud-specific values

| Cloud | Values override file |
|---|---|
| AWS / EKS | [`k8s/helm/euno/values-aws.yaml`](../k8s/helm/euno/values-aws.yaml) |
| GCP / GKE | [`k8s/helm/euno/values-gcp.yaml`](../k8s/helm/euno/values-gcp.yaml) |
| Azure / AKS | [`k8s/helm/euno/values-azure.yaml`](../k8s/helm/euno/values-azure.yaml) |

Apply a cloud-specific values file on top of the base:

```bash
# AWS
helm install euno ./k8s/helm/euno \
  --namespace euno \
  -f k8s/helm/euno/values.yaml \
  -f k8s/helm/euno/values-aws.yaml

# GCP
helm install euno ./k8s/helm/euno \
  --namespace euno \
  -f k8s/helm/euno/values.yaml \
  -f k8s/helm/euno/values-gcp.yaml

# Azure
helm install euno ./k8s/helm/euno \
  --namespace euno \
  -f k8s/helm/euno/values.yaml \
  -f k8s/helm/euno/values-azure.yaml
```

---

## Identity provider setup

| Cloud | Identity service | Guide |
|---|---|---|
| AWS | Amazon Cognito (+ IAM Identity Center SCIM) | [docs/issuer-idp-setup.md §10](issuer-idp-setup.md) |
| GCP | Google Workspace (+ SCIM bridge) | [docs/issuer-idp-setup.md §11](issuer-idp-setup.md) |
| Azure | Microsoft Entra ID (+ SCIM) | `docs/issuer-idp-setup.md §12` (coming in a future release) |

---

## Planning and tracking

See [`docs/multi-cloud-plan.md`](multi-cloud-plan.md) for the full
implementation checklist with per-phase status.

---

## Cross-cloud notes

### OCSF audit event format

All cloud providers receive OCSF API Activity events (class_uid 6003) from
the tool-gateway.  The mapping from OCSF to the cloud-native SIEM:

| Cloud | SIEM | Guide section |
|---|---|---|
| AWS | Security Hub / CloudWatch Logs Insights | `docs/deploy-eks.md §Observability` |
| GCP | Security Command Center | `docs/deploy-gke.md §Observability` |
| Azure | Microsoft Sentinel | `docs/deploy-aks.md §Observability` (coming) |

### HA Redis

Each cloud provider requires a different Redis HA configuration:

| Cloud | Service | Notes |
|---|---|---|
| AWS | ElastiCache Replication Group | TLS + auth token; `rediss://:<token>@<primary>:6380` |
| GCP | Memorystore | STANDARD_HA tier; in-transit encryption enabled |
| Azure | Azure Cache for Redis | Premium tier; port 6380 (TLS); Entra auth recommended |

Set `REDIS_URL`, `REVOCATION_REDIS_URL`, `KILL_SWITCH_REDIS_URL`, and
`CALL_COUNTER_REDIS_URL` to HA-capable endpoints.  See
[`docs/self-host.md §Redis HA`](self-host.md) for the production Redis HA
validation requirements.
