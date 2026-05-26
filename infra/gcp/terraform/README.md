# Euno — GCP Terraform Modules

This directory contains the **modular Terraform layout** for deploying Euno on
Google Cloud Platform (GCP).  Each sub-module manages one infrastructure
concern and can be applied independently or composed together via the root
module (`main.tf` in this directory).

```
infra/gcp/terraform/
├── README.md          ← this file
├── main.tf            ← root module (calls all sub-modules)
├── terraform.tfvars.example
├── network/           ← VPC, subnets, Cloud NAT
│   └── main.tf
├── compute/           ← GKE cluster, Workload Identity, autoscaling
│   └── main.tf
├── data/              ← Cloud SQL (Postgres), Memorystore Redis
│   └── main.tf
├── security/          ← Cloud KMS keyring, Secret Manager, IAM bindings
│   └── main.tf
└── observability/     ← Cloud Monitoring dashboards, alerting policies
    └── main.tf
```

> **Relationship to `infra/terraform/gcp/`**
>
> The monolithic module at `infra/terraform/gcp/main.tf` was the Sprint-1
> baseline that provisions the core GKE/KMS/Logging stack.  This directory
> provides a **production-ready modular layout** with additional managed
> databases (`data/`), secrets (`security/`), and observability resources
> (`observability/`) that are not included in the Sprint-1 baseline.

---

## Prerequisites

| Tool | Minimum version |
|---|---|
| Terraform | 1.5.0 |
| `gcloud` CLI | 455.0.0 |
| `kubectl` | 1.28 |
| `helm` | 3.14 |

Authenticate with Application Default Credentials (ADC) before applying:

```bash
gcloud auth application-default login
gcloud config set project <YOUR_PROJECT_ID>
```

---

## Quick start

### 1. Clone the repository and navigate to this directory

```bash
git clone https://github.com/edgeobs/eunox.git
cd eunox/infra/gcp/terraform
```

### 2. Copy the example variables file and customize it

```bash
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars
```

At minimum set:

```hcl
project_id  = "my-gcp-project-id"
gcp_region  = "us-central1"
name_prefix = "euno"
environment = "prod"
```

### 3. Initialize Terraform

```bash
terraform init
```

Terraform downloads the `hashicorp/google` and `hashicorp/random` providers and
creates the `.terraform/` lock file.

### 4. Review the execution plan

```bash
terraform plan -out=tfplan
```

Review every resource Terraform intends to create.  Pay particular attention to:

- **`module.network`** — VPC CIDR ranges (ensure no overlap with existing
  networks).
- **`module.data`** — Cloud SQL and Memorystore SKUs and sizes.
- **`module.security`** — KMS key rotation window and Secret Manager bindings.

### 5. Apply

```bash
terraform apply tfplan
```

A full apply creates approximately 45 resources and takes 15–25 minutes (GKE
cluster provisioning is the longest step).

### 6. Configure `kubectl`

```bash
gcloud container clusters get-credentials \
  $(terraform output -raw cluster_name) \
  --region $(terraform output -raw gcp_region)
```

### 7. Deploy Euno via Helm

```bash
helm install euno ./k8s/helm/euno \
  --namespace euno --create-namespace \
  -f k8s/helm/euno/values.yaml \
  -f k8s/helm/euno/values-gcp.yaml \
  --set gateway.env.AUDIT_LEDGER_PG_URL="$(terraform output -raw gateway_db_url)" \
  --set gateway.env.REDIS_URL="$(terraform output -raw gateway_redis_url)"
```

---

## Module reference

### `module.network` — VPC, subnets, Cloud NAT

| Resource | Description |
|---|---|
| `google_compute_network` | Custom-mode VPC |
| `google_compute_subnetwork` | Regional subnet with secondary ranges for GKE pods and services |
| `google_compute_router` | Cloud Router for NAT egress |
| `google_compute_router_nat` | Cloud NAT for private node outbound traffic |

**Key inputs:**

| Variable | Default | Description |
|---|---|---|
| `subnet_cidr` | `10.50.0.0/20` | Primary subnet CIDR |
| `pods_cidr` | `10.52.0.0/14` | GKE pod secondary range |
| `services_cidr` | `10.56.0.0/20` | GKE service secondary range |

### `module.compute` — GKE, Workload Identity, autoscaling

| Resource | Description |
|---|---|
| `google_container_cluster` | Regional GKE cluster (REGULAR release channel) |
| `google_container_node_pool` | Node pool with cluster autoscaler enabled |
| `google_service_account` × 2 | Dedicated GCP SAs for issuer and gateway pods |
| `google_service_account_iam_member` × 2 | Workload Identity bindings (K8s SA → GCP SA) |

**Key inputs:**

| Variable | Default | Description |
|---|---|---|
| `gke_node_machine_type` | `e2-standard-4` | Machine type for each node |
| `gke_node_count` | `1` | Initial nodes per zone |
| `gke_node_max_count` | `3` | Autoscaler upper bound per zone |

### `module.data` — Cloud SQL, Memorystore

| Resource | Description |
|---|---|
| `google_sql_database_instance` | Cloud SQL for PostgreSQL 15 (HA by default) |
| `google_sql_database` | `euno` application database |
| `google_sql_user` | `euno` database user |
| `google_redis_instance` | Memorystore for Redis 7.x (STANDARD_HA tier) |

**Key inputs:**

| Variable | Default | Description |
|---|---|---|
| `db_tier` | `db-g1-small` | Cloud SQL machine tier |
| `db_ha_enabled` | `true` | Enable HA replica |
| `redis_tier` | `STANDARD_HA` | Memorystore tier |
| `redis_memory_size_gb` | `4` | Redis memory size |

**Outputs used by Helm:**

| Output | Description |
|---|---|
| `gateway_db_url` | `postgresql://` connection string for `AUDIT_LEDGER_PG_URL` |
| `gateway_redis_url` | `rediss://` connection string for `REDIS_URL` |

### `module.security` — Cloud KMS, Secret Manager, IAM

| Resource | Description |
|---|---|
| `google_kms_key_ring` | KMS key ring for signing keys |
| `google_kms_crypto_key` | Asymmetric RSA-2048 signing key (`prevent_destroy = true`) |
| `google_secret_manager_secret` × N | Placeholders for HMAC secret, admin API key, and partner DID pin |
| `google_kms_crypto_key_iam_member` | Signer/verifier bindings for issuer and gateway SAs |
| `google_project_iam_member` | `roles/secretmanager.secretAccessor` for issuer and gateway |

### `module.observability` — Cloud Monitoring, alerting

| Resource | Description |
|---|---|
| `google_monitoring_dashboard` | Euno runtime dashboard (denial rate, latency, error rate) |
| `google_monitoring_alert_policy` × 3 | Denial spike, invalid token burst, pod crash-loop alerts |
| `google_logging_project_bucket_config` × 2 | Runtime and audit log buckets |
| `google_logging_project_sink` | Audit-tagged entries routed to the audit log bucket |

---

## Destroying the deployment

> ⚠️ The Cloud KMS signing key has `lifecycle { prevent_destroy = true }`.
> You must remove this guard manually in `security/main.tf` before `terraform destroy`.

```bash
terraform destroy
```

---

## See also

- [`infra/terraform/gcp/main.tf`](../../terraform/gcp/main.tf) — Sprint-1 monolithic baseline
- [`infra/gcp/config-connector/`](../config-connector/) — Config Connector KRM alternative
- [`docs/deploy-gke.md`](../../../docs/deploy-gke.md) — Full GKE deployment guide
- [`k8s/helm/euno/values-gcp.yaml`](../../../k8s/helm/euno/values-gcp.yaml) — Helm overrides
