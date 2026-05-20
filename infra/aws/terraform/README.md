# Euno AWS Terraform — Modular Layout

Modular Terraform configuration for the Euno Capability-Native Agent Governance
platform on AWS.  Extracted and reorganised from the monolithic
`infra/terraform/aws/main.tf` (Sprint 1) into five self-contained modules that
can be reviewed, tested, and applied independently.

```
infra/aws/terraform/
├── main.tf                 Root module — wires sub-modules together
├── variables.tf            Shared input variables
├── outputs.tf              Aggregated outputs
├── terraform.tfvars.example  Example variable values
├── network/                VPC, subnets, IGW, NAT gateways, route tables
├── compute/                EKS cluster, node groups / Fargate profiles, IRSA
├── data/                   RDS PostgreSQL, ElastiCache Redis, subnet groups
├── security/               KMS, S3 Object Lock, Secrets Manager, IAM policies
└── observability/          CloudWatch log groups, Security Hub, ADOT collector
```

---

## Prerequisites

- [Terraform](https://developer.hashicorp.com/terraform/install) ≥ 1.5.0
- AWS credentials configured (`~/.aws/credentials` or environment variables)
- An S3 bucket + DynamoDB table for remote state (recommended for production)

---

## Quick start

```bash
# 1. Navigate to the module root
cd infra/aws/terraform

# 2. Initialise providers and modules
terraform init

# 3. Copy and edit the example variable file
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars

# 4. Preview changes
terraform plan -var-file=terraform.tfvars

# 5. Apply
terraform apply -var-file=terraform.tfvars
```

For production, configure a remote backend first:

```hcl
# backend.tf  (create alongside main.tf; do NOT commit secrets)
terraform {
  backend "s3" {
    bucket         = "euno-tf-state-prod"
    key            = "euno/platform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "euno-tf-lock"
    encrypt        = true
  }
}
```

Then run `terraform init -reconfigure` to migrate state.

---

## Module overview

### `network/`

Provisions the VPC and all layer-3 primitives:

| Resource | Description |
|---|---|
| `aws_vpc` | VPC with DNS hostnames + support enabled |
| `aws_internet_gateway` | Internet gateway attached to the VPC |
| `aws_subnet.public[*]` | One public subnet per AZ (ELB/ALB tagged) |
| `aws_subnet.private[*]` | One private subnet per AZ (internal-ELB tagged) |
| `aws_eip.nat[*]` | One Elastic IP per AZ for NAT gateways |
| `aws_nat_gateway.main[*]` | One NAT gateway per AZ (HA egress for private subnets) |
| `aws_route_table.public` | Public route table (0.0.0.0/0 → IGW) |
| `aws_route_table.private[*]` | Per-AZ private route tables (0.0.0.0/0 → NAT) |

### `compute/`

Provisions the EKS cluster and workload identity primitives:

| Resource | Description |
|---|---|
| `aws_iam_role.eks_cluster` | IAM role for the EKS control plane |
| `aws_eks_cluster` | EKS cluster (control-plane logs → CloudWatch) |
| `aws_iam_openid_connect_provider` | OIDC provider for IRSA |
| `aws_eks_node_group.system` | Optional managed node group (skip for Fargate) |
| `aws_eks_fargate_profile.euno_system` | Fargate profile for `euno-system` namespace |

### `data/`

Provisions stateful data stores:

| Resource | Description |
|---|---|
| `aws_db_subnet_group` | RDS subnet group (isolated / private subnets) |
| `aws_db_instance.postgres` | RDS PostgreSQL 15, Multi-AZ, encrypted, gp3 |
| `aws_elasticache_subnet_group` | ElastiCache subnet group |
| `aws_elasticache_replication_group` | Redis 7.1, TLS, auth token, HA |

### `security/`

Provisions cryptographic and secret-management resources:

| Resource | Description |
|---|---|
| `aws_kms_key.capability_signing` | RSA-2048 SIGN_VERIFY key for capability tokens |
| `aws_kms_alias` | Human-friendly alias for the signing key |
| `aws_s3_bucket.audit_anchor` | Object Lock (COMPLIANCE) audit anchor bucket |
| `aws_secretsmanager_secret.hmac_key` | AUDIT_LEDGER_HMAC_SECRET |
| `aws_secretsmanager_secret.admin_api_key` | ADMIN_API_KEY |
| `aws_secretsmanager_secret.redis_auth_token` | ElastiCache auth token |
| `aws_iam_role.issuer_irsa` | IRSA role for capability-issuer (KMS Sign) |
| `aws_iam_role.gateway_irsa` | IRSA role for tool-gateway (KMS Verify) |
| `aws_ecr_repository.service[*]` | ECR repos: immutable tags, scan on push |

### `observability/`

Provisions monitoring and compliance resources:

| Resource | Description |
|---|---|
| `aws_cloudwatch_log_group.runtime` | `/euno/runtime` — application logs |
| `aws_cloudwatch_log_group.audit` | `/euno/audit` — audit ledger entries |
| `aws_cloudwatch_metric_alarm.denial_spike` | SOC 2 CC7.3 denial-rate alarm |
| `aws_cloudwatch_metric_alarm.kill_switch` | Kill-switch activation alarm |
| `aws_sns_topic.alarms` | SNS topic for alarm notifications |
| `aws_securityhub_account` | Security Hub (CIS Foundations Benchmark) |
| `aws_cloudtrail` | Management + data events trail (CC6.1 / CC7.2) |

---

## Outputs

After `terraform apply`, retrieve key outputs:

```bash
terraform output cluster_name
terraform output issuer_role_arn
terraform output gateway_role_arn
terraform output signing_key_arn
terraform output cognito_user_pool_id
terraform output audit_anchor_bucket
```

Feed these into the Helm chart:

```bash
helm upgrade --install euno ./k8s/helm/euno \
  --namespace euno \
  -f k8s/helm/euno/values.yaml \
  -f k8s/helm/euno/values-aws.yaml \
  --set gateway.serviceAccountAnnotations."eks\.amazonaws\.com/role-arn"=$(terraform output -raw gateway_role_arn) \
  --set issuer.serviceAccountAnnotations."eks\.amazonaws\.com/role-arn"=$(terraform output -raw issuer_role_arn)
```

See `docs/deploy-eks.md` for the full deployment guide.

---

## Differences from `infra/terraform/aws/main.tf`

The monolithic `infra/terraform/aws/main.tf` (Sprint 1 baseline) contained all
resources in a single file.  This modular layout:

- Adds RDS PostgreSQL and ElastiCache Redis (`data/`)
- Adds S3 Object Lock audit anchor, Secrets Manager secrets (`security/`)
- Adds CloudWatch alarms, SNS topic, CloudTrail (`observability/`)
- Adds EKS Fargate profile for `euno-system` namespace (`compute/`)
- Splits Cognito into `security/` alongside KMS so all cryptographic / secrets
  resources are co-located

The monolithic file is retained for backwards compatibility.
