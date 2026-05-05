# Euno Infrastructure-as-Code

This directory contains the reproducible-provisioning artifacts for
the Azure pilot deployment, plus the multi-cloud parity
artifacts for AWS and GCP.

## Contents

| Path                                           | Cloud | Purpose                                                                                         |
|------------------------------------------------|-------|-------------------------------------------------------------------------------------------------|
| `bicep/main.bicep`                             | Azure | Single-file Bicep template provisioning every Azure resource.                                   |
| `bicep/main.parameters.example.json`           | Azure | Example parameter file — copy and customize before deploying.                                   |
| `sentinel/analytic-rules.json`                 | Azure | ARM-deployable Microsoft Sentinel scheduled analytic rules (KQL).                               |
| `terraform/aws/main.tf`                        | AWS   | Terraform for EKS, KMS, IAM, CloudWatch, ECR, Cognito (parity with `bicep/main.bicep`).         |
| `terraform/aws/terraform.tfvars.example`       | AWS   | Example tfvars file.                                                                            |
| `aws/api-gateway/`                             | AWS   | API Gateway OpenAPI + Lambda authorizer (parity with APIM `validate-jwt`).                      |
| `aws/security/`                                | AWS   | CloudWatch Logs Insights queries, Metric Filter / Alarm CFN, Security Hub insights.             |
| `terraform/gcp/main.tf`                        | GCP   | Terraform for GKE, Cloud KMS, IAM, Cloud Logging, Artifact Registry (parity with bicep).        |
| `terraform/gcp/terraform.tfvars.example`       | GCP   | Example tfvars file.                                                                            |
| `gcp/api-gateway/`                             | GCP   | GCP API Gateway OpenAPI + Apigee `VerifyJWT` policy (parity with APIM `validate-jwt`).          |
| `gcp/security/`                                | GCP   | Cloud Logging queries, Cloud Monitoring alert policies, SCC custom modules.                     |

## Deploying the Bicep template

> Pre-requisites: Azure CLI ≥ 2.55, Bicep ≥ 0.24, Owner or User Access
> Administrator role on the target subscription (RBAC role assignments are
> created during deployment).

```bash
# 1. Pick a region and create the resource group
az group create --name euno-pilot-rg --location eastus

# 2. Deploy
az deployment group create \
  --resource-group euno-pilot-rg \
  --template-file infra/bicep/main.bicep \
  --parameters @infra/bicep/main.parameters.example.json
```

The template provisions:

* Log Analytics Workspace (90-day retention by default)
* Application Insights (workspace-based) for issuer + gateway telemetry
* Key Vault (RBAC mode, purge protection on) + RSA-2048 signing key
* User-assigned managed identity for the Capability Issuer with `Key Vault Crypto User` rights
* Optional `Key Vault Crypto Officer` assignment for an admin user (parameter `keyVaultAdminObjectId`)
* Container Registry (Standard SKU)
* AKS cluster (system-assigned identity, OIDC issuer + workload identity, Container Insights add-on, Azure Network Policy)
* `acrpull` role assignment on ACR for the AKS kubelet identity
* Diagnostic settings shipping Key Vault audit logs and AKS control-plane logs into Log Analytics so Microsoft Sentinel can evaluate them

The deployment outputs (e.g. `keyVaultUri`, `acrLoginServer`,
`appInsightsConnectionString`, `aksOidcIssuerUrl`, `issuerIdentityClientId`)
are everything you need for the Kubernetes manifests under `../k8s` and
for the GitHub Actions release workflow.

## Deploying Sentinel analytic rules

Once you have onboarded the Log Analytics workspace to Microsoft Sentinel
(via the Azure portal or `az sentinel onboarding-state`), deploy the
Sprint-5 detection rules:

```bash
az deployment group create \
  --resource-group euno-pilot-rg \
  --template-file infra/sentinel/analytic-rules.json \
  --parameters workspaceName=<your-law-name>
```

See `../docs/PILOT_PLAYBOOK.md` for the full pilot rollout and metrics-collection procedures.

## Deploying the AWS Terraform module

```bash
cd infra/terraform/aws
cp terraform.tfvars.example terraform.tfvars  # then edit
terraform init
terraform apply
```

The module provisions every AWS resource called out in the Sprint-1
multi-cloud parity matrix (EKS, KMS asymmetric signing key, IAM roles for
IRSA, ECR, Cognito User Pool, CloudWatch Log Groups, Security Hub).
After it completes, layer in the gateway profile and security analytics
rules:

```bash
# Edge JWT enforcement (parity with APIM validate-jwt)
ls infra/aws/api-gateway/        # openapi.json + lambda-authorizer.js + README

# Security analytics (parity with infra/sentinel/analytic-rules.json)
aws cloudformation deploy \
  --template-file infra/aws/security/cloudwatch-alarms.yaml \
  --stack-name euno-security-alerts \
  --capabilities CAPABILITY_NAMED_IAM
```

## Deploying the GCP Terraform module

```bash
cd infra/terraform/gcp
cp terraform.tfvars.example terraform.tfvars  # then edit
terraform init
terraform apply
```

The module provisions every GCP resource called out in the Sprint-1
multi-cloud parity matrix (GKE with Workload Identity, Cloud KMS asymmetric
signing key, GCP service accounts + Workload Identity bindings, Artifact
Registry, dedicated Cloud Logging buckets, Pub/Sub topic for SCC findings).
After it completes:

```bash
# Edge JWT enforcement (parity with APIM validate-jwt)
ls infra/gcp/api-gateway/        # openapi.yaml + apigee-validate-jwt.xml + README

# Security analytics (parity with infra/sentinel/analytic-rules.json)
cd infra/gcp/security && terraform init && terraform apply -var="project_id=<your-project>"
```

## Sprint-1 multi-cloud parity matrix

| Capability                       | Azure                                            | AWS                                                                  | GCP                                                                |
|----------------------------------|--------------------------------------------------|----------------------------------------------------------------------|--------------------------------------------------------------------|
| Infrastructure-as-Code           | `bicep/main.bicep`                               | `terraform/aws/main.tf`                                              | `terraform/gcp/main.tf`                                            |
| Edge JWT enforcement             | APIM `validate-jwt` policy (referenced in plan)  | `aws/api-gateway/openapi.json` + `lambda-authorizer.js`              | `gcp/api-gateway/openapi.yaml` + `apigee-validate-jwt.xml`         |
| OBS — security analytics rules   | `sentinel/analytic-rules.json`                   | `aws/security/cloudwatch-logs-insights.json` + `cloudwatch-alarms.yaml` + `security-hub-insights.json` | `gcp/security/cloud-logging-queries.json` + `cloud-monitoring-alerts.tf` + `scc-custom-modules.yaml` |
| OBS — log-shipping transport     | Console transport scraped by Container Insights  | `AWS_CLOUDWATCH_LOG_GROUP` env var → CloudWatch Logs winston transport | `GCP_LOG_NAME` env var → Cloud Logging winston transport            |
