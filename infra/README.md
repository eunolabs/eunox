# Euno Infrastructure-as-Code

This directory contains the Sprint 5 reproducible-provisioning artifacts for
the Azure pilot deployment.

## Contents

| Path                                           | Purpose                                                                 |
|------------------------------------------------|-------------------------------------------------------------------------|
| `bicep/main.bicep`                             | Single-file Bicep template provisioning every Azure resource.           |
| `bicep/main.parameters.example.json`           | Example parameter file — copy and customize before deploying.           |
| `sentinel/analytic-rules.json`                 | ARM-deployable Microsoft Sentinel scheduled analytic rules (KQL).       |

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

See `../docs/SPRINT_5_PILOT_LAUNCH.md` for the full pilot rollout, hypercare,
and metrics-collection procedures.
