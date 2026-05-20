# Multi-Cloud Ecosystem Support Plan

This document describes the plan to deepen euno's first-class support for
**AWS** and **GCP** ecosystems in addition to the existing Azure integrations.
The goal is feature parity across all three major cloud providers so that any
team — regardless of their cloud home — can deploy and operate euno without
workarounds.

---

## Current state

| Capability | Azure | AWS | GCP |
|---|---|---|---|
| Identity provider | ✅ Entra ID (`azure-ad` adapter) | ✅ Cognito (`aws-cognito` adapter) | ✅ Cloud Identity (`gcp-identity` adapter) |
| Token signing (KMS) | ✅ Key Vault (`azure-keyvault` signer) | ✅ KMS (`aws-kms` signer) | ✅ Cloud KMS (`gcp-cloudkms` signer) |
| Secrets management | ✅ Key Vault secrets referenced in docs | ⚠️ Secrets Manager — referenced in docs, no native SDK integration | ⚠️ Secret Manager — referenced in docs, no native SDK integration |
| Audit ledger storage | ✅ Azure Blob (S3-compatible via `@azure/storage-blob`) | ✅ S3 Object Lock (cross-chain anchor) | ⚠️ GCS — not yet integrated as cross-chain anchor target |
| Infrastructure-as-code | ⚠️ Bicep/ARM — not provided | ⚠️ CloudFormation / CDK — not provided | ⚠️ Deployment Manager / Terraform — not provided |
| Container registry | ⚠️ ACR — not documented | ⚠️ ECR — not documented | ⚠️ Artifact Registry — not documented |
| Helm deployment | ✅ AKS compatible | ⚠️ EKS — tested manually, not documented | ⚠️ GKE — tested manually, not documented |
| Observability integration | ⚠️ Azure Monitor/Sentinel — partially referenced | ⚠️ CloudWatch / Security Hub — not integrated | ⚠️ Cloud Monitoring / Security Command Center — not integrated |
| Managed IdP SCIM push | ⚠️ Entra ID SCIM — documented in issuer-idp-setup.md | ⚠️ Cognito → SCIM bridge — not documented | ⚠️ Google Workspace → SCIM bridge — not documented |

---

## Guiding principles

1. **Adapter parity, not feature parity via workarounds.** Each cloud service
   must be supported through the same `IdentityAdapter` / `SigningAdapter`
   contracts. No cloud-specific code paths in the enforcement or audit core.

2. **Least-privilege credential model for each cloud.** AWS: IAM roles with
   instance profile / IRSA; no long-lived access keys. GCP: Workload Identity
   Federation / service account key-less auth. Azure: Managed Identity (already
   implemented).

3. **Operational equivalence.** An operator who knows one cloud deployment
   should be able to reason about the others from the same runbook structure.
   Provider-specific guides live in `docs/` but reference the same environment
   variables and Helm values.

4. **No mandatory cloud dependency for local or self-hosted mode.** Local
   (`@euno/mcp` only) and self-hosted deployments must continue to work with
   no cloud account at all. Cloud integrations are opt-in extensions, not
   required dependencies.

---

## AWS ecosystem plan

### Phase 1 — Documentation and configuration (near-term)

- [ ] **EKS deployment guide** (`docs/deploy-eks.md`)
  - IAM roles for service accounts (IRSA) wiring for capability-issuer and
    tool-gateway pods
  - ECR image pull configuration and air-gap image push script
  - ALB Ingress Controller + ACM certificate setup
  - Example `values.yaml` overrides for the Helm umbrella chart

- [ ] **AWS Secrets Manager integration** (`docs/secrets-aws.md`)
  - How to reference `AUDIT_LEDGER_HMAC_SECRET`, `GATEWAY_ADMIN_API_KEY`, and
    `PARTNER_DID_PIN_SECRET` from Secrets Manager at pod startup
  - External Secrets Operator vs. AWS Secrets and Configuration Provider (ASCP)
    side-by-side comparison

- [ ] **Cognito SCIM bridge guide** (`docs/issuer-idp-setup.md` §Cognito SCIM)
  - Cognito User Pool + AWS IAM Identity Center SCIM endpoint configuration
  - Attribute mappings for `sub`, `email`, and group claims to euno roles

- [ ] **CloudWatch / Security Hub observability guide**
  - Prometheus → CloudWatch Metrics forwarding (ADOT Collector)
  - OCSF audit event → Security Hub finding mapping
  - CloudWatch Insights query templates for denial-reason histograms

### Phase 2 — Native SDK integration (medium-term)

- [ ] **AWS Secrets Manager secrets-store adapter**
  - Implement `SecretsManagerSecretStore` that satisfies the internal
    `SecretStore` interface used by `createLedgerSignerFromConfig` and
    `createIssuerConfigFromEnv`
  - Fall back to `process.env` when `AWS_SECRETS_ARN_*` vars are absent
  - Unit tests with `@aws-sdk/client-secrets-manager` mock

- [ ] **S3 cross-chain anchor — region and endpoint improvements**
  - Current `CrossChainAnchor` already writes to S3 Object Lock; review
    whether GovCloud (`us-gov-*`) and FIPS endpoints work without changes
  - Add `AUDIT_LEDGER_S3_ENDPOINT` override for VPC endpoint / PrivateLink
    deployments

- [ ] **AWS KMS signer — additional key specs**
  - Add `ECC_NIST_P384` and `ECC_NIST_P521` key spec support to
    `aws-kms-signer.ts` (currently RS256/PS256 RSA only)
  - EdDSA signing via external signer shim for partner DID (`did:ion`) use cases

### Phase 3 — Infrastructure-as-code (longer-term)

- [ ] **AWS CDK constructs** (`infra/aws/cdk/`)
  - `EunoGatewayStack` — EKS Fargate cluster, RDS Postgres, ElastiCache Redis,
    KMS key, S3 Object Lock bucket, Secrets Manager secrets, IAM roles
  - `EunoIssuerStack` — adds Cognito User Pool, SCIM endpoint wiring
  - `EunoEnterpriseStack` — adds partner DID registry, SOC 2 audit pipeline
  - CDK unit tests via `aws-cdk-lib/assertions`

- [ ] **Terraform module** (`infra/aws/terraform/`)
  - Modular layout: `network/`, `compute/`, `data/`, `security/`, `observability/`
  - Variables file with euno-specific naming conventions
  - README with `terraform init / plan / apply` walkthrough

---

## GCP ecosystem plan

### Phase 1 — Documentation and configuration (near-term)

- [ ] **GKE deployment guide** (`docs/deploy-gke.md`)
  - Workload Identity Federation for capability-issuer and tool-gateway pods
    (no service account keys on disk)
  - Artifact Registry image push and pull configuration
  - GKE Ingress + Google-managed SSL certificate setup
  - Example `values.yaml` overrides for the Helm umbrella chart

- [ ] **GCP Secret Manager integration** (`docs/secrets-gcp.md`)
  - How to reference secrets from Secret Manager at pod startup
  - External Secrets Operator vs. Secret Manager add-on comparison
  - IAM binding patterns for Workload Identity

- [ ] **Google Workspace SCIM bridge guide** (`docs/issuer-idp-setup.md` §Google Workspace SCIM)
  - Google Workspace SCIM provisioning endpoint and OAuth service account setup
  - Attribute mappings for `sub`, `email`, and `groups` claims to euno roles
  - Cloud Identity → euno role mapping table example

- [ ] **Cloud Monitoring / Security Command Center observability guide**
  - Prometheus → Cloud Monitoring (via OpenTelemetry Collector) integration
  - OCSF audit event → Security Command Center finding type mapping
  - Log-based metrics for denial histograms in Cloud Logging

### Phase 2 — Native SDK integration (medium-term)

- [ ] **GCP Secret Manager secrets-store adapter**
  - Implement `SecretManagerSecretStore` satisfying the internal `SecretStore`
    interface
  - Authenticate via Workload Identity Federation (no JSON key file required)
  - Fall back to `process.env` when `GCP_SECRET_*` vars are absent
  - Unit tests with `@google-cloud/secret-manager` mock

- [ ] **GCS cross-chain anchor target**
  - Extend `CrossChainAnchor` to support GCS as an alternative to S3
  - Object Lock equivalent: GCS bucket retention policy + object holds
  - New env var `AUDIT_LEDGER_GCS_BUCKET` alongside existing
    `AUDIT_LEDGER_S3_BUCKET`; both can be active simultaneously for
    multi-cloud redundancy

- [ ] **GCP Cloud KMS signer — additional key specs**
  - Add `EC_SIGN_P384_SHA384` and `RSA_SIGN_PKCS1_4096_SHA512` support to
    `gcp-cloudkms-signer.ts`
  - Key version listing for automated rotation detection

### Phase 3 — Infrastructure-as-code (longer-term)

- [ ] **Terraform module** (`infra/gcp/terraform/`)
  - `network/` — VPC, subnets, Cloud NAT
  - `compute/` — GKE cluster with Workload Identity, node pool autoscaling
  - `data/` — Cloud SQL (Postgres), Memorystore Redis
  - `security/` — Cloud KMS key ring, Secret Manager secrets, IAM bindings
  - `observability/` — Cloud Monitoring dashboards, alerting policies
  - README with `terraform init / plan / apply` walkthrough

- [ ] **Google Cloud Deployment Manager / Config Connector** (`infra/gcp/config-connector/`)
  - KRM manifests for Cloud SQL, Memorystore, Cloud KMS, and Artifact Registry
  - Annotated with Workload Identity bindings

---

## Cross-cloud work

### Shared infrastructure improvements

- [ ] **Secrets abstraction layer (`SecretStore` interface)**
  - Define a minimal `SecretStore` interface (already implicit in config code)
    as a first-class exported type in `@euno/common-core`
  - Register built-in implementations: `EnvSecretStore` (default),
    `AzureKeyVaultSecretStore`, `AwsSecretsManagerSecretStore`,
    `GcpSecretManagerSecretStore`
  - Document the selection logic: if `SECRET_STORE_PROVIDER` is set, load the
    corresponding implementation; otherwise fall back to `process.env`

- [ ] **Cloud-agnostic object storage anchor**
  - Refactor `CrossChainAnchor` to use an `ObjectStore` interface
    (`put(key, data): Promise<void>`) instead of hard-coding the AWS SDK
  - Built-in implementations: `S3ObjectStore`, `GcsObjectStore`,
    `AzureBlobObjectStore`
  - Selection via `AUDIT_LEDGER_OBJECT_STORE_PROVIDER` env var

- [ ] **Helm chart — cloud-specific values files**
  - `k8s/helm/euno/values-azure.yaml`
  - `k8s/helm/euno/values-aws.yaml`
  - `k8s/helm/euno/values-gcp.yaml`
  - Each file documents every provider-specific override with inline comments

### Testing

- [ ] Integration test matrix across cloud adapters
  - Extend `euno-platform/packages/integration-tests/` with adapter-specific
    test suites that can run against live cloud resources (guarded by env vars)
    or against localstack / fake-gcs-server / Azurite in CI
  - CI workflow step: `test:cloud-adapters` — runs against emulators only by
    default; real cloud targets are opt-in via repository secrets

### Documentation

- [ ] **Multi-cloud runbook index** (`docs/multi-cloud.md`)
  - Quick comparison table (this document)
  - Links to per-cloud deployment guides, secrets guides, SCIM guides,
    and observability guides
  - Migration path from single-cloud to multi-cloud (e.g., Azure primary +
    S3 cross-chain anchor for disaster recovery)

---

## Prioritization

The work above is ordered so that **documentation and configuration** can
be shipped first (no code changes, high user value), followed by **native
SDK integration** (code changes confined to adapter packages, no enforcement
core changes), and finally **infrastructure-as-code** (high effort, high
long-term value for enterprise customers).

Each phase is independently shippable. The cross-cloud shared-infrastructure
work (secrets abstraction, object-store abstraction, Helm values files) should
be sequenced alongside Phase 2 for each cloud, since the adapters depend on
the interface definitions.
