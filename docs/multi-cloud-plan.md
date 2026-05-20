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
| Audit ledger storage | ✅ Azure Blob (`AzureBlobObjectStore` via `AUDIT_LEDGER_OBJECT_STORE_PROVIDER=azure-blob`; managed identity, shared-key, or connection-string auth) | ✅ S3 Object Lock (`S3ObjectStore` / `AUDIT_LEDGER_OBJECT_STORE_PROVIDER=s3`; cross-chain anchor) | ✅ GCS (`GcsObjectStore` / `AUDIT_LEDGER_OBJECT_STORE_PROVIDER=gcs`; `temporaryHold` per object; multi-cloud redundancy alongside S3) |
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

- [x] **EKS deployment guide** (`docs/deploy-eks.md`)
  - IAM roles for service accounts (IRSA) wiring for capability-issuer and
    tool-gateway pods
  - ECR image pull configuration and air-gap image push script
  - ALB Ingress Controller + ACM certificate setup
  - Example `values.yaml` overrides for the Helm umbrella chart

- [x] **AWS Secrets Manager integration** (`docs/secrets-aws.md`)
  - How to reference `AUDIT_LEDGER_HMAC_SECRET`, `GATEWAY_ADMIN_API_KEY`, and
    `PARTNER_DID_PIN_SECRET` from Secrets Manager at pod startup
  - External Secrets Operator vs. AWS Secrets and Configuration Provider (ASCP)
    side-by-side comparison

- [x] **Cognito SCIM bridge guide** (`docs/issuer-idp-setup.md` §Cognito SCIM)
  - Cognito User Pool + AWS IAM Identity Center SCIM endpoint configuration
  - Attribute mappings for `sub`, `email`, and group claims to euno roles

- [x] **CloudWatch / Security Hub observability guide**
  - Prometheus → CloudWatch Metrics forwarding (ADOT Collector)
  - OCSF audit event → Security Hub finding mapping
  - CloudWatch Insights query templates for denial-reason histograms

### Phase 2 — Native SDK integration (medium-term)

- [x] **AWS Secrets Manager secrets-store adapter**
  - `AwsSecretsManagerSecretStore` satisfies the internal `SecretStore`
    interface used by `createLedgerSignerFromConfig` and the issuer config
    loader (`loadConfigOrExit(..., 'issuer')`)
  - `arnsBySecretName` map lets operators pin individual secrets to Secrets
    Manager ARNs; `createSecretStoreFromEnv` auto-builds the map from every
    `AWS_SECRETS_ARN_<NAME>` env var it finds
  - Falls back to `fallbackEnv` (default `process.env`) for secrets without
    an ARN override — supports incremental migration
  - Unit tests with `@aws-sdk/client-secrets-manager` mock

- [x] **S3 cross-chain anchor — region and endpoint improvements**
  - `AUDIT_LEDGER_S3_ENDPOINT` env var added to `GatewayConfigSchema`;
    passed to `AwsSdkS3AnchorClient` for VPC endpoint / PrivateLink deployments
  - `AUDIT_LEDGER_S3_FORCE_PATH_STYLE` env var added for path-style addressing
    (required for some VPC endpoint configurations and MinIO)
  - `createS3AnchorClientFromEnv()` factory in `@euno/common-infra` —
    the standard bootstrap auto-creates an `S3AnchorClient` when
    `AUDIT_LEDGER_S3_BUCKET` is set; no custom entrypoint required
  - GovCloud (`us-gov-*`) endpoints are resolved automatically from `AWS_REGION`
    by the SDK; no special handling required
  - Unit tests in `common-infra`

- [x] **AWS KMS signer — additional key specs**
  - `ECC_NIST_P384` → ES384 and `ECC_NIST_P521` → ES512 already supported
    in `aws-kms-signer.ts` (auto-detected from `GetPublicKeyCommand.KeySpec`)
  - EdDSA signing shim (`AwsEdDsaSigner`) for partner DID (`did:ion`) use cases:
    stores Ed25519 private key in Secrets Manager; signs locally with `jose`;
    configured via `AWS_EDDSA_KEY_ARN` env var
  - Unit tests in `capability-issuer/tests/aws-eddsa-signer.test.ts`

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

- [x] **GKE deployment guide** (`docs/deploy-gke.md`)
  - Workload Identity Federation for capability-issuer and tool-gateway pods
    (no service account keys on disk)
  - Artifact Registry image push and pull configuration
  - GKE Ingress + Google-managed SSL certificate setup
  - Example `values.yaml` overrides for the Helm umbrella chart

- [x] **GCP Secret Manager integration** (`docs/secrets-gcp.md`)
  - How to reference secrets from Secret Manager at pod startup
  - External Secrets Operator vs. Secret Manager add-on comparison
  - IAM binding patterns for Workload Identity

- [x] **Google Workspace SCIM bridge guide** (`docs/issuer-idp-setup.md` §Google Workspace SCIM)
  - Google Workspace SCIM provisioning endpoint and OAuth service account setup
  - Attribute mappings for `sub`, `email`, and `groups` claims to euno roles
  - Cloud Identity → euno role mapping table example

- [x] **Cloud Monitoring / Security Command Center observability guide**
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

- [x] **GCS cross-chain anchor target**
  - Extended `CrossChainAnchor` to support GCS as an alternative or complement
    to S3 (`gcs?` option on `CrossChainAnchorOptions`)
  - Implemented `GcsAnchorClient` interface + `GcsAnchorClientImpl`
    (`@google-cloud/storage` loaded lazily; sets `temporaryHold` by default)
  - New `gcs?` options on `PostgresLedgerOptions`, `PerReplicaPostgresLedgerOptions`,
    and `CrossChainAnchorOptions` — both S3 and GCS can be active simultaneously
    for multi-cloud redundancy
  - New env vars `AUDIT_LEDGER_GCS_BUCKET` / `AUDIT_LEDGER_GCS_PREFIX` in
    config schema alongside existing `AUDIT_LEDGER_S3_BUCKET`
  - `audit-module.ts` warns (per-replica) / errors (postgres) when
    `AUDIT_LEDGER_GCS_BUCKET` is set without a wired GCS client
  - 25 new tests across `ledger-signer.test.ts`, `per-replica-ledger.test.ts`,
    and `common-infra/src/__tests__/gcs-anchor-client.test.ts`

- [x] **GCP Cloud KMS signer — key version listing for rotation detection**
  - Added `listKeyVersions(): Promise<GCPKeyVersionInfo[]>` to
    `GCPCloudKMSSigner` — uses `kmsClient.listCryptoKeyVersions()` under the
    hood
  - `GCPKeyVersionInfo` interface exported from `gcp-cloudkms-signer.ts`
  - 6 new tests covering normal operation, empty list, DESTROYED versions,
    null SDK return, rotation detection pattern, and error propagation

### Phase 3 — Infrastructure-as-code (longer-term)

- [x] **Terraform module** (`infra/gcp/terraform/`)
  - `network/` — VPC, subnets, Cloud NAT
  - `compute/` — GKE cluster with Workload Identity, node pool autoscaling
  - `data/` — Cloud SQL (Postgres), Memorystore Redis
  - `security/` — Cloud KMS key ring, Secret Manager secrets, IAM bindings
  - `observability/` — Cloud Monitoring dashboards, alerting policies
  - README with `terraform init / plan / apply` walkthrough

- [x] **Google Cloud Deployment Manager / Config Connector** (`infra/gcp/config-connector/`)
  - KRM manifests for Cloud SQL, Memorystore, Cloud KMS, and Artifact Registry
  - Annotated with Workload Identity bindings

---

## Cross-cloud work

### Shared infrastructure improvements

- [x] **Secrets abstraction layer (`SecretStore` interface)**
  - Define a minimal `SecretStore` interface (already implicit in config code)
    as a first-class exported type in `@euno/common-core`
  - Register built-in implementations: `EnvSecretStore` (default),
    `AzureKeyVaultSecretStore`, `AwsSecretsManagerSecretStore`,
    `GcpSecretManagerSecretStore`
  - Document the selection logic: if `SECRET_STORE_PROVIDER` is set, load the
    corresponding implementation; otherwise fall back to `process.env`
  - `createSecretStoreFromEnv()` factory in `@euno/common-core` wired to env config
  - `SECRET_STORE_PROVIDER` and provider-specific vars added to `IssuerConfigSchema`
    and `GatewayConfigSchema` with cross-field validation
  - Unit tests in `public/packages/common/src/__tests__/secret-store.test.ts`
  - Config schema tests in `euno-platform/packages/common/tests/config.test.ts`
  - `docs/ADAPTERS.md` §"Secret Store" added

- [x] **Cloud-agnostic object storage anchor**
  - Refactored `CrossChainAnchor`, `PostgresLedgerBackend`, and
    `PerReplicaPostgresLedgerBackend` to support an `ObjectStore` interface
    (`put(key, data, contentType): Promise<void>`) via the new `objectStores?`
    option, decoupling anchor writes from provider-specific clients
  - Built-in implementations: `S3ObjectStore` (wraps existing `S3AnchorClient`),
    `GcsObjectStore` (wraps existing `GcsAnchorClient`), `AzureBlobObjectStore`
    (lazily loads `@azure/storage-blob`; uses `DefaultAzureCredential`,
    shared-key, or connection-string auth)
  - `createObjectStoreFromEnv()` factory selects the implementation based on
    `AUDIT_LEDGER_OBJECT_STORE_PROVIDER` (`s3` | `gcs` | `azure-blob`)
  - New env vars: `AUDIT_LEDGER_OBJECT_STORE_PROVIDER`,
    `AUDIT_LEDGER_AZURE_CONTAINER`, `AUDIT_LEDGER_AZURE_STORAGE_CONNECTION_STRING`,
    `AUDIT_LEDGER_AZURE_ACCOUNT_NAME`, `AUDIT_LEDGER_AZURE_ACCOUNT_KEY`,
    `AUDIT_LEDGER_AZURE_ENDPOINT`, `AUDIT_LEDGER_GCS_SKIP_HOLD` added to
    `GatewayConfigSchema`
  - `audit-module.ts` standard bootstrap automatically wires the generic
    `ObjectStore` into both the ledger backend and the `CrossChainAnchor`
    when `AUDIT_LEDGER_OBJECT_STORE_PROVIDER` is set
  - All three backends (`objectStores` array) fan out to every configured
    store independently — a failure in one does not block others
  - 33 new unit tests in `common-infra/src/__tests__/object-store.test.ts`

- [x] **Helm chart — cloud-specific values files**
  - [x] `k8s/helm/euno/values-azure.yaml`
  - [x] `k8s/helm/euno/values-aws.yaml`
  - [x] `k8s/helm/euno/values-gcp.yaml`
  - Each file documents every provider-specific override with inline comments

### Testing

- [ ] Integration test matrix across cloud adapters
  - Extend `euno-platform/packages/integration-tests/` with adapter-specific
    test suites that can run against live cloud resources (guarded by env vars)
    or against localstack / fake-gcs-server / Azurite in CI
  - CI workflow step: `test:cloud-adapters` — runs against emulators only by
    default; real cloud targets are opt-in via repository secrets

### Documentation

- [x] **Multi-cloud runbook index** (`docs/multi-cloud.md`)
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
