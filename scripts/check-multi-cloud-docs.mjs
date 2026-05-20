#!/usr/bin/env node
/**
 * CI lint: verify that AWS and GCP multi-cloud documentation requirements
 * are complete, including AWS Phase 2 and Phase 3 checks.
 *
 * Checks performed:
 *   1. docs/deploy-eks.md exists and contains required sections:
 *      - IRSA (IAM Roles for Service Accounts)
 *      - ECR image configuration
 *      - ALB Ingress Controller + ACM
 *      - Helm deployment section
 *      - CloudWatch / Security Hub observability section
 *      - Security Hub findings mapping
 *      - EKS security checklist
 *      [Phase 2] S3 endpoint / PrivateLink configuration section
 *      [Phase 2] AUDIT_LEDGER_S3_ENDPOINT env var documentation
 *      [Phase 2] AUDIT_LEDGER_S3_FORCE_PATH_STYLE env var documentation
 *      [Phase 2] GovCloud S3 endpoint note
 *   2. docs/secrets-aws.md exists and contains required sections:
 *      - AUDIT_LEDGER_HMAC_SECRET reference
 *      - GATEWAY_ADMIN_API_KEY reference (as ADMIN_API_KEY)
 *      - PARTNER_DID_PIN_SECRET reference
 *      - External Secrets Operator (ESO) section
 *      - ASCP (AWS Secrets and Configuration Provider) section
 *      - ESO vs. ASCP comparison table
 *      [Phase 2] Native SDK integration section
 *      [Phase 2] AWS_SECRETS_ARN_* env var pattern
 *      [Phase 2] AwsEdDsaSigner / EdDSA shim documentation
 *      [Phase 2] AWS_EDDSA_KEY_ARN env var
 *   3. docs/issuer-idp-setup.md contains the Cognito SCIM bridge section (§10):
 *      - Section heading for Cognito SCIM bridge
 *      - IAM Identity Center reference
 *      - ISSUER_SCIM_BEARER_TOKEN environment variable reference
 *      - Attribute mappings table
 *   4. k8s/helm/euno/values-aws.yaml exists and contains required entries:
 *      - ECR registry reference
 *      - IRSA annotation (eks.amazonaws.com/role-arn)
 *      - SIGNING_PROVIDER: aws-kms
 *      - IDENTITY_PROVIDER: aws-cognito
 *   5. docs/multi-cloud-plan.md Phase 2 items are marked complete:
 *      [Phase 2] AWS Secrets Manager adapter item is checked off
 *      [Phase 2] S3 endpoint item is checked off
 *      [Phase 2] KMS/EdDSA signer item is checked off
 *   6. docs/deploy-gke.md exists and contains required sections:
 *      - Workload Identity Federation section
 *      - iam.gke.io/gcp-service-account annotation
 *      - Artifact Registry image configuration
 *      - GKE Ingress section
 *      - Google-managed SSL certificate
 *      - values-gcp.yaml reference
 *      - Cloud Monitoring observability section
 *      - Security Command Center section
 *      - OCSF → SCC finding mapping
 *      - Log-based metrics / denial histogram
 *   7. docs/secrets-gcp.md exists and contains required sections:
 *      - AUDIT_LEDGER_HMAC_SECRET reference
 *      - ADMIN_API_KEY reference
 *      - PARTNER_DID_PIN_SECRET reference
 *      - Secret Accessor role / IAM binding
 *      - External Secrets Operator (ESO) section
 *      - SecretStore resource example
 *      - ExternalSecret resource example
 *      - Secret Manager Add-on section
 *      - ESO vs. comparison table
 *   8. docs/issuer-idp-setup.md contains the Google Workspace SCIM bridge (§11):
 *      - Section heading for Google Workspace SCIM bridge
 *      - OAuth service account reference
 *      - ISSUER_SCIM_BEARER_TOKEN environment variable reference (§11-scoped)
 *      - sub claim / externalId mapping (externalId: user.id)
 *      - ISSUER_SCIM_GROUP_ROLE_MAP reference (§11-scoped)
 *   9. k8s/helm/euno/values-gcp.yaml exists and contains required entries:
 *      - Artifact Registry reference (pkg.dev)
 *      - Workload Identity annotation (iam.gke.io/gcp-service-account)
 *      - SIGNING_PROVIDER: gcp-cloudkms
 *      - IDENTITY_PROVIDER: gcp-identity
 *      - GCP_PROJECT_ID placeholder
 *  10. [Phase 3] AWS CDK constructs exist and have correct content:
 *      - infra/aws/cdk/src/stacks/gateway-stack.ts: EunoGatewayStack
 *      - infra/aws/cdk/src/stacks/issuer-stack.ts: EunoIssuerStack
 *      - infra/aws/cdk/src/stacks/enterprise-stack.ts: EunoEnterpriseStack
 *      - infra/aws/cdk/package.json references aws-cdk-lib and constructs
 *      - CDK test files reference aws-cdk-lib/assertions
 *  11. [Phase 3] AWS Terraform modular layout exists:
 *      - network/, compute/, data/, security/, observability/ sub-modules
 *      - README with terraform init / plan / apply walkthrough
 *  12. [Phase 3] k8s/helm/euno/values-azure.yaml exists and contains required entries:
 *      - ACR registry reference (azurecr.io)
 *      - Workload Identity annotation (azure.workload.identity/client-id)
 *      - SIGNING_PROVIDER: azure-keyvault
 *      - IDENTITY_PROVIDER: azure-ad
 *      - AZURE_TENANT_ID placeholder
 *  13. [Phase 3] docs/multi-cloud.md exists and links to deployment guides and IaC:
 *      - References deploy-eks.md, deploy-gke.md
 *      - References infra/aws/cdk and infra/aws/terraform
 *  14. [Phase 3] docs/multi-cloud-plan.md Phase 3 items are marked complete:
 *      - AWS CDK constructs item is checked off
 *      - Terraform module item is checked off
 *      - values-azure.yaml item is checked off
 *      - Multi-cloud runbook index item is checked off
 *
 * Usage (from the repo root):
 *
 *   node scripts/check-multi-cloud-docs.mjs
 *
 * Options:
 *   --root <path>   Override the workspace root (default: repo root).
 *                   Used by unit tests to point at synthetic fixtures.
 *
 * Exit codes:
 *   0 -- all checks pass
 *   1 -- one or more checks failed or a required file is missing
 */

import { readFileSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '..');

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

const argv = process.argv.slice(2);
let workspaceRoot = repoRoot;

for (let i = 0; i < argv.length; i++) {
  if (argv[i] === '--root' && argv[i + 1]) {
    workspaceRoot = resolve(argv[i + 1]);
    i++;
  } else if (argv[i].startsWith('--root=')) {
    workspaceRoot = resolve(argv[i].slice('--root='.length));
  } else {
    console.error(`Unknown argument: ${argv[i]}`);
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const failures = [];

function requireFile(relPath, description) {
  const abs = resolve(workspaceRoot, relPath);
  if (!existsSync(abs)) {
    failures.push(`Missing file: ${description} (expected at ${relPath})`);
    return null;
  }
  return readFileSync(abs, 'utf8');
}

function requireText(content, needle, description) {
  if (content === null) return;
  if (!content.includes(needle)) {
    failures.push(`Missing: ${description} (looked for: ${JSON.stringify(needle)})`);
  }
}

/**
 * Extract the text starting from the first occurrence of a level-2 heading
 * whose text begins with the given prefix (e.g. '## 11.'). Returns an empty
 * string when the heading is not found, so that requireText() calls on the
 * result will fail as expected.
 */
function extractSection(content, headingPrefix) {
  if (content === null) return null;
  const idx = content.indexOf(`\n${headingPrefix}`);
  // Return content from the matched heading onward; if the heading is absent,
  // return empty string so section-scoped requireText() calls emit "Missing:".
  return idx >= 0 ? content.slice(idx + 1) : '';
}

// ---------------------------------------------------------------------------
// Check 1 — docs/deploy-eks.md
// ---------------------------------------------------------------------------

const eksGuide = requireFile('docs/deploy-eks.md', 'docs/deploy-eks.md');

requireText(eksGuide, 'IAM Roles for Service Accounts',
  'deploy-eks.md: IAM Roles for Service Accounts (IRSA) section');
requireText(eksGuide, 'eks.amazonaws.com/role-arn',
  'deploy-eks.md: IRSA annotation example');
requireText(eksGuide, 'ECR',
  'deploy-eks.md: ECR image configuration section');
requireText(eksGuide, 'ALB Ingress Controller',
  'deploy-eks.md: ALB Ingress Controller section');
requireText(eksGuide, 'ACM',
  'deploy-eks.md: ACM certificate section');
requireText(eksGuide, 'values-aws.yaml',
  'deploy-eks.md: reference to values-aws.yaml');
requireText(eksGuide, 'CloudWatch',
  'deploy-eks.md: CloudWatch observability section');
requireText(eksGuide, 'Security Hub',
  'deploy-eks.md: Security Hub section');
requireText(eksGuide, 'OCSF',
  'deploy-eks.md: OCSF → Security Hub finding mapping');
requireText(eksGuide, 'CloudWatch Insights',
  'deploy-eks.md: CloudWatch Insights query templates');
requireText(eksGuide, 'denial_reason',
  'deploy-eks.md: denial_reason histogram query');

// Phase 2 — S3 endpoint configuration
requireText(eksGuide, 'AUDIT_LEDGER_S3_ENDPOINT',
  'deploy-eks.md [Phase 2]: AUDIT_LEDGER_S3_ENDPOINT env var documented');
requireText(eksGuide, 'AUDIT_LEDGER_S3_FORCE_PATH_STYLE',
  'deploy-eks.md [Phase 2]: AUDIT_LEDGER_S3_FORCE_PATH_STYLE env var documented');
requireText(eksGuide, 'VPC endpoint',
  'deploy-eks.md [Phase 2]: VPC endpoint / PrivateLink S3 configuration documented');
requireText(eksGuide, 'us-gov-west-1',
  'deploy-eks.md [Phase 2]: GovCloud S3 region example documented');

// ---------------------------------------------------------------------------
// Check 2 — docs/secrets-aws.md
// ---------------------------------------------------------------------------

const secretsAwsGuide = requireFile('docs/secrets-aws.md', 'docs/secrets-aws.md');

requireText(secretsAwsGuide, 'AUDIT_LEDGER_HMAC_SECRET',
  'secrets-aws.md: AUDIT_LEDGER_HMAC_SECRET referenced');
requireText(secretsAwsGuide, 'ADMIN_API_KEY',
  'secrets-aws.md: ADMIN_API_KEY (GATEWAY_ADMIN_API_KEY) referenced');
requireText(secretsAwsGuide, 'PARTNER_DID_PIN_SECRET',
  'secrets-aws.md: PARTNER_DID_PIN_SECRET referenced');
requireText(secretsAwsGuide, 'EunoKmsSigningPolicy',
  'secrets-aws.md: EunoKmsSigningPolicy IAM policy defined');
requireText(secretsAwsGuide, 'External Secrets Operator',
  'secrets-aws.md: External Secrets Operator (ESO) section');
requireText(secretsAwsGuide, 'SecretStore',
  'secrets-aws.md: ESO SecretStore resource example');
requireText(secretsAwsGuide, 'ExternalSecret',
  'secrets-aws.md: ESO ExternalSecret resource example');
requireText(secretsAwsGuide, 'Secrets Store CSI',
  'secrets-aws.md: ASCP / Secrets Store CSI driver section');
requireText(secretsAwsGuide, 'SecretProviderClass',
  'secrets-aws.md: SecretProviderClass resource example');
requireText(secretsAwsGuide, 'ESO vs. ASCP',
  'secrets-aws.md: ESO vs. ASCP comparison table or section');

// Phase 2 — native SDK integration
requireText(secretsAwsGuide, 'AwsSecretsManagerSecretStore',
  'secrets-aws.md [Phase 2]: AwsSecretsManagerSecretStore native SDK section');
requireText(secretsAwsGuide, 'AWS_SECRETS_ARN_',
  'secrets-aws.md [Phase 2]: AWS_SECRETS_ARN_* env var pattern documented');
requireText(secretsAwsGuide, 'arnsBySecretName',
  'secrets-aws.md [Phase 2]: arnsBySecretName map explained');
requireText(secretsAwsGuide, 'AwsEdDsaSigner',
  'secrets-aws.md [Phase 2]: AwsEdDsaSigner EdDSA shim documented');
requireText(secretsAwsGuide, 'AWS_EDDSA_KEY_ARN',
  'secrets-aws.md [Phase 2]: AWS_EDDSA_KEY_ARN env var documented');

// ---------------------------------------------------------------------------
// Check 3 — docs/issuer-idp-setup.md Cognito SCIM bridge section
// ---------------------------------------------------------------------------

const idpSetup = requireFile('docs/issuer-idp-setup.md', 'docs/issuer-idp-setup.md');

requireText(idpSetup, 'Cognito SCIM bridge',
  'issuer-idp-setup.md: Cognito SCIM bridge section heading');
requireText(idpSetup, 'IAM Identity Center',
  'issuer-idp-setup.md: AWS IAM Identity Center reference in Cognito SCIM section');
requireText(idpSetup, 'ISSUER_SCIM_BEARER_TOKEN',
  'issuer-idp-setup.md: ISSUER_SCIM_BEARER_TOKEN in Cognito SCIM section');
requireText(idpSetup, 'externalId',
  'issuer-idp-setup.md: externalId attribute mapping in Cognito SCIM section');
requireText(idpSetup, 'ISSUER_SCIM_GROUP_ROLE_MAP',
  'issuer-idp-setup.md: ISSUER_SCIM_GROUP_ROLE_MAP in Cognito SCIM section');

// ---------------------------------------------------------------------------
// Check 4 — k8s/helm/euno/values-aws.yaml
// ---------------------------------------------------------------------------

const valuesAws = requireFile('k8s/helm/euno/values-aws.yaml',
  'k8s/helm/euno/values-aws.yaml');

requireText(valuesAws, 'dkr.ecr',
  'values-aws.yaml: ECR registry reference (dkr.ecr)');
requireText(valuesAws, 'eks.amazonaws.com/role-arn',
  'values-aws.yaml: IRSA role-arn annotation');
requireText(valuesAws, 'aws-kms',
  'values-aws.yaml: SIGNING_PROVIDER: aws-kms');
requireText(valuesAws, 'aws-cognito',
  'values-aws.yaml: IDENTITY_PROVIDER: aws-cognito');
requireText(valuesAws, 'AWS_COGNITO_USER_POOL_ID',
  'values-aws.yaml: AWS_COGNITO_USER_POOL_ID placeholder');
requireText(valuesAws, 'gp3',
  'values-aws.yaml: gp3 EBS storage class for posture-emitter');

// ---------------------------------------------------------------------------
// Check 5 — docs/multi-cloud-plan.md Phase 2 items are checked off
// ---------------------------------------------------------------------------

const multiCloudPlan = requireFile('docs/multi-cloud-plan.md', 'docs/multi-cloud-plan.md');

requireText(multiCloudPlan, '[x] **AWS Secrets Manager secrets-store adapter**',
  'multi-cloud-plan.md [Phase 2]: AWS Secrets Manager adapter item is checked off');
requireText(multiCloudPlan, '[x] **S3 cross-chain anchor',
  'multi-cloud-plan.md [Phase 2]: S3 endpoint item is checked off');
requireText(multiCloudPlan, '[x] **AWS KMS signer',
  'multi-cloud-plan.md [Phase 2]: KMS/EdDSA signer item is checked off');

// ---------------------------------------------------------------------------
// Check 6 — docs/deploy-gke.md
// ---------------------------------------------------------------------------

const gkeGuide = requireFile('docs/deploy-gke.md', 'docs/deploy-gke.md');

requireText(gkeGuide, 'Workload Identity',
  'deploy-gke.md: Workload Identity Federation section');
requireText(gkeGuide, 'iam.gke.io/gcp-service-account',
  'deploy-gke.md: Workload Identity annotation example');
requireText(gkeGuide, 'Artifact Registry',
  'deploy-gke.md: Artifact Registry image configuration section');
requireText(gkeGuide, 'GKE Ingress',
  'deploy-gke.md: GKE Ingress section');
requireText(gkeGuide, 'ManagedCertificate',
  'deploy-gke.md: Google-managed SSL certificate (ManagedCertificate) section');
requireText(gkeGuide, 'values-gcp.yaml',
  'deploy-gke.md: reference to values-gcp.yaml');
requireText(gkeGuide, 'Cloud Monitoring',
  'deploy-gke.md: Cloud Monitoring observability section');
requireText(gkeGuide, 'Security Command Center',
  'deploy-gke.md: Security Command Center section');
requireText(gkeGuide, 'OCSF',
  'deploy-gke.md: OCSF → Security Command Center finding mapping');
requireText(gkeGuide, 'denial_reason',
  'deploy-gke.md: denial_reason histogram query');

// ---------------------------------------------------------------------------
// Check 7 — docs/secrets-gcp.md
// ---------------------------------------------------------------------------

const secretsGcpGuide = requireFile('docs/secrets-gcp.md', 'docs/secrets-gcp.md');

requireText(secretsGcpGuide, 'AUDIT_LEDGER_HMAC_SECRET',
  'secrets-gcp.md: AUDIT_LEDGER_HMAC_SECRET referenced');
requireText(secretsGcpGuide, 'ADMIN_API_KEY',
  'secrets-gcp.md: ADMIN_API_KEY referenced');
requireText(secretsGcpGuide, 'PARTNER_DID_PIN_SECRET',
  'secrets-gcp.md: PARTNER_DID_PIN_SECRET referenced');
requireText(secretsGcpGuide, 'secretAccessor',
  'secrets-gcp.md: Secret Accessor IAM role binding');
requireText(secretsGcpGuide, 'External Secrets Operator',
  'secrets-gcp.md: External Secrets Operator (ESO) section');
requireText(secretsGcpGuide, 'SecretStore',
  'secrets-gcp.md: ESO SecretStore resource example');
requireText(secretsGcpGuide, 'ExternalSecret',
  'secrets-gcp.md: ESO ExternalSecret resource example');
requireText(secretsGcpGuide, 'Secret Manager Add-on',
  'secrets-gcp.md: Secret Manager Add-on section');
requireText(secretsGcpGuide, 'ESO vs.',
  'secrets-gcp.md: ESO vs. comparison table or section');

// ---------------------------------------------------------------------------
// Check 8 — docs/issuer-idp-setup.md Google Workspace SCIM bridge section
// ---------------------------------------------------------------------------

requireText(idpSetup, 'Google Workspace SCIM bridge',
  'issuer-idp-setup.md: Google Workspace SCIM bridge section heading');
requireText(idpSetup, 'OAuth service account',
  'issuer-idp-setup.md: OAuth service account reference in Google Workspace SCIM section');
requireText(idpSetup, 'externalId: user.id',
  'issuer-idp-setup.md: externalId = Google user.id mapping in Google Workspace SCIM section');

// Scope the following checks to the §11 section so that §10 (Cognito) entries
// do not satisfy GCP-specific requirements.
const idpSetupSection11 = extractSection(idpSetup, '## 11.');

requireText(idpSetupSection11, 'ISSUER_SCIM_BEARER_TOKEN',
  'issuer-idp-setup.md §11: ISSUER_SCIM_BEARER_TOKEN environment variable');
requireText(idpSetupSection11, 'ISSUER_SCIM_GROUP_ROLE_MAP',
  'issuer-idp-setup.md §11: ISSUER_SCIM_GROUP_ROLE_MAP environment variable');

// ---------------------------------------------------------------------------
// Check 9 — k8s/helm/euno/values-gcp.yaml
// ---------------------------------------------------------------------------

const valuesGcp = requireFile('k8s/helm/euno/values-gcp.yaml',
  'k8s/helm/euno/values-gcp.yaml');

requireText(valuesGcp, 'pkg.dev',
  'values-gcp.yaml: Artifact Registry reference (pkg.dev)');
requireText(valuesGcp, 'iam.gke.io/gcp-service-account',
  'values-gcp.yaml: Workload Identity annotation (iam.gke.io/gcp-service-account)');
requireText(valuesGcp, 'gcp-cloudkms',
  'values-gcp.yaml: SIGNING_PROVIDER: gcp-cloudkms');
requireText(valuesGcp, 'gcp-identity',
  'values-gcp.yaml: IDENTITY_PROVIDER: gcp-identity');
requireText(valuesGcp, 'GCP_PROJECT_ID',
  'values-gcp.yaml: GCP_PROJECT_ID placeholder');
requireText(valuesGcp, 'premium-rwo',
  'values-gcp.yaml: premium-rwo GKE storage class for posture-emitter');

// ---------------------------------------------------------------------------
// Check 10 — AWS CDK constructs (Phase 3)
// ---------------------------------------------------------------------------

const cdkGatewayStack = requireFile(
  'infra/aws/cdk/src/stacks/gateway-stack.ts',
  'infra/aws/cdk/src/stacks/gateway-stack.ts',
);

requireText(cdkGatewayStack, 'EunoGatewayStack',
  'gateway-stack.ts: EunoGatewayStack class declared');
requireText(cdkGatewayStack, 'aws-cdk-lib/aws-eks',
  'gateway-stack.ts: EKS import from aws-cdk-lib/aws-eks');
requireText(cdkGatewayStack, 'aws-cdk-lib/aws-rds',
  'gateway-stack.ts: RDS import from aws-cdk-lib/aws-rds');
requireText(cdkGatewayStack, 'aws-cdk-lib/aws-elasticache',
  'gateway-stack.ts: ElastiCache import from aws-cdk-lib/aws-elasticache');
requireText(cdkGatewayStack, 'aws-cdk-lib/aws-kms',
  'gateway-stack.ts: KMS import from aws-cdk-lib/aws-kms');
requireText(cdkGatewayStack, 'aws-cdk-lib/aws-s3',
  'gateway-stack.ts: S3 import from aws-cdk-lib/aws-s3');
requireText(cdkGatewayStack, 'objectLockEnabled',
  'gateway-stack.ts: S3 Object Lock enabled for audit anchor bucket');
requireText(cdkGatewayStack, 'aws-cdk-lib/aws-secretsmanager',
  'gateway-stack.ts: Secrets Manager import from aws-cdk-lib/aws-secretsmanager');
requireText(cdkGatewayStack, 'FargateProfile',
  'gateway-stack.ts: EKS Fargate profile for euno-system namespace');

const cdkIssuerStack = requireFile(
  'infra/aws/cdk/src/stacks/issuer-stack.ts',
  'infra/aws/cdk/src/stacks/issuer-stack.ts',
);

requireText(cdkIssuerStack, 'EunoIssuerStack',
  'issuer-stack.ts: EunoIssuerStack class declared');
requireText(cdkIssuerStack, 'aws-cdk-lib/aws-cognito',
  'issuer-stack.ts: Cognito import from aws-cdk-lib/aws-cognito');
requireText(cdkIssuerStack, 'UserPool',
  'issuer-stack.ts: Cognito UserPool provisioned');
requireText(cdkIssuerStack, 'SCIM',
  'issuer-stack.ts: SCIM endpoint wiring documented');
requireText(cdkIssuerStack, 'PARTNER_DID_PIN_SECRET',
  'issuer-stack.ts: PARTNER_DID_PIN_SECRET secret provisioned');

const cdkEnterpriseStack = requireFile(
  'infra/aws/cdk/src/stacks/enterprise-stack.ts',
  'infra/aws/cdk/src/stacks/enterprise-stack.ts',
);

requireText(cdkEnterpriseStack, 'EunoEnterpriseStack',
  'enterprise-stack.ts: EunoEnterpriseStack class declared');
requireText(cdkEnterpriseStack, 'aws-cdk-lib/aws-dynamodb',
  'enterprise-stack.ts: DynamoDB import for partner DID registry');
requireText(cdkEnterpriseStack, 'partnerDidRegistry',
  'enterprise-stack.ts: partner DID registry DynamoDB table');
requireText(cdkEnterpriseStack, 'aws-cdk-lib/aws-cloudtrail',
  'enterprise-stack.ts: CloudTrail import for SOC 2 audit pipeline');
requireText(cdkEnterpriseStack, 'aws-cdk-lib/aws-kinesisfirehose',
  'enterprise-stack.ts: Kinesis Firehose import for audit pipeline');
requireText(cdkEnterpriseStack, 'aws-cdk-lib/aws-securityhub',
  'enterprise-stack.ts: Security Hub import');

const cdkPkgJson = requireFile('infra/aws/cdk/package.json',
  'infra/aws/cdk/package.json');

requireText(cdkPkgJson, 'aws-cdk-lib',
  'infra/aws/cdk/package.json: aws-cdk-lib dependency declared');
requireText(cdkPkgJson, 'constructs',
  'infra/aws/cdk/package.json: constructs dependency declared');

const cdkGatewayTest = requireFile(
  'infra/aws/cdk/test/gateway-stack.test.ts',
  'infra/aws/cdk/test/gateway-stack.test.ts',
);

requireText(cdkGatewayTest, 'aws-cdk-lib/assertions',
  'gateway-stack.test.ts: uses aws-cdk-lib/assertions');
requireText(cdkGatewayTest, 'EunoGatewayStack',
  'gateway-stack.test.ts: tests EunoGatewayStack');

const cdkIssuerTest = requireFile(
  'infra/aws/cdk/test/issuer-stack.test.ts',
  'infra/aws/cdk/test/issuer-stack.test.ts',
);

requireText(cdkIssuerTest, 'aws-cdk-lib/assertions',
  'issuer-stack.test.ts: uses aws-cdk-lib/assertions');
requireText(cdkIssuerTest, 'EunoIssuerStack',
  'issuer-stack.test.ts: tests EunoIssuerStack');

const cdkEnterpriseTest = requireFile(
  'infra/aws/cdk/test/enterprise-stack.test.ts',
  'infra/aws/cdk/test/enterprise-stack.test.ts',
);

requireText(cdkEnterpriseTest, 'aws-cdk-lib/assertions',
  'enterprise-stack.test.ts: uses aws-cdk-lib/assertions');
requireText(cdkEnterpriseTest, 'EunoEnterpriseStack',
  'enterprise-stack.test.ts: tests EunoEnterpriseStack');

// ---------------------------------------------------------------------------
// Check 11 — AWS Terraform modular layout (Phase 3)
// ---------------------------------------------------------------------------

const tfReadme = requireFile('infra/aws/terraform/README.md',
  'infra/aws/terraform/README.md');

requireText(tfReadme, 'terraform init',
  'infra/aws/terraform/README.md: terraform init walkthrough');
requireText(tfReadme, 'terraform plan',
  'infra/aws/terraform/README.md: terraform plan walkthrough');
requireText(tfReadme, 'terraform apply',
  'infra/aws/terraform/README.md: terraform apply walkthrough');

requireFile('infra/aws/terraform/network/main.tf',
  'infra/aws/terraform/network/main.tf');
requireFile('infra/aws/terraform/compute/main.tf',
  'infra/aws/terraform/compute/main.tf');
requireFile('infra/aws/terraform/data/main.tf',
  'infra/aws/terraform/data/main.tf');

const tfSecurityMain = requireFile('infra/aws/terraform/security/main.tf',
  'infra/aws/terraform/security/main.tf');

requireText(tfSecurityMain, 'aws_kms_key',
  'infra/aws/terraform/security/main.tf: KMS key resource');
requireText(tfSecurityMain, 'SIGN_VERIFY',
  'infra/aws/terraform/security/main.tf: KMS key usage SIGN_VERIFY');
requireText(tfSecurityMain, 'aws_secretsmanager_secret',
  'infra/aws/terraform/security/main.tf: Secrets Manager secrets');
requireText(tfSecurityMain, 'aws_cognito_user_pool',
  'infra/aws/terraform/security/main.tf: Cognito User Pool');
requireText(tfSecurityMain, 'aws_iam_role',
  'infra/aws/terraform/security/main.tf: IAM IRSA roles');

const tfObservabilityMain = requireFile(
  'infra/aws/terraform/observability/main.tf',
  'infra/aws/terraform/observability/main.tf',
);

requireText(tfObservabilityMain, 'aws_cloudwatch_log_group',
  'infra/aws/terraform/observability/main.tf: CloudWatch log groups');
requireText(tfObservabilityMain, 'aws_securityhub_account',
  'infra/aws/terraform/observability/main.tf: Security Hub');
requireText(tfObservabilityMain, 'aws_cloudtrail',
  'infra/aws/terraform/observability/main.tf: CloudTrail trail');

// ---------------------------------------------------------------------------
// Check 12 — k8s/helm/euno/values-azure.yaml (Phase 3 / cross-cloud)
// ---------------------------------------------------------------------------

const valuesAzure = requireFile('k8s/helm/euno/values-azure.yaml',
  'k8s/helm/euno/values-azure.yaml');

requireText(valuesAzure, 'azurecr.io',
  'values-azure.yaml: Azure Container Registry reference (azurecr.io)');
requireText(valuesAzure, 'azure.workload.identity/client-id',
  'values-azure.yaml: Workload Identity annotation (azure.workload.identity/client-id)');
requireText(valuesAzure, 'azure-keyvault',
  'values-azure.yaml: SIGNING_PROVIDER: azure-keyvault');
requireText(valuesAzure, 'azure-ad',
  'values-azure.yaml: IDENTITY_PROVIDER: azure-ad');
requireText(valuesAzure, 'AZURE_TENANT_ID',
  'values-azure.yaml: AZURE_TENANT_ID placeholder');

// ---------------------------------------------------------------------------
// Check 13 — docs/multi-cloud.md (Phase 3 / cross-cloud)
// ---------------------------------------------------------------------------

const multiCloudDoc = requireFile('docs/multi-cloud.md', 'docs/multi-cloud.md');

requireText(multiCloudDoc, 'deploy-eks.md',
  'docs/multi-cloud.md: link to docs/deploy-eks.md');
requireText(multiCloudDoc, 'deploy-gke.md',
  'docs/multi-cloud.md: link to docs/deploy-gke.md');
requireText(multiCloudDoc, 'infra/aws/cdk',
  'docs/multi-cloud.md: reference to infra/aws/cdk CDK constructs');
requireText(multiCloudDoc, 'infra/aws/terraform',
  'docs/multi-cloud.md: reference to infra/aws/terraform modular Terraform');

// ---------------------------------------------------------------------------
// Check 14 — docs/multi-cloud-plan.md Phase 3 items are checked off
// ---------------------------------------------------------------------------

requireText(multiCloudPlan, '[x] **AWS CDK constructs**',
  'multi-cloud-plan.md [Phase 3]: AWS CDK constructs item is checked off');
requireText(multiCloudPlan, '[x] **Terraform module** (`infra/aws/terraform/',
  'multi-cloud-plan.md [Phase 3]: AWS Terraform modular layout item is checked off');
requireText(multiCloudPlan, '[x] `k8s/helm/euno/values-azure.yaml`',
  'multi-cloud-plan.md [Phase 3]: values-azure.yaml item is checked off');
requireText(multiCloudPlan, '[x] **Multi-cloud runbook index**',
  'multi-cloud-plan.md [Phase 3]: multi-cloud runbook index item is checked off');

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

if (failures.length === 0) {
  console.log('check-multi-cloud-docs: all checks passed.');
  process.exit(0);
} else {
  console.error('check-multi-cloud-docs: FAILED');
  for (const f of failures) {
    console.error(`  FAIL: ${f}`);
  }
  process.exit(1);
}
